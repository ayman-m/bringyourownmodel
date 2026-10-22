"""GuardianEval -- the light eval harness: replays a small, canned set of
test cases through the REAL `GuardianAgentLoop` and scores basic outcome
metrics into `guardian_eval_results` for the observability dashboard.

SCOPE
--------------------------------------------------------------------------
This is a pass/fail-shaped gate signal, not a judged quality score. Per case
it answers four basic questions: did the run conclude (vs. still running, or
failed), how many ticks and how much cost, did it reach a verdict, and how
many distinct tools did it use. Ground truth (`expected_verdict`,
`expected_techniques`) lives in the STATIC `GUARDIAN_EVAL_CASES` library (plus
an optional runtime case List), never round-tripped through an incident
field, and is joined to scored rows by `case_id` at REPORT time
(`action=report` -> :func:`guardian_eval_report`). `action=score` records only
raw observed facts, no accuracy math (see :func:`guardian_eval_score_one`).

- No per-incident Context probing (`Guardian.Loop.*`): the incident's own
  first-class `runStatus` field (`"completed"`/`"failed"`/`"running"`/
  `"waiting"`) plus its `CustomFields` (`guardiantickcount`,
  `guardiancostusd`, `guardianverdict`, all written directly onto the
  incident by `GuardianReasoningTick`) are sufficient and much simpler than
  the cross-incident Context read `GuardianHousekeeping` uses.
- The "run" step does not itself wait for a case to conclude (ticks run on a
  real ~15s cadence over real wall-clock minutes -- this harness is not a
  synchronous test runner). Scoring is a SEPARATE step (`action=score`),
  delivered as a scheduled Job (`Jobs/job-guardianevalscore.json` ->
  `playbook-GuardianEvalScore.yml`) that periodically catches up on any case
  that has since concluded. Seeding new canned cases (`action=run`) is a
  manual, on-demand action.

DESIGN FACTS THIS BUILDS ON
--------------------------------------------------------------------------
- A "Guardian Agent Run" incident's `runStatus` (a first-class incident
  field, returned directly by `/incidents/search` -- NOT
  `Guardian.Loop.status`, which only lives in that incident's own Context)
  reflects the attached playbook's state: `""` before investigation,
  `"running"`/`"waiting"` while `GuardianReasoningTick`'s self-rescheduling
  chain is still ticking, `"completed"` once the loop concluded cleanly,
  `"failed"` on an unhandled playbook error.
- `GuardianAgentLoop`'s playbook input (`prompt`) is a STATIC default (the
  SOC intake-triage sweep) with no per-incident override. Every canned case
  in :data:`GUARDIAN_EVAL_CASES` therefore runs the SAME real production sweep
  prompt against a single driver incident whose `details` carry that case's
  own investigation narrative. This is the real production path
  (`GuardianIntakeSweep`'s own Job triggers the identical default-sweep
  incident type), not a special-cased eval-only bypass.
- There is no registered `IncidentField` to carry a `case_id`; the case id is
  instead embedded in the driver incident's `name` (`"Guardian Eval -
  <case_id> - <uuid>"`) and recovered by :func:`guardian_eval_parse_case_id`
  when scoring. Driver incidents are tagged `guardiantriggersource="eval"`
  (distinct from `GuardianSimulateIncidents`' own `"simulate"` tag, so the two
  tools' incidents are independently filterable).
- Distinct tool usage per run is read from the SHARED, run_id-filterable
  `guardian_audit` List (`GuardianAuditWrite`'s append-only ledger,
  `{ts, actor, action, target, status, duration_ms, tick_id, run_id,
  detail}` -- `run_id` is the incident id) rather than any Context read.

`guardian_eval_results` IS AN APPEND-ONLY ARRAY, IDEMPOTENT PER INCIDENT
--------------------------------------------------------------------------
Scoring an incident id already present in `guardian_eval_results` is a
no-op (skipped, bucketed `"already_scored"`) -- the Job can run as often
as it likes without ever double-counting a case.

OPERATOR/TEST TOOL -- NOT AN AGENT TOOL
--------------------------------------------------------------------------
Never added to `guardian_tool_allowlist`/`guardian_policy`.
"""

import json
import math
import re
import time
import uuid
from datetime import datetime, timezone

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# <GUARDIAN_COMMON_INJECT>
# <GUARDIAN_COMMON>
# ---------------------------------------------------------------------------
# Everything between this marker and the matching closing marker below is
# shared code that is copied into every Guardian script that carries a
# placeholder region. The block is self-contained: it relies on `demisto`,
# `json` and the `CommonServerPython` star-import (standard boilerplate at the
# top of every Guardian script) and on nothing else in this file.
# ---------------------------------------------------------------------------

#: Substrings (case-insensitive) of a dict key that mark its value as
#: secret-ish and therefore subject to masking by ``guardian_redact``.
#: Substring matching intentionally over-redacts (e.g. "api_key_id" still
#: masks) because silent leakage is the worse failure mode for a SOC audit
#: trail.
#:
#: The bare substring "key" is deliberately not included: it would match any
#: field named "key" -- for example the lookup key of a stored memory note,
#: which is not a secret -- and mask legitimate data to "***" before the model
#: or an analyst sees it. Instead the secret-bearing compound shapes are
#: enumerated individually: every `*_key` credential field
#: (access/secret/signing/encryption/decryption/master/hmac/consumer/ssh/
#: private/api key) still masks. `session`/`jwt`/`secret` (present as their own
#: substrings) transitively cover `session_key`/`jwt_key`/`secret_key`, so
#: those are not repeated.
GUARDIAN_SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "pwd",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "secret",
    "secret_key",
    "signing_key",
    "encryption_key",
    "decryption_key",
    "master_key",
    "hmac_key",
    "consumer_key",
    "ssh_key",
    "credential",
    "authorization",
    "auth",
    "private_key",
    "bearer",
    "cookie",
    "otp",
    "pin",
    "session",
    "access_token",
    "refresh_token",
    "client_secret",
    "jwt",
    "signature",
)

#: Mask written in place of a redacted secret value.
GUARDIAN_REDACTED_VALUE = "***"

#: Cap applied ONLY to the mask substituted for a value redacted under a
#: sensitive key (belt-and-suspenders in case ``GUARDIAN_REDACTED_VALUE`` ever
#: grows past this). Deliberately NOT applied to non-secret string values --
#: a generic size cap on arbitrary tool output is a SEPARATE 16KB mechanism
#: that lives in GuardianToolBridge, not here. Capping every string here
#: would silently truncate legitimate tool evidence before the model (or an
#: analyst reading the War Room) ever sees it.
GUARDIAN_MAX_VALUE_LEN = 512

#: DBotScore integer -> label, the only four values XSOAR's reputation model
#: defines. Anything else (out of range / not an int) maps to "Unknown".
GUARDIAN_DBOT_LABELS = {0: "Unknown", 1: "Good", 2: "Suspicious", 3: "Bad"}

#: The Go zero-value timestamp XSOAR stores in `dueDate` when no SLA timer is
#: running. Any timestamp starting with this prefix means "no SLA", not a
#: real date in the year 1 — treat it as null or it poisons date sorts.
GUARDIAN_NO_SLA_DATE_PREFIX = "0001-01-01"

#: Context namespace every Guardian read/write lives under, so Guardian's
#: incident-scoped state can never collide with another pack's Context keys.
GUARDIAN_CONTEXT_NAMESPACE = "Guardian"

#: XSOAR entry Type for an error War Room entry (`entryTypes['error']` in
#: CommonServerPython). Hardcoded here too so this block has no dependency
#: beyond `demisto`/`json` when pasted into a consumer script.
GUARDIAN_ERROR_ENTRY_TYPE = 4

#: Entry Type of a warning War Room entry (`entryTypes['warning']`, what `return_warning` writes).
GUARDIAN_WARNING_ENTRY_TYPE = 11

#: Platform-client failure phrases (`... failed client execute - error: request to
#: [...] returned non-whitelisted status [500] ...`). A command that reports a failed platform
#: call through `return_warning` leaves them as the plain-string Contents of ONE warning entry
#: (Type 11) and nothing else. Only that shape is read for this wording (see guardian_execute):
#: a note, a stored List, a memory value or a war-room entry read back can QUOTE the same text
#: as data, and must never turn into an error. Deliberately the framework's own wording only --
#: never the bare word "error", and never the entry Type alone: some integrations warn on an
#: empty result.
_GUARDIAN_HTTP_FAILURE_TEXT_PATTERN_STR = r"(?i)non-whitelisted status \[\d{3}\]|failed client execute"

#: Commands that read Guardian's own stored data (Lists, war-room entries, incidents, context)
#: and every `Guardian*` script. Their replies are data that may quote a failed lookup, so the
#: failure-wording rule is never applied to them, whatever the shape of the reply.
_GUARDIAN_STORED_DATA_READERS = frozenset(("getlist", "getentries", "getincidents", "getcontext"))

#: Message substrings that mark a failed `executeCommand` entry as an auth
#: failure (never worth blind-retrying) vs. a transient one (worth retrying).
_GUARDIAN_AUTH_ERROR_HINTS = (
    "unauthorized",
    "unauthenticated",
    "authentication failed",
    "invalid api key",
    "invalid credentials",
    "access denied",
    "forbidden",
    " 401",
    "(401)",
    " 403",
    "(403)",
)
_GUARDIAN_RETRYABLE_ERROR_HINTS = (
    "timed out",
    "timeout",
    "rate limit",
    "too many requests",
    "temporarily unavailable",
    "connection reset",
    "connection refused",
    "service unavailable",
    " 429",
    "(429)",
    " 502",
    "(502)",
    " 503",
    "(503)",
    " 504",
    "(504)",
    "internal server error",
)


def guardian_envelope(ok, data=None, error=None, retryable=False, is_auth_error=False):
    """Build the canonical Guardian tool-result envelope.

    Every Guardian helper/bridge that can fail returns this exact shape so
    callers (including the LLM-facing tool bridge) can branch on failure
    without inspecting exceptions or provider-specific error shapes.

    :param ok: ``True`` if the operation succeeded.
    :type ok: ``bool``
    :param data: The successful payload, or partial/raw data on failure.
    :param error: Human-readable error message, or ``None`` on success.
    :type error: ``str`` or ``None``
    :param retryable: ``True`` if retrying the same call might succeed later
        (e.g. rate limit, transient 5xx). Never ``True`` alongside
        ``is_auth_error``.
    :type retryable: ``bool``
    :param is_auth_error: ``True`` if the failure looks like an
        authentication/authorization problem (retrying without fixing
        credentials will never help).
    :type is_auth_error: ``bool``
    :return: ``{"ok", "data", "error", "retryable", "is_auth_error"}``
    :rtype: ``dict``
    """
    return {
        "ok": bool(ok),
        "data": data,
        "error": error,
        "retryable": bool(retryable),
        "is_auth_error": bool(is_auth_error),
    }


def _guardian_classify_error_text(message):
    """Classify a single error message as auth-error and/or retryable.

    :param message: The error text to inspect.
    :type message: ``str``
    :return: ``(is_auth_error, retryable)``
    :rtype: ``tuple(bool, bool)``
    """
    text = (message or "").lower()
    is_auth_error = any(hint in text for hint in _GUARDIAN_AUTH_ERROR_HINTS)
    retryable = (not is_auth_error) and any(hint in text for hint in _GUARDIAN_RETRYABLE_ERROR_HINTS)
    return is_auth_error, retryable


def guardian_execute(command, args, using=None):
    """Run an XSOAR command via ``demisto.executeCommand`` with the Guardian
    no-silent-success discipline.

    ``demisto.executeCommand`` **never raises** on command failure — it
    returns a list of War Room entries, some of which may carry
    ``Type == 4`` (``entryTypes['error']``). Callers that only check "did an
    exception happen?" will read a failed containment action as a success.
    A failure that arrives some other way also counts, in one confirmed shape only: the
    reply is warning entries (``return_warning``, ``Type == 11``) whose string Contents
    carry the platform client's failure wording, and no other entry carries data. A
    warning without that wording is not an error, a warning next to data is not an
    error, and a note, a stored List or a war-room entry that merely quotes the wording
    is data (the wording is never read in the replies of ``getList``, ``getEntries``,
    ``getIncidents``, ``getContext`` or a ``Guardian*`` script).
    This wraps the call, inspects **every** returned entry, and returns
    ``ok=False`` if **any** entry is an error entry — this function itself
    also never raises (a Python exception from the call itself, e.g. a bad
    command name, is caught and turned into a ``retryable`` envelope).

    :param command: The XSOAR command / script name to run (e.g. ``"ip"``,
        ``"setIncident"``).
    :type command: ``str``
    :param args: Command arguments.
    :type args: ``dict``
    :param using: Optional integration instance name to pin the command to
        (passed through as the ``using`` arg XSOAR recognizes).
    :type using: ``str`` or ``None``
    :return: A :func:`guardian_envelope`. ``data`` on success is the raw list
        of War Room entries returned by ``executeCommand`` (callers needing a
        single JSON payload should pull ``entry["Contents"]`` themselves —
        multi-entry results are common and this helper doesn't guess which
        entry the caller wants).
    :rtype: ``dict``
    """
    import json  # defensive: this block is injected verbatim into other
    # scripts (see module docstring) and must not depend on the consuming
    # script's top-level `import json` actually being present.

    call_args = dict(args) if args else {}
    if using:
        call_args["using"] = using

    try:
        entries = demisto.executeCommand(command, call_args)
    except Exception as exc:  # still never raise outward — convert to envelope
        return guardian_envelope(
            False,
            error=f"executeCommand raised for '{command}': {exc}",
            retryable=True,
        )

    if not entries:
        return guardian_envelope(True, data=[])

    error_messages = []
    is_auth_error = False
    retryable = False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("Type") == GUARDIAN_ERROR_ENTRY_TYPE:
            # Redact BEFORE flattening to text -- mirrors the success path
            # (GuardianToolBridge's guardian_bridge_shape_result also runs
            # guardian_redact on the structured Contents before
            # serializing). A failing entry's Contents can be a dict an
            # upstream integration returned verbatim (e.g. echoing back the
            # request it rejected, api_key included) -- guardian_redact
            # masks any dict value under a sensitive key; it is a no-op on
            # an already-scalar string Contents (nothing to structurally
            # redact there -- see guardian_scrub_secrets below for that
            # free-form-string case, applied by callers at their own
            # error-string chokepoint).
            contents = guardian_redact(entry.get("Contents"))
            if isinstance(contents, str) and contents:
                message = contents
            elif contents is not None:
                message = json.dumps(contents, default=str)
            else:
                message = entry.get("HumanReadable") or f"{command} failed"
            error_messages.append(message)
            entry_auth, entry_retryable = _guardian_classify_error_text(message)
            is_auth_error = is_auth_error or entry_auth
            retryable = retryable or entry_retryable

    # An error that did not arrive as a Type 4 entry: the confirmed shape is a command that
    # reports a failed platform call through `return_warning` -- ONE warning entry (Type 11)
    # whose string Contents carry the platform client's own failure wording (see
    # _GUARDIAN_HTTP_FAILURE_TEXT_PATTERN_STR), with no other entry carrying data. Nothing
    # else is read for that wording: a Type 1 note, a stored List (`getList` returns it as a
    # JSON string), a memory value or a war-room entry read back can quote the same words
    # as data. A warning without the wording, or next to a data entry, is a normal result and
    # is passed through unchanged, and so is any data that merely mentions the word "error".
    command_name = str(command or "")
    reads_stored_data = command_name.lower() in _GUARDIAN_STORED_DATA_READERS or command_name.startswith("Guardian")
    if not error_messages and not reads_stored_data:
        import re  # defensive: see the module docstring

        def _carries_data(candidate):
            if not isinstance(candidate, dict):
                return False
            candidate_contents = candidate.get("Contents")
            if candidate_contents in (None, "", [], {}):
                return False
            # another warning that only holds text is not data; any other entry is
            return not (candidate.get("Type") == GUARDIAN_WARNING_ENTRY_TYPE and isinstance(candidate_contents, str))

        if not any(_carries_data(entry) for entry in entries):
            for entry in entries:
                if not isinstance(entry, dict) or entry.get("Type") != GUARDIAN_WARNING_ENTRY_TYPE:
                    continue
                contents = entry.get("Contents")
                if not isinstance(contents, str) or not re.search(_GUARDIAN_HTTP_FAILURE_TEXT_PATTERN_STR, contents):
                    continue
                try:
                    parsed = json.loads(contents)
                except (TypeError, ValueError):
                    parsed = None
                if isinstance(parsed, (dict, list)):
                    continue  # a JSON document is data that quotes the wording, not a failure report
                error_messages.append(contents)
                entry_auth, entry_retryable = _guardian_classify_error_text(contents)
                is_auth_error = is_auth_error or entry_auth
                retryable = retryable or entry_retryable

    # Auth precedence: a multi-entry response can independently OR in an
    # auth-flavored entry AND a retryable-flavored entry (e.g. one "401
    # Unauthorized" entry plus one "503" entry in the same executeCommand
    # response). guardian_envelope's contract is that retryable is never
    # True alongside is_auth_error -- retrying without fixing credentials
    # will never help regardless of what else looked transient.
    retryable = retryable and not is_auth_error

    if error_messages:
        return guardian_envelope(
            False,
            data=entries,
            error="; ".join(error_messages),
            retryable=retryable,
            is_auth_error=is_auth_error,
        )

    return guardian_envelope(True, data=entries)


def guardian_project_incident(inc):
    """Project a raw XSOAR incident object down to Guardian's 9-field
    summary, so the model/audit trail never carries a full incident's worth
    of tokens for a routine lookup.

    :param inc: A raw incident dict (e.g. from ``demisto.incident()`` or an
        ``incidents/search`` result).
    :type inc: ``dict``
    :return: ``{id,name,type,severity,status,owner,created,modified,due_date}``
    :rtype: ``dict``
    """
    inc = inc or {}
    return {
        "id": inc.get("id"),
        "name": inc.get("name"),
        "type": inc.get("type"),
        "severity": inc.get("severity"),
        "status": inc.get("status"),
        "owner": inc.get("owner"),
        "created": inc.get("created"),
        "modified": inc.get("modified"),
        "due_date": guardian_normalize_due(inc.get("dueDate")),
    }


def guardian_dbot_label(score):
    """Map a DBotScore integer (0-3) to its label.

    :param score: A DBotScore value, or anything score-like (numeric string
        also accepted).
    :return: One of ``"Unknown"``, ``"Good"``, ``"Suspicious"``, ``"Bad"``.
        Anything unparseable or out of the 0-3 range also maps to
        ``"Unknown"`` rather than raising.
    :rtype: ``str``
    """
    try:
        score_int = int(score)
    except (TypeError, ValueError):
        return "Unknown"
    return GUARDIAN_DBOT_LABELS.get(score_int, "Unknown")


def guardian_normalize_due(due):
    """Normalize an XSOAR SLA/``dueDate`` timestamp.

    XSOAR stores the Go zero-value ``"0001-01-01T00:00:00Z"`` in ``dueDate``
    when no SLA timer is running. Left as-is, that timestamp sorts *before*
    every real deadline and silently poisons "what's most overdue" logic.
    This normalizes any ``0001-01-01``-prefixed value to ``None``.

    :param due: The raw ``dueDate`` value (or anything else — non-strings
        pass through unchanged).
    :return: ``None`` if ``due`` is the Go zero-value timestamp, else ``due``
        unchanged.
    """
    if isinstance(due, str) and due.startswith(GUARDIAN_NO_SLA_DATE_PREFIX):
        return None
    return due


#: ATT&CK technique-id grammar: ``T####`` or a sub-technique ``T####.###``.
#: Kept as a plain string, not a pre-compiled pattern -- this constant lives
#: inside the injected GUARDIAN_COMMON block (see module docstring) and a
#: module-level ``re.compile(...)`` would need ``re`` imported at that same
#: module scope, which every consuming script isn't guaranteed to have done.
GUARDIAN_TECHNIQUE_PATTERN_STR = r"^T\d{4}(?:\.\d{3})?$"


def guardian_normalize_techniques(value):
    """Normalize a raw ATT&CK technique-id collection into a clean, sorted list.

    Shared by every Guardian surface that ingests model-authored technique ids
    (the reasoning loop's verdict-telemetry write, the eval scorer) so they
    can never drift out of sync on what counts as a valid id.

    :param value: A ``list`` of technique-id-like strings, a single
        comma/whitespace-separated string (``"T1566, T1078"``), or ``None``.
    :return: Uppercased, whitespace-trimmed ids matching the ATT&CK grammar
        (``T####`` or ``T####.###``), with any sub-technique collapsed to its
        parent (``T1566.001`` -> ``T1566``), de-duplicated and sorted.
        Anything that doesn't match the grammar is silently dropped.
        ``None``/empty input -> ``[]``.
    :rtype: ``list`` of ``str``
    """
    import re  # defensive: this block is injected verbatim into other
    # scripts (see module docstring) and must not depend on the consuming
    # script's top-level `import re` actually being present.

    if isinstance(value, str):
        items = re.split(r"[,\s]+", value)
    elif isinstance(value, list):
        items = value
    else:
        items = []
    techniques = set()
    for item in items:
        if item is None:
            continue
        candidate = str(item).strip().upper()
        if not candidate:
            continue
        if not re.match(GUARDIAN_TECHNIQUE_PATTERN_STR, candidate):
            continue
        techniques.add(candidate.split(".")[0])
    return sorted(techniques)


def guardian_estimate_tokens(text):
    """Bias-low token estimate for a chunk of text.

    Uses the ``chars / 4`` heuristic Guardian uses throughout (matches
    typical English/code tokenization closely enough for budgeting), plus a
    flat ``+5`` so short/empty strings never estimate to zero tokens (message
    envelopes, role markers, etc. always cost a handful of tokens even when
    the payload is empty).

    :param text: The text to estimate. Non-strings are JSON-serialized first
        (so callers can pass a dict/list tool result directly).
    :return: Estimated token count.
    :rtype: ``int``
    """
    import json  # defensive: see guardian_execute's identical local import
    # -- this injected block must not depend on the consuming script's
    # top-level `import json` actually being present.

    if text is None:
        text = ""
    elif not isinstance(text, str):
        text = json.dumps(text, default=str)
    return (len(text) // 4) + 5


def _guardian_is_sensitive_key(key, sensitive_substrings):
    """Return ``True`` if ``key`` (a dict key) looks secret-ish."""
    if not isinstance(key, str):
        return False
    lowered = key.lower()
    return any(substr in lowered for substr in sensitive_substrings)


def _guardian_redact_value(key, value, sensitive_substrings):
    """Redact a single value, recursing into dicts and lists.

    ``key`` is ``None`` for list elements, which have no key name to check —
    those are never masked and are never length-capped either: this function
    only shortens a string when it is substituting the redaction mask itself
    (see ``GUARDIAN_MAX_VALUE_LEN``). A non-secret string is returned exactly
    as given, no matter how long, so legitimate tool output and evidence is
    never silently truncated before it reaches the model or an analyst.

    Leaf-key scope: only a **leaf** string value whose own dict key matches a
    sensitive substring is masked. A sensitive parent key whose value is
    itself a dict or list is recursed into (not masked wholesale), so a nested
    leaf with a non-matching key name is not masked even under a
    sensitive-looking parent, e.g. ``{"credentials": {"value": "secret"}}``
    leaves ``"secret"`` untouched because the leaf key is ``"value"``, not
    ``"credentials"``. This is an intentional limitation of the leaf-key
    design.
    """
    if isinstance(value, dict):
        return _guardian_redact_walk(value, sensitive_substrings)
    if isinstance(value, list):
        return [_guardian_redact_value(None, item, sensitive_substrings) for item in value]
    if isinstance(value, str):
        if key is not None and _guardian_is_sensitive_key(key, sensitive_substrings):
            return GUARDIAN_REDACTED_VALUE[:GUARDIAN_MAX_VALUE_LEN]
        return value
    return value


def _guardian_redact_walk(obj, sensitive_substrings):
    if isinstance(obj, dict):
        return {k: _guardian_redact_value(k, v, sensitive_substrings) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_guardian_redact_value(None, item, sensitive_substrings) for item in obj]
    return obj


def guardian_redact(obj, extra_keys=None):
    """Redact secret-ish values and cap oversized strings, recursively.

    Applied **at capture time** (before anything is written to Context, the
    War Room, or an audit row) — never as a post-hoc scrub, since a scrub
    that only checks top-level keys misses nested secrets.

    Behavior:

    - Any dict value whose **key name** contains one of
      ``GUARDIAN_SENSITIVE_KEY_SUBSTRINGS`` (plus ``extra_keys``, if given),
      case-insensitively, is replaced with ``"***"`` — but only if the value
      is itself a string (non-string secrets, e.g. a nested dict of
      credentials, are recursed into instead of masked wholesale, which means
      a non-matching **leaf** key nested under a sensitive-looking parent key
      is NOT masked — see ``_guardian_redact_value`` for an example).
    - Every other string value is returned **unchanged, uncapped** — this
      function does NOT size-cap generic tool output; that is a separate
      16KB mechanism in GuardianToolBridge. Capping here would risk silently
      truncating legitimate evidence before the model/analyst sees it.
    - Dicts and lists are walked recursively; non-string/dict/list scalars
      (int, float, bool, ``None``) pass through unchanged.

    :param obj: The value to redact — typically a tool-call args/result
        dict, but any JSON-like structure is accepted.
    :param extra_keys: Additional sensitive key substrings (case-insensitive)
        to merge with the built-in list, for callers with domain-specific
        secret field names.
    :type extra_keys: ``list`` or ``None``
    :return: A redacted deep copy of ``obj``. The input is never mutated.
    """
    sensitive_substrings = tuple(s.lower() for s in GUARDIAN_SENSITIVE_KEY_SUBSTRINGS)
    if extra_keys:
        sensitive_substrings = sensitive_substrings + tuple(s.lower() for s in extra_keys)
    return _guardian_redact_walk(obj, sensitive_substrings)


#: Regex pattern STRINGS (not pre-compiled: this module-level block must stay
#: usable with nothing bound at parse time beyond plain string/tuple literals)
#: used to mask common secret shapes inside a FREE-FORM string -- the
#: scalar-string counterpart to ``guardian_redact``'s structural, key-based
#: masking (which only touches a dict VALUE found under a sensitive KEY, and
#: cannot help with a secret sitting inside an arbitrary string's own
#: contents, e.g. raw error text an upstream integration returned). Applied in
#: this order by ``guardian_scrub_secrets``:
#: 1. ``Authorization: Bearer <token>`` headers -- matched WHOLE (keyword +
#:    token together) before the generic key=value rule below gets a chance
#:    to partially match just the word "Bearer" as if it were the secret
#:    value and leave the real token behind unmasked.
#: 2. Common provider API-key prefixes (OpenAI/Stripe-style ``sk-``/``pk-``/
#:    ``rk-``, GitHub's ``ghp-``/``gho-``/``ghu-``/``ghs-``, Slack's
#:    ``xox[baprs]-``, ...).
#: 3. ``key=value`` / ``key: value`` pairs where ``key`` looks secret-ish.
#:    Deliberately excludes "authorization" from this keyword list -- the
#:    dedicated Bearer pattern above already owns that phrasing, and letting
#:    both patterns compete over the same text is what causes the
#:    partial-match problem described above.
#: 4. Connection-string passwords (``scheme://user:PASSWORD@host``) -- masks
#:    only the password segment, so the (non-secret) username stays legible.
#: 5. Any other long (20+ char) contiguous base64/hex-alphabet run that ALSO
#:    contains at least one digit, as a catch-all -- intentionally broad
#:    (silent leakage is the worse failure mode here, the same tradeoff
#:    ``guardian_redact``'s own key-substring matching), but the digit
#:    requirement is a deliberate, narrow guard against the most common false
#:    positive this catch-all would otherwise produce: a plain
#:    lowercase_with_underscores identifier (e.g. a List name like
#:    ``guardian_tool_denylist`` -- 22 characters, past the 20-char floor, and
#:    made up entirely of characters this charset allows) that is not a secret
#:    at all. Real tokens and hashes overwhelmingly contain at least one
#:    digit; a plain identifier typically does not.
#:    With ``keep_identifiers=True`` (opt-in, for text Guardian itself writes
#:    -- case notes, memory values) rule 5 alone skips a matched token that
#:    is a plain identifier: a UUID, a bare 40/64-hex hash or asset id, or a
#:    multi-part name (see ``_guardian_is_plain_identifier``). Rules 1-4 are
#:    unaffected by the flag, except that a cloud resource id (Azure / AWS ARN /
#:    GCP path, see ``_GUARDIAN_RESOURCE_ID_PATTERN_STR``) is lifted out first and
#:    restored last, so no rule can mask a slice of it.
_GUARDIAN_BEARER_PATTERN_STR = r"(?i)\bbearer\s+[A-Za-z0-9._-]{10,}"
_GUARDIAN_PROVIDER_KEY_PATTERN_STR = r"\b(?:sk|pk|rk|ghp|gho|ghu|ghs|xox[baprs])-[A-Za-z0-9_-]{10,}"
_GUARDIAN_SECRET_KV_PATTERN_STR = (
    r"(?i)\b(api[_-]?key|apikey|access[_-]?key|secret[_-]?key|token|password|passwd|pwd|secret|"
    r"client[_-]?secret|private[_-]?key)\b(\s*[:=]\s*)(['\"]?)([^\s'\",;]{3,})(['\"]?)"
)
_GUARDIAN_CONN_STRING_PASSWORD_PATTERN_STR = r"(://[^:@/\s]+:)([^@/\s]+)(@)"
_GUARDIAN_LONG_TOKEN_PATTERN_STR = (
    r"(?<![A-Za-z0-9+/=_-])(?=[A-Za-z0-9+/=_-]*[0-9])[A-Za-z0-9+/=_-]{20,}(?![A-Za-z0-9+/=_-])"
)
# Identifier shapes that ``guardian_scrub_secrets(keep_identifiers=True)``
# lets through rule 5. UUID: 8-4-4-4-12 hex, either case. Hash/asset id:
# EXACTLY 40 (sha1) or 64 (sha256) hex chars -- 32 hex (md5-sized, also a
# common secret length) stays masked. A multi-part name is split on ``-``
# and ``_`` only; every part must match the word-like pattern: all
# lowercase, all uppercase, one-or-more Capitalized words (letters only),
# all digits, or any alphanumeric part of at most 4 characters (a lowercase-letters-then-digits part such as ``nodepool1`` only beside a 6+ digit part); and at least
# one part must be letters-only with 3+ characters.
_GUARDIAN_UUID_PATTERN_STR = (
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_GUARDIAN_HEX_ID_PATTERN_STR = r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})"
_GUARDIAN_NAME_PART_PATTERN_STR = r"(?:[a-z]+|[A-Z]+|(?:[A-Z][a-z]+)+|[0-9]+|[A-Za-z0-9]{1,4})"
_GUARDIAN_POOL_PART_PATTERN_STR = r"[a-z]+[0-9]{1,4}"
# A part may also be lowercase letters followed by 1-4 digits (``nodepool1``) but ONLY in a token
# that also has an all-digit part of 6+ digits: the default AKS node-pool scale set
# ``aks-nodepool1-<8 digits>-vmss[_<n>]``. Without that hash a generated passphrase such as
# ``word-word7-word`` would be kept, so it stays masked.
# A token that starts with a provider key prefix is never a name (``ghp_...``, ``AKIA-...``).
_GUARDIAN_KEY_PREFIX_PATTERN_STR = r"(?i:sk|pk|rk|ghp|gho|ghu|ghs|ghr|github|xox[a-z]?|akia)"
# Cloud resource identifiers kept by ``guardian_scrub_secrets(keep_identifiers=True)``
# (never rule 5's catch-all: its charset includes ``/`` so it would mask a path up
# to its first ``.``). Each shape is anchored on a fixed provider prefix and only
# spans path-safe characters -- a trailing ``.`` / ``:`` (end of sentence) is left
# outside, and ``=``, ``?``, ``&`` and whitespace end the id. Azure:
# ``/subscriptions/<uuid>/...``. AWS: ``arn:aws[-partition]:service:region:account:resource``.
# GCP: ``projects/<id>/...`` (optionally the full ``//<svc>.googleapis.com/`` name).
_GUARDIAN_RESOURCE_ID_PATTERN_STR = (
    r"(?<![A-Za-z0-9_.:/-])(?:"
    r"/(?i:subscriptions)/" + _GUARDIAN_UUID_PATTERN_STR + r"(?:/[A-Za-z0-9._()~-]*[A-Za-z0-9_)])*"
    r"|arn:aws(?:-[a-z]+)*:[a-z0-9-]*:[a-z0-9-]*:[0-9]*:[A-Za-z0-9_./:*+@-]*[A-Za-z0-9_*]"
    r"|(?://[a-z0-9.-]+\.googleapis\.com/)?projects/[A-Za-z0-9_.-]*[A-Za-z0-9_](?:/[A-Za-z0-9._-]*[A-Za-z0-9_])+"
    r")"
)
_GUARDIAN_RESOURCE_PLACEHOLDER = "\x00GRID{}\x00"
# The secret shape looked for INSIDE a kept resource id: an unbroken run of 20+ base64-alphabet
# characters (no ``-`` or ``_``, so the parts of a name such as ``vm_OsDisk_1_<32 hex>`` are
# separate runs) that has an uppercase letter and a digit -- an access key, a base64 secret.
# All-lowercase runs (a storage account name, an ECS task id, a managed-disk hex suffix) are
# resource names and are kept, so a lowercase hex secret inside an id survives; a provider
# key (``sk-...``) is masked by its own rule.
_GUARDIAN_RESOURCE_SEGMENT_TOKEN_PATTERN_STR = r"[A-Za-z0-9+/=]{20,}"


def _guardian_is_plain_identifier(token):
    """True if ``token`` (a rule-5 catch-all match) is a plain identifier --
    a UUID, a 40/64-hex hash, or a multi-part name -- rather than a probable
    secret. See the ``_GUARDIAN_*_PATTERN_STR`` constants above for the exact
    shapes. A token containing ``/``, ``+`` or ``=`` is never a multi-part
    name (base64 secrets), an empty part (``a--b``) disqualifies it, and at
    least one part must be letters-only with 3+ characters.
    """
    import re  # defensive: see guardian_scrub_secrets

    if re.fullmatch(_GUARDIAN_UUID_PATTERN_STR, token) or re.fullmatch(_GUARDIAN_HEX_ID_PATTERN_STR, token):
        return True
    if "/" in token or "+" in token or "=" in token:
        return False
    parts = re.split(r"[-_]", token)
    if len(parts) < 3:
        return False
    if re.fullmatch(_GUARDIAN_KEY_PREFIX_PATTERN_STR, parts[0]):
        return False
    has_hash = any(re.fullmatch(r"[0-9]{6,}", part) for part in parts)
    if not all(
        re.fullmatch(_GUARDIAN_NAME_PART_PATTERN_STR, part)
        or (has_hash and re.fullmatch(_GUARDIAN_POOL_PART_PATTERN_STR, part))
        for part in parts
    ):
        return False
    # At least one real word (3+ letters): keeps product-key / recovery-code shapes such as
    # ``a1b2-c3d4-e5f6-g7h8-i9j0`` and digit-only runs masked.
    return any(re.fullmatch(r"[A-Za-z]{3,}", part) for part in parts)


def _guardian_scrub_resource_id(resource_id):
    """Mask a secret hiding inside ONE cloud resource id lifted by ``keep_identifiers``.

    The id is checked segment by segment (split on ``/`` and ``:``, the separators are kept).
    A segment is masked where it carries a provider key (``sk-...``) or an unbroken 20+
    character run with both an uppercase letter and a digit (see
    ``_GUARDIAN_RESOURCE_SEGMENT_TOKEN_PATTERN_STR``). GUIDs, resource-group names and
    resource names -- storage accounts, managed-disk names, ECS task ids -- survive, so the id
    stays usable as a ``resource=`` argument. The cost: a lowercase hex secret inside an id is kept.

    :param resource_id: A resource id matched by ``_GUARDIAN_RESOURCE_ID_PATTERN_STR``.
    :type resource_id: ``str``
    :return: The id with any secret segment replaced by ``***``.
    :rtype: ``str``
    """
    import re  # defensive: see guardian_scrub_secrets

    def _mask_run(match):
        run = match.group(0)
        if re.search(r"[A-Z]", run) and re.search(r"[0-9]", run):
            return GUARDIAN_REDACTED_VALUE
        return run

    pieces = re.split(r"([/:])", resource_id)
    for index in range(0, len(pieces), 2):
        segment = re.sub(_GUARDIAN_PROVIDER_KEY_PATTERN_STR, GUARDIAN_REDACTED_VALUE, pieces[index])
        pieces[index] = re.sub(_GUARDIAN_RESOURCE_SEGMENT_TOKEN_PATTERN_STR, _mask_run, segment)
    return "".join(pieces)


def guardian_scrub_secrets(text, keep_identifiers=False):
    """Pattern-mask common secret shapes inside a FREE-FORM string.

    ``guardian_redact`` structurally cannot help here -- it only ever masks
    a dict VALUE whose own KEY looks secret-ish, never scans an arbitrary
    string's contents. This is the complementary layer for exactly that
    case: a failing tool call's flattened error text is free-form (a raw
    HTTP error body, a driver exception message, an upstream integration
    echoing back what it rejected) and real examples routinely embed a
    credential directly in the sentence, e.g. ``"401 Unauthorized: invalid
    api_key 'sk-abc123...'"`` or a DB connection string with an embedded
    password. See the module-level pattern constants just above this
    function for the exact shapes matched and the order they are applied in
    (order matters -- more specific patterns run first so a generic rule
    cannot partially match a keyword like "Bearer" and leave the real token
    next to it unmasked).

    Every match is replaced with ``"***"`` -- the whole match for the
    provider-key-prefix/bearer/catch-all patterns (nothing worth preserving
    around those), but only the captured secret VALUE for the key=value and
    connection-string patterns, so surrounding context (e.g. ``"password="``,
    the connection string's username) stays legible for a human/analyst
    reading the scrubbed text.

    :param text: The text to scrub.
    :type text: ``str`` or ``None``
    :param keep_identifiers: Default ``False`` keeps the strict catch-all
        (right for error and tool-failure text, where unlabelled keys leak).
        ``True`` makes the catch-all (rule 5 only) skip plain identifiers --
        UUIDs, 40/64-hex hashes and asset ids, multi-part names such as
        ``STATUS_250_RESOLVED_FIXED`` -- for text Guardian writes itself (case
        notes, memory) where a SOC needs those ids. Cloud resource ids (Azure
        ``/subscriptions/<uuid>/...``, AWS ``arn:aws...``, GCP ``projects/...``) are also
        kept, including as a ``resource=`` value, except that a ``/``- or ``:``-separated
        segment holding a provider key or a long mixed-case token with a digit is masked (a GUID,
        a resource-group name or a resource name is kept). Rules 1-4 still mask a secret anywhere outside
        those id spans.
    :type keep_identifiers: ``bool``
    :return: The scrubbed string, or the original value unchanged if it was
        falsy (``None``/``""`` -- nothing to scrub).
    :rtype: ``str`` or the original falsy value
    """
    import re  # defensive: this block is injected verbatim into other
    # scripts (see module docstring) and must not depend on the consuming
    # script's top-level `import re` actually being present.

    if not text:
        return text

    def _mask_kv(match):
        return "{}{}{}{}{}".format(
            match.group(1), match.group(2), match.group(3), GUARDIAN_REDACTED_VALUE, match.group(5)
        )

    def _mask_conn_string(match):
        return "{}{}{}".format(match.group(1), GUARDIAN_REDACTED_VALUE, match.group(3))

    # keep_identifiers: lift cloud resource ids out of the text behind NUL-delimited
    # placeholders (no rule's charset matches NUL), scrub the rest, then put them back.
    # A secret next to an id (``?sig=...``, ``key sk-...``) is still outside the span.
    resource_ids = []
    if keep_identifiers:

        def _lift_resource_id(match):
            resource_ids.append(_guardian_scrub_resource_id(match.group(0)))
            return _GUARDIAN_RESOURCE_PLACEHOLDER.format(len(resource_ids) - 1)

        text = re.sub(_GUARDIAN_RESOURCE_ID_PATTERN_STR, _lift_resource_id, text)

    scrubbed = re.sub(_GUARDIAN_BEARER_PATTERN_STR, "Bearer {}".format(GUARDIAN_REDACTED_VALUE), text)
    scrubbed = re.sub(_GUARDIAN_PROVIDER_KEY_PATTERN_STR, GUARDIAN_REDACTED_VALUE, scrubbed)
    scrubbed = re.sub(_GUARDIAN_SECRET_KV_PATTERN_STR, _mask_kv, scrubbed)
    scrubbed = re.sub(_GUARDIAN_CONN_STRING_PASSWORD_PATTERN_STR, _mask_conn_string, scrubbed)
    def _mask_long_token(match):
        token = match.group(0)
        if keep_identifiers and _guardian_is_plain_identifier(token):
            return token
        return GUARDIAN_REDACTED_VALUE

    scrubbed = re.sub(_GUARDIAN_LONG_TOKEN_PATTERN_STR, _mask_long_token, scrubbed)
    for index, resource_id in enumerate(resource_ids):
        scrubbed = scrubbed.replace(_GUARDIAN_RESOURCE_PLACEHOLDER.format(index), resource_id)
    return scrubbed


def guardian_ctx_read(key, default=None):
    """Read a value from incident Context under the ``Guardian.<key>``
    namespace.

    :param key: Dotted sub-path under the ``Guardian`` namespace (e.g.
        ``"state.tick_count"`` reads ``Guardian.state.tick_count``).
    :type key: ``str``
    :param default: Returned if the path isn't present.
    :return: The stored value, or ``default``.
    """
    ctx = demisto.context() or {}
    return demisto.get(ctx, f"{GUARDIAN_CONTEXT_NAMESPACE}.{key}", default)


def guardian_ctx_write(key, value):
    """Write a value to incident Context under the ``Guardian.<key>``
    namespace via ``demisto.setContext``.

    :param key: Dotted sub-path under the ``Guardian`` namespace (e.g.
        ``"state.tick_count"`` writes ``Guardian.state.tick_count``).
    :type key: ``str``
    :param value: The value to store (must be JSON-serializable — Context is
        persisted server-side as JSON).
    :return: The raw ``demisto.setContext`` result (``{"status": True}`` on
        the mock; the real server returns an operation-result object).
    """
    return demisto.setContext(f"{GUARDIAN_CONTEXT_NAMESPACE}.{key}", value)


#: `demisto-api-post`'s primary command name, plus the `core-api-post` alias
#: some servers expose instead (both take the same `uri`/`body` args and wrap
#: the raw HTTP response under a `"response"` key). Tried in this order; the
#: second is only attempted if the first looks unregistered, never as a blind
#: retry of a real failure.
_GUARDIAN_REST_POST_COMMANDS = ("demisto-api-post", "core-api-post")


def _guardian_rest_last_contents(entries):
    """Pull the last non-``None`` ``Contents`` value out of an
    `executeCommand` entry list. A private, block-local copy of the small
    reducer that Guardian scripts keep for themselves -- underscore-prefixed
    and scoped to this REST helper so it can never collide with a consuming
    script's own identically-shaped local helper once this block is copied
    into that script.
    """
    contents = None
    for entry in entries or []:
        if isinstance(entry, dict) and entry.get("Contents") is not None:
            contents = entry["Contents"]
    return contents


def _guardian_rest_post(uri, body_obj):
    """POST `body_obj` (JSON-serialized here) to XSOAR's own REST API at
    `uri`, via the Core REST API integration.

    Tries ``demisto-api-post`` first, falling back to ``core-api-post`` only
    when the FIRST attempt's error text suggests the command itself isn't
    registered on this server (e.g. the "was not found in module" wording
    XSOAR emits for an unknown command/script name) or the raw
    `executeCommand` call itself raised. Any OTHER failure (an HTTP 4xx/5xx
    the API itself returned, an optimistic-lock error, an auth failure) is a
    real error that is surfaced as-is -- never masked behind a second, blind
    attempt with the other command name.

    :param uri: The XSOAR REST path, e.g. ``"/incidents/search"``,
        ``"/incident"``.
    :type uri: ``str``
    :param body_obj: The JSON request body as a plain Python dict/list --
        callers never pre-serialize it themselves.
    :return: A :func:`guardian_envelope`; ``data`` on success is the
        PARSED response body (the integration's own inner ``"response"``
        payload -- e.g. the raw ``/incidents/search`` or ``/incident`` JSON,
        never the ``executeCommand`` entry-list wrapper). An entry whose
        ``Contents`` isn't a dict carrying a dict-shaped ``"response"`` (e.g.
        a bad `uri` silently falling through to the server's HTML SPA shell)
        is itself treated as a failure -- Type != 4 alone is NOT proof of a
        usable REST response.
    :rtype: ``dict``
    """
    import json  # defensive: this block is injected verbatim into other
    # scripts (see module docstring) and must not depend on the consuming
    # script's top-level `import json` actually being present.

    body_json = json.dumps(body_obj, default=str)
    last_result = None
    for command in _GUARDIAN_REST_POST_COMMANDS:
        result = guardian_execute(command, {"uri": uri, "body": body_json})
        if result["ok"]:
            contents = _guardian_rest_last_contents(result["data"])
            response = contents.get("response") if isinstance(contents, dict) else None
            if not isinstance(response, dict):
                return guardian_envelope(
                    False,
                    error="{} succeeded but returned an unexpected response shape for {}".format(command, uri),
                )
            return guardian_envelope(True, data=response)

        last_result = result
        error_text = (result.get("error") or "").lower()
        looks_unregistered = (
            "not found in module" in error_text
            or "unsupported command" in error_text  # "Unsupported Command : demisto-api-post , verify you have proper integration enabled"
            or "executecommand raised for" in error_text
        )
        if not looks_unregistered:
            return guardian_envelope(
                False,
                error="{} failed for {}: {}".format(command, uri, result["error"]),
                retryable=result["retryable"],
                is_auth_error=result["is_auth_error"],
            )
        # else: this command looks unregistered on this server -- try the next
        # alias in _GUARDIAN_REST_POST_COMMANDS before giving up.

    return guardian_envelope(
        False,
        error="no Core REST API command available for {} (tried {})".format(
            uri, ", ".join(_GUARDIAN_REST_POST_COMMANDS)
        ),
        retryable=(last_result or {}).get("retryable", False),
    )


def guardian_set_incident_fields(incident_id, fields, details=None):
    """Persist `fields` onto an incident's `CustomFields` via the REST
    full-object merge -- the only form that reliably persists custom-field
    writes: the `setIncident` COMMAND form silently fails for custom fields
    (it returns "missing argument (7)", or a bare "done" with nothing
    persisted), while `POST /incident` (a full-object upsert -- a partial
    body is treated as a create and fails) persists when given the
    incident's current full object with the merged `CustomFields`.

    This is meant for a script's own harness-internal bookkeeping (cost,
    tick-count, and similar telemetry the reasoning loop keeps on itself --
    never a value a model's tool call asked for). That bookkeeping includes
    the reasoning loop's own fixed-allowlist verdict self-assessment written
    at conclusion (`guardianverdict`/`guardianconfidence`/
    `guardianattacktechniques`/`guardianblastradius`, built key-by-key from
    four hardcoded cliNames by `guardian_tick_write_verdict_telemetry` --
    never the parsed block passed through whole, so no extra model-authored
    key can smuggle a CustomField write). This helper therefore deliberately
    bypasses GuardianToolBridge/`guardian_policy`: `guardian_policy` gates a
    bare `setIncident` as `require_approval` for ANY target (the right
    default for a model-requested field edit), which would wrongly park the
    harness's own telemetry writes behind a human approval gate. A
    model-requested incident-field edit must still go through
    GuardianToolBridge, never this helper.

    Sequence: read the incident fresh (`/incidents/search` by `filter.id`),
    merge `fields` into its `CustomFields` (capital C, keyed by lowercase
    cliName), `POST /incident` with the FULL merged object. On a detected
    `errOptimisticLock` failure (the version drifted between this helper's
    own read and write -- a narrow race window, since read-then-write is not
    atomic), retries the whole read-merge-write cycle once with a fresh read
    before giving up. Never raises -- every failure mode (incident not found,
    a REST error, a malformed response shape) resolves to a
    :func:`guardian_envelope`.

    :param incident_id: The incident id to update (e.g.
        ``demisto.incident().get("id")``).
    :type incident_id: ``str`` or ``int``
    :param fields: ``{cliName: value}`` to merge into `CustomFields`.
        Number-typed Guardian fields (``guardiancostusd``,
        ``guardianconfidence``, ``guardiantickcount``, ...) MUST be passed as
        a real ``int``/``float``, never a numeric string -- this helper
        merges values exactly as given, it does not coerce types.
    :type fields: ``dict``
    :param details: Optional, for an operator-owned writer of the incident's
        top-level ``details`` text (GuardianIncidentSummary). A function that
        takes the ``details`` text of the record this helper has just read and
        returns the new text, or ``None`` to leave it unchanged. It is called
        on every attempt with that attempt's fresh read, so a retry after an
        optimistic-lock collision rebuilds the text from the newest record
        and never writes over a change made in between. It is called only when
        the record holds ``details`` as a string (an empty string counts): a
        record without it is not written, because an empty text cannot be
        assumed. No other top-level field is ever changed by this helper.
    :type details: ``callable`` or ``None``
    :return: A :func:`guardian_envelope`; ``data`` on success is
        ``{"id": incident_id, "fields": fields}``, plus ``"details_written"``
        (whether the details text was changed) when `details` is given.
    :rtype: ``dict``
    """
    if not incident_id:
        return guardian_envelope(False, error="guardian_set_incident_fields: missing incident_id")
    if not fields and details is None:
        return guardian_envelope(True, data={"id": incident_id, "fields": {}})

    last_error = None
    last_retryable = False
    last_is_auth_error = False
    for _attempt in range(2):  # one retry on a detected optimistic-lock collision
        read_result = _guardian_rest_post("/incidents/search", {"filter": {"id": [str(incident_id)]}})
        if not read_result["ok"]:
            return guardian_envelope(
                False,
                error="guardian_set_incident_fields: incident read failed: {}".format(read_result["error"]),
                retryable=read_result["retryable"],
                is_auth_error=read_result["is_auth_error"],
            )

        response = read_result["data"]
        records = response.get("data") if isinstance(response, dict) else None
        if not records or not isinstance(records[0], dict):
            return guardian_envelope(
                False, error="guardian_set_incident_fields: incident '{}' not found".format(incident_id)
            )

        incident = records[0]
        details_written = False
        if details is not None:
            current = incident.get("details")
            if not isinstance(current, str):
                return guardian_envelope(
                    False, error="guardian_set_incident_fields: incident '{}' was read without its details text, so "
                                 "the details are not written".format(incident_id)
                )
            try:
                new_details = details(current)
            except Exception as exc:  # the caller's builder must never turn into a raise here
                return guardian_envelope(
                    False, error="guardian_set_incident_fields: building the new details failed: {}".format(exc)
                )
            if isinstance(new_details, str) and new_details != current:
                incident["details"] = new_details
                details_written = True
        if fields:
            custom_fields = incident.get("CustomFields")
            custom_fields = dict(custom_fields) if isinstance(custom_fields, dict) else {}
            custom_fields.update(fields)
            incident["CustomFields"] = custom_fields
        data = {"id": incident_id, "fields": fields or {}}
        if details is not None:
            data["details_written"] = details_written
            if not fields and not details_written:
                return guardian_envelope(True, data=data)

        write_result = _guardian_rest_post("/incident", incident)
        if write_result["ok"]:
            return guardian_envelope(True, data=data)

        last_error = write_result["error"]
        last_retryable = write_result["retryable"]
        last_is_auth_error = write_result["is_auth_error"]
        if "optimistic lock" not in (last_error or "").lower() and "erroptimisticlock" not in (
            last_error or ""
        ).lower():
            # Not a version-collision -- a second attempt would fail exactly
            # the same way, so don't spend it.
            break

    return guardian_envelope(
        False,
        error="guardian_set_incident_fields: incident write failed: {}".format(last_error),
        retryable=last_retryable,
        is_auth_error=last_is_auth_error,
    )


# ---------------------------------------------------------------------------
# The model catalogue (`guardian_model_catalog`): lookup. A model is found by id or alias; the lookup lives
# here, in the shared block, because every script that reads the run's model numbers resolves the model's size
# class from the catalogue (see guardian_resolve_model_params), not only the four that handle documented limits.
# ---------------------------------------------------------------------------

GUARDIAN_CATALOG_LIST_NAME = "guardian_model_catalog"

#: Alias prefixes that name a platform. `foundry:Cohere-command-a` is the alias `Cohere-command-a`; a
#: colon after any other word (`command-r:35b`) is part of the name, not a prefix.
GUARDIAN_CATALOG_ALIAS_PREFIXES = ("foundry", "bedrock", "vertex", "hf", "oci", "ollama")

#: The Foundry "Model" dropdown: this choice means "use the free-text deployment name instead".
GUARDIAN_CATALOG_CHOICE_PARAM = "model_choice"
GUARDIAN_CATALOG_CHOICE_CUSTOM = "Custom (use the deployment name below)"

_GUARDIAN_CATALOG_DATE_SUFFIXES = (
    r"[-@](\d{4})-(\d{2})-(\d{2})$",
    r"[-@](\d{4})(\d{2})(\d{2})$",
    r"[-@](\d{2})(\d{2})$",
)


def _guardian_catalog_strip_date(name):
    """Remove a trailing dated suffix: -YYYY-MM-DD, -YYYYMMDD, @YYYYMMDD or -MMDD. The month must be
    01-12 and the day 01-31, so a year-month suffix such as -2506 is not taken for a date."""
    import re  # defensive local import: this block is injected into scripts that may not import re
    for pattern in _GUARDIAN_CATALOG_DATE_SUFFIXES:
        match = re.search(pattern, name)
        if match:
            month, day = int(match.group(match.lastindex - 1)), int(match.group(match.lastindex))
            if 1 <= month <= 12 and 1 <= day <= 31:
                return name[:match.start()]
    return name


def _guardian_catalog_strip_prefix(name):
    """Remove a provider path prefix: publishers/google/models/x, models/x or meta/llama-x -> the last segment."""
    return name.rsplit("/", 1)[-1] if "/" in name else name


def _guardian_catalog_candidates(name):
    """The strings to try for ``name``, in order: exact, dated suffix removed, provider prefix removed,
    both removed. Lower-cased, de-duplicated."""
    base = str(name or "").strip().lower()
    if not base:
        return []
    unprefixed = _guardian_catalog_strip_prefix(base)
    ordered = [base, _guardian_catalog_strip_date(base), unprefixed, _guardian_catalog_strip_date(unprefixed)]
    seen = []
    for item in ordered:
        if item and item not in seen:
            seen.append(item)
    return seen


def _guardian_catalog_index(catalog):
    """``(strong, weak)`` lookup tables, lower-cased key -> model. Strong keys are the ids, the aliases as
    stored, and the exact ids of versioned provider rows; weak keys are aliases with their platform prefix
    removed. The first model in the List wins a key."""
    strong, weak = {}, {}
    models = catalog.get("models") if isinstance(catalog, dict) else None
    for model in models if isinstance(models, list) else []:
        if not isinstance(model, dict) or not isinstance(model.get("id"), str):
            continue
        strong.setdefault(model["id"].lower(), model)
        for alias in model.get("aliases") or []:
            if not isinstance(alias, str):
                continue
            strong.setdefault(alias.lower(), model)
            prefix, separator, rest = alias.partition(":")
            if separator and rest and prefix.lower() in GUARDIAN_CATALOG_ALIAS_PREFIXES:
                weak.setdefault(rest.lower(), model)
        for row in model.get("provider_limits") or []:
            for version in (row.get("versions") or []) if isinstance(row, dict) else []:
                if isinstance(version, str):
                    strong.setdefault(version.lower(), model)
    return strong, weak


def guardian_catalog_lookup(catalog, name):
    """The catalogue model for ``name``, or ``None``. Case-insensitive, on the id or any alias.

    The exact name is tried first; then with a dated suffix removed (-YYYY-MM-DD, -YYYYMMDD, @YYYYMMDD,
    -MMDD); then with a provider prefix removed (publishers/google/models/x, meta/llama-x, models/x).

    :param catalog: The parsed List: ``{"checked": "...", "models": [...]}``.
    :param name: A configured or provider-reported model name.
    :return: The model dict, or ``None``.
    """
    strong, weak = _guardian_catalog_index(catalog)
    for candidate in _guardian_catalog_candidates(name):
        model = strong.get(candidate) or weak.get(candidate)
        if model is not None:
            return model
    return None


def guardian_catalog_configured_model(params):
    """The model an integration instance is configured to call, from its parameter list
    (``[{"name", "value"}, ...]``): the Foundry "Model" dropdown choice unless it is the Custom option,
    else the free-text model / deployment name. ``None`` when neither is set."""
    choice, model = None, None
    for param in params if isinstance(params, list) else []:
        if not isinstance(param, dict):
            continue
        if param.get("name") == GUARDIAN_CATALOG_CHOICE_PARAM:
            choice = param.get("value")
        elif param.get("name") == "model":
            model = param.get("value")
    choice = choice.strip() if isinstance(choice, str) else ""
    if choice and choice != GUARDIAN_CATALOG_CHOICE_CUSTOM:
        return choice
    model = model.strip() if isinstance(model, str) else ""
    return model or None


def guardian_catalog_parse(contents):
    """The catalogue dict from a ``getList`` entry's ``Contents`` (a JSON string or a dict), or ``None``."""
    import json  # defensive: the consuming script may not import it at the top
    if isinstance(contents, str):
        try:
            contents = json.loads(contents)
        except ValueError:
            return None
    if isinstance(contents, dict) and isinstance(contents.get("models"), list):
        return contents
    return None


def guardian_catalog_load():
    """Read the `guardian_model_catalog` List. Never raises; a missing or unreadable List gives ``None``
    (the callers then fall back to the probe, as before the catalogue existed)."""
    result = guardian_execute("getList", {"listName": GUARDIAN_CATALOG_LIST_NAME})
    if not result["ok"]:
        return None
    contents = None
    for entry in result["data"] or []:
        if isinstance(entry, dict) and entry.get("Contents") is not None:
            contents = entry["Contents"]
    return guardian_catalog_parse(contents)


#: Model-size profiles: the knobs that relax as the model gets more capable. Keyed by the same string an
#: operator picks on the LLM provider integration's "Model size" dropdown (the `model_tier` parameter of
#: GuardianCohere), so there is one vocabulary end to end (dropdown option -> guardian_settings.model_tier /
#: the catalogue's size_class -> this dict's keys -> the audit row / !guardian-model output). Which key a run
#: uses is worked out by guardian_resolve_model_params: the operator's pin, else the model's size in the model
#: catalogue, else guardian_settings.model_tier, else "small".
#:
#: What a profile contains: tool-catalogue breadth and verbosity, and how aggressively the loop recovers
#: from degenerate turns. What no profile ever contains, at any size: every GuardianToolBridge dispatch
#: gate (kill-switch, denylist, allowlist, policy, approval), audit, cost accounting, the
#: repeated-call and runaway-cost backstops (max_same_call, max_repeats, MAX_TICKS), grounding
#: (guardian_tick_incident_context_message, and guardian_bridge_run_set_incident ignoring the model's own
#: `id`), and every anti-fabrication prompt rule. Those are security controls and correctness invariants,
#: and none of them may be keyed off this table. Sampling temperature is also absent: no LLM vendor
#: publishes model-size-specific sampling guidance, so there is nothing to tier it against.
#:
#:   - ``tier0_gate``: whether guardian_tick_select_catalog_tier narrows tick 0's offered catalogue to the
#:     tier-0 evidence-gathering subset (see GUARDIAN_TICK_TIER0_COMMANDS in GuardianReasoningTick) until a
#:     real evidence call has succeeded. Small models return empty turns more often when offered a wide
#:     schema from tick 0; a more capable model does not, and the gate would only keep it from using
#:     findIndicators, GuardianKBSearch or parallel scoping on tick 0.
#:   - ``max_ticks``: the turn limit per run (MAX_TICKS): 25 small, 40 medium, 60 large. A larger model keeps
#:     a long transcript coherent and can use the turns; an explicit ``guardian_settings.MAX_TICKS`` or
#:     ``overrides.max_ticks`` in guardian_model_profile still wins. It is a cost backstop, not a gate.
#:   - ``max_tool_def_tokens``: the tool-schema token budget GuardianToolCatalogBuilder priority-truncates
#:     the allowlist against. It is a harness budget, not a provider-published limit (Cohere's only
#:     published catalogue constraint is the Chat V2 strict_tools 200-field cap, which this budget does not
#:     enforce). It must stay comfortably under the ``max_input_tokens`` that guardian-probe-model derives
#:     for the tier's smallest realistic context window. That formula is
#:     ``floor((window - output_reserve) * safety_margin * measured_chars_per_token/4)``, where
#:     ``output_reserve`` is read from ``guardian_settings.output_reserve_tokens``. GuardianProbeModel is
#:     the only consumer of that field; GuardianReasoningTick enforces the already-derived
#:     ``max_input_tokens`` and does not load it, so there is a single source of truth for the reserve. At
#:     "large" the smallest candidate context is 128K (Command R+ / Command A+):
#:     (128000 - 4096) * 0.85 ~= 105318 tokens remain for prompt, catalogue and transcript, so a 24000-token
#:     catalogue budget is conservative. The value here is the floor for a large model: when the input budget
#:     is known it is raised to 25% of it (never past 60% of it).
#:   - ``description_max_len``: GUARDIAN_TOOL_DESCRIPTION_MAX_LEN's per-tier value -- how hard each
#:     command description is elided before it counts against the budget above. 0 means no shortening.
#:   - ``max_same_tool``: GUARDIAN_MAX_SAME_TOOL's per-tier value -- the per-tool-NAME dispatch cap that
#:     catches a model re-issuing the same tool with varying args forever. A low cap also blocks a capable
#:     model from legitimately enriching more than a few distinct indicators of the same type in one
#:     investigation (six IPs through `ip`, say), so it is raised per tier. The exact-fingerprint
#:     repeated-call guard (max_same_call) and MAX_TICKS remain the real cost backstops regardless of this
#:     value.
#:   - ``force_tool_choice_on_empty_turn``: whether an empty turn (no content, no tool_calls) is retried
#:     with `tool_choice="required"` forced. This recovers small models that return empty turns; forcing a
#:     tool call on a larger model that legitimately wants to answer without one would over-constrain it,
#:     so it applies only at the smallest tier.
#:
#: The no-verdict corrective retry (GUARDIAN_NO_VERDICT_RETRY_LIMIT) is deliberately not in this table. A
#: model can finish with a complete, well-punctuated sentence that simply contains no verdict block (for
#: example "I am unable to provide a verdict without further information."), which a punctuation-based
#: "trailed off" check cannot detect, so gating the retry by tier would silently drop
#: guardianverdict/confidence/etc. The retry costs at most one extra tick at any model size; only a length
#: filter (skip short, legitimately terse answers like "done") applies, at every tier.
GUARDIAN_TIER_PROFILES = {
    "small": {
        "tier0_gate": True,
        # The turn limit (MAX_TICKS): the run is made to conclude after this many turns. Small models degrade on long
        # transcripts, so this is the value the pack has always shipped.
        "max_ticks": 25,
        "max_tool_def_tokens": 4000,
        "max_tool_calls_per_turn": 1,
        "description_max_len": 300,
        "max_same_tool": 3,
        "force_tool_choice_on_empty_turn": True,
    },
    "medium": {
        "tier0_gate": False,
        "max_ticks": 40,
        "max_tool_def_tokens": 16000,
        "max_tool_calls_per_turn": 1,
        "description_max_len": 600,
        "max_same_tool": 6,
        "force_tool_choice_on_empty_turn": False,
    },
    "large": {
        "tier0_gate": False,
        "max_ticks": 60,
        # The floor for a large model: guardian_resolve_model_params raises it to a share of the input budget
        # when that is larger (GUARDIAN_LARGE_TOOL_BUDGET_SHARE_PERCENT).
        "max_tool_def_tokens": 24000,
        "max_tool_calls_per_turn": 0,
        # 1024 is a provider-safety limit, not a size saving: OpenAI-family function descriptions may be limited
        # to 1024 characters, and no allowlisted command's description is longer, so nothing is lost. (0 would
        # mean "no shortening"; see guardian_shorten_tool_description.)
        "description_max_len": 1024,
        "max_same_tool": 10,
        "force_tool_choice_on_empty_turn": False,
    },
}

#: Fail-safe default when no tier can be worked out -- no operator pin, the model is not in the catalogue (or
#: its size is not stated there) and `model_tier` in guardian_settings is "auto", absent, unreadable, or not a
#: recognized key. This is the smallest, most-constrained profile. An under-performing correctly-gated agent is
#: a tuning ticket; an over-trusted mis-tiered one (a small model silently given a large model's wide-open
#: catalogue) is an incident. Never widen this default without an explicit, positive signal.
GUARDIAN_DEFAULT_MODEL_TIER = "small"

#: The value `guardian_settings.model_tier` ships with: no explicit value, so the model's size comes from the
#: model catalogue. "auto", a missing key and any unrecognized value all mean the same thing.
GUARDIAN_TIER_AUTO = "auto"


def guardian_tier_name(value):
    """The tier name in ``value`` ("small", "medium" or "large", any case), else ``None``. ``"auto"``, blank,
    a non-string and an unrecognized string are all ``None``: "no explicit value"."""
    if isinstance(value, str) and value.strip().lower() in GUARDIAN_TIER_PROFILES:
        return value.strip().lower()
    return None


def guardian_resolve_tier(settings_data):
    """Resolve the operator-declared model-size tier from a raw `guardian_settings` dict ALONE.

    This is only the settings step of the tier order (see :func:`guardian_resolve_model_params`, which puts
    the operator's pin in `guardian_model_profile` first and the model catalogue's size class second): an
    explicit "small"/"medium"/"large", else the fail-safe default (:data:`GUARDIAN_DEFAULT_MODEL_TIER`). It is
    what a script uses before the run's model numbers are known.

    :param settings_data: The raw dict read from `guardian_settings` (NOT the normalized
        `guardian_tick_load_settings()` result). Any non-dict input resolves to the default, same as a
        missing/unreadable List.
    :return: ``(tier_name, profile)`` -- `tier_name` is always one of `GUARDIAN_TIER_PROFILES`'s own
        keys; `profile` is that key's dict from `GUARDIAN_TIER_PROFILES` (never a copy the caller
        could accidentally mutate the canonical table through -- callers must treat it as read-only).
    :rtype: ``tuple(str, dict)``
    """
    tier = GUARDIAN_DEFAULT_MODEL_TIER
    if isinstance(settings_data, dict):
        tier = guardian_tier_name(settings_data.get("model_tier")) or GUARDIAN_DEFAULT_MODEL_TIER
    return tier, GUARDIAN_TIER_PROFILES[tier]


#: The runtime-mutable List that holds what the daily model-adaptation Job measured about the model
#: that is actually enabled (served context window, tokens per character, tool and structured-output
#: support, the recommended input budget). Deliberately NOT pack-seeded: a pack-seeded List installs
#: as system:true and `setList` would be rejected, and the whole point is that the Job can refresh it
#: with no redeploy and no approval. It is created by GuardianBootstrap (and by the writer itself on
#: first use). Shape: ``{"active": "<provider>:<instance>", "profiles": {"<provider>:<instance>":
#: {record}}, "overrides": {"max_input_tokens": N, "max_tool_def_tokens": N, "model_tier": "..."}}``.
#: The Job rewrites ``active`` and ``profiles`` and NEVER touches ``overrides`` (operator-edited).
GUARDIAN_MODEL_PROFILE_LIST_NAME = "guardian_model_profile"

#: Key of the per-run snapshot the playbook's "Resolve model profile" task leaves in context
#: (``Guardian.ModelProfile``), so every task of one run, and every tick of the session, sees the
#: same numbers even if the Job refreshes the List halfway through the run.
GUARDIAN_MODEL_PROFILE_SNAPSHOT_KEY = "ModelProfile"

#: Context key (under ``Guardian``) of the agent loop's state; its ``model_params`` entry holds the numbers
#: the loop settled on at tick 0. The scripts a loop calls (tool bridge, subagents, compaction) read them
#: from there when no playbook snapshot exists, so every part of one run uses the same numbers.
GUARDIAN_RUN_STATE_CONTEXT_KEY = "Loop"

#: The tool-definition budget never takes more than this share of ``max_input_tokens``: a tier's
#: default budget (16000 at "medium") assumes a window that can hold it, and a model served with a
#: small context would otherwise be offered more tool schema than its whole input budget. 60% leaves the
#: rest for the system prompt, the incident and the transcript. Applies to the tier default and to an
#: explicit ``guardian_settings.max_tool_def_tokens``, never to an operator override in the profile List.
GUARDIAN_TOOL_BUDGET_MAX_INPUT_FRACTION = 0.6

# ---------------------------------------------------------------------------
# Limits that scale with the model's input budget.
#
# UNITS. ``max_input_tokens`` (B) is counted in Guardian's own estimator tokens, not real provider tokens:
# ``guardian_estimate_tokens`` is chars / 4 (+5 per message), and the catalogue's documented budgets already
# include the factor that turns real tokens into those. So every byte or character cap below is converted
# with that SAME unit: characters = estimator tokens x GUARDIAN_CHARS_PER_ESTIMATED_TOKEN. Never mix this with
# a real tokenizer's ratio.
# ---------------------------------------------------------------------------

#: The estimator's characters per token (see ``guardian_estimate_tokens``).
GUARDIAN_CHARS_PER_ESTIMATED_TOKEN = 4

#: One tool result may take this share of B (20%), but never less than the floor below.
GUARDIAN_EVIDENCE_CEILING_BUDGET_SHARE_PERCENT = 20
#: The per-result ceiling never goes below this many bytes: it is also the value used when no budget is known.
GUARDIAN_EVIDENCE_CEILING_FLOOR_BYTES = 16384
#: Head and tail kept when a result is cut: about half the ceiling each, less room for the truncation marker, so
#: head + marker + tail comes to the ceiling (not half of it).
GUARDIAN_EVIDENCE_MARKER_RESERVE_BYTES = 128
#: The incident details pinned into the prompt may take this share of B (5%), never less than the floor.
GUARDIAN_INCIDENT_DETAILS_BUDGET_SHARE_PERCENT = 5
GUARDIAN_INCIDENT_DETAILS_FLOOR_CHARS = 2000
#: A large model's tool-list budget is at least this share of B (25%), still capped at
#: GUARDIAN_TOOL_BUDGET_MAX_INPUT_FRACTION of B.
GUARDIAN_LARGE_TOOL_BUDGET_SHARE_PERCENT = 25
#: When a conversation is summarized, one tool result is shown to the summarizer cut to this fraction (1/8) of
#: the per-result ceiling, never less than the floor.
GUARDIAN_COMPACT_RENDER_CEILING_DIVISOR = 8
GUARDIAN_COMPACT_RENDER_FLOOR_CHARS = 2000
#: The values used when no input budget is known (the model is uncatalogued and nothing was measured or set).
GUARDIAN_HISTORY_FALLBACK_BATCH_CAP = 25
GUARDIAN_SUBAGENT_TOOL_MESSAGE_FALLBACK_BYTES = 8000


def _guardian_positive_int(value):
    """``int(value)`` when it is a real positive number (not a bool), else ``None``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = int(value)
    return number if number > 0 else None


#: Messages the conversation can never lose, whatever the budget: the system prompt (message 0), the incident pin
#: that tells the model which incident it is working, and the task (the investigation prompt, wrapped as untrusted
#: case data). Token compaction and the summarizing path both keep them verbatim.
GUARDIAN_INCIDENT_PIN_PREFIX = "YOU ARE ALREADY WORKING"
GUARDIAN_TASK_MESSAGE_PREFIX = "<untrusted-case-data>"
#: The text the free compaction path puts at the start of its one-line "turns were dropped" note (a user message).
GUARDIAN_COMPACTION_BREADCRUMB_PREFIX = "[Guardian-compaction] "


def guardian_is_protected_message(message):
    """Is ``message`` the incident pin (a system message that starts with the pin text) or the task (a user message
    that starts with the untrusted-case-data wrapper)? A compaction checkpoint is never one of them."""
    if not isinstance(message, dict) or message.get("guardian_checkpoint") is True:
        return False
    content = message.get("content")
    if not isinstance(content, str):
        return False
    role = message.get("role")
    return (role == "system" and content.startswith(GUARDIAN_INCIDENT_PIN_PREFIX)) or (
        role == "user" and content.startswith(GUARDIAN_TASK_MESSAGE_PREFIX))


def guardian_split_protected_head(messages):
    """``(head, rest)``: ``head`` is message 0 (the system prompt), the system messages right after it (the incident
    pin) and the first user message after those (the task); ``rest`` is everything after, which is what compaction
    may drop or summarize. A compaction checkpoint or breadcrumb ends the head: they are never part of it."""
    items = list(messages or [])
    if not items:
        return [], []
    index = 1
    while index < len(items) and isinstance(items[index], dict) and items[index].get("role") == "system" \
            and items[index].get("guardian_checkpoint") is not True:
        index += 1
    if index < len(items) and isinstance(items[index], dict) and items[index].get("role") == "user" \
            and not str(items[index].get("content") or "").startswith(GUARDIAN_COMPACTION_BREADCRUMB_PREFIX):
        index += 1
    return items[:index], items[index:]


def guardian_evidence_head_tail(ceiling):
    """The head (and the tail) size, in bytes, for a result cut to ``ceiling``: half the ceiling less
    :data:`GUARDIAN_EVIDENCE_MARKER_RESERVE_BYTES` for the marker between them."""
    return max((int(ceiling) - GUARDIAN_EVIDENCE_MARKER_RESERVE_BYTES) // 2, 1)


def guardian_derive_limits(max_input_tokens, settings_data=None):
    """Every limit that scales with the input budget B (``max_input_tokens``), in ONE place, each with the
    source it came from. Pure. The tick, the tool bridge, the catalogue builder, the subagent dispatcher and
    the compaction script all read these numbers, so they cannot disagree.

    With B known:

    - ``evidence_truncate_bytes``: max(16384, 20% of B in characters) -- one tool result's ceiling.
      ``evidence_head_tail_bytes`` is about half the ceiling, each end, less the truncation marker.
    - ``incident_details_chars``: max(2000, 5% of B in characters).
    - ``batch_cap``: ``None`` -- history is compacted by tokens against B, never by message count.
    - ``subagent_tool_message_bytes``: the per-result ceiling. ``compact_tool_render_chars``:
      max(2000, ceiling / 8).

    With B unknown the values are today's: 16384 / 4096 / 2000, a 25-message cap, 8000 and 2000.

    An explicit positive number in ``guardian_settings`` (``evidence_truncate_bytes``,
    ``evidence_head_tail_bytes``, ``batch_cap``) overrides the derived value; the shipped settings carry none of
    them. See the units note above: characters = estimator tokens x 4.

    :return: ``{"evidence_truncate_bytes", "evidence_truncate_bytes_source", "evidence_head_tail_bytes",
        "evidence_head_tail_bytes_source", "incident_details_chars", "incident_details_chars_source",
        "batch_cap" (int or None), "batch_cap_source", "history_by" ("tokens" or "messages"),
        "subagent_tool_message_bytes", "compact_tool_render_chars"}``. JSON-safe.
    :rtype: ``dict``
    """
    settings = settings_data if isinstance(settings_data, dict) else {}
    budget = _guardian_positive_int(max_input_tokens)
    unit = GUARDIAN_CHARS_PER_ESTIMATED_TOKEN

    if budget is not None:
        ceiling = max(GUARDIAN_EVIDENCE_CEILING_FLOOR_BYTES,
                      budget * unit * GUARDIAN_EVIDENCE_CEILING_BUDGET_SHARE_PERCENT // 100)
        ceiling_source = "{}% of the input budget".format(GUARDIAN_EVIDENCE_CEILING_BUDGET_SHARE_PERCENT)
        details = max(GUARDIAN_INCIDENT_DETAILS_FLOOR_CHARS,
                      budget * unit * GUARDIAN_INCIDENT_DETAILS_BUDGET_SHARE_PERCENT // 100)
        details_source = "{}% of the input budget".format(GUARDIAN_INCIDENT_DETAILS_BUDGET_SHARE_PERCENT)
    else:
        ceiling = GUARDIAN_EVIDENCE_CEILING_FLOOR_BYTES
        ceiling_source = "default (no input budget)"
        details = GUARDIAN_INCIDENT_DETAILS_FLOOR_CHARS
        details_source = "default (no input budget)"
    explicit_ceiling = _guardian_positive_int(settings.get("evidence_truncate_bytes"))
    if explicit_ceiling is not None:
        ceiling, ceiling_source = explicit_ceiling, "guardian_settings"

    head_tail = guardian_evidence_head_tail(ceiling)
    head_tail_source = "half the per-result limit, less the marker"
    explicit_head_tail = _guardian_positive_int(settings.get("evidence_head_tail_bytes"))
    if explicit_head_tail is not None:
        head_tail, head_tail_source = explicit_head_tail, "guardian_settings"

    explicit_cap = _guardian_positive_int(settings.get("batch_cap"))
    if explicit_cap is not None:
        batch_cap, batch_source, history_by = explicit_cap, "guardian_settings", "messages"
    elif budget is not None:
        batch_cap, batch_source, history_by = None, "compacted by tokens against the input budget", "tokens"
    else:
        batch_cap, batch_source, history_by = (
            GUARDIAN_HISTORY_FALLBACK_BATCH_CAP, "default (no input budget)", "messages")

    if budget is not None:
        subagent = ceiling
        render = max(GUARDIAN_COMPACT_RENDER_FLOOR_CHARS, ceiling // GUARDIAN_COMPACT_RENDER_CEILING_DIVISOR)
    else:
        subagent = GUARDIAN_SUBAGENT_TOOL_MESSAGE_FALLBACK_BYTES
        render = GUARDIAN_COMPACT_RENDER_FLOOR_CHARS
    return {
        "evidence_truncate_bytes": ceiling,
        "evidence_truncate_bytes_source": ceiling_source,
        "evidence_head_tail_bytes": head_tail,
        "evidence_head_tail_bytes_source": head_tail_source,
        "incident_details_chars": details,
        "incident_details_chars_source": details_source,
        "batch_cap": batch_cap,
        "batch_cap_source": batch_source,
        "history_by": history_by,
        "subagent_tool_message_bytes": subagent,
        "compact_tool_render_chars": render,
    }


def guardian_active_profile_record(profile_list):
    """The active record of a raw ``guardian_model_profile`` dict, or ``None``."""
    plist = profile_list if isinstance(profile_list, dict) else {}
    active, profiles = plist.get("active"), plist.get("profiles")
    if isinstance(active, str) and isinstance(profiles, dict) and isinstance(profiles.get(active), dict):
        return profiles[active]
    return None


def guardian_catalog_model_for_record(catalog, record, configured_model=None):
    """The catalogue model for a run: by the active record's ``catalog_id``, else by the configured model
    name (id, alias, dated or prefixed spelling), else by the name the record holds. ``None`` when the
    catalogue does not know it."""
    names = []
    if isinstance(record, dict) and isinstance(record.get("catalog_id"), str):
        names.append(record["catalog_id"])
    if isinstance(configured_model, str):
        names.append(configured_model)
    if isinstance(record, dict) and isinstance(record.get("model"), str):
        names.append(record["model"])
    for name in names:
        if name.strip():
            model = guardian_catalog_lookup(catalog, name)
            if model is not None:
                return model
    return None


def guardian_catalog_size_info(model):
    """``{"model_id", "size_class", "params_b"}`` for a catalogue model; ``size_class`` is ``None`` when the
    catalogue does not state the model's size. ``None`` when ``model`` is not a catalogue entry."""
    if not isinstance(model, dict):
        return None
    return {"model_id": model.get("id"), "size_class": guardian_tier_name(model.get("size_class")),
            "params_b": model.get("params_b")}


def guardian_search_integrations():
    """The integration-search response (``{"instances", "configurations"}``), or ``None`` when it could not
    be fetched. Never raises."""
    result = _guardian_rest_post("/settings/integration/search", {"size": 200})
    if not result["ok"]:
        return None
    return result["data"] if isinstance(result["data"], dict) else {}


def guardian_enabled_llm_provider(response):
    """The first ENABLED Guardian LLM provider instance (an integration that offers `guardian-llm-chat`) in an
    integration-search response, or ``None``: ``{"brand", "instance_name", "configured_model"}``. Pure."""
    if not isinstance(response, dict) or not isinstance(response.get("instances"), list):
        return None
    brands = set()
    configurations = response.get("configurations")
    for conf in configurations if isinstance(configurations, list) else []:
        if not isinstance(conf, dict):
            continue
        script = conf.get("integrationScript") if isinstance(conf.get("integrationScript"), dict) else {}
        commands = script.get("commands") if isinstance(script.get("commands"), list) else []
        if any(isinstance(cmd, dict) and cmd.get("name") == "guardian-llm-chat" for cmd in commands):
            for key in ("name", "brand"):
                brand = str(conf.get(key) or "").strip().lower()
                if brand:
                    brands.add(brand)
    for inst in response["instances"]:
        if not isinstance(inst, dict):
            continue
        enabled = inst.get("enabled")
        if not (enabled is True or (isinstance(enabled, str) and enabled.strip().lower() == "true")):
            continue
        brand = str(inst.get("brand") or "").strip().lower()
        if brands:
            if brand not in brands:
                continue
        elif not brand.startswith("guardian"):
            continue
        data = inst.get("data") if isinstance(inst.get("data"), list) else []
        return {"brand": inst.get("brand"), "instance_name": inst.get("name"),
                "configured_model": guardian_catalog_configured_model(data)}
    return None


def guardian_catalog_size_for_run(profile_list, configured_model=None, catalog=None):
    """Look the model in use up in the catalogue and return its size (:func:`guardian_catalog_size_info`), or
    ``None`` (the operator pinned a tier, the catalogue is unavailable, or the model is not in it).

    Done on EVERY run, from the catalogue as it is now: nothing is stored in the profile records, so a record
    written before the catalogue carried sizes gets its size with no rewrite. The model is found by the active
    record's ``catalog_id``, else the configured model name; when neither is known (no record yet and the
    caller did not pass the name), the enabled provider instance is looked up once.

    :param profile_list: The raw ``guardian_model_profile`` dict.
    :param configured_model: The model name the provider instance is configured with, when the caller knows it.
    :param catalog: The parsed catalogue, when the caller already has it (else it is read).
    """
    plist = profile_list if isinstance(profile_list, dict) else {}
    overrides = plist.get("overrides") if isinstance(plist.get("overrides"), dict) else {}
    if guardian_tier_name(overrides.get("model_tier")):
        return None  # the operator's pin wins; the catalogue is not needed
    record = guardian_active_profile_record(plist)
    if not (configured_model or (record and (record.get("catalog_id") or record.get("model")))):
        found = guardian_enabled_llm_provider(guardian_search_integrations())
        configured_model = (found or {}).get("configured_model")
        if not configured_model:
            return None
    if catalog is None:
        catalog = guardian_catalog_load()
    if catalog is None:
        return None
    return guardian_catalog_size_info(guardian_catalog_model_for_record(catalog, record, configured_model))


def guardian_resolve_model_params(settings_data, profile_list, catalog_size=None):
    """Work out the model-adaptation numbers for one run. Pure (no I/O): pass in the raw
    ``guardian_settings`` dict, the raw ``guardian_model_profile`` dict (either may be missing, unreadable or
    malformed; it then counts as empty) and, when the model is in the catalogue, its size
    (:func:`guardian_catalog_size_for_run`).

    Order, per value (first that applies wins):

    - ``tier``: ``overrides.model_tier`` (an explicit operator pin; source ``override``) > the model's size
      class in the catalogue (source ``catalogue (<model id>)``) > an explicit ``guardian_settings.model_tier``
      of small / medium / large (source ``guardian_settings``: the setting for a model NOT in the catalogue) >
      ``small``. "auto", a missing key and an unrecognized value mean "no explicit value" in the settings.
      When an explicit settings tier is ignored because the catalogue knows the model, ``tier_note`` says so.
    - ``max_input_tokens``: ``overrides.max_input_tokens`` > the measured ``max_input_tokens`` of the
      active profile record > ``guardian_settings.max_input_tokens`` > ``None`` (no ceiling).
    - ``max_tool_def_tokens``: ``overrides.max_tool_def_tokens`` > explicit
      ``guardian_settings.max_tool_def_tokens`` > the tier default (a large model: at least 25% of the input
      budget). Unless it is an override it is capped at :data:`GUARDIAN_TOOL_BUDGET_MAX_INPUT_FRACTION` of
      the resolved ``max_input_tokens``.
    - ``limits``: everything that scales with ``max_input_tokens`` (:func:`guardian_derive_limits`).

    - ``max_ticks``: ``overrides.max_ticks`` > an explicit numeric ``guardian_settings.MAX_TICKS`` > the tier's value
      (small 25, medium 40, large 60).
    - ``max_tool_calls_per_turn``: ``overrides.max_tool_calls_per_turn`` > ``guardian_settings.max_tool_calls_per_turn``
      > ``0``. ``0`` means no limit (the default). A positive value makes the run execute only that many of the
      tool calls a model proposes in one turn and tell the model the rest were deferred, for models that batch every
      call into one turn and so cannot use the result of one call to choose the next.

    :param catalog_size: ``{"model_id", "size_class", "params_b"}`` from the catalogue, or ``None`` when the
        model is not in it (``size_class`` ``None`` means the catalogue lists the model without a size).
    :return: ``{"tier", "tier_source", "tier_note", "catalog_model", "max_input_tokens",
        "max_input_tokens_source", "max_tool_def_tokens", "max_tool_def_tokens_source", "max_tool_calls_per_turn",
        "max_tool_calls_per_turn_source", "max_ticks", "max_ticks_source", "limits", "profile"}``. ``profile`` is a small
        summary of the active record (key, model, instance, probed_at, window, chars_per_token,
        tools, structured_output) or ``None`` when there is none. JSON-safe.
    :rtype: ``dict``
    """
    settings = settings_data if isinstance(settings_data, dict) else {}
    plist = profile_list if isinstance(profile_list, dict) else {}
    overrides = plist.get("overrides") if isinstance(plist.get("overrides"), dict) else {}

    record = guardian_active_profile_record(plist)
    active = plist.get("active")

    size = catalog_size if isinstance(catalog_size, dict) else None
    catalog_class = guardian_tier_name(size.get("size_class")) if size else None
    catalog_model = size.get("model_id") if size else None
    settings_tier = guardian_tier_name(settings.get("model_tier"))
    tier_note = None
    override_tier = guardian_tier_name(overrides.get("model_tier"))
    if override_tier:
        tier, tier_source = override_tier, "override"
    elif catalog_class:
        tier, tier_source = catalog_class, "catalogue ({})".format(catalog_model)
        if settings_tier and settings_tier != tier:
            tier_note = (
                "guardian_settings.model_tier ({}) is not used: {} is a {} model in the model catalogue; to force a "
                "size use overrides.model_tier in guardian_model_profile.".format(settings_tier, catalog_model, tier))
    elif settings_tier:
        tier, tier_source = settings_tier, "guardian_settings"
    else:
        tier = GUARDIAN_DEFAULT_MODEL_TIER
        if size:
            tier_source = ("default (the model catalogue does not give the size of {}; set model_tier in "
                           "guardian_settings)".format(catalog_model))
        else:
            tier_source = "default (model not in the catalogue; set model_tier in guardian_settings)"
    tier_profile = GUARDIAN_TIER_PROFILES[tier]

    max_input = _guardian_positive_int(overrides.get("max_input_tokens"))
    max_input_source = "override"
    if max_input is None:
        max_input = _guardian_positive_int((record or {}).get("max_input_tokens"))
        max_input_source = "measured"
    if max_input is None:
        max_input = _guardian_positive_int(settings.get("max_input_tokens"))
        max_input_source = "guardian_settings"
    if max_input is None:
        max_input_source = "none"

    max_tools = _guardian_positive_int(overrides.get("max_tool_def_tokens"))
    max_tools_source = "override"
    if max_tools is None:
        max_tools = _guardian_positive_int(settings.get("max_tool_def_tokens"))
        max_tools_source = "guardian_settings"
    if max_tools is None:
        max_tools = tier_profile["max_tool_def_tokens"]
        max_tools_source = "tier"
        if tier == "large" and max_input is not None:
            scaled = max_input * GUARDIAN_LARGE_TOOL_BUDGET_SHARE_PERCENT // 100
            if scaled > max_tools:
                max_tools = scaled
                max_tools_source = "tier ({}% of the input budget)".format(GUARDIAN_LARGE_TOOL_BUDGET_SHARE_PERCENT)
    if max_tools_source != "override" and max_input is not None:
        cap = int(max_input * GUARDIAN_TOOL_BUDGET_MAX_INPUT_FRACTION)
        if cap < max_tools:
            max_tools = cap
            max_tools_source += ", capped to {}% of max_input_tokens".format(
                int(GUARDIAN_TOOL_BUDGET_MAX_INPUT_FRACTION * 100))

    max_calls = _guardian_positive_int(overrides.get("max_tool_calls_per_turn"))
    max_calls_source = "override"
    if max_calls is None:
        max_calls = _guardian_positive_int(settings.get("max_tool_calls_per_turn"))
        max_calls_source = "guardian_settings"
    if max_calls is None:
        max_calls = _guardian_positive_int(tier_profile.get("max_tool_calls_per_turn"))
        max_calls_source = "tier"
    if max_calls is None:
        max_calls = 0
        max_calls_source = "none"

    max_ticks = _guardian_positive_int(overrides.get("max_ticks"))
    max_ticks_source = "override"
    if max_ticks is None:
        max_ticks = _guardian_positive_int(settings.get("MAX_TICKS"))
        max_ticks_source = "guardian_settings"
    if max_ticks is None:
        max_ticks = tier_profile["max_ticks"]
        max_ticks_source = "tier"

    summary = None
    if record is not None:
        summary = {
            "key": active,
            "model": record.get("model"),
            "instance_name": record.get("instance_name"),
            "probed_at": record.get("probed_at"),
            "window": record.get("window"),
            "chars_per_token": record.get("chars_per_token"),
            "tools": record.get("tools"),
            "structured_output": record.get("structured_output"),
        }
    return {
        "tier": tier,
        "tier_source": tier_source,
        "tier_note": tier_note,
        "catalog_model": catalog_model,
        "max_input_tokens": max_input,
        "max_input_tokens_source": max_input_source,
        "max_tool_def_tokens": max_tools,
        "max_tool_def_tokens_source": max_tools_source,
        "max_tool_calls_per_turn": max_calls,
        "max_tool_calls_per_turn_source": max_calls_source,
        "max_ticks": max_ticks,
        "max_ticks_source": max_ticks_source,
        "limits": guardian_derive_limits(max_input, settings),
        "profile": summary,
    }


def guardian_model_params_valid(params):
    """Is ``params`` a usable output of :func:`guardian_resolve_model_params` (a snapshot read back
    from context may be missing, stale in shape, or hand-edited)? Checks the keys a consumer needs. A
    snapshot written before the limits were derived has no ``limits`` and is not valid: the caller resolves
    again."""
    limits = params.get("limits") if isinstance(params, dict) else None
    return (
        isinstance(params, dict)
        and params.get("tier") in GUARDIAN_TIER_PROFILES
        and isinstance(params.get("max_tool_def_tokens"), int)
        and not isinstance(params.get("max_tool_def_tokens"), bool)
        and (params.get("max_input_tokens") is None or _guardian_positive_int(params.get("max_input_tokens")))
        and _guardian_positive_int(params.get("max_ticks")) is not None
        and isinstance(limits, dict)
        and _guardian_positive_int(limits.get("evidence_truncate_bytes")) is not None
        and _guardian_positive_int(limits.get("evidence_head_tail_bytes")) is not None
        and _guardian_positive_int(limits.get("incident_details_chars")) is not None
    )


def guardian_load_model_profile_list():
    """Read ``guardian_model_profile`` as a dict. A missing or unreadable List is not an error here:
    the profile is optional, so the answer is then ``{}`` and the caller falls back to
    ``guardian_settings``.

    :return: ``{"ok": bool, "data": dict, "error": str or None}``; ``ok`` is ``False`` only when the
        List exists but could not be parsed, or the read failed for a reason other than "not found".
    :rtype: ``dict``
    """
    result = guardian_execute("getList", {"listName": GUARDIAN_MODEL_PROFILE_LIST_NAME})
    if not result["ok"]:
        text = (result.get("error") or "").lower()
        if "item not found" in text:
            return {"ok": True, "data": {}, "error": None}
        return {"ok": False, "data": {}, "error": result.get("error")}
    contents = None
    for entry in result["data"] or []:
        if isinstance(entry, dict) and entry.get("Contents") is not None:
            contents = entry["Contents"]
    if isinstance(contents, str):
        try:
            contents = json.loads(contents)
        except ValueError:
            return {"ok": False, "data": {}, "error": "guardian_model_profile is not valid JSON"}
    if contents is None:
        return {"ok": True, "data": {}, "error": None}
    if not isinstance(contents, dict):
        return {"ok": False, "data": {}, "error": "guardian_model_profile is not a JSON object"}
    return {"ok": True, "data": contents, "error": None}


def guardian_run_model_params():
    """The numbers this run already settled on, from context, or ``None``: the playbook's snapshot
    (``Guardian.ModelProfile``) when it is present and well formed, else the ones the agent loop kept in its
    own state at tick 0 (``Guardian.Loop.model_params``). Never raises."""
    candidates = [("snapshot", guardian_ctx_read(GUARDIAN_MODEL_PROFILE_SNAPSHOT_KEY))]
    run_state = guardian_ctx_read(GUARDIAN_RUN_STATE_CONTEXT_KEY)
    if isinstance(run_state, dict):
        candidates.append(("run state", run_state.get("model_params")))
    for source, params in candidates:
        if guardian_model_params_valid(params):
            return params, source
    return None, None


def guardian_model_params_for_run(settings_data, use_snapshot=False, configured_model=None, catalog=None):
    """The model-adaptation numbers one run should use. With ``use_snapshot`` (the playbook's later
    tasks, and the scripts the loop calls) it takes the numbers the run already settled on
    (:func:`guardian_run_model_params`: the "Resolve model profile" task's snapshot, else the loop's own
    state) when they are present and well formed; otherwise it reads ``guardian_model_profile``, looks the
    model up in the catalogue and resolves. Never raises: a failure to read the profile List only means
    falling back to settings.

    :param configured_model: The model name the provider instance is configured with, when the caller
        already knows it (saves one integration search when there is no profile record yet).
    :param catalog: The parsed model catalogue, when the caller already has it.
    :return: ``(params, source_note)`` -- the :func:`guardian_resolve_model_params` dict, and a short
        text saying where it came from (``"snapshot"``, ``"run state"``, ``"resolved"`` or ``"resolved
        (profile list unreadable: ...)"``).
    :rtype: ``tuple(dict, str)``
    """
    if use_snapshot:
        params, source = guardian_run_model_params()
        if params is not None:
            return params, source
    loaded = guardian_load_model_profile_list()
    note = "resolved" if loaded["ok"] else "resolved (profile list unreadable: {})".format(loaded["error"])
    try:
        size = guardian_catalog_size_for_run(loaded["data"], configured_model, catalog)
    except Exception:  # the catalogue only refines the size; a failure there is the settings fallback
        size = None
    return guardian_resolve_model_params(settings_data, loaded["data"], size), note


def guardian_limits_describe(params):
    """The War Room lines for the limits that scale with the input budget. Pure."""
    limits = params.get("limits") if isinstance(params.get("limits"), dict) else {}
    if not limits:
        return []
    budget = params.get("max_input_tokens")
    lines = [
        "Tool result limit: {:,} bytes per result ({}).".format(
            limits["evidence_truncate_bytes"], limits.get("evidence_truncate_bytes_source")),
        "Incident details in the prompt: up to {:,} characters ({}).".format(
            limits["incident_details_chars"], limits.get("incident_details_chars_source")),
    ]
    if limits.get("history_by") == "tokens" and budget:
        lines.append("History: compacted by tokens at {:,}.".format(budget))
    else:
        lines.append("History: compacted at {} messages ({}).".format(limits.get("batch_cap"), limits.get("batch_cap_source")))
    return lines


def guardian_model_params_describe(params):
    """One War Room line per value saying what it is and where it came from. Pure."""
    profile = params.get("profile")
    lines = [
        "Model size: {} ({}).".format(params["tier"], params["tier_source"]),
        "Input budget (max_input_tokens): {} ({}).".format(
            params["max_input_tokens"] if params["max_input_tokens"] is not None else "no ceiling",
            params["max_input_tokens_source"]),
        "Tool list budget (max_tool_def_tokens): {} ({}).".format(
            params["max_tool_def_tokens"], params["max_tool_def_tokens_source"]),
    ]
    if params.get("max_ticks"):
        lines.append("Turn limit (MAX_TICKS): {} ({}).".format(params["max_ticks"], params.get("max_ticks_source")))
    lines.extend(guardian_limits_describe(params))
    if params.get("tier_note"):
        lines.append(params["tier_note"])
    if profile:
        lines.append("Measured profile: {} on {}, probed {}.".format(
            profile.get("model") or "unknown model", profile.get("instance_name") or "unknown instance",
            profile.get("probed_at") or "at an unknown time"))
    else:
        lines.append("No measured profile yet (the GuardianModelAdaptation job, or "
                     "`!guardian-probe-model` then `!GuardianModelProfileUpdate`, creates one).")
    return lines

def guardian_model_params_summary(params):
    """The run's model numbers on ONE short line: size and where it came from, input budget, tool list
    budget, per-result limit, incident-details limit and how the history is compacted. Pure."""
    limits = params.get("limits") if isinstance(params.get("limits"), dict) else {}
    budget = params.get("max_input_tokens")
    parts = [
        "size {} ({})".format(params.get("tier"), params.get("tier_source")),
        "input budget {}".format("{:,}".format(budget) if budget else "unknown"),
        "tool list budget {:,}".format(params.get("max_tool_def_tokens") or 0),
    ]
    if params.get("max_ticks"):
        parts.append("turn limit {}".format(params["max_ticks"]))
    if limits:
        parts.append("tool result limit {:,} bytes".format(limits["evidence_truncate_bytes"]))
        parts.append("incident details {:,} characters".format(limits["incident_details_chars"]))
        if limits.get("history_by") == "tokens" and budget:
            parts.append("history compacted by tokens at {:,}".format(budget))
        else:
            parts.append("history compacted at {} messages".format(limits.get("batch_cap")))
    return "Model profile: " + "; ".join(parts) + "."


#: ---------------------------------------------------------------------------
#: HTML helpers for the layout display scripts (dynamic sections).
#:
#: A dynamic section may return an HTML entry. The renderer's sanitizer is not documented, so the
#: output is deliberately plain: div, span, table, b, code, br, h4 and a little inline style, with
#: no <script>, no <style> block, no external resource, no image and no event handler. No page
#: colour is set: text inherits the theme and the badges are solid mid-tones with white text, so
#: they read on a light or a dark layout. If a tenant strips the inline styles, the tables, bold
#: and code stay readable as plain structure.
#:
#: Safety rule: every value goes through ``guardian_html_escape`` unless it is already a
#: ``GuardianHtml`` (the type every helper below returns). A plain ``str`` is therefore never
#: treated as markup, so model output, tool arguments, case fields and list data cannot inject
#: HTML.
#: ---------------------------------------------------------------------------

#: Border colour used by every card, table rule and empty state (readable on light and dark).
GUARDIAN_HTML_BORDER = "rgba(128,128,128,.35)"

#: Badge / accent colours: solid mid-tones that carry white text on either theme.
GUARDIAN_HTML_COLORS = {
    "ok": "#1f8a5b",
    "warn": "#b36b00",
    "danger": "#c0392b",
    "info": "#2f6fb5",
    "muted": "#667085",
}

#: A free-text status (audit status, approval status, loop status, readiness state) -> badge colour.
GUARDIAN_HTML_STATUS_KINDS = {
    "ok": "ok",
    "success": "ok",
    "succeeded": "ok",
    "approved": "ok",
    "done": "ok",
    "completed": "ok",
    "ready": "ok",
    "running": "info",
    "available": "ok",
    "allowed": "ok",
    "consumed": "info",
    "pending": "warn",
    "pending_approval": "warn",
    "awaiting_approval": "warn",
    "awaiting_analyst": "warn",
    "paused": "warn",
    "needs review": "warn",
    "needs refresh": "warn",
    "stopped": "warn",
    "denied": "danger",
    "error": "danger",
    "halted": "danger",
    "failed": "danger",
    "degraded": "danger",
    "expired": "muted",
    "unknown": "muted",
    "skipped": "muted",
    "not initialized": "muted",
}

#: Approval risk tier -> badge colour.
GUARDIAN_HTML_TIER_KINDS = {"soft": "info", "destructive": "warn", "credential": "danger", "deny": "danger"}

#: XSOAR entry Type 1 is a note; ContentsFormat "html" is what a dynamic section renders as HTML.
GUARDIAN_HTML_NOTE_ENTRY_TYPE = 1
GUARDIAN_HTML_CONTENTS_FORMAT = "html"


class GuardianHtml(str):
    """A string that is already safe markup. Only the ``guardian_html_*`` helpers create one."""

    __slots__ = ()


def guardian_html_trusted(markup):
    """Mark ``markup`` as trusted. Use only on literal strings written in code, never on data."""
    return GuardianHtml(markup)


def guardian_html_escape(value, max_len=None, keep_newlines=False):
    """Make any value safe to place in HTML text: stringify, truncate, escape, then handle newlines.

    :param value: Any value. ``None`` becomes an empty string; a dict/list/tuple is rendered as
        compact JSON; a ``GuardianHtml`` is returned unchanged.
    :param max_len: Truncate to at most this many characters (a trailing ellipsis counts) BEFORE
        escaping, so an entity is never cut in half.
    :type max_len: ``int`` or ``None``
    :param keep_newlines: ``True`` turns line breaks into ``<br>``; otherwise they become spaces.
    :type keep_newlines: ``bool``
    :return: Safe markup.
    :rtype: ``GuardianHtml``
    """
    import html as _gh_html
    import json as _gh_json

    if isinstance(value, GuardianHtml):
        return value
    if value is None:
        text = ""
    elif isinstance(value, str):
        text = value
    elif isinstance(value, (dict, list, tuple)):
        text = _gh_json.dumps(value, default=str)
    else:
        text = str(value)
    if max_len and len(text) > max_len:
        text = text[: max_len - 1] + "…"
    escaped = _gh_html.escape(text, quote=True).replace("\r\n", "\n").replace("\r", "\n")
    escaped = escaped.replace("\n", "<br>" if keep_newlines else " ")
    return GuardianHtml(escaped)


def guardian_html_join(parts, sep=""):
    """Join parts into safe markup. A plain string part is escaped; a ``GuardianHtml`` part is kept.
    ``sep`` is trusted markup written in code."""
    return GuardianHtml(sep.join(guardian_html_escape(part) for part in parts if part is not None))


def guardian_html_bold(value, max_len=None):
    return GuardianHtml("<b>{}</b>".format(guardian_html_escape(value, max_len)))


def guardian_html_code(value, max_len=None):
    """Inline monospace, for ids, command names and short arguments."""
    return GuardianHtml(
        '<code style="font-family:monospace;font-size:12px">{}</code>'.format(guardian_html_escape(value, max_len))
    )


def guardian_html_muted(value, max_len=None):
    """De-emphasised text (``opacity``, so it follows the theme's own text colour)."""
    return GuardianHtml('<span style="opacity:.7">{}</span>'.format(guardian_html_escape(value, max_len)))


def guardian_html_badge(text, kind="muted", max_len=40):
    """A solid-colour pill with white text. ``kind`` is ok, warn, danger, info or muted (unknown = muted)."""
    color = GUARDIAN_HTML_COLORS.get(kind, GUARDIAN_HTML_COLORS["muted"])
    return GuardianHtml(
        '<span style="display:inline-block;padding:1px 9px;border-radius:10px;background:{};color:#fff;'
        'font-size:11px;font-weight:600;line-height:18px;white-space:nowrap">{}</span>'.format(
            color, guardian_html_escape(text, max_len)
        )
    )


def guardian_html_status_badge(status, label=None):
    """A badge for a free-text status; the colour comes from ``GUARDIAN_HTML_STATUS_KINDS``."""
    text = str(status).strip() if status not in (None, "") else "unknown"
    kind = GUARDIAN_HTML_STATUS_KINDS.get(text.lower(), "muted")
    return guardian_html_badge(label if label is not None else text.upper().replace("_", " "), kind)


def guardian_html_tier_badge(tier):
    """A badge for an approval risk tier (soft, destructive, credential)."""
    text = str(tier).strip() if tier not in (None, "") else "unknown"
    return guardian_html_badge(text, GUARDIAN_HTML_TIER_KINDS.get(text.lower(), "muted"))


def guardian_html_table(headers, rows, aligns=None, nowrap_cols=()):
    """A table with a header row and aligned columns.

    :param headers: Header labels (escaped).
    :param rows: A list of rows; each row is a list of cells. A cell that is a plain value is
        escaped; a ``GuardianHtml`` cell is kept.
    :param aligns: Optional per-column ``"left"``/``"right"``/``"center"``.
    :param nowrap_cols: Column indexes whose text must not wrap (ids, timestamps, badges).
    :rtype: ``GuardianHtml``
    """
    aligns = list(aligns or [])
    nowrap = set(nowrap_cols or ())

    def _align(index):
        return aligns[index] if index < len(aligns) and aligns[index] in ("left", "right", "center") else "left"

    head_cells = "".join(
        '<th style="text-align:{};padding:5px 10px;border-bottom:2px solid {};font-size:11px;'
        'text-transform:uppercase;letter-spacing:.04em;opacity:.7;white-space:nowrap">{}</th>'.format(
            _align(index), GUARDIAN_HTML_BORDER, guardian_html_escape(header)
        )
        for index, header in enumerate(headers)
    )
    body_rows = []
    for row in rows:
        row = list(row)
        row += [""] * (len(headers) - len(row))
        cells = "".join(
            '<td style="text-align:{};padding:5px 10px;border-bottom:1px solid rgba(128,128,128,.2);'
            'vertical-align:top{}">{}</td>'.format(
                _align(index), ";white-space:nowrap" if index in nowrap else "", guardian_html_escape(cell)
            )
            for index, cell in enumerate(row)
        )
        body_rows.append("<tr>{}</tr>".format(cells))
    return GuardianHtml(
        '<table cellpadding="0" cellspacing="0" style="border-collapse:collapse;width:100%;margin:6px 0">'
        "<thead><tr>{}</tr></thead><tbody>{}</tbody></table>".format(head_cells, "".join(body_rows))
    )


def guardian_html_card(title, body, kind=None):
    """A bordered block with an optional coloured left edge. ``body`` is escaped unless it is
    ``GuardianHtml`` (use ``guardian_html_text_block`` for free text)."""
    accent = GUARDIAN_HTML_COLORS.get(kind) if kind else None
    left = "border-left:4px solid {};".format(accent) if accent else ""
    title_html = (
        '<div style="font-weight:600;margin-bottom:6px"><b>{}</b></div>'.format(guardian_html_escape(title)) if title else ""
    )
    return GuardianHtml(
        '<div style="border:1px solid {};{}border-radius:6px;padding:10px 14px;margin:8px 0">{}{}</div>'.format(
            GUARDIAN_HTML_BORDER, left, title_html, guardian_html_escape(body)
        )
    )


def guardian_html_text_block(text, max_len=2000, mono=False):
    """Free text (a model conclusion, a persona) with its line breaks kept, escaped and truncated."""
    style = "font-family:monospace;font-size:12px;" if mono else ""
    return GuardianHtml(
        '<div style="{}word-break:break-word">{}</div>'.format(style, guardian_html_escape(text, max_len, keep_newlines=True))
    )


def guardian_html_empty(message, hint=None):
    """An empty state: one line saying what is missing and, optionally, what happens next."""
    hint_html = '<br><span style="opacity:.7">{}</span>'.format(guardian_html_escape(hint)) if hint else ""
    return GuardianHtml(
        '<div style="border:1px dashed rgba(128,128,128,.45);border-radius:6px;padding:12px 14px;margin:8px 0">'
        "<b>{}</b>{}</div>".format(guardian_html_escape(message), hint_html)
    )


def guardian_html_heading(text):
    return GuardianHtml('<h4 style="margin:14px 0 4px 0;font-size:13px">{}</h4>'.format(guardian_html_escape(text)))


def guardian_html_note(text, max_len=None):
    """A small de-emphasised line (a source note, a truncation notice)."""
    return GuardianHtml(
        '<div style="opacity:.7;font-size:12px;margin:6px 0">{}</div>'.format(guardian_html_escape(text, max_len))
    )


def guardian_html_header(title, badges=(), facts=()):
    """A compact header: title, status badges, then a line of ``label value`` facts.

    :param badges: Badges (``GuardianHtml``) placed after the title.
    :param facts: ``(label, value)`` pairs; a pair whose value is ``None`` or empty is skipped.
    """
    badge_html = "".join(" " + str(guardian_html_escape(badge)) for badge in badges)
    fact_html = " &middot; ".join(
        "<b>{}</b> {}".format(guardian_html_escape(label), guardian_html_escape(value))
        for label, value in facts
        if value is not None and value != ""
    )
    facts_div = '<div style="margin-top:4px;opacity:.85">{}</div>'.format(fact_html) if fact_html else ""
    return GuardianHtml(
        '<div style="margin:0 0 8px 0"><span style="font-size:15px;font-weight:700"><b>{}</b></span>{}{}</div>'.format(
            guardian_html_escape(title), badge_html, facts_div
        )
    )


def guardian_html_page(parts):
    """The outer wrapper of a section: one div that only sets the font size."""
    return GuardianHtml(
        '<div style="font-size:13px;line-height:1.5">{}</div>'.format("".join(str(guardian_html_escape(p)) for p in parts))
    )


def guardian_html_entry(markup, context=None):
    """The entry a dynamic section returns for HTML (a note whose ContentsFormat is html).

    :param markup: The finished section markup.
    :param context: Optional ``EntryContext`` to publish alongside it.
    :rtype: ``dict``
    """
    entry = {
        "Type": GUARDIAN_HTML_NOTE_ENTRY_TYPE,
        "ContentsFormat": GUARDIAN_HTML_CONTENTS_FORMAT,
        "Contents": str(markup),
    }
    if context:
        entry["EntryContext"] = context
    return entry


def guardian_html_or_fallback(build_html, build_fallback, context=None):
    """Return the HTML entry for a section, or the old text/Markdown result if building the HTML raises.

    A display script must never make the layout error out: a failure in the HTML builder is logged
    and the section falls back to what it showed before.

    :param build_html: Zero-argument callable returning the section markup.
    :param build_fallback: Zero-argument callable returning what ``return_results`` accepts
        (usually ``CommandResults``).
    :param context: Optional ``EntryContext`` for the HTML entry.
    """
    try:
        return guardian_html_entry(build_html(), context)
    except Exception as exc:
        try:
            demisto.error("Guardian layout HTML builder failed; falling back to text: {}".format(exc))
        except Exception:
            pass
        return build_fallback()


def guardian_ts_parse(value):
    """Parse an ISO-8601 timestamp (``Z`` or offset, any number of fractional digits) into an aware
    UTC ``datetime``, or ``None`` when it is empty or unparseable."""
    import re as _gh_re
    from datetime import datetime as _gh_datetime, timezone as _gh_timezone

    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    # fromisoformat before Python 3.11 accepts only 3 or 6 fractional digits: normalise to 6.
    text = _gh_re.sub(r"\.(\d+)", lambda match: "." + (match.group(1) + "000000")[:6], text)
    try:
        parsed = _gh_datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_gh_timezone.utc)
    return parsed.astimezone(_gh_timezone.utc)


def guardian_ts_parse_any(value):
    """Parse a point in time given as ISO-8601 text (see :func:`guardian_ts_parse`) or as epoch seconds or
    milliseconds -- a number or a string of digits (``"1767323045678"``, ``"1767323045.5"``) -- into an aware UTC
    ``datetime``. Returns ``None`` for an empty, boolean, out-of-range or unreadable value. A number of
    100000000000 or more is milliseconds. The caller decides what counts as a plausible date (for example
    ``parsed.year > 1970``)."""
    from datetime import datetime as _gh_datetime, timezone as _gh_timezone

    number = None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
    elif isinstance(value, str) and value.strip().replace(".", "", 1).isdigit():
        number = float(value.strip())
    if number is None:
        return guardian_ts_parse(value)
    try:
        return _gh_datetime.fromtimestamp(number / 1000.0 if number >= 100000000000 else number, tz=_gh_timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def guardian_ts_short(value):
    """A timestamp as ``YYYY-MM-DD HH:MM:SS`` (UTC), or the original text when it cannot be parsed."""
    parsed = guardian_ts_parse(value)
    if parsed is None:
        return "" if value is None else str(value)
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def guardian_duration_text(seconds):
    """Seconds as a short ``1h 05m`` / ``12m`` / ``40s`` string (``""`` for a non-number)."""
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
        return ""
    total = int(abs(seconds))
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return "{}h {:02d}m".format(hours, minutes)
    if minutes:
        return "{}m".format(minutes)
    return "{}s".format(secs)


def guardian_pricing_entry(pricing, model):
    """The `guardian_pricing` row for a model, or ``None``. An exact key wins; else the LONGEST row name the model name
    starts with, at a ``-`` / ``:`` / ``@`` / ``.`` boundary (case-insensitive), because a provider reports
    `gpt-5-mini-2025-08-07` where the operator wrote the row `gpt-5-mini`, and `gpt-5` must never price `gpt-5-mini`.
    Pure; never raises."""
    if not isinstance(pricing, dict) or not isinstance(model, str) or not model:
        return None
    entry = pricing.get(model)
    if isinstance(entry, dict):
        return entry
    lowered = model.lower()
    best, found = None, None
    for key, value in pricing.items():
        name = str(key).lower()
        if (isinstance(value, dict) and lowered.startswith(name) and len(lowered) > len(name)
                and lowered[len(name)] in "-:@." and (best is None or len(name) > len(best))):
            best, found = name, value
    return found


# --- Triage block: the machine-checked answer of a triage session --------------------------------------------------
# One parser and one validator, shared by the reasoning tick (which decides whether a conclusion is accepted) and by
# GuardianTriageResult (which repairs, merges and writes the result), so the two can never disagree about what a
# valid block is. The taxonomy lives in the pack List `guardian_triage_types`; GUARDIAN_TRIAGE_DEFAULT_TYPES is the
# same data, used only when that List cannot be read (a content test keeps the two equal).

GUARDIAN_TRIAGE_LIST_NAME = "guardian_triage_types"

#: The severities a triage block may give, lowest first (setIncident maps them to XSOAR's 1-4 scale).
GUARDIAN_TRIAGE_SEVERITIES = ("low", "medium", "high", "critical")

#: The investigation type that means "none of the others fits".
GUARDIAN_TRIAGE_OTHER = "other"

GUARDIAN_TRIAGE_DOMAINS = ("detection", "posture")

#: The entity lists a triage block may carry. Anything else under `key_entities` is dropped.
GUARDIAN_TRIAGE_ENTITY_KEYS = ("identities", "ips", "hosts", "hashes", "domains", "urls", "emails")
GUARDIAN_TRIAGE_ENTITY_MAX_ITEMS = 10
#: An entity longer than this is dropped, never cut off: a truncated identifier names nothing, and a lookup given one
#: reads as a clean "no entries". 512 covers a long URL or a long cloud resource id.
GUARDIAN_TRIAGE_ENTITY_MAX_CHARS = 512
GUARDIAN_TRIAGE_SUMMARY_MIN_CHARS = 20
GUARDIAN_TRIAGE_SUMMARY_MAX_CHARS = 300
GUARDIAN_TRIAGE_NEXT_STEP_MAX_CHARS = 300
#: The optional `analysis` (what the model saw and why it rated the incident so) and `recommendations` (short next
#: actions). A malformed or missing value is treated as absent; it never makes a block invalid.
GUARDIAN_TRIAGE_ANALYSIS_MAX_CHARS = 800
GUARDIAN_TRIAGE_RECOMMENDATION_MAX_CHARS = 200
GUARDIAN_TRIAGE_RECOMMENDATIONS_MAX_ITEMS = 5
#: The optional `complexity` of the investigation the incident needs. GuardianModelChoice picks the investigation model
#: by it. Any other value is read as absent.
GUARDIAN_TRIAGE_COMPLEXITIES = ("low", "medium", "high")

GUARDIAN_TRIAGE_DEFAULT_TYPES = [
    {"name": "phishing",
     "description": "A reported or detected email: phishing, malicious attachment or link, business email compromise.",
     "domains": ["detection"], "sub_playbook": "GuardianTriagePhishing", "skill": "xsoar_case_investigation"},
    {"name": "identity_threat",
     "description": "Sign-in anomaly, credential use, brute force or session abuse by a person or service account.",
     "domains": ["detection"], "sub_playbook": "GuardianTriageIdentityThreat", "skill": "xsoar_case_investigation"},
    {"name": "endpoint_threat",
     "description": "Malware, suspicious execution or persistence on a host.",
     "domains": ["detection"], "sub_playbook": "GuardianTriageEndpointThreat", "skill": "xsoar_case_investigation"},
    {"name": "network_threat",
     "description": "Network detection: command and control, scanning, IDS/IPS or firewall alert, suspicious traffic.",
     "domains": ["detection"], "sub_playbook": "GuardianTriageNetworkThreat", "skill": "xsoar_case_investigation"},
    {"name": "data_exposure",
     "description": "Data loss prevention alert, exfiltration, or public or over-shared data.",
     "domains": ["detection", "posture"], "sub_playbook": "GuardianTriageDataExposure", "skill": "xsoar_case_investigation"},
    {"name": "vulnerability",
     "description": "A known CVE or scanner finding on a host, image or application.",
     "domains": ["posture"], "sub_playbook": "GuardianTriageVulnerability", "skill": "xsoar_case_investigation"},
    {"name": "other",
     "description": "None of the above fits; an analyst decides.",
     "domains": ["detection", "posture"], "sub_playbook": "GuardianTriageOther", "skill": ""},
]

_GUARDIAN_TRIAGE_VAGUE_SUMMARY = ("n/a", "na", "none", "unknown", "not sure", "no comment", "tbd", "test", "summary",
                                  "see above", "insufficient evidence", "insufficient information")


def guardian_triage_clean_type_row(row):
    """One `guardian_triage_types` row reduced to ``{name, description, domains, sub_playbook, skill}``, or ``None``
    when it has no usable name or no valid domain. `skill` is a string, or a ``{domain: skill}`` dict."""
    if not isinstance(row, dict):
        return None
    name = str(row.get("name") or "").strip().lower()
    if not name or not all(ch.isalnum() or ch == "_" for ch in name):
        return None
    domains = row.get("domains")
    domains = [d for d in GUARDIAN_TRIAGE_DOMAINS if isinstance(domains, (list, tuple)) and d in domains]
    if not domains:
        return None
    skill = row.get("skill")
    if isinstance(skill, dict):
        skill = {d: str(skill.get(d) or "").strip() for d in GUARDIAN_TRIAGE_DOMAINS if skill.get(d)}
    else:
        skill = str(skill or "").strip()
    return {
        "name": name,
        "description": " ".join(str(row.get("description") or "").split()),
        "domains": domains,
        "sub_playbook": str(row.get("sub_playbook") or "").strip(),
        "skill": skill,
    }


def guardian_triage_normalize_table(contents):
    """The triage taxonomy from the List's content (a JSON string or a dict) as ``{"severities": [...], "types":
    [row, ...]}``, or ``None`` when it is unusable. Rows without a valid name or domain are dropped, the first row
    of a repeated name wins, and an ``other`` row is always present (appended from the defaults when missing)."""
    import json  # defensive: the consuming script may not import it at the top
    if isinstance(contents, str):
        try:
            contents = json.loads(contents)
        except ValueError:
            return None
    if not isinstance(contents, dict):
        return None
    rows, seen = [], set()
    for raw in contents.get("types") or []:
        row = guardian_triage_clean_type_row(raw)
        if row and row["name"] not in seen:
            seen.add(row["name"])
            rows.append(row)
    if not rows:
        return None
    if GUARDIAN_TRIAGE_OTHER not in seen:
        rows.append(guardian_triage_clean_type_row(GUARDIAN_TRIAGE_DEFAULT_TYPES[-1]))
    severities = [s for s in (contents.get("severities") or []) if s in GUARDIAN_TRIAGE_SEVERITIES]
    return {"severities": severities or list(GUARDIAN_TRIAGE_SEVERITIES), "types": rows}


def guardian_triage_default_table():
    """The built-in taxonomy (same data as the shipped List)."""
    return guardian_triage_normalize_table({"severities": list(GUARDIAN_TRIAGE_SEVERITIES),
                                            "types": GUARDIAN_TRIAGE_DEFAULT_TYPES})


def guardian_triage_load_table():
    """``(table, source)``: the taxonomy read from the `guardian_triage_types` List (``source == "list"``), or the
    built-in one (``source == "default"``) when the List is missing, unreadable or malformed. Never raises."""
    try:
        result = guardian_execute("getList", {"listName": GUARDIAN_TRIAGE_LIST_NAME})
        if result["ok"]:
            contents = None
            for entry in result["data"] or []:
                if isinstance(entry, dict) and entry.get("Contents") is not None:
                    contents = entry["Contents"]
            table = guardian_triage_normalize_table(contents)
            if table:
                return table, "list"
    except Exception:
        pass
    return guardian_triage_default_table(), "default"


def guardian_triage_type_row(table, name):
    """The table row called `name`, or ``None``."""
    for row in (table or {}).get("types") or []:
        if row["name"] == name:
            return row
    return None


def guardian_triage_last_candidate(text):
    """The decoded triage object in `text`, or ``None``. Preference order:

    1. the LAST fenced JSON object (```json or plain ```) that carries an ``investigation_type`` key;
    2. else the whole stripped answer, when it is one JSON object (a model that answers with bare JSON);
    3. else the LAST balanced top-level ``{...}`` in the text that parses and carries ``investigation_type``
       (prose, then a bare object).

    Text before and after a fenced block is ignored, and an earlier draft is never a fallback for a last one. This
    only finds the object: whether it is valid is :func:`guardian_triage_validate`'s call, and an object that fails
    validation goes to the repair call like any other bad answer."""
    import json
    import re
    if not isinstance(text, str):
        return None
    pattern = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)
    for block in reversed(pattern.findall(text)):
        try:
            raw = json.loads(block)
        except (ValueError, TypeError):
            continue
        if isinstance(raw, dict) and "investigation_type" in raw:
            return raw
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            whole = json.loads(stripped)
        except (ValueError, TypeError):
            whole = None
        if isinstance(whole, dict):
            return whole
    decoder = json.JSONDecoder()
    found, position = None, text.find("{")
    while position != -1:
        try:
            raw, end = decoder.raw_decode(text, position)
        except (ValueError, TypeError, RecursionError):
            position = text.find("{", position + 1)
            continue
        if isinstance(raw, dict) and "investigation_type" in raw:
            found = raw
        position = text.find("{", end)
    return found


def guardian_triage_bool(value):
    """``True`` / ``False`` for a boolean or the text ``true`` / ``false``; ``None`` for anything else."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def guardian_triage_clean_entities(raw):
    """``key_entities`` reduced to the known lists of plain, bounded, de-duplicated strings. A value that is
    not a dict gives empty lists; a single string stands for a one-item list; non-strings are dropped.

    Whitespace is collapsed. An item longer than GUARDIAN_TRIAGE_ENTITY_MAX_CHARS (after that collapse) is DROPPED, never
    truncated: a cut-off identifier names nothing and a lookup given it looks like a clean "no entries", whereas a
    missing value shows up as a skipped lookup. A dropped item does not count toward GUARDIAN_TRIAGE_ENTITY_MAX_ITEMS,
    so it never crowds out a good one."""
    raw = raw if isinstance(raw, dict) else {}
    out = {}
    for key in GUARDIAN_TRIAGE_ENTITY_KEYS:
        value = raw.get(key)
        value = [value] if isinstance(value, str) else value
        items = []
        for item in value if isinstance(value, (list, tuple)) else []:
            if not isinstance(item, str):
                continue
            text = " ".join(item.split())
            if not text or len(text) > GUARDIAN_TRIAGE_ENTITY_MAX_CHARS:
                continue
            if text not in items:
                items.append(text)
            if len(items) >= GUARDIAN_TRIAGE_ENTITY_MAX_ITEMS:
                break
        out[key] = items
    return out


def guardian_triage_clean_analysis(raw):
    """The optional ``analysis`` text: whitespace collapsed, secrets scrubbed and cut to
    GUARDIAN_TRIAGE_ANALYSIS_MAX_CHARS. Anything that is not text gives an empty string."""
    if not isinstance(raw, str):
        return ""
    return guardian_scrub_secrets(" ".join(raw.split()), keep_identifiers=True)[:GUARDIAN_TRIAGE_ANALYSIS_MAX_CHARS].strip()


def guardian_triage_clean_complexity(raw):
    """The optional ``complexity``: ``low``, ``medium`` or ``high`` (case and surrounding spaces forgiven), else an empty
    string."""
    value = raw.strip().lower() if isinstance(raw, str) else ""
    return value if value in GUARDIAN_TRIAGE_COMPLEXITIES else ""


def guardian_triage_clean_recommendations(raw):
    """The optional ``recommendations`` list: at most GUARDIAN_TRIAGE_RECOMMENDATIONS_MAX_ITEMS non-empty strings,
    each whitespace-collapsed, scrubbed of secrets and cut to GUARDIAN_TRIAGE_RECOMMENDATION_MAX_CHARS. A single
    string stands for a one-item list; anything else gives an empty list."""
    items = [raw] if isinstance(raw, str) else raw
    out = []
    for item in items if isinstance(items, (list, tuple)) else []:
        if not isinstance(item, str):
            continue
        text = guardian_scrub_secrets(" ".join(item.split()), keep_identifiers=True)[:GUARDIAN_TRIAGE_RECOMMENDATION_MAX_CHARS].strip()
        if text:
            out.append(text)
        if len(out) >= GUARDIAN_TRIAGE_RECOMMENDATIONS_MAX_ITEMS:
            break
    return out


def guardian_triage_validate(raw, table=None):
    """Validate one decoded triage block and return it normalized, or ``None`` when it is not valid.

    Rules (the block is model-authored text produced after reading an untrusted narrative):
    ``severity`` and ``investigation_type`` must be values from the taxonomy (case and surrounding spaces are
    forgiven, nothing else); any other value rejects the WHOLE block, never a guess. ``confidence`` is required and
    is clamped to 0-100. ``likely_benign`` and ``escalate`` are booleans (default false when absent, invalid when
    present and not a boolean). ``summary`` must be a non-vague string of at least
    GUARDIAN_TRIAGE_SUMMARY_MIN_CHARS characters. ``next_step`` is optional. ``analysis`` and ``recommendations`` are
    optional too (see :func:`guardian_triage_clean_analysis` and :func:`guardian_triage_clean_recommendations`): a
    block without them is just as valid, and a malformed one is read as absent. So is ``complexity`` (``low``, ``medium``
    or ``high``; anything else is read as absent and the block stays valid). ``key_entities`` is cleaned (see
    :func:`guardian_triage_clean_entities`). Unknown keys are dropped.

    Whether the type fits the incident's domain is NOT decided here: that is GuardianTriageResult's call, not the model's
    and not this validator's.
    """
    if not isinstance(raw, dict):
        return None
    table = table or guardian_triage_default_table()
    severity = str(raw.get("severity", "")).strip().lower()
    if severity not in table["severities"]:
        return None
    itype = str(raw.get("investigation_type", "")).strip().lower()
    if guardian_triage_type_row(table, itype) is None:
        return None
    confidence = raw.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float, str)):
        return None
    try:
        confidence = max(0, min(100, int(float(confidence))))
    except (TypeError, ValueError, OverflowError):  # "inf", 1e999 and Infinity parse as floats but have no int
        return None
    flags = {}
    for key in ("likely_benign", "escalate"):
        if key not in raw or raw.get(key) is None:
            flags[key] = False
            continue
        flag = guardian_triage_bool(raw.get(key))
        if flag is None:
            return None
        flags[key] = flag
    summary = raw.get("summary")
    if not isinstance(summary, str):
        return None
    summary = " ".join(summary.split())
    if len(summary) < GUARDIAN_TRIAGE_SUMMARY_MIN_CHARS or summary.lower().rstrip(".") in _GUARDIAN_TRIAGE_VAGUE_SUMMARY:
        return None
    next_step = raw.get("next_step")
    next_step = " ".join(next_step.split())[:GUARDIAN_TRIAGE_NEXT_STEP_MAX_CHARS] if isinstance(next_step, str) else ""
    return {
        "severity": severity,
        "investigation_type": itype,
        "confidence": confidence,
        "likely_benign": flags["likely_benign"],
        "escalate": flags["escalate"],
        "summary": summary[:GUARDIAN_TRIAGE_SUMMARY_MAX_CHARS],
        "key_entities": guardian_triage_clean_entities(raw.get("key_entities")),
        "next_step": next_step,
        "analysis": guardian_triage_clean_analysis(raw.get("analysis")),
        "recommendations": guardian_triage_clean_recommendations(raw.get("recommendations")),
        "complexity": guardian_triage_clean_complexity(raw.get("complexity")),
    }


def guardian_triage_parse_block(text, table=None):
    """The validated triage block from `text` (the last fenced JSON block, else a bare JSON answer, else the last bare
    object that has an ``investigation_type`` key -- see :func:`guardian_triage_last_candidate`), or ``None`` (no
    such object, malformed JSON, or an invalid one -- see :func:`guardian_triage_validate`)."""
    return guardian_triage_validate(guardian_triage_last_candidate(text), table)


# --- Guardian's section of an incident's details -------------------------------------------------------------------
# GuardianIncidentSummary appends one section to the end of an incident's `details`, behind this marker line (the same
# marker the Cortex platform edition puts at the end of an issue's description, hence the helper names). The evidence
# packet, the incident pin, every tool result and the eval harvest drop that section again, so the model never reads
# Guardian's own earlier conclusion back as if it were evidence about the incident.

GUARDIAN_ISSUE_SECTION_MARKER = "--- Guardian (automated) ---"
#: What GuardianIncidentSummary puts between the original text and the marker.
GUARDIAN_ISSUE_SECTION_GAP = "\n\n"


def guardian_split_issue_section(text):
    """``(original, section)``: the details text above the Guardian section, exactly as it was before the section was
    appended, and the section itself (the marker line to the end; empty when there is none). The gap the writer put
    before the marker is not part of the original. A marker is a line that holds nothing but the marker text."""
    import re
    if not isinstance(text, str):
        return "", ""
    match = re.search(r"(?m)^[ \t]*" + re.escape(GUARDIAN_ISSUE_SECTION_MARKER) + r"[ \t\r]*$", text)
    if match is None:
        return text, ""
    original = text[:match.start()]
    for gap in (GUARDIAN_ISSUE_SECTION_GAP, "\r\n\r\n"):
        if original.endswith(gap):
            original = original[:-len(gap)]
            break
    return original, text[match.start():]


def guardian_strip_issue_section(text):
    """``text`` without Guardian's section (everything from the marker line to the end). Text that has no marker, and
    anything that is not text, comes back unchanged."""
    return guardian_split_issue_section(text)[0] if isinstance(text, str) and GUARDIAN_ISSUE_SECTION_MARKER in text else text


def guardian_strip_issue_section_deep(value, _depth=0):
    """``value`` with Guardian's details section removed from every string in it (dicts and lists are walked, up to
    eight levels). A string that holds JSON text, where the line breaks are written as ``\\n``, loses the section too: from
    the marker to the end of that JSON string. Values without the marker come back as they are."""
    import re
    if isinstance(value, str):
        if GUARDIAN_ISSUE_SECTION_MARKER not in value:
            return value
        stripped = guardian_strip_issue_section(value)
        if GUARDIAN_ISSUE_SECTION_MARKER in stripped:
            stripped = re.sub(r'(?:(?:\\r)?\\n){0,2}' + re.escape(GUARDIAN_ISSUE_SECTION_MARKER) + r'(?:\\.|[^"\\])*', "", stripped)
        return stripped
    if _depth >= 8:
        return value
    if isinstance(value, dict):
        return {key: guardian_strip_issue_section_deep(item, _depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [guardian_strip_issue_section_deep(item, _depth + 1) for item in value]
    return value


# </GUARDIAN_COMMON>
# </GUARDIAN_COMMON_INJECT>


GUARDIAN_EVAL_RESULTS_LIST = "guardian_eval_results"
GUARDIAN_EVAL_TRIGGER_SOURCE_VALUE = "eval"
GUARDIAN_EVAL_INCIDENT_TYPE = "Guardian Eval Case"
GUARDIAN_EVAL_AUDIT_LIST = "guardian_audit"

#: `runStatus` values that mean "the attached playbook is no longer
#: ticking" -- either outcome is scoreable; anything else (``""``,
#: ``"running"``, ``"waiting"``) means still in flight, not yet scoreable.
GUARDIAN_EVAL_CONCLUDED_RUN_STATUSES = ("completed", "failed")

#: The CustomField (see `IncidentFields/incidentfield-guardianevalrunlabel.json`)
#: an eval driver incident carries its launch's `run_label` under -- read back
#: by :func:`guardian_eval_score_one` into the scored row's own `"run_label"`
#: key. It is what makes :func:`guardian_eval_report_data_by_run_label` and
#: :func:`guardian_eval_compare_runs` possible.
GUARDIAN_EVAL_RUN_LABEL_FIELD = "guardianevalrunlabel"

#: The summary prefix GuardianReasoningTick writes (to `guardianblastradius`) on the Inconclusive placeholder it records
#: when the model returned no usable verdict block. A run with that placeholder produced no verdict, so it scores like
#: a run with none.
GUARDIAN_UNSTRUCTURED_SUMMARY_MARKER = "[Format violation: no verdict block]"

#: The defined value for a case's OPTIONAL `expected_outcome` field (see
#: `GUARDIAN_EVAL_CASES`'s own comment). Marks a REGRESSION case whose correct
#: behavior is that the run does NOT reach a verdict at all -- genuinely different from reaching
#: one and it being `"Inconclusive"` (a model successfully recognizing
#: insufficient evidence and SAYING so is a normal, scored verdict; a
#: `no_conclusion` case instead tests whether the model holds back from
#: concluding altogether -- e.g. it should keep gathering evidence, escalate
#: to the analyst, or hit a safety boundary that stops it short of any
#: verdict). Scored on a completely separate, additive metric axis in
#: :func:`guardian_eval_report_data` (`regression_no_conclusion_*`) -- these
#: rows NEVER enter the confusion matrix / binary / exact / technique
#: accuracy pipeline, since their `expected_verdict` (still required, kept
#: `"Inconclusive"` by convention for schema/test consistency) is not a real
#: accuracy comparison target for this case type.
GUARDIAN_EVAL_OUTCOME_NO_CONCLUSION = "no_conclusion"

#: The labeled-case library of single-incident cases, each `{case_id, name,
#: details, expected_verdict, expected_techniques}`, plus an OPTIONAL
#: `expected_outcome` (only `GUARDIAN_EVAL_OUTCOME_NO_CONCLUSION` is
#: defined; absent means ordinary verdict-scored behavior, which is every
#: case in this library). `details` is the FULL investigation narrative written directly onto the driver
#: incident (see :func:`guardian_eval_launch_case`) -- it deliberately states
#: each enrichment OUTCOME (e.g. "returns known-bad"/"returns known-good"/
#: "returns Unknown") rather than just raw indicators, so the expected verdict
#: is derivable even though the live agent independently re-enriches every
#: indicator itself (a synthetic/reserved-range indicator would otherwise
#: return null reputation and bias a competent agent toward Inconclusive).
#: `expected_verdict` is one of `Malicious`/`Suspicious`/`Benign`/
#: `Inconclusive`; `expected_techniques` is a list of parent-level ATT&CK ids
#: (`T####`), empty for cases with no applicable technique.
GUARDIAN_EVAL_CASES = (
    {
        "case_id": "cred-phish-okta-clone",
        "name": "Credential phishing - cloned Okta portal",
        "details": (
            "Finance users received an email from 'IT Service Desk <it-support@acme-sso-verify.com>' "
            "about an 'expired SSO session', linking to https://acme-sso-verify.com/login -- a pixel "
            "clone of the corporate Okta page. Threat-intel lookup on acme-sso-verify.com returns "
            "KNOWN-BAD (registered 2 days ago, 31 vendor phishing detections); the IP it resolves to, "
            "45.83.220.14, returns known credential-harvesting C2 (Netherlands hosting). Proxy logs "
            "confirm j.rivera@acme submitted credentials, and 20 min later a successful VPN login for "
            "j.rivera came from 45.83.220.14, followed by a new Outlook inbox rule deleting "
            "'password reset' mail."
        ),
        "expected_verdict": "Malicious",
        "expected_techniques": ["T1564", "T1566", "T1078"],
    },
    {
        "case_id": "impossible-travel-mfa-satisfied",
        "name": "Impossible travel with MFA satisfied - shared VPN exit",
        "details": (
            "Okta sign-in logs show m.chen@acme authenticating from Chicago, IL at 14:02 UTC and again "
            "from Lagos, Nigeria at 14:41 UTC -- a geographic jump the SOC's impossible-travel rule "
            "flags as physically infeasible in 39 minutes. Threat-intel lookup on the Lagos IP, "
            "102.89.44.201, returns SUSPICIOUS (2 of 60 vendor detections, tagged as a commercial "
            "VPN/proxy exit node, not confirmed malicious infrastructure). The Lagos sign-in satisfied "
            "a push-MFA challenge that m.chen approved from their own enrolled device (no MFA-fatigue "
            "pattern -- a single prompt, approved within 8 seconds, no prior denied prompts). No "
            "anomalous activity followed: no mass mailbox export, no new inbox rules, no OAuth grants, "
            "no privileged role changes in the 4 hours after sign-in. m.chen, contacted by phone, "
            "reports having used a commercial VPN while traveling but cannot confirm the exact exit "
            "location."
        ),
        "expected_verdict": "Suspicious",
        "expected_techniques": ["T1078"],
    },
    {
        "case_id": "vuln-scan-known-infra",
        "name": "Vulnerability-scan traffic from known scanner appliance",
        "details": (
            "The IDS fired 40+ port-scan alerts in 3 minutes for source IP 10.20.4.15 sweeping TCP "
            "ports across the 10.20.6.0/24 finance subnet. CMDB/asset-inventory lookup on 10.20.4.15 "
            "returns KNOWN-GOOD: it is the corporate Tenable.io scanner appliance, and change ticket "
            "CHG-4471 shows an authorized, currently-in-window monthly vulnerability scan of that exact "
            "subnet. Threat-intel lookup on 10.20.4.15 also returns known-good (internal RFC1918 "
            "address, no external reputation hits). No authentication attempts, exploit payloads, or "
            "data-exfiltration indicators are associated with the source in the same window -- traffic "
            "is scan-only (SYN probes), consistent with the ticketed scan."
        ),
        "expected_verdict": "Benign",
        "expected_techniques": [],
    },
    {
        "case_id": "single-dlp-alert-thin-signal",
        "name": "Single DLP alert, no corroborating signal",
        "details": (
            "A DLP rule fired once for contractor endpoint LT-CTR-0231 (user d.osei) uploading a file "
            "named 'notes.txt' (82KB) to personal Dropbox over HTTPS. This is the only alert involving "
            "this user or host in the preceding 30 days. Threat-intel lookup on the destination "
            "(www.dropbox.com) and the uploading endpoint's public IP both return UNKNOWN -- Dropbox is "
            "an unclassified multi-tenant SaaS domain with no case-specific signal either way, and the "
            "endpoint IP has no vendor history. The DLP rule matched on filename pattern only; file "
            "contents were not captured, so there is no way to confirm what 'notes.txt' actually "
            "contains. No related process, network, or authentication anomalies appear for d.osei or "
            "LT-CTR-0231 in the same window."
        ),
        "expected_verdict": "Inconclusive",
        "expected_techniques": [],
    },
    # --- additional Malicious cases (confirmed hostile: enrichment known-bad
    # --- + corroborating behavior) --------------------------------------------
    {
        "case_id": "oauth-consent-grant-mail-exfil",
        "name": "OAuth illicit consent grant - mailbox exfiltration app",
        "details": (
            "Legal team member r.patel@acme received an email titled 'Action required: sign this PDF' "
            "containing a link to authorize an app called 'Quick PDF Signer' against the corporate "
            "Microsoft 365 tenant, requesting Mail.Read, Mail.Send, and offline_access scopes. Azure AD "
            "consent logs show r.patel approved the grant at 09:14 UTC. App-reputation lookup on the "
            "app's publisher domain, quickpdfsigner-app.net, returns KNOWN-BAD (registered 6 days prior, "
            "flagged by 2 vendors as a known OAuth consent-phishing app, and cross-referenced against "
            "Microsoft's own malicious-app indicator list). Within 12 minutes of the grant, the app's "
            "service principal used the issued token to read 340 messages in r.patel's mailbox via Graph "
            "API from an IP that independently returns known-bad (same ASN as 3 other reported "
            "consent-phishing campaigns), then created a mail-forwarding rule silently BCC'ing all "
            "incoming Legal correspondence to an external address. No password or MFA prompt was ever "
            "shown -- consent-phishing bypasses both."
        ),
        "expected_verdict": "Malicious",
        "expected_techniques": ["T1566", "T1528", "T1114"],
    },
    {
        "case_id": "c2-beacon-confirmed-known-bad",
        "name": "C2 beaconing to confirmed known-bad IP",
        "details": (
            "EDR on workstation WKS-FIN-0087 (user t.oyelaran) flagged a background process, "
            "updater_svc.exe (unsigned), making outbound HTTPS connections to 185.220.101.47 every 60 "
            "seconds (+/-2s jitter) -- a pattern consistent with C2 beaconing. Threat-intel lookup on "
            "185.220.101.47 returns KNOWN-BAD (tagged active Cobalt Strike C2 infrastructure, 44 vendor "
            "detections, seen in 3 unrelated incident feeds in the past week). File-hash lookup on "
            "updater_svc.exe also returns KNOWN-BAD (matches a published Cobalt Strike beacon hash). 20 "
            "minutes after beaconing began, the same process spawned an encoded PowerShell command "
            "(`powershell -enc ...`) that enumerated local Active Directory group membership, consistent "
            "with post-compromise reconnaissance."
        ),
        "expected_verdict": "Malicious",
        "expected_techniques": ["T1071", "T1059", "T1069"],
    },
    {
        "case_id": "lateral-movement-rdp-compromised-admin",
        "name": "Lateral movement via RDP using compromised admin credential",
        "details": (
            "Security logs show the domain admin account svc-admin-jsmith authenticating via RDP (event "
            "4624, LogonType 10) to 5 different servers (DC-02, FILE-03, SQL-01, APP-07, BKUP-01) within "
            "an 8-minute window from workstation WKS-CORP-0192 -- a host svc-admin-jsmith has never "
            "logged into before. Asset-inventory lookup confirms WKS-CORP-0192 is a standard end-user "
            "laptop, not an admin jump box, and the same account was flagged 2 hours earlier for a "
            "CONFIRMED Mimikatz-signature credential-dumping attempt (lsass.exe memory access) on that "
            "same workstation -- EDR's process-behavior detection, not a heuristic warning. On DC-02, a "
            "new service was created remotely immediately after the RDP logon, matching a known "
            "PsExec-style lateral-movement pattern. No change ticket or scheduled maintenance window "
            "covers this activity."
        ),
        "expected_verdict": "Malicious",
        "expected_techniques": ["T1003", "T1078", "T1021", "T1569"],
    },
    {
        "case_id": "lateral-movement-psexec-smb-admin-share",
        "name": "Lateral movement via PsExec over SMB admin shares",
        "details": (
            "Following an earlier confirmed phishing compromise on WKS-MKT-0044 (user l.dubois), SMB "
            "logs show the local admin account on that workstation authenticating to the ADMIN$ share on "
            "6 other marketing-subnet hosts within 4 minutes, copying a binary named svchost_update.exe "
            "to each, then immediately creating and starting a remote service (PSEXESVC) on all 6 hosts. "
            "Hash lookup on svchost_update.exe returns KNOWN-BAD (matches a published commodity-loader "
            "hash, 38 vendor detections). None of the 6 destination hosts are in l.dubois's normal job "
            "function or prior access history, and no change ticket authorizes this activity. Two of the "
            "6 hosts subsequently began the same 60-second C2 beacon pattern observed on the originating "
            "workstation."
        ),
        "expected_verdict": "Malicious",
        "expected_techniques": ["T1021", "T1078", "T1570", "T1569"],
    },
    {
        "case_id": "data-exfil-known-bad-file-share",
        "name": "Data exfiltration to known-bad external file-sharing site",
        "details": (
            "DLP and proxy logs show endpoint WKS-ENG-0210 (user p.nguyen, R&D) creating a "
            "password-protected archive (design_specs_q3.7z, 1.4GB) at 02:11 local time, then uploading "
            "it via HTTPS to filedump-secure.cc, a domain neither p.nguyen nor anyone on the R&D team "
            "has visited before. Threat-intel lookup on filedump-secure.cc returns KNOWN-BAD (tagged an "
            "actively-abused anonymous file-drop service used in multiple documented exfiltration "
            "campaigns, 19 vendor detections); the destination IP, 91.219.237.66, independently returns "
            "known-bad bulletproof hosting. The upload volume is roughly 40x p.nguyen's normal daily "
            "outbound baseline, falls outside their normal working hours, and no VPN/remote-work "
            "justification or business ticket covers the transfer."
        ),
        "expected_verdict": "Malicious",
        "expected_techniques": ["T1560", "T1567"],
    },
    {
        "case_id": "ransomware-precursor-shadow-copy-mass-rename",
        "name": "Ransomware precursor - shadow-copy deletion and mass file rename",
        "details": (
            "On file server FILE-05, an interactive session under service account svc-backup executed "
            "`vssadmin.exe delete shadows /all /quiet`, removing all volume shadow copies, at 03:02 UTC. "
            "Behavioral-detection lookup on this exact command line returns KNOWN-BAD (matches a "
            "published pre-ransomware TTP used by at least 2 named ransomware affiliates). Within the "
            "following 6 minutes, EDR recorded over 4,000 files across 2 shared drives being renamed "
            "with a new `.hcp9x` extension at a rate far exceeding any legitimate backup or migration "
            "job -- consistent with an active encryption routine, not a completed one. svc-backup's "
            "session source, internal IP 192.168.44.19, was itself flagged 40 minutes earlier for the "
            "same C2 beacon pattern (contacting a threat-intel-confirmed KNOWN-BAD IP, 45.147.230.12) "
            "seen on a separate compromised host. No backup-maintenance window or change ticket covers "
            "this activity."
        ),
        "expected_verdict": "Malicious",
        "expected_techniques": ["T1490", "T1486", "T1071"],
    },
    {
        "case_id": "web-shell-iis-known-bad-c2",
        "name": "Web shell dropped on public-facing IIS server",
        "details": (
            "WAF/IIS logs on public-facing server WEB-DMZ-02 show a file-upload endpoint accepting a "
            "file named update.aspx at 04:47 UTC from external IP 194.61.55.12, followed immediately by "
            "repeated GET requests to /update.aspx with an encoded `cmd` parameter. Hash lookup on "
            "update.aspx returns KNOWN-BAD (matches a published ASPX web-shell family, 27 vendor "
            "detections); threat-intel lookup on 194.61.55.12 also returns known-bad (associated with 4 "
            "other documented web-shell deployment campaigns). Process-creation logs confirm w3wp.exe "
            "(the IIS worker process) spawning cmd.exe and whoami.exe moments after each request -- a "
            "process/network pairing IIS never legitimately produces. The upload endpoint's own "
            "application configuration only permits image files."
        ),
        "expected_verdict": "Malicious",
        "expected_techniques": ["T1190", "T1505", "T1059"],
    },
    {
        "case_id": "malicious-scheduled-task-persistence-download",
        "name": "Malicious scheduled task for persistence and payload download",
        "details": (
            "On workstation WKS-HR-0033, a scheduled task named 'AdobeUpdateCheck' was created at 15:20 "
            "UTC to run every 30 minutes, executing a command that downloads a file from "
            "hxxp://198.51.100.77/upd.bin and runs it via rundll32.exe. SCCM/Intune show no "
            "corresponding approved push for this task, and the HR employee whose account created it "
            "denies doing so when contacted. Threat-intel lookup on 198.51.100.77 returns KNOWN-BAD "
            "(flagged active malware-staging infrastructure, 33 vendor detections); the downloaded "
            "payload's hash, retrieved by IR for analysis, also returns known-bad (matches a published "
            "commodity RAT). The task had already executed twice successfully before detection, each "
            "run followed by a brief outbound connection to the same IP."
        ),
        "expected_verdict": "Malicious",
        "expected_techniques": ["T1053", "T1105", "T1218", "T1071"],
    },
    # --- additional Suspicious cases (real hostile signal, not confirmed) ----
    {
        "case_id": "oauth-consent-suspicious-broad-scope",
        "name": "OAuth consent grant to unverified app with broad scope",
        "details": (
            "Sales team member k.abara approved an OAuth consent prompt for an app called 'SalesBoost "
            "Sync,' requesting Contacts.Read, Mail.Read, and Files.ReadWrite.All -- broader than the "
            "app's stated purpose. The app's publisher is unverified (no Microsoft Partner verification "
            "badge) and the consent link arrived via an unsolicited email k.abara can no longer produce. "
            "App-reputation lookup on the app's redirect domain, salesboost-sync.io, returns SUSPICIOUS "
            "(3 of 55 vendor detections, tagged 'newly observed, low-reputation,' not confirmed "
            "malicious). Graph API logs show the app made a small number of Contacts.Read calls in the "
            "hour after consent, but no mass mailbox export, external forwarding rule, or file download "
            "has been observed since."
        ),
        "expected_verdict": "Suspicious",
        "expected_techniques": ["T1528"],
    },
    {
        "case_id": "c2-beacon-suspicious-low-confidence",
        "name": "Periodic outbound beacon to low-confidence-reputation IP",
        "details": (
            "NDR flagged workstation WKS-OPS-0071 making a low-volume HTTPS connection to 103.224.182.9 "
            "roughly every 5 minutes for the past 3 hours -- a regular-interval pattern resembling "
            "beaconing but with looser (+/-30-90s) jitter than a scripted C2 cadence. Threat-intel "
            "lookup on 103.224.182.9 returns SUSPICIOUS (3 of 62 vendor detections, generic "
            "'low-reputation/unrated' tag, hosted on shared cloud infrastructure with no specific "
            "C2-family attribution). The initiating process is a signed analytics SDK "
            "(telemetry-agent.exe) bundled with a third-party inventory-management tool the Ops team is "
            "known to use, but that vendor's own documentation does not describe this connection "
            "behavior. No process injection, credential access, or lateral-movement activity has been "
            "observed from this host."
        ),
        "expected_verdict": "Suspicious",
        "expected_techniques": ["T1071"],
    },
    {
        "case_id": "lateral-movement-rdp-offhours-ambiguous",
        "name": "Off-hours RDP logon to server outside normal access pattern",
        "details": (
            "Security logs show admin account j.oduya authenticating via RDP to APP-SERVER-14 at 01:47 "
            "local time -- a server appearing in j.oduya's access history only twice in the past 6 "
            "months, both during documented maintenance windows; no change ticket matches this session. "
            "The source IP is internal (RFC1918), so threat-intel lookup returns no reputation signal "
            "either way (not applicable to an internal address). No file changes, new services, "
            "credential-dumping indicators, or outbound network anomalies were observed on APP-SERVER-14 "
            "in the 2 hours following the logon, and the session lasted only 6 minutes before logging "
            "off cleanly. j.oduya has not yet responded to the SOC's outreach to confirm or deny "
            "performing this access."
        ),
        "expected_verdict": "Suspicious",
        "expected_techniques": ["T1078", "T1021"],
    },
    {
        "case_id": "insider-misuse-mass-file-access-resignation",
        "name": "Insider - mass access to sensitive files ahead of resignation",
        "details": (
            "HR systems show contractor a.fontaine submitted a resignation notice 2 days ago, effective "
            "in 1 week. In the past 18 hours, file-access logs show a.fontaine opened 210 documents "
            "across the 'Contracts' and 'Pricing' SharePoint sites -- roughly 15x their average daily "
            "access count over the prior 3 months, and covering multiple client accounts outside their "
            "assigned portfolio. This is purely internal file access; no USB, personal-cloud, or "
            "email-attachment egress for any of these files has been recorded by DLP in the same window, "
            "so there is no destination to run threat-intel enrichment against. a.fontaine's manager was "
            "not consulted before this access and cannot confirm a legitimate handoff reason."
        ),
        "expected_verdict": "Suspicious",
        "expected_techniques": ["T1213"],
    },
    {
        "case_id": "exfil-suspicious-cloud-storage-mixed-signal",
        "name": "Large outbound transfer to newly-observed cloud storage domain",
        "details": (
            "Proxy logs show endpoint WKS-FIN-0056 (user s.okonkwo) uploading 620MB across 4 files to "
            "cloudvault-transfer.app over HTTPS -- a domain the proxy has never logged traffic to for "
            "this tenant before. Threat-intel lookup on cloudvault-transfer.app returns SUSPICIOUS (6 of "
            "58 vendor detections, tagged 'newly registered file-transfer service,' not confirmed "
            "malicious but also not an approved corporate SaaS domain). s.okonkwo, contacted by the SOC, "
            "states they were sending a large client deliverable and 'couldn't get it through email "
            "attachment limits,' but the uploaded file names (Q3_board_deck_draft.pptx, "
            "comp_review_2026.xlsx) don't obviously match a client-deliverable description, and no "
            "manager approval or business-justification ticket covers using an unapproved transfer "
            "service."
        ),
        "expected_verdict": "Suspicious",
        "expected_techniques": ["T1567"],
    },
    # --- additional Benign cases (confirmed non-threat / expected activity) --
    {
        "case_id": "expected-admin-maintenance-scheduled-task",
        "name": "Scheduled task created during authorized patch window",
        "details": (
            "EDR flagged a new scheduled task, 'MonthlyPatchRollout,' created on 60 workstations in the "
            "Finance OU at 22:05 UTC, running a signed PowerShell script that installs pending Windows "
            "updates and reboots. Change-ticket lookup confirms CHG-5210, an approved monthly "
            "patch-deployment window for exactly this OU and time slot, executed by the known "
            "IT-Automation service account svc-patchmgr. Lookup on the script's publisher certificate "
            "and the SCCM distribution-point IP it downloads from both return KNOWN-GOOD (internal "
            "signed certificate; RFC1918 distribution point already in the asset inventory). No "
            "unexpected process, network, or credential-use anomaly accompanies the task's creation or "
            "execution on any of the 60 hosts."
        ),
        "expected_verdict": "Benign",
        "expected_techniques": [],
    },
    {
        "case_id": "known-good-saas-oauth-login-zoom",
        "name": "Known-good SaaS OAuth grant - approved Zoom add-on",
        "details": (
            "Sales team member b.harrison approved an OAuth consent prompt for 'Zoom Scheduler for "
            "Outlook,' requesting Calendars.ReadWrite. The app's publisher is Zoom Video Communications, "
            "Inc., verified via Microsoft Partner verification, and the app already appears in the "
            "tenant's IT-approved app catalog (added 8 months ago for company-wide Zoom rollout). "
            "App-reputation lookup on the app's domain, zoom.us, returns KNOWN-GOOD (established, "
            "high-reputation SaaS vendor, zero vendor detections, category business/collaboration). "
            "Graph API activity after the grant is limited to normal calendar read/write calls "
            "consistent with a meeting-scheduling add-in, matching the same app already in active use by "
            "140 other employees."
        ),
        "expected_verdict": "Benign",
        "expected_techniques": [],
    },
    {
        "case_id": "dlp-false-positive-approved-sharepoint-transfer",
        "name": "DLP false positive - approved SharePoint client-deliverable upload",
        "details": (
            "A DLP rule fired for user r.singh (Client Services) uploading a file that pattern-matched "
            "as 'financial account numbers' to a SharePoint site named "
            "'ClientDeliverables-ExternalShare.' The destination is an internal, IT-provisioned "
            "SharePoint Online tenant site (sharepoint.com, Microsoft-owned) that returns KNOWN-GOOD on "
            "lookup and is explicitly configured by IT for authorized external client-sharing with "
            "guest-access review already enabled. Manager confirmation is on file: r.singh's team lead "
            "approved this exact deliverable (ticket CS-1187) for client XYZ Corp the same morning, and "
            "the flagged 'account numbers' pattern is a false-positive match against the client's own "
            "internal reference IDs, not financial account data. No other unusual access or transfer "
            "activity is associated with r.singh in the same window."
        ),
        "expected_verdict": "Benign",
        "expected_techniques": [],
    },
    {
        "case_id": "patch-management-traffic-wsus-sccm",
        "name": "Beaconing alert resolved as internal patch-management traffic",
        "details": (
            "NDR flagged workstation WKS-LEG-0019 making a regular-interval outbound connection every 4 "
            "hours to 10.20.2.11, initially scored as possible beaconing due to the consistent cadence. "
            "Asset-inventory lookup on 10.20.2.11 returns KNOWN-GOOD: it is the corporate WSUS/SCCM "
            "patch-management server, and the connection is the endpoint's standard update-check-in "
            "cycle (confirmed by the expected User-Agent string and the /ClientWebService/client.asmx "
            "WSUS endpoint path in proxy logs). Threat-intel lookup on 10.20.2.11 also returns known-good "
            "(internal RFC1918 address, already documented in the CMDB as core patch infrastructure). No "
            "payload download outside the standard signed-update catalog and no unexpected process "
            "occurs, and the identical pattern is observed across 400+ other managed endpoints in the "
            "same subnet."
        ),
        "expected_verdict": "Benign",
        "expected_techniques": [],
    },
    {
        "case_id": "security-tool-self-test-eicar-canary",
        "name": "EDR self-test alert - EICAR canary file",
        "details": (
            "The EDR platform generated a 'malware detected' alert on server MON-EDR-01 for a file named "
            "eicar_canary_2026-07-15.txt, immediately quarantined. Hash lookup on the file confirms it "
            "matches the industry-standard EICAR test string (a benign, universally-recognized antivirus "
            "self-test file, not real malware) -- KNOWN-GOOD/expected. Investigation confirms the file "
            "was written and detected by the EDR vendor's own scheduled detection-health-check job, "
            "which runs every 24 hours on a designated canary host to verify the agent is actively "
            "scanning and alerting, per the vendor's documented self-test mechanism (change ticket "
            "MON-0092 documents this canary job's existence). No other process, network, or user "
            "activity is associated with this event."
        ),
        "expected_verdict": "Benign",
        "expected_techniques": [],
    },
    # --- additional Inconclusive cases (genuinely insufficient signal) -------
    {
        "case_id": "isolated-failed-login-unknown-ip",
        "name": "Single failed login from unfamiliar IP, no follow-up",
        "details": (
            "Authentication logs show exactly one failed login attempt for user o.laurent from IP "
            "41.203.18.94 at 03:15 UTC -- no successful login followed, and no further attempts from "
            "this or any other unusual IP occurred in the following 7 days. Threat-intel lookup on "
            "41.203.18.94 returns UNKNOWN -- no reputation history, not listed on any watchlist, not "
            "flagged as VPN/proxy/hosting infrastructure, no vendor detections either way. o.laurent's "
            "normal sign-in pattern already shows occasional travel-related logins from varied IPs, and "
            "they were not contacted given the single low-severity alert. No other account, endpoint, or "
            "network anomaly is associated with o.laurent in the surrounding 30-day window."
        ),
        "expected_verdict": "Inconclusive",
        "expected_techniques": [],
    },
    {
        "case_id": "unattributed-rare-process-hash-unknown",
        "name": "Rare unsigned process observed once, hash unattributed",
        "details": (
            "EDR flagged a single execution of an unsigned binary, svcmgr_helper.exe, on workstation "
            "WKS-IT-0004 (user g.silva) at 11:40 UTC -- the process ran for under 2 seconds, made no "
            "network connections, spawned no child processes, and modified no files outside its own "
            "working directory. Hash lookup on svcmgr_helper.exe returns UNKNOWN -- not present in any "
            "vendor's malware database and not present in any known-good software catalog either (a "
            "genuinely unrecognized binary, not merely low-prevalence). No other workstation in the "
            "environment has ever executed this file, and g.silva does not recall running it or "
            "recognize the filename when asked. No related process, credential, or network indicator has "
            "surfaced anywhere else in the environment in the following 5 days."
        ),
        "expected_verdict": "Inconclusive",
        "expected_techniques": [],
    },
)

#: The RUNTIME case store -- `createList`-ed lazily on first write, like
#: `GUARDIAN_EVAL_RESULTS_LIST`, so it is never pack-seeded (a pack-seeded List
#: is immutable at runtime). Same case schema as `GUARDIAN_EVAL_CASES`
#: (`case_id`/`name`/`details`/`expected_verdict`/`expected_techniques`,
#: optional `expected_outcome`) -- see :func:`guardian_eval_all_cases` for how
#: the two sources combine, and `GuardianEvalHarvest.py` for the writer this
#: List has. An analyst can also `!setList` a hand-authored addition directly.
GUARDIAN_EVAL_RUNTIME_CASES_LIST = "guardian_eval_cases_runtime"


def _guardian_eval_validate_case_shape(case):
    """Strictly validate one case-shaped dict against the same schema the
    static library follows -- unlike :func:`guardian_normalize_techniques`
    (which SILENTLY DROPS a malformed technique id), this is a hard pass/fail: a
    runtime-sourced case is untrusted input (anyone with `!setList` access
    could write malformed JSON into :data:`GUARDIAN_EVAL_RUNTIME_CASES_LIST`),
    and every consumer downstream (`guardian_eval_run`'s dispatch loop,
    `guardian_eval_report_data`'s scoring math) assumes a well-formed case --
    e.g. `case["expected_verdict"]` is a bare, unguarded key access elsewhere
    in this file. A malformed row must never reach those call sites; it must
    be skipped (and logged) at the LOAD boundary instead.

    :param case: The value to validate.
    :return: ``(ok, reason)`` -- `reason` is ``None`` on success, else a
        short human-readable description of what's wrong.
    :rtype: ``tuple(bool, str or None)``
    """
    if not isinstance(case, dict):
        return False, "not a dict"
    required = {"case_id", "name", "details", "expected_verdict", "expected_techniques"}
    missing = required - set(case)
    if missing:
        return False, "missing required key(s): {}".format(", ".join(sorted(missing)))
    if not isinstance(case.get("case_id"), str) or not case["case_id"].strip():
        return False, "case_id must be a non-empty string"
    if not isinstance(case.get("name"), str) or not isinstance(case.get("details"), str):
        return False, "name and details must both be strings"
    if case.get("expected_verdict") not in GUARDIAN_EVAL_VALID_VERDICTS:
        return False, "expected_verdict {!r} is not one of {}".format(
            case.get("expected_verdict"), GUARDIAN_EVAL_VALID_VERDICTS
        )
    techniques = case.get("expected_techniques")
    if not isinstance(techniques, list) or not all(
        isinstance(t, str) and re.match(GUARDIAN_TECHNIQUE_PATTERN_STR, t) for t in techniques
    ):
        return False, "expected_techniques must be a list of T#### (or T####.###) strings"
    outcome = case.get("expected_outcome")
    if outcome is not None and outcome != GUARDIAN_EVAL_OUTCOME_NO_CONCLUSION:
        return False, "expected_outcome {!r} is not a recognized value".format(outcome)
    return True, None


def guardian_eval_load_runtime_cases():
    """Read + validate :data:`GUARDIAN_EVAL_RUNTIME_CASES_LIST`. Best-effort
    like every other List read in this module: an absent/unreadable/
    malformed List degrades to `[]` (the static library alone), never a
    crashed run.

    :return: The list of well-formed case dicts found. A malformed
        individual row is skipped and logged (`demisto.error`), never
        raised -- one bad row must not take down the whole runtime corpus.
    :rtype: ``list`` of ``dict``
    """
    result = guardian_execute("getList", {"listName": GUARDIAN_EVAL_RUNTIME_CASES_LIST})
    if not result["ok"]:
        return []
    contents = None
    for entry in result["data"] or []:
        if isinstance(entry, dict) and entry.get("Contents") is not None:
            contents = entry["Contents"]
    if isinstance(contents, str):
        text = contents.strip()
        if not text:
            return []
        try:
            contents = json.loads(text)
        except ValueError:
            demisto.error(
                "GuardianEval: {} is not valid JSON -- runtime case store treated as empty this "
                "call.".format(GUARDIAN_EVAL_RUNTIME_CASES_LIST)
            )
            return []
    if not isinstance(contents, list):
        return []

    valid_cases = []
    for raw_case in contents:
        ok, reason = _guardian_eval_validate_case_shape(raw_case)
        if ok:
            valid_cases.append(raw_case)
        else:
            demisto.error(
                "GuardianEval: skipping malformed row in {} ({}): {!r}".format(
                    GUARDIAN_EVAL_RUNTIME_CASES_LIST, reason, raw_case
                )
            )
    return valid_cases


def guardian_eval_all_cases():
    """The FULL case library -- :data:`GUARDIAN_EVAL_CASES` (static,
    hand-authored) plus
    :func:`guardian_eval_load_runtime_cases` (runtime, harvested or
    hand-added via `!setList`), merged.

    Static wins on a `case_id` collision -- a curated, hand-authored case is
    treated as more trusted than a runtime one sharing its id; the colliding
    runtime row is silently dropped (never overrides, never duplicates).

    Every OTHER function in this file that needs "the whole case library"
    (:func:`guardian_eval_case_by_id`, `guardian_eval_run`'s launch loop)
    calls this instead of referencing :data:`GUARDIAN_EVAL_CASES` directly,
    so a runtime-added case behaves identically to a hand-authored one
    everywhere -- launchable, scoreable, reportable -- with zero special
    casing at any of those call sites.

    :return: The combined case list.
    :rtype: ``list`` of ``dict``
    """
    static_ids = {case["case_id"] for case in GUARDIAN_EVAL_CASES}
    runtime_cases = [c for c in guardian_eval_load_runtime_cases() if c["case_id"] not in static_ids]
    return list(GUARDIAN_EVAL_CASES) + runtime_cases


#: Matches this script's own driver-incident naming
#: (`"Guardian Eval - <case_id> - <uuid>"`) -- see
#: :func:`guardian_eval_build_name`.
_GUARDIAN_EVAL_NAME_PATTERN = re.compile(r"^Guardian Eval - (?P<case_id>.+) - [0-9a-f]{8}$")


def guardian_eval_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def guardian_eval_build_name(case_id):
    return "Guardian Eval - {} - {}".format(case_id, uuid.uuid4().hex[:8])


def guardian_eval_parse_case_id(name):
    """Recover the `case_id` embedded in a driver incident's name by this
    script (see :func:`guardian_eval_build_name`). Returns `None` if `name`
    doesn't match the expected shape (e.g. a hand-created incident that
    happens to also carry `guardiantriggersource=eval`) -- never raises.
    """
    if not isinstance(name, str):
        return None
    match = _GUARDIAN_EVAL_NAME_PATTERN.match(name)
    return match.group("case_id") if match else None


def guardian_eval_case_by_id(case_id):
    """Linear-scan :func:`guardian_eval_all_cases` (static + runtime,
    merged) for `case_id`.

    :param case_id: The `case_id` to look up.
    :type case_id: ``str``
    :return: The matching case dict, or `None` if no case has that id.
    :rtype: ``dict`` or ``None``
    """
    for case in guardian_eval_all_cases():
        if case.get("case_id") == case_id:
            return case
    return None


# --- action=run: launch canned cases -------------------------------------------


#: `createNewIncident` returns before XSOAR's search index has the new incident, so an immediate
#: name lookup can miss it (the case would be left created but never started). Retry the lookup
#: briefly before giving up.
GUARDIAN_EVAL_LOOKUP_ATTEMPTS = 5
GUARDIAN_EVAL_LOOKUP_RETRY_SECONDS = 2


def guardian_eval_launch_case(case, run_label=None):
    """Create + investigate ONE driver incident carrying `case`'s own
    investigation narrative in its `details`.

    :param run_label: An optional grouping label, stamped onto the driver
        incident's `GUARDIAN_EVAL_RUN_LABEL_FIELD` CustomField when given
        (``None``/empty means the incident carries no label at all -- it will
        not appear under any :func:`guardian_eval_report_data_by_run_label`
        call).
    :type run_label: ``str`` or ``None``
    :return: A :func:`guardian_envelope`; `data` on success is
        `{"case_id", "incident_id", "name", "run_label"}`.
    :rtype: ``dict``
    """
    case_id = case["case_id"]
    name = guardian_eval_build_name(case_id)
    custom_fields = {"guardiantriggersource": GUARDIAN_EVAL_TRIGGER_SOURCE_VALUE}
    if run_label:
        custom_fields[GUARDIAN_EVAL_RUN_LABEL_FIELD] = run_label
    create_args = {
        "name": name,
        "type": GUARDIAN_EVAL_INCIDENT_TYPE,
        "severity": "1",
        "details": case["details"],
        "labels": json.dumps([{"type": "guardiantriggersource", "value": GUARDIAN_EVAL_TRIGGER_SOURCE_VALUE}]),
        "customFields": json.dumps(custom_fields),
    }
    create_result = guardian_execute("createNewIncident", create_args)
    if not create_result["ok"]:
        return guardian_envelope(False, error="createNewIncident failed for case '{}': {}".format(case_id, create_result["error"]))

    records = None
    for attempt in range(GUARDIAN_EVAL_LOOKUP_ATTEMPTS):
        if attempt:
            time.sleep(GUARDIAN_EVAL_LOOKUP_RETRY_SECONDS)
        find_result = _guardian_rest_post("/incidents/search", {"filter": {"query": 'name:"{}"'.format(name)}})
        if not find_result["ok"]:
            return guardian_envelope(False, error="lookup after create failed for case '{}': {}".format(case_id, find_result["error"]))
        records = find_result["data"].get("data") if isinstance(find_result["data"], dict) else None
        if records and isinstance(records[0], dict):
            break
    if not records or not isinstance(records[0], dict):
        return guardian_envelope(False, error="created incident for case '{}' not found by name lookup after {} attempts".format(
            case_id, GUARDIAN_EVAL_LOOKUP_ATTEMPTS))
    incident_id = records[0].get("id")
    version = records[0].get("version")

    inv_result = _guardian_rest_post("/incident/investigate", {"id": str(incident_id), "version": version})
    if not inv_result["ok"]:
        return guardian_envelope(
            False, error="incident {} created for case '{}' but investigate failed: {}".format(
                incident_id, case_id, inv_result["error"]
            )
        )

    return guardian_envelope(
        True, data={"case_id": case_id, "incident_id": incident_id, "name": name, "run_label": run_label}
    )


def guardian_eval_run(case_ids_filter=None, run_label=None):
    """Launch every case in :func:`guardian_eval_all_cases` (static + runtime,
    merged -- optionally restricted to `case_ids_filter`), best-effort.

    :param case_ids_filter: An optional set of `case_id` strings to
        restrict the run to; `None`/empty means "all cases".
    :param run_label: An optional grouping label applied to EVERY case this
        call launches (see
        :func:`guardian_eval_launch_case`'s own docstring). Passing the SAME
        label across repeat `action=run` invocations of the same case_ids is
        what lets :func:`guardian_eval_report_data_by_run_label` aggregate
        them ("three of five is the finding; one of one is an anecdote"),
        and passing two DIFFERENT labels across two invocations is what lets
        :func:`guardian_eval_compare_runs` diff them.
    :type run_label: ``str`` or ``None``
    :return: A :func:`guardian_envelope`; `data` is `{"launched": [...],
        "errors": [...]}`.
    :rtype: ``dict``
    """
    cases = guardian_eval_all_cases()
    if case_ids_filter:
        cases = [c for c in cases if c["case_id"] in case_ids_filter]

    launched = []
    errors = []
    for case in cases:
        result = guardian_eval_launch_case(case, run_label=run_label)
        if not result["ok"]:
            errors.append({"case_id": case["case_id"], "error": result["error"]})
            continue
        launched.append(result["data"])

    data = {"launched": launched, "errors": errors}
    if errors:
        return guardian_envelope(False, data=data, error="{} of {} case(s) failed to launch.".format(len(errors), len(cases)))
    return guardian_envelope(True, data=data)


# --- action=score: score concluded runs -----------------------------------------


def guardian_eval_load_results():
    """Read `guardian_eval_results` (an array of row dicts) -- best-effort,
    an absent/unreadable List starts this run's view empty. It is never
    bootstrapped on read; `action=score` `createList`s it lazily the first
    time a row is actually appended, so a genuinely missing List never
    crashes a run.
    """
    result = guardian_execute("getList", {"listName": GUARDIAN_EVAL_RESULTS_LIST})
    if not result["ok"]:
        return []
    contents = None
    for entry in result["data"] or []:
        if isinstance(entry, dict) and entry.get("Contents") is not None:
            contents = entry["Contents"]
    if contents is None or (isinstance(contents, str) and not contents.strip()):
        return []
    if isinstance(contents, str):
        try:
            parsed = json.loads(contents)
        except ValueError:
            return []
    else:
        parsed = contents
    return parsed if isinstance(parsed, list) else []


def guardian_eval_save_results(rows):
    payload = json.dumps(rows)
    create_result = guardian_execute("createList", {"listName": GUARDIAN_EVAL_RESULTS_LIST, "listData": payload})
    if not create_result["ok"]:
        return guardian_envelope(False, error=create_result["error"])
    return guardian_envelope(True)


#: Page size for guardian_eval_find_scoreable_incidents' pagination loop.
GUARDIAN_EVAL_FIND_SCOREABLE_PAGE_SIZE = 100

#: Hard cap on pages fetched (10,000 incidents at the page size above) --
#: defensive against a runaway loop if the server ever echoes back a page
#: that never shrinks below the requested size; a real eval corpus is
#: nowhere near this.
GUARDIAN_EVAL_FIND_SCOREABLE_MAX_PAGES = 100


def guardian_eval_find_scoreable_incidents():
    """Query for every incident tagged `guardiantriggersource=eval` --
    candidates for scoring are filtered further (already-scored / still
    in-flight) by the caller.

    Paginates until a page returns fewer records than the requested page
    size (a single unpaginated size=100 call would silently drop every eval
    incident past the 100th from both scoring and the launched count, with no
    error).

    :return: A :func:`guardian_envelope`; `data` on success is a list of
        raw incident records (`id`, `name`, `runStatus`, `CustomFields`).
    :rtype: ``dict``
    """
    records = []
    for page in range(GUARDIAN_EVAL_FIND_SCOREABLE_MAX_PAGES):
        result = _guardian_rest_post(
            "/incidents/search",
            {
                "filter": {
                    "query": "guardiantriggersource:{}".format(GUARDIAN_EVAL_TRIGGER_SOURCE_VALUE),
                    "size": GUARDIAN_EVAL_FIND_SCOREABLE_PAGE_SIZE,
                    "page": page,
                }
            },
        )
        if not result["ok"]:
            return guardian_envelope(False, error=result["error"], retryable=result["retryable"])
        page_records = result["data"].get("data") if isinstance(result["data"], dict) else None
        page_records = page_records or []
        records.extend(page_records)
        if len(page_records) < GUARDIAN_EVAL_FIND_SCOREABLE_PAGE_SIZE:
            break
    return guardian_envelope(True, data=records)


def guardian_eval_fetch_incident(incident_id):
    """Fetch one incident by id -- used when the caller passes an explicit
    `incident_ids` arg to `action=score` (bypassing the tag-based scan, for
    ad hoc/live testing of a single just-launched case).
    """
    result = _guardian_rest_post("/incidents/search", {"filter": {"id": [str(incident_id)]}})
    if not result["ok"]:
        return guardian_envelope(False, error=result["error"], retryable=result["retryable"])
    records = result["data"].get("data") if isinstance(result["data"], dict) else None
    if not records or not isinstance(records[0], dict):
        return guardian_envelope(False, error="incident {} not found".format(incident_id))
    return guardian_envelope(True, data=records[0])


def guardian_eval_load_audit_rows():
    """Read the shared `guardian_audit` List (`GuardianAuditWrite`'s
    append-only ledger -- see module docstring) -- best-effort, like
    :func:`guardian_eval_load_results`: an
    absent/unreadable List, or one whose `listData` isn't valid JSON, never
    raises here -- it resolves to `[]`, the same "nothing to work with yet"
    signal a genuinely-empty ledger would produce.

    :return: The parsed list of audit-row dicts (each shaped like
        `{ts, actor, action, target, status, duration_ms, tick_id, run_id,
        detail}` -- see module docstring), or `[]`.
    :rtype: ``list``
    """
    result = guardian_execute("getList", {"listName": GUARDIAN_EVAL_AUDIT_LIST})
    if not result["ok"]:
        return []
    contents = None
    for entry in result["data"] or []:
        if isinstance(entry, dict) and entry.get("Contents") is not None:
            contents = entry["Contents"]
    if contents is None or (isinstance(contents, str) and not contents.strip()):
        return []
    if isinstance(contents, str):
        try:
            parsed = json.loads(contents)
        except ValueError:
            return []
    else:
        parsed = contents
    return parsed if isinstance(parsed, list) else []


def _guardian_eval_parse_iso(ts):
    """Parse an RFC3339-ish timestamp string into an aware ``datetime``,
    tolerating the two shapes the real `guardian_audit` ledger produces that
    ``datetime.fromisoformat`` (Python 3.11, the eval Job's runtime) can't
    handle natively:

    - A trailing ``Z`` (not a valid UTC-offset suffix for
      ``fromisoformat`` before Python 3.11's own limited ``Z`` support) --
      rewritten to the explicit ``+00:00`` offset.
    - Fractional seconds with MORE than 6 digits -- the server's own
      `guardian_audit` timestamps can carry RFC3339Nano (9 fractional digits),
      but ``fromisoformat`` only accepts up to 6 (microseconds) and raises
      ``ValueError`` on anything longer. Truncated to the first 6 digits
      (microsecond precision is already far finer than this function's own
      second-granularity callers need).

    :param ts: The raw timestamp value.
    :return: A parsed ``datetime``, or ``None`` if `ts` isn't a non-empty
        string or isn't parseable even after the fixups above -- never
        raises.
    :rtype: ``datetime.datetime`` or ``None``
    """
    if not isinstance(ts, str) or not ts.strip():
        return None
    text = ts.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    text = re.sub(r"\.(\d{6})\d+", r".\1", text, count=1)
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def guardian_eval_latency_seconds(incident_id):
    """Wall-clock latency for one incident's run, computed from the
    append-only `guardian_audit` ledger -- never from a Context/incident-field
    read (the ledger is the one shared, run_id-filterable source of truth).

    :param incident_id: The incident id (the ledger's own `run_id`) to
        compute latency for.
    :return: ``max(ts) - min(ts)`` in seconds over every `guardian_audit`
        row whose `run_id == str(incident_id)` and whose `ts` parses, when
        AT LEAST 2 such rows parse AND the resulting duration is `>= 0`
        (a negative delta means a malformed/out-of-order ledger -- never
        trust it). Otherwise `None` -- fewer than 2 parseable timestamps
        can't bound a duration, and an unparseable `ts` is treated exactly
        like a missing one (never raises the whole computation).
    :rtype: ``float`` or ``None``
    """
    incident_id_str = str(incident_id)
    timestamps = []
    for row in guardian_eval_load_audit_rows():
        if not isinstance(row, dict) or str(row.get("run_id")) != incident_id_str:
            continue
        parsed = _guardian_eval_parse_iso(row.get("ts"))
        if parsed is not None:
            timestamps.append(parsed)
    if len(timestamps) < 2:
        return None
    delta = (max(timestamps) - min(timestamps)).total_seconds()
    return delta if delta >= 0 else None


def guardian_eval_distinct_tools(incident_id):
    """Distinct tool names + total tool-call count for `incident_id`, read
    from the shared `guardian_audit` ledger (see module docstring).

    :return: A :func:`guardian_envelope`; `data` on success is
        `{"distinct_tools": [...], "tool_call_count": N}`.
    :rtype: ``dict``
    """
    result = guardian_execute("getList", {"listName": GUARDIAN_EVAL_AUDIT_LIST})
    if not result["ok"]:
        return guardian_envelope(False, error=result["error"])
    contents = None
    for entry in result["data"] or []:
        if isinstance(entry, dict) and entry.get("Contents") is not None:
            contents = entry["Contents"]
    rows = []
    if isinstance(contents, str) and contents.strip():
        try:
            parsed = json.loads(contents)
            rows = parsed if isinstance(parsed, list) else []
        except ValueError:
            rows = []
    elif isinstance(contents, list):
        rows = contents

    matching = [row for row in rows if isinstance(row, dict) and str(row.get("run_id")) == str(incident_id)]
    distinct_tools = sorted({row.get("action") for row in matching if row.get("action")})
    return guardian_envelope(True, data={"distinct_tools": distinct_tools, "tool_call_count": len(matching)})


def guardian_eval_score_one(incident):
    """Record one concluded incident's RAW observed facts into a
    `guardian_eval_results` row -- no accuracy math here (no comparison
    against a case's `expected_verdict`/`expected_techniques`): that's a
    later report-time computation over these raw rows, kept deliberately out
    of this scorer so re-running a report never requires re-scoring.

    :param incident: A raw incident record (from `/incidents/search`).
    :return: A :func:`guardian_envelope`; `data` on success is the row dict
        -- `{case_id, incident_id, ts, run_status, concluded, failed,
        actual_verdict, actual_techniques, cost_usd, tick_count,
        latency_seconds, distinct_tools, tool_call_count, passed,
        run_label}`. `passed` (`== concluded`) is kept alongside the raw
        fields purely so `main()`'s summary print never `KeyError`s -- it
        carries no accuracy judgement of its own. `run_label` is whatever
        `GUARDIAN_EVAL_RUN_LABEL_FIELD` the driver incident carried at
        launch time, or ``None`` when the caller never set one.
    :rtype: ``dict``
    """
    incident_id = incident.get("id")
    run_status = incident.get("runStatus") or ""
    custom_fields = incident.get("CustomFields") if isinstance(incident.get("CustomFields"), dict) else {}
    concluded = run_status == "completed"

    tools_result = guardian_eval_distinct_tools(incident_id)
    distinct_tools = tools_result["data"]["distinct_tools"] if tools_result["ok"] else []
    tool_call_count = tools_result["data"]["tool_call_count"] if tools_result["ok"] else 0

    row = {
        "case_id": guardian_eval_parse_case_id(incident.get("name")),
        "incident_id": incident_id,
        "ts": guardian_eval_now_iso(),
        "run_status": run_status,
        "concluded": concluded,
        "failed": run_status == "failed",
        "actual_verdict": None if str(custom_fields.get("guardianblastradius") or "").startswith(
            GUARDIAN_UNSTRUCTURED_SUMMARY_MARKER) else custom_fields.get("guardianverdict"),
        "actual_techniques": guardian_normalize_techniques(custom_fields.get("guardianattacktechniques")),
        "cost_usd": custom_fields.get("guardiancostusd"),
        "tick_count": custom_fields.get("guardiantickcount"),
        "latency_seconds": guardian_eval_latency_seconds(incident_id),
        "distinct_tools": distinct_tools,
        "tool_call_count": tool_call_count,
        "passed": concluded,
        "run_label": custom_fields.get(GUARDIAN_EVAL_RUN_LABEL_FIELD),
    }
    return guardian_envelope(True, data=row)


def guardian_eval_merge_row(existing_rows, row):
    """Merge `row` into `existing_rows`, replacing any prior row sharing its
    `incident_id` IN PLACE (last-wins) rather than ever appending a 2nd row
    for the same incident -- the dedup discipline that lets `action=score`
    re-run over an incident it already has a row for (e.g. to pick up an
    `actual_verdict` that was still `None` the first time, before
    `GuardianReasoningTick`'s verdict-telemetry write landed) without
    duplicating that incident's row in `guardian_eval_results`.

    :param existing_rows: The current `guardian_eval_results` rows.
    :type existing_rows: ``list`` of ``dict``
    :param row: The new row to merge in (must carry an `incident_id`).
    :type row: ``dict``
    :return: A NEW list with `row` merged in -- `existing_rows` is never
        mutated in place.
    :rtype: ``list``
    """
    target_id = str(row.get("incident_id"))
    merged = []
    replaced = False
    for existing in existing_rows:
        if isinstance(existing, dict) and str(existing.get("incident_id")) == target_id:
            merged.append(row)
            replaced = True
        else:
            merged.append(existing)
    if not replaced:
        merged.append(row)
    return merged


def guardian_eval_score(incident_ids_filter=None):
    """Score every eligible incident, best-effort, merging (never blindly
    appending -- see :func:`guardian_eval_merge_row`) new rows into
    `guardian_eval_results` in ONE write.

    An incident already carrying a row IS still skipped as `already_scored`
    -- UNLESS that prior row's `actual_verdict is None` (the run had
    concluded but hadn't yet written its verdict telemetry when it was first
    scored), in which case re-scoring is allowed so the row can be replaced
    in place once a real verdict is available.

    :param incident_ids_filter: An optional list of specific incident ids to
        score directly (bypassing the tag-based scan) -- used for ad hoc/
        live testing of a single just-launched case. `None` means "scan
        every guardiantriggersource=eval incident".
    :return: A :func:`guardian_envelope`; `data` is `{"scored": [...],
        "still_running": [...], "already_scored": [...], "errors": [...]}`.
    :rtype: ``dict``
    """
    existing_rows = guardian_eval_load_results()
    existing_by_id = {
        str(row.get("incident_id")): row
        for row in existing_rows
        if isinstance(row, dict) and row.get("incident_id") is not None
    }

    if incident_ids_filter:
        candidates = []
        errors = []
        for incident_id in incident_ids_filter:
            fetch_result = guardian_eval_fetch_incident(incident_id)
            if not fetch_result["ok"]:
                errors.append({"incident_id": incident_id, "error": fetch_result["error"]})
                continue
            candidates.append(fetch_result["data"])
    else:
        scan_result = guardian_eval_find_scoreable_incidents()
        if not scan_result["ok"]:
            return guardian_envelope(
                False,
                data={"scored": [], "still_running": [], "already_scored": [], "errors": []},
                error="failed to scan for eval incidents: {}".format(scan_result["error"]),
            )
        candidates = scan_result["data"]
        errors = []

    scored = []
    still_running = []
    already_scored = []
    new_rows = list(existing_rows)

    for incident in candidates:
        incident_id = str(incident.get("id"))
        existing_row = existing_by_id.get(incident_id)
        if existing_row is not None and existing_row.get("actual_verdict") is not None:
            already_scored.append(incident_id)
            continue
        run_status = incident.get("runStatus") or ""
        if run_status not in GUARDIAN_EVAL_CONCLUDED_RUN_STATUSES:
            still_running.append({"incident_id": incident_id, "run_status": run_status})
            continue
        score_result = guardian_eval_score_one(incident)
        if not score_result["ok"]:
            errors.append({"incident_id": incident_id, "error": score_result["error"]})
            continue
        new_rows = guardian_eval_merge_row(new_rows, score_result["data"])
        scored.append(score_result["data"])
        existing_by_id[incident_id] = score_result["data"]

    if scored:
        save_result = guardian_eval_save_results(new_rows)
        if not save_result["ok"]:
            errors.append({"incident_id": None, "error": "failed to persist guardian_eval_results: {}".format(save_result["error"])})

    data = {"scored": scored, "still_running": still_running, "already_scored": already_scored, "errors": errors}
    if errors:
        return guardian_envelope(False, data=data, error="{} error(s) while scoring.".format(len(errors)))
    return guardian_envelope(True, data=data)


# --- action=report: accuracy/cost/latency aggregation -----------------------------
#
# Pinned math (do not "simplify" -- these three formulas are the crux of the
# whole action):
#
# - `_guardian_pct`: linear-interpolation percentile (numpy's default
#   "linear" method) -- `median := _guardian_pct(vals, 50)`, deliberately
#   NEVER `statistics.median` (the two diverge on even `n`: `statistics.median`
#   averages the two middle values, which happens to equal this method's p50
#   only because `r=(50/100)*(n-1)` always lands exactly halfway between the
#   two middle indices for p=50 specifically -- but every OTHER percentile
#   this module computes, p90 in particular, has no such shortcut).
# - `_guardian_f1`: local harmonic-mean-of-precision/recall helper, NEVER
#   `statistics.harmonic_mean` (which raises `StatisticsError` on the
#   disjoint-non-empty case `p=r=0` -- exactly the "the model predicted zero
#   techniques and none of them were expected" / "predicted techniques but
#   none overlap" case this scorer must handle without crashing the whole
#   report).
# - `_guardian_wilson`: Wilson score 95% CI (z=1.96) -- a normal-approximation
#   CI (`p +/- z*sqrt(p(1-p)/n)`) badly overstates confidence at this eval
#   harness's tiny `n` (a handful of canned cases); Wilson's interval stays
#   sane down to `n` this small.


#: The 4 valid `expected_verdict` labels (see `GUARDIAN_EVAL_CASES`) --
#: also the 4 "real" confusion-matrix columns/rows.
GUARDIAN_EVAL_VALID_VERDICTS = ("Malicious", "Suspicious", "Benign", "Inconclusive")

#: The full confusion-matrix column set: the 4 valid labels above, plus
#: "Other" (a non-empty `actual_verdict` that isn't one of the 4 -- a model
#: bug/typo, not a real label) and "None" (`actual_verdict` absent/empty --
#: see :func:`guardian_eval_score_one`'s own docstring on why a CONCLUDED run
#: can still lack a verdict). See :func:`_guardian_eval_verdict_bucket`.
GUARDIAN_EVAL_CONFUSION_COLUMNS = GUARDIAN_EVAL_VALID_VERDICTS + ("Other", "None")

#: The z-score for a 95% Wilson score confidence interval.
_GUARDIAN_EVAL_WILSON_Z = 1.96

#: Minimum sample size a p90 estimate is trusted at (see
#: :func:`_guardian_eval_aggregate`) -- below this, p90 is noise, not signal.
_GUARDIAN_EVAL_P90_MIN_N = 10


def _guardian_pct(sorted_vals, p):
    """Linear-interpolation percentile of `sorted_vals` at percentile `p`
    (numpy's default `"linear"` method): `r = (p/100) * (n-1)`, interpolated
    between the values at `floor(r)` and `ceil(r)`.

    :param sorted_vals: The values to compute a percentile over. SORTED
        HERE (ascending), regardless of the caller's own ordering -- a
        caller passing an already-sorted list only pays the (cheap) cost of
        re-sorting an already-sorted list; correctness never depends on the
        caller remembering to sort first.
    :type sorted_vals: iterable of ``float``/``int``
    :param p: The percentile to compute, ``0..100``.
    :type p: ``float`` or ``int``
    :return: The interpolated value, the single value when `n==1` (nothing
        to interpolate against), or ``None`` when `n==0` (no data).
    :rtype: ``float`` or ``None``
    """
    vals = sorted(sorted_vals)
    n = len(vals)
    if n == 0:
        return None
    if n == 1:
        return vals[0]
    r = (p / 100.0) * (n - 1)
    lo = int(math.floor(r))
    hi = int(math.ceil(r))
    if lo == hi:
        return vals[lo]
    return vals[lo] + (r - lo) * (vals[hi] - vals[lo])


def _guardian_f1(p, r):
    """F1 (harmonic mean of precision `p` and recall `r`), guarding the
    disjoint-non-empty case `p == r == 0` that the textbook `2pr/(p+r)`
    formula (and `statistics.harmonic_mean`) divides by zero on. A LOCAL
    helper -- never `statistics.harmonic_mean` (see this section's own
    header comment for why). Computed from UNROUNDED `p`/`r` by every
    caller in this module.

    :param p: Precision, ``0..1``.
    :type p: ``float``
    :param r: Recall, ``0..1``.
    :type r: ``float``
    :return: ``0.0`` if `p + r == 0`, else `2*p*r/(p+r)`.
    :rtype: ``float``
    """
    return 0.0 if (p + r) == 0 else 2 * p * r / (p + r)


def _guardian_wilson(k, n):
    """Wilson score 95% confidence interval (`z=1.96`) for the binomial
    proportion `k/n`.

    :param k: Successes (e.g. correct binary verdicts).
    :type k: ``int``
    :param n: Trials (e.g. `N_v`).
    :type n: ``int``
    :return: `(lo, hi)`, both clamped to `[0.0, 1.0]`. `(0.0, 0.0)` when
        `n == 0` (no data -- nothing to bound).
    :rtype: ``tuple(float, float)``
    """
    if n == 0:
        return (0.0, 0.0)
    z = _GUARDIAN_EVAL_WILSON_Z
    phat = k / n
    denom = 1 + (z * z) / n
    centre = phat + (z * z) / (2 * n)
    adjustment = z * math.sqrt((phat * (1 - phat) + (z * z) / (4 * n)) / n)
    lo = (centre - adjustment) / denom
    hi = (centre + adjustment) / denom
    return (max(0.0, lo), min(1.0, hi))


def _guardian_eval_normalize_verdict(value):
    """Normalize a raw `actual_verdict`-ish value: trim, then title-case
    (`"malicious"` / `"MALICIOUS"` / `" Malicious "` all normalize to the
    same `"Malicious"`).

    :param value: The raw value (typically a row's `actual_verdict`).
    :return: The trimmed, title-cased string, or ``None`` for an
        absent/empty value.
    :rtype: ``str`` or ``None``
    """
    if value is None:
        return None
    text = str(value).strip()
    return text.title() if text else None


def _guardian_eval_verdict_bucket(value):
    """Bucket a raw `actual_verdict`-ish value into one of the 6
    confusion-matrix columns (see :data:`GUARDIAN_EVAL_CONFUSION_COLUMNS`):
    one of the 4 valid labels, `"Other"` (normalizes to a non-empty string
    that isn't one of the 4), or `"None"` (normalizes to ``None`` -- see
    :func:`_guardian_eval_normalize_verdict`).

    :param value: The raw value to bucket.
    :return: One of :data:`GUARDIAN_EVAL_CONFUSION_COLUMNS`.
    :rtype: ``str``
    """
    normalized = _guardian_eval_normalize_verdict(value)
    if normalized is None:
        return "None"
    return normalized if normalized in GUARDIAN_EVAL_VALID_VERDICTS else "Other"


def _guardian_eval_expects_no_conclusion(case_id):
    """Whether `case_id`'s library entry declares
    `"expected_outcome": GUARDIAN_EVAL_OUTCOME_NO_CONCLUSION` -- see that
    constant's comment for the full rationale (a regression case testing
    RESTRAINT, genuinely different from an ordinary case whose expected
    verdict happens to be `"Inconclusive"`).

    The field is entirely OPTIONAL and defaults to ordinary verdict-scored
    behavior, so this returns ``False`` for every case that does not set it.

    :param case_id: A row's `case_id` string. Not validated here -- an
        unknown id (already filtered out earlier in
        :func:`guardian_eval_report_data`, but defensive here too) is
        ``False``, same as any other case with no `expected_outcome` set.
    :return: ``True`` only when the case genuinely exists AND declares
        `expected_outcome == GUARDIAN_EVAL_OUTCOME_NO_CONCLUSION`.
    :rtype: ``bool``
    """
    case = guardian_eval_case_by_id(case_id)
    return isinstance(case, dict) and case.get("expected_outcome") == GUARDIAN_EVAL_OUTCOME_NO_CONCLUSION


def guardian_eval_count_launched(run_label=None, case_ids=None):
    """Live count of every incident ever tagged `guardiantriggersource=eval`
    -- the denominator for the reliability metric `concluded_rate` computed
    by :func:`guardian_eval_report_data`. A thin, SEPARATELY-monkeypatchable
    wrapper over :func:`guardian_eval_find_scoreable_incidents`'s own
    tag-scan (report tests stub this function directly rather than the REST
    layer underneath it).

    Best-effort like every other read in this module: a failed scan
    degrades to `0` (an undefined `concluded_rate`, never a crashed report)
    rather than blocking the whole report over a transient REST hiccup.

    :param run_label: When given, restricts the count to launches whose
        `GUARDIAN_EVAL_RUN_LABEL_FIELD` CustomField equals `run_label`,
        filtered CLIENT-SIDE over the SAME tag-scan result (every returned
        record already carries its own `CustomFields`). ``None`` (the
        default) means every eval-tagged launch ever.
    :type run_label: ``str`` or ``None``
    :param case_ids: Keeps the denominator in the same population as a
        `case_ids`-filtered `concluded_count`: dividing by an unfiltered,
        server-wide count would make the printed rate meaningless whenever a
        report is scoped to a case subset. When given, restricts the count to
        launches whose incident `name` embeds one of these `case_id`s (via
        :func:`guardian_eval_parse_case_id` -- incidents carry no dedicated
        case_id CustomField, only this name convention set by
        :func:`guardian_eval_build_name` at launch time), filtered
        CLIENT-SIDE over the SAME tag-scan result, same as `run_label`.
        Combines with `run_label` as AND, not OR. ``None``/empty (the
        default) means every case.
    :type case_ids: iterable of ``str`` or ``None``
    :return: The live incident count.
    :rtype: ``int``
    """
    result = guardian_eval_find_scoreable_incidents()
    if not result["ok"]:
        return 0
    records = result["data"]
    case_ids_set = set(case_ids) if case_ids else None
    if run_label is None and case_ids_set is None:
        return len(records)
    count = 0
    for r in records:
        if not isinstance(r, dict):
            continue
        if run_label is not None and (r.get("CustomFields") or {}).get(GUARDIAN_EVAL_RUN_LABEL_FIELD) != run_label:
            continue
        if case_ids_set is not None and guardian_eval_parse_case_id(r.get("name")) not in case_ids_set:
            continue
        count += 1
    return count


def _guardian_eval_aggregate(values):
    """Aggregate one metric's non-null values: `available` (the `n` this
    section's own aggregates are reported against), mean, median (via
    :func:`_guardian_pct` -- see this section's header comment), max, and
    p90 (via :func:`_guardian_pct` too, ONLY when `available >=
    _GUARDIAN_EVAL_P90_MIN_N` -- a p90 estimated from fewer samples is noise,
    not signal).

    :param values: The raw values (may include ``None`` -- filtered out
        here; non-numeric values are the caller's problem, not guarded
        against here).
    :return: ``{"available", "mean", "median", "max", "p90"}`` -- every key
        but `available` is ``None`` when `available == 0` (and `p90` alone
        is also ``None`` when `0 < available < _GUARDIAN_EVAL_P90_MIN_N`).
    :rtype: ``dict``
    """
    vals = sorted(v for v in values if v is not None)
    n = len(vals)
    if n == 0:
        return {"available": 0, "mean": None, "median": None, "max": None, "p90": None}
    return {
        "available": n,
        "mean": sum(vals) / n,
        "median": _guardian_pct(vals, 50),
        "max": vals[-1],
        "p90": _guardian_pct(vals, 90) if n >= _GUARDIAN_EVAL_P90_MIN_N else None,
    }


def guardian_eval_report_data(case_ids=None, rows=None, run_label=None):
    """Compute every number the eval scorecard needs, as a plain dict --
    kept SEPARATE from markdown rendering (:func:`guardian_eval_render_report`)
    so `main()` can hand the SAME computed numbers to both `readable_output`
    and `outputs` without recomputing (in particular, without a second live
    `guardian_eval_count_launched` REST scan that could disagree with the
    first).

    Working row set: `rows` if given, else a fresh `guardian_eval_load_results()`
    (:func:`guardian_eval_report_data_by_run_label` is the one caller that
    passes a pre-filtered `rows`; every other caller loads fresh),
    optionally restricted to `case_ids`, with any row whose `case_id` isn't
    in the case library dropped -- there's no ground truth to score a
    retired/unknown case against. Every metric below is computed
    over this SAME working set (or a documented sub-slice of it), never a
    freshly-reloaded one.

    :param case_ids: An optional iterable of `case_id` strings to restrict
        the report to. ``None``/empty means every scored row in the working
        set. Also threaded through to `guardian_eval_count_launched` so
        `concluded_count` (scoped to `case_ids` via `rows`) and
        `count_launched` are computed over the SAME population; otherwise a
        report restricted to a case subset would divide by every eval-tagged
        incident ever, making `concluded_rate` meaningless.
    :param rows: An optional pre-loaded/pre-filtered row set. ``None`` (the
        default) loads fresh via `guardian_eval_load_results()`.
    :type rows: ``list`` of ``dict`` or ``None``
    :param run_label: An optional label passed through to
        `guardian_eval_count_launched` to scope its LIVE denominator scan to
        the same label `rows` was already filtered to -- this function does
        NOT filter `rows` by `run_label` itself; the caller is expected to
        have already done that if `rows` is given. ``None`` (the default)
        scopes the denominator to every eval-tagged launch ever.
    :type run_label: ``str`` or ``None``
    :return: A dict consumed by :func:`guardian_eval_render_report`
        (`rows`, `rows_count`, `count_launched`, `concluded_count`,
        `concluded_rate`, `n_v`, `verdict_production_rate`,
        `binary_correct`, `binary_accuracy`, `wilson_lo`, `wilson_hi`,
        `majority_baseline`, `confusion_matrix`, `exact_correct`,
        `exact_accuracy`, `technique_case_count`, `technique_f1_mean`,
        `restraint_total`, `restraint_correct`, `benign_restraint`,
        `regression_no_conclusion_total`, `regression_no_conclusion_correct`,
        `regression_no_conclusion_rate` (see
        :data:`GUARDIAN_EVAL_OUTCOME_NO_CONCLUSION`), `cost_usd`,
        `latency_seconds`, `tick_count` -- the last 3 are
        :func:`_guardian_eval_aggregate` dicts).
    :rtype: ``dict``
    """
    rows = guardian_eval_load_results() if rows is None else rows
    if case_ids:
        case_ids_set = set(case_ids)
        rows = [r for r in rows if isinstance(r, dict) and r.get("case_id") in case_ids_set]
    rows = [r for r in rows if isinstance(r, dict) and guardian_eval_case_by_id(r.get("case_id")) is not None]

    count_launched = guardian_eval_count_launched(run_label=run_label, case_ids=case_ids)
    concluded_rows = [r for r in rows if r.get("concluded")]
    concluded_count = len(concluded_rows)
    concluded_rate = (concluded_count / count_launched) if count_launched else 0.0

    # A "no_conclusion" case's `expected_verdict` is a
    # placeholder (kept "Inconclusive" by schema convention, see
    # GUARDIAN_EVAL_OUTCOME_NO_CONCLUSION's own docstring), never a real
    # accuracy comparison target -- excluded here so it can never enter the
    # confusion matrix / binary / exact / technique-F1 / restraint pipeline
    # below, whether or not the model happened to produce a verdict anyway.
    # Scored separately below instead (regression_no_conclusion_*).
    with_verdict_rows = [
        r
        for r in concluded_rows
        if _guardian_eval_verdict_bucket(r.get("actual_verdict")) != "None"
        and not _guardian_eval_expects_no_conclusion(r.get("case_id"))
    ]
    n_v = len(with_verdict_rows)
    verdict_production_rate = (n_v / concluded_count) if concluded_count else 0.0

    # --- binary malicious-detection accuracy, Wilson CI, majority baseline,
    # and the 4-class confusion matrix -- one pass over `with_verdict_rows`.
    binary_correct = 0
    malicious_expected_count = 0
    invalid_expected_verdict_count = 0
    confusion_matrix = {
        expected: {col: 0 for col in GUARDIAN_EVAL_CONFUSION_COLUMNS} for expected in GUARDIAN_EVAL_VALID_VERDICTS
    }
    for row in with_verdict_rows:
        case = guardian_eval_case_by_id(row.get("case_id"))
        # Defensive: route `expected_verdict` through the SAME trim+title-case
        # normalization `_guardian_eval_verdict_bucket` applies to the actual
        # side, so a case-only difference (e.g. "malicious") still lands on
        # the right confusion-matrix row. `GUARDIAN_EVAL_CASES` is expected
        # to always conform to `GUARDIAN_EVAL_VALID_VERDICTS`, but a genuine
        # typo would otherwise KeyError indexing `confusion_matrix` below --
        # skip + record that row instead of raising.
        expected_verdict = _guardian_eval_normalize_verdict(case["expected_verdict"])
        if expected_verdict not in GUARDIAN_EVAL_VALID_VERDICTS:
            invalid_expected_verdict_count += 1
            demisto.error(
                "GuardianEval: case_id={} has an invalid expected_verdict {!r} -- row excluded from the "
                "confusion matrix and binary/exact accuracy.".format(row.get("case_id"), case.get("expected_verdict"))
            )
            continue
        actual_bucket = _guardian_eval_verdict_bucket(row.get("actual_verdict"))
        confusion_matrix[expected_verdict][actual_bucket] += 1

        expected_malicious = expected_verdict == "Malicious"
        actual_malicious = actual_bucket == "Malicious"
        if expected_malicious == actual_malicious:
            binary_correct += 1
        if expected_malicious:
            malicious_expected_count += 1

    matrix_total = sum(sum(cols.values()) for cols in confusion_matrix.values())
    if matrix_total + invalid_expected_verdict_count != n_v:
        raise DemistoException(
            "GuardianEval: confusion matrix cell total {} (+ {} invalid expected_verdict row(s)) != N_v {} -- "
            "data integrity check failed.".format(matrix_total, invalid_expected_verdict_count, n_v)
        )

    binary_accuracy = (binary_correct / n_v) if n_v else 0.0
    wilson_lo, wilson_hi = _guardian_wilson(binary_correct, n_v)
    majority_baseline = (max(malicious_expected_count, n_v - malicious_expected_count) / n_v) if n_v else 0.0

    exact_correct = sum(confusion_matrix[label][label] for label in GUARDIAN_EVAL_VALID_VERDICTS)
    exact_accuracy = (exact_correct / n_v) if n_v else 0.0

    # --- technique detection: per-case P/R/F1 over `|E|>0` concluded-with-
    # verdict cases only; benign restraint over the complementary `|E|==0`
    # slice of that same `with_verdict_rows` set.
    per_case_f1 = []
    restraint_total = 0
    restraint_correct = 0
    for row in with_verdict_rows:
        case = guardian_eval_case_by_id(row.get("case_id"))
        expected_techniques = set(case.get("expected_techniques") or [])
        actual_techniques = set(row.get("actual_techniques") or [])
        if not expected_techniques:
            restraint_total += 1
            if not actual_techniques:
                restraint_correct += 1
            continue
        true_positives = len(expected_techniques & actual_techniques)
        precision = (true_positives / len(actual_techniques)) if actual_techniques else 0.0
        recall = true_positives / len(expected_techniques)
        per_case_f1.append(_guardian_f1(precision, recall))

    technique_f1_mean = (sum(per_case_f1) / len(per_case_f1)) if per_case_f1 else None
    benign_restraint = (restraint_correct / restraint_total) if restraint_total else None

    # --- "no_conclusion" regression cases -- a
    # completely separate, additive metric axis (never mixed into the
    # verdict-accuracy pipeline above). Scored over the FULL working set
    # `rows` (not `concluded_rows`/`with_verdict_rows`): "correct" here means
    # the run did NOT conclude, so a case counted here is, by construction,
    # never a `with_verdict_rows` member anyway.
    no_conclusion_rows = [r for r in rows if _guardian_eval_expects_no_conclusion(r.get("case_id"))]
    regression_no_conclusion_total = len(no_conclusion_rows)
    regression_no_conclusion_correct = sum(1 for r in no_conclusion_rows if not r.get("concluded"))
    regression_no_conclusion_rate = (
        (regression_no_conclusion_correct / regression_no_conclusion_total)
        if regression_no_conclusion_total
        else None
    )

    # --- cost / latency / tick aggregates -- over every row in the working
    # set (not just `with_verdict_rows`: a failed or not-yet-verdicted run
    # can still carry partial cost/tick/latency telemetry worth reporting).
    cost_agg = _guardian_eval_aggregate(r.get("cost_usd") for r in rows)
    latency_agg = _guardian_eval_aggregate(r.get("latency_seconds") for r in rows)
    tick_agg = _guardian_eval_aggregate(r.get("tick_count") for r in rows)

    return {
        "rows": rows,
        "rows_count": len(rows),
        "count_launched": count_launched,
        "concluded_count": concluded_count,
        "concluded_rate": concluded_rate,
        "n_v": n_v,
        "verdict_production_rate": verdict_production_rate,
        "binary_correct": binary_correct,
        "binary_accuracy": binary_accuracy,
        "wilson_lo": wilson_lo,
        "wilson_hi": wilson_hi,
        "majority_baseline": majority_baseline,
        "confusion_matrix": confusion_matrix,
        "exact_correct": exact_correct,
        "exact_accuracy": exact_accuracy,
        "technique_case_count": len(per_case_f1),
        "technique_f1_mean": technique_f1_mean,
        "restraint_total": restraint_total,
        "restraint_correct": restraint_correct,
        "benign_restraint": benign_restraint,
        "regression_no_conclusion_total": regression_no_conclusion_total,
        "regression_no_conclusion_correct": regression_no_conclusion_correct,
        "regression_no_conclusion_rate": regression_no_conclusion_rate,
        "cost_usd": cost_agg,
        "latency_seconds": latency_agg,
        "tick_count": tick_agg,
    }


#: The noise floor a `guardian_eval_compare_runs` delta must clear to be
#: reported as "moved" rather than noise. Calibrated for the 0..1
#: FRACTION-shaped metrics this compares (accuracy/rate metrics); see
#: `GUARDIAN_EVAL_COMPARE_METRICS` for why cost/latency/tick means are
#: intentionally out of scope.
GUARDIAN_EVAL_COMPARE_MIN_DELTA = 0.20

#: The fraction-shaped `guardian_eval_report_data` metrics
#: `guardian_eval_compare_runs` diffs -- `(report_data key, display label)`.
#: Every metric here is a 0..1 fraction (or ``None``) --
#: `GUARDIAN_EVAL_COMPARE_MIN_DELTA`'s 0.20 noise floor is calibrated for
#: this scale specifically. `cost_usd`/`latency_seconds`/`tick_count` are
#: aggregate dicts on a totally different unit scale and are intentionally
#: left out -- there is no established noise floor for them, and inventing
#: one without a real basis would be worse than not comparing them at all.
GUARDIAN_EVAL_COMPARE_METRICS = (
    ("concluded_rate", "Concluded rate"),
    ("verdict_production_rate", "Verdict production rate"),
    ("binary_accuracy", "Binary malicious-detection accuracy"),
    ("exact_accuracy", "Exact 4-class accuracy"),
    ("benign_restraint", "Benign restraint"),
    ("technique_f1_mean", "Technique-detection F1 (mean)"),
    ("regression_no_conclusion_rate", "No-conclusion regression rate"),
)


def guardian_eval_report_data_by_run_label(run_label, case_ids=None):
    """:func:`guardian_eval_report_data`'s SAME metrics, computed over only
    the rows whose `run_label` matches --
    numerator (`rows`) AND denominator (`count_launched`, via
    `guardian_eval_count_launched`'s own `run_label` param) both correctly
    scoped to the SAME label, so `concluded_rate`/etc. mean the same thing
    here as they do for the unscoped, whole-corpus report.

    :param run_label: The label to restrict to -- see
        `GUARDIAN_EVAL_RUN_LABEL_FIELD`'s own docstring for how a row gets
        this value in the first place (`guardian_eval_run`'s own `run_label`
        arg, stamped onto the driver incident at launch time).
    :type run_label: ``str``
    :param case_ids: Same as :func:`guardian_eval_report_data`'s own
        `case_ids` param.
    :return: :func:`guardian_eval_report_data`'s own return shape, scoped to
        this label. An unknown/never-used label produces a well-defined
        empty-group result (`n_v == 0`, every rate `0.0`/``None``), never a
        crash.
    :rtype: ``dict``
    """
    all_rows = guardian_eval_load_results()
    label_rows = [r for r in all_rows if isinstance(r, dict) and r.get("run_label") == run_label]
    return guardian_eval_report_data(case_ids=case_ids, rows=label_rows, run_label=run_label)


def guardian_eval_compare_runs(baseline_label, candidate_label, case_ids=None, min_delta=None):
    """Baseline-vs-candidate compare with a noise floor: it reports which
    properties moved, by name, and never a verdict. Computes
    :func:`guardian_eval_report_data_by_run_label` for EACH label, then
    diffs :data:`GUARDIAN_EVAL_COMPARE_METRICS` between them.

    Deliberately renders NO verdict of its own ("candidate is better/worse")
    -- only reports each metric's baseline value, candidate value, the raw
    delta, and whether `|delta|` clears `min_delta`
    (:data:`GUARDIAN_EVAL_COMPARE_MIN_DELTA` by default). Interpreting
    whether a moved metric is good or bad news is left to the human reading
    the report.

    Flags `either_side_is_anecdotal` whenever EITHER side's `n_v` (the
    accuracy-relevant sample size) is `<= 1` -- a delta computed from a single
    run on either side is not yet a repeat-tested finding, however large it
    looks.

    Empty-group guard: a label with zero matching rows produces
    `guardian_eval_report_data`'s own well-defined zero-row output (`n_v=0`,
    every rate `0.0`/``None``) rather than raising -- this function never
    crashes on an empty or unknown label, it just reports "no data" honestly
    via that side's own `n_v == 0`.

    :param baseline_label: The `run_label` to treat as the baseline (left) side.
    :type baseline_label: ``str``
    :param candidate_label: The `run_label` to treat as the candidate (right) side.
    :type candidate_label: ``str``
    :param case_ids: Same as :func:`guardian_eval_report_data`'s own
        `case_ids` param, applied to BOTH sides identically.
    :param min_delta: Overrides :data:`GUARDIAN_EVAL_COMPARE_MIN_DELTA` when given.
    :type min_delta: ``float`` or ``None``
    :return: ``{"baseline_label", "candidate_label", "min_delta", "baseline",
        "candidate"`` (the 2 full `guardian_eval_report_data` dicts, minus
        `"rows"`)``, "either_side_is_anecdotal", "metrics"}``, where
        `"metrics"` is a list of ``{"key", "label", "baseline_value",
        "candidate_value", "delta", "moved"}`` (`"delta"`/`"moved"` are
        ``None``/``False`` when either side's value for that metric is
        ``None`` -- an undefined delta is never silently coerced to `0`).
    :rtype: ``dict``
    """
    threshold = GUARDIAN_EVAL_COMPARE_MIN_DELTA if min_delta is None else min_delta
    baseline_data = guardian_eval_report_data_by_run_label(baseline_label, case_ids=case_ids)
    candidate_data = guardian_eval_report_data_by_run_label(candidate_label, case_ids=case_ids)

    metrics = []
    for key, label in GUARDIAN_EVAL_COMPARE_METRICS:
        baseline_value = baseline_data.get(key)
        candidate_value = candidate_data.get(key)
        if baseline_value is None or candidate_value is None:
            delta = None
            moved = False
        else:
            delta = candidate_value - baseline_value
            moved = abs(delta) >= threshold
        metrics.append(
            {
                "key": key,
                "label": label,
                "baseline_value": baseline_value,
                "candidate_value": candidate_value,
                "delta": delta,
                "moved": moved,
            }
        )

    return {
        "baseline_label": baseline_label,
        "candidate_label": candidate_label,
        "min_delta": threshold,
        "baseline": {k: v for k, v in baseline_data.items() if k != "rows"},
        "candidate": {k: v for k, v in candidate_data.items() if k != "rows"},
        "either_side_is_anecdotal": baseline_data["n_v"] <= 1 or candidate_data["n_v"] <= 1,
        "metrics": metrics,
    }


def _guardian_eval_pct_str(value):
    """Render a `0..1` fraction as an `"XX.X%"` string, or `"n/a"` for
    ``None``."""
    return "n/a" if value is None else "{:.1f}%".format(value * 100)


def _guardian_eval_num_str(value, digits=3):
    """Render a numeric value to `digits` decimal places, or `"n/a"` for
    ``None``."""
    return "n/a" if value is None else "{:.{}f}".format(value, digits)


def _guardian_eval_cell(value):
    """Render one per-case markdown table cell: an em dash for
    ``None``/absent, the plain string form of anything else."""
    return "—" if value is None else str(value)


def _guardian_eval_render_aggregate_row(label, agg, digits):
    """One `Cost/Latency/Ticks` markdown table row -- `p90` reads
    `"n/a (n<10)"` (spelled out, not a bare `"n/a"`) specifically when the
    metric's own `available` count is below :data:`_GUARDIAN_EVAL_P90_MIN_N`,
    so a reader can tell "no p90 because too few samples" apart from "no p90
    because zero samples at all"."""
    if agg["available"] < _GUARDIAN_EVAL_P90_MIN_N:
        p90_display = "n/a (n<10)"
    else:
        p90_display = _guardian_eval_num_str(agg["p90"], digits)
    return "| {} |".format(
        " | ".join(
            [
                label,
                str(agg["available"]),
                _guardian_eval_num_str(agg["mean"], digits),
                _guardian_eval_num_str(agg["median"], digits),
                _guardian_eval_num_str(agg["max"], digits),
                p90_display,
            ]
        )
    )


def guardian_eval_render_report(data):
    """Render :func:`guardian_eval_report_data`'s numbers as the eval
    scorecard markdown: reliability, binary malicious-detection accuracy
    (+ Wilson CI + majority-class baseline), the 4-class confusion matrix
    (+ secondary exact-4-class accuracy), technique-detection headline F1
    + benign restraint, the no-conclusion regression rate,
    cost/latency/tick aggregates, and a per-case table.

    :param data: The dict returned by :func:`guardian_eval_report_data`.
    :return: The full report markdown.
    :rtype: ``str``
    """
    lines = ["## Guardian Eval Report", ""]

    lines.append("### Reliability")
    lines.append("- Launched (guardiantriggersource=eval incidents): {}".format(data["count_launched"]))
    lines.append(
        "- Concluded: {}/{} ({})".format(
            data["concluded_count"], data["count_launched"], _guardian_eval_pct_str(data["concluded_rate"])
        )
    )
    lines.append(
        "- Verdict produced: {}/{} ({})".format(
            data["n_v"], data["concluded_count"], _guardian_eval_pct_str(data["verdict_production_rate"])
        )
    )
    lines.append("")

    lines.append("### Binary malicious-detection accuracy (N_v={})".format(data["n_v"]))
    lines.append(
        "**Binary malicious-detection accuracy:** {}/{} ({}) -- Wilson 95% CI [{}, {}]".format(
            data["binary_correct"],
            data["n_v"],
            _guardian_eval_pct_str(data["binary_accuracy"]),
            _guardian_eval_pct_str(data["wilson_lo"]),
            _guardian_eval_pct_str(data["wilson_hi"]),
        )
    )
    lines.append("Majority-class baseline: {}".format(_guardian_eval_pct_str(data["majority_baseline"])))
    lines.append("")

    lines.append(
        "### 4-class confusion matrix (secondary; exact-4-class accuracy {})".format(
            _guardian_eval_pct_str(data["exact_accuracy"])
        )
    )
    matrix_header = ["Expected \\ Actual"] + list(GUARDIAN_EVAL_CONFUSION_COLUMNS)
    lines.append("| " + " | ".join(matrix_header) + " |")
    lines.append("|" + "---|" * len(matrix_header))
    for expected in GUARDIAN_EVAL_VALID_VERDICTS:
        row_cells = [expected] + [str(data["confusion_matrix"][expected][col]) for col in GUARDIAN_EVAL_CONFUSION_COLUMNS]
        lines.append("| " + " | ".join(row_cells) + " |")
    lines.append("")

    lines.append(
        "### Technique detection (|E|>0 concluded-with-verdict cases, n={})".format(data["technique_case_count"])
    )
    if data["technique_f1_mean"] is None:
        f1_display = "n/a (no |E|>0 cases)"
    else:
        f1_display = "{:.3f}".format(data["technique_f1_mean"])
    lines.append("Headline F1 (mean per-case, unrounded): {}".format(f1_display))
    if data["benign_restraint"] is None:
        restraint_display = "n/a (no |E|==0 cases)"
    else:
        restraint_display = "{}/{} ({})".format(
            data["restraint_correct"], data["restraint_total"], _guardian_eval_pct_str(data["benign_restraint"])
        )
    lines.append("Benign restraint (|E|==0 cases with |A|==0): {}".format(restraint_display))
    lines.append("")

    lines.append("### Regression: expected no-conclusion cases")
    if data["regression_no_conclusion_total"] == 0:
        no_conclusion_display = "n/a (no expected_outcome=no_conclusion cases scored)"
    else:
        no_conclusion_display = "{}/{} ({})".format(
            data["regression_no_conclusion_correct"],
            data["regression_no_conclusion_total"],
            _guardian_eval_pct_str(data["regression_no_conclusion_rate"]),
        )
    lines.append(
        "Correctly withheld a verdict (never enters the accuracy pipeline above): {}".format(
            no_conclusion_display
        )
    )
    lines.append("")

    lines.append("### Cost / latency / ticks")
    lines.append("| Metric | Available | Mean | Median | Max | p90 |")
    lines.append("|---|---|---|---|---|---|")
    lines.append(_guardian_eval_render_aggregate_row("Cost (USD)", data["cost_usd"], 4))
    lines.append(_guardian_eval_render_aggregate_row("Latency (s)", data["latency_seconds"], 1))
    lines.append(_guardian_eval_render_aggregate_row("Ticks", data["tick_count"], 1))
    lines.append("")

    lines.append("### Per-case results ({} row(s))".format(data["rows_count"]))
    per_case_header = ["case_id", "incident_id", "concluded", "expected verdict", "actual verdict", "cost (USD)", "latency (s)", "ticks"]
    lines.append("| " + " | ".join(per_case_header) + " |")
    lines.append("|" + "---|" * len(per_case_header))
    for row in sorted(data["rows"], key=lambda r: (str(r.get("case_id") or ""), str(r.get("incident_id") or ""))):
        case = guardian_eval_case_by_id(row.get("case_id"))
        expected_verdict = case["expected_verdict"] if case else "—"
        row_cells = [
            _guardian_eval_cell(row.get("case_id")),
            _guardian_eval_cell(row.get("incident_id")),
            str(row.get("concluded")),
            expected_verdict,
            _guardian_eval_cell(row.get("actual_verdict")),
            _guardian_eval_cell(row.get("cost_usd")),
            _guardian_eval_cell(row.get("latency_seconds")),
            _guardian_eval_cell(row.get("tick_count")),
        ]
        lines.append("| " + " | ".join(row_cells) + " |")

    return "\n".join(lines)


def guardian_eval_report(case_ids=None):
    """Compute + render the eval scorecard markdown in one call.

    `main()` calls :func:`guardian_eval_report_data` and
    :func:`guardian_eval_render_report` directly instead of this wrapper, so
    it can hand the SAME computed numbers to both `readable_output` and
    `outputs` without a second live `guardian_eval_count_launched` scan --
    this function is for callers (tests, ad hoc use) that just want the
    rendered markdown.

    :param case_ids: See :func:`guardian_eval_report_data`.
    :return: The report markdown.
    :rtype: ``str``
    """
    return guardian_eval_render_report(guardian_eval_report_data(case_ids))


def guardian_eval_render_compare(data):
    """Render :func:`guardian_eval_compare_runs`'s data as compact markdown:
    each side's sample size, a prominent anecdote warning when either side's
    `n_v <= 1`, and a metric-by-metric delta table. Renders NO verdict of
    its own -- see :func:`guardian_eval_compare_runs`'s own docstring.

    :param data: The dict returned by :func:`guardian_eval_compare_runs`.
    :return: The full compare markdown.
    :rtype: ``str``
    """
    lines = [
        "## Guardian Eval Compare: {} (baseline) vs {} (candidate)".format(
            data["baseline_label"], data["candidate_label"]
        ),
        "",
    ]
    lines.append(
        "Baseline n_v={}, candidate n_v={}.".format(data["baseline"]["n_v"], data["candidate"]["n_v"])
    )
    if data["either_side_is_anecdotal"]:
        lines.append(
            "**WARNING**: at least one side has n_v<=1 -- \"three of five is the finding; one of one is "
            "an anecdote.\" This compare is not yet repeat-tested; treat any 'moved' flag below with "
            "caution until more repeats exist on the thin side."
        )
    lines.append("")

    lines.append("| Metric | Baseline | Candidate | Delta | Moved (\\|delta\\|>={:.2f}) |".format(data["min_delta"]))
    lines.append("|---|---|---|---|---|")
    for metric in data["metrics"]:
        delta_display = "n/a" if metric["delta"] is None else "{:+.1f}%".format(metric["delta"] * 100)
        lines.append(
            "| {} | {} | {} | {} | {} |".format(
                metric["label"],
                _guardian_eval_pct_str(metric["baseline_value"]),
                _guardian_eval_pct_str(metric["candidate_value"]),
                delta_display,
                "yes" if metric["moved"] else "no",
            )
        )

    return "\n".join(lines)


def guardian_eval_compare(baseline_label, candidate_label, case_ids=None, min_delta=None):
    """Compute + render the baseline-vs-candidate compare markdown in one
    call (the compare counterpart of :func:`guardian_eval_report`).

    :param baseline_label: See :func:`guardian_eval_compare_runs`.
    :param candidate_label: See :func:`guardian_eval_compare_runs`.
    :param case_ids: See :func:`guardian_eval_compare_runs`.
    :param min_delta: See :func:`guardian_eval_compare_runs`.
    :return: The compare markdown.
    :rtype: ``str``
    """
    return guardian_eval_render_compare(
        guardian_eval_compare_runs(baseline_label, candidate_label, case_ids=case_ids, min_delta=min_delta)
    )


def main():
    args = demisto.args()
    action = (args.get("action") or "run").strip().lower()
    case_ids_arg = args.get("case_ids")
    case_ids_filter = {c.strip() for c in case_ids_arg.split(",") if c.strip()} if case_ids_arg else None
    incident_ids_arg = args.get("incident_ids")
    incident_ids_filter = [i.strip() for i in incident_ids_arg.split(",") if i.strip()] if incident_ids_arg else None
    # `run_label` groups repeat `action=run` launches
    # and/or scopes `action=report` to one group; `action=compare` diffs two
    # groups outright (its own baseline_label/candidate_label args below).
    run_label_arg = (args.get("run_label") or "").strip() or None

    try:
        if action == "score":
            result = guardian_eval_score(incident_ids_filter)
        elif action == "run":
            result = guardian_eval_run(case_ids_filter, run_label=run_label_arg)
        elif action == "report":
            if run_label_arg:
                report_data = guardian_eval_report_data_by_run_label(run_label_arg, case_ids=case_ids_filter)
            else:
                report_data = guardian_eval_report_data(case_ids_filter)
            result = guardian_envelope(True, data=report_data)
        elif action == "compare":
            baseline_label = (args.get("baseline_label") or "").strip()
            candidate_label = (args.get("candidate_label") or "").strip()
            if not baseline_label or not candidate_label:
                return_error("GuardianEval (compare): both 'baseline_label' and 'candidate_label' args are required.")
                return
            min_delta_arg = args.get("min_delta")
            min_delta = float(min_delta_arg) if min_delta_arg not in (None, "") else None
            compare_data = guardian_eval_compare_runs(
                baseline_label, candidate_label, case_ids=case_ids_filter, min_delta=min_delta
            )
            result = guardian_envelope(True, data=compare_data)
        else:
            return_error(
                "GuardianEval: unknown action '{}' -- expected 'run', 'score', 'report', or 'compare'.".format(action)
            )
            return
    except Exception as ex:  # last-resort guard -- the run/score/report/compare
        # helpers themselves should never raise, but this is the only entry point.
        return_error("GuardianEval failed unexpectedly: {}".format(ex))
        return

    data = result["data"]
    if action == "run":
        lines = ["GuardianEval run: {} case(s) launched, {} error(s).".format(len(data["launched"]), len(data["errors"]))]
        for item in data["launched"]:
            lines.append("- case_id={} incident_id={} name='{}'".format(item["case_id"], item["incident_id"], item["name"]))
        for err in data["errors"]:
            lines.append("ERROR (case {}): {}".format(err["case_id"], err["error"]))
        summary = "\n".join(lines)
    elif action == "score":
        lines = [
            "GuardianEval score: {} scored, {} still running, {} already scored, {} error(s).".format(
                len(data["scored"]), len(data["still_running"]), len(data["already_scored"]), len(data["errors"])
            )
        ]
        for row in data["scored"]:
            lines.append(
                "- incident_id={} case_id={} passed={} ticks={} cost_usd={} tools={}".format(
                    row["incident_id"], row["case_id"], row["passed"], row["tick_count"], row["cost_usd"], row["distinct_tools"]
                )
            )
        for err in data["errors"]:
            lines.append("ERROR (incident {}): {}".format(err.get("incident_id"), err["error"]))
        summary = "\n".join(lines)
    elif action == "compare":  # `data` was built by guardian_eval_compare_runs() above
        summary = guardian_eval_render_compare(data)
    else:  # report -- `data` was built by guardian_eval_report_data[_by_run_label]() above
        summary = guardian_eval_render_report(data)
        # `rows` (the full per-row payload) is already rendered into the
        # markdown's own per-case table -- dropped from `outputs` so this
        # action's Context write stays a compact summary, not a duplicate
        # copy of every row's raw fields.
        data = {k: v for k, v in data.items() if k != "rows"}

    if not result["ok"]:
        return_error("GuardianEval ({}) failed.\n{}".format(action, summary))
        return

    return_results(
        CommandResults(
            readable_output=summary,
            outputs_prefix="Guardian.Eval.{}".format(action.capitalize()),
            outputs=data,
            raw_response=data,
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
