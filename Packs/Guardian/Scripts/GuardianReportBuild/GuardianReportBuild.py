"""GuardianReportBuild -- turn a finished Guardian run into the structured `Guardian.Report` the incident page draws.

The investigation is not touched. This is a separate step after it (the last task of `GuardianAgentLoop` and of the
investigation branch of `GuardianTriageAndInvestigateIncident`). It asks the run's model for a JSON report in three
focused calls, so every reply stays small:

- core: headline, entities, edges;
- story: attack, timeline, tree (given the entity ids from core);
- close: findings, actions, gaps.

Input: the run's transcript (`Guardian.Loop.messages`, plus the dropped-transcript archive when the run was compacted),
the conclusion, the recorded verdict (`Guardian.Loop.verdict`, else the incident's `guardianverdict` and
`guardianconfidence` fields), the severity change `GuardianTriageApply` made, and the tool names in
`Guardian.ToolCatalog`.

- **Evidence.** Every tool call of the run in order, numbered t1..tn: the tool, its arguments and the head of its result.
  Procedure and self-referential tools (`GUARDIAN_REPORT_SKIP_TOOLS`) are left out. The heads are cut so the largest of the
  three prompts fits the run's input budget (`model_params.max_input_tokens` at `GUARDIAN_CHARS_PER_ESTIMATED_TOKEN`
  characters per token), less a reserve of one group's reply: that budget already leaves room for the provider's reply
  (`output_reserve_tokens`), so the reserve is not counted twice. When even the shortest heads do not fit, the oldest
  calls are left out.
- **Model calls.** One `guardian-llm-chat` call per group, no tools and no `response_format` (a provider may ignore it):
  the JSON is taken out of the text. A reply with no usable JSON gets ONE repair request ("return only the JSON object").
  `report_max_calls` (`guardian_settings`, default 3) is the number of groups asked for, in the order above; repair
  requests are extra. The model is the one the run was routed to.
- **Not asked of the model.** Verdict, confidence and severity come from the run's own record, so the page always agrees
  with the incident fields.
- **Validation and grounding.** Enums, caps and string lengths are the ones the page applies (`GuardianLayoutAssessment`).
  A ref that is not an evidence id is dropped. An entity value found neither in the evidence results nor in the conclusion
  is dropped; one found only in the conclusion keeps an empty ref list, so the page shows it as unverified. A command in
  an action must be in the run's tool list, and an action about Guardian's own bookkeeping is dropped.

Output: `Guardian.Report` (written with `setContext`, so a re-run replaces it):

    {v, run_id, tick, fingerprint, generated_at, model, calls, tokens, cost_usd, seconds, report, refs, errors}

`report` is the merged report (or null when no group gave one) and `refs` maps each cited evidence id to
`{tool, summary}`, built here from the evidence list and never taken from the model. One `report_build` audit row is
written, each call is charged through `GuardianCostLedger`, and a short note goes to the War Room. The page shows the
report only while `run_id`, `tick` and `fingerprint` (the run's last assistant fingerprint) match the run state, so a report of
an earlier run on the same incident is never shown.

It never raises. A failure writes `Guardian.Report` with `errors` and no report, and the page falls back to the
assessment card. With `report_enabled` false in `guardian_settings`, with the kill switch on, or for a run started by a
scheduled Job (`guardiantriggersource` starting with `job:`, such as the intake sweep, which investigates the whole queue
and has no single incident to report on) it makes no model call and writes no report; it deletes `Guardian.Report`, so a
report of an earlier run cannot be shown. The kill switch is read again before every later model call. When the fixed
text of the prompts does not fit the run's input budget it makes no call and says so in `errors`. It is operator-owned: denylisted and not on the allowlist, so the model can never call it.
"""

import json
import re
import time
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

# --- constants ---------------------------------------------------------------------------------------------------

GUARDIAN_REPORT_LIST_NAME = "guardian_prompt_report"
GUARDIAN_REPORT_SETTINGS_LIST = "guardian_settings"
GUARDIAN_REPORT_KILL_SWITCH_LIST = "guardian_kill_switch"
GUARDIAN_REPORT_ARCHIVE_LIST = "guardian_dropped_transcript_archive"
GUARDIAN_REPORT_JOB_TRIGGER_PREFIX = "job:"
GUARDIAN_REPORT_CONTEXT_KEY = "Report"
GUARDIAN_REPORT_VERSION = 1
GUARDIAN_REPORT_TRIGGER = "report_build"
GUARDIAN_REPORT_ACTION = "report_build"
GUARDIAN_REPORT_ACTOR = "report"
GUARDIAN_REPORT_DEFAULT_MAX_CALLS = 3
GUARDIAN_REPORT_GROUPS = ("core", "story", "close")
GUARDIAN_REPORT_GROUP_KEYS = {
    "core": ("headline", "entities", "edges"),
    "story": ("attack", "timeline", "tree"),
    "close": ("findings", "actions", "gaps"),
}

#: Tools whose calls are not evidence: they read procedure or the agent's own notes, or write to the case.
GUARDIAN_REPORT_SKIP_TOOLS = frozenset((
    "GuardianSkillRead", "GuardianKBSearch", "GuardianMemory", "GuardianAskAnalyst", "GuardianCaseNote",
    "GuardianPlanApprove",
))

GUARDIAN_REPORT_MAX_EVIDENCE = 200
GUARDIAN_REPORT_HEAD_MAX_CHARS = 3000
GUARDIAN_REPORT_HEAD_MIN_CHARS = 60
GUARDIAN_REPORT_ARGS_MAX_CHARS = 300
GUARDIAN_REPORT_TASK_MAX_CHARS = 1500
GUARDIAN_REPORT_REPLY_RESERVE_TOKENS = 2048
GUARDIAN_REPORT_DEFAULT_INPUT_TOKENS = 28258
GUARDIAN_REPORT_CONCLUSION_SHARE_PERCENT = 25
GUARDIAN_REPORT_CONCLUSION_FLOOR_CHARS = 2000
#: Room kept in every prompt for the entity list that the story and close groups are given.
GUARDIAN_REPORT_ENTITY_LIST_CHARS = 4000
GUARDIAN_REPORT_TOOL_LIST_MAX_CHARS = 2400
GUARDIAN_REPORT_CUT_MARK = " ...[cut]"
GUARDIAN_REPORT_REPAIR_REPLY_MAX_CHARS = 4000
GUARDIAN_REPORT_ERROR_MAX_CHARS = 200
GUARDIAN_REPORT_MODEL_ERROR_TAGS = ("MODEL_NOT_AVAILABLE:", "MODEL_SELECTION_UNSUPPORTED:")

#: Caps, enums and string lengths. `GuardianLayoutAssessment` applies the same ones when it draws the report; a content
#: test keeps the two copies equal.
GUARDIAN_REPORT_CAPS = {"entities": 20, "edges": 30, "attack": 15, "timeline": 25, "tree": 30, "findings": 10,
                        "actions": 8, "gaps": 5}
GUARDIAN_REPORT_ETYPES = ("user", "host", "process", "file", "ip", "domain", "url", "email", "hash", "cloud", "other")
GUARDIAN_REPORT_ROLES = ("victim", "attacker", "infra", "asset", "tool", "other")
GUARDIAN_REPORT_REPS = ("malicious", "suspicious", "benign", "unknown")
GUARDIAN_REPORT_RELS = ("logged_on", "ran", "spawned", "wrote", "connected", "resolved", "downloaded", "sent", "received",
                        "authenticated", "accessed", "other")
GUARDIAN_REPORT_FLAGS = ("malicious", "suspicious")
GUARDIAN_REPORT_VERDICTS = ("malicious", "suspicious", "benign", "inconclusive")
GUARDIAN_REPORT_SEVERITIES = ("informational", "low", "medium", "high", "critical")
GUARDIAN_REPORT_OWNERS = ("guardian", "analyst")
GUARDIAN_REPORT_TACTICS = ("Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
                           "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                           "Collection", "Command and Control", "Exfiltration", "Impact")
GUARDIAN_REPORT_TACTIC_ALIAS = {
    "reconnaissance": 0, "recon": 0, "ta0043": 0, "resourcedevelopment": 1, "resourcedev": 1, "ta0042": 1,
    "initialaccess": 2, "ta0001": 2, "execution": 3, "ta0002": 3, "persistence": 4, "ta0003": 4,
    "privilegeescalation": 5, "privesc": 5, "ta0004": 5, "defenseevasion": 6, "defenceevasion": 6, "ta0005": 6,
    "credentialaccess": 7, "credaccess": 7, "ta0006": 7, "discovery": 8, "ta0007": 8, "lateralmovement": 9,
    "lateralmvmt": 9, "ta0008": 9, "collection": 10, "ta0009": 10, "commandandcontrol": 11, "commandcontrol": 11,
    "c2": 11, "ta0011": 11, "exfiltration": 12, "exfil": 12, "ta0010": 12, "impact": 13, "ta0040": 13,
}
GUARDIAN_REPORT_LIMITS = {"headline": 140, "reason": 160, "value": 120, "tactic": 40, "tech": 16, "name": 60, "evidence": 160,
                          "event": 160, "src": 24, "cmd": 160, "pid": 10, "time": 30, "finding": 200, "action": 160,
                          "action_cmd": 200, "gap": 200, "ref_tool": 40, "ref_summary": 200}
GUARDIAN_REPORT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.\-]{1,12}$")
#: A value that names a kind of thing, not a thing. The prompt forbids these as entities; this is the same rule in code.
GUARDIAN_REPORT_GENERIC_VALUES = frozenset((
    "workstation", "server", "host", "hostname", "user", "username", "account", "attacker", "victim", "malware", "file",
    "process", "ip", "ip address", "domain", "url", "email", "hash", "endpoint", "system", "network", "device", "unknown",
    "n/a", "none", "laptop", "desktop", "machine", "computer", "client", "website", "link", "attachment",
))
#: An action about Guardian's own bookkeeping (its incident fields, notes, memory), which is never a recommendation.
GUARDIAN_REPORT_BOOKKEEPING_PATTERN = re.compile(
    r"guardian(?:verdict|confidence|blastradius|attacktechniques|costusd|tickcount|model|toolcalls|toolfailures|toolsused|"
    r"gateaction|approvalmode|approvalsrequested|triggersource|evalrunlabel)|"
    r"guardian(?:casenote|memory|skillread|askanalyst|kbsearch)", re.I)

# The prompt text is a deploy-time List (`guardian_prompt_report`); this copy is used when the List is missing or malformed,
# and a content test keeps the two equal.
GUARDIAN_REPORT_DEFAULT_PROMPTS = {
    "rules": (
        "You write the structured report of a FINISHED Guardian security investigation. You get the task the investigation "
        "was given, the EVIDENCE (the run's tool results, each numbered t1, t2, ...), the investigation's CONCLUSION and the "
        "TOOLS the run could call. Return ONE JSON object and nothing else: no prose, no Markdown.\n"
        "\n"
        "Rules:\n"
        "- Use only facts that appear in the EVIDENCE or the CONCLUSION. Never invent a host, user, IP, domain, hash, process, "
        "time or technique. Copy values exactly as written. If there is nothing for a section, return an empty list.\n"
        "- \"ref\" lists the evidence ids that show the item (for example [\"t2\"]). The CONCLUSION is not evidence: a fact "
        "found only in the conclusion gets \"ref\": [].\n"
        "- An entity is a concrete identifier copied from the evidence: a user name, host name, process image, file name or "
        "path, IP address, domain, URL, email address, hash or cloud resource id. A generic word (\"workstation\", "
        "\"server\", \"attacker\", \"malware\") or a label (\"suspicious file\") is never an entity.\n"
        "- Times are ISO 8601 UTC, taken from the evidence only.\n"
        "- Strings are plain text, short, no HTML or Markdown. Respect every list cap.\n"
        "- The verdict, confidence and severity of the report come from the run's own record. Do not return them.\n"
        "- An action's \"cmd\" may only name a command from the TOOLS list. When no listed command fits, leave \"cmd\" out. "
        "Never propose an action about Guardian's own bookkeeping (Guardian incident fields, case notes, memory, or the "
        "verdict itself).\n"
    ),
    "core": (
        "Return exactly these keys:\n"
        "{\"v\":1,\n"
        " \"headline\": str<=140 (one sentence: what happened and how sure),\n"
        " \"entities\": [<=20 {\"id\":\"e1\",\"type\": user|host|process|file|ip|domain|url|email|hash|cloud|other, "
        "\"value\": str<=120,\n"
        "              \"rep\": malicious|suspicious|benign|unknown, \"role\": victim|attacker|infra|asset|tool|other, "
        "\"ref\":[ids]}],\n"
        " \"edges\": [<=30 {\"from\":\"e1\",\"to\":\"e2\",\"rel\": logged_on|ran|spawned|wrote|connected|resolved|"
        "downloaded|sent|received|\n"
        "            authenticated|accessed|other, \"time\"?: iso, \"ref\":[ids]}]   (\"from REL to\", e.g. a process "
        "connected to an ip)\n"
        "}"
    ),
    "story": (
        "Return exactly these keys:\n"
        "{\"v\":1,\n"
        " \"attack\": [<=15 {\"tactic\": ATT&CK enterprise tactic name, \"tech\": \"T1071.001\", \"name\": str<=60, "
        "\"time\"?: iso,\n"
        "            \"evidence\": str<=160, \"ents\": [entity ids], \"ref\":[ids]}]   (only techniques the evidence "
        "shows),\n"
        " \"timeline\": [<=25 {\"t\": iso, \"event\": str<=160, \"src\": str<=24 (data source), \"ents\": [entity ids], "
        "\"tech\"?: str,\n"
        "              \"ref\":[ids]}]   (only events with a time in the evidence),\n"
        " \"tree\": [<=30 {\"id\":\"n1\",\"parent\": \"n0\"|null, \"ent\"?: entity id, \"name\": str<=60, "
        "\"cmd\"?: str<=160, \"pid\"?: str,\n"
        "          \"flag\"?: malicious|suspicious, \"tech\"?: str, \"ref\":[ids]}]   (the process tree, only if the "
        "evidence has one)\n"
        "}\n"
        "Use the entity ids already defined (listed below); do not create new entities."
    ),
    "close": (
        "Return exactly these keys:\n"
        "{\"v\":1,\n"
        " \"findings\": [<=10 {\"text\": str<=200, \"ref\":[ids]}]   (the key facts, each tied to its evidence),\n"
        " \"actions\": [<=8 {\"p\": 1|2|3, \"action\": str<=160, \"owner\": \"guardian\"|\"analyst\", "
        "\"approval\": true|false,\n"
        "             \"cmd\"?: str<=200}]   (approval true for anything that changes a system; \"cmd\" only from the "
        "TOOLS list),\n"
        " \"gaps\": [<=5 str<=200]   (what the investigation could not establish)\n"
        "}"
    ),
    "repair": "Return only the JSON object.",
}


# --- small helpers -----------------------------------------------------------------------------------------------

def guardian_report_clip(value, limit):
    """Plain one-line text cut to `limit` characters; ``""`` for anything that is not text or a number."""
    if value is None or isinstance(value, (dict, list, tuple, set, bool)):
        return ""
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[:max(limit - 1, 0)] + "…"


def guardian_report_enum(value, allowed, default):
    text = value.strip().lower() if isinstance(value, str) else ""
    return text if text in allowed else default


def guardian_report_number(value):
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number == number and abs(number) != float("inf") else None


def guardian_report_positive_int(value, default):
    number = guardian_report_number(value)
    return int(number) if number is not None and number >= 1 else default


def guardian_report_dict(value):
    """The dict itself, or the last dict of a list (appended context); ``{}`` otherwise."""
    if isinstance(value, list):
        value = next((item for item in reversed(value) if isinstance(item, dict)), {})
    return value if isinstance(value, dict) else {}


def guardian_report_items(value, cap):
    return [item for item in value if isinstance(item, dict)][:cap] if isinstance(value, list) else []


def guardian_report_tactic(name):
    """The ATT&CK tactic's full name for a name, short form or TA id; the cleaned input when unknown."""
    text = guardian_report_clip(name, GUARDIAN_REPORT_LIMITS["tactic"])
    slot = GUARDIAN_REPORT_TACTIC_ALIAS.get(re.sub(r"[^a-z0-9]", "", text.lower()))
    return GUARDIAN_REPORT_TACTICS[slot] if slot is not None else text


def guardian_report_technique(value):
    """An ATT&CK technique id (T1059 or T1059.001), or ``""``."""
    text = guardian_report_clip(value, GUARDIAN_REPORT_LIMITS["tech"]).upper()
    return text if re.match(GUARDIAN_TECHNIQUE_PATTERN_STR, text) else ""


def guardian_report_iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- reading the Lists -------------------------------------------------------------------------------------------

def guardian_report_load_list_json(list_name):
    """``(data, error)`` for a List's JSON content; ``data`` is ``None`` when it cannot be read or parsed."""
    result = guardian_execute("getList", {"listName": list_name})
    if not result["ok"]:
        return None, str(result["error"])[:GUARDIAN_REPORT_ERROR_MAX_CHARS]
    contents = None
    for entry in result["data"] or []:
        if isinstance(entry, dict) and entry.get("Contents") is not None:
            contents = entry["Contents"]
    if isinstance(contents, str):
        try:
            contents = json.loads(contents) if contents.strip() else None
        except ValueError:
            return None, "'{}' is not valid JSON".format(list_name)
    if not isinstance(contents, (dict, list)):
        return None, "'{}' has no usable content".format(list_name)
    return contents, ""


def guardian_report_read_settings():
    """``{"enabled": bool, "max_calls": int}`` from `guardian_settings`; an unreadable List means the defaults."""
    data, _error = guardian_report_load_list_json(GUARDIAN_REPORT_SETTINGS_LIST)
    data = data if isinstance(data, dict) else {}
    enabled = data.get("report_enabled")
    off = enabled is False or (isinstance(enabled, str) and enabled.strip().lower() in ("false", "no", "0", "off"))
    return {"enabled": not off, "max_calls": min(len(GUARDIAN_REPORT_GROUPS), guardian_report_positive_int(
        data.get("report_max_calls"), GUARDIAN_REPORT_DEFAULT_MAX_CALLS))}


def guardian_report_kill_switch_on():
    """The same read as the reasoning loop: halted only when `guardian_kill_switch.enabled` is true; an unreadable List
    is ambiguous, not proof the operator wants everything halted, so it counts as off."""
    data, _error = guardian_report_load_list_json(GUARDIAN_REPORT_KILL_SWITCH_LIST)
    return isinstance(data, dict) and data.get("enabled") is True


def guardian_report_load_prompts():
    """``(prompts, source)``: the five prompt texts from `guardian_prompt_report` (``"list"``), each falling back to the
    built-in copy when it is missing or empty; all built in (``"default"``) when the List cannot be read."""
    data, _error = guardian_report_load_list_json(GUARDIAN_REPORT_LIST_NAME)
    if not isinstance(data, dict):
        return dict(GUARDIAN_REPORT_DEFAULT_PROMPTS), "default"
    prompts = {}
    for key, default in GUARDIAN_REPORT_DEFAULT_PROMPTS.items():
        text = data.get(key)
        prompts[key] = text.strip() if isinstance(text, str) and text.strip() else default
    return prompts, "list"


def guardian_report_load_archive(run_id, tick, compacted, session_id=None):
    """The dropped-transcript rows of THIS run, oldest first; ``[]`` when the run was not compacted or the archive cannot
    be read. The run id is the incident id, so every run on an incident shares it: with the run state's `session_id` only
    the rows of that session are kept (rows written before the id existed are not this session's). A run state without one
    (saved by an older version) falls back to the tick: rows from a later tick, and rows before the last point where the
    tick fell back, are left out."""
    if not compacted:
        return []
    data, _error = guardian_report_load_list_json(GUARDIAN_REPORT_ARCHIVE_LIST)
    if not isinstance(data, list):
        return []
    rows = [row for row in data if isinstance(row, dict) and str(row.get("run_id")) == str(run_id)]
    if session_id:
        return [row for row in rows if row.get("session_id") == session_id]
    if isinstance(tick, int):
        rows = [row for row in rows if not isinstance(row.get("tick"), int) or row["tick"] <= tick]
    start, last = 0, None
    for index, row in enumerate(rows):
        value = row.get("tick") if isinstance(row.get("tick"), int) else None
        if value is not None and last is not None and value < last:
            start = index
        last = value if value is not None else last
    return rows[start:]


# --- the evidence ------------------------------------------------------------------------------------------------

def guardian_report_payload_text(payload):
    if isinstance(payload, str):
        return payload
    if isinstance(payload, list) and payload and all(isinstance(item, str) for item in payload):
        return "\n".join(payload)
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)


def guardian_report_leaves(value, depth=0):
    """Every string inside a decoded result (keys and values), with the strings that are themselves JSON opened one level
    deeper, so a value is found as the tool printed it, not as JSON escaped it."""
    if isinstance(value, str):
        out = [value]
        if depth < 3 and value[:1] in "{[":
            try:
                out += guardian_report_leaves(json.loads(value), depth + 1)
            except ValueError:
                pass
        return out
    if isinstance(value, dict):
        out = []
        for key, item in value.items():
            out.append(str(key))
            out += guardian_report_leaves(item, depth)
        return out
    if isinstance(value, list):
        out = []
        for item in value:
            out += guardian_report_leaves(item, depth)
        return out
    return [] if value is None else [str(value)]


def guardian_report_decode_result(content):
    """``(body, grounding)`` for one tool message: the text shown to the model (the bridge's envelope removed; a failure or
    a non-ok status says so) and the text an entity is looked up in (every string of the result, as printed)."""
    raw = content if isinstance(content, str) else json.dumps(content, default=str)
    try:
        obj = json.loads(raw)
    except ValueError:
        obj = None
    status, failed = "", False
    if isinstance(obj, dict) and "ok" in obj and ("result" in obj or "error" in obj):
        failed = obj.get("ok") is not True
        payload = obj.get("error") if failed else obj.get("result")
        status = obj.get("status") if isinstance(obj.get("status"), str) else ""
    else:
        payload = obj if obj is not None else raw
    body = guardian_report_payload_text(payload)
    if failed:
        body = "FAILED: " + body
    elif status and status != "ok":
        body = "[status={}] {}".format(status, body)
    return body, "\n".join(guardian_report_leaves(payload)) + "\n" + raw


def guardian_report_evidence(messages):
    """The run's tool calls in order as ``[{"id", "tool", "args", "body", "grounding"}]``, ids t1..tn, skipped tools left
    out. `messages` is the archive's dropped messages followed by the current transcript."""
    calls, results, seen = [], {}, set()
    for message in messages:
        if not isinstance(message, dict):
            continue
        if message.get("role") == "assistant":
            for call in message.get("tool_calls") or []:
                function = call.get("function") if isinstance(call, dict) else None
                if not isinstance(function, dict):
                    continue
                call_id = str(call.get("id") or "")
                if call_id and call_id in seen:
                    continue
                seen.add(call_id)
                arguments = function.get("arguments")
                arguments = arguments if isinstance(arguments, str) else json.dumps(arguments or {}, default=str)
                calls.append((call_id, str(function.get("name") or ""), " ".join(arguments.split())))
        elif message.get("role") == "tool" and message.get("tool_call_id"):
            results[str(message["tool_call_id"])] = message.get("content")
    evidence = []
    for call_id, name, arguments in calls:
        if not name or name in GUARDIAN_REPORT_SKIP_TOOLS:
            continue
        if call_id in results:
            body, grounding = guardian_report_decode_result(results[call_id])
        else:
            body, grounding = "(no result was recorded)", ""
        if len(arguments) > GUARDIAN_REPORT_ARGS_MAX_CHARS:
            arguments = arguments[:GUARDIAN_REPORT_ARGS_MAX_CHARS - 1] + "…"
        evidence.append({"id": "t{}".format(len(evidence) + 1), "tool": name, "args": arguments, "body": body,
                         "grounding": grounding})
    return evidence


def guardian_report_fit_evidence(evidence, available_chars):
    """Cut the result heads so the evidence block fits `available_chars`. Every head is cut to the same cap (a short result
    stays whole and leaves its share to the others), never below `GUARDIAN_REPORT_HEAD_MIN_CHARS`; when even that does not
    fit, the oldest calls are left out. Returns ``(text, shown_ids)``."""
    items = [(ev, "[{}] {} {}".format(ev["id"], ev["tool"], ev["args"])) for ev in evidence[-GUARDIAN_REPORT_MAX_EVIDENCE:]]

    def size(rows, cap):
        return sum(len(line) + 3 + min(len(ev["body"]), cap) + (len(GUARDIAN_REPORT_CUT_MARK) if len(ev["body"]) > cap else 0)
                   for ev, line in rows)

    cap = GUARDIAN_REPORT_HEAD_MAX_CHARS
    if size(items, cap) > available_chars:
        low, high = 0, cap
        while low < high:
            middle = (low + high + 1) // 2
            if size(items, middle) <= available_chars:
                low = middle
            else:
                high = middle - 1
        cap = low
    if cap < GUARDIAN_REPORT_HEAD_MIN_CHARS:
        cap = GUARDIAN_REPORT_HEAD_MIN_CHARS
        while items and size(items, cap) > available_chars:
            items = items[1:]
    blocks = []
    for ev, line in items:
        body = ev["body"]
        blocks.append("{}\n{}".format(line, body if len(body) <= cap else body[:cap] + GUARDIAN_REPORT_CUT_MARK))
    return "\n\n".join(blocks), [ev["id"] for ev, _line in items]


# --- the run's recorded facts -----------------------------------------------------------------------------------

def guardian_report_conclusion(loop):
    text = loop.get("conclusion")
    if isinstance(text, str) and text.strip():
        return text.strip()
    for message in reversed(loop.get("messages") if isinstance(loop.get("messages"), list) else []):
        if isinstance(message, dict) and message.get("role") == "assistant" and not message.get("tool_calls"):
            content = message.get("content")
            if isinstance(content, str) and content.strip():
                return content.strip()
    return ""


def guardian_report_task(loop):
    for message in loop.get("messages") if isinstance(loop.get("messages"), list) else []:
        if isinstance(message, dict) and message.get("role") == "user" and isinstance(message.get("content"), str):
            return message["content"].strip()[:GUARDIAN_REPORT_TASK_MAX_CHARS]
    return ""


def guardian_report_severity_name(value):
    text = str(value).strip().lower() if value is not None and not isinstance(value, (dict, list)) else ""
    if text in GUARDIAN_REPORT_SEVERITIES:
        return text
    number = guardian_report_number(value)
    return {0.5: "informational", 1: "low", 2: "medium", 3: "high", 4: "critical"}.get(number, "")


def guardian_report_recorded_verdict(incident, loop, triage):
    """``{"verdict", "confidence"}`` from the run's own record: `Guardian.Loop.verdict`, else the incident's verdict fields,
    else the triage result. A key is missing when nothing recorded it. Never from the report model."""
    recorded = guardian_report_dict(loop.get("verdict"))
    fields = guardian_report_dict(incident.get("CustomFields"))
    name = guardian_report_enum(recorded.get("verdict"), GUARDIAN_REPORT_VERDICTS, "")
    if not name:
        name = guardian_report_enum(fields.get("guardianverdict"), GUARDIAN_REPORT_VERDICTS, "")
    if not name and triage.get("likely_benign") is True:
        name = "benign"
    confidence = guardian_report_number(recorded.get("confidence") if recorded.get("verdict") else None)
    if confidence is None:
        confidence = guardian_report_number(fields.get("guardianconfidence"))
    if confidence is None:
        confidence = guardian_report_number(triage.get("confidence")) if triage else None
    out = {}
    if name:
        out["verdict"] = name
    if confidence is not None:
        out["confidence"] = int(min(100, max(0, confidence)))
    return out


def guardian_report_recorded_severity(incident, apply_record):
    """``{"from", "to", "reason"}`` as the incident page states it: before the triage change and after it (``to`` is empty
    when Guardian did not change the severity)."""
    if not apply_record:
        return {"from": guardian_report_severity_name(incident.get("severity")), "to": "",
                "reason": "Severity was not changed by Guardian in this run."}
    before = guardian_report_severity_name(apply_record.get("severity_before"))
    after = guardian_report_severity_name(apply_record.get("severity_after"))
    status = str(apply_record.get("status") or "").lower()
    reason = guardian_report_clip(apply_record.get("reason"), GUARDIAN_REPORT_LIMITS["reason"])
    changed = status in ("applied", "dry_run") and after and after != before
    return {"from": before or guardian_report_severity_name(incident.get("severity")), "to": after if changed else "",
            "reason": reason or ("Severity was changed by Guardian triage." if changed else "Severity was not changed by Guardian in this run.")}


# --- the prompts -------------------------------------------------------------------------------------------------

def guardian_report_user_message(inp, evidence_text, entities=None):
    verdict = inp["verdict"]
    recorded = ""
    if verdict:
        recorded = "RECORDED VERDICT (from the run, do not change it): {}{}.\n\n".format(
            verdict.get("verdict", "none"), ", confidence {}".format(verdict["confidence"]) if "confidence" in verdict else "")
    text = "INCIDENT: {}\n\n{}TASK (what the investigation was asked):\n{}\n\nEVIDENCE:\n{}\n\nCONCLUSION:\n{}\n\n" \
           "TOOLS the run could call (an action \"cmd\" may only name one of these):\n{}".format(
               json.dumps(inp["incident"], ensure_ascii=False), recorded, inp["task"], evidence_text or "(none)",
               inp["conclusion"] or "(none)", inp["tool_text"] or "(none)")
    if entities is not None:
        text += "\n\nENTITIES ALREADY DEFINED:\n" + json.dumps(entities, ensure_ascii=False)
    return text


def guardian_report_messages(prompts, group, inp, evidence_text, entities=None):
    system = "{}\n{}".format(prompts["rules"], prompts[group])
    return [{"role": "system", "content": system},
            {"role": "user", "content": guardian_report_user_message(inp, evidence_text, entities)}]


def guardian_report_budget_chars(model_params):
    """Characters the largest prompt may hold: the run's input budget at the shared chars-per-token estimate, less a
    reserve of one group's reply."""
    params = model_params if isinstance(model_params, dict) else {}
    tokens = guardian_report_positive_int(params.get("max_input_tokens"), GUARDIAN_REPORT_DEFAULT_INPUT_TOKENS)
    return max(tokens - GUARDIAN_REPORT_REPLY_RESERVE_TOKENS, 1000) * GUARDIAN_CHARS_PER_ESTIMATED_TOKEN


def guardian_report_inputs(incident, loop, triage, apply_record, tool_names, archive_rows, prompts):
    """Everything the three prompts are made of, and the grounding texts. Pure."""
    messages = []
    for row in archive_rows:
        messages += [m for m in row.get("dropped_messages") or [] if isinstance(m, dict)]
    messages += [m for m in loop.get("messages") or [] if isinstance(m, dict)]
    evidence = guardian_report_evidence(messages)
    budget = guardian_report_budget_chars(loop.get("model_params"))
    conclusion_cap = max(GUARDIAN_REPORT_CONCLUSION_FLOOR_CHARS, budget * GUARDIAN_REPORT_CONCLUSION_SHARE_PERCENT // 100)
    conclusion = guardian_report_conclusion(loop)
    tool_text = ", ".join(tool_names)[:GUARDIAN_REPORT_TOOL_LIST_MAX_CHARS]
    inp = {
        "incident": {"id": str(incident.get("id") or ""), "name": guardian_report_clip(incident.get("name"), 200),
                     "type": guardian_report_clip(incident.get("type"), 80),
                     "severity": guardian_report_severity_name(incident.get("severity"))},
        "task": guardian_report_task(loop), "conclusion": conclusion[:conclusion_cap], "tool_text": tool_text,
        "verdict": guardian_report_recorded_verdict(incident, loop, triage),
    }
    fixed = max(sum(len(m["content"]) for m in guardian_report_messages(prompts, group, inp, ""))
                for group in GUARDIAN_REPORT_GROUPS) + GUARDIAN_REPORT_ENTITY_LIST_CHARS
    evidence_text, shown = guardian_report_fit_evidence(evidence, budget - fixed)
    shown_evidence = [ev for ev in evidence if ev["id"] in set(shown)]
    inp.update({
        "evidence": shown_evidence, "evidence_text": evidence_text, "tool_names": set(tool_names), "budget_chars": budget,
        "grounding": "\n".join(ev["grounding"] for ev in shown_evidence).lower(),
        "conclusion_lower": conclusion.lower(),
        "recorded_severity": guardian_report_recorded_severity(incident, apply_record),
        "fixed_chars": fixed, "fits": budget >= fixed,
    })
    return inp


# --- the model call ----------------------------------------------------------------------------------------------

def guardian_report_last_contents(entries):
    contents = None
    for entry in entries or []:
        if isinstance(entry, dict) and entry.get("Contents") is not None:
            contents = entry["Contents"]
    return contents


def guardian_report_call_llm(messages, model=None):
    """One `guardian-llm-chat` call, no tools and no `response_format`. Returns ``{"ok", "content", "usage", "model",
    "error"}``. The run's routed `model` is passed when there is one, and dropped once for a provider that cannot serve it."""
    call_args = {"messages": messages, "tool_choice": "none"}
    if model:
        call_args["model"] = model
    result = guardian_execute("guardian-llm-chat", call_args)
    if model and not result["ok"] and any(tag in str(result["error"]) for tag in GUARDIAN_REPORT_MODEL_ERROR_TAGS):
        call_args.pop("model")
        result = guardian_execute("guardian-llm-chat", call_args)
    if not result["ok"]:
        return {"ok": False, "content": "", "usage": {}, "model": "", "error": result["error"]}
    completion = guardian_report_last_contents(result["data"])
    if not isinstance(completion, dict):
        return {"ok": False, "content": "", "usage": {}, "model": "", "error": "guardian-llm-chat returned no completion"}
    usage, name = completion.get("usage") or {}, completion.get("model") or ""
    if completion.get("content_filter"):
        return {"ok": False, "content": "", "usage": usage, "model": name,
                "error": "blocked by the provider's content filter", "filtered": True}
    choices = completion.get("choices") or []
    message = choices[0].get("message") if choices and isinstance(choices[0], dict) else None
    content = (message.get("content") if isinstance(message, dict) else "") or ""
    return {"ok": True, "content": str(content).strip(), "usage": usage, "model": name, "error": ""}


def guardian_report_charge(turn, run_id):
    """Charge one call through `GuardianCostLedger`; its USD cost, or 0.0 when it cannot be charged."""
    if not turn.get("usage") and not turn.get("model"):
        return 0.0
    result = guardian_execute("GuardianCostLedger", {
        "usage": json.dumps(turn.get("usage") or {}), "model": turn.get("model") or "", "run_id": str(run_id),
        "trigger": GUARDIAN_REPORT_TRIGGER})
    if not result["ok"]:
        return 0.0
    cost = guardian_report_last_contents(result["data"])
    usd = cost.get("usd") if isinstance(cost, dict) else None
    return float(usd) if isinstance(usd, (int, float)) and not isinstance(usd, bool) else 0.0


def guardian_report_extract_json(text, keys):
    """The first JSON object in `text` that has one of `keys`, or ``None``. Fenced blocks are tried first, then every ``{``;
    each candidate is decoded with `raw_decode`, so quotes, escapes and braces inside strings cannot end it early."""
    if not isinstance(text, str):
        return None
    decoder = json.JSONDecoder()
    spans = [match.start(1) for match in re.finditer(r"```[ \t]*[\w+-]*[ \t]*\n?(\{)", text)]
    spans += [match.start() for match in re.finditer(r"\{", text) if match.start() not in spans]
    for start in spans:
        try:
            value, _end = decoder.raw_decode(text, start)
        except ValueError:
            continue
        if isinstance(value, dict) and any(key in value for key in keys):
            return value
    return None


# --- validation and grounding -------------------------------------------------------------------------------------

def guardian_report_refs(item, valid):
    value = item.get("ref")
    if not isinstance(value, list):
        return []
    return [ref for ref in dict.fromkeys(x for x in value if isinstance(x, str)) if ref in valid][:8]


def guardian_report_ent_ids(item, known, cap=6):
    out = []
    for value in item.get("ents") if isinstance(item.get("ents"), list) else []:
        if isinstance(value, str) and value in known and value not in out:
            out.append(value)
    return out[:cap]


def guardian_report_normalize_core(obj, inp):
    valid = {ev["id"] for ev in inp["evidence"]}
    limits = GUARDIAN_REPORT_LIMITS
    entities, seen, dropped = [], set(), 0
    for item in guardian_report_items(obj.get("entities"), 60):
        entity_id, full = item.get("id"), guardian_report_clip(item.get("value"), 10000)
        value = guardian_report_clip(full, limits["value"])
        if not (isinstance(entity_id, str) and GUARDIAN_REPORT_ID_PATTERN.match(entity_id)) or entity_id in seen or not value:
            continue
        low = full.lower()
        if low in GUARDIAN_REPORT_GENERIC_VALUES:
            dropped += 1
            continue
        in_evidence, in_conclusion = low in inp["grounding"], low in inp["conclusion_lower"]
        if not (in_evidence or in_conclusion):
            dropped += 1
            continue
        seen.add(entity_id)
        entities.append({
            "id": entity_id, "type": guardian_report_enum(item.get("type"), GUARDIAN_REPORT_ETYPES, "other"), "value": value,
            "rep": guardian_report_enum(item.get("rep"), GUARDIAN_REPORT_REPS, "unknown"),
            "role": guardian_report_enum(item.get("role"), GUARDIAN_REPORT_ROLES, "other"),
            "ref": guardian_report_refs(item, valid) if in_evidence else []})
    entities = entities[:GUARDIAN_REPORT_CAPS["entities"]]
    known, edges, keys = {e["id"] for e in entities}, [], set()
    for item in guardian_report_items(obj.get("edges"), 100):
        source, target = item.get("from"), item.get("to")
        rel = guardian_report_enum(item.get("rel"), GUARDIAN_REPORT_RELS, "other")
        if not (isinstance(source, str) and isinstance(target, str) and source in known and target in known
                and source != target) or (source, target, rel) in keys:
            continue
        keys.add((source, target, rel))
        edges.append({"from": source, "to": target, "rel": rel, "time": guardian_report_clip(item.get("time"), limits["time"]),
                      "ref": guardian_report_refs(item, valid)})
    return {"headline": guardian_report_clip(obj.get("headline"), limits["headline"]), "entities": entities,
            "edges": edges[:GUARDIAN_REPORT_CAPS["edges"]]}, dropped


def guardian_report_normalize_story(obj, inp, entities):
    valid, limits = {ev["id"] for ev in inp["evidence"]}, GUARDIAN_REPORT_LIMITS
    known = {e["id"]: e for e in entities}
    attack = []
    for item in guardian_report_items(obj.get("attack"), 40):
        step = {"tactic": guardian_report_tactic(item.get("tactic")), "tech": guardian_report_technique(item.get("tech")),
                "name": guardian_report_clip(item.get("name"), limits["name"]),
                "time": guardian_report_clip(item.get("time"), limits["time"]),
                "evidence": guardian_report_clip(item.get("evidence"), limits["evidence"]),
                "ents": guardian_report_ent_ids(item, known), "ref": guardian_report_refs(item, valid)}
        if step["name"] or step["tech"] or step["evidence"]:
            attack.append(step)
    timeline = []
    for item in guardian_report_items(obj.get("timeline"), 60):
        event = guardian_report_clip(item.get("event"), limits["event"])
        if event:
            timeline.append({"t": guardian_report_clip(item.get("t"), limits["time"]), "event": event,
                             "src": guardian_report_clip(item.get("src"), limits["src"]),
                             "ents": guardian_report_ent_ids(item, known),
                             "tech": guardian_report_technique(item.get("tech")), "ref": guardian_report_refs(item, valid)})
    tree, seen = [], set()
    for item in guardian_report_items(obj.get("tree"), 60):
        node_id = item.get("id")
        if not (isinstance(node_id, str) and GUARDIAN_REPORT_ID_PATTERN.match(node_id)) or node_id in seen:
            continue
        entity = item.get("ent") if isinstance(item.get("ent"), str) and item.get("ent") in known else None
        name = guardian_report_clip(item.get("name"), limits["name"]) or (known[entity]["value"] if entity else "")
        if not name:
            continue
        seen.add(node_id)
        tree.append({"id": node_id, "parent": item.get("parent") if isinstance(item.get("parent"), str) else None,
                     "ent": entity, "name": name, "cmd": guardian_report_clip(item.get("cmd"), limits["cmd"]),
                     "pid": guardian_report_clip(item.get("pid"), limits["pid"]),
                     "flag": guardian_report_enum(item.get("flag"), GUARDIAN_REPORT_FLAGS, ""),
                     "tech": guardian_report_technique(item.get("tech")), "ref": guardian_report_refs(item, valid)})
    tree = tree[:GUARDIAN_REPORT_CAPS["tree"]]
    ids = {node["id"] for node in tree}
    for node in tree:
        if node["parent"] not in ids or node["parent"] == node["id"]:
            node["parent"] = None
    return {"attack": attack[:GUARDIAN_REPORT_CAPS["attack"]], "timeline": timeline[:GUARDIAN_REPORT_CAPS["timeline"]],
            "tree": tree}


def guardian_report_command_name(command):
    token = command.strip().lstrip("!").split(None, 1)[0] if command.strip().lstrip("!") else ""
    return token


def guardian_report_normalize_close(obj, inp):
    valid, limits = {ev["id"] for ev in inp["evidence"]}, GUARDIAN_REPORT_LIMITS
    findings = [{"text": guardian_report_clip(item.get("text"), limits["finding"]), "ref": guardian_report_refs(item, valid)}
                for item in guardian_report_items(obj.get("findings"), 30)
                if guardian_report_clip(item.get("text"), limits["finding"])]
    actions = []
    for item in guardian_report_items(obj.get("actions"), 30):
        action = guardian_report_clip(item.get("action"), limits["action"])
        command = guardian_report_clip(item.get("cmd"), limits["action_cmd"])
        if not action or GUARDIAN_REPORT_BOOKKEEPING_PATTERN.search(action + " " + command):
            continue
        if command and guardian_report_command_name(command) not in inp["tool_names"]:
            command = ""
        priority = guardian_report_number(item.get("p"))
        actions.append({"p": min(3, max(1, int(priority))) if priority is not None else 3, "action": action,
                        "owner": guardian_report_enum(item.get("owner"), GUARDIAN_REPORT_OWNERS, "analyst"),
                        "approval": item.get("approval") not in (False, "false", "no", 0), "cmd": command})
    gaps = [guardian_report_clip(gap, limits["gap"]) for gap in (obj.get("gaps") if isinstance(obj.get("gaps"), list) else [])
            if guardian_report_clip(gap, limits["gap"])]
    return {"findings": findings[:GUARDIAN_REPORT_CAPS["findings"]], "actions": actions[:GUARDIAN_REPORT_CAPS["actions"]],
            "gaps": gaps[:GUARDIAN_REPORT_CAPS["gaps"]]}


def guardian_report_scrub(value):
    """Secrets masked in every string of the report (identifiers kept)."""
    if isinstance(value, str):
        return guardian_scrub_secrets(value, keep_identifiers=True)
    if isinstance(value, list):
        return [guardian_report_scrub(item) for item in value]
    if isinstance(value, dict):
        return {key: guardian_report_scrub(item) for key, item in value.items()}
    return value


def guardian_report_cited(report):
    ids = []
    for key in ("entities", "edges", "attack", "timeline", "tree", "findings"):
        for item in report.get(key) or []:
            for ref in item.get("ref") or []:
                if ref not in ids:
                    ids.append(ref)
    return ids


def guardian_report_unverified(report):
    return sum(1 for key in ("entities", "edges", "attack", "timeline", "tree", "findings")
               for item in report.get(key) or [] if not item.get("ref"))


# --- the run -----------------------------------------------------------------------------------------------------

def guardian_report_generate(inp, prompts, max_calls, call_llm, charge, run_id="", tick=None, clock=time.time, now=None,
                             fingerprint=None, halted=None):
    """The three group calls, validation and merge. Pure apart from `call_llm(messages)`, `charge(turn)` and `halted()` (the
    kill switch, read before every call after the first), which tests replace.

    :return: the `Guardian.Report` record. It never raises: a failing group is recorded in ``errors`` and the others go on.
    """
    started = clock()
    errors, calls, tokens, cost, model = [], 0, 0, 0.0, ""
    report, entities, stopped = {}, [], False
    if not inp.get("fits", True):
        errors.append("the fixed text of the prompts ({:,} characters) does not fit the run's input budget ({:,} characters); "
                      "no model call was made".format(inp.get("fixed_chars", 0), inp.get("budget_chars", 0)))
        max_calls = 0
    for group in GUARDIAN_REPORT_GROUPS[:max_calls]:
        if stopped:
            break
        keys = GUARDIAN_REPORT_GROUP_KEYS[group]
        try:
            messages = guardian_report_messages(prompts, group, inp, inp["evidence_text"],
                                                [{"id": e["id"], "type": e["type"], "value": e["value"]} for e in entities]
                                                if group != "core" else None)
            obj = None
            for attempt in (0, 1):
                if calls and halted is not None and halted():
                    errors.append("{}: the kill switch is on, so the remaining calls were not made".format(group))
                    stopped = True
                    break
                calls += 1
                turn = call_llm(messages)
                usage = turn.get("usage") if isinstance(turn.get("usage"), dict) else {}
                tokens += int(guardian_report_number(usage.get("total_tokens"))
                              or (guardian_report_number(usage.get("prompt_tokens")) or 0)
                              + (guardian_report_number(usage.get("completion_tokens")) or 0))
                cost += charge(turn)
                model = turn.get("model") or model
                if not turn.get("ok"):
                    errors.append("{}: model call failed: {}".format(group, guardian_scrub_secrets(str(turn.get("error")))[:GUARDIAN_REPORT_ERROR_MAX_CHARS]))
                    break
                obj = guardian_report_extract_json(turn.get("content"), keys)
                if obj is not None:
                    break
                if attempt == 0:
                    messages = messages + [
                        {"role": "assistant", "content": str(turn.get("content") or "")[:GUARDIAN_REPORT_REPAIR_REPLY_MAX_CHARS]},
                        {"role": "user", "content": prompts["repair"]}]
                else:
                    errors.append("{}: the reply held no usable JSON, even after one repair request".format(group))
            if obj is None or stopped:
                continue
            if group == "core":
                part, dropped = guardian_report_normalize_core(obj, inp)
                entities = part["entities"]
                if dropped:
                    errors.append("core: {} entit{} not found in the evidence or the conclusion, dropped".format(
                        dropped, "y" if dropped == 1 else "ies"))
            elif group == "story":
                part = guardian_report_normalize_story(obj, inp, entities)
            else:
                part = guardian_report_normalize_close(obj, inp)
            report.update(part)
        except Exception as exc:  # a group must never take the others down
            errors.append("{}: {}".format(group, guardian_scrub_secrets(str(exc))[:GUARDIAN_REPORT_ERROR_MAX_CHARS]))
    built = None
    if report:
        built = {"v": GUARDIAN_REPORT_VERSION}
        built.update(inp["verdict"])
        built["severity"] = inp["recorded_severity"]
        built.update(report)
        built = guardian_report_scrub(built)
    refs = {}
    if built:
        evidence = {ev["id"]: ev for ev in inp["evidence"]}
        for ref in guardian_report_cited(built):
            refs[ref] = {"tool": guardian_report_clip(evidence[ref]["tool"], GUARDIAN_REPORT_LIMITS["ref_tool"]),
                         "summary": guardian_scrub_secrets(guardian_report_clip(evidence[ref]["args"], GUARDIAN_REPORT_LIMITS["ref_summary"]),
                                                           keep_identifiers=True)}
    return {"v": GUARDIAN_REPORT_VERSION, "run_id": str(run_id), "tick": tick, "fingerprint": fingerprint,
            "generated_at": now or guardian_report_iso_now(),
            "model": model, "calls": calls, "tokens": tokens, "cost_usd": round(cost, 6),
            "seconds": round(clock() - started, 1), "report": built, "refs": refs, "errors": errors}


def guardian_report_failure_record(run_id, tick, error, fingerprint=None):
    return {"v": GUARDIAN_REPORT_VERSION, "run_id": str(run_id or ""), "tick": tick, "fingerprint": fingerprint,
            "generated_at": guardian_report_iso_now(),
            "model": "", "calls": 0, "tokens": 0, "cost_usd": 0.0, "seconds": 0.0, "report": None, "refs": {},
            "errors": [guardian_scrub_secrets(str(error))[:GUARDIAN_REPORT_ERROR_MAX_CHARS]]}


def guardian_report_tool_names():
    names = []
    for item in guardian_ctx_read("ToolCatalog") or []:
        function = item.get("function") if isinstance(item, dict) else None
        if isinstance(function, dict) and isinstance(function.get("name"), str) and function["name"] not in names:
            names.append(function["name"])
    return names


def guardian_report_compacted(loop):
    if (guardian_report_number(loop.get("dropped_count")) or 0) > 0:
        return True
    return any(isinstance(m, dict) and m.get("guardian_checkpoint") for m in loop.get("messages") or [])


def guardian_report_audit(record, summary):
    """One `report_build` audit row. Never raises."""
    try:
        guardian_execute("GuardianAuditWrite", {
            "action": GUARDIAN_REPORT_ACTION, "target": record["run_id"][:200],
            "status": "ok" if record["report"] else "error", "actor": GUARDIAN_REPORT_ACTOR, "run_id": record["run_id"],
            "detail": json.dumps({
                "calls": record["calls"], "tokens": record["tokens"], "cost_usd": record["cost_usd"],
                "seconds": record["seconds"], "model": record["model"], "entities": summary["entities"],
                "techniques": summary["techniques"], "unverified": summary["unverified"], "errors": record["errors"][:6]})})
    except Exception as exc:  # the audit row must never stop the run
        demisto.error("GuardianReportBuild: audit write failed: {}".format(exc))


def guardian_report_summary(record):
    report = record.get("report") or {}
    techniques = {item.get("tech") for key in ("attack", "timeline") for item in report.get(key) or [] if item.get("tech")}
    return {"entities": len(report.get("entities") or []), "techniques": len(techniques),
            "unverified": guardian_report_unverified(report)}


def guardian_report_readable(record, summary):
    row = {"Calls": record["calls"], "Seconds": record["seconds"], "Entities": summary["entities"],
           "Techniques": summary["techniques"], "Unverified items": summary["unverified"],
           "Errors": "; ".join(record["errors"]) if record["errors"] else "none"}
    if not record["report"]:
        return tableToMarkdown("Guardian report: not built (the page shows the assessment card)", [row], headers=list(row))
    return tableToMarkdown("Guardian report", [row], headers=list(row))


def guardian_report_clear():
    """Delete `Guardian.Report`, so a report of an earlier run cannot be shown. Never raises."""
    try:
        guardian_execute("DeleteContext", {"key": "{}.{}".format(GUARDIAN_CONTEXT_NAMESPACE, GUARDIAN_REPORT_CONTEXT_KEY)})
    except Exception as exc:
        demisto.debug("GuardianReportBuild: could not clear the old report: {}".format(exc))


def guardian_report_job_source(incident):
    """The incident's `guardiantriggersource` when it names a scheduled Job (it starts with ``job:``), else ``""``."""
    source = guardian_report_dict(incident.get("CustomFields")).get("guardiantriggersource")
    source = source.strip() if isinstance(source, str) else ""
    return source if source.lower().startswith(GUARDIAN_REPORT_JOB_TRIGGER_PREFIX) else ""


def guardian_report_int(value):
    """A whole number from an int, a float or a numeric string; ``None`` otherwise (a boolean is not a tick)."""
    number = guardian_report_number(value.strip() or None) if isinstance(value, str) else guardian_report_number(value)
    return int(number) if number is not None and number == int(number) else None


def guardian_report_run_all():
    """Read the run, build the report, write `Guardian.Report`, audit and note. Returns the readable note."""
    settings = guardian_report_read_settings()
    incident = guardian_report_dict(demisto.incident())
    if not settings["enabled"]:
        guardian_report_clear()
        return "Guardian report: turned off (`report_enabled` is false in `guardian_settings`). No report was built."
    job = guardian_report_job_source(incident)
    if job:
        guardian_report_clear()
        return ("Guardian report: skipped, this run was started by a scheduled Job ({}), which covers the whole queue and has "
                "no single incident to report on. No model call was made.".format(guardian_report_clip(job, 40)))
    if guardian_report_kill_switch_on():
        guardian_report_clear()
        return "Guardian report: the kill switch is on, so no model call was made and no report was built."
    loop = guardian_report_dict(guardian_ctx_read("Loop"))
    run_id = str(loop.get("run_id") or incident.get("id") or "")
    tick = guardian_report_int(loop.get("tick"))
    fingerprint = loop.get("last_assistant_fingerprint") if isinstance(loop.get("last_assistant_fingerprint"), str) else None
    if not loop:
        record = guardian_report_failure_record(run_id, tick, "there is no Guardian.Loop run state in this incident's context")
    else:
        prompts, _source = guardian_report_load_prompts()
        archive = guardian_report_load_archive(run_id, tick, guardian_report_compacted(loop), loop.get("session_id"))
        inp = guardian_report_inputs(incident, loop, guardian_report_dict(guardian_ctx_read("Triage")),
                                     guardian_report_dict(guardian_ctx_read("TriageApply")), guardian_report_tool_names(),
                                     archive, prompts)
        params = guardian_report_dict(loop.get("model_params"))
        routed = params.get("model") if params.get("routed") is True and not loop.get("model_route_dropped") else None
        routed = routed.strip() if isinstance(routed, str) and routed.strip() else None
        record = guardian_report_generate(
            inp, prompts, settings["max_calls"], lambda messages: guardian_report_call_llm(messages, routed),
            lambda turn: guardian_report_charge(turn, run_id), run_id=run_id, tick=tick,
            fingerprint=fingerprint, halted=guardian_report_kill_switch_on)
    demisto.setContext("{}.{}".format(GUARDIAN_CONTEXT_NAMESPACE, GUARDIAN_REPORT_CONTEXT_KEY), record)
    summary = guardian_report_summary(record)
    guardian_report_audit(record, summary)
    return guardian_report_readable(record, summary)


def main():
    try:
        note = guardian_report_run_all()
    except Exception as exc:  # never raise: the page falls back to the assessment card
        demisto.error("GuardianReportBuild: failed: {}".format(exc))
        record = guardian_report_failure_record("", None, exc)
        try:
            incident = guardian_report_dict(demisto.incident())
            loop = guardian_report_dict(guardian_ctx_read("Loop"))
            record["run_id"] = str(loop.get("run_id") or incident.get("id") or "")
            record["tick"] = guardian_report_int(loop.get("tick"))
            demisto.setContext("{}.{}".format(GUARDIAN_CONTEXT_NAMESPACE, GUARDIAN_REPORT_CONTEXT_KEY), record)
        except Exception as inner:
            demisto.error("GuardianReportBuild: could not write the failure record: {}".format(inner))
        note = "Guardian report: not built ({}). The page shows the assessment card.".format(record["errors"][0])
    return_results(CommandResults(readable_output=note))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
