"""GuardianProbeModel -- `!guardian-probe-model`, an operator command that EMPIRICALLY calibrates the
enabled Guardian LLM provider by probing it through `guardian-llm-chat` (provider-agnostic, exactly
like the reasoning tick -- so it works for Guardian Vertex / Cohere / any future provider with no
per-integration code). It reports, so the operator can make an INFORMED choice of the
`guardian_settings.max_input_tokens` budget instead of guessing:

  1. **Tokens-per-char ratio** -- from the provider's own reported `usage.prompt_tokens` (a two-point
     calibration that cancels fixed prompt overhead). This corrects the `chars/4` estimate, which
     undercounts tool-schema/JSON content (a small model can pack closer to chars/2.9).
  2. **Effective context window** -- a search using a needle-recall test AND a `prompt_tokens`
     truncation-plateau signal, so it works for providers that silently truncate (Ollama/North-style)
     AND providers that hard-error on overflow (OpenAI/Azure-style).
  3. **Capabilities** -- whether the model actually honors `tools` and `response_format`
     (fills the `guardian_settings.provider_capabilities` placeholders).
  4. A **recommended `max_input_tokens`** = floor((window - output_reserve) x safety_margin), where
     `output_reserve` is read live from `guardian_settings.output_reserve_tokens` (falling back to a
     built-in default only if that can't be read) so there is a single source of truth for it.

OPERATOR-ONLY, NOT AN AGENT TOOL: deliberately NOT on `guardian_tool_allowlist` -- calibrating the
model plane is an infrastructure decision, and this makes real (billable) model calls. THIS SCRIPT ITSELF
CHANGES NO AGENT BEHAVIOR: it never writes `guardian_settings` or `guardian_model_profile`. It
appends one best-effort history record per run to `guardian_model_calibration` (see that List's own
write-site comment below) and returns that record as `calibration_record`. The daily
GuardianModelAdaptation playbook then runs GuardianModelProfileUpdate, which turns a usable result into
the `guardian_model_profile` List the investigation reads (a Job task, so no approval step is involved;
the agent never writes it). Running the probe by hand changes nothing until you run
`!GuardianModelProfileUpdate` (or the Job runs).

MODEL CATALOGUE: after the warm-up, the model is looked up in `guardian_model_catalog` (documented context
limits of commonly used models; the configured name first, then the model the provider reported). A
documented closed frontier model (`probe: skip`) gets NO window search unless `force=true`: only the
characters per token and the capability checks are measured, and the result is marked so that
GuardianModelProfileUpdate saves a `documented` profile. Any other known model is searched up to its
documented usable input limit (an unlisted model keeps the 131072 ceiling; `max_probe_tokens` always wins) and
the measured window is compared with the documented limit by the 20% rule (`guardian_catalog_compare`).

QUOTA, EFFORT, LATENCY: a 429 or quota error stops the search ("quota reached at N tokens, not a context limit")
and is never counted as a context limit. Every call asks for the lowest reasoning effort (`low`), retrying once
without the parameter if a provider rejects it. A size is too slow only when its first response exceeds the
model's own small-prompt time plus the latency budget, so a reasoning model's fixed thinking delay is not
slowness.

WARM-UP: a model server that unloads idle models (Ollama does) pays its load time inside the first
call, and a small context window measured that way would shrink the budgets for a whole day. The probe
makes one throwaway call first (`warm_up`, default true) so the measured calls see a loaded model.

LATENCY, NOT JUST CORRECTNESS: the window probe's pass predicate requires BOTH a correct needle
recall AND a first response within `max_response_seconds` (read live from the enabled provider
instance's own configured request timeout, safety-margined -- see
`_guardian_probe_resolve_max_response_seconds`). A prompt size can be within the model's real context
window (it recalls correctly) yet still be operationally useless if the hardware serving it is too
slow to answer within Guardian's own tick budget. This is reported as a DISTINCT
`correctness_window` (an opportunistic lower bound, not a rigorously searched ceiling) vs
`latency_bounded_window` (the number that actually matters for `max_input_tokens`), so a
"speed-limited, not context-limited" deployment is diagnosed as such rather than silently reported as
merely small.
"""

import json
import re
import time

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

# <GUARDIAN_CATALOG>
# ---------------------------------------------------------------------------
# Documented model limits: helpers over the `guardian_model_catalog` List.
#
# CANONICAL SOURCE: scripts/guardian_catalog_block.py. This block is copied verbatim, between its two
# marker lines, into GuardianModelProfileCheck, GuardianProbeModel, GuardianModelProfileUpdate and
# GuardianModelCommand in BOTH packs (scripts cannot import one another). Edit it ONLY in the canonical
# file, then run `python3 scripts/sync_catalog_block.py`; a parity test fails if any copy differs.
#
# Everything here is pure (no I/O). The lookup itself (`guardian_catalog_lookup`, `guardian_catalog_load`,
# `guardian_catalog_configured_model`, `guardian_catalog_parse`) lives in GuardianCommon, because the run
# resolves the model's size class from the catalogue in every script that reads the model numbers, not only
# in these four; this block builds on it. The List is pack-seeded data, like `guardian_pricing`: it is only
# ever read. The block uses the standard library only and carries no platform wording, so it stays identical
# in both packs.
# ---------------------------------------------------------------------------
import re

#: What a model's characters-per-token is assumed to be when it has not been measured. This is
#: deliberately conservative (lower than the 4.0 the loop's own estimator assumes): SOC content is
#: JSON-heavy and tokenises densely. The recommended budget is scaled by (chars per token / 4) so that the
#: loop's chars/4 estimate stays under the real window; at an assumed 4.0 the budget would overflow the
#: window for any tokenizer that packs below about 3.4 characters per token. A documented or confirmed
#: budget never uses a measured ratio ABOVE this value: the probe measures English prose (a gpt-5 model
#: gives about 4.6), but the loop's real content is JSON-heavy, so a prose ratio would put the real token
#: count over the documented limit.
GUARDIAN_CATALOG_ASSUMED_CHARS_PER_TOKEN = 3.0
#: The headroom factor applied to the usable input limit (the same 0.85 the probe uses).
GUARDIAN_CATALOG_SAFETY_MARGIN = 0.85
#: The characters per token the loop's own estimator assumes (chars / 4).
GUARDIAN_CATALOG_ESTIMATOR_CHARS_PER_TOKEN = 4.0
#: A measured window at or above this share of the documented usable input limit confirms the documented
#: figure; below it the measured figure wins (the "20% rule").
GUARDIAN_CATALOG_CONFIRM_SHARE = 0.8
#: The Guardian integration (spaces, case and punctuation ignored) -> the cloud platform whose provider
#: limits row applies to it. Any other integration, including a self-hosted one, has no platform.
GUARDIAN_CATALOG_PLATFORMS = {"guardianfoundry": "azure-foundry", "guardianvertex": "vertex"}


def _guardian_catalog_positive(value):
    """``int(value)`` when it is a real positive number (not a bool), else ``None``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = int(value)
    return number if number > 0 else None


def guardian_catalog_platform(integration_brand):
    """The cloud platform whose provider limits apply to a Guardian integration: GuardianFoundry ->
    ``azure-foundry``, GuardianVertex -> ``vertex``; anything else (GuardianCohere is self-hosted) -> ``None``."""
    key = re.sub(r"[^a-z0-9]", "", str(integration_brand or "").lower())
    return GUARDIAN_CATALOG_PLATFORMS.get(key)


def _guardian_catalog_provider_row(model, platform, name):
    """The provider row to apply: one whose versions include ``name``, else the first row with no versions."""
    rows = [row for row in (model.get("provider_limits") or []) if isinstance(row, dict) and row.get("provider") == platform]
    candidates = _guardian_catalog_candidates(name)
    for row in rows:
        versions = [str(v).lower() for v in (row.get("versions") or [])]
        if versions and any(candidate in versions for candidate in candidates):
            return row
    for row in rows:
        if not row.get("versions"):
            return row
    return None


def guardian_catalog_limits(model, platform, name=None):
    """The documented limits to use for ``model`` on ``platform``.

    The provider's row for that platform when there is one, else the vendor's figures. A row that
    describes a different release of the model (it lists ``versions``) applies only when ``name`` is one
    of those ids, so pass the name that was matched.

    :return: ``{"context_window", "max_input_tokens", "max_output_tokens", "basis", "managed"}``.
        ``basis`` is ``"<platform> cap"`` (for example ``"azure-foundry cap"``) or ``"vendor"``; ``managed``
        is ``True`` when a provider row matched. ``None`` when ``model`` is not a dict.
    """
    if not isinstance(model, dict):
        return None
    row = _guardian_catalog_provider_row(model, platform, name) if platform else None
    source = row if row is not None else model
    return {
        "context_window": _guardian_catalog_positive(source.get("context_window")),
        "max_input_tokens": _guardian_catalog_positive(source.get("max_input_tokens")),
        "max_output_tokens": _guardian_catalog_positive(source.get("max_output_tokens")),
        "basis": "{} cap".format(platform) if row is not None else "vendor",
        "managed": row is not None,
    }


def guardian_catalog_usable_input(limits, output_reserve):
    """The documented usable input limit, in REAL tokens, or ``None`` when no figure is known.

    ``min(max_input_tokens, context_window - output_reserve)`` when both are known; ``max_input_tokens``
    when only that is; ``context_window - output_reserve`` when only the window is.
    """
    limits = limits if isinstance(limits, dict) else {}
    window = _guardian_catalog_positive(limits.get("context_window"))
    max_input = _guardian_catalog_positive(limits.get("max_input_tokens"))
    reserve = _guardian_catalog_positive(output_reserve) or 0
    if window and max_input:
        usable = min(max_input, window - reserve)
    elif max_input:
        usable = max_input
    elif window:
        usable = window - reserve
    else:
        usable = None
    return usable if usable is not None and usable > 0 else None


def _guardian_catalog_budget_from_usable(usable, chars_per_token, safety_margin, cap):
    """``(budget, cpt_used, cpt_source, capped)`` for one DOCUMENTED usable input limit, in the loop's chars/4
    units. The ratio used is ``min(measured, assumed)``: a measured ratio only ever lowers the budget (see
    :data:`GUARDIAN_CATALOG_ASSUMED_CHARS_PER_TOKEN`); ``cpt_source`` is ``"measured"`` only when the measured
    ratio was the lower one."""
    cpt = chars_per_token if isinstance(chars_per_token, (int, float)) and not isinstance(chars_per_token, bool) \
        and chars_per_token > 0 else None
    cpt_source = "measured" if cpt is not None and cpt < GUARDIAN_CATALOG_ASSUMED_CHARS_PER_TOKEN else "assumed"
    if cpt is None or cpt >= GUARDIAN_CATALOG_ASSUMED_CHARS_PER_TOKEN:
        cpt = GUARDIAN_CATALOG_ASSUMED_CHARS_PER_TOKEN
    budget = None
    capped = False
    if usable:
        budget = int(usable * safety_margin * (cpt / GUARDIAN_CATALOG_ESTIMATOR_CHARS_PER_TOKEN))
        cap_value = _guardian_catalog_positive(cap)
        if cap_value is not None and budget > cap_value:
            budget, capped = cap_value, True
    return budget, cpt, cpt_source, capped


def guardian_catalog_documented_budget(limits, output_reserve, chars_per_token, cap=None,
                                       safety_margin=GUARDIAN_CATALOG_SAFETY_MARGIN):
    """The input budget the loop should use for a documented model, in the loop's own units.

    A profile's ``max_input_tokens`` is not a count of real tokens: the loop compares it with its own
    chars/4 estimate. So this uses the probe's formula, ``(window - output_reserve) x safety x (cpt / 4)``,
    where the usable input limit stands in for ``window - output_reserve``.

    :param limits: :func:`guardian_catalog_limits`'s result.
    :param output_reserve: Tokens kept free for the answer.
    :param chars_per_token: The measured ratio, or ``None``. The ratio used is the lower of this and the
        conservative assumed one (3.0).
    :param cap: Optional ``guardian_settings.max_input_tokens_cap`` (unset by default); limits the budget.
    :return: ``{"budget", "usable_input_tokens", "output_reserve", "chars_per_token",
        "chars_per_token_source", "safety_margin", "cap", "capped"}``; ``budget`` is ``None`` when the
        limits give no usable input figure.
    """
    usable = guardian_catalog_usable_input(limits, output_reserve)
    budget, cpt, cpt_source, capped = _guardian_catalog_budget_from_usable(usable, chars_per_token, safety_margin, cap)
    return {
        "budget": budget,
        "usable_input_tokens": usable,
        "output_reserve": _guardian_catalog_positive(output_reserve) or 0,
        "chars_per_token": round(cpt, 3),
        "chars_per_token_source": cpt_source,
        "safety_margin": safety_margin,
        "cap": _guardian_catalog_positive(cap),
        "capped": capped,
    }


def guardian_catalog_documented_trusted(catalog_entry):
    """May a model's documented window stand in for what is served? Yes for a model that needs no probe (a
    closed frontier model) and for one the provider's own cap row covers; no for a self-hosted open-weight
    model, whose served window depends on the runtime. ``catalog_entry`` is the probe's ``catalog`` dict."""
    entry = catalog_entry if isinstance(catalog_entry, dict) else {}
    return entry.get("probe") == "skip" or bool((entry.get("limits") or {}).get("managed"))


def guardian_catalog_compare(documented_input_real_tokens, probe_result, safety_margin=GUARDIAN_CATALOG_SAFETY_MARGIN,
                             cap=None, documented_trusted=True):
    """The 20% rule: weigh a probe against the documented usable input limit, like with like.

    The probe's measured window (``latency_bounded_window``, real tokens) is compared with the documented
    usable input limit (real tokens), never with a recommended budget.

    - ``confirmed``: the measured window is at least 80% of the documented limit, or the probe reached its
      ceiling. The documented-derived budget is used (with the lower of the measured and the assumed
      characters per token), but never above the probe's own recommendation when it has one: the window it
      measured may be smaller than the documented one.
    - ``measured``: the measured window is below 80% (or the search ran out of time below it). The
      probe's recommended budget is used, with an evidence line.
    - ``quota``: the probe stopped on a tokens-per-minute quota error. The window was not contradicted, so
      the documented-derived budget is used, but only when ``documented_trusted`` (the model needs no probe,
      or the provider's own cap applies). For a self-hosted model the served window is unknown: the verdict is
      then ``measured``, the budget is the probe's recommendation from the largest size that answered (``None``
      when none did), and the evidence names the quota stop.
    - No documented figure (an unknown model): the probe's recommendation, verdict ``measured``.

    :param documented_input_real_tokens: :func:`guardian_catalog_usable_input`'s result, or ``None``.
    :param documented_trusted: ``False`` for a self-hosted open-weight model (``probe`` is not ``skip`` and no
        provider cap applies): its documented window is not evidence of what is served.
    :param probe_result: The probe's calibration record (``latency_bounded_window``, ``at_ceiling``,
        ``truncated``, ``probe_ceiling_tokens``, ``quota_limited``, ``quota_at_tokens``,
        ``recommended_max_input_tokens``, ``chars_per_token``, ``chars_per_token_measured``,
        ``limit_evidence``).
    :return: ``{"verdict", "budget", "documented_input", "measured_window", "share", "gap_percent",
        "evidence", "chars_per_token", "chars_per_token_source", "capped"}``.
    """
    probe = probe_result if isinstance(probe_result, dict) else {}
    documented = _guardian_catalog_positive(documented_input_real_tokens)
    window = _guardian_catalog_positive(probe.get("latency_bounded_window"))
    measured_cpt = probe.get("chars_per_token") if probe.get("chars_per_token_measured") else None
    share = round(window / float(documented), 3) if documented and window else None
    gap_percent = int(round((1.0 - share) * 100)) if share is not None and share < 1.0 else 0
    recommended = _guardian_catalog_positive(probe.get("recommended_max_input_tokens"))

    def _documented_budget():
        return _guardian_catalog_budget_from_usable(documented, measured_cpt, safety_margin, cap)

    def _result(verdict, budget, evidence, cpt, cpt_source, capped):
        return {"verdict": verdict, "budget": budget, "documented_input": documented, "measured_window": window,
                "share": share, "gap_percent": gap_percent, "evidence": evidence,
                "chars_per_token": round(cpt, 3) if cpt else None, "chars_per_token_source": cpt_source,
                "capped": capped}

    quota_note = "quota (tokens-per-minute) reached at {} tokens; the window was not reached".format(
        probe.get("quota_at_tokens") or "an unknown number of")

    if documented is None or (probe.get("quota_limited") and not documented_trusted):
        cap_value = _guardian_catalog_positive(cap)
        budget = min(recommended, cap_value) if recommended and cap_value else recommended
        evidence = probe.get("limit_evidence")
        if probe.get("quota_limited"):
            evidence = quota_note + ("; the budget is sized from the largest size that answered ({} tokens)".format(window)
                                     if window else "")
        return _result("measured", budget, evidence, probe.get("chars_per_token"),
                       "measured" if probe.get("chars_per_token_measured") else "assumed",
                       bool(recommended and cap_value and recommended > cap_value))

    if probe.get("quota_limited"):
        budget, cpt, cpt_source, capped = _documented_budget()
        return _result("quota", budget, quota_note, cpt, cpt_source, capped)

    ceiling = _guardian_catalog_positive(probe.get("probe_ceiling_tokens"))
    reached_ceiling = bool(probe.get("at_ceiling")) and (ceiling is None or ceiling >= documented * GUARDIAN_CATALOG_CONFIRM_SHARE)
    if reached_ceiling or (window and window >= documented * GUARDIAN_CATALOG_CONFIRM_SHARE):
        budget, cpt, cpt_source, capped = _documented_budget()
        if recommended and budget is not None and recommended < budget:
            budget = recommended  # the window the probe measured can be smaller than the documented one
        if reached_ceiling:
            evidence = "the probe reached its ceiling of {} tokens without a failure".format(window or ceiling)
        else:
            evidence = "the measured window ({} tokens) is {}% of the documented usable input limit ({})".format(
                window, int(round(share * 100)), documented)
        return _result("confirmed", budget, evidence, cpt, cpt_source, capped)

    cap_value = _guardian_catalog_positive(cap)
    budget = min(recommended, cap_value) if recommended and cap_value else recommended
    if window is None:
        evidence = probe.get("limit_evidence") or "the probe could not determine a window"
    else:
        evidence = probe.get("limit_evidence") or "the largest size that was answered correctly and in time was {} tokens".format(window)
        if probe.get("truncated"):
            evidence += "; the search ran out of time, so this is a floor and the real window may be larger"
    cpt = probe.get("chars_per_token")
    return _result("measured", budget, evidence, cpt, "measured" if probe.get("chars_per_token_measured") else "assumed",
                   bool(recommended and cap_value and recommended > cap_value))


def guardian_catalog_record_source(record):
    """Where a profile record's figure comes from: ``documented``, ``confirmed``, ``measured`` or
    ``quota``. A record with no ``source`` (every record written before the catalogue existed) is measured."""
    source = record.get("source") if isinstance(record, dict) else None
    return source if source in ("documented", "confirmed", "quota") else "measured"


def guardian_catalog_source_label(record):
    """Short text for where a record's input budget comes from, for the "(source)" part of a report line."""
    source = guardian_catalog_record_source(record)
    if source == "documented":
        return "documented, catalogue {}".format(record.get("catalog_checked") or "date unknown")
    if source == "confirmed":
        return "confirmed by a probe, documented limit used"
    if source == "quota":
        return "documented, a probe hit a quota limit"
    return "measured"


def guardian_catalog_profile_line(record):
    """The report line that describes the active profile record, worded for where its figure comes from
    (the shared describe line says "Measured profile ... probed" whatever the source)."""
    source = guardian_catalog_record_source(record)
    model = record.get("model") or "unknown model"
    instance = record.get("instance_name") or "unknown instance"
    probed = record.get("probed_at") or "at an unknown time"
    documented = record.get("documented_input_tokens")
    window = record.get("window")
    if source == "documented":
        return "Documented profile: {} on {}, from the model catalogue checked {} ({}). No probe has run for it.".format(
            model, instance, record.get("catalog_checked") or "on an unknown date",
            (record.get("limits") or {}).get("basis") or "vendor")
    if source == "confirmed":
        return ("Confirmed profile: {} on {}, probed {}. The measured window ({}) is within 20% of the documented "
                "usable input limit ({}), so the documented limit is used.").format(model, instance, probed, window, documented)
    if source == "quota":
        return ("Documented profile, quota-limited probe: {} on {}, probed {}. The probe stopped on a "
                "tokens-per-minute quota ({}), so the documented window was not contradicted and the documented "
                "limit is used.").format(model, instance, probed, record.get("evidence") or "no detail")
    line = "Measured profile: {} on {}, probed {}.".format(model, instance, probed)
    if documented and isinstance(window, (int, float)) and window < documented:
        line += " The measured window ({:,}) is {}% below the documented usable input limit ({:,}){}.".format(
            int(window), int(round((1.0 - window / float(documented)) * 100)), documented,
            ": " + record["evidence"] if record.get("evidence") else "")
    return line


def guardian_catalog_apply_source(params, record):
    """A copy of the resolved model numbers whose ``max_input_tokens_source`` names where the record's
    figure really comes from. The resolver says "measured" for any profile record; that is wrong for a
    documented one. Other sources (override, settings) are left alone."""
    out = dict(params)
    if isinstance(record, dict) and out.get("max_input_tokens_source") == "measured":
        out["max_input_tokens_source"] = guardian_catalog_source_label(record)
    return out


def guardian_catalog_describe(params, record):
    """War Room lines for the resolved model numbers, worded for the active record's source.
    ``guardian_model_params_describe`` plus the two rewrites a documented figure needs."""
    lines = guardian_model_params_describe(guardian_catalog_apply_source(params, record))
    if isinstance(record, dict) and params.get("profile") and lines and lines[-1].startswith("Measured profile:"):
        lines[-1] = guardian_catalog_profile_line(record)
    return lines
# </GUARDIAN_CATALOG>



""" PROBE CONSTANTS """

#: Default assumption when the provider does not report usable `prompt_tokens` (matches
#: guardian_estimate_tokens' chars/4). Reported as an assumption, not a measurement, in that case.
GUARDIAN_PROBE_DEFAULT_CHARS_PER_TOKEN = 4.0

#: Two content sizes (chars) for the marginal tokens-per-char calibration. The DIFFERENCE cancels
#: fixed per-request overhead (chat template, role markers), isolating the content ratio.
GUARDIAN_PROBE_RATIO_SMALL_CHARS = 2000
GUARDIAN_PROBE_RATIO_LARGE_CHARS = 12000

#: Distinctive needle the window probe hides at the START of an oversized prompt; a truncating
#: provider drops the oldest tokens (the needle) so its absence from the reply proves overflow.
GUARDIAN_PROBE_NEEDLE = "QZX-4471-KILO-NEEDLE"

#: Below this many tokens the window is considered "definitely fits" (baseline sanity floor).
GUARDIAN_PROBE_WINDOW_FLOOR_TOKENS = 1000
#: Default ceiling for the window search of a model that is NOT in the model catalogue (arg-overridable).
#: ~128K covers Command/Claude-class windows; a larger window would report "at ceiling -- raise it". For a
#: model the catalogue knows, the default ceiling is its documented usable input limit instead.
GUARDIAN_PROBE_DEFAULT_MAX_PROBE_TOKENS = 131072
#: Max binary-search iterations (each is one billable model call).
GUARDIAN_PROBE_MAX_SEARCH_STEPS = 8
#: A provider that truncated reports far fewer prompt_tokens than we sent; below this fraction of the
#: target we treat it as a truncation plateau (i.e. the window was exceeded).
GUARDIAN_PROBE_PLATEAU_FRACTION = 0.9

#: Recommendation defaults (arg-overridable).
GUARDIAN_PROBE_DEFAULT_SAFETY_MARGIN = 0.85
GUARDIAN_PROBE_DEFAULT_OUTPUT_RESERVE = 4096
#: The chars-per-token the tick's `guardian_estimate_tokens` assumes (chars/4). The recommended
#: `max_input_tokens` is scaled by (measured / this) so the budget -- which the tick compares against
#: its OWN chars/4 estimate -- keeps the ACTUAL token count under the window even when the real
#: tokenizer packs denser than chars/4 (as tool-schema/JSON content does). No core-tick change needed.
GUARDIAN_PROBE_ESTIMATOR_ASSUMED_CHARS_PER_TOKEN = 4.0

#: Latency-budget constants. The provider-agnostic param name this reads off the enabled instance --
#: matches GuardianCohere.yml's "Request timeout (seconds)" `request_timeout` param; a provider
#: integration should use the same name for this to work unmodified.
GUARDIAN_PROBE_TIMEOUT_PARAM_NAME = "request_timeout"
#: A call that SUCCEEDS has already beaten the provider's real configured timeout (a genuine timeout
#: aborts the call client-side and lands in "failed", never "correct_slow") -- using the live value
#: VERBATIM as max_response_seconds would make correct_fast/correct_slow nearly the same set. Scale it
#: down instead, so "correct_slow" (recalled fine, but ate most of the real budget) can actually fire.
GUARDIAN_PROBE_TIMEOUT_SAFETY_FRACTION = 0.75
GUARDIAN_PROBE_MIN_MAX_RESPONSE_SECONDS = 15
#: Ceiling clamp on max_response_seconds regardless of how generous the live-configured timeout is.
#: Its job is bounding one call's budgeted worst case so it can't by itself eat the whole
#: GUARDIAN_PROBE_RUN_DEADLINE_SECONDS run budget below, independent of what the operator configured.
GUARDIAN_PROBE_MAX_MAX_RESPONSE_SECONDS = 100
#: Fallback ONLY when the live instance-param read fails outright (no enabled provider found, the
#: REST call errors, or no request_timeout param is set) -- 0.75x Guardian Vertex's own hardcoded
#: DEFAULT_TIMEOUT=120 (Vertex has no yml override at all, so there is nothing live to read), and
#: comfortably under Cohere's yml default of 200 too, so it is a safe floor for either shipped
#: provider even when the live read comes back empty.
GUARDIAN_PROBE_DEFAULT_MAX_RESPONSE_SECONDS = 90

#: Overall wall-clock budget for ONE full !guardian-probe-model run (ratio + window search +
#: capabilities), independent of any single call's own timeout. A per-call threshold alone says
#: nothing about the SUM of up to ~14 sequential guardian-llm-chat calls one run can make (2 ratio +
#: up to 10 window-search + 2 capabilities), all inside one script execution bound by XSOAR's
#: script timeout (GuardianProbeModel.yml sets no per-script override). The latency-driven search
#: below is designed to converge near the correct_fast/correct_slow boundary, so on slow hardware
#: several near-max_response_seconds calls back to back is the expected case, not a rare edge case.
#: A platform kill is not catchable and would discard the whole report AND the calibration write
#: (which only happens on a run that gets far enough to finish). The deadline check below turns
#: that into an honest, partial, still-useful "search truncated after N/M steps" result instead.
#:
#: Every call carries a hard `timeout` (:data:`GUARDIAN_PROBE_CALL_TIMEOUT_FACTOR`) and the deadline
#: check budgets with that hard bound, so a run ends by about this many seconds plus one report
#: write. The value stays below the ~300s at which an operator-run Playground command is killed.
GUARDIAN_PROBE_RUN_DEADLINE_SECONDS = 240
#: Every probe call carries a HARD per-call limit (the `guardian-llm-chat` contract's `timeout`
#: arg) of `max_response_seconds` x this factor. Above 1.0 so a correct-but-slow answer can still be
#: observed and reported as `"correct_slow"`; bounded so that one runaway call cannot outlive
#: XSOAR's own script timeout (without a per-call bound, a model that rambles on one needle call
#: is limited only by the provider's own request timeout, and XSOAR can kill the probe with no
#: report at all).
GUARDIAN_PROBE_CALL_TIMEOUT_FACTOR = 1.25
#: Headroom reserved for building the report / calibration write after the last probe call returns.
GUARDIAN_PROBE_DEADLINE_OVERHEAD_SECONDS = 10
#: Upper bound on the hard per-call `timeout` once the latency baseline is added to the allowance (see
#: :func:`_guardian_probe_hard_timeout`). It is at least the largest timeout a run without a baseline can
#: send (100 s x 1.25), so nothing changes for those runs, and it keeps the deadline arithmetic honest:
#: at least one call plus the report still fit in :data:`GUARDIAN_PROBE_RUN_DEADLINE_SECONDS`.
GUARDIAN_PROBE_MAX_HARD_CALL_SECONDS = 130

#: Every probe call asks for the lowest reasoning effort in the `guardian-llm-chat` contract
#: (docs/GUARDIAN_LLM_CHAT_CONTRACT.md: low | medium | high), so a reasoning model does not spend the
#: timing on a thinking loop. The integrations drop the parameter where the model does not support it.
GUARDIAN_PROBE_REASONING_EFFORT = "low"
#: Per-run state: the effort still being sent. A provider that rejects the parameter flips it to ``None``
#: for the rest of the run (so only one call pays for the retry). Reset at the start of every run.
_GUARDIAN_PROBE_STATE = {"reasoning_effort": GUARDIAN_PROBE_REASONING_EFFORT}

#: An error that means "the account hit a rate or quota limit" rather than "the prompt does not fit". The
#: probe sees error TEXT, not a status code. `429` is matched as a whole number so that a token count in a
#: context-length message ("... resulted in 14290 tokens") is never taken for it.
_GUARDIAN_PROBE_QUOTA_PATTERN = re.compile(
    r"\b429\b|too many requests|rate[\s_-]?limit|quota|tokens[\s_-]per[\s_-]minute", re.IGNORECASE)

#: DIAGNOSTIC HISTORY ONLY. Nothing else in this pack may read this List to change agent behavior;
#: `guardian_settings.max_input_tokens` stays manual/redeploy-gated. This is a human operator's
#: calibration history to read across runs, never a second, quieter path to the same knob.
GUARDIAN_MODEL_CALIBRATION_LIST_NAME = "guardian_model_calibration"
GUARDIAN_MODEL_CALIBRATION_NOT_FOUND_HINT = "item not found"
#: Keep the newest N records per provider:instance:model key rather than one overwritten record or an
#: unbounded list -- history is the point (an operator comparing today's probe against last month's
#: after a hardware change), but an unbounded List risks the growth problems of a large rolling List.
GUARDIAN_MODEL_CALIBRATION_MAX_HISTORY = 10
GUARDIAN_MODEL_CALIBRATION_UNKNOWN_PROVIDER = "unknown-provider"
GUARDIAN_MODEL_CALIBRATION_UNKNOWN_INSTANCE = "unknown-instance"
GUARDIAN_MODEL_CALIBRATION_UNKNOWN_MODEL = "unknown-model"

#: guardian-llm-chat is the provider-agnostic discovery marker for a "Guardian LLM provider"
#: integration (the same command GuardianModelCommand and GuardianReasoningTick use).
GUARDIAN_PROBE_LLM_CHAT_COMMAND = "guardian-llm-chat"


""" PROBE HELPERS """


def _guardian_probe_last_contents(entries):
    """Last non-None `Contents` from an executeCommand entry list (the guardian-llm-chat completion
    object)."""
    contents = None
    for entry in entries or []:
        if isinstance(entry, dict) and entry.get("Contents") is not None:
            contents = entry["Contents"]
    return contents


def _guardian_probe_instance_enabled(inst):
    """XSOAR's integration-search response carries `enabled` as the STRING "true"/"false", not a JSON
    bool."""
    value = inst.get("enabled") if isinstance(inst, dict) else None
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _guardian_probe_read_enabled_instance():
    """One `/settings/integration/search` read: the first ENABLED Guardian LLM provider instance's
    live-configured values -- brand-agnostic, discovered by which integration exposes the
    `guardian-llm-chat` command. Read ONCE per probe run and reused for everything that needs it
    (max_response_seconds' live default, the calibration record's
    provider/instance/model_tier/declared-model fields) rather than three redundant REST calls.

    Never raises. A failed search, no enabled provider instance, or a provider instance missing the
    param all just mean "nothing live to read" -- every caller of this function has an explicit,
    documented fallback for that case; this is diagnostic tooling; it must never block a probe run.

    :return: ``{"provider", "instance_name", "request_timeout", "model_tier", "declared_model"}``
        (any value may be ``None`` if that specific param wasn't set; ``declared_model`` honours the
        Foundry "Model" dropdown), or ``None`` if no enabled provider instance could be found at all.
    :rtype: ``dict`` or ``None``
    """
    result = _guardian_rest_post("/settings/integration/search", {"size": 200})
    if not result["ok"]:
        return None
    response = result["data"] if isinstance(result["data"], dict) else {}
    all_instances = response.get("instances")
    if not isinstance(all_instances, list):
        return None

    provider_brands = set()
    configurations = response.get("configurations")
    if isinstance(configurations, list):
        for conf in configurations:
            if not isinstance(conf, dict):
                continue
            script = conf.get("integrationScript") if isinstance(conf.get("integrationScript"), dict) else {}
            commands = script.get("commands") if isinstance(script.get("commands"), list) else []
            has_chat = any(
                isinstance(cmd, dict) and cmd.get("name") == GUARDIAN_PROBE_LLM_CHAT_COMMAND
                for cmd in commands
            )
            if has_chat:
                for key in ("name", "brand"):
                    brand = str(conf.get(key) or "").strip().lower()
                    if brand:
                        provider_brands.add(brand)

    for inst in all_instances:
        if not isinstance(inst, dict) or not _guardian_probe_instance_enabled(inst):
            continue
        brand = str(inst.get("brand") or "").strip().lower()
        if provider_brands:
            if brand not in provider_brands:
                continue
        elif not brand.startswith("guardian"):
            continue
        data = inst.get("data") if isinstance(inst.get("data"), list) else []
        values = {"request_timeout": None, "model_tier": None, "model": None}
        for param in data:
            if isinstance(param, dict) and param.get("name") in values:
                values[param["name"]] = param.get("value")
        # The configured model as the integration resolves it: the "Model" dropdown choice unless it is
        # the Custom option, else the free-text deployment name (the catalogue block's helper).
        configured_model = guardian_catalog_configured_model(data)
        return {
            "provider": inst.get("brand"),
            "instance_name": inst.get("name"),
            "request_timeout": values["request_timeout"],
            "model_tier": values["model_tier"],
            "declared_model": configured_model if configured_model is not None else values["model"],
        }
    return None


#: `guardian_settings` List name (the same List GuardianReasoningTick reads).
GUARDIAN_PROBE_SETTINGS_LIST_NAME = "guardian_settings"


def _guardian_probe_read_settings_output_reserve():
    """Read `guardian_settings.output_reserve_tokens`, the single source of truth for the
    output-token reserve, so the probe and the reasoning tick never use two independently hardcoded
    numbers. One `getList` read, used as the live default for `guardian_probe_run`'s
    `output_reserve` arg (an explicit arg still overrides it).

    Never raises. Any failure (List unreadable, missing, malformed, field absent/non-numeric) returns
    ``None`` -- the caller's own hardcoded fallback (:data:`GUARDIAN_PROBE_DEFAULT_OUTPUT_RESERVE`)
    covers that case; this is diagnostic tooling and must never block a probe run.

    :return: The configured `output_reserve_tokens` value, or ``None`` if unavailable.
    :rtype: ``int`` or ``None``
    """
    result = guardian_execute("getList", {"listName": GUARDIAN_PROBE_SETTINGS_LIST_NAME})
    if not result["ok"]:
        return None
    contents = _guardian_probe_last_contents(result["data"])
    if contents is None:
        return None
    try:
        parsed = json.loads(contents) if isinstance(contents, str) else contents
    except (TypeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    value = parsed.get("output_reserve_tokens")
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        return None
    return int(value)


def _guardian_probe_resolve_output_reserve(args):
    """Resolve the output-token reserve subtracted from the window before computing a recommended
    `max_input_tokens`. Priority: an explicit `output_reserve` arg (operator override) > the LIVE
    `guardian_settings.output_reserve_tokens` value (the single source of truth this field is meant
    to be -- see :func:`_guardian_probe_read_settings_output_reserve`) > the hardcoded
    fallback (only when the List read comes back empty).

    :return: ``(output_reserve, source)`` where `source` is one of ``"arg"``, ``"live"``,
        ``"fallback"``.
    :rtype: ``tuple(int, str)``
    """
    explicit = args.get("output_reserve")
    if explicit not in (None, ""):
        try:
            return max(0, int(float(explicit))), "arg"
        except (TypeError, ValueError):
            pass
    live = _guardian_probe_read_settings_output_reserve()
    if live is not None:
        return live, "live"
    return GUARDIAN_PROBE_DEFAULT_OUTPUT_RESERVE, "fallback"


def _guardian_probe_resolve_max_response_seconds(args, instance):
    """Resolve the "first response must arrive within this many seconds to count as fast" budget.

    Priority: an explicit `max_response_seconds` arg (operator override) > a safety-margined fraction
    of the enabled instance's OWN live-configured `request_timeout` > the hardcoded fallback -- never
    the live value verbatim (see :data:`GUARDIAN_PROBE_TIMEOUT_SAFETY_FRACTION`'s own docstring for
    why), and always clamped to a sane [min, max] band regardless of source.

    :param args: The command's raw `demisto.args()`.
    :type args: ``dict``
    :param instance: :func:`_guardian_probe_read_enabled_instance`'s result, or ``None``.
    :type instance: ``dict`` or ``None``
    :return: ``(max_response_seconds, source)`` where `source` is one of ``"arg"``, ``"live"``,
        ``"fallback"``.
    :rtype: ``tuple(int, str)``
    """
    explicit = args.get("max_response_seconds")
    if explicit not in (None, ""):
        try:
            return max(1, int(float(explicit))), "arg"
        except (TypeError, ValueError):
            pass

    live_timeout = (instance or {}).get("request_timeout")
    try:
        live_timeout = float(live_timeout) if live_timeout not in (None, "") else None
    except (TypeError, ValueError):
        live_timeout = None

    if live_timeout and live_timeout > 0:
        candidate = int(live_timeout * GUARDIAN_PROBE_TIMEOUT_SAFETY_FRACTION)
        candidate = max(
            GUARDIAN_PROBE_MIN_MAX_RESPONSE_SECONDS,
            min(candidate, GUARDIAN_PROBE_MAX_MAX_RESPONSE_SECONDS, int(live_timeout) - 5),
        )
        return candidate, "live"

    return GUARDIAN_PROBE_DEFAULT_MAX_RESPONSE_SECONDS, "fallback"


#: A word bank of natural SOC/English prose. The calibration/padding text is built from this (with
#: occasional JSON-ish `field:"value"` fragments) so its tokens-per-char ratio RESEMBLES Guardian's
#: real prompt content (English system prompt + JSON tool schemas + incident data) -- NOT a
#: number-heavy filler, which tokenizes ~1 char/token and would over-report density.
_GUARDIAN_PROBE_WORDS = (
    "the alert triggered on a monitored host when a process attempted to reach an external endpoint "
    "the analyst reviewed available evidence and correlated related incidents across the tenant "
    "severity was assessed from the observed behavior and the reputation of the indicators involved "
    "recommended remediation includes isolating the affected asset notifying the incident owner and "
    "documenting the findings before closing the case as resolved or a false positive after review "
    "the investigation examined authentication events network connections and endpoint telemetry to "
    "determine whether the activity represented a genuine threat or expected administrative behavior"
).split()


def _guardian_probe_padding(target_chars):
    """Deterministic, non-repetitive English/JSON-ish filler of exactly `target_chars` characters.
    Rotating word selection keeps the token stream varied (so a tokenizer can't over-compress it),
    while staying natural-language so the measured ratio reflects real Guardian content."""
    if target_chars <= 0:
        return ""
    words = _GUARDIAN_PROBE_WORDS
    n = len(words)
    parts = []
    total = 0
    i = 0
    while total < target_chars:
        if i % 17 == 0:
            piece = ' {{"field_{}": "value_{}"}} '.format(i % 97, (i * 3) % 97)  # occasional JSON shape
        else:
            piece = words[(i * 7 + i // n) % n] + (". " if i % 13 == 0 else " ")
        parts.append(piece)
        total += len(piece)
        i += 1
    return "".join(parts)[:target_chars]


def _guardian_probe_call_timeout(max_response_seconds):
    """The hard per-call `timeout` every probe call sends -- see
    :data:`GUARDIAN_PROBE_CALL_TIMEOUT_FACTOR`."""
    return int(max_response_seconds * GUARDIAN_PROBE_CALL_TIMEOUT_FACTOR + 0.999)


def _guardian_probe_effort_rejected(error_text):
    """Does this error say the provider rejected the reasoning-effort parameter? Matches only when the
    text names the parameter, so an unrelated failure is never retried."""
    text = (error_text or "").lower()
    return "reasoning_effort" in text or "reasoning effort" in text


def _guardian_probe_is_quota_error(error_text):
    """Does this error text say a rate or quota limit was hit (HTTP 429, "Too Many Requests", "rate
    limit", "quota", "tokens per minute")? That is an account limit, not a context limit."""
    return bool(error_text) and bool(_GUARDIAN_PROBE_QUOTA_PATTERN.search(str(error_text)))


def _guardian_probe_hard_timeout(allowed_seconds):
    """The hard per-call `timeout` for a call whose "fast" allowance is `allowed_seconds`: the usual 1.25x
    (:func:`_guardian_probe_call_timeout`), never more than :data:`GUARDIAN_PROBE_MAX_HARD_CALL_SECONDS`.
    The allowance is the latency budget PLUS the model's own small-prompt time, so it can exceed the
    budget; the cap keeps a slow baseline from pushing one call past the run deadline."""
    return min(_guardian_probe_call_timeout(allowed_seconds), GUARDIAN_PROBE_MAX_HARD_CALL_SECONDS)


def guardian_probe_call(messages, tools=None, tool_choice=None, response_format=None, temperature=0, timeout=None):
    """One guardian-llm-chat round-trip. Uses the reasoning tick's call path (so it hits whichever
    provider is enabled), plus the contract's per-call `timeout` when given. Returns
    ``{"ok", "completion", "error"}`` -- never raises."""
    call_args = {"messages": messages}
    effort = _GUARDIAN_PROBE_STATE.get("reasoning_effort")
    if effort:
        call_args["reasoning_effort"] = effort
    if timeout is not None:
        call_args["timeout"] = timeout
    if tools is not None:
        call_args["tools"] = tools
    if tool_choice is not None:
        call_args["tool_choice"] = tool_choice
    if response_format is not None:
        call_args["response_format"] = response_format
    if temperature is not None:
        call_args["temperature"] = temperature

    result = guardian_execute("guardian-llm-chat", call_args)
    if not result["ok"] and effort and _guardian_probe_effort_rejected(result["error"]):
        # The provider rejected the reasoning-effort parameter: retry this call once without it, and
        # send it no more for the rest of the run.
        _GUARDIAN_PROBE_STATE["reasoning_effort"] = None
        call_args.pop("reasoning_effort", None)
        result = guardian_execute("guardian-llm-chat", call_args)
    if not result["ok"]:
        return {"ok": False, "completion": None, "error": result["error"]}
    completion = _guardian_probe_last_contents(result["data"])
    if not isinstance(completion, dict):
        return {"ok": False, "completion": None, "error": "guardian-llm-chat returned no usable completion object"}
    return {"ok": True, "completion": completion, "error": None}


def _guardian_probe_prompt_tokens(completion):
    usage = completion.get("usage") if isinstance(completion, dict) else None
    pt = (usage or {}).get("prompt_tokens")
    return pt if isinstance(pt, (int, float)) else None


def _guardian_probe_reply_text(completion):
    choices = completion.get("choices") if isinstance(completion, dict) else None
    if not choices or not isinstance(choices[0], dict):
        return ""
    message = choices[0].get("message") or {}
    return message.get("content") or ""


#: Hard bound on the throwaway warm-up call (the integration still caps it at the instance timeout).
GUARDIAN_PROBE_WARM_UP_MAX_SECONDS = 90


def guardian_probe_warm_up(timeout_seconds=GUARDIAN_PROBE_WARM_UP_MAX_SECONDS):
    """One tiny throwaway call so a cold model is loaded before anything is measured. Never raises;
    a failed warm-up is reported, and the measured calls then fail or succeed on their own.

    :return: ``{"ok", "seconds", "error", "model"}``; ``model`` is the model the provider reported, which
        the catalogue lookup tries after the configured name.
    """
    started = time.time()
    result = guardian_probe_call([{"role": "user", "content": "Reply with exactly: OK"}], temperature=0,
                                 timeout=timeout_seconds)
    reported_model = (result.get("completion") or {}).get("model") if isinstance(result.get("completion"), dict) else None
    return {"ok": result["ok"], "seconds": round(time.time() - started, 1), "error": result.get("error"),
            "model": reported_model}


def guardian_probe_ratio(call_timeout=None):
    """Two-point marginal tokens-per-char calibration from the provider's own `usage.prompt_tokens`.

    Also opportunistically captures an OBSERVED model identifier from these same two calls' own
    completions (`completion["model"]` -- GuardianCohere's `normalize_response` prefers the backend's
    own `meta.model` over the operator's static "Model label" param when the backend echoes one) at
    zero extra calls, for the calibration record to key off instead of trusting a label that may not
    match what actually answered.

    :return: ``{"ok", "chars_per_token", "small_tokens", "large_tokens", "observed_model",
        "small_seconds"}`` (``small_seconds`` is how long the small-prompt call took: the latency
        baseline) or ``{"ok": False, "error"}``.
    """
    small_content = _guardian_probe_padding(GUARDIAN_PROBE_RATIO_SMALL_CHARS) + " Reply with exactly: OK"
    large_content = _guardian_probe_padding(GUARDIAN_PROBE_RATIO_LARGE_CHARS) + " Reply with exactly: OK"
    small_started = time.time()
    small = guardian_probe_call([{"role": "user", "content": small_content}], temperature=0, timeout=call_timeout)
    small_seconds = round(time.time() - small_started, 1)
    large = guardian_probe_call([{"role": "user", "content": large_content}], temperature=0, timeout=call_timeout)
    if not small["ok"] or not large["ok"]:
        return {"ok": False, "error": "ratio probe call failed: {}".format(small.get("error") or large.get("error"))}
    ts = _guardian_probe_prompt_tokens(small["completion"])
    tl = _guardian_probe_prompt_tokens(large["completion"])
    observed_model = (small["completion"] or {}).get("model") or (large["completion"] or {}).get("model")
    if ts is None or tl is None or tl <= ts:
        return {"ok": False, "error": "provider did not report usable prompt_tokens; cannot calibrate the ratio",
                "observed_model": observed_model, "small_seconds": small_seconds}
    delta_chars = GUARDIAN_PROBE_RATIO_LARGE_CHARS - GUARDIAN_PROBE_RATIO_SMALL_CHARS
    chars_per_token = delta_chars / float(tl - ts)
    return {"ok": True, "chars_per_token": chars_per_token, "small_tokens": ts, "large_tokens": tl,
            "observed_model": observed_model, "small_seconds": small_seconds}


def _guardian_probe_looks_like_timeout(error_text):
    """A narrow, timeout-SPECIFIC check -- deliberately not the broader `retryable` classification
    (:func:`_guardian_classify_error_text`), which also covers rate limits and 502/503/504: those are
    real call failures but not evidence the MODEL itself is too slow, and conflating them would mislabel
    a rate-limited probe as a hardware-speed finding."""
    text = (error_text or "").lower()
    return "timed out" in text or "timeout" in text


def _guardian_probe_window_fits(target_tokens, chars_per_token, max_response_seconds):
    """Does a ~`target_tokens` prompt get answered CORRECTLY and WITHIN BUDGET?

    Two different root causes can make a size unusable: "the model can't correctly process this much
    content" (a context-window limit) and "the model processes it fine but the hardware is too slow
    to answer in time" (a latency limit). An operator needs to know WHICH one they hit: the first
    means shrink the prompt; the second means faster hardware or a longer configured timeout, and
    shrinking the prompt won't help at all. So there are three outcomes rather than one boolean:

      - ``"correct_fast"``: needle recalled, not truncation-plateaued, elapsed <= max_response_seconds.
      - ``"correct_slow"``: needle recalled, not plateaued, but elapsed > max_response_seconds -- the
        model handles this size correctly but too slowly; distinct from a genuine failure.
      - ``"failed"``: needle not recalled, OR truncation-plateaued, OR the call itself errored
        (including a client-side timeout abort once `request_timeout` is exceeded -- `elapsed` in that
        case reflects how long the ABORT took to fire, not a real generation time).

    :param max_response_seconds: The elapsed-seconds threshold separating "fast" from "slow".
    :type max_response_seconds: ``int`` or ``float``
    :return: ``(outcome, error, prompt_tokens, elapsed_seconds, timeout_suspected)``.
    :rtype: ``tuple(str, str or None, number or None, float, bool)``
    """
    pad_chars = int(max(0, target_tokens * chars_per_token))
    content = (
        "SECRET PASSPHRASE: {}. Remember this passphrase. ".format(GUARDIAN_PROBE_NEEDLE)
        + _guardian_probe_padding(pad_chars)
        + " END OF LOG. Ignore every log line above. What was the SECRET PASSPHRASE stated at the very "
        "beginning, before the logs? Reply with ONLY that passphrase (one word) and nothing else."
    )
    t0 = time.time()
    r = guardian_probe_call([{"role": "user", "content": content}], tool_choice="none", temperature=0,
                            timeout=_guardian_probe_hard_timeout(max_response_seconds))
    elapsed = time.time() - t0
    if not r["ok"]:
        # A context-length hard error (OpenAI/Azure), a client-side request_timeout abort, or any
        # other call failure -> "failed". `timeout_suspected` flags the abort case specifically so the
        # caller can distinguish "the model got it wrong" from "we never even found out" in narration.
        return "failed", r.get("error"), None, elapsed, _guardian_probe_looks_like_timeout(r.get("error"))
    completion = r["completion"]
    pt = _guardian_probe_prompt_tokens(completion)
    reply = _guardian_probe_reply_text(completion) or ""
    recalled = GUARDIAN_PROBE_NEEDLE in reply
    plateaued = pt is not None and pt < target_tokens * GUARDIAN_PROBE_PLATEAU_FRACTION
    if not recalled or plateaued:
        return "failed", None, pt, elapsed, False
    outcome = "correct_fast" if elapsed <= max_response_seconds else "correct_slow"
    return outcome, None, pt, elapsed, False


def guardian_probe_window(chars_per_token, max_probe_tokens, max_response_seconds, deadline_check=None):
    """Search the LATENCY-BOUNDED effective context window: the largest size that recalls the
    needle correctly AND responds within `max_response_seconds` (`"correct_fast"`). This is the
    operationally-real number `max_input_tokens` should be based on.

    A quota error (HTTP 429, "rate limit", "quota", "tokens per minute") at any size stops the search with
    ``quota_limited`` and ``quota_at_tokens`` set: it says nothing about the window. The result then
    reports the largest size that was answered.

    Search order: confirm the floor, then GALLOP UP -- double the size after every success -- until
    the first failure or the ceiling, then bisect between the last success and that failure.
    Successes are cheap (a short correct answer); failures past the real window are the expensive
    case (a truncating provider drops the needle and the model answers at length). Galloping pays
    for one such failure before bisecting, and when the budget runs out, the confirmed floor it
    reports is already close to the answer.

    Every probed point -- the floor check, the ceiling check, and every bisection step -- goes through
    one uniform `_probe()` closure that appends to `steps`, so a caller deriving a separate
    correctness-window estimate from `steps` afterwards (see `guardian_probe_run`) sees the COMPLETE
    set of calls actually made, including the floor/ceiling boundary checks.

    :param max_response_seconds: Passed straight through to :func:`_guardian_probe_window_fits`. It is the
        ALLOWED first-response time: the run adds the model's own small-prompt time to the latency
        budget, so a reasoning model's fixed thinking delay is not counted as slowness.
    :type max_response_seconds: ``int`` or ``float``
    :param deadline_check: Optional zero-arg callable returning ``False`` once the overall probe run's
        wall-clock budget (:data:`GUARDIAN_PROBE_RUN_DEADLINE_SECONDS`) is exhausted. When it returns
        ``False`` the search stops EARLY and reports `"truncated": True` with whatever `lo` it last
        confirmed -- an honest floor, not a fully bisected value -- rather than risking an uncatchable
        platform-level kill that would discard the entire run (report AND calibration write). ``None``
        disables the check (used only by tests that don't care about the overall run budget).
    :type deadline_check: callable or ``None``
    """
    lo = GUARDIAN_PROBE_WINDOW_FLOOR_TOKENS
    hi = max(lo * 2, int(max_probe_tokens))
    steps = []

    def _probe(tokens):
        outcome, err, pt, elapsed, timeout_suspected = _guardian_probe_window_fits(
            tokens, chars_per_token, max_response_seconds
        )
        if outcome == "failed" and _guardian_probe_is_quota_error(err):
            outcome = "quota"  # an account limit, not a context limit: the search stops here
        steps.append({
            "tokens": tokens, "outcome": outcome, "prompt_tokens": pt,
            "elapsed_seconds": round(elapsed, 1), "error": err, "timeout_suspected": timeout_suspected,
        })
        return outcome

    def _quota_stopped(at_tokens, window):
        note = ("quota reached at {} tokens (tokens-per-minute limit), not a context limit; the window was "
                "not reached".format(at_tokens))
        if window is None:
            return {"ok": False, "steps": steps, "quota_limited": True, "quota_at_tokens": at_tokens, "error": note}
        return {"ok": True, "window": window, "at_ceiling": False, "steps": steps, "quota_limited": True,
                "quota_at_tokens": at_tokens,
                "note": note + "; {} tokens is the largest size that was answered.".format(window)}

    lo_outcome = _probe(lo)
    if lo_outcome == "quota":
        return _quota_stopped(lo, None)
    if lo_outcome == "correct_slow":
        # A distinct, more urgent diagnosis than "window undetermined": the model answers correctly
        # even at the smallest size probed, it is simply too slow at EVERY size -- shrinking the
        # prompt will not help at all here, unlike a genuine correctness/context-window failure.
        return {
            "ok": False, "steps": steps, "speed_limited_at_floor": True,
            "error": "recalled correctly even at the floor ({} tokens) but took longer than "
            "max_response_seconds ({}s) to do it -- this deployment is speed-limited at EVERY prompt "
            "size, not context-limited. A smaller max_input_tokens will not fix this; the fix is a "
            "longer configured request timeout or faster inference hardware.".format(lo, max_response_seconds),
        }
    if lo_outcome == "failed":
        return {
            "ok": False, "steps": steps,
            "error": "the model could not recall a needle even at {} tokens (err={}); the window probe "
            "is unreliable for this model -- rely on the provider's published context window "
            "instead.".format(lo, steps[-1]["error"]),
        }

    def _truncated(note):
        return {"ok": True, "window": lo, "at_ceiling": False, "steps": steps, "truncated": True, "note": note}

    if deadline_check is not None and not deadline_check():
        return _truncated("wall-clock budget exhausted after the floor probe; window is a confirmed "
                          "floor, not a searched value.")

    # Gallop up from the confirmed floor until the first failure (`hi`) or the ceiling.
    ceiling = hi
    hi = None
    grown = 0
    while hi is None:
        nxt = min(lo * 2, ceiling)
        if grown and deadline_check is not None and not deadline_check():
            return _truncated("wall-clock budget exhausted after growing the window {} time(s); window "
                              "is a confirmed floor, not a fully bisected value.".format(grown))
        grown += 1
        outcome = _probe(nxt)
        if outcome == "quota":
            return _quota_stopped(nxt, lo)
        if outcome != "correct_fast":
            hi = nxt
        elif nxt >= ceiling:
            return {"ok": True, "window": nxt, "at_ceiling": True, "steps": steps,
                    "note": "window is >= the probe ceiling ({}); raise max_probe_tokens to probe "
                    "higher.".format(ceiling)}
        else:
            lo = nxt

    # Bisect between the last success (`lo`) and the first failure (`hi`).
    steps_taken = 0
    for _ in range(GUARDIAN_PROBE_MAX_SEARCH_STEPS):
        if hi - lo <= max(GUARDIAN_PROBE_WINDOW_FLOOR_TOKENS, int(lo * 0.05)):
            break
        if deadline_check is not None and not deadline_check():
            return {"ok": True, "window": lo, "at_ceiling": False, "steps": steps, "truncated": True,
                    "note": "wall-clock budget exhausted after {}/{} search steps; window is a "
                    "confirmed floor, not a fully bisected value.".format(
                        steps_taken, GUARDIAN_PROBE_MAX_SEARCH_STEPS)}
        mid = (lo + hi) // 2
        outcome = _probe(mid)
        if outcome == "quota":
            return _quota_stopped(mid, lo)
        if outcome == "correct_fast":
            lo = mid
        else:
            hi = mid
        steps_taken += 1
    return {"ok": True, "window": lo, "at_ceiling": False, "steps": steps}


def _guardian_probe_deadline_check(run_start, per_call_seconds):
    """Builds the `deadline_check` callable :func:`guardian_probe_window` takes: returns ``False``
    once starting one more call (whose worst case is `per_call_seconds`, the hard per-call `timeout`
    every probe call carries) would risk exceeding :data:`GUARDIAN_PROBE_RUN_DEADLINE_SECONDS`. A single pathological call can
    overrun `max_response_seconds` by at most :data:`GUARDIAN_PROBE_CALL_TIMEOUT_FACTOR` (every call
    carries that hard per-call `timeout`), so a run cannot outlive XSOAR's script timeout.

    :return: A zero-arg callable returning ``True`` while there is still budget, ``False`` once
        starting another call would risk the deadline.
    :rtype: callable
    """
    def _check():
        elapsed = time.time() - run_start
        return elapsed + per_call_seconds + GUARDIAN_PROBE_DEADLINE_OVERHEAD_SECONDS <= GUARDIAN_PROBE_RUN_DEADLINE_SECONDS
    return _check


def guardian_probe_capabilities(call_timeout=None, deadline_check=None):
    """Probe whether the model honors `tools` and `response_format`. Best-effort booleans."""
    caps = {"tools": False, "structured_output": False, "tools_error": None, "structured_error": None}

    tool = [{
        "type": "function",
        "function": {
            "name": "get_ticket",
            "description": "Look up a support ticket by its id.",
            "parameters": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]},
        },
    }]
    r = guardian_probe_call(
        [{"role": "user", "content": "Look up ticket ABC-123 by calling the get_ticket tool."}],
        tools=tool, tool_choice="auto", temperature=0, timeout=call_timeout,
    )
    if r["ok"]:
        completion = r["completion"]
        choices = completion.get("choices") or [{}]
        message = (choices[0] or {}).get("message") or {}
        caps["tools"] = bool(message.get("tool_calls")) or completion.get("finish_reason") == "tool_calls"
    else:
        caps["tools_error"] = r.get("error")

    if deadline_check is not None and not deadline_check():
        caps["structured_error"] = "skipped: wall-clock budget exhausted after the tools check"
        return caps

    r2 = guardian_probe_call(
        [{"role": "user", "content": "Return a JSON object with a single field \"verdict\" whose value is "
                                     "the string \"benign\". Output ONLY the JSON."}],
        response_format={"type": "json_object"}, temperature=0, timeout=call_timeout,
    )
    if r2["ok"]:
        reply = _guardian_probe_reply_text(r2["completion"]) or ""
        try:
            parsed = json.loads(reply)
            caps["structured_output"] = isinstance(parsed, dict)
        except (TypeError, ValueError):
            caps["structured_output"] = False
    else:
        caps["structured_error"] = r2.get("error")
    return caps


""" MODEL CALIBRATION HISTORY (guardian_model_calibration) """


def _guardian_model_calibration_bootstrap_list():
    """Create the (missing) `guardian_model_calibration` List fresh, as an empty history object
    (`{}`), via `createList`. This script's own defensive fallback for a server where
    `GuardianBootstrap` (the primary bootstrap owner) has not been run. Called ONLY after a
    `getList` failure whose error text matches :data:`GUARDIAN_MODEL_CALIBRATION_NOT_FOUND_HINT`
    (`createList` is create-OR-OVERWRITE; calling it speculatively would risk wiping real
    accumulated history).
    """
    return guardian_execute(
        "createList", {"listName": GUARDIAN_MODEL_CALIBRATION_LIST_NAME, "listData": "{}"}
    )


def guardian_model_calibration_load():
    """Read + JSON-parse `guardian_model_calibration`'s `data` payload into a Python dict, defensively
    self-bootstrapping the List via `createList` on first use if it doesn't exist yet (getList ->
    not-found -> bootstrap -> parse/normalize).

    :return: A :func:`guardian_envelope`; ``data`` is the parsed ``{key: [record, ...]}`` dict on
        success.
    :rtype: ``dict``
    """
    result = guardian_execute("getList", {"listName": GUARDIAN_MODEL_CALIBRATION_LIST_NAME})
    if not result["ok"]:
        error_text = (result["error"] or "").lower()
        if GUARDIAN_MODEL_CALIBRATION_NOT_FOUND_HINT in error_text:
            bootstrap_result = _guardian_model_calibration_bootstrap_list()
            if not bootstrap_result["ok"]:
                return guardian_envelope(
                    False,
                    error="failed to bootstrap missing '{}': {}".format(
                        GUARDIAN_MODEL_CALIBRATION_LIST_NAME, bootstrap_result["error"]
                    ),
                    retryable=bootstrap_result["retryable"],
                )
            return guardian_envelope(True, data={})
        return guardian_envelope(
            False,
            error="failed to read '{}': {}".format(GUARDIAN_MODEL_CALIBRATION_LIST_NAME, result["error"]),
            retryable=result["retryable"],
        )

    contents = _guardian_probe_last_contents(result["data"])
    if contents is None:
        return guardian_envelope(True, data={})

    if isinstance(contents, str):
        text = contents.strip()
        if not text:
            return guardian_envelope(True, data={})
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            return guardian_envelope(
                False,
                error="NEEDS_CONTEXT: '{}' Contents is a string but not valid JSON: {}".format(
                    GUARDIAN_MODEL_CALIBRATION_LIST_NAME, exc
                ),
            )
    elif isinstance(contents, dict):
        parsed = contents
    elif isinstance(contents, list) and not contents:
        parsed = {}
    else:
        return guardian_envelope(
            False,
            error="NEEDS_CONTEXT: '{}' Contents has unexpected type {}".format(
                GUARDIAN_MODEL_CALIBRATION_LIST_NAME, type(contents).__name__
            ),
        )

    if not isinstance(parsed, dict):
        return guardian_envelope(
            False,
            error="NEEDS_CONTEXT: '{}' payload is not a JSON object".format(GUARDIAN_MODEL_CALIBRATION_LIST_NAME),
        )
    return guardian_envelope(True, data=parsed)


def guardian_model_calibration_save(history):
    """Write `history` back to `guardian_model_calibration` via `setList` -- always the FULL merged
    dict (never a single key), so a write never wipes other models'/instances' history.

    :param history: The full ``{key: [record, ...]}`` dict to persist.
    :type history: ``dict``
    :return: A :func:`guardian_envelope`.
    :rtype: ``dict``
    """
    return guardian_execute(
        "setList", {"listName": GUARDIAN_MODEL_CALIBRATION_LIST_NAME, "listData": json.dumps(history)}
    )


def _guardian_probe_server_time():
    """Get "now" from the XSOAR server for the calibration record's `timestamp` field -- never from
    this process's own clock (a Docker sandbox's wall clock is not a trustworthy substitute for the
    server's own notion of "now"). There is no incident.modified fallback: this operator-only script
    is typically run from the Playground and has no incident context.

    :return: An ISO-8601 string, or ``None`` if `GetTime` is unavailable (never fabricated locally).
    :rtype: ``str`` or ``None``
    """
    result = guardian_execute("GetTime", {"dateFormat": "ISO"})
    if result["ok"]:
        for entry in result["data"] or []:
            if isinstance(entry, dict) and isinstance(entry.get("Contents"), str) and entry["Contents"].strip():
                return entry["Contents"].strip()
    return None


def guardian_model_calibration_key(provider, instance_name, model):
    """Composite `provider:instance:model` key -- NEVER a bare model string. Two distinct real
    deployments (different provider, different instance, different configured timeout, different
    hardware) can share the same model name/label; a bare-model key would let them silently overwrite
    each other's calibration history with no way for a later reader to tell.

    :return: The composite key, with each blank/unknown component replaced by its own
        ``GUARDIAN_MODEL_CALIBRATION_UNKNOWN_*`` sentinel so a probe run with partial information
        still produces a stable, greppable key instead of silently guessing.
    :rtype: ``str``
    """
    return "{}:{}:{}".format(
        provider or GUARDIAN_MODEL_CALIBRATION_UNKNOWN_PROVIDER,
        instance_name or GUARDIAN_MODEL_CALIBRATION_UNKNOWN_INSTANCE,
        model or GUARDIAN_MODEL_CALIBRATION_UNKNOWN_MODEL,
    )


def guardian_model_calibration_record_and_save(key, record):
    """Append `record` to `key`'s history in `guardian_model_calibration`, trimming to the newest
    :data:`GUARDIAN_MODEL_CALIBRATION_MAX_HISTORY` entries, then persist the FULL history dict.

    Best-effort and never fatal to the caller: `guardian_probe_run` treats this purely as an
    informational side effect (the report + recommendation remain the primary deliverable regardless
    of whether the write succeeds).

    :param key: :func:`guardian_model_calibration_key`'s output.
    :type key: ``str``
    :param record: The calibration record dict to append.
    :type record: ``dict``
    :return: A :func:`guardian_envelope`.
    :rtype: ``dict``
    """
    load_result = guardian_model_calibration_load()
    if not load_result["ok"]:
        return load_result
    history = load_result["data"]
    bucket = history.setdefault(key, [])
    if not isinstance(bucket, list):
        bucket = []
        history[key] = bucket
    bucket.append(record)
    del bucket[:-GUARDIAN_MODEL_CALIBRATION_MAX_HISTORY]
    return guardian_model_calibration_save(history)


""" ORCHESTRATION """


def _guardian_probe_short_error(error_text, limit=160):
    """An error message squeezed onto one short line for the evidence text."""
    text = " ".join(str(error_text or "").split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def guardian_probe_limit_evidence(window_result, allowed_seconds):
    """One sentence on why the window search stopped where it did, built from its own steps. Pure.

    "past N tokens the first response took X s, above the acceptable Y s" for a size that was answered
    correctly but too slowly; "requests above N tokens failed: <short error>" for a size that errored; and
    a sentence about the prompt losing its start for a size that was answered wrongly. ``None`` when the
    search found no failing size above the window (it reached the ceiling, or ran out of time).
    """
    window = window_result.get("window") if isinstance(window_result, dict) else None
    if not window:
        return None
    above = [s for s in window_result.get("steps", [])
             if s.get("tokens", 0) > window and s.get("outcome") in ("correct_slow", "failed")]
    if not above:
        return None
    first = min(above, key=lambda s: s["tokens"])
    if first["outcome"] == "correct_slow":
        return "past {} tokens the first response took {} s, above the acceptable {} s".format(
            window, first.get("elapsed_seconds"), allowed_seconds)
    if first.get("timeout_suspected"):
        return "requests above {} tokens timed out after {} s".format(window, first.get("elapsed_seconds"))
    if first.get("error"):
        return "requests above {} tokens failed: {}".format(window, _guardian_probe_short_error(first["error"]))
    return "past {} tokens the model lost the start of the prompt (the context window was exceeded)".format(window)


def guardian_probe_catalog_match(catalog, instance, reported_models, output_reserve, measured_chars_per_token, force=False):
    """Look the enabled model up in the catalogue and work out its documented figures. Pure.

    The configured name is tried first, then each model name the provider reported (the warm-up
    completion, then the ratio calls), so a custom Foundry deployment name still matches.

    :return: ``None`` when the catalogue is missing or the model is not in it; else ``{"id", "vendor",
        "probe", "open_weight", "checked", "matched_name", "matched_by", "platform", "limits",
        "usable_input_tokens", "documented_budget", "budget_inputs", "supports_tools",
        "supports_structured_output", "skip_window_search"}``.
    """
    if not isinstance(catalog, dict):
        return None
    names = [("configured", (instance or {}).get("declared_model"))]
    names.extend(("reported", name) for name in reported_models or [])
    model, matched_name, matched_by = None, None, None
    for how, name in names:
        if isinstance(name, str) and name.strip():
            model = guardian_catalog_lookup(catalog, name)
            if model is not None:
                matched_name, matched_by = name.strip(), how
                break
    if model is None:
        return None
    platform = guardian_catalog_platform((instance or {}).get("provider"))
    limits = guardian_catalog_limits(model, platform, matched_name)
    budget = guardian_catalog_documented_budget(limits, output_reserve, measured_chars_per_token)
    usable = budget["usable_input_tokens"]
    return {
        "id": model.get("id"),
        "vendor": model.get("vendor"),
        "probe": model.get("probe"),
        "open_weight": bool(model.get("open_weight")),
        "checked": catalog.get("checked"),
        "matched_name": matched_name,
        "matched_by": matched_by,
        "platform": platform,
        "limits": limits,
        "usable_input_tokens": usable,
        "documented_budget": budget["budget"],
        "budget_inputs": {k: budget[k] for k in ("output_reserve", "chars_per_token", "chars_per_token_source",
                                                 "safety_margin")},
        "supports_tools": model.get("supports_tools"),
        "supports_structured_output": model.get("supports_structured_output"),
        # A documented frontier model needs no window search (unless `force`), but only when the
        # catalogue gives a usable input figure to rely on.
        "skip_window_search": model.get("probe") == "skip" and usable is not None and not force,
    }


def _guardian_probe_latency_baseline(warm_up, ratio_result, max_response_seconds):
    """The model's own small-prompt time, in whole seconds: the smaller of the successful small-call
    times (the warm-up, which may have absorbed a cold model load, and the small ratio call, which is
    warm), capped at the latency budget. ``0`` when neither call succeeded."""
    times = []
    if (warm_up or {}).get("ok") and isinstance(warm_up.get("seconds"), (int, float)):
        times.append(warm_up["seconds"])
    small = (ratio_result or {}).get("small_seconds")
    if isinstance(small, (int, float)) and not isinstance(small, bool) and small >= 0:
        times.append(small)
    if not times:
        return 0
    return int(round(min(min(times), max_response_seconds)))


def guardian_probe_run(args):
    """Run the full probe. Never raises -- returns ``{"ok", "data"/"error"}``.

    The run is bounded by an overall wall-clock deadline
    (:data:`GUARDIAN_PROBE_RUN_DEADLINE_SECONDS`) spanning ALL calls it makes -- see
    :func:`_guardian_probe_deadline_check` for why a per-call timeout alone isn't enough. It reads
    the enabled provider instance's own live-configured request timeout once (reused for the latency
    budget, the calibration record's provenance, and the model-tier-at-probe field), and persists one
    diagnostic history record to `guardian_model_calibration` on every run that gets far enough to
    have something worth recording.

    The model catalogue (`guardian_model_catalog`) is consulted after the warm-up: a documented
    frontier model (`probe: skip`) gets no window search unless ``force=true``; any other known model is
    searched up to its documented usable input limit and then compared with it (the 20% rule is applied
    by :func:`guardian_catalog_compare` here and again by GuardianModelProfileUpdate).
    """
    run_start = time.time()
    _GUARDIAN_PROBE_STATE["reasoning_effort"] = GUARDIAN_PROBE_REASONING_EFFORT
    explicit_ceiling = _guardian_probe_arg_int(args.get("max_probe_tokens"), None)
    force = str(args.get("force", "false")).strip().lower() in ("true", "yes", "1")
    output_reserve, output_reserve_source = _guardian_probe_resolve_output_reserve(args)
    safety_margin = _guardian_probe_arg_float(args.get("safety_margin"), GUARDIAN_PROBE_DEFAULT_SAFETY_MARGIN)

    instance = _guardian_probe_read_enabled_instance()
    max_response_seconds, max_response_seconds_source = _guardian_probe_resolve_max_response_seconds(
        args, instance
    )

    call_timeout = _guardian_probe_call_timeout(max_response_seconds)
    warm_up_arg = str(args.get("warm_up", "true")).strip().lower()
    if warm_up_arg in ("false", "no", "0"):
        warm_up = {"ok": None, "seconds": 0, "error": None, "skipped": True}
    else:
        warm_up = guardian_probe_warm_up()
    ratio_result = guardian_probe_ratio(call_timeout)
    if ratio_result["ok"]:
        chars_per_token = ratio_result["chars_per_token"]
        ratio_measured = True
    else:
        chars_per_token = GUARDIAN_PROBE_DEFAULT_CHARS_PER_TOKEN
        ratio_measured = False
    observed_model = ratio_result.get("observed_model")

    # The catalogue lookup: configured name first, then what the provider reported. An unmeasured ratio
    # is passed as None so the documented budget uses the conservative assumed one, not the probe's 4.0.
    catalog = guardian_catalog_load()
    catalog_match = guardian_probe_catalog_match(
        catalog, instance, [warm_up.get("model"), observed_model], output_reserve,
        chars_per_token if ratio_measured else None, force=force)
    skip_window_search = bool(catalog_match and catalog_match["skip_window_search"])
    if explicit_ceiling:
        max_probe_tokens, ceiling_source = explicit_ceiling, "arg"
    elif catalog_match and catalog_match["usable_input_tokens"]:
        max_probe_tokens, ceiling_source = catalog_match["usable_input_tokens"], "documented"
    else:
        max_probe_tokens, ceiling_source = GUARDIAN_PROBE_DEFAULT_MAX_PROBE_TOKENS, "default"

    # Latency is judged against the model's own small-prompt time: a reasoning model's fixed thinking
    # delay is not slowness. The allowance is the budget plus that baseline, in whole seconds.
    baseline_seconds = _guardian_probe_latency_baseline(warm_up, ratio_result, max_response_seconds)
    allowed_seconds = max_response_seconds + baseline_seconds
    window_call_timeout = _guardian_probe_hard_timeout(allowed_seconds)

    # Budget every next call with its HARD bound (call_timeout), not the softer latency threshold,
    # so no call can start that could carry the run past the deadline.
    deadline_check = _guardian_probe_deadline_check(run_start, call_timeout)
    # Capabilities run BEFORE the window search: they are two short calls, and "does this model honor
    # tools at all" matters more than the last few percent of window precision. Run last, a slow
    # model's window search could use the whole budget and leave capabilities skipped.
    if deadline_check():
        capabilities = guardian_probe_capabilities(call_timeout, deadline_check)
    else:
        capabilities = {"tools": False, "structured_output": False, "tools_error": None,
                         "structured_error": None, "skipped": True,
                         "skip_reason": "wall-clock budget exhausted before the capabilities probe could run"}
    window_deadline_check = _guardian_probe_deadline_check(run_start, window_call_timeout)
    if skip_window_search:
        window_result = {"ok": True, "window": None, "skipped": True, "steps": [],
                         "note": "no window probe needed (documented)"}
    elif window_deadline_check():
        window_result = guardian_probe_window(chars_per_token, max_probe_tokens, allowed_seconds,
                                              window_deadline_check)
    else:  # the two ratio calls alone used the budget (a pathologically slow deployment)
        window_result = {"ok": False, "steps": [], "error": "wall-clock budget exhausted by the two "
                         "tokenizer calls before the window search could start -- this deployment is too "
                         "slow to calibrate within one run; check the model host before anything else."}

    # Opportunistic lower bound, NOT a rigorously searched ceiling -- the search above bisects on the
    # LATENCY predicate, so it only visits points near that crossover; it may never visit a point large
    # enough to find where pure correctness actually fails. A real gap between this and the
    # latency-bounded `window` below is genuine signal ("this model can process more than we can serve
    # in time"), but the absolute correctness_window value itself carries less confidence than `window`
    # does -- guardian_probe_render must say so every time it reports this.
    correctness_points = [
        s["tokens"] for s in window_result.get("steps", []) if s.get("outcome") in ("correct_fast", "correct_slow")
    ]
    correctness_window = max(correctness_points) if correctness_points else None

    recommended = None
    if window_result["ok"] and window_result.get("window"):
        usable = window_result["window"] - output_reserve
        if usable > 0:
            # Scale by (measured chars/token) / (estimator's assumed chars/token). When the real
            # tokenizer is denser than chars/4, this LOWERS the budget so the tick's own chars/4
            # estimate trips compaction before the ACTUAL token count reaches the window.
            estimator_compensation = chars_per_token / GUARDIAN_PROBE_ESTIMATOR_ASSUMED_CHARS_PER_TOKEN
            recommended = int(usable * safety_margin * estimator_compensation)
        if recommended is not None and recommended < GUARDIAN_PROBE_WINDOW_FLOOR_TOKENS:
            recommended = None  # window too small / reserve too big to leave a sane input budget

    calibration_key = guardian_model_calibration_key(
        (instance or {}).get("provider"), (instance or {}).get("instance_name"),
        observed_model or (instance or {}).get("declared_model"),
    )
    calibration_record = {
        "timestamp": _guardian_probe_server_time(),
        "provider": (instance or {}).get("provider"),
        "instance_name": (instance or {}).get("instance_name"),
        "model": observed_model or (instance or {}).get("declared_model"),
        "model_source": "observed" if observed_model else "declared",
        # The instance's own "Model size" dropdown as it was set (small, medium, large or auto): display-only, not
        # the size a run uses (that comes from the catalogue, or guardian_settings, or an override).
        "model_tier_at_probe": (instance or {}).get("model_tier"),
        "request_timeout_configured": (instance or {}).get("request_timeout"),
        "max_response_seconds_used": max_response_seconds,
        "max_response_seconds_source": max_response_seconds_source,
        "latency_baseline_seconds": baseline_seconds,
        "latency_allowed_seconds": allowed_seconds,
        "latency_bounded_window": window_result.get("window"),
        "correctness_window": correctness_window,
        "at_ceiling": bool(window_result.get("at_ceiling")),
        "truncated": bool(window_result.get("truncated")),
        "speed_limited_at_floor": bool(window_result.get("speed_limited_at_floor")),
        "probe_ceiling_tokens": None if skip_window_search else max_probe_tokens,
        "probe_ceiling_source": ceiling_source,
        "quota_limited": bool(window_result.get("quota_limited")),
        "quota_at_tokens": window_result.get("quota_at_tokens"),
        "window_search_skipped": skip_window_search,
        "limit_evidence": guardian_probe_limit_evidence(window_result, allowed_seconds),
        "recommended_max_input_tokens": recommended,
        "output_reserve_used": output_reserve,
        "output_reserve_source": output_reserve_source,
        "safety_margin_used": safety_margin,
        "chars_per_token": round(chars_per_token, 3),
        "chars_per_token_measured": ratio_measured,
        "capabilities": {k: v for k, v in capabilities.items() if k in ("tools", "structured_output")},
        "capabilities_skipped": bool(capabilities.get("skipped")),
        "catalog": catalog_match,
    }
    comparison = None
    if catalog_match and not skip_window_search:
        comparison = guardian_catalog_compare(catalog_match["usable_input_tokens"], calibration_record, safety_margin,
                                              documented_trusted=guardian_catalog_documented_trusted(catalog_match))
    calibration_write = guardian_model_calibration_record_and_save(calibration_key, calibration_record)

    return {
        "ok": True,
        "data": {
            "warm_up": warm_up,
            "calibration_record": calibration_record,
            "ratio": {
                "chars_per_token": round(chars_per_token, 3),
                "measured": ratio_measured,
                "detail": ratio_result if ratio_measured else {"error": ratio_result.get("error")},
                "observed_model": observed_model,
            },
            "window": window_result,
            "correctness_window": correctness_window,
            "latency_budget": {
                "max_response_seconds": max_response_seconds,
                "source": max_response_seconds_source,
                "request_timeout_configured": (instance or {}).get("request_timeout"),
                "baseline_seconds": baseline_seconds,
                "allowed_seconds": allowed_seconds,
            },
            "ceiling": {"max_probe_tokens": max_probe_tokens, "source": ceiling_source},
            "capabilities": capabilities,
            "catalog": catalog_match,
            "comparison": comparison,
            "recommendation": {
                "max_input_tokens": recommended,
                "safety_margin": safety_margin,
                "output_reserve": output_reserve,
                "output_reserve_source": output_reserve_source,
            },
            "calibration_write": {
                "ok": calibration_write["ok"],
                "key": calibration_key,
                "error": None if calibration_write["ok"] else calibration_write.get("error"),
            },
        },
    }


def _guardian_probe_arg_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _guardian_probe_arg_float(value, default):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def guardian_probe_render(data):
    """Markdown report of one probe. Pure (no I/O)."""
    ratio = data["ratio"]
    window = data["window"]
    correctness_window = data.get("correctness_window")
    latency_budget = data.get("latency_budget") or {}
    caps = data["capabilities"]
    rec = data["recommendation"]
    calib = data.get("calibration_write") or {}
    lines = ["## Guardian model probe -- empirical calibration", ""]

    # ratio
    cpt = ratio["chars_per_token"]
    if ratio["measured"]:
        lines.append("**Tokenizer:** ~`{}` chars/token (measured from the provider's reported "
                     "prompt_tokens). The `chars/4` estimate assumes 4.0 -- if this is lower, the "
                     "estimator UNDERcounts and the transcript can overflow before compaction.".format(cpt))
    else:
        lines.append("**Tokenizer:** the provider did not report usable prompt_tokens, so this fell "
                     "back to the assumed `chars/4` (4.0). ({})".format((ratio.get("detail") or {}).get("error")))
    if ratio.get("observed_model"):
        lines.append("**Observed model:** `{}` (from the provider's own response, not the declared "
                     "integration label).".format(ratio["observed_model"]))
    lines.append("")

    warm_up = data.get("warm_up") or {}
    if warm_up.get("skipped"):
        lines.append("**Warm-up:** skipped (`warm_up=false`).")
    elif warm_up.get("ok"):
        lines.append("**Warm-up:** the throwaway call took {}s (a cold model loads here, not inside a "
                     "measurement).".format(warm_up.get("seconds")))
    else:
        lines.append("**Warm-up:** the throwaway call failed after {}s ({}); the measurements below may "
                     "include a cold start.".format(warm_up.get("seconds"), warm_up.get("error")))
    lines.append("")

    # latency budget
    lines.append("**Latency budget:** a first response counts as \"fast\" if it arrives within "
                 "`{}`s ({}).".format(
                     latency_budget.get("max_response_seconds"),
                     {"arg": "operator-supplied", "live": "0.75x the enabled instance's configured "
                      "request timeout ({}s)".format(latency_budget.get("request_timeout_configured")),
                      "fallback": "no live timeout could be read; used the built-in fallback"}.get(
                          latency_budget.get("source"), latency_budget.get("source"))))
    if latency_budget.get("baseline_seconds"):
        lines.append("The model's own small-prompt time is `{}`s, so a size counts as too slow only when its first "
                     "response takes longer than `{}`s (the budget plus that baseline). A reasoning model's fixed "
                     "thinking delay is therefore not counted as slowness.".format(
                         latency_budget.get("baseline_seconds"), latency_budget.get("allowed_seconds")))
    lines.append("")

    # the model catalogue
    catalog_match = data.get("catalog")
    if catalog_match:
        limits = catalog_match.get("limits") or {}
        lines.append("### Documented limits (model catalogue checked {})".format(catalog_match.get("checked")))
        lines.append("`{}` matched `{}` ({} name) -- {} limits ({}): context window {}, max input {}, max output {}.".format(
            catalog_match.get("id"), catalog_match.get("matched_name"), catalog_match.get("matched_by"),
            catalog_match.get("vendor"), limits.get("basis"), limits.get("context_window") or "not stated",
            limits.get("max_input_tokens") or "not stated", limits.get("max_output_tokens") or "not stated"))
        lines.append("Usable input limit (real tokens, after the {} output reserve): **{}**.".format(
            (catalog_match.get("budget_inputs") or {}).get("output_reserve"),
            catalog_match.get("usable_input_tokens") or "unknown"))
        lines.append("")
    else:
        ceiling = data.get("ceiling") or {}
        lines.append("**Model catalogue:** this model is not in `guardian_model_catalog` (or the List could not be "
                     "read), so it is probed from scratch. The search ceiling is {} tokens ({}); raise it with "
                     "`max_probe_tokens` if the window is reported as \"at ceiling\".".format(
                         ceiling.get("max_probe_tokens"), {"arg": "your max_probe_tokens", "default": "the default"}.get(
                             ceiling.get("source"), ceiling.get("source"))))
        lines.append("")

    # window (latency-bounded -- the operationally real number)
    if window.get("skipped"):
        lines.append("**Latency-bounded context window:** not searched -- no window probe needed (documented). "
                     "Pass `force=true` to probe it anyway.")
    elif window.get("quota_limited"):
        lines.append("**Latency-bounded context window: QUOTA REACHED, not a context limit.** {}".format(
            window.get("note") or window.get("error")))
    elif window["ok"]:
        approx = ">= {}".format(window["window"]) if window.get("at_ceiling") else "~{}".format(window["window"])
        truncated_note = ""
        if window.get("truncated"):
            truncated_note = (" **TRUNCATED**: the overall probe wall-clock budget ran out before the "
                              "search finished -- this is a confirmed FLOOR, not a fully bisected value; "
                              "the true window may be larger.")
        lines.append("**Latency-bounded context window:** {} tokens.{}{}".format(
            approx, " " + window["note"] if window.get("note") else "", truncated_note))
    elif window.get("speed_limited_at_floor"):
        lines.append("**Latency-bounded context window: SPEED-LIMITED, not context-limited.** {}".format(
            window.get("error")))
    else:
        lines.append("**Latency-bounded context window:** could not be determined. {}".format(window.get("error")))
    lines.append("")

    # correctness window -- only worth showing when it diverges meaningfully from the latency-bounded one
    if correctness_window is not None and window.get("ok") and window.get("window"):
        if correctness_window > window["window"] * 1.05:
            lines.append("**Correctness window (sampled lower bound, not a searched ceiling):** "
                         "~{} tokens recalled correctly regardless of speed -- this endpoint supports "
                         "MORE context than it can serve within your latency budget. Speed-limited, "
                         "not context-limited: faster hardware or a longer configured request timeout "
                         "would raise the usable window; a smaller `max_input_tokens` will not help "
                         "correctness, only latency.".format(correctness_window))
            lines.append("")

    # capabilities
    if caps.get("skipped"):
        lines.append("**Capabilities:** skipped -- {}.".format(caps.get("skip_reason")))
    else:
        lines.append("**Capabilities:** tools = `{}` | structured output (response_format) = `{}`.".format(
            "yes" if caps.get("tools") else "no", "yes" if caps.get("structured_output") else "no"))
        if caps.get("tools_error"):
            lines.append("  - tools probe error: {}".format(caps["tools_error"]))
    lines.append("")

    # documented vs measured
    comparison = data.get("comparison")
    if comparison:
        verdict_text = {
            "confirmed": "CONFIRMED -- the documented limit is used",
            "measured": "MEASURED -- the measured figure is used (it is more than 20% below the documented limit)",
            "quota": "QUOTA -- the window was not contradicted, so the documented limit is used",
        }.get(comparison["verdict"], comparison["verdict"])
        if comparison["verdict"] == "measured" and window.get("quota_limited"):
            verdict_text = ("MEASURED -- a quota stop on a model whose served window is not documented, so the budget is "
                            "sized from the largest size that answered")
        lines.append("### Documented vs measured")
        lines.append("Documented usable input limit: **{}** real tokens. Measured window: **{}**{}. Verdict: **{}**.".format(
            comparison.get("documented_input") or "unknown", comparison.get("measured_window") or "none",
            " ({}% of the documented limit)".format(int(round(comparison["share"] * 100))) if comparison.get("share") else "",
            verdict_text))
        if comparison.get("evidence"):
            lines.append("Evidence: {}.".format(comparison["evidence"]))
        lines.append("Input budget the profile would get: **{}** (in the loop's chars/4 units).".format(
            comparison.get("budget") if comparison.get("budget") is not None else "none"))
        lines.append("")
    elif catalog_match and window.get("skipped"):
        inputs = catalog_match.get("budget_inputs") or {}
        lines.append("### Documented budget")
        lines.append("Documented input budget: **{}** = floor(usable input limit {} x {} safety x ({} / 4)), with {} "
                     "characters per token ({}). `!GuardianModelProfileUpdate` saves this as a `documented` profile.".format(
                         catalog_match.get("documented_budget"), catalog_match.get("usable_input_tokens"),
                         inputs.get("safety_margin"), inputs.get("chars_per_token"), inputs.get("chars_per_token"),
                         "measured by this probe" if inputs.get("chars_per_token_source") == "measured"
                         else "assumed, because the ratio could not be measured"))
        lines.append("")

    # recommendation
    lines.append("### Recommended budget")
    if window.get("skipped"):
        lines.append("No window probe was run, so there is no probe-based recommendation; use the documented "
                     "budget above.")
    elif rec["max_input_tokens"] is not None:
        lines.append("Recommended **`max_input_tokens` = `{}`**".format(rec["max_input_tokens"]))
        lines.append("")
        lines.append("= floor((latency-bounded window - {} output reserve) x {} safety x ({}/4 "
                     "estimator compensation)). The last factor pre-corrects for the tick's `chars/4` "
                     "estimate so the ACTUAL context stays under the window even when the real "
                     "tokenizer packs denser -- no core-tick change needed.".format(
                         rec["output_reserve"], rec["safety_margin"], cpt))
        lines.append("")
        lines.append("Output reserve source: {}.".format(
            {"arg": "operator-supplied", "live": "read live from guardian_settings.output_reserve_tokens",
             "fallback": "no live value found; used the built-in fallback"}.get(
                rec.get("output_reserve_source"), rec.get("output_reserve_source"))))
        lines.append("")
        lines.append("`!GuardianModelProfileUpdate` (or the daily GuardianModelAdaptation job) saves this "
                     "to `guardian_model_profile`, which the investigation reads in preference to "
                     "`guardian_settings.max_input_tokens`. To pin a value by hand, set it under "
                     "`overrides` in that List.")
    else:
        lines.append("Could not compute a safe budget (window undetermined, or too small for the "
                     "output reserve). Consult the provider's published context window.")
    lines.append("")

    # calibration write
    if calib.get("ok"):
        lines.append("**Calibration history:** saved to `guardian_model_calibration` under key "
                     "`{}`.".format(calib.get("key")))
    else:
        lines.append("**Calibration history:** could NOT be saved ({}) -- the report above is still "
                     "valid, just not persisted for later comparison.".format(calib.get("error")))
    lines.append("")
    lines.append("> This command is OPERATOR-ONLY and makes real (billable) model calls to probe the "
                 "live provider. It changes nothing by itself: it appends one history record to "
                 "`guardian_model_calibration`. To make Guardian use the result, run "
                 "`!GuardianModelProfileUpdate` (the daily GuardianModelAdaptation job does this for "
                 "you) -- that writes `guardian_model_profile`, which the investigation reads. "
                 "`guardian_settings` is never touched. Re-run after you switch the provider/model or "
                 "change the hardware.")
    return "\n".join(lines)


def main():
    try:
        result = guardian_probe_run(demisto.args() or {})
    except Exception as ex:  # this is the automation's only entry point -- never surface a traceback
        return_error("GuardianProbeModel failed unexpectedly: {}".format(ex))
        return

    if not result["ok"]:
        return_error("GuardianProbeModel failed: {}".format(result.get("error")))
        return

    data = result["data"]
    return_results(
        CommandResults(
            readable_output=guardian_probe_render(data),
            outputs_prefix="Guardian.ModelProbe",
            outputs=data,
            raw_response=data,
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
