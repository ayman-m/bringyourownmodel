"""GuardianIssueSummary -- write Guardian's triage summary or investigation conclusion to the issue. Operator-owned: the model never calls it.

Two places, one stage at a time (the `stage` argument):

- a short War Room note, posted the way `GuardianCaseNote` posts one (`addEntries`, `Note: True`, a tag, markdown):
  "Guardian triage" or "Guardian investigation". The model's own case note stays the full report; this is the card;
- one section at the END of the issue's description, through ONE `core-update-issue` call that carries only `id` and
  `description`. The section starts at a fixed marker line (`GUARDIAN_ISSUE_SECTION_MARKER`) and holds a `Triage:` line
  and an `Investigation:` line. The text above the marker is never changed: the new description is the original text
  exactly, a blank line, and the section. A re-run replaces the section (from the marker to the end), never adds a
  second one, and a stage keeps the other stage's line when it is there. Model text is collapsed to one line, scrubbed
  of secrets and capped (`GUARDIAN_ISSUE_SUMMARY_PART_MAX_CHARS` per line, `GUARDIAN_ISSUE_SUMMARY_SECTION_MAX_CHARS`
  for the whole section). `GuardianIssueEvidence`, the issue pin of the reasoning loop and the tool bridge (every tool
  result) drop the section again, so the model never reads its own earlier conclusion back as evidence.

`stage=triage` reads `Guardian.Triage` and `Guardian.TriageApply` and skips when there is no triage result or the apply
step skipped the issue (already triaged, owned or resolved). `stage=investigation` reads the verdict or posture
assessment the reasoning loop recorded (`Guardian.Loop.verdict`) and skips when the run ended without one.

The current description is read from the platform (`core-get-issues`, the field `core-update-issue` replaces), with the
issue's own `details` or `description` as the fallback. When neither shows the text, or the platform cannot confirm an
empty one, the description is not written and the reason says so: the original text is never put at risk.

With `apply_changes=false` the text is computed and reported and nothing is written (no note, no description).

Result -- one entry per stage, returned as the command's outputs and merged by `stage`:

    Guardian.IssueSummary = {stage: triage|investigation, status: written|dry_run|skipped|error, note_posted: bool,
                             description_updated: bool, section_chars: int, reason: str}

Every outcome leaves an audit row. This script writes no name, type or status, and the model can never call it (it is on
the denylist and not on the allowlist).
"""

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

#: DBotScore integer -> label, the only four values Cortex platform's reputation model
#: defines. Anything else (out of range / not an int) maps to "Unknown".
GUARDIAN_DBOT_LABELS = {0: "Unknown", 1: "Good", 2: "Suspicious", 3: "Bad"}

#: The Go zero-value timestamp Cortex platform stores in `dueDate` when no SLA timer is
#: running. Any timestamp starting with this prefix means "no SLA", not a
#: real date in the year 1 — treat it as null or it poisons date sorts.
GUARDIAN_NO_SLA_DATE_PREFIX = "0001-01-01"

#: Context namespace every Guardian read/write lives under, so Guardian's
#: incident-scoped state can never collide with another pack's Context keys.
GUARDIAN_CONTEXT_NAMESPACE = "Guardian"

#: Cortex platform entry Type for an error War Room entry (`entryTypes['error']` in
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
    """Run a Cortex platform command via ``demisto.executeCommand`` with the Guardian
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

    :param command: The Cortex platform command / script name to run (e.g. ``"ip"``,
        ``"setIncident"``).
    :type command: ``str``
    :param args: Command arguments.
    :type args: ``dict``
    :param using: Optional integration instance name to pin the command to
        (passed through as the ``using`` arg Cortex platform recognizes).
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
    """Project a raw Cortex platform incident object down to Guardian's 9-field
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
    """Normalize a Cortex platform SLA/``dueDate`` timestamp.

    Cortex platform stores the Go zero-value ``"0001-01-01T00:00:00Z"`` in ``dueDate``
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
    """POST `body_obj` (JSON-serialized here) to Cortex platform's own REST API at
    `uri`, via the Core REST API integration.

    Tries ``demisto-api-post`` first, falling back to ``core-api-post`` only
    when the FIRST attempt's error text suggests the command itself isn't
    registered on this server (e.g. the "was not found in module" or "Unsupported Command"
    wording the server emits for an unknown or unconfigured command) or the raw
    `executeCommand` call itself raised. Any OTHER failure (an HTTP 4xx/5xx
    the API itself returned, an optimistic-lock error, an auth failure) is a
    real error that is surfaced as-is -- never masked behind a second, blind
    attempt with the other command name.

    :param uri: The Cortex platform REST path, e.g. ``"/incidents/search"``,
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


def guardian_set_incident_fields(incident_id, fields):
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
    :return: A :func:`guardian_envelope`; ``data`` on success is
        ``{"id": incident_id, "fields": fields}``.
    :rtype: ``dict``
    """
    if not incident_id:
        return guardian_envelope(False, error="guardian_set_incident_fields: missing incident_id")
    if not fields:
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
        custom_fields = incident.get("CustomFields")
        custom_fields = dict(custom_fields) if isinstance(custom_fields, dict) else {}
        custom_fields.update(fields)
        incident["CustomFields"] = custom_fields

        write_result = _guardian_rest_post("/incident", incident)
        if write_result["ok"]:
            return guardian_envelope(True, data={"id": incident_id, "fields": fields})

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


#: Prefix that marks a command argument as base64-encoded JSON (``b64:<base64 of the UTF-8 JSON text>``).
#: XSIAM (unlike Cortex platform) damages a JSON string argument that carries deeply nested backslash escapes --
#: which a tool result holding a stringified REST response does: a 58 KB ``messages`` argument failed with
#: "Expecting ',' delimiter" although the same text is valid JSON. Base64 contains no backslashes or quotes,
#: so it passes through untouched. Every consumer that parses a JSON argument accepts either form.
GUARDIAN_B64_ARG_PREFIX = "b64:"


def guardian_arg_encode(value):
    """Encode a JSON-serializable value as a ``b64:`` command argument (see GUARDIAN_B64_ARG_PREFIX)."""
    import base64  # defensive local import, like guardian_execute's json import
    import json

    raw = json.dumps(value, default=str).encode("utf-8")
    return GUARDIAN_B64_ARG_PREFIX + base64.b64encode(raw).decode("ascii")


def guardian_arg_decode(raw):
    """Decode a command argument that is either plain JSON text or a ``b64:`` argument.

    :param raw: The argument value as received (a string, or an already-parsed list/dict, which is returned as is).
    :return: The parsed value.
    :raises ValueError: when the text is not valid JSON (or valid base64 of JSON).
    """
    import base64
    import json

    if not isinstance(raw, str):
        return raw
    if raw.startswith(GUARDIAN_B64_ARG_PREFIX):
        try:
            return json.loads(base64.b64decode(raw[len(GUARDIAN_B64_ARG_PREFIX):]).decode("utf-8"))
        except Exception as exc:  # binascii.Error, UnicodeDecodeError and JSON errors alike
            raise ValueError("invalid b64 argument: {}".format(exc))
    return json.loads(raw)


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


# --- Triage block: the machine-checked answer of a triage session --------------------------------------------------
# One parser and one validator, shared by the reasoning tick (which decides whether a conclusion is accepted) and by
# GuardianTriageResult (which repairs, merges and writes the result), so the two can never disagree about what a
# valid block is. The taxonomy lives in the pack List `guardian_triage_types`; GUARDIAN_TRIAGE_DEFAULT_TYPES is the
# same data, used only when that List cannot be read (a content test keeps the two equal).

GUARDIAN_TRIAGE_LIST_NAME = "guardian_triage_types"

#: The severities `core-update-issue` accepts, lowest first.
GUARDIAN_TRIAGE_SEVERITIES = ("low", "medium", "high", "critical")

#: The investigation type that means "none of the others fits".
GUARDIAN_TRIAGE_OTHER = "other"

GUARDIAN_TRIAGE_DOMAINS = ("detection", "posture")

#: The entity lists a triage block may carry. Anything else under `key_entities` is dropped.
GUARDIAN_TRIAGE_ENTITY_KEYS = ("identities", "ips", "resources", "assets", "hosts", "hashes")
GUARDIAN_TRIAGE_ENTITY_MAX_ITEMS = 10
#: An entity longer than this is dropped, never cut off: a truncated identifier names nothing, and a lookup given one
#: reads as a clean "no entries". 512 covers a long cloud resource id (an Azure VM scale-set instance id runs past 250).
GUARDIAN_TRIAGE_ENTITY_MAX_CHARS = 512
GUARDIAN_TRIAGE_SUMMARY_MIN_CHARS = 20
GUARDIAN_TRIAGE_SUMMARY_MAX_CHARS = 300
GUARDIAN_TRIAGE_NEXT_STEP_MAX_CHARS = 300
#: The optional `analysis` (what the model saw and why it rated the issue so) and `recommendations` (short next
#: actions). A malformed or missing value is treated as absent; it never makes a block invalid.
GUARDIAN_TRIAGE_ANALYSIS_MAX_CHARS = 800
GUARDIAN_TRIAGE_RECOMMENDATION_MAX_CHARS = 200
GUARDIAN_TRIAGE_RECOMMENDATIONS_MAX_ITEMS = 5

GUARDIAN_TRIAGE_DEFAULT_TYPES = [
    {"name": "identity_threat",
     "description": "Sign-in anomaly, credential use or session abuse by a person or service identity.",
     "domains": ["detection"], "sub_playbook": "GuardianTriageIdentityThreat", "skill": "cortex_detection_investigation"},
    {"name": "cloud_change",
     "description": "A person or identity changed cloud network, IAM or storage configuration.",
     "domains": ["detection"], "sub_playbook": "GuardianTriageCloudChange", "skill": "cortex_detection_investigation"},
    {"name": "endpoint_threat",
     "description": "Malware, suspicious execution or persistence on a host.",
     "domains": ["detection"], "sub_playbook": "GuardianTriageEndpointThreat", "skill": "cortex_detection_investigation"},
    {"name": "data_exposure",
     "description": "Public or over-shared data, unusual data access or exfiltration.",
     "domains": ["detection", "posture"], "sub_playbook": "GuardianTriageDataExposure",
     "skill": {"detection": "cortex_detection_investigation", "posture": "cortex_posture_misconfiguration"}},
    {"name": "misconfiguration",
     "description": "A cloud (CSPM) or Kubernetes policy finding: a setting that is wrong.",
     "domains": ["posture"], "sub_playbook": "GuardianTriageMisconfiguration", "skill": "cortex_posture_misconfiguration"},
    {"name": "vulnerability",
     "description": "A known CVE on a host, image or package.",
     "domains": ["posture"], "sub_playbook": "GuardianTriageVulnerability", "skill": "cortex_vulnerability_triage"},
    {"name": "code_risk",
     "description": "Infrastructure-as-code, secrets or package operational risk found in code.",
     "domains": ["posture"], "sub_playbook": "GuardianTriageCodeRisk", "skill": "cortex_vulnerability_triage"},
    {"name": "excessive_privilege",
     "description": "CIEM finding: admin or unused permissions on an identity or role.",
     "domains": ["posture"], "sub_playbook": "GuardianTriageExcessivePrivilege", "skill": "cortex_identity_risk"},
    {"name": "attack_path",
     "description": "A graph attack path from an entry point to a sensitive asset.",
     "domains": ["posture"], "sub_playbook": "GuardianTriageAttackPath", "skill": "cortex_attack_path"},
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
    """``key_entities`` reduced to the six known lists of plain, bounded, de-duplicated strings. A value that is
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
    block without them is just as valid, and a malformed one is read as absent. ``key_entities`` is cleaned (see
    :func:`guardian_triage_clean_entities`). Unknown keys are dropped.

    Whether the type fits the issue's domain is NOT decided here: that is GuardianTriageResult's call, not the model's
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
    }


def guardian_triage_parse_block(text, table=None):
    """The validated triage block from `text` (the last fenced JSON block, else a bare JSON answer, else the last bare
    object that has an ``investigation_type`` key -- see :func:`guardian_triage_last_candidate`), or ``None`` (no
    such object, malformed JSON, or an invalid one -- see :func:`guardian_triage_validate`)."""
    return guardian_triage_validate(guardian_triage_last_candidate(text), table)


# --- Guardian's section of an issue's description ------------------------------------------------------------------
# GuardianIssueSummary appends one section to the end of an issue's description, behind this marker line. The evidence
# packet drops that section again (see GuardianIssueEvidence), so the model never reads Guardian's own earlier
# conclusion back as if it were evidence about the issue.

GUARDIAN_ISSUE_SECTION_MARKER = "--- Guardian (automated) ---"
#: What GuardianIssueSummary puts between the original text and the marker.
GUARDIAN_ISSUE_SECTION_GAP = "\n\n"


def guardian_split_issue_section(text):
    """``(original, section)``: the description text above the Guardian section, exactly as it was before the section
    was appended, and the section itself (the marker line to the end; empty when there is none). The gap the writer put
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
    """``value`` with Guardian's description section removed from every string in it (dicts and lists are walked, up to
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


GUARDIAN_ISSUE_SUMMARY_CONTEXT_PATH = "Guardian.IssueSummary"
GUARDIAN_ISSUE_SUMMARY_ACTOR = "operator"
GUARDIAN_ISSUE_SUMMARY_UPDATE_COMMAND = "core-update-issue"
GUARDIAN_ISSUE_SUMMARY_NOTE_TAG = "guardian-issue-summary"
GUARDIAN_ISSUE_SUMMARY_NOTE_MAX_CHARS = 3000
GUARDIAN_ISSUE_SUMMARY_STAGES = ("triage", "investigation")
GUARDIAN_ISSUE_SUMMARY_LABELS = {"triage": "Triage: ", "investigation": "Investigation: "}

#: One line of the section (the triage line or the investigation line), without its label. The two lines plus the
#: marker stay under the section limit, so one stage can never push the other's line out.
GUARDIAN_ISSUE_SUMMARY_PART_MAX_CHARS = 700
#: The whole section, marker included.
GUARDIAN_ISSUE_SUMMARY_SECTION_MAX_CHARS = 1500

#: The descriptions the platform may keep the issue's text under in the issue's own fields, first match wins.
GUARDIAN_ISSUE_SUMMARY_FIELD_NAMES = ("details", "description")

_GUARDIAN_ISSUE_SUMMARY_POSTURE_LABELS = ("exposure", "owner", "fix")


def guardian_summary_parse_flag(value):
    """The ``apply_changes`` argument: ``True`` when missing or empty (the default), ``False`` for false/0/no/off, and
    ``False`` for anything unrecognised -- an argument that cannot be read never turns writes on."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return True
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def guardian_summary_line(value, limit=None):
    """``value`` as one line of plain text: whitespace (newlines included) collapsed, secrets scrubbed, and cut to
    `limit` characters with a trailing ``...`` when it was longer."""
    text = guardian_scrub_secrets(" ".join(str(value if value is not None else "").split()), keep_identifiers=True)
    if limit and len(text) > limit:
        text = text[:max(limit - 3, 0)].rstrip() + "..."
    return text


def guardian_summary_latest(key):
    """`Guardian.<key>`, or its newest dict when an earlier run appended a second copy and made it a list."""
    value = guardian_ctx_read(key)
    if isinstance(value, list):
        dicts = [item for item in value if isinstance(item, dict)]
        return dicts[-1] if dicts else None
    return value if isinstance(value, dict) else None


# --- the section ------------------------------------------------------------------------------------------------

def guardian_summary_parse_section(section):
    """``{"triage": str, "investigation": str}``: the lines of an existing Guardian section, without their labels.
    Anything else under the marker is not Guardian's own and is dropped."""
    parts = {"triage": "", "investigation": ""}
    for line in (section or "").splitlines():
        for stage, label in GUARDIAN_ISSUE_SUMMARY_LABELS.items():
            if line.startswith(label) and not parts[stage]:
                parts[stage] = line[len(label):].strip()
    return parts


def guardian_summary_build_section(parts):
    """The section text for ``parts`` (see :func:`guardian_summary_parse_section`), or an empty string when both lines
    are empty. Each line is cut to GUARDIAN_ISSUE_SUMMARY_PART_MAX_CHARS and the whole to
    GUARDIAN_ISSUE_SUMMARY_SECTION_MAX_CHARS."""
    lines = [GUARDIAN_ISSUE_SECTION_MARKER]
    for stage in GUARDIAN_ISSUE_SUMMARY_STAGES:
        text = guardian_summary_line(parts.get(stage), GUARDIAN_ISSUE_SUMMARY_PART_MAX_CHARS)
        if text:
            lines.append(GUARDIAN_ISSUE_SUMMARY_LABELS[stage] + text)
    if len(lines) == 1:
        return ""
    return "\n".join(lines)[:GUARDIAN_ISSUE_SUMMARY_SECTION_MAX_CHARS]


def guardian_summary_new_description(current, stage, part_text):
    """``(description, section)``: the issue's description with this stage's line in Guardian's section, and the
    section. The text above the marker is returned exactly as it was. ``("", "")`` when there is nothing to write."""
    original, existing = guardian_split_issue_section(current)
    parts = guardian_summary_parse_section(existing)
    parts[stage] = part_text
    section = guardian_summary_build_section(parts)
    if not section:
        return "", ""
    return (original + GUARDIAN_ISSUE_SECTION_GAP + section if original else section), section


# --- the triage text --------------------------------------------------------------------------------------------

def guardian_summary_triage_facts(triage, apply_result):
    """The values the triage text shows: type, severity before and after, confidence, escalate."""
    apply_result = apply_result if isinstance(apply_result, dict) else {}
    before = apply_result.get("severity_before") or triage.get("original_severity") or "unknown"
    after = apply_result.get("severity_after") or triage.get("severity") or before
    branch = str(triage.get("branch") or "").strip() or "other"
    kept = ""
    if apply_result.get("status") == "skipped":
        # The apply step left the severity alone (an owner, a resolved issue, an earlier triage): the summary still
        # records what this run found, and says why nothing changed.
        after = before
        kept = guardian_summary_line(apply_result.get("reason"), 160) or "the apply step skipped this issue"
    return {
        "type": branch,
        "before": before,
        "after": after,
        "kept": kept,
        "confidence": triage.get("confidence", 0),
        "escalate": "yes" if triage.get("escalate") is True else "no",
        "fallback": triage.get("status") == "fallback",
    }


def guardian_summary_triage_note(triage, apply_result):
    """The War Room note for the triage stage (markdown)."""
    facts = guardian_summary_triage_facts(triage, apply_result)
    lines = [
        "**Guardian triage**",
        "- Type: `{}`{}".format(facts["type"], " (no structured rating; an analyst should review it)" if facts["fallback"] else ""),
        "- Severity: {}".format("{} (unchanged: {})".format(facts["before"], facts["kept"]) if facts["kept"]
                                else "{} -> {}".format(facts["before"], facts["after"])),
        "- Confidence: {}".format(facts["confidence"]),
        "- Escalate: {}".format(facts["escalate"]),
        "- Summary: {}".format(guardian_summary_line(triage.get("summary"))),
    ]
    if triage.get("analysis"):
        lines.append("- Analysis: {}".format(guardian_summary_line(triage["analysis"])))
    recommendations = [guardian_summary_line(r) for r in triage.get("recommendations") or [] if isinstance(r, str) and r.strip()]
    if recommendations:
        lines.append("- Recommendations:")
        lines += ["  {}. {}".format(index, text) for index, text in enumerate(recommendations, 1)]
    return "\n".join(lines)[:GUARDIAN_ISSUE_SUMMARY_NOTE_MAX_CHARS]


def guardian_summary_triage_part(triage, apply_result):
    """The triage line of the description section (one line of text, at most GUARDIAN_ISSUE_SUMMARY_PART_MAX_CHARS)."""
    facts = guardian_summary_triage_facts(triage, apply_result)
    severity = "{} (unchanged)".format(facts["before"]) if facts["kept"] else "{} -> {}".format(facts["before"], facts["after"])
    head = "type {}, severity {}, confidence {}, escalate {}.".format(
        facts["type"], severity, facts["confidence"], facts["escalate"])
    pieces = [head, "Summary: " + guardian_summary_line(triage.get("summary"))]
    if triage.get("analysis"):
        pieces.append("Analysis: " + guardian_summary_line(triage["analysis"]))
    recommendations = [guardian_summary_line(r) for r in triage.get("recommendations") or [] if isinstance(r, str) and r.strip()]
    if recommendations:
        pieces.append("Recommendations: " + " ".join("{}) {}".format(i, text) for i, text in enumerate(recommendations, 1)))
    return guardian_summary_line(" ".join(pieces), GUARDIAN_ISSUE_SUMMARY_PART_MAX_CHARS)


def guardian_summary_triage_skip(triage, apply_result):
    """The reason this stage writes nothing, or an empty string."""
    if not isinstance(triage, dict) or not triage.get("status"):
        return "there is no Guardian.Triage result"
    return ""


# --- the investigation text -------------------------------------------------------------------------------------

def guardian_summary_posture_fields(summary):
    """``(priority, {exposure, owner, fix}, rationale)`` read from a posture summary written as
    ``P2 | exposure: ... | owner: ... | fix: ... | rationale`` (what the reasoning loop records; an ``[unverified: ...]``
    marker may come first and stays with the rationale). A summary in any other shape gives no priority, no fields and
    the whole text as the rationale."""
    import re
    priority, fields, rationale = "", {}, []
    for piece in (part.strip() for part in str(summary or "").split(" | ")):
        head = re.match(r"^(\[[^\]]*\]\s*)?(P[1-4])$", piece) if not (priority or fields or rationale) else None
        label = next((name for name in _GUARDIAN_ISSUE_SUMMARY_POSTURE_LABELS if piece.lower().startswith(name + ":")), "")
        if head:
            priority = head.group(2)
            if head.group(1):
                rationale.append(head.group(1).strip())
        elif label and label not in fields:
            fields[label] = piece[len(label) + 1:].strip()
        elif piece:
            rationale.append(piece)
    return priority, fields, " | ".join(rationale)


def guardian_summary_investigation_facts(loop):
    """The values the investigation text shows, or ``None`` when the run recorded no verdict or assessment."""
    verdict = loop.get("verdict") if isinstance(loop, dict) and isinstance(loop.get("verdict"), dict) else None
    if not verdict or not verdict.get("verdict"):
        return None
    posture = verdict.get("kind") == "posture"
    priority, fields, rationale = guardian_summary_posture_fields(verdict.get("summary")) if posture else ("", {}, "")
    techniques = verdict.get("techniques") if isinstance(verdict.get("techniques"), list) else []
    return {
        "posture": posture,
        "label": str(verdict["verdict"]),
        "confidence": verdict.get("confidence"),
        "priority": str(verdict.get("priority") or priority or ""),
        "techniques": [str(t) for t in techniques if t],
        "fields": fields,
        "summary": rationale if posture and rationale else str(verdict.get("summary") or ""),
    }


def guardian_summary_investigation_skip(loop):
    """The reason this stage writes nothing, or an empty string."""
    if isinstance(loop, dict) and loop.get("assessment_mode") == "triage":
        return "the last model session was the triage session; the investigation did not run or did not start"
    if guardian_summary_investigation_facts(loop) is None:
        return "the investigation ended without a verdict or assessment"
    return ""


def guardian_summary_investigation_note(loop):
    """The War Room note for the investigation stage (markdown)."""
    facts = guardian_summary_investigation_facts(loop)
    lines = ["**Guardian investigation**"]
    if facts["posture"]:
        lines.append("- Assessment: {}{}".format(facts["label"], ", priority " + facts["priority"] if facts["priority"] else ""))
    else:
        lines.append("- Verdict: {}, confidence {}".format(facts["label"], facts["confidence"]))
    if facts["techniques"]:
        lines.append("- Techniques: {}".format(", ".join(facts["techniques"])))
    for name in _GUARDIAN_ISSUE_SUMMARY_POSTURE_LABELS:
        if facts["fields"].get(name):
            lines.append("- {}: {}".format(name.capitalize(), guardian_summary_line(facts["fields"][name])))
    lines.append("- Summary: {}".format(guardian_summary_line(facts["summary"])))
    return "\n".join(lines)[:GUARDIAN_ISSUE_SUMMARY_NOTE_MAX_CHARS]


def guardian_summary_investigation_part(loop):
    """The investigation line of the description section (one line, at most GUARDIAN_ISSUE_SUMMARY_PART_MAX_CHARS)."""
    facts = guardian_summary_investigation_facts(loop)
    if facts["posture"]:
        head = "{}{}.".format(facts["label"], " " + facts["priority"] if facts["priority"] else "")
    else:
        head = "{}, confidence {}.".format(facts["label"], facts["confidence"])
    pieces = [head]
    if facts["techniques"]:
        pieces.append("Techniques: {}.".format(", ".join(facts["techniques"])))
    for name in _GUARDIAN_ISSUE_SUMMARY_POSTURE_LABELS:
        if facts["fields"].get(name):
            pieces.append("{}: {}.".format(name.capitalize(), guardian_summary_line(facts["fields"][name]).rstrip(".")))
    pieces.append("Summary: " + guardian_summary_line(facts["summary"]))
    return guardian_summary_line(" ".join(pieces), GUARDIAN_ISSUE_SUMMARY_PART_MAX_CHARS)


# --- the writes -------------------------------------------------------------------------------------------------

def guardian_summary_issue_field(incident, names):
    """``(found, text)``: the first of `names` that is a string in the issue (top level, then CustomFields)."""
    for container in (incident, incident.get("CustomFields")):
        if isinstance(container, dict):
            for name in names:
                if isinstance(container.get(name), str):
                    return True, container[name]
    return False, ""


def guardian_summary_issue_rows(entries):
    """The issue records in the reply of ``core-get-issues``: the dicts that carry an ``internal_id`` or ``issue_id``,
    found in each entry's Contents (a list, or a dict that wraps one) up to three levels down."""
    rows = []

    def collect(value, depth):
        if isinstance(value, list):
            for item in value:
                collect(item, depth)
        elif isinstance(value, dict):
            if "internal_id" in value or "issue_id" in value:
                rows.append(value)
            elif depth < 3:
                for item in value.values():
                    collect(item, depth + 1)

    for entry in entries or []:
        if isinstance(entry, dict) and entry.get("Type") != GUARDIAN_ERROR_ENTRY_TYPE:
            collect(entry.get("Contents"), 0)
    return rows


def guardian_summary_current_description(incident, issue_id):
    """``(text, source)``: the issue's current description, or ``(None, reason)`` when it cannot be known well enough to
    append to it safely.

    The platform's own record is read first (`core-get-issues`, the field `core-update-issue` replaces). When that gives
    no description field, the issue's own `details` or `description` is used if it holds text. A description that
    neither source shows is never taken as empty on a guess."""
    result = guardian_execute("core-get-issues", {"issue_id": str(issue_id), "page_size": "1"})
    row = next((r for r in guardian_summary_issue_rows(result["data"] if result["ok"] else None)
                if str(r.get("internal_id", r.get("issue_id"))) == str(issue_id)), None)
    if row is not None and isinstance(row.get("description"), str):
        return row["description"], "core-get-issues"
    found, text = guardian_summary_issue_field(incident, GUARDIAN_ISSUE_SUMMARY_FIELD_NAMES)
    if found and text.strip():
        return text, "the issue's own fields"
    if not result["ok"]:
        return None, "the description could not be read ({})".format(guardian_summary_line(result["error"], 160))
    return None, "the platform did not show the issue's description, so an empty one cannot be assumed"


def guardian_summary_write_note(content):
    """Post the War Room note. Never raises; returns whether it was written."""
    try:
        entries = [{"Contents": content, "ContentsFormat": "markdown", "Tags": [GUARDIAN_ISSUE_SUMMARY_NOTE_TAG], "Note": True}]
        return bool(guardian_execute("addEntries", {"entries": entries})["ok"])
    except Exception as exc:
        demisto.error("GuardianIssueSummary: the note could not be written: {}".format(exc))
        return False


def guardian_summary_audit(result, issue_id):
    """One audit row for the outcome. Never raises."""
    try:
        guardian_execute("GuardianAuditWrite", {
            "action": "GuardianIssueSummary",
            "target": str(issue_id)[:200],
            "status": {"skipped": "skipped", "error": "error"}.get(result["status"], "ok"),
            "actor": GUARDIAN_ISSUE_SUMMARY_ACTOR,
            "run_id": str(issue_id),
            "detail": json.dumps(result)[:1500],
        })
    except Exception as exc:  # the audit row must never stop the run
        demisto.error("GuardianIssueSummary: audit write failed: {}".format(exc))


def guardian_summary_result(stage, status, reason="", note_posted=False, description_updated=False, section_chars=0):
    return {"stage": stage, "status": status, "note_posted": note_posted, "description_updated": description_updated,
            "section_chars": section_chars, "reason": reason}


def guardian_summary_run(stage, apply_changes, incident, triage, apply_result, loop):
    """Compute the stage's text and, when allowed, write the note and the description. Returns the result dict.
    Never raises."""
    if stage not in GUARDIAN_ISSUE_SUMMARY_STAGES:
        return guardian_summary_result(stage, "error", "stage must be triage or investigation")
    incident = incident if isinstance(incident, dict) else {}
    issue_id = str(incident.get("id") or "").strip()
    skip = guardian_summary_triage_skip(triage, apply_result) if stage == "triage" else guardian_summary_investigation_skip(loop)
    if skip:
        result = guardian_summary_result(stage, "skipped", skip)
        guardian_summary_audit(result, issue_id)
        return result
    if not issue_id:
        return guardian_summary_result(stage, "skipped", "there is no issue to write to")

    if stage == "triage":
        note, part = guardian_summary_triage_note(triage, apply_result), guardian_summary_triage_part(triage, apply_result)
    else:
        note, part = guardian_summary_investigation_note(loop), guardian_summary_investigation_part(loop)

    if not apply_changes:
        _description, section = guardian_summary_new_description("", stage, part)
        result = guardian_summary_result(stage, "dry_run", "apply_changes is false, so nothing was written", section_chars=len(section))
        guardian_summary_audit(result, issue_id)
        return result

    note_posted = guardian_summary_write_note(note)
    reasons = [] if note_posted else ["the note could not be posted"]
    description_updated, section_chars = False, 0
    current, source = guardian_summary_current_description(incident, issue_id)
    if current is None:
        reasons.append("description not written: " + source)
    else:
        description, section = guardian_summary_new_description(current, stage, part)
        section_chars = len(section)
        if description == current:
            reasons.append("the description already holds this text")
        else:
            outcome = guardian_execute(GUARDIAN_ISSUE_SUMMARY_UPDATE_COMMAND, {"id": issue_id, "description": description})
            if outcome["ok"]:
                description_updated = True
            else:
                reasons.append("description not written: {} failed: {}".format(
                    GUARDIAN_ISSUE_SUMMARY_UPDATE_COMMAND, guardian_summary_line(outcome["error"], 200)))
    status = "written" if (note_posted or description_updated) else "error"
    result = guardian_summary_result(stage, status, "; ".join(reasons), note_posted, description_updated, section_chars)
    guardian_summary_audit(result, issue_id)
    return result


def guardian_summary_readable(result):
    return tableToMarkdown("Guardian issue summary", [{
        "Stage": result["stage"], "Status": result["status"], "Note posted": result["note_posted"],
        "Description updated": result["description_updated"], "Section characters": result["section_chars"],
        "Reason": result["reason"]}], headers=["Stage", "Status", "Note posted", "Description updated", "Section characters", "Reason"])


def main():
    try:
        args = demisto.args()
        stage = str(args.get("stage") or "").strip().lower()
        result = guardian_summary_run(
            stage, guardian_summary_parse_flag(args.get("apply_changes")), demisto.incident() or {},
            guardian_summary_latest("Triage"), guardian_summary_latest("TriageApply"), guardian_summary_latest("Loop"))
    except Exception as ex:  # belt-and-suspenders: an automation must not leak a traceback
        return_error("GuardianIssueSummary failed unexpectedly: {}".format(ex))
        return

    # One entry per stage, merged by `stage`: the triage entry and the investigation entry sit side by side, and a
    # re-run of a stage updates its own entry.
    return_results(CommandResults(
        readable_output=guardian_summary_readable(result), outputs_prefix=GUARDIAN_ISSUE_SUMMARY_CONTEXT_PATH,
        outputs_key_field="stage", outputs=result, raw_response=result))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
