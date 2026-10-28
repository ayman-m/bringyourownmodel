"""GuardianToolBridge -- the single security chokepoint every agent tool
call flows through.

GuardianReasoningTick hands each of the model's `tool_calls` to THIS
automation, one call at a time. The bridge is the only place a
model-proposed command is ever actually dispatched to
`demisto.executeCommand`. The prompt-side tool catalogue
(GuardianToolCatalogBuilder) is curation only, **not** a security boundary: a
denied command is still reachable unless it is denied at the point of
dispatch. This is that point.

THE DECISION SEQUENCE (each step short-circuits with a structured envelope;
this automation never raises -- every path returns a normalized result)
--------------------------------------------------------------------------
    1. Kill-switch check      (`guardian_kill_switch`)
    2. Denylist check         (`guardian_tool_denylist`)  -- SECURITY BOUNDARY
    3. Allowlist / default-deny gate (`guardian_tool_allowlist`) -- SECURITY
       BOUNDARY (see "DEFAULT-DENY ALLOWLIST ENFORCEMENT" below)
    4. Policy tier check      (`guardian_policy`)
    5. Execute                (`guardian_execute` -> `demisto.executeCommand`)
    6. Result shaping         (redact, then size-cap/truncate)
    7. Audit                  (`GuardianAuditWrite`, exactly one row)
    8. Return                 (`Guardian.ToolResult`, the model's tool message)

FAIL-OPEN VS FAIL-CLOSED (deliberately asymmetric)
--------------------------------------------------------------------------
Every GATE in this bridge is fail-CLOSED except one, on purpose:

- **Kill switch unreadable -> NOT halted (fail-OPEN), but ONLY in `manual`
  mode.** An unreadable kill switch is ambiguous, not a proof the operator
  wants everything stopped, and treating "I can't read the kill switch" as
  "halt everything" would let a transient List hiccup silently freeze the
  whole agent. Instead the bridge logs loudly (`demisto.error`, plus a `note`
  carried into the audit `detail`) and lets the call proceed to the
  (fail-closed) denylist/allowlist/policy gates below.

  When the incident is in `bypass` mode (pre-approved autonomous containment
  is active -- a `require_approval` command CAN auto-execute with no human in
  the loop), this ONE gate flips to fail-CLOSED instead: an unreadable or
  malformed `guardian_kill_switch` HALTS the call. In `manual` mode, fail-open
  only ever costs a human reviewer one more `require_approval` park to look
  at; in `bypass` mode the same degraded read could silently mask a genuine
  operator halt request for as long as the List stays unreadable, precisely
  while pre-approved auto-execution keeps running unattended -- the one
  scenario the kill switch exists to guard against.
  `guardian_bridge_get_approval_mode` is consulted ONLY on this already
  degraded path (the common healthy-List case never pays for the extra
  `demisto.incident()` read) -- see `guardian_bridge_check_kill_switch`.
- **Denylist unreadable -> denied (fail-CLOSED).** This is THE
  self-escape-prevention boundary; an unreadable denylist is never silently
  treated as "nothing is denied."
- **Allowlist unreadable -> denied (fail-CLOSED), unconditionally, exactly
  like the denylist.** `guardian_bridge_check_allowlist` denies the call
  outright the instant `guardian_tool_allowlist` fails to load/parse -- it
  does NOT fall through to "well, maybe `guardian_policy` allows it." The
  permitted-set computation needs a good read of this List to be trustworthy
  at all.
- **Policy unreadable -> denied (fail-CLOSED).** An unreadable policy List is
  never silently treated as "everything is allowed."

SELF-ESCAPE PREVENTION (the arg-level denylist rule)
--------------------------------------------------------------------------
`guardian_tool_denylist`'s `denied` array mixes two kinds of entries:
bare command names (full exclusion, e.g. `"setIntegration"`) and
`command:targetList` argument-level rules (e.g. `"setList:guardian_policy"`)
meaning "deny `command` specifically when its `listName` argument targets
`targetList`" -- without this, a model could call the otherwise-legitimate
`setList`/`addToList` commands against Guardian's OWN control-plane Lists
(`guardian_policy`, `guardian_tool_allowlist`, `guardian_tool_denylist`,
`guardian_kill_switch`) and rewrite its own guardrails. This bridge enforces
BOTH:

1. An **exact** `(tool_name, listName)` match against the parsed
   `command:targetList` entries in `denied` (data-driven, no hardcoded
   protected-list names in this file).
2. A **generic cross-check**: `guardian_tool_denylist` also carries a
   `protected_lists` array (the list of control-plane List names). For the
   known list-mutating commands (`GUARDIAN_LIST_MUTATING_COMMANDS` --
   `setList`, `addToList`, `createList`, `deleteList`), if the `listName`
   argument names ANY entry in `protected_lists`, the call is denied even
   if that exact `command:targetList` pair wasn't separately spelled out in
   `denied` -- so adding a new protected list to `protected_lists` closes
   the self-escape hole immediately, without also requiring matching
   `denied` entries for every list-mutating command. `createList` is in this
   set because XSOAR's real `createList` CREATES-OR-OVERWRITES an existing
   list -- it is just as much a self-escape vector as `setList`; `deleteList`
   likewise, from the deletion side.

The `listName` argument is compared **case-sensitively** (XSOAR list names
are case-sensitive server-side, so lowercasing here would incorrectly treat
two distinct real Lists as the same one) but IS `.strip()`-ped first, so a
stray leading/trailing space in a model-supplied `listName` can't dodge the
comparison while still resolving to the protected list server-side.

Both checks are read from the SAME `guardian_tool_denylist` load -- there is
no separate fetch.

DEFAULT-DENY ALLOWLIST ENFORCEMENT
--------------------------------------------------------------------------
The prompt-side tool catalogue (`GuardianToolCatalogBuilder`) curates
`guardian_tool_allowlist` into the schemas actually OFFERED to the model, but
that curation is advisory only: a model can emit a `tool_name` it was never
offered. The most dangerous case is a generic Core REST API verb such as
`demisto-api-post {"uri": "/apikeys", "body": {...}}`, which would otherwise
reach XSOAR's entire REST API: minting an API key, overwriting
`guardian_kill_switch` via `/lists/save`, or hitting containment endpoints
that bypass the `xdr-*` = `require_approval` gate entirely.

So a command is permitted to reach the policy-tier decision (Step 4) ONLY if
it is EITHER (a) present on `guardian_tool_allowlist` (the curated read-only
surface -- `guardian_bridge_check_allowlist`), OR (b) an explicit key in
`guardian_policy` (a command someone deliberately classified into a tier --
`guardian_bridge_check_policy`'s `in_policy` field). A command satisfying
NEITHER condition is denied by `guardian_tool_bridge_run` itself, with a
dedicated, audited refusal ("not on allowlist and not policy-classified --
denied by default"), before `guardian_bridge_check_policy`'s "absent ->
allow" default is ever acted on. Both this allowlist gate and the denylist
are fail-closed (see "FAIL-OPEN VS FAIL-CLOSED" above). As defense in depth,
the generic REST verbs are also listed in `guardian_tool_denylist` directly
(a hard denylist entry wins even if the allowlist gate were ever bypassed),
and `createList`/`deleteList` are tiered into `guardian_policy` as
`require_approval` (see `GUARDIAN_LIST_MUTATING_COMMANDS`).

POLICY TIERS AND THE APPROVAL GATE
--------------------------------------------------------------------------
`guardian_policy` maps native command/automation names to a tier: `allow`,
`require_approval`, or `deny`. `deny` short-circuits identically to the
denylist (no execute). A command that is `allow`-tiered proceeds to
execute, as does a command that is simply absent from `guardian_policy`
entirely -- but only once Step 3 has confirmed the command is at least on
`guardian_tool_allowlist` OR an explicit `guardian_policy` key; an
absent-from-policy command that is ALSO absent from the allowlist is denied
at Step 3 and never reaches this "allow" default at all.

`require_approval` is a REAL gate, not a dead-end:

1. **Fresh ask** (no `approval_id`/`plan_approval_id` given): this bridge
   creates a pending approval -- a row in the runtime-created
   `guardian_approvals_ledger` List (`{approval_id, kind:"tool", tool_name,
   tool_args, canonical_args, risk_tier, status:"pending", created_ts,
   requested_by:"agent", ...}` -- see `guardian_bridge_create_approval`) plus
   a War Room note formatted by `risk_tier` (soft/destructive/credential --
   `guardian_bridge_risk_tier`), and returns `status:"pending_approval"`
   WITHOUT executing. The returned `approval_id` is what a human acts on.
   `GuardianReasoningTick` (the only caller) recognizes this `status` and sets
   `Guardian.Loop.pending`, pausing the loop.
2. **Resolution** (`Scripts/GuardianApprovalResolve` + `Scripts/GuardianDeny`,
   `!guardian-approve`/`!guardian-deny`) flips that ledger row's `status` to
   `"approved"`/`"denied"`, recording the resolver + timestamp. Self-resolve
   prevention: the agent's own tool-calling path can never reach either
   script at all (neither is on `guardian_tool_allowlist` nor a
   `guardian_policy` key -- the same default-deny gate this bridge enforces
   for every other command makes them structurally unreachable by a model
   `tool_call`), plus an in-script `actor` check rejects `actor="agent"` as
   defense in depth.
3. **Re-dispatch with the approved-token** (`approval_id` given): this
   bridge validates the token via `guardian_bridge_consume_approval_token` --
   it must match the ledger's `approved` row for THIS EXACT
   `tool_name` + `canonical(tool_args)`, and must not already be
   `consumed` -- then marks it `consumed` (single-use, no replay) and falls
   through to Step 5 to actually execute, exactly like an `allow`-tiered
   call (the executed call's audit `detail.approved_via` records the
   `approval_id` that authorized it; `status` stays the ordinary `ok`/
   `error` the execution itself produced -- there is no separate "approved"
   status value). A token that fails to match/consume is DENIED outright
   (never silently re-parked as a fresh ask, and never executed) -- see the
   `guardian_tool_bridge_run` call site below.
4. **Plan-approval** (`plan_approval_id` + `plan_step_index`, from
   `Scripts/GuardianPlanApprove`/`GuardianReasoningTick`'s pending
   short-circuit): the same idea, one ledger row per level (`kind:"plan"`,
   `steps:[...]`), each step consumed independently via
   `guardian_bridge_consume_plan_step`. "Per-step gate skipped" means ONLY
   that a `require_approval`-tiered step's park-again is bypassed once its own
   step-token is validated; kill-switch/denylist/allowlist/`deny` tier are
   NEVER bypassed by a plan token (they run unconditionally above, same as
   every other path) and every step is still audited individually (each step
   is its own `guardian_tool_bridge_run` call, each producing its own
   `GuardianAuditWrite` row via the same `_guardian_bridge_finalize`
   chokepoint every other path uses).
5. **Pre-approved autonomous containment** (see the next section): a third
   way `require_approval` can execute without ever creating a ledger row at
   all -- when no token was presented (paths 3/4 don't apply) but the call
   matches a narrow, explicit `guardian_preapproved` class, is ALSO a member
   of this file's own `GUARDIAN_AUTO_APPROVABLE_COMMANDS` frozenset, while the
   incident is in `bypass` mode and the command is NOT destructive/credential
   tier.

PRE-APPROVED AUTONOMOUS CONTAINMENT (SECURITY-CRITICAL)
--------------------------------------------------------------------------
`GuardianApprovalMode` (`guardianapprovalmode` CustomField, manual|bypass) is
consumed only in one extremely narrow way: it never skips the approval gate
wholesale, it only ever lets a SMALL, explicitly enumerated class of low-risk
containment auto-execute in place of parking. It is read FRESH every call
(`guardian_bridge_get_approval_mode` hits `demisto.incident()` directly, never
a cached/earlier-tick value) -- flipping the field takes effect on the very
next `guardian_tool_bridge_run` call, and flipping it back to `manual`
immediately stops any further auto-execution.

The mechanism is reached ONLY from inside the `require_approval` branch, ONLY
when NEITHER `approval_id` NOR `plan_approval_id` was presented (i.e. this is
what would otherwise become a brand-new "fresh ask"; paths 3/4 above,
consuming an existing human-issued token, are completely unaffected):

1. **Risk tier gate (checked FIRST, independent of `guardian_preapproved`'s
   own contents)**: `guardian_bridge_risk_tier(tool_name, parsed_args)` must
   NOT return `"destructive"` or `"credential"`. Even a misconfigured
   `guardian_preapproved` entry that named a destructive/credential-class
   command (e.g. `xdr-isolate-endpoint`, `closeInvestigation`, anything
   credential-flavored) can NEVER auto-execute -- the risk-tier
   classification lives in THIS file's own
   `GUARDIAN_RISK_TIER_DESTRUCTIVE_COMMANDS`/`_CREDENTIAL_SUBSTRINGS`
   constants, not in the pack-seeded List, so a List edit alone can never
   widen this gate.
2. **Code-level allow-map gate (checked alongside gate 1, equally
   independent of `guardian_preapproved`'s own contents)**: `tool_name` must
   be a member of THIS file's own `GUARDIAN_AUTO_APPROVABLE_COMMANDS`
   frozenset (`xdr-endpoint-tag-add` and `GuardianContainmentSimulate`, an
   inert simulated-containment command that exercises this mechanism
   end-to-end with no real containment effect). A `guardian_preapproved` List
   edit alone can NEVER widen auto-execution to a command not ALSO blessed
   here: expanding autonomy to a new command requires a CODE change (and
   therefore a code review), never just a List edit.
3. **Approval-mode gate**: `guardian_bridge_get_approval_mode()` must return
   `"bypass"` for THIS incident, read fresh this call. In `manual` mode (the
   default), this whole mechanism is inert -- every `require_approval`
   command parks.
4. **Class-match gate**: the exact `(tool_name, parsed_args)` must match one
   of `guardian_preapproved`'s explicit `classes` entries
   (`guardian_bridge_check_preapproved` / `guardian_bridge_class_matches`) --
   a SMALL, pack-seeded, read-only allow-map of `{command, arg_constraints}`
   pairs (pack-seeded config Lists are read-only at runtime by construction;
   `guardian_preapproved` is never mutated by any Guardian automation).
   Matching is conservative in both directions: every argument key ACTUALLY
   PRESENT in the call must be one the class explicitly names (an argument
   the class never anticipated fails the match, rather than being silently
   ignored -- this closes the "smuggle one extra argument through a narrow
   class" hole), every `"required": true` key must be present with a
   non-empty value, and every key carrying an `"allowed_values"` list must
   match one of those values EXACTLY (case-sensitive). An
   unreadable/malformed/empty `guardian_preapproved` List means NO class
   matches ANYTHING -- fail-closed like every other gate in this file, never
   "everything is pre-approved."

Shadow flag (evidence-gathering, opt-in per class): a `guardian_preapproved`
class may carry `"shadow": true`. When gates 1-4 above ALL hold AND the
matched class is shadowed, this mechanism deliberately does NOT set
`approved_via` -- the call still falls through to the ordinary fresh-ask
pending-approval path, exactly as if bypass mode were off, so a shadowed class
can never actually loosen autonomy. The only effect is that
`detail.shadow_would_have_approved` on that pending-approval's audit row is
set to the matched class's command name, so an operator considering a new
preapproved class can watch it "fire" against real traffic (still parking for
a human every time) before removing the shadow flag and letting it genuinely
auto-execute.

ALL FOUR gates must hold (the shadow flag changes only WHICH of the two
matching outcomes applies; it is not itself a gate that can block a match),
or the call falls straight through to the ordinary fresh-ask path (a
pending-approval ledger row + War Room note, exactly as in `manual` mode) --
there is no partial/degraded auto-execution. Expanding autonomous execution to
a NEW command therefore requires BOTH a `guardian_preapproved` List entry
(data) AND a `GUARDIAN_AUTO_APPROVABLE_COMMANDS` code change (reviewed code);
neither alone is sufficient, so a compromised or misconfigured List can never
widen autonomy on its own. When all four DO hold, `guardian_tool_bridge_run`
sets `approved_via = {"auto_approved": True, "bypass_source": <mode>,
"preapproved_class": <command>}` and falls through to Step 5 exactly like a
human-approved-token dispatch. Kill-switch, denylist, allowlist/default-deny,
and the `deny` policy tier all already ran, unconditionally, ABOVE this entire
branch (Steps 1-4 execute before `policy_check["decision"]` is even
inspected), so none of them are bypassed by this mechanism either. **Every
auto-executed call is still fully audited**: the ordinary Step 7
`GuardianAuditWrite` row fires exactly as it does for any other executed call
(`status:"ok"`/`"error"`, full `detail`), with `detail.approved_via` carrying
the dict above PLUS top-level `detail.auto_approved` (bool) and
`detail.bypass_source` convenience fields for a human or dashboard scanning
the audit trail.

`GuardianPromptBuilder` narrates this accurately to the model in the
approval-mode block: `bypass` mode's block names the exact
`guardian_preapproved` classes and their argument constraints, and states
plainly that every OTHER `require_approval` command (including anything
destructive/credential-class) still parks in `bypass` mode exactly as in
`manual` mode.

EVIDENCE SHAPING: REDACT FIRST, THEN SIZE-CAP (order matters)
--------------------------------------------------------------------------
`guardian_redact` operates on the STRUCTURED result (walking dict/list
values, masking secret-ish leaf strings by key name) -- it must run BEFORE
the result is serialized to a string for size-capping, or a secret sitting
exactly at the head/tail truncation boundary could leak a partial value
into the "safe" preview. So the pipeline is always: raw entries -> extract
each entry's `Contents` (dropping XSOAR's internal entry envelope noise --
`Type`, `EntryContext`, etc. -- the model only needs the payload) ->
`guardian_redact` -> serialize -> size-check against
the per-result ceiling (20% of the model's input budget in characters, never under 16384; the agent loop
passes it in, else it is worked out from the run's model numbers; an explicit
`guardian_settings.evidence_truncate_bytes` overrides it) -> if over, reduce.

When evidence is truncated, `guardian_bridge_shape_result` also returns the
complete, REDACTED, pre-truncation payload (`full_payload`, `None` when
untruncated), threaded through `_guardian_bridge_finalize` as a SIBLING of
`tool_result` in the returned `data` (never nested inside `tool_result`
itself -- the reasoning tick serializes the WHOLE `tool_result` into the
model-facing message, so embedding the already-oversized full payload there
would defeat truncation entirely). `tool_result` itself carries `truncated`/
`truncation_note` directly, and the audit row records them too. The
reasoning tick is the one place per-tick file uploads make sense
architecturally, and calls `fileResult` + `demisto.results` when it sees
`truncated=True` (`guardian_tick_attach_truncated_evidence`).

**Structural reduction is preferred over a raw byte slice.** When the
redacted result is a non-empty LIST (the common shape for search/enrichment
commands -- `getIncidents`, `SearchIncidentsV2`, `splunk-search`, etc.),
:func:`guardian_bridge_reduce_list_structurally` drops trailing ITEMS
wholesale (never slicing through the middle of one) and appends a small
summary marker object, so every item the model sees is still a complete,
valid piece of JSON -- reduced structurally, keeping it useful, not merely
parseable (see that function's docstring). This is the PREFERRED path whenever
it applies and actually helps; a byte-slice head+tail with a
`...[truncated N bytes]...` marker remains the fallback for everything a
structural reduction can't meaningfully help: a non-list result (a dict or a
bare string), or a list whose single oversized item can't be reduced further
without slicing through IT.

ERROR-PATH REDACTION: THE `result` PATH ISN'T THE ONLY LEAK VECTOR
--------------------------------------------------------------------------
Everything above (redact-then-size-cap) describes the SUCCESS payload
(`Contents` on an ok entry). A FAILING command's error text is every bit as
capable of carrying a secret -- a real integration's own error message
routinely echoes back what it rejected, e.g. `401 Unauthorized: invalid
api_key 'sk-abc...'`, or a DB driver exception embedding a full connection
string with its password. Left unredacted, that raw text would flow straight
into `Guardian.ToolResult.error`, the War Room readable output, and
`raw_response` -- and from there into the LLM's own context, the exact
opposite of what the `result` redaction above exists to prevent. This bridge
closes that gap with two layers, precisely because `guardian_redact` and
free-form error text don't compose:

1. **Structural** (`GuardianCommon.guardian_execute`): a failing entry's
   `Contents`, if it's a DICT an upstream integration returned verbatim, is
   passed through `guardian_redact` before being flattened into the joined
   error string -- it mirrors the success path, just one step earlier (before
   `guardian_execute` even returns).
2. **Scalar-string** (`guardian_scrub_secrets`, applied in
   `guardian_tool_bridge_run`'s Step 5/6, right after `guardian_execute`
   returns): `guardian_redact` can only ever mask a dict VALUE under a
   sensitive KEY -- it cannot scan an arbitrary STRING's own contents,
   which is exactly what a flattened error message is.
   `guardian_scrub_secrets` pattern-masks common secret shapes (API-key
   prefixes, `key=value` pairs, bearer tokens, connection-string passwords,
   long base64/hex blobs) directly in that string. Applied to BOTH
   `exec_result["error"]` and `shaped_result` (the latter can carry the
   SAME raw failing text -- `guardian_bridge_extract_contents` pulls a
   failing entry's `Contents` into `result` regardless of status), and
   ONLY when `status == "error"` -- NOT at the generic
   `_guardian_bridge_finalize` funnel every path shares, and NOT for a
   genuine `ok` result. It is scoped this way because scrubbing every `error`
   string at the shared funnel would mask real, non-secret text (for example
   the List name `guardian_tool_denylist` -- 22 characters, which matches the
   catch-all's charset) inside this bridge's OWN synthesized denylist-deny
   message; see `_guardian_bridge_finalize`'s docstring note.

EXACTLY-ONE-AUDIT-ROW INVARIANT
--------------------------------------------------------------------------
Every decision path that reaches the funnel (halted / denied /
pending_approval / ok / error) calls `GuardianAuditWrite` via
`guardian_execute('GuardianAuditWrite', ...)` **exactly once**, through the
single `_guardian_bridge_finalize` chokepoint below -- there is no other
call site. The one exception is a caller-usage error (`tool_name` missing
or not a string): there is no meaningful tool call to audit in that case,
matching GuardianAuditWrite's own `action`-required check, which similarly
returns before any write.

DURATION MEASUREMENT
--------------------------------------------------------------------------
GuardianAuditWrite's module docstring explains that an audit row's absolute
timestamp (`ts`) must come from the XSOAR SERVER, never this process's own
clock (skew, container restarts, etc. make a local wall clock untrustworthy
for "what time did this happen"). `duration_ms` is a different quantity -- an
ELAPSED interval, not an absolute timestamp -- and for that, this sandbox's
own monotonic clock (`time.monotonic()`, immune to wall-clock adjustments) is
the right tool; a round trip to the server's own clock for this would add
latency for no accuracy benefit. Only the `guardian_execute` step itself
(Step 5) is timed -- the gate checks before it are cheap List reads, not the
thing an operator cares about timing.
"""

import ipaddress
import json
import re
import time
import uuid

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


#: The runtime-mutable kill-switch List (createList-bootstrapped by
#: GuardianBootstrap, never pack-seeded, so it stays writable). Shape:
#: `{"enabled": bool}`.
GUARDIAN_KILL_SWITCH_LIST_NAME = "guardian_kill_switch"

#: The pack-seeded, read-only anti-self-escape denylist. Shape:
#: `{"_comment", "protected_lists": [...], "denied": [...]}`.
GUARDIAN_DENYLIST_LIST_NAME = "guardian_tool_denylist"

#: The pack-seeded, read-only approval-gate policy. Shape: a flat
#: `{command_name: tier}` map (plus a few `_comment*`/`_note*` metadata keys
#: that never collide with a real command name).
GUARDIAN_POLICY_LIST_NAME = "guardian_policy"

#: The pack-seeded baseline remains available only until the first Guardian
#: bootstrap / SOC Agent refresh creates the editable runtime selection.
#: Runtime List read failures are fail-closed; only a definitive not-found
#: response falls back to the pack List.
GUARDIAN_STATIC_ALLOWLIST_LIST_NAME = "guardian_tool_allowlist"
GUARDIAN_RUNTIME_ALLOWLIST_LIST_NAME = "guardian_tool_allowlist_runtime"
GUARDIAN_ALLOWLIST_LIST_NAME = GUARDIAN_STATIC_ALLOWLIST_LIST_NAME  # legacy/test compatibility
GUARDIAN_LIST_NOT_FOUND_HINT = "item not found"

# These runtime Lists are operator/control-plane state even though XSOAR must
# create them at runtime to keep them editable. Merge them into the pack
# denylist's protected-list set in code so an agent can never use generic
# setList/addToList/createList/deleteList to widen its own callable surface or
# forge the discovery view. The dedicated SOC Agent refresh automation writes
# them directly, outside the LLM bridge.
GUARDIAN_RUNTIME_PROTECTED_LISTS = frozenset(
    ("guardian_tool_allowlist_runtime", "guardian_tool_available")
)

# Keep this exact operator-control boundary in code as well as the editable
# Lists. It is intentionally duplicated in GuardianToolCatalogBuilder so a
# user-selected runtime command is neither shown to the model nor callable
# through a forged/off-catalogue tool call.
GUARDIAN_OPERATOR_ONLY_COMMANDS = frozenset(
    (
        "guardian-approve",
        "guardian-deny",
        "guardian-killswitch",
        "guardian-tools",
        "guardian-model",
        "guardian-cost",
        "guardian-help",
        "guardian-compact",
        "guardian-plan",
        "guardian-probe-model",
        "GuardianBootstrap",
        "GuardianAuditWrite",
        "GuardianContentBackup",
        "GuardianCostLedger",
        "GuardianEval",
        "GuardianHousekeeping",
        "GuardianIntakeHygiene",
        "GuardianJobGuard",
        "GuardianSeedContent",
        "GuardianSimulateIncidents",
        "GuardianToolCatalogBuilder",
        "GuardianToolBridge",
        "GuardianToolRegistryRefresh",
        "GuardianReasoningTick",
        # Incident-layout action buttons (operator clicks, never a model tool call).
        "GuardianButtonApprove",
        "GuardianButtonApproveCredential",
        "GuardianButtonDeny",
        "GuardianButtonReply",
        "GuardianButtonCompact",
        "GuardianButtonPause",
        "GuardianButtonResume",
    )
)

#: The pack-seeded, read-only runtime settings List -- this bridge reads an optional explicit
#: `evidence_truncate_bytes` / `evidence_head_tail_bytes` from it (through the shared limit derivation).
GUARDIAN_SETTINGS_LIST_NAME = "guardian_settings"

#: The pack-seeded, read-only pre-approved-containment allow-map -- see the
#: module docstring's "PRE-APPROVED AUTONOMOUS CONTAINMENT" section. Shape:
#: `{"_comment", "classes": [{"command", "arg_constraints", "description"},
#: ...]}`. Never mutated at runtime (pack-seeded config Lists are read-only by
#: construction).
GUARDIAN_PREAPPROVED_LIST_NAME = "guardian_preapproved"

#: `CustomFields` cliName for the incident field that selects manual vs.
#: bypass autonomy mode (`IncidentFields/incidentfield-guardianapprovalmode.
#: json`). This bridge reads it in `guardian_bridge_get_approval_mode`;
#: GuardianPromptBuilder reads the same field.
GUARDIAN_APPROVAL_MODE_FIELD = "guardianapprovalmode"
GUARDIAN_APPROVAL_MODE_VALUES = ("manual", "bypass")
GUARDIAN_APPROVAL_MODE_DEFAULT = "manual"

#: The only tiers `guardian_policy` may map a command to. Anything else is a
#: data-quality problem in the policy List itself and is treated as
#: fail-closed deny, never guessed at.
GUARDIAN_POLICY_VALID_TIERS = ("allow", "require_approval", "deny")

#: Commands whose primary target is named by a `listName` argument -- the
#: generic `protected_lists` cross-check (see module docstring's
#: "SELF-ESCAPE PREVENTION" section) applies to these four; other commands
#: aren't list-mutating and have no `listName` argument to check.
#: `createList` is explicitly included even though its name suggests pure
#: creation: XSOAR's real `createList` command CREATES-OR-OVERWRITES --
#: calling it against an EXISTING list name (e.g. `guardian_tool_denylist`)
#: silently replaces that list's content, same as `setList` would. Without
#: `createList` here, a bare `createList {listName:"guardian_tool_denylist",
#: listData:"{\"denied\":[]}"}` call would sail past the bare-name denylist
#: check (it's not `setList`/`addToList`) and the arg-level
#: `command:targetList` rules (none spelled out for `createList`), reaching
#: this `protected_lists` cross-check as the last line of defense --
#: overwriting the fail-closed denylist with valid-but-empty content would
#: disarm this entire security boundary in one call if this cross-check
#: didn't also cover `createList`/`deleteList`. `guardian_policy` also tiers
#: both `require_approval` as a second, independent layer, and the
#: default-deny allowlist gate (see the module docstring's "DEFAULT-DENY
#: ALLOWLIST ENFORCEMENT" section) denies any command that is neither
#: allowlisted nor policy-classified. `deleteList` is included for the same
#: reason from the other direction: deleting a protected list out from under
#: the bridge is just as much a self-escape as overwriting it.
GUARDIAN_LIST_MUTATING_COMMANDS = ("setList", "addToList", "createList", "deleteList")

#: Fallback evidence-truncation ceiling (bytes) used only if the limits cannot be worked out at all (no input
#: budget is known and nothing is set): the same floor the shared derivation uses.
GUARDIAN_DEFAULT_EVIDENCE_TRUNCATE_BYTES = 16384

#: Fallback head/tail size (bytes, each) used for the same reason as above --
#: about half the fallback ceiling less the marker, which is also what the input-budget derivation gives.
GUARDIAN_DEFAULT_EVIDENCE_HEAD_TAIL_BYTES = 8128

#: Bounds on a per-result ceiling a CALLER hands the bridge (the agent loop passes the ceiling it derived from
#: the model's input budget, so the loop and the bridge cut at the same number). A value outside the bounds is
#: clamped, so a bad argument can neither disable result shaping nor starve a result of all its content.
GUARDIAN_BRIDGE_EVIDENCE_ARG_MIN_BYTES = 2048
GUARDIAN_BRIDGE_EVIDENCE_ARG_MAX_BYTES = 8 * 1024 * 1024
GUARDIAN_BRIDGE_EVIDENCE_HEAD_TAIL_ARG_MIN_BYTES = 512

#: Max length of the "concise arg summary" passed to `GuardianAuditWrite` as
#: `target` -- long enough to be useful in the War Room / audit row, short
#: enough to never itself blow up the audit substrate.
GUARDIAN_TARGET_SUMMARY_MAX_LEN = 200

#: Max length of the FULL tool_name+args preview rendered into a War Room
#: APPROVAL NOTE specifically --
#: deliberately far larger than `GUARDIAN_TARGET_SUMMARY_MAX_LEN` (used ONLY
#: for the terse `GuardianAuditWrite` `target` field, unaffected by this
#: constant). A human approver must be able to see essentially the WHOLE
#: payload they are about to authorize before clicking approve -- a 200-char
#: preview could hide the truly dangerous part of a large args blob (e.g. an
#: `xdr-run-script` call's full `parameters`, or a multi-field `setIncident`
#: update); rubber-stamping something you can't fully read defeats the point
#: of a human approval gate. Still redacted first (never show a raw secret
#: in the War Room either -- see `guardian_bridge_full_args_preview`) and
#: still capped (never let a truly enormous payload blow up the War Room
#: note itself), just at a much more generous ceiling than the audit-row
#: summary.
GUARDIAN_APPROVAL_NOTE_ARGS_MAX_LEN = 4000

#: The full set of outcome statuses this bridge can report -- deliberately
#: the same vocabulary `GuardianAuditWrite` accepts.
GUARDIAN_BRIDGE_STATUSES = ("ok", "error", "denied", "halted", "pending_approval")

# --- The approval gate (ledger + risk tiers + token consumption) ---

#: The runtime-mutable approvals ledger. Like `guardian_kill_switch`/
#: `guardian_audit`/`guardian_cost_ledger`, this is bootstrapped by
#: `GuardianBootstrap` (listed in its `GUARDIAN_BOOTSTRAP_TARGETS`) and
#: defensively self-created here too (like `guardian_audit`) -- it is
#: deliberately NEVER pack-seeded: a List shipped via a pack install becomes
#: `system:true` and permanently rejects every runtime write
#: (`setList`/`createList`/delete all fail `100001`), which would silently
#: disable the approval gate entirely (no ledger row could ever be created,
#: resolved, or consumed). See GuardianBootstrap.py's module docstring.
GUARDIAN_APPROVALS_LEDGER_LIST_NAME = "guardian_approvals_ledger"

#: Tag applied to every approval-request War Room note (the same per-purpose
#: tag convention GuardianAuditWrite and GuardianAskAnalyst use).
GUARDIAN_APPROVAL_NOTE_TAG = "guardian-approval"

#: Risk-tier ceremony: commands whose real-world blast radius is
#: destructive/hard-to-reverse get a louder War Room card. This is
#: purely a PRESENTATION classification -- whether a command needs approval
#: AT ALL is still decided exclusively by `guardian_policy`'s tier; a command
#: absent from this set (and not credential-flavored, see
#: `GUARDIAN_RISK_TIER_CREDENTIAL_SUBSTRINGS` below) defaults to the least-
#: alarming "soft" tier, which is safe precisely because it never affects
#: whether/how the gate itself is enforced, only how the ask is worded.
GUARDIAN_RISK_TIER_DESTRUCTIVE_COMMANDS = frozenset(
    (
        "closeInvestigation",
        "deleteList",
        "GuardianJobsDelete",
        "xdr-isolate-endpoint",
        "xdr-endpoint-isolate",
        "xdr-unisolate-endpoint",
        "xdr-blocklist-files",
        "xdr-file-quarantine",
        "xdr-quarantine-files",
        "xdr-endpoint-scan-execute",
        "xdr-run-script",
        "xdr-kill-process-script-execute",
        "xdr-file-delete-script-execute",
        "xdr-delete-endpoints",
        "xdr-set-user-role",
        "ews-delete-items",
        "ews-move-item",
        "ews-mark-item-as-junk",
    )
)

#: Substrings (case-insensitive) of a command NAME that mark it credential-
#: class regardless of whether it's individually enumerated -- like
#: `GUARDIAN_SENSITIVE_KEY_SUBSTRINGS`, it errs toward over-classification
#: (silent under-classification is the worse failure mode). Every
#: credential-touching command in the catalogue (`GuardianApiKeysCreate`/
#: `Rotate`/`Revoke`, `createAPIKey`, ...) is outright denylisted (see
#: `guardian_tool_denylist`), never merely `require_approval`-tiered, so this
#: classification covers a future `guardian_policy` entry that DOES
#: `require_approval` something credential-shaped: it gets the typed-CONFIRM
#: ceremony automatically. See :func:`guardian_bridge_risk_tier` for the
#: other reachable path: `GuardianSkillsCRUD` reuses this same tier -- by
#: ARGUMENT, not name -- for its `op=delete`.
GUARDIAN_RISK_TIER_CREDENTIAL_SUBSTRINGS = ("apikey", "api_key", "credential", "secret")

#: Commands whose arguments carry a Splunk SPL query that Splunk runs as-is.
#: `splunk-search` is on the curated read-only allowlist, but SPL itself is
#: not read-only -- so for these commands (and only these) the risk tier also
#: looks at argument VALUES, see :func:`guardian_bridge_spl_write_commands`.
GUARDIAN_SPL_QUERY_COMMANDS = frozenset(("splunk-search", "splunk-job-create"))

#: SPL commands that write events, lookups, models or summaries, send mail or
#: alert actions (`sendalert` also creates ES notables/risk events), delete
#: events, or run a search/script/SQL statement this bridge cannot see
#: (`map`, `savedsearch`, `script`/`run`, `dbxquery`). Any of them in a
#: Splunk query promotes the call to the "destructive" tier, which holds it
#: for human approval in every mode (see `guardian_tool_bridge_run`).
#: Deliberately over-inclusive: a false positive costs one approval, a miss
#: lets the agent change Splunk unattended. Not a complete boundary -- a
#: macro (backtick) expands server-side where this scan cannot follow, and
#: apps add their own custom commands -- so the Splunk account behind the
#: SplunkPy instance must itself be read-only (see OPERATOR_RUNBOOK.md).
GUARDIAN_SPL_WRITE_COMMANDS = frozenset(
    (
        "collect",
        "summaryindex",
        "tscollect",
        "mcollect",
        "meventcollect",
        "outputlookup",
        "outputcsv",
        "outputtext",
        "delete",
        "sendemail",
        "sendalert",
        "fit",
        "map",
        "savedsearch",
        "script",
        "run",
        "dbxquery",
        "dbxoutput",
    )
)

#: An SPL command name is the first word of a query or the first word after a
#: pipe or a subsearch's opening bracket. Case-insensitive, like SPL itself.
#: Quoted strings are NOT stripped: a pipe inside quotes over-matches (safe
#: direction), and it keeps `map search="... | outputlookup ..."` visible.
_GUARDIAN_SPL_COMMAND_RE = re.compile(r"(?:^|[|\[])\s*([A-Za-z_]\w*)")

#: `GuardianSkillsCRUD` is an agent self-modification surface (the agent
#: editing its own skill instructions) whose `delete` op is destructive
#: (a skill's live List is removed, though soft-deleted/restorable), so it
#: gets the stronger typed-CONFIRM ceremony. Risk
#: tier is otherwise classified purely by COMMAND NAME (see
#: `guardian_bridge_risk_tier`), which cannot distinguish `op=delete` from
#: `op=create`/`update`/`toggle` within the SAME command -- so this ONE
#: command+arg pair is special-cased to the `"credential"` tier (the only
#: typed-CONFIRM lane this codebase has) rather than inventing a second
#: ceremony. The resulting War Room note's "CREDENTIAL-CLASS ACTION" heading
#: is a known, accepted cosmetic mismatch for a skill-delete -- the human
#: approver still sees the full tool name, args, and risk tier line, so the
#: request is never misleading about WHAT is being asked for.
GUARDIAN_RISK_TIER_TYPED_CONFIRM_COMMAND = "GuardianSkillsCRUD"
GUARDIAN_RISK_TIER_TYPED_CONFIRM_OP_VALUE = "delete"

#: SECURITY-CRITICAL: the CODE-LEVEL allow-map for the pre-approved
#: autonomous containment mechanism -- see the module docstring's
#: "PRE-APPROVED AUTONOMOUS CONTAINMENT" section.
#: `guardian_tool_bridge_run` requires `tool_name` to be a member of THIS
#: frozenset before it will even consult
#: `guardian_bridge_get_approval_mode`/`guardian_bridge_check_preapproved`.
#: Without it, a pack-seeded config List (data, not code) would be the only
#: thing standing between "narrow, reviewed autonomy" and auto-executing any
#: soft-tier command a `guardian_preapproved` entry happened to name (e.g.
#: `send-mail`, `setIncident`, `setPlaybook`, `GuardianSettingsWrite`,
#: `createNewIndicator`, ...). With it, widening auto-execution to a new
#: command requires a CODE change (and therefore a code review) in addition
#: to a `guardian_preapproved` List edit, never a List edit alone. It is
#: deliberately narrow: `xdr-endpoint-tag-add` and `GuardianContainmentSimulate`
#: (a dummy, inert simulated-containment automation with NO real
#: EDR/containment effect, which exercises this mechanism end-to-end without
#: granting autonomy over anything that touches an endpoint) are the only two
#: commands blessed for autonomous execution (see
#: `Lists/list-guardian_preapproved.json`'s own `_note_narrow_by_design`).
#: Adding a further entry here is a deliberate, reviewed decision, not a
#: default.
GUARDIAN_AUTO_APPROVABLE_COMMANDS = frozenset({"xdr-endpoint-tag-add", "GuardianContainmentSimulate"})

#: The literal value `GuardianApprovalResolve`/`GuardianDeny` require in the
#: `confirm` argument to approve a credential-tier request (`confirm=CONFIRM`)
#: -- an exact, case-sensitive match, never fuzzy-matched, so a human must
#: deliberately type the word rather than any argument merely being non-blank.
GUARDIAN_CREDENTIAL_CONFIRM_VALUE = "CONFIRM"

#: The only `kind` values a `guardian_approvals_ledger` row may have --
#: `"tool"` (one command, from a require_approval GuardianToolBridge call)
#: or `"plan"` (a batch of steps, from GuardianPlanApprove).
GUARDIAN_APPROVAL_KIND_TOOL = "tool"
GUARDIAN_APPROVAL_KIND_PLAN = "plan"

#: The only `status` values a ledger row may have. `"pending"` (awaiting
#: resolution) -> `"approved"`/`"denied"` (GuardianApprovalResolve/
#: GuardianDeny) -> for `"approved"`, `"consumed"` becomes `True` once the
#: token is spent (single-tool) or once every step is consumed (plan, judged
#: by the caller, not stored as a row-level flag). `"expired"` is set by
#: GuardianReasoningTick's own SLA/pending-tick-cap breach path (never by
#: this bridge) -- hold+escalate, never auto-execute.
GUARDIAN_APPROVAL_STATUS_PENDING = "pending"
GUARDIAN_APPROVAL_STATUS_APPROVED = "approved"
GUARDIAN_APPROVAL_STATUS_DENIED = "denied"
GUARDIAN_APPROVAL_STATUS_EXPIRED = "expired"


def guardian_bridge_spl_write_commands(tool_name, parsed_args):
    """Return the write-capable SPL commands in a Splunk query call.

    Scans every top-level string argument of a :data:`GUARDIAN_SPL_QUERY_COMMANDS`
    call (not only ``query``, so a renamed argument can't slip past) for a
    command in :data:`GUARDIAN_SPL_WRITE_COMMANDS`, including inside
    subsearches. The values are matched, never logged.

    :return: The matched command names, lower-cased and sorted; ``[]`` for any
        other command or a query with no write-capable command.
    :rtype: ``list`` of ``str``
    """
    if tool_name not in GUARDIAN_SPL_QUERY_COMMANDS or not isinstance(parsed_args, dict):
        return []
    found = set()
    for value in parsed_args.values():
        if isinstance(value, str):
            found.update(name.lower() for name in _GUARDIAN_SPL_COMMAND_RE.findall(value))
    return sorted(found & GUARDIAN_SPL_WRITE_COMMANDS)


def guardian_bridge_risk_tier(tool_name, parsed_args=None):
    """Classify `tool_name` and argument *names* into a risk tier.

    A command's name is not the whole security boundary: a nominally read-only
    command carrying an API key, password, bearer token, or similar credential
    can disclose a secret or make an otherwise harmless-looking request
    privileged. The classifier therefore inspects only top-level argument
    names using the same sensitive-key vocabulary as redaction; it never reads
    or logs the argument values while making this decision.

    The one exception is a Splunk query command: SPL can write, send and
    delete, so a query containing a write-capable command is "destructive"
    even though `splunk-search` itself is allowlisted as read-only -- see
    :func:`guardian_bridge_spl_write_commands`.

    KNOWN LIMITATION: a secret nested one level down (``{"lookup":
    {"api_key": ...}}``) or under a key that avoids every substring in
    ``GUARDIAN_SENSITIVE_KEY_SUBSTRINGS`` (e.g. ``"cred"``, which doesn't
    contain "credential") is invisible to this check -- the same miss that
    ``guardian_redact`` accepts (silent under-classification over over-eager
    masking of legitimate fields). Beyond being unmasked in a log, such a call
    is also not promoted to the credential tier. Deepening the scan
    (recursing into nested values, widening the vocabulary) is a real design
    trade-off against false positives and cost.

    :param tool_name: The command name (already `.strip()`-ped by the
        caller).
    :type tool_name: ``str``
    :param parsed_args: The parsed tool-call arguments, if any. Sensitive
        top-level key names promote the call to ``credential``; the existing
        ``GuardianSkillsCRUD op=delete`` rule remains a separate typed-
        operation rule.
    :type parsed_args: ``dict`` or ``None``
    :return: ``"credential"``, ``"destructive"``, or ``"soft"``.
    :rtype: ``str``
    """
    lowered = (tool_name or "").lower()
    if any(sub in lowered for sub in GUARDIAN_RISK_TIER_CREDENTIAL_SUBSTRINGS):
        return "credential"
    sensitive_key_names = tuple(s.lower() for s in GUARDIAN_SENSITIVE_KEY_SUBSTRINGS)
    if isinstance(parsed_args, dict) and any(
        _guardian_is_sensitive_key(key, sensitive_key_names) for key in parsed_args
    ):
        return "credential"
    if (
        tool_name == GUARDIAN_RISK_TIER_TYPED_CONFIRM_COMMAND
        and isinstance(parsed_args, dict)
        and parsed_args.get("op") == GUARDIAN_RISK_TIER_TYPED_CONFIRM_OP_VALUE
    ):
        return "credential"
    if tool_name in GUARDIAN_RISK_TIER_DESTRUCTIVE_COMMANDS:
        return "destructive"
    if guardian_bridge_spl_write_commands(tool_name, parsed_args):
        return "destructive"
    return "soft"


def guardian_bridge_get_approval_mode():
    """Read the current incident's ``guardianapprovalmode`` CustomField,
    FRESH, on every call -- never cached across ticks or even across two calls
    within the same tick. GuardianPromptBuilder reads the same field.

    ``demisto.incident()`` returns ``{}`` in the Playground (no incident
    context there) -- expected, not an error; that (and any other
    unrecognized value) resolves to the ``"manual"`` default, which is the
    SAFER of the two values (this function never defaults to ``"bypass"``).

    :return: ``"manual"`` or ``"bypass"``.
    :rtype: ``str``
    """
    try:
        incident = demisto.incident() or {}
    except Exception:
        incident = {}
    custom_fields = incident.get("CustomFields") if isinstance(incident, dict) else None
    mode = custom_fields.get(GUARDIAN_APPROVAL_MODE_FIELD) if isinstance(custom_fields, dict) else None
    if mode not in GUARDIAN_APPROVAL_MODE_VALUES:
        return GUARDIAN_APPROVAL_MODE_DEFAULT
    return mode


def guardian_bridge_load_preapproved_classes():
    """Read + parse `guardian_preapproved`'s `classes` array.

    Fail-CLOSED like every other gate this bridge reads: an unreadable or
    malformed List means NO class matches ANYTHING -- this returns `[]`
    rather than signaling failure differently, so the caller
    (`guardian_bridge_check_preapproved`) treats "List unreadable" and "List
    readable but empty" identically (both mean "fall through to the normal
    human-approval gate"). Logs loudly via `demisto.error` either way so a
    genuinely broken/misconfigured List doesn't fail silently -- it just
    fails SAFE (more approvals get parked for a human, never fewer).

    :return: The parsed `classes` array (a list of dicts) -- malformed
        entries (non-dict items) are dropped, never raised on.
    :rtype: ``list``
    """
    load_result = guardian_bridge_load_list_json(GUARDIAN_PREAPPROVED_LIST_NAME)
    if not load_result["ok"]:
        demisto.error(
            "GuardianToolBridge: {} unreadable -- treating as NO pre-approved classes "
            "(fail-closed, every require_approval command still parks): {}".format(
                GUARDIAN_PREAPPROVED_LIST_NAME, load_result["error"]
            )
        )
        return []

    data = load_result["data"]
    if not isinstance(data, dict) or not isinstance(data.get("classes"), list):
        demisto.error(
            "GuardianToolBridge: {} has an unexpected shape (expected a dict with a 'classes' "
            "array, got {}) -- treating as NO pre-approved classes (fail-closed).".format(
                GUARDIAN_PREAPPROVED_LIST_NAME, _guardian_bridge_shape_repr(data)
            )
        )
        return []

    return [entry for entry in data["classes"] if isinstance(entry, dict)]


def guardian_bridge_class_matches(preapproved_class, tool_name, parsed_args):
    """Does ONE `guardian_preapproved` class entry match this EXACT
    `(tool_name, parsed_args)` call?

    Conservative in both directions:

    1. `preapproved_class["command"]` must equal `tool_name` exactly
       (already-canonicalized -- `.strip()`-ped -- by the caller).
    2. Every argument key ACTUALLY PRESENT in `parsed_args` must be a key
       the class's `arg_constraints` explicitly names -- an argument the
       class never anticipated FAILS the match (denied, never silently
       ignored). This closes the obvious "smuggle one extra, unreviewed
       argument through a narrow class" hole.
    3. Every `arg_constraints` key marked `"required": true` must be present
       in `parsed_args` with a non-empty (truthy) value.
    4. Every `arg_constraints` key carrying a non-empty `"allowed_values"`
       list must have `parsed_args[key]` -- if present at all -- match one
       of those values EXACTLY (case-sensitive string equality; no fuzzy/
       substring matching).

    :param preapproved_class: One entry of `guardian_preapproved`'s `classes`
        array.
    :type preapproved_class: ``dict``
    :param tool_name: The command name (already canonicalized).
    :type tool_name: ``str``
    :param parsed_args: The parsed tool-call arguments.
    :type parsed_args: ``dict``
    :return: ``True`` if this call matches the class, else ``False``. Never
        raises -- any malformed class entry simply fails to match.
    :rtype: ``bool``
    """
    if not isinstance(preapproved_class, dict):
        return False
    if preapproved_class.get("command") != tool_name:
        return False

    constraints = preapproved_class.get("arg_constraints")
    if not isinstance(constraints, dict) or not constraints:
        # A class with no argument constraints at all is a data-quality
        # problem in guardian_preapproved, not something to guess at --
        # fail the match rather than treating "no constraints" as "anything
        # goes" (that would make the class's `arg_constraints` key
        # meaningless the moment it's accidentally omitted/emptied).
        return False

    parsed_args = parsed_args if isinstance(parsed_args, dict) else {}

    # Every argument the CALL carries must be one the class explicitly
    # names -- an unanticipated extra argument fails the match outright.
    for key in parsed_args:
        if key not in constraints:
            return False

    for arg_name, rule in constraints.items():
        if not isinstance(rule, dict):
            return False
        value = parsed_args.get(arg_name)
        if rule.get("required") and not value:
            return False
        allowed_values = rule.get("allowed_values")
        if isinstance(allowed_values, list) and allowed_values and value is not None:
            if value not in allowed_values:
                return False

    return True


def guardian_bridge_check_preapproved(tool_name, parsed_args):
    """Does this EXACT `(tool_name, parsed_args)` call match ANY
    `guardian_preapproved` class?

    Purely a matcher -- does NOT check risk tier or approval mode (those are
    two SEPARATE, independent gates the caller, `guardian_tool_bridge_run`,
    enforces itself; see the module docstring's "PRE-APPROVED AUTONOMOUS
    CONTAINMENT" section).

    :param tool_name: The command name (already canonicalized).
    :type tool_name: ``str``
    :param parsed_args: The parsed tool-call arguments.
    :type parsed_args: ``dict``
    :return: The matched class dict, or ``None`` if no class matches
        (including when `guardian_preapproved` itself is unreadable/empty --
        see `guardian_bridge_load_preapproved_classes`).
    :rtype: ``dict`` or ``None``
    """
    for preapproved_class in guardian_bridge_load_preapproved_classes():
        if guardian_bridge_class_matches(preapproved_class, tool_name, parsed_args):
            return preapproved_class
    return None


def guardian_bridge_canonical_json(value):
    """Deterministic JSON-string form of `value`, for exact approved-token
    argument matching -- `json.dumps(..., sort_keys=True)` so two
    structurally-identical arg dicts with keys in a different order (e.g.
    the model re-emitting the same call with reordered JSON keys) always
    canonicalize to the SAME string. `GuardianReasoningTick` uses the same
    canonical form.

    :param value: Any JSON-serializable value (typically the parsed
        tool-call arguments dict).
    :return: The canonical JSON string, or `str(value)` if it isn't
        JSON-serializable (never raises).
    :rtype: ``str``
    """
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except Exception:
        return str(value)


def guardian_bridge_get_server_time():
    """Get "now" from the XSOAR server for a ledger row's timestamp fields --
    never this process's own clock (the same approach as GuardianAuditWrite's
    `guardian_audit_get_server_time`).

    :return: ``(ts, warning)`` -- `ts` is an ISO-8601 string or ``None`` if
        unobtainable; `warning` describes the degraded path taken, or
        ``None`` on the clean path. Never blocks the caller -- a ledger row
        with `ts=None` is still written rather than losing the whole
        approval request over a clock read failing.
    :rtype: ``tuple(str or None, str or None)``
    """
    result = guardian_execute("GetTime", {"dateFormat": "ISO"})
    if result["ok"]:
        for entry in result["data"] or []:
            if isinstance(entry, dict) and isinstance(entry.get("Contents"), str) and entry["Contents"].strip():
                return entry["Contents"].strip(), None

    try:
        incident = demisto.incident() or {}
    except Exception:
        incident = {}
    modified = incident.get("modified") if isinstance(incident, dict) else None
    if isinstance(modified, str) and modified and not modified.startswith("0001-01-01"):
        return modified, "GetTime unavailable ({}); used incident.modified as a degraded fallback.".format(
            result["error"]
        )
    return None, "GetTime unavailable ({}) and no incident.modified fallback available.".format(result["error"])


def guardian_bridge_load_approvals_ledger():
    """Read + JSON-parse `guardian_approvals_ledger`'s `Contents` (via
    `getList`), defensively self-bootstrapping the List via `createList` on
    first use if it doesn't exist yet -- the same fallback GuardianAuditWrite
    uses for `guardian_audit` (the primary bootstrap owner is
    `GuardianBootstrap`, which lists this List in its own
    `GUARDIAN_BOOTSTRAP_TARGETS`).

    :return: A :func:`guardian_envelope`; ``data`` is the parsed row list on
        success.
    :rtype: ``dict``
    """
    result = guardian_execute("getList", {"listName": GUARDIAN_APPROVALS_LEDGER_LIST_NAME})
    if not result["ok"]:
        error_text = (result["error"] or "").lower()
        if "item not found" in error_text:
            create_result = guardian_execute(
                "createList", {"listName": GUARDIAN_APPROVALS_LEDGER_LIST_NAME, "listData": "[]"}
            )
            if not create_result["ok"]:
                return guardian_envelope(
                    False,
                    error="failed to bootstrap missing '{}': {}".format(
                        GUARDIAN_APPROVALS_LEDGER_LIST_NAME, create_result["error"]
                    ),
                )
            return guardian_envelope(True, data=[])
        return guardian_envelope(
            False,
            error="failed to read '{}': {}".format(GUARDIAN_APPROVALS_LEDGER_LIST_NAME, result["error"]),
            retryable=result["retryable"],
        )

    contents = None
    for entry in result["data"] or []:
        if isinstance(entry, dict) and entry.get("Contents") is not None:
            contents = entry["Contents"]

    if contents is None:
        return guardian_envelope(True, data=[])

    if isinstance(contents, str):
        text = contents.strip()
        if not text:
            return guardian_envelope(True, data=[])
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            return guardian_envelope(
                False,
                error="NEEDS_CONTEXT: '{}' Contents is a string but not valid JSON: {}".format(
                    GUARDIAN_APPROVALS_LEDGER_LIST_NAME, exc
                ),
            )
    elif isinstance(contents, list):
        parsed = contents
    else:
        return guardian_envelope(
            False,
            error="NEEDS_CONTEXT: '{}' Contents has unexpected type {}".format(
                GUARDIAN_APPROVALS_LEDGER_LIST_NAME, _guardian_bridge_shape_repr(contents)
            ),
        )

    if not isinstance(parsed, list):
        return guardian_envelope(
            False, error="NEEDS_CONTEXT: '{}' payload is not a JSON array".format(GUARDIAN_APPROVALS_LEDGER_LIST_NAME)
        )
    return guardian_envelope(True, data=parsed)


def guardian_bridge_save_approvals_ledger(rows):
    """Write `rows` back to `guardian_approvals_ledger` via `setList`.

    :param rows: The full row list to persist.
    :type rows: ``list``
    :return: A :func:`guardian_envelope`.
    :rtype: ``dict``
    """
    return guardian_execute(
        "setList", {"listName": GUARDIAN_APPROVALS_LEDGER_LIST_NAME, "listData": json.dumps(rows)}
    )


def guardian_bridge_full_args_preview(parsed_args):
    """Render the FULL redacted tool-call args for a War Room APPROVAL NOTE.

    Unlike `guardian_bridge_summarize_target` (capped at
    `GUARDIAN_TARGET_SUMMARY_MAX_LEN`, 200 chars -- correct for the terse,
    substrate-conscious `GuardianAuditWrite` `target` field), this is capped at the much larger
    `GUARDIAN_APPROVAL_NOTE_ARGS_MAX_LEN` so a human approver can see
    essentially the whole payload they are about to authorize, not a
    preview that could hide the dangerous part of a large call. Redacted
    first, exactly like `guardian_bridge_summarize_target` -- never shows a
    raw secret either; pretty-printed (`indent=2`) since this is meant to be
    read by a human in a fenced code block, not packed into one audit-row
    line.

    :param parsed_args: The parsed tool-call arguments.
    :type parsed_args: ``dict``
    :return: A redacted, generously-capped, pretty-printed JSON string, or
        ``"(no arguments)"`` if there were no arguments at all.
    :rtype: ``str``
    """
    if not parsed_args:
        return "(no arguments)"
    redacted = guardian_redact(parsed_args)
    try:
        text = json.dumps(redacted, sort_keys=True, indent=2, default=str)
    except Exception:
        text = str(redacted)
    if len(text) > GUARDIAN_APPROVAL_NOTE_ARGS_MAX_LEN:
        text = text[: GUARDIAN_APPROVAL_NOTE_ARGS_MAX_LEN - 3] + "..."
    return text


def guardian_bridge_format_approval_note(approval_id, tool_name, parsed_args, risk_tier):
    """Render the War Room approval-request note, styled by `risk_tier`
    (the risk-tier ceremony): soft = a single plain ask;
    destructive = a loud, explicitly-flagged red/warning-styled ask (XSOAR
    War Room notes have no real text-color control, so this uses a bold
    emoji-flagged heading as the practical equivalent); credential = the
    same loud styling PLUS the typed-CONFIRM instruction.

    The **Args** section renders the FULL redacted payload (`
    guardian_bridge_full_args_preview`, capped at
    `GUARDIAN_APPROVAL_NOTE_ARGS_MAX_LEN` -- far larger than the terse
    audit-row `target` summary): a human must be able to see essentially
    everything they are about to authorize, not a 200-char preview that could
    hide the dangerous part of a large call.

    :return: Markdown text.
    :rtype: ``str``
    """
    if risk_tier == "destructive":
        heading = "🔴 **DESTRUCTIVE ACTION REQUIRES APPROVAL**"
    elif risk_tier == "credential":
        heading = "🔐 **CREDENTIAL-CLASS ACTION REQUIRES APPROVAL** (typed confirmation required)"
    else:
        heading = "**Action requires approval**"

    args_preview = guardian_bridge_full_args_preview(parsed_args)

    lines = [
        heading,
        "",
        "- **Tool:** `{}`".format(tool_name),
        "- **Approval ID:** `{}`".format(approval_id),
        "- **Risk tier:** {}".format(risk_tier),
        "- **Args:**",
        "```json",
        args_preview,
        "```",
        "",
    ]
    if risk_tier == "credential":
        lines.append(
            "Reply `!guardian-approve approval_id={} confirm={}` to APPROVE (typed confirmation required), "
            'or `!guardian-deny approval_id={} reason="..."` to DENY.'.format(
                approval_id, GUARDIAN_CREDENTIAL_CONFIRM_VALUE, approval_id
            )
        )
    else:
        lines.append(
            "Reply `!guardian-approve approval_id={}` to APPROVE, "
            'or `!guardian-deny approval_id={} reason="..."` to DENY.'.format(approval_id, approval_id)
        )
    return "\n".join(lines)


def guardian_bridge_create_approval(tool_name, parsed_args, tick_id, run_id):
    """Create a NEW pending approval for `tool_name`/`parsed_args`: append a
    row to `guardian_approvals_ledger` and post the risk-tiered War Room
    note. Never raises.

    :return: A :func:`guardian_envelope`; ``data`` is
        ``{"approval_id", "risk_tier", "posted_to_war_room"}`` on success.
    :rtype: ``dict``
    """
    ledger_result = guardian_bridge_load_approvals_ledger()
    if not ledger_result["ok"]:
        return guardian_envelope(False, error="failed to read approvals ledger: {}".format(ledger_result["error"]))

    rows = ledger_result["data"]
    approval_id = uuid.uuid4().hex
    risk_tier = guardian_bridge_risk_tier(tool_name, parsed_args)
    ts, _ts_warning = guardian_bridge_get_server_time()

    try:
        incident = demisto.incident() or {}
    except Exception:
        incident = {}
    incident_id = incident.get("id") if isinstance(incident, dict) else None

    row = {
        "approval_id": approval_id,
        "kind": GUARDIAN_APPROVAL_KIND_TOOL,
        "incident_id": incident_id,
        "run_id": run_id or incident_id,
        "tool_name": tool_name,
        # `tool_args`/`canonical_args` MUST stay the exact, unredacted original --
        # a later approval consumes this row by re-dispatching with these SAME
        # values (GuardianReasoningTick reads `row["tool_args"]` back for the
        # real execution), and `canonical_args` is the exact-match token
        # `guardian_bridge_consume_approval_token` validates a re-presented call
        # against. Redacting either would silently corrupt approved re-dispatch.
        # `tool_args_redacted` is a SEPARATE, display-only copy for any
        # direct-List-read surface -- never itself consumed for matching or
        # execution.
        "tool_args": parsed_args,
        "canonical_args": guardian_bridge_canonical_json(parsed_args),
        "tool_args_redacted": guardian_redact(parsed_args),
        "risk_tier": risk_tier,
        "status": GUARDIAN_APPROVAL_STATUS_PENDING,
        "created_ts": ts,
        "tick_id": tick_id,
        "requested_by": "agent",
        "resolved_by": None,
        "resolved_ts": None,
        "reason": None,
        "confirm_provided": False,
        "consumed": False,
        "consumed_ts": None,
        # A fresh random marker written by
        # `guardian_bridge_consume_approval_token` alongside `consumed: True`
        # -- see that function's docstring, and
        # `guardian_bridge_confirm_tool_claim` right below it, for the
        # double-invocation race this narrows.
        "claim_token": None,
    }
    rows.append(row)

    save_result = guardian_bridge_save_approvals_ledger(rows)
    if not save_result["ok"]:
        return guardian_envelope(
            False, error="failed to persist approval request to ledger: {}".format(save_result["error"])
        )

    note_result = guardian_execute(
        "addEntries",
        {
            "entries": [
                {
                    "Contents": guardian_bridge_format_approval_note(approval_id, tool_name, parsed_args, risk_tier),
                    "ContentsFormat": "markdown",
                    "Tags": [GUARDIAN_APPROVAL_NOTE_TAG],
                    "Note": True,
                }
            ]
        },
    )
    if not note_result["ok"]:
        demisto.error(
            "GuardianToolBridge: failed to post approval War Room note for approval_id={}: {}".format(
                approval_id, note_result["error"]
            )
        )

    return guardian_envelope(
        True, data={"approval_id": approval_id, "risk_tier": risk_tier, "posted_to_war_room": note_result["ok"]}
    )


def guardian_bridge_consume_approval_token(approval_id, tool_name, parsed_args):
    """Validate + consume a single-use approved-token for a single-tool
    (`kind:"tool"`) approval.

    The token IS `approval_id` itself -- there is no separate secret,
    because presenting it only ever authorizes execution if the matching
    ledger row is ALSO already `status:"approved"` (which only a human
    resolver, never the agent, can set -- see GuardianApprovalResolve). This
    validates the full tuple: `approval_id` + `tool_name` +
    `canonical(tool_args)` must all match the ledger row EXACTLY, the row must
    be `"approved"`, and it must not already be `consumed` -- then marks it
    `consumed` (so it can never be replayed) BEFORE returning success, in the
    same read-modify-write as the match check (a read-then-write against a
    single shared List with no native compare-and-swap this platform exposes
    to List writes -- see GuardianAuditWrite's "SINGLE-WRITER / RACE HANDLING"
    note for the same limitation on `guardian_audit`).

    Any failure here (ledger unreadable, id not found, wrong `kind`, not
    `approved`, already `consumed`, `tool_name`/args mismatch) is reported
    as `ok=False` with a specific reason -- the caller
    (`guardian_tool_bridge_run`) treats every one of these identically: DENY,
    never execute, never silently fall back to creating a fresh ask.

    DOUBLE-INVOCATION HARDENING
    ------------------------------------------------------------------
    Two genuinely concurrent `guardian_tool_bridge_run` calls presenting the
    SAME `approval_id` (e.g. GuardianReasoningTick's re-entrant loop
    double-dispatch risk) can both reach this function before either's own read-check-write has
    landed: both read the row as approved-and-unconsumed, both pass every
    check above, and -- absent any further protection -- both would mark it
    `consumed` and both would return `ok=True`, letting the caller dispatch
    a possibly-destructive command TWICE (e.g. two `xdr-isolate-endpoint`/
    `closeInvestigation` calls for one human approval). This function alone
    cannot fully close that window (there is no List-level CAS primitive
    this platform exposes via `getList`/`setList`) -- but it writes a fresh,
    random `claim_token` onto the row alongside `consumed:True` and returns
    it to the caller, so `guardian_tool_bridge_run` can perform ONE more
    fresh re-read (:func:`guardian_bridge_confirm_tool_claim`) IMMEDIATELY
    before actually dispatching the command, asking "is MY claim_token still
    the one on record?". Since `setList` fully overwrites the List's
    content, whichever writer's save the server processes LAST is the one
    whose data survives -- so that one final check reliably tells the writer
    who lost the race (their `claim_token` was silently clobbered) from the
    one who won, with a MUCH narrower residual window than this function's
    own read-check-write alone (just one more read, right before the one
    step that actually matters, rather than the full round trip of another
    caller's entire read-check-write). See
    :func:`guardian_bridge_confirm_tool_claim`'s own docstring for the exact
    mechanics and the residual (much narrower, not eliminated) race this
    still leaves.

    :return: A :func:`guardian_envelope`; ``data`` is ``{"row": <dict>,
        "claim_token": <str>}`` on success (the now-`consumed` row, and the
        fresh marker the caller must re-confirm immediately before
        executing).
    :rtype: ``dict``
    """
    ledger_result = guardian_bridge_load_approvals_ledger()
    if not ledger_result["ok"]:
        return guardian_envelope(False, error="approval ledger unreadable: {}".format(ledger_result["error"]))

    rows = ledger_result["data"]
    matched_index = None
    for index, row in enumerate(rows):
        if isinstance(row, dict) and row.get("approval_id") == approval_id:
            matched_index = index
            break
    if matched_index is None:
        return guardian_envelope(
            False, error="approval_id '{}' not found in guardian_approvals_ledger".format(approval_id)
        )

    row = rows[matched_index]
    if row.get("kind", GUARDIAN_APPROVAL_KIND_TOOL) != GUARDIAN_APPROVAL_KIND_TOOL:
        return guardian_envelope(
            False, error="approval_id '{}' is not a single-tool approval (kind={!r})".format(approval_id, row.get("kind"))
        )
    if row.get("status") != GUARDIAN_APPROVAL_STATUS_APPROVED:
        return guardian_envelope(
            False, error="approval_id '{}' is not approved (status={!r})".format(approval_id, row.get("status"))
        )
    if row.get("consumed"):
        return guardian_envelope(False, error="approval_id '{}' has already been consumed (replay denied)".format(approval_id))
    if row.get("tool_name") != tool_name:
        return guardian_envelope(
            False,
            error="approval_id '{}' was approved for tool '{}', not '{}'".format(
                approval_id, row.get("tool_name"), tool_name
            ),
        )
    if row.get("canonical_args") != guardian_bridge_canonical_json(parsed_args):
        return guardian_envelope(
            False, error="approval_id '{}' was approved for different arguments -- args must match exactly".format(approval_id)
        )

    ts, _ = guardian_bridge_get_server_time()
    claim_token = uuid.uuid4().hex
    row = dict(row)
    row["consumed"] = True
    row["consumed_ts"] = ts
    row["claim_token"] = claim_token
    rows[matched_index] = row

    save_result = guardian_bridge_save_approvals_ledger(rows)
    if not save_result["ok"]:
        return guardian_envelope(
            False, error="failed to mark approval_id '{}' consumed: {}".format(approval_id, save_result["error"])
        )

    return guardian_envelope(True, data={"row": row, "claim_token": claim_token})


def guardian_bridge_confirm_tool_claim(approval_id, claim_token):
    """Double-invocation hardening: immediately BEFORE actually executing a
    `require_approval`-tiered command authorized by a
    just-consumed single-tool approval token, re-read
    `guardian_approvals_ledger` FRESH one more time and confirm THIS
    invocation's own `claim_token` (the random per-consumption marker
    :func:`guardian_bridge_consume_approval_token` just wrote onto the row
    alongside `consumed:True`) is still the one on record.

    See :func:`guardian_bridge_consume_approval_token`'s own docstring for
    the double-invocation race this narrows (two concurrent callers both
    passing the approved-and-unconsumed check before either's write lands).
    This is the second half of that hardening: since `setList` fully
    overwrites the List's content, whichever writer's save the server
    processed LAST is the one whose `claim_token` survives -- so re-reading
    right here, immediately before dispatch, and comparing against the
    token THIS call itself just wrote, reliably distinguishes "I won the
    race" (my token is still there) from "I lost it" (a concurrent
    consumer's write landed after mine and silently clobbered my claim) --
    with a MUCH narrower window than the original consume step alone (one
    more read, right before the one place that actually matters, instead of
    the full round trip of another caller's entire read-check-write). This
    does NOT achieve true atomicity -- a third overwrite landing in the
    instant between THIS read and the actual `guardian_execute` call is
    still theoretically possible, and closing that fully would require
    either a real List-level compare-and-swap primitive this platform
    doesn't expose via `getList`/`setList`, or moving the ledger off Lists
    entirely. This is the pragmatic minimum hardening; the residual window is
    documented here rather than silently assumed away.

    :param approval_id: The single-tool approval id being spent.
    :type approval_id: ``str``
    :param claim_token: The marker THIS invocation's own
        :func:`guardian_bridge_consume_approval_token` call wrote onto the
        row.
    :type claim_token: ``str``
    :return: A :func:`guardian_envelope`; ``ok=False`` means the claim was
        lost to a concurrent consumer (or the row/ledger is otherwise no
        longer readable/consistent) -- the caller MUST NOT execute in that
        case.
    :rtype: ``dict``
    """
    ledger_result = guardian_bridge_load_approvals_ledger()
    if not ledger_result["ok"]:
        return guardian_envelope(
            False,
            error="approval ledger unreadable during pre-execute re-confirmation: {}".format(ledger_result["error"]),
        )

    row = None
    for candidate in ledger_result["data"]:
        if isinstance(candidate, dict) and candidate.get("approval_id") == approval_id:
            row = candidate
            break
    if row is None:
        return guardian_envelope(
            False,
            error="approval_id '{}' no longer found in guardian_approvals_ledger during "
            "pre-execute re-confirmation".format(approval_id),
        )

    if row.get("consumed") is True and row.get("claim_token") == claim_token:
        return guardian_envelope(True)

    return guardian_envelope(
        False,
        error="approval_id '{}' claim_token no longer matches the persisted ledger row -- a concurrent "
        "consumer won the race (double-invocation protection; action NOT executed)".format(approval_id),
    )


def guardian_bridge_consume_plan_step(plan_approval_id, step_index, tool_name, parsed_args):
    """The plan-approval counterpart of
    :func:`guardian_bridge_consume_approval_token` -- validates + consumes
    ONE step of an already-`approved` `kind:"plan"` ledger row.

    Every check mirrors the single-tool path exactly, one level deeper
    (`row["steps"][step_index]` instead of the row itself): `step_index`
    must be a valid index into `steps`, that step must carry the matching
    `tool_name`/`canonical_args`, and must not already be `consumed`. Only
    that ONE step is marked consumed -- a plan's other steps remain
    independently consumable (or already consumed) regardless of this call's
    outcome. The same double-invocation hardening as the single-tool path
    applies: a fresh random `claim_token` is written
    onto the STEP alongside `consumed:True` and returned to the caller, so
    `guardian_tool_bridge_run` can re-confirm it (:func:`guardian_bridge_confirm_plan_step_claim`)
    immediately before dispatch -- see :func:`guardian_bridge_consume_approval_token`'s
    docstring for the full race this narrows.

    :return: A :func:`guardian_envelope`; ``data`` is
        ``{"row": <dict>, "step": <dict>, "claim_token": <str>}`` on
        success.
    :rtype: ``dict``
    """
    ledger_result = guardian_bridge_load_approvals_ledger()
    if not ledger_result["ok"]:
        return guardian_envelope(False, error="approval ledger unreadable: {}".format(ledger_result["error"]))

    rows = ledger_result["data"]
    matched_index = None
    for index, row in enumerate(rows):
        if isinstance(row, dict) and row.get("approval_id") == plan_approval_id:
            matched_index = index
            break
    if matched_index is None:
        return guardian_envelope(False, error="plan approval_id '{}' not found in guardian_approvals_ledger".format(plan_approval_id))

    row = rows[matched_index]
    if row.get("kind") != GUARDIAN_APPROVAL_KIND_PLAN:
        return guardian_envelope(
            False, error="approval_id '{}' is not a plan approval (kind={!r})".format(plan_approval_id, row.get("kind"))
        )
    if row.get("status") != GUARDIAN_APPROVAL_STATUS_APPROVED:
        return guardian_envelope(
            False, error="plan approval_id '{}' is not approved (status={!r})".format(plan_approval_id, row.get("status"))
        )

    steps = row.get("steps")
    if not isinstance(steps, list) or not isinstance(step_index, int) or not (0 <= step_index < len(steps)):
        return guardian_envelope(
            False, error="plan approval_id '{}' has no step index {}".format(plan_approval_id, step_index)
        )

    step = steps[step_index]
    if not isinstance(step, dict):
        return guardian_envelope(False, error="plan approval_id '{}' step {} is malformed".format(plan_approval_id, step_index))
    if step.get("consumed"):
        return guardian_envelope(
            False, error="plan approval_id '{}' step {} has already been consumed (replay denied)".format(plan_approval_id, step_index)
        )
    if step.get("tool_name") != tool_name:
        return guardian_envelope(
            False,
            error="plan approval_id '{}' step {} was approved for tool '{}', not '{}'".format(
                plan_approval_id, step_index, step.get("tool_name"), tool_name
            ),
        )
    if step.get("canonical_args") != guardian_bridge_canonical_json(parsed_args):
        return guardian_envelope(
            False,
            error="plan approval_id '{}' step {} was approved for different arguments -- args must match exactly".format(
                plan_approval_id, step_index
            ),
        )

    ts, _ = guardian_bridge_get_server_time()
    claim_token = uuid.uuid4().hex
    step = dict(step)
    step["consumed"] = True
    step["consumed_ts"] = ts
    step["claim_token"] = claim_token
    steps = list(steps)
    steps[step_index] = step
    row = dict(row)
    row["steps"] = steps
    rows[matched_index] = row

    save_result = guardian_bridge_save_approvals_ledger(rows)
    if not save_result["ok"]:
        return guardian_envelope(
            False, error="failed to mark plan approval_id '{}' step {} consumed: {}".format(plan_approval_id, step_index, save_result["error"])
        )

    return guardian_envelope(True, data={"row": row, "step": step, "claim_token": claim_token})


def guardian_bridge_confirm_plan_step_claim(plan_approval_id, step_index, claim_token):
    """The plan-step counterpart of :func:`guardian_bridge_confirm_tool_claim`
    -- see that function's docstring for the double-invocation race this
    narrows. Re-reads `guardian_approvals_ledger` fresh, immediately before
    dispatch, and confirms THIS invocation's own `claim_token` is still the
    one recorded on `steps[step_index]`.

    :param plan_approval_id: The plan approval id.
    :type plan_approval_id: ``str``
    :param step_index: The 0-based step index being spent.
    :type step_index: ``int``
    :param claim_token: The marker THIS invocation's own
        :func:`guardian_bridge_consume_plan_step` call wrote onto the step.
    :type claim_token: ``str``
    :return: A :func:`guardian_envelope`; ``ok=False`` means the claim was
        lost to a concurrent consumer (or the row/step/ledger is otherwise
        no longer readable/consistent) -- the caller MUST NOT execute in
        that case.
    :rtype: ``dict``
    """
    ledger_result = guardian_bridge_load_approvals_ledger()
    if not ledger_result["ok"]:
        return guardian_envelope(
            False,
            error="approval ledger unreadable during pre-execute re-confirmation: {}".format(ledger_result["error"]),
        )

    row = None
    for candidate in ledger_result["data"]:
        if isinstance(candidate, dict) and candidate.get("approval_id") == plan_approval_id:
            row = candidate
            break
    if row is None:
        return guardian_envelope(
            False,
            error="plan approval_id '{}' no longer found in guardian_approvals_ledger during "
            "pre-execute re-confirmation".format(plan_approval_id),
        )

    steps = row.get("steps")
    if not isinstance(steps, list) or not (0 <= step_index < len(steps)):
        return guardian_envelope(
            False,
            error="plan approval_id '{}' has no step index {} during pre-execute re-confirmation".format(
                plan_approval_id, step_index
            ),
        )

    step = steps[step_index]
    if isinstance(step, dict) and step.get("consumed") is True and step.get("claim_token") == claim_token:
        return guardian_envelope(True)

    return guardian_envelope(
        False,
        error="plan approval_id '{}' step {} claim_token no longer matches the persisted ledger row -- a "
        "concurrent consumer won the race (double-invocation protection; action NOT executed)".format(
            plan_approval_id, step_index
        ),
    )


def _guardian_bridge_shape_repr(value):
    """Short, safe-to-log description of an unexpected value's shape."""
    if isinstance(value, dict):
        return "dict with keys {}".format(sorted(str(k) for k in value.keys()))
    return "{} ({!r})".format(type(value).__name__, value)[:200]


def guardian_bridge_load_list_json(list_name):
    """Read + JSON-parse one Guardian config List's `data` payload via
    `guardian_execute('getList', ...)`.

    Every gate this bridge consults (`guardian_kill_switch`,
    `guardian_tool_denylist`, `guardian_policy`, `guardian_settings`) is a
    List read of this exact shape, so this is the single reducer all four
    call.

    :param list_name: The XSOAR List name.
    :type list_name: ``str``
    :return: A :func:`guardian_envelope`; ``data`` is the parsed JSON value
        (dict or list) on success.
    :rtype: ``dict``
    """
    result = guardian_execute("getList", {"listName": list_name})
    if not result["ok"]:
        return guardian_envelope(
            False,
            error="failed to read '{}': {}".format(list_name, result["error"]),
            retryable=result["retryable"],
            is_auth_error=result["is_auth_error"],
        )

    contents = None
    for entry in result["data"] or []:
        if isinstance(entry, dict) and entry.get("Contents") is not None:
            contents = entry["Contents"]

    if contents is None:
        return guardian_envelope(False, error="getList '{}' returned no Contents".format(list_name))

    if isinstance(contents, str):
        text = contents.strip()
        if not text:
            return guardian_envelope(False, error="getList '{}' returned blank Contents".format(list_name))
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            return guardian_envelope(
                False,
                error="NEEDS_CONTEXT: '{}' Contents is a string but not valid JSON: {}".format(list_name, exc),
            )
    elif isinstance(contents, (dict, list)):
        parsed = contents
    else:
        return guardian_envelope(
            False,
            error="NEEDS_CONTEXT: '{}' Contents has unexpected type {}".format(
                list_name, _guardian_bridge_shape_repr(contents)
            ),
        )

    return guardian_envelope(True, data=parsed)


def guardian_bridge_parse_tool_args(tool_args):
    """Parse the `tool_args` argument into a dict for dispatch. Never raises.

    Accepts a JSON object string (the common case -- war-room CLI args
    arrive as strings), an already-a-dict value (the common case when called
    via `demisto.executeCommand` from another script, e.g.
    GuardianReasoningTick), or ``None``/blank (no arguments). Anything else
    (malformed JSON, a JSON array/scalar, an unexpected type) is treated as
    "no arguments" plus a warning -- never blocks the call outright, since a
    malformed-but-harmless `tool_args` shouldn't itself deny/error a tool
    call that the denylist/policy gates would otherwise allow.

    :param tool_args: The raw `tool_args` argument value.
    :return: ``(parsed_args, warning)`` -- ``parsed_args`` is always a
        ``dict`` (empty on any parse failure); ``warning`` is ``None`` on
        the clean path.
    :rtype: ``tuple(dict, str or None)``
    """
    if tool_args is None:
        return {}, None
    if isinstance(tool_args, dict):
        return tool_args, None
    if isinstance(tool_args, str):
        text = tool_args.strip()
        if not text:
            return {}, None
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            return {}, "tool_args is not valid JSON ({}); treated as no arguments".format(exc)
        if isinstance(parsed, dict):
            return parsed, None
        return {}, "tool_args parsed to a non-object JSON value ({}); treated as no arguments".format(
            _guardian_bridge_shape_repr(parsed)
        )
    return {}, "tool_args has unexpected type {}; treated as no arguments".format(type(tool_args).__name__)


def guardian_bridge_summarize_target(parsed_args):
    """Build the "concise arg summary" passed to `GuardianAuditWrite` as
    `target` -- redacted first (never leak a secret into the audit row's
    target field), then length-capped.

    :param parsed_args: The parsed tool-call arguments.
    :type parsed_args: ``dict``
    :return: A short, redacted string, or ``None`` if there were no
        arguments at all.
    :rtype: ``str`` or ``None``
    """
    if not parsed_args:
        return None
    redacted = guardian_redact(parsed_args)
    try:
        text = json.dumps(redacted, sort_keys=True, default=str)
    except Exception:
        text = str(redacted)
    if len(text) > GUARDIAN_TARGET_SUMMARY_MAX_LEN:
        text = text[: GUARDIAN_TARGET_SUMMARY_MAX_LEN - 3] + "..."
    return text


def guardian_bridge_check_kill_switch():
    """Step 1: read `guardian_kill_switch`. See the module docstring's
    "FAIL-OPEN VS FAIL-CLOSED" section -- this is the ONE fail-open gate in
    the whole bridge, by design, but ONLY in `manual` mode (the default).

    SECURITY-CRITICAL: when `guardian_bridge_get_approval_mode()` reports
    `"bypass"` for this incident (pre-approved autonomous containment is
    active -- see the module docstring), a degraded (unreadable/malformed) read
    instead fails CLOSED (halted). An unreadable kill switch in `bypass`
    mode could otherwise silently mask a genuine operator halt request for
    as long as the List stays unreadable, exactly while auto-execution
    keeps running with no human in the loop -- the one scenario the kill
    switch exists to guard against. The approval mode is read ONLY on this
    already-degraded path (`demisto.incident()` is never consulted on the
    common, healthy-List path below), so the clean case pays no extra cost.

    :return: ``{"halted": bool, "note": str or None}``. ``note`` is set on
        the degraded (unreadable/malformed) path, describing what happened
        (also logged via ``demisto.error``) -- ``None`` on the clean path.
    :rtype: ``dict``
    """
    load_result = guardian_bridge_load_list_json(GUARDIAN_KILL_SWITCH_LIST_NAME)
    if not load_result["ok"]:
        if guardian_bridge_get_approval_mode() == "bypass":
            note = (
                "guardian_kill_switch unreadable ({}) -- autonomous bypass mode is ACTIVE for this "
                "incident, so this degraded read fails CLOSED (halted) instead of open: an unreadable "
                "kill switch must never silently mask a halt request while pre-approved auto-execution "
                "keeps running unattended.".format(load_result["error"])
            )
            demisto.error("GuardianToolBridge: {}".format(note))
            return {"halted": True, "note": note}
        note = (
            "guardian_kill_switch unreadable ({}) -- manual mode treats an unreadable kill switch as "
            "NOT halted (a deliberate fail-OPEN for this one gate only in manual mode; the denylist "
            "and policy gates below are always fail-CLOSED, and this same gate fails CLOSED instead "
            "when the incident is in bypass mode).".format(load_result["error"])
        )
        demisto.error("GuardianToolBridge: {}".format(note))
        return {"halted": False, "note": note}

    data = load_result["data"]
    if not isinstance(data, dict):
        if guardian_bridge_get_approval_mode() == "bypass":
            note = (
                "guardian_kill_switch content has unexpected shape ({}) -- autonomous bypass mode is "
                "ACTIVE for this incident, so this fails CLOSED (halted) instead of open.".format(
                    _guardian_bridge_shape_repr(data)
                )
            )
            demisto.error("GuardianToolBridge: {}".format(note))
            return {"halted": True, "note": note}
        note = "guardian_kill_switch content has unexpected shape ({}) -- treated as NOT halted.".format(
            _guardian_bridge_shape_repr(data)
        )
        demisto.error("GuardianToolBridge: {}".format(note))
        return {"halted": False, "note": note}

    return {"halted": data.get("enabled") is True, "note": None}


def guardian_bridge_split_denylist_entries(denied):
    """Split `guardian_tool_denylist`'s `denied` array into bare command
    names (full exclusion) and `command:targetList` argument-level rules.

    The arg-level rules are returned as `(command, target)` TUPLES, for exact
    dispatch-time matching against a real call's arguments (GuardianToolCatalogBuilder
    keeps the raw `"command:target"` strings, since it only reports them).

    :param denied: The denylist's `denied` array.
    :type denied: ``list``
    :return: ``(bare_names: set, arg_rules: set of (str, str) tuples)``
    :rtype: ``tuple(set, set)``
    """
    bare_names = set()
    arg_rules = set()
    for entry in denied or []:
        if not isinstance(entry, str) or not entry:
            continue
        if ":" in entry:
            command, _, target = entry.partition(":")
            if command and target:
                arg_rules.add((command, target))
        else:
            bare_names.add(entry)
    return bare_names, arg_rules


def guardian_bridge_check_denylist(tool_name, parsed_args):
    """Step 2: the security boundary. Enforces both the bare denylist and
    the arg-level self-escape rule (see the module docstring's "SELF-ESCAPE
    PREVENTION" section for the two-part enforcement).

    Fail-closed: an unreadable/malformed `guardian_tool_denylist` denies the
    call rather than allowing it through.

    :param tool_name: The command the model wants to call.
    :type tool_name: ``str``
    :param parsed_args: The parsed tool-call arguments (used to read the
        `listName` argument for the arg-level check).
    :type parsed_args: ``dict``
    :return: A :func:`guardian_envelope`; ``ok=True`` means "not denied,
        proceed to the policy check"; ``ok=False`` means denied, with
        ``error`` explaining why.
    :rtype: ``dict``
    """
    load_result = guardian_bridge_load_list_json(GUARDIAN_DENYLIST_LIST_NAME)
    if not load_result["ok"]:
        return guardian_envelope(
            False,
            error="guardian_tool_denylist unreadable -- fail-closed deny: {}".format(load_result["error"]),
        )

    data = load_result["data"]
    if not isinstance(data, dict) or not isinstance(data.get("denied"), list):
        return guardian_envelope(
            False,
            error="NEEDS_CONTEXT: guardian_tool_denylist shape unexpected (missing/invalid 'denied' "
            "array, got {}) -- fail-closed deny.".format(_guardian_bridge_shape_repr(data)),
        )

    bare_names, arg_rules = guardian_bridge_split_denylist_entries(data["denied"])

    if tool_name in bare_names:
        return guardian_envelope(False, error="'{}' is on the bare guardian_tool_denylist".format(tool_name))

    protected_lists = data.get("protected_lists")
    protected_lists = set(protected_lists) if isinstance(protected_lists, list) else set()
    protected_lists.update(GUARDIAN_RUNTIME_PROTECTED_LISTS)
    target_list_name = parsed_args.get("listName") if isinstance(parsed_args, dict) else None
    if isinstance(target_list_name, str):
        # Whitespace-normalize ONLY -- NOT lowercased. XSOAR list names are
        # case-SENSITIVE server-side, so lowercasing here would silently
        # treat two distinct real Lists (e.g. "Guardian_Policy" vs.
        # "guardian_policy") as the same one, which could deny a legitimate
        # call against an unrelated, differently-cased list. A leading/
        # trailing space, on the other hand, has no such legitimate use --
        # XSOAR resolves the list server-side by exact name, so " guardian_
        # policy " and "guardian_policy" already name the SAME real list;
        # stripping here just closes a whitespace-padding dodge of this
        # in-memory comparison, it doesn't change what the server resolves.
        target_list_name = target_list_name.strip()

    if target_list_name:
        if (tool_name, target_list_name) in arg_rules:
            return guardian_envelope(
                False,
                error="'{}' targeting protected list '{}' is denied by denylist rule '{}:{}'".format(
                    tool_name, target_list_name, tool_name, target_list_name
                ),
            )
        if tool_name in GUARDIAN_LIST_MUTATING_COMMANDS and target_list_name in protected_lists:
            return guardian_envelope(
                False,
                error="'{}' targeting '{}' is denied -- '{}' is a protected_list in "
                "guardian_tool_denylist (self-escape prevention)".format(
                    tool_name, target_list_name, target_list_name
                ),
            )

    return guardian_envelope(True)


def guardian_bridge_validate_allowlist_payload(data, list_name):
    """Normalize an allowlist payload to its valid command-name set."""
    if isinstance(data, dict) and isinstance(data.get("commands"), list):
        commands = data["commands"]
    elif isinstance(data, list):
        commands = data
    else:
        return guardian_envelope(
            False,
            error="NEEDS_CONTEXT: {} shape unexpected (expected a dict with a 'commands' array, or a bare "
            "array, got {}) -- fail-closed deny.".format(list_name, _guardian_bridge_shape_repr(data)),
        )
    return guardian_envelope(True, data={name for name in commands if isinstance(name, str) and name})


def guardian_bridge_load_effective_allowlist():
    """Load the operator-managed allowlist, falling back only before bootstrap."""
    runtime = guardian_bridge_load_list_json(GUARDIAN_RUNTIME_ALLOWLIST_LIST_NAME)
    if runtime["ok"]:
        checked = guardian_bridge_validate_allowlist_payload(runtime["data"], GUARDIAN_RUNTIME_ALLOWLIST_LIST_NAME)
        if not checked["ok"]:
            return checked
        return guardian_envelope(True, data={"commands": checked["data"], "source": "runtime"})
    if GUARDIAN_LIST_NOT_FOUND_HINT not in (runtime["error"] or "").lower():
        return guardian_envelope(
            False,
            error="guardian_tool_allowlist_runtime unreadable -- fail-closed deny: {}".format(runtime["error"]),
            retryable=runtime["retryable"],
            is_auth_error=runtime["is_auth_error"],
        )

    baseline = guardian_bridge_load_list_json(GUARDIAN_STATIC_ALLOWLIST_LIST_NAME)
    if not baseline["ok"]:
        return guardian_envelope(
            False,
            error="guardian_tool_allowlist unreadable -- fail-closed deny: {}".format(baseline["error"]),
            retryable=baseline["retryable"],
            is_auth_error=baseline["is_auth_error"],
        )
    checked = guardian_bridge_validate_allowlist_payload(baseline["data"], GUARDIAN_STATIC_ALLOWLIST_LIST_NAME)
    if not checked["ok"]:
        return checked
    return guardian_envelope(True, data={"commands": checked["data"], "source": "baseline_fallback"})


def guardian_bridge_check_allowlist(tool_name):
    """Step 3: the default-deny permitted-set gate. See the module
    docstring's "DEFAULT-DENY ALLOWLIST ENFORCEMENT" section for the
    vulnerability this closes: without this gate, ANY command that is neither
    on the bare `guardian_tool_denylist` NOR present in `guardian_policy` would
    execute ungated -- e.g. a model-emitted, off-catalogue
    `demisto-api-post {uri, body}` call reaching XSOAR's entire REST API.

    This function only answers "is `tool_name` on the read-only curated
    allowlist?" -- the OTHER half of the permitted-set OR ("present in
    `guardian_policy`") is answered by `guardian_bridge_check_policy`'s own
    `in_policy` field; `guardian_tool_bridge_run` combines both.

    Fail-closed, the SAME way `guardian_bridge_check_denylist` is: an
    unreadable/malformed `guardian_tool_allowlist` denies the call
    OUTRIGHT (``ok=False``) -- regardless of what `guardian_policy` would
    otherwise say -- for the same "can't confirm the negative, so fail
    closed" reason as the denylist. This bridge cannot safely
    compute the permitted-command set without being able to read this
    List, and the safer failure mode is denying every call while the List
    is unreadable, not silently falling back to "policy alone decides."

    The editable runtime List wins after it is created. Before then, only a
    conclusive "item not found" response falls back to the pack baseline.
    Both sources accept either `{"commands": [...]}` or a bare array.

    :param tool_name: The command the model wants to call (already
        canonicalized -- stripped of leading/trailing whitespace -- by
        `guardian_tool_bridge_run` before this is called).
    :type tool_name: ``str``
    :return: A :func:`guardian_envelope`; ``data`` is
        ``{"on_allowlist": bool, "source": str}`` when ``ok=True``. ``ok=False`` means the
        allowlist itself could not be read/parsed -- callers MUST treat
        that as an outright deny, never as "not on allowlist, fall through
        to policy."
    :rtype: ``dict``
    """
    load_result = guardian_bridge_load_effective_allowlist()
    if not load_result["ok"]:
        return guardian_envelope(
            False, error=load_result["error"], retryable=load_result["retryable"], is_auth_error=load_result["is_auth_error"]
        )
    return guardian_envelope(
        True,
        data={
            "on_allowlist": tool_name in load_result["data"]["commands"],
            "source": load_result["data"]["source"],
        },
    )


def guardian_bridge_check_policy(tool_name):
    """Step 4: the approval-gate policy tier check.

    Fail-closed: an unreadable/malformed `guardian_policy` denies the call.
    An unrecognized (non-`GUARDIAN_POLICY_VALID_TIERS`) tier value is a
    data-quality problem in the policy List itself and is ALSO treated as
    fail-closed deny, never guessed at.

    `require_approval` is a REAL gate: see
    `guardian_tool_bridge_run`'s own handling of `policy_check["decision"]
    == "require_approval"` for the park/resolve/consume/re-dispatch flow --
    this function itself only classifies the tier, it doesn't gate.

    :param tool_name: The command the model wants to call.
    :type tool_name: ``str``
    :return: ``{"decision": "allow"|"deny"|"require_approval", "in_policy":
        bool, "error": str or None}``. ``in_policy`` is ``True`` only when
        `tool_name` is an explicit key in `guardian_policy` (i.e. a
        deliberately-classified command) -- ``False`` when `guardian_policy`
        itself was unreadable/malformed (nothing could be checked) AND when
        it was readable but simply didn't mention `tool_name`. The
        default-deny gate (`guardian_tool_bridge_run`) uses this to tell
        "known-but-untiered" apart from "never classified at all" -- the
        latter is the off-catalogue-command case, denied UNLESS the command
        is separately on `guardian_tool_allowlist`.
    :rtype: ``dict``
    """
    load_result = guardian_bridge_load_list_json(GUARDIAN_POLICY_LIST_NAME)
    if not load_result["ok"]:
        return {
            "decision": "deny",
            "in_policy": False,
            "error": "guardian_policy unreadable -- fail-closed deny: {}".format(load_result["error"]),
        }

    data = load_result["data"]
    if not isinstance(data, dict):
        return {
            "decision": "deny",
            "in_policy": False,
            "error": "NEEDS_CONTEXT: guardian_policy has unexpected shape ({}) -- fail-closed deny.".format(
                _guardian_bridge_shape_repr(data)
            ),
        }

    tier = data.get(tool_name)
    in_policy = tier is not None

    if tier is None:
        # Absent from guardian_policy entirely: this alone does not mean
        # "proceed" -- `in_policy=False` here signals
        # `guardian_tool_bridge_run`'s default-deny gate to check whether
        # `tool_name` is at least on `guardian_tool_allowlist` before
        # trusting this "allow". A command that is on NEITHER List is
        # denied by that gate before this "allow" decision is ever acted
        # on.
        return {"decision": "allow", "in_policy": False, "error": None}

    if tier == "deny":
        return {
            "decision": "deny",
            "in_policy": True,
            "error": "'{}' is tier 'deny' in guardian_policy".format(tool_name),
        }

    if tier == "require_approval":
        return {"decision": "require_approval", "in_policy": True, "error": None}

    if tier == "allow":
        return {"decision": "allow", "in_policy": True, "error": None}

    return {
        "decision": "deny",
        "in_policy": in_policy,
        "error": "NEEDS_CONTEXT: guardian_policy tier for '{}' is {!r}, not one of {} -- "
        "fail-closed deny.".format(tool_name, tier, GUARDIAN_POLICY_VALID_TIERS),
    }


def _guardian_bridge_is_recognized(tool_name):
    """Return ``True`` if `tool_name` is EITHER on `guardian_tool_allowlist`
    OR an explicit key in `guardian_policy` -- the same "permitted set" test
    `guardian_tool_bridge_run`'s own default-deny gate applies, reused here
    ONLY to decide whether a name is worth resolving to (see
    `guardian_bridge_resolve_tool_alias`). Never used to gate a call by
    itself -- `guardian_tool_bridge_run` re-runs the full denylist/allowlist/
    policy sequence against whatever name this helped choose.

    Fail-closed by construction: an unreadable `guardian_tool_allowlist`
    makes `guardian_bridge_check_allowlist` return ``ok=False``, which this
    treats as "not recognized" (falls through to the policy check, then
    ``False`` if that also doesn't recognize it) -- never as a reason to
    guess a name is fine.
    """
    allowlist_check = guardian_bridge_check_allowlist(tool_name)
    if allowlist_check["ok"] and allowlist_check["data"]["on_allowlist"]:
        return True
    return bool(guardian_bridge_check_policy(tool_name)["in_policy"])


def guardian_bridge_resolve_tool_alias(tool_name):
    """Resolve a mangled command name to the real one, SECURITY-PRESERVING:
    a model sometimes emits a command name with the wrong word
    separator -- most often underscores where the real XSOAR command uses
    hyphens (e.g. ``xdr_endpoint_tag_add`` for the real
    ``xdr-endpoint-tag-add``). The default-deny bridge correctly denies the
    mangled name (it matches nothing on `guardian_tool_allowlist` or in
    `guardian_policy`), which is safe but a reliability papercut when the
    model's INTENT was clearly the real, already-permitted command.

    This performs NO gating of its own -- it is a pure name-lookup
    substitution, applied ONCE, before any gate runs:

    - If `tool_name` AS GIVEN is already recognized (on the allowlist or an
      explicit `guardian_policy` key), it is returned UNCHANGED. No swapped
      variant is even attempted -- the common/healthy-path case costs
      nothing beyond the allowlist/policy reads `guardian_tool_bridge_run`
      already needs for Steps 3-4.
    - Only when `tool_name` as-is is recognized by NEITHER List is the
      underscore<->hyphen-swapped variant tried (only when the name has
      ONE of the two separators, never both -- a name mixing `_` and `-`,
      or with neither, has no unambiguous swap and is left untouched rather
      than guessed at). If that swapped spelling IS recognized, it is
      returned as the canonical name.
    - If NEITHER the original NOR the swapped spelling is recognized,
      `tool_name` is returned UNCHANGED -- the caller's default-deny gate
      then denies it exactly as if this function did not exist.

    CRITICAL invariant this preserves: the name this returns still passes
    through the FULL, unmodified denylist -> allowlist -> policy ->
    default-deny sequence in `guardian_tool_bridge_run`, at the SAME tier a
    direct call with that spelling would get (e.g. `require_approval` stays
    `require_approval`, never silently upgraded to `allow`). This can only
    ever help a mangled ALIAS of an ALREADY-PERMITTED command resolve to
    that command's real name -- it can never widen what is permitted, since
    "permitted" here is decided by the exact same fail-closed
    allowlist/policy reads every other call goes through.

    :param tool_name: The already-canonicalized (`.strip()`-ped) tool name.
    :type tool_name: ``str``
    :return: The canonical name to use for the rest of the pipeline.
    :rtype: ``str``
    """
    if "_" in tool_name and "-" not in tool_name:
        swapped = tool_name.replace("_", "-")
    elif "-" in tool_name and "_" not in tool_name:
        swapped = tool_name.replace("-", "_")
    else:
        return tool_name

    if _guardian_bridge_is_recognized(tool_name):
        return tool_name
    if _guardian_bridge_is_recognized(swapped):
        return swapped
    return tool_name


def guardian_bridge_clamp_evidence_arg(value, low, high):
    """``value`` as an int clamped to ``[low, high]``, or ``None`` when it is not a real positive number."""
    if isinstance(value, str):
        try:
            value = float(value.strip())
        except ValueError:
            return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        return None
    return max(low, min(int(value), high))


def guardian_bridge_load_evidence_limits(truncate_arg=None, head_tail_arg=None):
    """The result-size ceiling and head/tail size (bytes) this call shapes its result with.

    The same numbers the agent loop uses, in this order:

    1. the caller's own argument (the loop passes the ceiling it derived from the model's input budget),
       clamped to sane bounds;
    2. the numbers the run already settled on in context (the playbook's ``Guardian.ModelProfile`` snapshot,
       else the loop's ``Guardian.Loop.model_params``);
    3. a fresh resolution from ``guardian_settings`` + ``guardian_model_profile`` + the model catalogue
       (an explicit ``evidence_truncate_bytes`` in ``guardian_settings`` still wins there);
    4. the built-in defaults.

    A missing or unreadable List must never block a tool result from being returned, only the exact byte
    ceiling used to size-cap it.

    :return: ``(truncate_bytes: int, head_tail_bytes: int)``
    :rtype: ``tuple(int, int)``
    """
    explicit = guardian_bridge_clamp_evidence_arg(
        truncate_arg, GUARDIAN_BRIDGE_EVIDENCE_ARG_MIN_BYTES, GUARDIAN_BRIDGE_EVIDENCE_ARG_MAX_BYTES)
    if explicit is not None:
        head_tail = guardian_bridge_clamp_evidence_arg(
            head_tail_arg, GUARDIAN_BRIDGE_EVIDENCE_HEAD_TAIL_ARG_MIN_BYTES, max(explicit // 2, 1))
        return explicit, head_tail if head_tail is not None else guardian_evidence_head_tail(explicit)

    try:
        params, _source = guardian_run_model_params()
    except Exception:
        params = None
    if params is None:
        load_result = guardian_bridge_load_list_json(GUARDIAN_SETTINGS_LIST_NAME)
        settings = load_result["data"] if load_result["ok"] and isinstance(load_result["data"], dict) else {}
        try:
            params, _note = guardian_model_params_for_run(settings)
        except Exception:
            params = None
        if params is None:
            limits = guardian_derive_limits(None, settings)
            return limits["evidence_truncate_bytes"], limits["evidence_head_tail_bytes"]
    limits = params["limits"]
    return limits["evidence_truncate_bytes"], limits["evidence_head_tail_bytes"]


def guardian_bridge_extract_contents(entries):
    """Pull each entry's `Contents` value out of a raw `executeCommand`
    entry list, dropping XSOAR's internal entry envelope (`Type`,
    `EntryContext`, `HumanReadable`, etc.) -- the model only needs the
    payload data, not the transport wrapper.

    :param entries: The raw entry list (`guardian_execute`'s ``data``).
    :type entries: ``list`` or ``None``
    :return: The single entry's `Contents` value directly if exactly one
        entry carried one (the common case); a list of each entry's
        `Contents` for a genuine multi-entry response; ``None`` if no entry
        carried a `Contents` key at all.
    """
    contents_list = [entry.get("Contents") for entry in entries or [] if isinstance(entry, dict) and "Contents" in entry]
    if not contents_list:
        return None
    if len(contents_list) == 1:
        return contents_list[0]
    return contents_list


def guardian_bridge_reduce_list_structurally(items, budget_bytes):
    """Reduce an oversized LIST result by dropping TRAILING ITEMS wholesale,
    never slicing through the middle of a serialized value the way a raw byte
    truncation would. The generic byte ceiling keeps an oversized record
    parseable; this keeps it useful -- every item this returns is complete,
    valid JSON on its own, not a mid-string fragment.

    Deliberately simple (drop-from-the-tail, not a "most important rows
    first" ranking): tool results this bridge shapes are heterogeneous
    (arbitrary allowlisted commands), so there is no general, safe way to
    know which rows matter most across all of them -- keeping the ORIGINAL
    ORDER's leading items is the one universally defensible choice, and
    matches how the head+tail byte-slice fallback already privileges the
    front of the payload too.

    A reduction step that can fail to reduce has to stop, not retry: if even
    the FIRST item alone is at or over
    `budget_bytes`, this still returns that one item (never an empty list --
    an empty result is strictly worse than one real, complete item) with
    every remaining item counted as omitted, rather than looping or
    attempting to slice that one oversized item itself. The caller
    (:func:`guardian_bridge_shape_result`) is expected to fall back to the
    byte-slice path when this can't usefully reduce anything (``omitted``
    comes back ``0`` while the caller's own ceiling was still exceeded --
    i.e. a single-item list whose one item is itself oversized).

    :param items: The (already redacted) list to reduce.
    :type items: ``list``
    :param budget_bytes: Serialized-size ceiling for the returned list,
        BEFORE the caller adds its own trailing summary marker.
    :type budget_bytes: ``int``
    :return: ``(kept_items, omitted_count)``. ``omitted_count`` is ``0`` if
        every item fit inside the budget.
    :rtype: ``tuple(list, int)``
    """
    kept = []
    used_bytes = 2  # "[" + "]"
    for index, item in enumerate(items):
        try:
            item_json = json.dumps(item, default=str)
        except Exception:
            item_json = str(item)
        item_bytes = len(item_json.encode("utf-8", errors="replace")) + 1  # +1 for the separating comma
        if kept and used_bytes + item_bytes > budget_bytes:
            return kept, len(items) - index
        kept.append(item)
        used_bytes += item_bytes
    return kept, 0


def guardian_bridge_shape_result(entries, truncate_arg=None, head_tail_arg=None):
    """Step 6: shape a raw `executeCommand` entry list into the redacted,
    size-capped `result` returned to the model. See the module docstring's
    "EVIDENCE SHAPING" section for why redaction MUST happen before
    serialization/truncation, and for the structural-vs-byte-slice reduction
    approach.

    :param entries: The raw entry list (`guardian_execute`'s ``data``).
    :type entries: ``list`` or ``None``
    :param truncate_arg: The per-result ceiling the caller (the agent loop) derived for the run's model, or
        ``None`` to work it out here (see :func:`guardian_bridge_load_evidence_limits`).
    :param head_tail_arg: The matching head/tail size, or ``None``.
    :return: ``(payload, truncated, note, full_payload)``. ``payload`` is the
        redacted structured value unchanged if small enough; a STRUCTURALLY
        reduced list (kept leading items + a trailing summary marker dict)
        when the redacted result is an oversized list; or a truncated
        head+tail STRING with a marker otherwise. ``truncated`` is a bool.
        ``note`` is ``None`` on the untruncated path, else a short
        human-readable description. ``full_payload`` is ``None`` on the
        untruncated path; otherwise the complete, REDACTED (never the raw
        pre-redaction value), pre-truncation payload -- the caller
        (`guardian_tool_bridge_run`) is the one that decides whether/how to
        actually attach it as a War Room file; this function only shapes.
    :rtype: ``tuple``
    """
    # Guardian's own section of an incident's details (GuardianIncidentSummary) never reaches the model, so a lookup of
    # the incident cannot hand it back its earlier conclusion as if it were evidence.
    contents = guardian_strip_issue_section_deep(guardian_bridge_extract_contents(entries))
    redacted = guardian_redact(contents)

    truncate_bytes, head_tail_bytes = guardian_bridge_load_evidence_limits(truncate_arg, head_tail_arg)

    try:
        serialized = json.dumps(redacted, default=str)
    except Exception:
        serialized = str(redacted)
    raw = serialized.encode("utf-8", errors="replace")

    if len(raw) <= truncate_bytes:
        return redacted, False, None, None

    if isinstance(redacted, list) and redacted:
        kept, omitted = guardian_bridge_reduce_list_structurally(redacted, truncate_bytes)
        if omitted:
            marker = {
                "_guardian_truncated": True,
                "omitted_items": omitted,
                "note": "{} of {} items omitted -- evidence exceeded the {} byte ceiling. The full "
                "untruncated payload is attached as a War Room file.".format(
                    omitted, len(redacted), truncate_bytes
                ),
            }
            reduced_payload = kept + [marker]
            try:
                reduced_bytes = len(json.dumps(reduced_payload, default=str).encode("utf-8", errors="replace"))
            except Exception:
                reduced_bytes = len(raw)  # be conservative -- fall through to the byte-slice below
            # A reduction step that can fail to reduce has to stop, not retry: only use this
            # path if it actually shrank things -- see guardian_bridge_reduce_list_structurally's
            # own docstring for the (near-impossible in practice, but checked anyway) case where
            # it wouldn't.
            if reduced_bytes <= len(raw):
                note = (
                    "evidence exceeded {} byte ceiling ({} actual bytes); reduced structurally to the "
                    "first {} of {} items (each kept unmodified) plus a summary marker for the {} "
                    "omitted. The full untruncated payload is attached as a War Room "
                    "file.".format(truncate_bytes, len(raw), len(kept), len(redacted), omitted)
                )
                return reduced_payload, True, note, redacted

    head = raw[:head_tail_bytes].decode("utf-8", errors="ignore") if head_tail_bytes else ""
    tail = raw[-head_tail_bytes:].decode("utf-8", errors="ignore") if head_tail_bytes else ""
    omitted = max(len(raw) - len(head.encode("utf-8")) - len(tail.encode("utf-8")), 0)
    marker = "...[truncated {} bytes -- full payload attached as a War Room file]...".format(omitted)
    truncated_payload = "{}{}{}".format(head, marker, tail)
    note = (
        "evidence exceeded {} byte ceiling ({} actual bytes); truncated to head+tail ({} bytes each) "
        "with a marker. The full untruncated payload is attached as a War Room file.".format(
            truncate_bytes, len(raw), head_tail_bytes
        )
    )
    return truncated_payload, True, note, redacted


def _guardian_bridge_scrub_error_evidence(value):
    """Scrub scalar secret patterns (`guardian_scrub_secrets`) from an
    error-path `result` payload, recursively -- see
    `guardian_tool_bridge_run`'s "ERROR-PATH REDACTION" comment at its
    Step 5/6 call site for why: on a `status == "error"` outcome,
    `guardian_bridge_shape_result` (via `guardian_bridge_extract_contents`)
    pulls the SAME failing entry's raw Contents into `result` that
    `guardian_execute` also flattens into `error` -- both need the same
    scalar-string scrub, since `guardian_redact` alone only masks a dict
    VALUE under a sensitive KEY, never an arbitrary string's own contents.

    Only ever called for the "error" status -- see the call site's
    docstring comment for why a genuine "ok" result must NOT go through
    this (real tool evidence, not free-form failing-command text).

    :param value: The (already redact-then-size-capped) `result` payload --
        a string, or a dict/list that may nest strings.
    :return: The same shape with every string leaf scrubbed.
    """
    if isinstance(value, str):
        return guardian_scrub_secrets(value)
    if isinstance(value, list):
        return [_guardian_bridge_scrub_error_evidence(item) for item in value]
    if isinstance(value, dict):
        return {k: _guardian_bridge_scrub_error_evidence(v) for k, v in value.items()}
    return value


def _guardian_bridge_elapsed_ms(start):
    """Milliseconds elapsed since `start` (a `time.monotonic()` reading).
    See the module docstring's "DURATION MEASUREMENT" section for why a
    monotonic clock -- not the server-time discipline `ts` requires -- is
    the right tool for an elapsed INTERVAL.
    """
    return int((time.monotonic() - start) * 1000)


def _guardian_bridge_finalize(
    tool_name,
    tool_call_id,
    target_summary,
    status,
    ok,
    result=None,
    error=None,
    duration_ms=None,
    tick_id=None,
    run_id=None,
    detail=None,
    truncated=False,
    truncation_note=None,
    full_payload=None,
):
    """Step 7 + 8, the single chokepoint every decision path funnels
    through: write exactly one `GuardianAuditWrite` row, then build the
    normalized tool-result object the model's `role:"tool"` message is built
    from. See the module docstring's "EXACTLY-ONE-AUDIT-ROW INVARIANT"
    section -- there is no other `GuardianAuditWrite` call site in this
    file.

    :param truncated: Whether `result` was shortened from its original size
        (only ever `True` from the ok/error tool-execution path -- see
        `guardian_bridge_shape_result`). Surfaced in `tool_result` itself
        (not just the audit row) so the model knows evidence was cut.
    :type truncated: ``bool``
    :param truncation_note: Human-readable description of what was cut, or
        ``None``.
    :type truncation_note: ``str`` or ``None``
    :param full_payload: The complete, REDACTED, pre-truncation payload when
        `truncated` is `True`, else `None`. Deliberately NOT placed inside
        `tool_result` -- `guardian_tick_tool_message` serializes the WHOLE
        `tool_result` dict into the model-facing message, so embedding the
        full (large, by definition) payload there would defeat the entire
        point of truncating it. Lives as a sibling of `tool_result` in the
        returned `data` dict instead, purely for `guardian_reasoning_tick_
        run` to read and attach as a War Room file (`fileResult`) -- never
        serialized into anything the model sees.
    :type full_payload: any JSON-serializable value, or ``None``
    :return: A :func:`guardian_envelope`. ``ok`` here means "the bridge
        itself completed and produced a decision" -- it is ``True`` for
        every one of halted/denied/pending_approval/ok/error, since all
        five are legitimate, successfully-reached outcomes. The tool call's
        OWN success/failure lives in ``data["tool_result"]["ok"]``.
        ``data`` is ``{"tool_result", "audit", "full_payload"}``.

    .. note:: ``error``/``result`` here are expected to ALREADY be scrubbed
        by the caller when they originate from raw command-execution text
        (see ``guardian_tool_bridge_run``'s "ERROR-PATH REDACTION" comment
        at its Step 5/6 call site) -- this finalize chokepoint intentionally
        does NOT blindly re-scrub ``error``, because several callers pass a
        synthesized, TRUSTED message here (the kill-switch/denylist/policy
        deny reasons, built only from List/command names, never from
        arbitrary tool output) that a generic scrub could otherwise
        over-mask -- e.g. the List name ``guardian_tool_denylist`` is 22
        characters of exactly the alphabet the scalar scrubber's long-token
        catch-all looks for, and masking THAT would make a denial message
        less useful to read, for no security benefit (there is no secret
        there to protect).
    :rtype: ``dict``
    """
    audit_result = guardian_execute(
        "GuardianAuditWrite",
        {
            "action": tool_name,
            "target": target_summary,
            "status": status,
            "duration_ms": duration_ms,
            "tick_id": tick_id,
            "run_id": run_id,
            "detail": detail,
        },
    )
    if not audit_result["ok"]:
        demisto.error("GuardianToolBridge: GuardianAuditWrite call failed: {}".format(audit_result["error"]))

    tool_result = {
        "tool_call_id": tool_call_id,
        "tool_name": tool_name,
        "status": status,
        "ok": bool(ok),
        "result": result,
        "error": error,
        "truncated": bool(truncated),
        "truncation_note": truncation_note,
    }

    return guardian_envelope(
        True, data={"tool_result": tool_result, "audit": audit_result, "full_payload": full_payload}
    )


#: ``setIncident`` args that steer the WRITE ITSELF rather than name an incident field value --
#: excluded when building the ``{cliName: value}`` field map in
#: :func:`guardian_bridge_run_set_incident`. ``id``/``version`` are dropped on purpose (the model
#: routinely hallucinates them, e.g. ``id:54``); the real target is always
#: ``demisto.incident()``. ``customFields``/``customfields`` are lifted separately (their NESTED
#: members ARE field values); ``using`` selects an integration instance, not a field.
GUARDIAN_SET_INCIDENT_CONTROL_ARGS = ("id", "version", "customFields", "customfields", "using")


def guardian_bridge_run_set_incident(parsed_args):
    """Execute a MODEL-requested ``setIncident`` against THIS run's incident.

    Two problems this solves:

    * **Hallucinated target.** The model can emit a made-up ``id`` (``id:54``, ``id:123``)
      that a plain ``setIncident`` dispatch would faithfully apply to the WRONG (or a non-existent)
      incident. The target is therefore ALWAYS ``demisto.incident()`` -- the incident this bridge run
      is executing under -- and any ``id``/``version`` the model supplied is ignored.
    * **Silent custom-field failure.** The ``setIncident`` COMMAND form can silently fail to persist
      custom fields on XSOAR 6 (returns a bare "done" with nothing written -- see
      :func:`guardian_set_incident_fields`). Writes therefore go through the REST full-object upsert.

    Runs at Step 5 (execute), i.e. AFTER the security chokepoint has already gated the call
    (``setIncident`` is ``require_approval`` -- a human approved it, or it is an approved-token
    replay). This is NOT a bypass: the model's request still passed every gate; this only changes HOW
    the approved write is applied.

    Field values are taken from the model's args -- both top-level ``cliName=value`` pairs and a nested
    ``customFields``/``customfields`` object -- minus :data:`GUARDIAN_SET_INCIDENT_CONTROL_ARGS`, keyed
    by lowercase cliName. Returns a :func:`guardian_envelope` shaped exactly like
    :func:`guardian_execute` so downstream result-shaping/auditing is identical for both paths.

    :param parsed_args: the model's parsed ``setIncident`` arguments.
    :type parsed_args: ``dict``
    :return: a :func:`guardian_envelope`; ``data`` on success is ``{"id", "fields"}``.
    :rtype: ``dict``
    """
    try:
        incident = demisto.incident() or {}
    except Exception:
        incident = {}
    incident_id = incident.get("id") if isinstance(incident, dict) else None
    if not incident_id:
        return guardian_envelope(
            False,
            error="setIncident: no current incident in context to target (demisto.incident() is empty)",
        )

    args = parsed_args if isinstance(parsed_args, dict) else {}
    fields = {}
    for key, value in args.items():
        if key in GUARDIAN_SET_INCIDENT_CONTROL_ARGS:
            continue
        fields[str(key).lower()] = value
    # A nested customFields/customfields object (either casing) carries field values too; its members
    # win over a same-named top-level arg (the explicit, structured form is the more deliberate one).
    for control_key in ("customFields", "customfields"):
        nested = args.get(control_key)
        if isinstance(nested, dict):
            for key, value in nested.items():
                fields[str(key).lower()] = value

    return guardian_set_incident_fields(incident_id, fields)


def guardian_bridge_normalize_splunk_search_args(parsed_args):
    """Strip a model-supplied ``polling`` arg from a ``splunk-search`` call
    before dispatch.

    ``splunk-search``'s ``polling=true`` path works by returning a
    ``ScheduledCommand`` when the search job isn't done yet -- a platform
    mechanism the PLAYBOOK TASK ENGINE drives by re-invoking the task later.
    This bridge only ever dispatches via a plain ``executeCommand`` call
    (never as its own playbook task), which cannot trigger that
    re-invocation: a still-running job then returns one static "scheduled to
    re-check in N seconds" entry that never actually fires, silently
    stalling the investigation on what reads as a real response. Without
    ``polling`` set at all, the command instead uses Splunk's own BLOCKING
    exec mode -- the job-creation call itself waits server-side until the
    search finishes, so a single dispatch already returns complete results.
    The prompt tail also tells the model never to set this
    argument; this is the code-level backstop for when it does anyway (a
    hallucinated/adversarial call, or a model discovering ``polling`` in its
    own tool schema and reasonably-but-wrongly assuming it helps here).

    :param parsed_args: The model's parsed ``splunk-search`` arguments.
    :return: ``(normalized_args, polling_was_stripped)``.
    :rtype: ``tuple(dict, bool)``
    """
    if not isinstance(parsed_args, dict) or "polling" not in parsed_args:
        return parsed_args, False
    normalized = dict(parsed_args)
    del normalized["polling"]
    return normalized, True


def guardian_bridge_flatten_list_args(tool_name, parsed_args):
    """Join a list of plain values into one comma-separated string before any gate runs.

    XSOAR command arguments are strings, and a command splits a list argument itself (``argToList``). A model that
    follows an array schema sends a JSON list instead, which ``SearchIncidentsV2`` rejects ("encoding without a string
    argument") and ``getIncidents`` misreads. Running this before the gates means the denylist, the allowlist and the
    policy check exactly what is dispatched, not a list that is turned into text later. Guardian's own scripts and
    ``setIncident``, where a list can be a multi-select field value, are left unchanged, and so is a list that holds
    anything but strings and numbers.

    :param tool_name: The resolved name of the tool being called.
    :param parsed_args: The model's parsed arguments.
    :return: ``parsed_args`` unchanged, or a copy in which each list of plain values is a comma-separated string.
    :rtype: ``dict``
    """
    if not isinstance(parsed_args, dict) or tool_name == "setIncident" or str(tool_name).startswith("Guardian"):
        return parsed_args
    flattened = {}
    for key, value in parsed_args.items():
        if isinstance(value, list) and all(isinstance(item, (str, int, float)) for item in value):
            value = ",".join(str(item).strip() for item in value)
        flattened[key] = value
    return flattened


def guardian_tool_bridge_run(
    tool_name,
    tool_args,
    tool_call_id=None,
    using=None,
    tick_id=None,
    run_id=None,
    approval_id=None,
    plan_approval_id=None,
    plan_step_index=None,
    evidence_truncate_bytes=None,
    evidence_head_tail_bytes=None,
):
    """Top-level orchestration for one GuardianToolBridge call -- the full
    kill-switch -> denylist -> allowlist/default-deny -> policy -> execute ->
    shape -> audit -> return sequence described in the module docstring.
    Never raises.

    :param tool_name: The command the model wants to call (required).
        Canonicalized (``.strip()``-ped) before any gate compares it, so a
        stray leading/trailing space -- or a model echoing back a tool name
        with incidental whitespace -- can't dodge the denylist/allowlist/
        policy checks (all of which compare the exact string).
    :type tool_name: ``str``
    :param tool_args: The tool-call arguments (JSON object string, dict, or
        blank/``None``).
    :param tool_call_id: Optional id echoed back for the model's tool
        message.
    :type tool_call_id: ``str`` or ``None``
    :param using: Optional integration instance to route the call to.
    :type using: ``str`` or ``None``
    :param tick_id: Optional reasoning-tick identifier, passed through to
        the audit row.
    :type tick_id: ``str`` or ``None``
    :param run_id: Optional run identifier, passed through to the audit row
        (`GuardianAuditWrite` defaults this to the current incident id when
        omitted).
    :type run_id: ``str`` or ``None``
    :param approval_id: The single-use approved-token for a
        PREVIOUSLY-parked single-tool (`kind:"tool"`) `require_approval`
        request. Only ever meaningful when `guardian_policy` classifies
        `tool_name` as `require_approval` -- ignored entirely for any other
        tier (an `allow`-tiered call was going to execute anyway; a `deny`-
        tiered call is denied regardless). Presenting a value here that
        fails to validate (wrong id/status/tool_name/args, or already
        consumed) DENIES the call outright -- it never silently falls back
        to creating a fresh ask. Mutually exclusive with
        `plan_approval_id`/`plan_step_index` (see :func:`guardian_bridge_consume_plan_step`'s
        docstring for the plan counterpart); if both are given,
        `plan_approval_id` takes precedence.
    :type approval_id: ``str`` or ``None``
    :param plan_approval_id: The plan-approval id, when this
        call is ONE step of an already-approved `GuardianPlanApprove` batch.
        Requires `plan_step_index` (a valid index into that ledger row's
        `steps`).
    :type plan_approval_id: ``str`` or ``None``
    :param evidence_truncate_bytes: Optional per-result size ceiling (bytes) the caller derived for the run's
        model; clamped. Without it the bridge works the number out itself (the run's context, then a fresh
        resolution). Affects only how much of a result the model is shown, never any gate.
    :param evidence_head_tail_bytes: Optional head/tail size (bytes, each) that goes with it.
    :param plan_step_index: The 0-based index into the plan ledger row's
        `steps` this call corresponds to.
    :type plan_step_index: ``int`` or ``str`` or ``None``
    :return: A :func:`guardian_envelope`; see :func:`_guardian_bridge_finalize`
        for the exact shape of ``data``. ``ok=False`` at the TOP level is
        reserved for a caller-usage error (missing/invalid ``tool_name``) --
        there is nothing meaningful to dispatch or audit in that case.
    :rtype: ``dict``
    """
    if not tool_name or not isinstance(tool_name, str):
        return guardian_envelope(False, error="NEEDS_CONTEXT: 'tool_name' is required and must be a non-empty string")

    # Canonicalize BEFORE any gate sees it -- every downstream comparison
    # (bare denylist names, arg-level denylist rules, guardian_tool_allowlist
    # membership, guardian_policy keys) is an exact string match, so a
    # whitespace-padded alias must resolve to the SAME decision as the
    # trimmed name, never a different (more permissive) one.
    tool_name = tool_name.strip()
    if not tool_name:
        return guardian_envelope(False, error="NEEDS_CONTEXT: 'tool_name' is required and must be a non-empty string")

    # SECURITY-PRESERVING alias resolution (see
    # `guardian_bridge_resolve_tool_alias`'s docstring): resolve a mangled
    # underscore/hyphen alias to its real, already-permitted spelling BEFORE
    # every gate below -- so the resolved name is what the denylist,
    # allowlist, policy, and default-deny checks all see (and what gets
    # dispatched/audited), never the mangled spelling. A name with no
    # permitted variant is returned unchanged, so it is denied exactly as it
    # would have been without this resolution step.
    tool_name = guardian_bridge_resolve_tool_alias(tool_name)

    parsed_args, args_warning = guardian_bridge_parse_tool_args(tool_args)
    if args_warning:
        demisto.error("GuardianToolBridge: {}".format(args_warning))
    # Before every gate, so each of them checks the value that is dispatched (see the function's docstring).
    parsed_args = guardian_bridge_flatten_list_args(tool_name, parsed_args)
    target_summary = guardian_bridge_summarize_target(parsed_args)
    risk_tier = guardian_bridge_risk_tier(tool_name, parsed_args)
    spl_write_commands = guardian_bridge_spl_write_commands(tool_name, parsed_args)

    # Every terminal path below must emit the same risk provenance. Before
    # policy has loaded, the independent hard-risk rule is still meaningful:
    # a destructive/credential call would require approval even if its policy
    # entry were later malformed, absent, or permissive.
    would_require_approval = risk_tier in ("destructive", "credential")

    def finalize(*args, **kwargs):
        """Attach complete risk provenance to every bridge audit row."""
        detail = kwargs.get("detail")
        detail = dict(detail) if isinstance(detail, dict) else {}
        detail.setdefault("risk_tier", risk_tier)
        detail.setdefault("would_require_approval", would_require_approval)
        if spl_write_commands:
            detail.setdefault("spl_write_commands", spl_write_commands)
        kwargs["detail"] = detail
        return _guardian_bridge_finalize(*args, **kwargs)

    # --- Step 1: kill switch (the ONE fail-open gate) ------------------------
    kill_switch = guardian_bridge_check_kill_switch()
    if kill_switch["halted"]:
        return finalize(
            tool_name,
            tool_call_id,
            target_summary,
            status="halted",
            ok=False,
            error="kill switch active -- tool call blocked before dispatch",
            tick_id=tick_id,
            run_id=run_id,
            detail={"args_warning": args_warning, "kill_switch_note": kill_switch["note"]},
        )

    # --- Step 2: denylist (the security boundary; fail-closed) --------------
    denylist_check = guardian_bridge_check_denylist(tool_name, parsed_args)
    if not denylist_check["ok"]:
        return finalize(
            tool_name,
            tool_call_id,
            target_summary,
            status="denied",
            ok=False,
            error=denylist_check["error"],
            tick_id=tick_id,
            run_id=run_id,
            detail={"args_warning": args_warning, "kill_switch_note": kill_switch["note"]},
        )

    # This boundary cannot be loosened through a runtime List edit. It
    # protects the human-approval and self-management controls that happen
    # to appear in XSOAR's general supported-command surface. Checked AFTER
    # the denylist (Step 2): if an operator ever ALSO adds one of these names
    # to guardian_tool_denylist's editable "denied" array, the denylist's
    # generic message wins the reported reason instead of this one -- same
    # outcome (denied) either way, just a less specific audit-trail message.
    if tool_name in GUARDIAN_OPERATOR_ONLY_COMMANDS:
        return finalize(
            tool_name,
            tool_call_id,
            target_summary,
            status="denied",
            ok=False,
            error="'{}' is a Guardian operator-only command and cannot be called by the agent".format(tool_name),
            tick_id=tick_id,
            run_id=run_id,
            detail={"args_warning": args_warning, "kill_switch_note": kill_switch["note"]},
        )

    # --- Step 3: allowlist / default-deny gate (fail-closed; see the module
    # docstring's "DEFAULT-DENY ALLOWLIST ENFORCEMENT" section). An
    # unreadable/malformed allowlist denies the call OUTRIGHT here, before
    # policy is even consulted -- like the denylist's own fail-closed
    # short-circuit above.
    allowlist_check = guardian_bridge_check_allowlist(tool_name)
    if not allowlist_check["ok"]:
        return finalize(
            tool_name,
            tool_call_id,
            target_summary,
            status="denied",
            ok=False,
            error=allowlist_check["error"],
            tick_id=tick_id,
            run_id=run_id,
            detail={"args_warning": args_warning, "kill_switch_note": kill_switch["note"]},
        )
    on_allowlist = allowlist_check["data"]["on_allowlist"]
    allowlist_source = allowlist_check["data"]["source"]

    # --- Step 4: policy tier (fail-closed) + default-deny cross-check --------
    policy_check = guardian_bridge_check_policy(tool_name)
    # Code outranks the editable policy List for high-risk calls. A policy
    # entry may narrow access further (deny still wins below), but it can
    # never downgrade a destructive or credential-bearing request to direct
    # dispatch. This decision is deliberately made before the one execution
    # path later in the function.
    risk_requires_approval = risk_tier in ("destructive", "credential")
    would_require_approval = risk_requires_approval or policy_check["decision"] == "require_approval"
    if policy_check["decision"] == "deny":
        return finalize(
            tool_name,
            tool_call_id,
            target_summary,
            status="denied",
            ok=False,
            error=policy_check["error"],
            tick_id=tick_id,
            run_id=run_id,
            detail={"args_warning": args_warning, "kill_switch_note": kill_switch["note"]},
        )
    if not on_allowlist and not policy_check["in_policy"]:
        # Default-deny: neither on the curated read-only allowlist NOR a
        # deliberately-classified guardian_policy entry -- e.g. an
        # off-catalogue `demisto-api-post` the model was never offered as a
        # tool but emitted anyway. Denied here, BEFORE guardian_policy's
        # absent-tool-name "allow" default is ever acted on.
        return finalize(
            tool_name,
            tool_call_id,
            target_summary,
            status="denied",
            ok=False,
            error="'{}' is not on guardian_tool_allowlist (effective source={}) and not classified in guardian_policy -- "
            "denied by default (default-deny gate)".format(tool_name, allowlist_source),
            tick_id=tick_id,
            run_id=run_id,
            detail={
                "args_warning": args_warning,
                "kill_switch_note": kill_switch["note"],
                "allowlist_source": allowlist_source,
            },
        )
    effective_policy_decision = policy_check["decision"]
    if risk_requires_approval and effective_policy_decision == "allow":
        effective_policy_decision = "require_approval"

    # Threaded into Step 5-8's `detail` below when set -- records WHICH
    # approved-token (single-tool or plan-step) authorized this dispatch, so
    # the audit row for an approved action is distinguishable from an
    # ordinary `allow`-tiered one WITHOUT needing a separate `status` value
    # (status stays 'ok'; `detail.approved_via` carries the 'approved'
    # provenance). ``None`` for every other path (allow-tiered, or this
    # policy tier not being require_approval at all).
    approved_via = None
    # Shadow/would-have-fired mode:
    # set ONLY when a `guardian_preapproved` class matches AND that class is
    # marked `"shadow": true` -- the call still parks for a human exactly
    # like an ordinary require_approval ask (this is the whole point: a
    # shadowed class must never actually loosen autonomy), but the fact that
    # it WOULD have auto-approved is recorded on the pending-approval audit
    # row so an operator can build evidence for a new preapproved class
    # before ever flipping it live. Threaded into that row's `detail` below.
    shadow_would_have_approved = None
    # The fresh per-consumption marker
    # `guardian_bridge_consume_approval_token`/`guardian_bridge_consume_plan_step`
    # just wrote onto the (now `consumed:True`) row/step -- threaded through
    # to the pre-execute re-confirmation check just below, kept OUT of
    # `approved_via` itself so `detail.approved_via`'s shape (audited, and
    # asserted exactly by existing tests) never changes.
    claim_token = None

    if effective_policy_decision == "require_approval":
        consume_error = None

        if plan_approval_id:
            try:
                step_index = int(plan_step_index) if plan_step_index is not None else None
            except (TypeError, ValueError):
                step_index = None
            if step_index is None:
                consume_error = "plan_approval_id given without a valid integer plan_step_index"
            else:
                consume_result = guardian_bridge_consume_plan_step(plan_approval_id, step_index, tool_name, parsed_args)
                if consume_result["ok"]:
                    approved_via = {"plan_approval_id": plan_approval_id, "plan_step_index": step_index}
                    claim_token = consume_result["data"]["claim_token"]
                else:
                    consume_error = consume_result["error"]
        elif approval_id:
            consume_result = guardian_bridge_consume_approval_token(approval_id, tool_name, parsed_args)
            if consume_result["ok"]:
                approved_via = {"approval_id": approval_id}
                claim_token = consume_result["data"]["claim_token"]
            else:
                consume_error = consume_result["error"]
        else:
            # --- PRE-APPROVED AUTONOMOUS CONTAINMENT -------------------------
            # No approval token was presented at all -- this would otherwise
            # become a brand-new "fresh ask" below. Before parking it, check
            # whether it qualifies for narrow, explicit pre-approval. See the
            # module docstring's "PRE-APPROVED AUTONOMOUS CONTAINMENT" section
            # for the full rationale; ALL FOUR gates below must hold, checked
            # in this order (cheapest/most-decisive first: no List read at all
            # is needed unless the risk tier AND the hardcoded
            # GUARDIAN_AUTO_APPROVABLE_COMMANDS membership already clear).
            # SECURITY-CRITICAL: the `tool_name in
            # GUARDIAN_AUTO_APPROVABLE_COMMANDS` check makes the "a
            # guardian_preapproved List edit alone can never widen this gate"
            # invariant true in code -- without it, ANY require_approval
            # command a List edit named (as long as it wasn't
            # destructive/credential tier) would auto-execute the moment
            # bypass mode was on. Expanding autonomy to a new command requires
            # a code change (and review) to that frozenset, not just a List
            # edit.
            if risk_tier not in ("destructive", "credential") and (
                tool_name in GUARDIAN_AUTO_APPROVABLE_COMMANDS
            ):
                current_approval_mode = guardian_bridge_get_approval_mode()
                if current_approval_mode == "bypass":
                    matched_class = guardian_bridge_check_preapproved(tool_name, parsed_args)
                    if matched_class is not None:
                        if matched_class.get("shadow"):
                            # Evidence-gathering only -- do NOT set approved_via. Falls through to
                            # the ordinary "fresh ask" pending_approval path below, unchanged.
                            shadow_would_have_approved = matched_class.get("command")
                        else:
                            approved_via = {
                                "auto_approved": True,
                                "bypass_source": current_approval_mode,
                                "preapproved_class": matched_class.get("command"),
                            }
            # claim_token stays None here in every case -- there is no ledger
            # token to re-confirm for an auto-approved dispatch, so Step 4.5
            # below (gated on `claim_token is not None`) never runs for this
            # path, regardless of what `approved_via` ends up holding.

        if approved_via is None:
            if approval_id or plan_approval_id:
                # A token was PRESENTED but failed validation -- DENY
                # outright. Never silently re-park as a fresh ask (that
                # would let a forged/stale/mismatched/replayed token quietly
                # "succeed" as a brand-new request instead of the caller
                # noticing its token didn't work) and never execute.
                return finalize(
                    tool_name,
                    tool_call_id,
                    target_summary,
                    status="denied",
                    ok=False,
                    error="approval token rejected -- {}".format(consume_error),
                    tick_id=tick_id,
                    run_id=run_id,
                    detail={"args_warning": args_warning, "kill_switch_note": kill_switch["note"]},
                )

            # No token presented at all -- a FRESH require_approval request:
            # create the ledger row + risk-tiered War Room note, park, and
            # return WITHOUT executing (see the module docstring's "POLICY
            # TIERS AND THE APPROVAL GATE" section).
            create_result = guardian_bridge_create_approval(tool_name, parsed_args, tick_id, run_id)
            if not create_result["ok"]:
                return finalize(
                    tool_name,
                    tool_call_id,
                    target_summary,
                    status="error",
                    ok=False,
                    error="approval required but failed to create the approval request: {}".format(
                        create_result["error"]
                    ),
                    tick_id=tick_id,
                    run_id=run_id,
                    detail={"args_warning": args_warning, "kill_switch_note": kill_switch["note"]},
                )

            approval_data = create_result["data"]
            return finalize(
                tool_name,
                tool_call_id,
                target_summary,
                status="pending_approval",
                ok=False,
                result={
                    "status": "pending_approval",
                    "approval_id": approval_data["approval_id"],
                    "risk_tier": approval_data["risk_tier"],
                    "tool_name": tool_name,
                    # Redacted: this `result` dict is written verbatim to
                    # `Guardian.ToolResult` context AND returned as the model's OWN
                    # role:"tool" message content -- unlike the ledger row's
                    # `tool_args` (guardian_bridge_create_approval, kept raw because
                    # a later re-dispatch on approval needs the EXACT original
                    # value), this copy is display-only and must never re-echo a
                    # secret back into the model's own transcript or a raw Context
                    # read.
                    "tool_args": guardian_redact(parsed_args),
                },
                error="approval required (risk_tier={}) -- parked as approval_id={}; a human must run "
                "!guardian-approve/!guardian-deny before this executes".format(
                    approval_data["risk_tier"], approval_data["approval_id"]
                ),
                tick_id=tick_id,
                run_id=run_id,
                detail={
                    "args_warning": args_warning,
                    "kill_switch_note": kill_switch["note"],
                    "approval_id": approval_data["approval_id"],
                    "risk_tier": approval_data["risk_tier"],
                    "posted_to_war_room": approval_data["posted_to_war_room"],
                    # Set to the matched class's command name only when a
                    # shadowed guardian_preapproved class matched this exact
                    # call -- evidence that bypass-mode auto-approval WOULD
                    # have fired here had the class not been shadowed.
                    "shadow_would_have_approved": shadow_would_have_approved,
                },
            )
        # else: approved_via is set -- fall through to Step 5 below and
        # actually execute, exactly like an allow-tiered command. True for
        # all THREE ways `approved_via` can be set: a consumed single-tool
        # token, a consumed plan-step token, or a narrow
        # pre-approved-class match in bypass mode. Kill switch / denylist /
        # allowlist / default-deny all already ran, unconditionally, above
        # every one of these three paths -- none of them bypasses any of it.

    # --- Step 4.5: pre-execute re-confirmation -- ONLY when this dispatch is
    # authorized by a just-consumed
    # approval token. Re-reads guardian_approvals_ledger fresh, immediately
    # before Step 5, and aborts (never executes) if a concurrent consumer's
    # write clobbered THIS invocation's own claim_token in the interim -- see
    # guardian_bridge_consume_approval_token's / guardian_bridge_confirm_tool_claim's
    # docstrings for the double-invocation race this narrows. Does nothing
    # (claim_token stays None) for an ordinary allow-tiered call -- there is
    # no token to re-confirm there.
    if claim_token is not None:
        if "plan_approval_id" in approved_via:
            reconfirm = guardian_bridge_confirm_plan_step_claim(
                approved_via["plan_approval_id"], approved_via["plan_step_index"], claim_token
            )
        else:
            reconfirm = guardian_bridge_confirm_tool_claim(approved_via["approval_id"], claim_token)

        if not reconfirm["ok"]:
            return finalize(
                tool_name,
                tool_call_id,
                target_summary,
                status="denied",
                ok=False,
                error="approval token consumption lost a race with a concurrent consumer -- action NOT "
                "executed: {}".format(reconfirm["error"]),
                tick_id=tick_id,
                run_id=run_id,
                detail={
                    "args_warning": args_warning,
                    "kill_switch_note": kill_switch["note"],
                    "approved_via": approved_via,
                },
            )

    # --- Step 5: execute (only reachable path that actually dispatches) -----
    # Bogon/private-IP short-circuit: a small model that gets a correct
    # "private, not routable" answer back from `ip` may not generalize that
    # to sibling private addresses in the same incident -- it re-dispatches
    # `ip` once per address, burning a full tick each time on a lookup that
    # can never have external reputation.
    # Answering instantly (no real dispatch, duration_ms stays None like the
    # kill-switch/denylist/policy-deny paths above) both removes the
    # per-address tick cost and gives the model an explicit stop instruction
    # in the tool result itself, reinforcing (rather than replacing) the
    # skill/prompt-tail guidance to recognize these ranges by inspection.
    bogon_ip = None
    splunk_polling_stripped = False
    if tool_name == "ip":
        ip_value = parsed_args.get("ip") if isinstance(parsed_args, dict) else None
        if isinstance(ip_value, str) and "," not in ip_value:
            try:
                candidate = ipaddress.ip_address(ip_value.strip())
            except ValueError:
                candidate = None
            if candidate and (
                candidate.is_private
                or candidate.is_loopback
                or candidate.is_link_local
                or candidate.is_reserved
                or candidate.is_multicast
                or candidate.is_unspecified
            ):
                bogon_ip = ip_value

    start = time.monotonic()
    if bogon_ip is not None:
        exec_result = guardian_envelope(
            True,
            data=[
                {
                    "Contents": (
                        "{} is not internet-routable, no reputation exists. STOP calling `ip` on "
                        "private/loopback/link-local addresses for the rest of THIS incident -- "
                        "classify any other such address in the incident by inspection, without "
                        "another tool call.".format(bogon_ip)
                    )
                }
            ],
        )
        duration_ms = None
    elif tool_name == "setIncident":
        # setIncident always targets THIS run's incident via REST upsert, never the model's
        # (frequently hallucinated) `id` arg -- see guardian_bridge_run_set_incident.
        exec_result = guardian_bridge_run_set_incident(parsed_args)
        duration_ms = _guardian_bridge_elapsed_ms(start)
    elif tool_name == "splunk-search":
        # A model-supplied polling=true schedules a platform ScheduledCommand
        # this bridge's plain executeCommand dispatch can never drive to
        # completion -- see guardian_bridge_normalize_splunk_search_args.
        splunk_args, splunk_polling_stripped = guardian_bridge_normalize_splunk_search_args(parsed_args)
        exec_result = guardian_execute(tool_name, splunk_args, using=using)
        duration_ms = _guardian_bridge_elapsed_ms(start)
    else:
        exec_result = guardian_execute(tool_name, parsed_args, using=using)
        duration_ms = _guardian_bridge_elapsed_ms(start)

    # --- Step 6: shape the result (redact, THEN size-cap) --------------------
    shaped_result, truncated, truncation_note, full_payload = guardian_bridge_shape_result(
        exec_result["data"], evidence_truncate_bytes, evidence_head_tail_bytes)

    status = "ok" if exec_result["ok"] else "error"

    # ERROR-PATH REDACTION, layer 2 of 2 (see the module docstring's
    # "ERROR-PATH REDACTION" section; layer 1 is GuardianCommon's
    # `guardian_execute` redacting a DICT-shaped failing entry's Contents
    # BEFORE it's ever flattened to text). `exec_result["error"]` here may
    # still be raw, free-form failing-command text (e.g. an upstream
    # integration's own "401 Unauthorized: invalid api_key 'sk-...'", or a
    # DB driver exception embedding a connection-string password) --
    # exactly the shape `guardian_redact` cannot reach, since it only ever
    # masks a dict VALUE under a sensitive KEY, never scans an arbitrary
    # string's own contents. `guardian_bridge_extract_contents` (used by
    # `guardian_bridge_shape_result` above) pulls a failing entry's Contents
    # into `result` too, regardless of `status` -- so on the "error" status
    # `shaped_result` can carry the SAME raw text as `exec_result["error"]`
    # (both trace back to the one `guardian_execute` call) and needs the
    # same scrub. Scoped to `status == "error"` ONLY -- a genuine `ok`
    # result is real tool evidence that `guardian_redact` already handles
    # structurally, and must not be scalar-scrubbed (that risks
    # over-masking legitimate long tokens/hashes/IDs in real evidence, the
    # same tension `guardian_redact`'s own docstring flags for itself). The
    # kill-switch/denylist/policy deny messages built above are NOT in
    # scope either -- those are synthesized by this bridge from trusted
    # List/command names, never from arbitrary tool output (see
    # `_guardian_bridge_finalize`'s own docstring note on why it doesn't
    # blindly re-scrub every `error` it receives).
    error_text = exec_result["error"]
    if status == "error":
        error_text = guardian_scrub_secrets(error_text) if error_text else error_text
        shaped_result = _guardian_bridge_scrub_error_evidence(shaped_result)

    detail = {
        "args_warning": args_warning,
        "kill_switch_note": kill_switch["note"],
        "truncated": truncated,
        "truncation_note": truncation_note,
        "retryable": exec_result["retryable"],
        "is_auth_error": exec_result["is_auth_error"],
        # Retain both decisions so a later policy change can distinguish a
        # genuine policy-gated call from a high-risk call that code promoted
        # despite an allow-tier List entry.
        "policy_decision": policy_check["decision"],
        "allowlist_source": allowlist_source,
        "effective_policy_decision": effective_policy_decision,
        "risk_gate_forced_approval": bool(
            risk_requires_approval and policy_check["decision"] == "allow"
        ),
        # Transparency for guardian_bridge_normalize_splunk_search_args: True
        # only when the model actually supplied polling on a splunk-search
        # call and this bridge stripped it before dispatch.
        "splunk_polling_stripped": splunk_polling_stripped,
        # Set only when this dispatch was authorized by a
        # single-use approved-token (single-tool or plan-step) or
        # a pre-approved-class bypass match, rather than an ordinary
        # allow-tiered call -- see `approved_via`'s own comment above for why
        # this lives in `detail` instead of a new `status`.
        "approved_via": approved_via,
        # Top-level convenience fields for the pre-approved-bypass
        # audit story -- directly greppable/dashboardable in the audit row's
        # `detail` JSON without needing to know `approved_via`'s three
        # possible shapes. `False`/`None` on every other path (allow-tiered,
        # or a genuine human-token-approved dispatch) -- never set outside
        # the one narrow auto-execution path described in the module
        # docstring's "PRE-APPROVED AUTONOMOUS CONTAINMENT" section.
        "auto_approved": bool(isinstance(approved_via, dict) and approved_via.get("auto_approved")),
        "bypass_source": (
            approved_via.get("bypass_source")
            if isinstance(approved_via, dict) and approved_via.get("auto_approved")
            else None
        ),
    }

    # --- Step 7 + 8: audit + normalized return -------------------------------
    return finalize(
        tool_name,
        tool_call_id,
        target_summary,
        status=status,
        ok=exec_result["ok"],
        result=shaped_result,
        error=error_text,
        duration_ms=duration_ms,
        tick_id=tick_id,
        run_id=run_id,
        detail=detail,
        truncated=truncated,
        truncation_note=truncation_note,
        full_payload=full_payload,
    )


def main():
    args = demisto.args()
    try:
        result = guardian_tool_bridge_run(
            tool_name=args.get("tool_name"),
            tool_args=args.get("tool_args"),
            tool_call_id=args.get("tool_call_id"),
            using=args.get("using") or None,
            tick_id=args.get("tick_id"),
            run_id=args.get("run_id"),
            approval_id=args.get("approval_id") or None,
            plan_approval_id=args.get("plan_approval_id") or None,
            plan_step_index=args.get("plan_step_index"),
            evidence_truncate_bytes=args.get("evidence_truncate_bytes"),
            evidence_head_tail_bytes=args.get("evidence_head_tail_bytes"),
        )
    except Exception as ex:  # last-resort guard -- guardian_tool_bridge_run
        # itself should never raise, but this is the automation's only
        # entry point and must never surface an unhandled traceback.
        return_error("GuardianToolBridge failed unexpectedly: {}".format(ex))
        return

    if not result["ok"]:
        # Only a caller-usage error (missing/invalid tool_name) reaches
        # here -- see guardian_tool_bridge_run's own ok=False contract.
        return_error("GuardianToolBridge failed: {}".format(result["error"]))
        return

    data = result["data"]
    tool_result = data["tool_result"]

    guardian_ctx_write("ToolResult", tool_result)

    lines = [
        "Guardian Tool Bridge: tool={} status={} ok={}".format(
            tool_result["tool_name"], tool_result["status"], tool_result["ok"]
        )
    ]
    if tool_result.get("error"):
        lines.append("error: {}".format(tool_result["error"]))

    return_results(
        CommandResults(
            readable_output="\n".join(lines),
            outputs_prefix="Guardian.ToolResult",
            outputs=tool_result,
            raw_response=data,
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
