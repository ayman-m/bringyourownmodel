# Guardian for Cortex XSOAR 6 — Operator's Guide & Live Smoke-Test Report

> **Status:** ✅ All checks green — **30/30 static + full dynamic suite PASS**
> **Tested:** 2026-07-14 · live against the reference tenant (Cortex XSOAR **6.14.0**, build 3036535) · Guardian pack **v0.0.1** · branch `guardian-xsoar-native`
> **Provider live:** Guardian Vertex → `gemini-2.5-flash` · kill switch **OFF**

Guardian is a **Cortex XSOAR 6-native SOC agent**: an LLM tool-calling reasoning loop that runs *inside* XSOAR (no external orchestrator), works incidents end-to-end, and forces every action it wants to take through a **default-DENY** tool chokepoint. This document is both the **operator's guide** (how to run and drive it) and the **live smoke-test report** (what was verified on the box, with evidence).

Every number and quoted result below is **live primary evidence** captured during the 2026-07-14 run — not assumed. The reusable harness is [`scripts/smoke.py`](../../scripts/smoke.py) + [`scripts/smoke_harness.py`](../../scripts/smoke_harness.py).

## Contents

1. [Environment & connecting to the box](#1-environment--connecting-to-the-box)
2. [What Guardian is & how the agent loop works](#2-what-guardian-is--how-the-agent-loop-works)
3. [The security model — default-deny tool chokepoint](#3-the-security-model--default-deny-tool-chokepoint)
4. [Operating Guardian — jobs, autonomy, model & budgets](#4-operating-guardian--jobs-autonomy-model--budgets)
5. [Analyst War-Room command reference](#5-analyst-war-room-command-reference)
6. [Observability — dashboard, widgets, cost, audit, memory](#6-observability--dashboard-widgets-cost-audit-memory)
7. [Smoke-test results — coverage matrix & verdicts](#7-smoke-test-results--coverage-matrix--verdicts)
8. [Guardian in action — a worked case (live)](#8-guardian-in-action--a-worked-case-live)
9. [Appendices](#appendices)

---

## 1. Environment & connecting to the box

The reference environment is a **Cortex XSOAR 6.14.0** server. This guide was written against a
server with no externally routable address, where both the REST API and the web UI are served on
port 443 and reached through an access tunnel mapped to a local port.

**1. Open your access path** (however your environment provides it — bastion, VPN, or a
cloud-provider tunnel), mapping the server's 443 to a local port such as `localhost:8443`.

**2. Trust the self-signed cert.** If the server presents a self-signed certificate:
- CLI/SDK: `DEMISTO_VERIFY_SSL=false` (or `--insecure`).
- Browser: open `https://localhost:8443`, and on the "Your connection is not private" page type **`thisisunsafe`** (or enable `chrome://flags/#allow-insecure-localhost` once) to reach the login.

**3. Connection env** (from the repo `.env`):

| Variable | Value |
|---|---|
| `DEMISTO_BASE_URL` | `https://localhost:8443` |
| `DEMISTO_API_KEY` | raw 32-char XSOAR-6 key (header `Authorization: <key>` — **no** `Bearer`, **no** `XSIAM_AUTH_ID`) |
| `DEMISTO_VERIFY_SSL` | `false` |
| `DEMISTO_SDK_IGNORE_CONTENT_WARNING` | `true` |

Verify with `curl -sk -H "Authorization: $DEMISTO_API_KEY" https://localhost:8443/user` → returns `admin`. Content operations use **demisto-sdk 1.39.0**; the repo satisfies its prerequisites (`.private-repo-settings`, `Tests/secrets_white_list.json`, a committed git history, and a Playground for the API user).

> **Note on screenshots.** The screens embedded throughout ([`screenshots/`](screenshots/)) were captured live from this XSOAR box during the run, window-isolated to the XSOAR browser window only (via `screencapture -l<windowID>`) so no other application, tab, or desktop content is ever in frame. They are raw/untrimmed — crop or annotate as needed.

---

## 2. What Guardian Is & How the Agent Loop Works

**Guardian is a Cortex XSOAR 6-native SOC agent** — an LLM tool-calling reasoning loop that runs entirely *inside* XSOAR 6, with **no external orchestrator**. There is no separate service, queue, or agent framework to stand up: the loop is a self-rescheduling XSOAR automation, and the LLM is reached through a provider integration exposing one command, `guardian-llm-chat` (live on the reference tenant: Guardian Vertex / `gemini-2.5-flash`). Every action the model wants to take is forced through a default-DENY tool chokepoint, `GuardianToolBridge`, so autonomy never means unbounded access.

### The "Guardian Agent Run" incident
Guardian runs *on an incident*. The pack ships one incident type, **Guardian Agent Run**, wired to:
- **Playbook:** `GuardianAgentLoop` (a plain, single-task playbook)
- **Layout:** `GuardianAgentRunLayout` (Guardian tab: Run Summary, Reasoning Trace, Tool-Call Ledger, Recommended Actions)

`GuardianAgentLoop` fires the automation `GuardianReasoningTick` **exactly once**. From there, the *script* owns all re-entry — the playbook never spawns another task. (It is deliberately not a GenericPolling wrapper; combining both would double-schedule.)

### The reasoning-tick lifecycle
`GuardianReasoningTick` has `polling: true` and self-reschedules by returning a `ScheduledCommand` with the **bare** script name. Each re-invocation is one model turn plus its tool calls. All evolving state (transcript, tick counter, cost, defense counters) round-trips through incident Context under `Guardian.Loop.*` — never through args.

| Control | Value | Source |
|---|---|---|
| Self-reschedule cadence | **15 s** (server floor 10 s) | `guardian_settings.tick_cadence_seconds` |
| Tick ceiling | **25 / 40 / 60 turns** (small / medium / large model) | not set by default; `guardian_settings.MAX_TICKS` or `overrides.max_ticks` in `guardian_model_profile` override |
| Re-entry mechanism | `ScheduledCommand`, bare name, `polling:true` | script yml + `.py` |

Per tick, in order: **1)** kill-switch check (`guardian_kill_switch`; halt → exit); **2)** on tick 0, build the system prompt (`GuardianPromptBuilder`) + tool catalogue (`GuardianToolCatalogBuilder`) and seed the transcript; **3)** run one `guardian-llm-chat` turn (`tool_choice=auto`); **4)** charge cost via `GuardianCostLedger` onto `GuardianCostUSD`; **5)** dispatch any *new* tool calls through `GuardianToolBridge`; **6)** persist `Guardian.Loop` in one write and reschedule.

The loop **stops (no reschedule)** when: the kill switch is on, the model concludes (no tool calls = final answer), the turn limit (MAX_TICKS) / `force_conclude` guard forces a no-tools summary turn, or a loop defense trips.

### How a run reaches completion
- **Autonomously:** the `GuardianIntakeSweep` job opens a Guardian Agent Run incident every 6 h and runs a read-only triage sweep (the autonomy heartbeat).
- **Manually:** create an incident of type Guardian Agent Run (a freshly `POST`ed incident sits at status 0 — move it to investigating so `GuardianAgentLoop` attaches and runs).

Live proof: incident **#29605** ("Suspicious OAuth Consent Grant") ran **3 ticks to completion** (`runStatus=completed`), cost **$0.008491**, with the layout rendering verdict, reasoning trace, and a tool-call ledger.

---

## 3. The Security Model — Default-Deny Tool Chokepoint

The most important thing to understand about Guardian: **the tool list shown to the model is not a security boundary.** Gemini can — and has been observed to — emit `tool_calls` for commands it was never offered (e.g. `setIncident`). The catalogue built by `GuardianToolCatalogBuilder` is curation only. The real boundary is one automation, `GuardianToolBridge`, the *only* place a model-proposed command ever reaches `demisto.executeCommand`.

### The decision sequence (every tool call, one at a time)

| # | Gate | List | On failure to read |
|---|------|------|--------------------|
| 1 | Kill-switch | `guardian_kill_switch` | fail-OPEN in `manual`, fail-CLOSED in `bypass` |
| 2 | Denylist | `guardian_tool_denylist` | fail-CLOSED (deny) |
| 3 | Allowlist / default-deny | `guardian_tool_allowlist` | fail-CLOSED (deny) |
| 4 | Policy tier | `guardian_policy` | fail-CLOSED (deny) |
| 5–8 | Execute → redact+size-cap → audit → return | — | exactly one `guardian_audit` row per call |

**Default-deny gate (step 3).** A command proceeds to the policy decision only if it is *either* on `guardian_tool_allowlist` (the 33-command read-only surface) *or* an explicit key in `guardian_policy`. Anything satisfying neither is denied with an audited refusal — closing the off-catalogue-REST-verb hole where `demisto-api-post {"uri":"/apikeys"}` could otherwise reach XSOAR's entire REST API.

**Denylist blocks at both ends.** Generic REST verbs (`demisto-api-post/get/put/multipart` + `core-api-*` aliases) and destructive verbs (`*-delete-incidents`, `*-install-packs`) are excluded at catalogue synthesis *and* denied again at dispatch — defense-in-depth, not either/or.

### Approval tiers and the self-resolve boundary

`guardian_policy` maps each command to `allow`, `require_approval`, or `deny`. A `require_approval` command parks as `pending_approval` (a `guardian_approvals_ledger` row + War Room note, classified soft/destructive/credential) without executing. **The agent can never resolve its own request:** `guardian-approve`/`guardian-deny` are on neither the allowlist nor in policy, so the same default-deny gate makes them structurally unreachable by a model `tool_call` — plus an in-script `actor="agent"` rejection as backstop.

**Preapproved narrows, never widens.** `guardian_preapproved` can only let a *require_approval* command skip the human step, and only when all hold: incident is in `bypass` mode, risk tier is non-destructive/credential, the command is in the code-level `GUARDIAN_AUTO_APPROVABLE_COMMANDS` frozenset, and args match a class. Today that is exactly one command, `xdr-endpoint-tag-add`. Expanding autonomy requires *both* a List entry *and* a reviewed code change.

**Arg-level List protection.** `setList`/`addToList`/`createList`/`deleteList` are denied whenever `listName` targets a control-plane List (`guardian_policy`, `guardian_tool_allowlist`, `guardian_tool_denylist`, `guardian_kill_switch`), so the agent cannot rewrite its own guardrails.

### Live dispatch evidence (4/4, smoke-tested through the bridge)

| Tool call | Classification | Result |
|-----------|---------------|--------|
| `getList` | allowlisted read | **ok** — dispatched |
| `demisto-api-get` | generic REST verb | **denied** — on the bare denylist |
| `totally-not-a-real-tool` | off-catalogue | **denied** — default-deny gate |
| `setList` | policy `require_approval` | **pending_approval** — parked `approval_id=603210f1…`; a human must `!guardian-approve`/`!guardian-deny` |

---

## 4. Operating Guardian — Jobs, Autonomy, Model & Budgets, Kill Switch

Once the pack is installed, Guardian runs itself on a schedule. Three Time-Triggered Jobs drive autonomy and upkeep — all currently **Enabled / Running** (Jobs page: 3 Running / 0 Waiting / 0 Error / 0 Disabled).

### The three jobs

| Job | Cadence | Runs | What it does |
|-----|---------|------|--------------|
| **GuardianIntakeSweep** | every **6h** | playbook `GuardianAgentLoop` on a new **Guardian Agent Run** incident | The autonomy heartbeat. Opens an incident (trigger `job:intake-sweep`) and runs a **read-only** triage sweep of the open queue, producing a ranked, evidence-backed assessment in the War Room. Recommend-only — never mutates or closes incidents. |
| **GuardianHousekeeping** | every **1h** | playbook `GuardianHousekeeping` | Consolidates per-incident audit ledgers, rotates/shards `guardian_audit`, reaps stale pending approvals + expired memory, and runs the stalled-run watchdog that re-arms or reaps loops whose self-reschedule died. |
| **GuardianEvalScore** | every **1h** | playbook `GuardianEvalScore` | Scores newly-concluded `guardiantriggersource=eval` incidents into `guardian_eval_results`; skips already-scored or still-running cases. Launching new eval cases stays manual. |

All three set **`closePrevRun: true`**, so each firing closes the prior run instead of stacking open incidents forever.

![Jobs page — GuardianIntakeSweep / Housekeeping / EvalScore, all Enabled and Time-Triggered (3 Running, 0 Error, 0 Disabled)](screenshots/05-jobs.png)

### Model plane

Guardian discovers its LLM **by command, not brand** — two provider integrations both expose the single command `guardian-llm-chat`, and you **enable exactly one**. Live state: **Guardian Vertex** is enabled (`provider=vertex`, model **gemini-2.5-flash**); Guardian Cohere is disabled.

**To change the model, edit the enabled integration instance** (Settings → Integrations). The model is *not* in `guardian_settings` — the GuardianLLM integration instance is the sole source of truth; run `!guardian-model` to see what's active. **Enable exactly one:** if *both* provider instances are enabled the model dispatch is ambiguous, and if *neither* is enabled every tick fails with no model — `!guardian-model` surfaces which state the box is in.

![Settings → Integrations filtered to Guardian — Guardian Vertex (Disable button = enabled) and Guardian Cohere (Enable button = disabled), both exposing guardian-llm-chat](screenshots/06-integrations.png)

Calibrate a new/small model with `!guardian-probe-model`. On this box it measured **~4.739 chars/token** — the naive `chars/4` estimate *undercounts by ~18%*, so a transcript can overflow the context window before compaction fires; probing the real tokenizer (instead of assuming 4.0) is what keeps the live context under budget. It found an effective window ≥131072 and recommends `max_input_tokens = 127878` = `floor((131072−4096)×0.85×(4.739/4))`.

### Budgets (`guardian_settings`)

| Key | Value | Meaning |
|-----|-------|---------|
| `MAX_TICKS` | not set (25 small, 40 medium, 60 large) | optional override of the turn limit per run |
| `tick_cadence_seconds` | 15 | loop re-schedule interval |
| `output_reserve_tokens` | 65536 | reserved for model output |
| `max_input_tokens` | `null` | pre-flight compaction ceiling; null = large-model/Gemini posture (disabled) |
| `max_tool_def_tokens` | `null` | null = 250000 default (full 33-tool catalogue) |
| `parallel_tool_calls` | `false` | defense-in-depth (bridge already dispatches sequentially) |

**Important:** `guardian_settings` is a pack-seeded, `system:true` List — runtime `!setList` is rejected. To change any budget you must **redeploy the pack**.

**Measured values win (1.0.1).** `max_input_tokens` and the tool-list budget are measured per model by the daily `GuardianModelAdaptation` job and saved to the runtime `guardian_model_profile` List, which every run reads. Order: an operator `overrides` entry in that List, then the measured value, then `guardian_settings`, then the built-in default. The values in the table above are therefore only the fallback. The model size is not measured: it is the model's size class in the model catalogue, looked up on every run. `model_tier` in `guardian_settings` (`auto` by default) is used only for a model that is not in the catalogue.

### Kill switch

`guardian_kill_switch` currently reads `{"enabled": false}` — **OFF, agent not halted**. Flipping it on **halts all tool dispatch** at the `GuardianToolBridge` chokepoint. Unlike settings, this is a runtime-mutable (`system:false`) List, so it can be toggled live (`!guardian-killswitch`) without a redeploy.

### Approval mode (`guardianapprovalmode`)

Every **Guardian Agent Run** incident carries a `guardianapprovalmode` field with two values, read **fresh on every tool call** (never cached):

| Mode | Behaviour | When to use |
|---|---|---|
| **`manual`** *(default, safer)* | Every `require_approval`-tiered action parks as `pending_approval` and waits for a human `!guardian-approve` / `!guardian-deny`. Preapproved auto-execution is **off**. | Normal operation, and any incident an analyst is actively reviewing. |
| **`bypass`** | A `require_approval` command may auto-execute **only** if it also passes every preapproved gate (see the Security Model): non-destructive/credential risk tier, in the `GUARDIAN_AUTO_APPROVABLE_COMMANDS` frozenset, and args match a `guardian_preapproved` class. Everything else still parks. | Narrow, pre-vetted autonomous containment (today: only `xdr-endpoint-tag-add`). |

Set it per incident (the incident's own field, e.g. via the layout or `setIncident`); an unset/unknown value resolves to `manual` — the bridge never defaults to `bypass`. `bypass` **narrows** which approvals may skip the human step; it never widens what commands are reachable at all (the allowlist/denylist/policy gates always run first).

---

## 5. Analyst War-Room Command Reference

Every Guardian operator command is a War Room automation you run with `!guardian-*` on a **Guardian Agent Run** incident. None of them are curated onto `guardian_tool_allowlist`, so the agent's own tool-calling loop can never invoke them — they are operator affordances over the loop's state. `!guardian-help` renders this same card live and works even on a cold box (no LLM instance, no Lists bootstrapped).

| Command (syntax) | What it does | Read-only / Mutating | Caller |
|---|---|---|---|
| `!guardian-help` | Prints this War Room command card. Pure string-building, zero I/O — works with no model configured. | Read-only | Operator |
| `!guardian-tools` | Lists exactly what `guardian_tool_allowlist` lets an agent tool call reach (the 33-command read-only surface). Cold-start/debug affordance. | Read-only | Operator |
| `!guardian-cost` | Cost/token summary: per-day + per-model rollup from `guardian_cost_ledger`, plus this incident's own spend. No model call. | Read-only | Operator |
| `!guardian-model` | Shows every `GuardianLLM` instance's live provider/model (the source of truth each tick uses). No arguments — change the model by editing the integration instance. | Read-only | Operator |
| `!guardian-probe-model [max_probe_tokens=] [output_reserve=] [safety_margin=]` | Empirically calibrates the enabled model (chars/token, context window, tools, structured output) and recommends a `max_input_tokens`. Appends one history record; changes nothing until `!GuardianModelProfileUpdate` (or the daily `GuardianModelAdaptation` job) saves it to `guardian_model_profile`. **Billable**. | Read-only | Operator |
| `!guardian-plan [incident_id=<id>]` | One plan-only LLM turn (`tool_choice=none`, no tools) proposing an investigation plan; posts it as a War Room note. **Billable** (own ledger bucket; needs a working GuardianLLM instance). | Read-only\* | Operator |
| `!guardian-compact [keep_recent=<n>]` | Force-summarizes older loop turns into a checkpoint, keeping the newest `keep_recent` (default 10) verbatim. **Billable**; needs an active loop. | Mutating | Operator |
| `!guardian-chat message="<text>" [incident_id=<id>]` | Analyst → agent. Queues a message onto this incident's loop, drained on the next tick (~15s). Answers an `ask-analyst` question and can re-open a concluded run. | Mutating | Operator |
| `!guardian-approve approval_id=<id> [confirm=CONFIRM] [reason=] [actor=]` | Approves a pending `require_approval` action/plan; the next tick re-dispatches it through `GuardianToolBridge` with a single-use token and executes it **exactly once**. Credential-tier needs `confirm=CONFIRM` (typed exactly). | Mutating | Operator only |
| `!guardian-deny approval_id=<id> [reason="<text>"]` | Denies a pending approval — nothing ever executes for that `approval_id`; the reason is fed to the model verbatim next tick. | Mutating | Operator only |
| `!guardian-killswitch state=on\|off [reason=] [actor=]` | `on` halts all tool dispatch within one poll cycle (checked at each tick + before every bridge dispatch) and stops new intake; `off` resumes. Rejects `actor=agent`. | Mutating | Operator only |
| `!GuardianAskAnalyst question="<text>"` | Agent → analyst: the agent calls this itself to pause and ask you something (reply with `!guardian-chat`). You can also run it manually to test the flow. | Mutating | **Agent-callable** + operator |

\* `!guardian-plan` does not execute tools or mutate agent state, but it posts a War Room note and makes a real, billable model call.

### Approval flow

Any state-changing agent tool call (e.g. `setList`) is parked by `GuardianToolBridge` as `status=pending_approval` with an `approval_id` (live example: `setList` → `approval_id=603210f1…`, shown in the Approvals Queue). A human resolves it with `!guardian-approve` or `!guardian-deny`. Risk tiers are **soft / destructive / credential**; a **credential-tier** approval additionally requires `confirm=CONFIRM`. The agent can **never resolve its own** requests: these commands are off `guardian_tool_allowlist`/`guardian_policy` (structural boundary) and also reject `actor=agent` in-script (defense-in-depth). A resolved row cannot be resolved again. Denying the live example returned: `Approval 603210f1 DENIED. Resolved by: analyst`.

### Answering the agent (`guardian-chat`)

When the agent pauses on `GuardianAskAnalyst`, reply with `!guardian-chat message="…"`; the text is folded into the transcript as `[Analyst]: …` before the next model turn. It is investigation-scoped — `incident_id` must match the current incident. `guardian-chat` can re-open a concluded run, but re-arming ticking may still require re-running the `GuardianAgentLoop` playbook (the command's output says so when that applies).

---

## 6. Observability — Dashboard, Widgets, Cost, Audit, Memory & the Incident Layout

Guardian is instrumented end to end: every tool call writes one audit row, every LLM turn writes cost, and two surfaces render it — a fleet-wide dashboard and a per-incident layout.

![Guardian Observability dashboard — Cost Ledger, Tool Call Activity donut, Loop Health, Approvals Queue, and Event Feed](screenshots/01-dashboard.png)

### The Guardian Observability dashboard
Dashboard id `guardian-observability`, five script-backed widgets. Live smoke values below.

| Widget | Type | Reads | Live reading (2026-07-14) |
|---|---|---|---|
| Guardian Cost Ledger | line | `guardian_cost_ledger` | per-day, per-model, in **milli-USD (USD×1000)**: 07-05 gemini 243, 07-06 gemini 104, 07-07 qwen 0 |
| Guardian Tool Call Activity | pie | `guardian_audit` by `status` | ok 482, error 80, pending_approval 23, denied 20, approved 12, halted 9 |
| Guardian Loop Health | table | each run's Context (probed) | 11 runs, kill_switch **OFF**, stalled_runs 0 |
| Guardian Approvals Queue | table | `guardian_approvals_ledger` | 1 pending (`setList` `603210f1`, soft risk) |
| Guardian Event Feed | table | high-signal `guardian_audit` | 51 events; top rows are the two live deny tests |

The Cost widget reports milli-USD because XSOAR's `/statistics/widgets/query` only accepts integer `Group.Data`; raw sub-cent USD would round to 0, so it uses `round(usd*1000)`. Loop Health is the "watchdog" view and the one place kill-switch state is shown — because `Guardian.Loop.status` lives in each incident's Context (not a searchable field), it probes each `Guardian Agent Run` incident individually via a read-only `GuardianHousekeeping` self-invocation, capped for cost. Approvals Queue shows only `status=="pending"`, oldest-first. Event Feed shows only denials/errors/halts plus kill-switch and job-disable actions — routine `ok` calls are excluded (the pie already covers them). All five are render-only: a missing List draws an empty widget, never a `createList` or an error.

### The per-incident Guardian layout
Incident type `Guardian Agent Run` → layout `GuardianAgentRunLayout`, "Guardian" tab. Four sections:

- **Run Summary** — 7 fields: `guardianverdict`, `guardianconfidence`, `guardianblastradius`, `guardiancostusd`, `guardiantickcount`, `guardiantriggersource`, `guardianattacktechniques`. On live #29605: Verdict Benign, Confidence 0, Cost $0.005879, Tick 2.
- **Reasoning Trace** (dynamic, `GuardianLayoutTrace`) — e.g. `Status: running | Tick 2 | Cost $0.0059 (29929 tokens) | Verdict pending`.
- **Tool-Call Ledger** (dynamic, `GuardianLayoutToolLedger`) — this incident's rows only, with Export-to-CSV. On #29605: 2 calls, Tick 0/1 `GuardianKBSearch`, ok, 214/208 ms.
- **Recommended Actions** (dynamic, `GuardianLayoutRecommendedActions`).

![Incident #29605 Guardian layout — Run Summary (verdict, confidence, cost, tick, trigger) and the live Reasoning Trace](screenshots/02-incident-layout.png)

![Tool-Call Ledger — this incident's tool calls (Tick 0/1 GuardianKBSearch, status ok, with latency and Export-to-CSV)](screenshots/03-tool-ledger.png)

![War Room — the agent's tool-call envelopes and field-change entries posted in place](screenshots/04-war-room.png)

### Audit trail, cost ledger, memory & KB
- **Audit** — one `guardian_audit` row per tool call: `{ts, actor, action, target, status, duration_ms, tick_id, run_id, detail}`. `GuardianHousekeeping` rotates rows older than `audit_retention_days` (default 30) into per-day shard Lists.
- **Cost ledger** — `guardian_cost_ledger` is a JSON *object* (not rows) keyed `day → model → trigger`, each bucket holding `{calls, prompt_tokens, completion_tokens, cached_tokens, total_tokens, usd}`. Each turn folds in incrementally (avoids the ~1000-row List ceiling), priced from `guardian_pricing`: non-cached prompt @ `input_per_1m`, cached @ `cached_input_per_1m`, completion @ `output_per_1m`; an unpriced model costs $0 with a warning, never a crash. Live grand total: **$0.347449 across 504 calls / 10,230,276 tokens** (gemini 143 calls $0.347449; qwen 361 calls $0).
- **Durable memory** — `GuardianMemory op=store` upserts by `key` into `guardian_memory` (`{key, value, scope, tags, ttl, created_at, updated_at, hits}`, value redacted at capture); `op=search` does keyword/substring match ranked by relevance + temporal decay (7-day half-life) + a capped hit boost, with **reap-on-read** dropping TTL-expired rows inline. Live: stored `smoke_probe_note`; search `smoke` → 1 hit.
- **KB search** — `GuardianKBSearch` over the pack-seeded `guardian_kb_soc_investigation` (30 docs: 20 ATT&CK technique guides + 10 IR playbooks), MITRE-scored. Live: `phishing investigation` → 3 hits, top T1566 score 14.0.

---

## 7. Smoke-Test Results — Coverage Matrix & Verdicts

**Headline: 30/30 static/script checks PASS, and every dynamic test PASS.** Captured 2026-07-14 against the reference tenant (Cortex XSOAR **6.14.0**, build 3036535), exercising Guardian pack **v0.0.1** live-installed content. Static checks ran via `/entry/execute/sync` on the admin Playground; dynamic checks created real incidents on the box.

### Static / script suite — 30/30 PASS

| Area | Tests | Result | Evidence |
|---|---|---|---|
| Config Lists | 9 | PASS | All 9 config Lists readable + valid JSON; kill switch OFF, `MAX_TICKS` 25, tiered policy, 33-cmd allowlist, denylist |
| Health | 2 | PASS | `GuardianPing`→`pong`; `GuardianDiagnostics`→16 enabled/2 disabled/2 unhealthy, 926 commands |
| Model | 2 | PASS | `guardian-probe-model` (~4.739 chars/tok, context ≥131072, tools+structured yes); `guardian_pricing` |
| Commands | 3 | PASS | `guardian-help`, `guardian-tools` (33), `guardian-cost` → $0.347449 / 504 calls / 10,230,276 tokens |
| Security | 4 | PASS | `GuardianToolBridge` chokepoint: allow→ok, denylist→denied, off-catalogue→denied, `setList`→pending_approval |
| Memory / KB | 3 | PASS | `GuardianMemory` store + search; `GuardianKBSearch` → 3 MITRE-scored hits (top T1566, 14.0) |
| Widgets | 5 | PASS | Cost, ToolLedger, LoopHealth, ApprovalsQueue, EventFeed — live, self-consistent data |
| Catalog | 1 | PASS | `GuardianToolCatalogBuilder` → 33 cmds, ~11,871 tokens |
| Prompt | 1 | PASS | `GuardianPromptBuilder` → 28,120 chars / ~7,035 tokens, manual approval mode |
| **Total** | **30** | **30/30 PASS** | |

### Dynamic suite — playbooks, subagent, approval (all PASS)

| Test | Component | Live artifact | Outcome |
|---|---|---|---|
| Core loop | GuardianAgentLoop | incident **#29605** (OAuth consent grant) | 3 ticks → `completed`, cost $0.008491, layout rendered |
| Housekeeping | GuardianHousekeeping | incident **#29606** | Completed successfully |
| Eval scoring | GuardianEvalScore | incident **#29607** | Completed successfully |
| Subagent | GuardianSubagentDispatch / Runner | phishing-analyst, 2/2 iterations | HIGH verdict (T1566+T1114), used live enrichment + 6-step plan |
| Approval path | GuardianApprovalGate / `guardian-deny` | approval `603210f1` | DENIED, resolved by analyst (operator-only path) |

### Known caveat (not a Guardian defect)

`GuardianDiagnostics` reports **2 unhealthy of 18 instances**: `Unit 42 Feed` and `Unit42IntelObjectsFeed`, both failing on fetch-indicators. These are **pre-existing non-Guardian feeds** on the box, unrelated to Guardian pack content, and do not affect any Guardian result above.

---

## 8. Guardian in action — a worked case (live)

Everything above describes the machinery. This is what it *does*. Below is a real case Guardian worked end-to-end on the box on 2026-07-14 (incident **#29622**), captured live — the story a SOC leader actually cares about: an AI analyst that investigates, collaborates, and stays under human control.

**The case.** A credential-harvesting phishing campaign against the finance team. Users received a fake *"your SSO session expired"* email linking to a cloned Okta page (`acme-sso-verify.com`, which POSTs submitted credentials to `45.83.220.14`). One finance user submitted credentials; twenty minutes later a successful VPN login for that user came from **the same attacker IP** (Netherlands vs. the user's US baseline), followed by an Outlook rule created to auto-delete "password reset" mail.

### 1 · It investigates autonomously
Guardian chose its own tools and worked the evidence — enriching the attacker IP (`ip` → *Malmö, Sweden; reputation unknown*), then searching its SOC knowledge base for the matching playbook — narrating every step in plain analyst language.

![Guardian reasoning trace — the agent's own turn-by-turn narration: enrich the IP, search the KB, decide to ask the analyst](screenshots/09-showcase-reasoning-trace.png)

### 2 · It works like a member of the SOC team
Finding no exact KB match and needing context only a human has, it did not guess — it **paused and asked the analyst a precise question**: *"Is phishing-resistant MFA enforced for the finance team?"* The loop suspends until a human replies (`!guardian-chat`), exactly like a junior analyst escalating to a senior.

### 3 · Every consequential action is governed
When Guardian moved to record its verdict, it **could not simply write it**. `setIncident` changes case state, so `GuardianToolBridge` parked the write in the **Approvals Queue** and waited for a human — the agent is structurally incapable of approving its own request.

![Tool-Call Ledger — ip / KBSearch / GuardianAskAnalyst all ok, then setIncident held PENDING_APPROVAL](screenshots/08-showcase-tool-ledger.png)

![Guardian Observability dashboard — the pending verdict-writes sitting in the Approvals Queue, with Loop Health (kill switch OFF) and the fleet-wide audit Event Feed](screenshots/10-showcase-approvals-queue.png)

### 4 · The human decides — and the verdict lands on the case
The analyst answered (*MFA is SMS-OTP only — not phishing-resistant, so treat the accounts as compromised*) and **approved** the write (`!guardian-approve`). Guardian's conclusion is now part of the incident record: **Malicious, 90% confidence**, blast radius documented, mapped to **MITRE ATT&CK T1566 / T1078 / T1114** — for a marginal model cost of **$0.006** for the whole run.

![Final case record — Guardian Verdict: Malicious, Confidence 90, blast radius, ATT&CK T1566/T1078/T1114](screenshots/11-showcase-verdict.png)

### The business value in one line
An AI analyst that triages and investigates cases around the clock, **escalates uncertainty instead of hallucinating**, records auditable, ATT&CK-mapped verdicts — and where it could take a consequential action, **a human is always in the loop**. Every tick, tool call, dollar, and approval is logged.

### Findings this run surfaced (the *other* value of testing)
Working a real case live also exposed three concrete engineering issues — logged here because honest evidence is the point:

| # | Finding | Impact |
|---|---------|--------|
| 1 | Gemini returns `400` when the model emits **parallel tool calls** — `guardian_settings.parallel_tool_calls=false` is not being enforced against the model. | Aborts an otherwise-healthy run. |
| 2 | The `domain` enrichment result is **not fed back** into the transcript, so the model re-issues the same call until the loop guard trips (matches gotcha #26). | Wastes ticks/budget; can end a run in `error`. |
| 3 | The agent's `setIncident` args carried a **hallucinated incident id** (`id:42`) instead of the current incident — the bridge should inject the real id before dispatch. | An approved write could target the wrong incident. |

None of these weaken the security model — **the chokepoint held on every call throughout** — but they should be fixed before fully unattended autonomy. (For this walkthrough the arc was run with one-tool-at-a-time prompting to route around #1/#2, and the approved verdict was applied to the correct incident via the REST upsert.)

---

## Appendices

### Appendix A — Reproduce the smoke test
The harness is included so any operator can re-run the battery after a deploy:

```bash
# 1. tunnel up (see §1), then from the repo root:
set -a; . ./.env; set +a
PY=$(command -v python3)   # any interpreter with `requests`
# run one category or all:
$PY scripts/smoke.py all
#   categories: config health model commands security memory widgets catalog prompt
```

`scripts/smoke.py` drives war-room commands via `/entry/execute/sync` on the admin Playground and asserts on the returned entries (a `type 4` error entry fails the check). `scripts/smoke_harness.py` is the thin `execute()` core. Dynamic playbook checks use `demisto-sdk run-playbook -p <id> --insecure -w`.

### Appendix C — Live artifacts created by this run
The smoke test created real, inspectable records on the box (left in place as evidence — not cleaned up):

| Artifact | ID / name | Note |
|---|---|---|
| Agent-loop incident | **#29605** | "Guardian Smoke – Suspicious OAuth Consent Grant", 3 ticks → completed |
| Housekeeping run | **#29606** | playbook completed |
| Eval-score run | **#29607** | playbook completed |
| Memory row | `guardian_memory` key `smoke_probe_note` | store + search round-trip |
| Denied approval | `guardian_approvals_ledger` `603210f1` | parked by a `setList` deny-test, then `!guardian-deny`-resolved |

### Appendix D — Known caveat (not a Guardian defect)
`GuardianDiagnostics` reports **2 unhealthy of 18 instances** — `Unit 42 Feed` and `Unit42IntelObjectsFeed`, both failing on `fetch-indicators`. These are **pre-existing, non-Guardian threat-feed integrations** on the box and do not affect any Guardian result in this report.

### Appendix E — Fixes verified (2026-07-15)
Three defects surfaced by the worked case (§8) were fixed and merged to `main` (PRs #1–#3), and the **full smoke suite still passes 30/30** afterward.

| Bug | Fix | Verification |
|---|---|---|
| Parallel-tool Gemini `400` | `GuardianVertex` groups the N `functionResponse` parts answering a turn's N `functionCall` parts into one Gemini `user` content | unit-tested 67/67 + 0 × 400 live |
| Hallucinated `setIncident` id | `GuardianToolBridge` routes `setIncident` to `demisto.incident()` (this run's incident) via REST upsert, ignoring the model's id | live: model emitted `id:54`, **incident 54 never created/touched**, verdict landed on the correct incident |
| `domain` infinite loop (gotcha #26) | per-run tool-dispatch cap moved to a runtime **List** (`getList` survives the stale-Context re-poll that the in-Context guard could not) | live: counter persisted across re-polls, tool capped, agent progressed through 4 tools. Residual scheduled-entry timeout tracked in [issue #4](https://github.com/soc-contents/xsoar-agents/issues/4), absorbed by the stalled-run watchdog |

**Live demonstration (incident #29670)** — a clean run concluded with a **Malicious** verdict (92% confidence, ATT&CK T1566·T1078·T1114) on the correct incident:

![Fix demo — Run Summary: Verdict Malicious, Confidence 92, ATT&CK T1566/T1078/T1114 on incident #29670](screenshots/12-fixes-demo-verdict.png)

The per-tool cap note firing (bug #2 fix in action) alongside the agent's analyst-ready summary and containment recommendations:

![Fix demo — the per-tool cap note ("already called setIncident 3 times… This call was NOT executed") plus the agent's summary + containment steps](screenshots/13-fixes-demo-cap-note-and-summary.png)

---

*Generated 2026-07-14 from a live smoke-test run against the reference tenant. Section drafts were produced by a parallel multi-agent documentation workflow and reconciled against the Guardian source (`GuardianToolBridge.py`, `guardian_settings`, the pack Lists) — where source and summary disagreed, source won (e.g. the approval risk tiers are `soft`/`destructive`/`credential`).*
