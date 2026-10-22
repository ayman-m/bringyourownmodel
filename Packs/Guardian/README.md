# Guardian

Guardian is an AI SOC-analyst agent that runs natively inside Cortex XSOAR 6 — no external
orchestration service. It works incidents end-to-end through a re-entrant, self-scheduling tick
loop (`GuardianReasoningTick`, driven via `ScheduledCommand`): it fetches an incident's record and
War Room, calls native XSOAR commands as tools (`getEntries`, `ip`, `splunk-search`, `findIndicators`,
`setIncident`, ...) through an LLM, documents its findings back onto the incident, and can pause for
analyst approval before any state-changing action.

The LLM itself is never called directly by the tick — every Guardian script reaches it through a
provider-agnostic `guardian-llm-chat` command, so swapping the underlying model only ever means
swapping which integration instance is enabled.

## Prerequisites

- Cortex XSOAR 6.10.0 or later.
- One enabled LLM provider integration: **Guardian Foundry** (Microsoft Foundry), **Guardian Vertex**
  (Google Vertex AI) or **Guardian Cohere** (a Cohere "North" endpoint). All three expose the same `guardian-llm-chat` command, so the
  rest of the pack works identically regardless of which one you configure.
- An LLM endpoint Guardian can reach from the XSOAR server or engine (see `docs/MODEL_SETUP.md` in the download).

## Setup

1. **Install this pack**, then configure and enable a Guardian LLM provider integration instance
   (**Guardian Foundry**, **Guardian Vertex** or **Guardian Cohere**) with your endpoint's URL and credentials.
2. **Set the instance's "Model size" dropdown** (`small` / `medium` / `large`) to roughly match the
   model actually serving your endpoint. This is a *display* value for cost/telemetry attribution —
   it does not by itself change agent behavior (see "Model-size tiers" below).
3. **Run the `GuardianModelAdaptation` job** once (a recurring Job; create it by hand on a manual
   install, then start one run by creating an incident with its playbook), and leave it on its daily
   schedule. It runs `!guardian-probe-model`, which makes a handful of real (billable) calls to measure
   the model's real tokens-per-char ratio, its latency-bounded effective context window, and whether it
   honors `tools` / `response_format`, then saves a trustworthy result to the runtime
   `guardian_model_profile` List that every investigation reads. By hand: `!guardian-probe-model` then
   `!GuardianModelProfileUpdate`. If you change the model or its context size, run it again.
   A model listed in the model catalogue (`guardian_model_catalog`, documented limits) gets a `documented`
   profile at the start of the first investigation, with no probe; a closed frontier model is not probed at
   all, and the probe confirms open-weight and self-hosted models against their documented limit (see
   `docs/MODEL_SETUP.md`).
4. **The model size follows the model.** `guardian_settings.model_tier` ships as `auto`: the size
   (`small` under 13B total parameters, `medium` 13B to 40B, `large` over 40B; a closed hosted model of unpublished size counts as large)
   is read from the model catalogue on every run. Set `small` / `medium` / `large` there only for a model that
   is not in the catalogue. `guardian_settings` is a pack-seeded system List — edit
   `Packs/Guardian/Lists/list-guardian_settings.json` and re-deploy the pack (a running instance cannot
   `!setList` it directly; that's deliberate, see "Design notes" below). To pin a context budget or force a
   size without a redeploy, set `overrides` in `guardian_model_profile`.
5. **Run `!GuardianBootstrap`** once (also from the Playground) to seed the pack's runtime-mutable
   Lists (audit log, cost ledger, memory store, approvals ledger, calibration history, ...) if they
   don't already exist.
6. **Investigate an incident**: bind an incident's playbook to `GuardianAgentLoop` (or
   `GuardianEvalInvestigate` for a scripted/eval-style run) and activate it. The first tick starts the
   loop; it reschedules itself every `guardian_settings.tick_cadence_seconds` until it concludes or
   pauses for approval. To triage an incident and then investigate it by type, bind it to
   `GuardianTriageAndInvestigateIncident` instead (see below).

## What's in the pack

- **Playbooks**: `GuardianAgentLoop` (the main entry point — preflight checks, then builds the prompt and tool list as separate tasks, then runs the model session as one task),
  `GuardianApprovalGate` (pauses for analyst sign-off on a state-changing action),
  `GuardianEvalInvestigate` / `GuardianEvalScore` (scripted evaluation runs), `GuardianHousekeeping`
  (periodic audit/approval-ledger maintenance and stalled-run recovery),
  `GuardianTriageAndInvestigateIncident` (a short triage session that ends with a fixed block, guarded severity and
  phase writes, then a full investigation through one of seven `GuardianTriage<Type>` sub-playbooks; the triage summary
  and the conclusion are written as War Room notes and as one Guardian section at the end of the incident's details by
  the operator-owned `GuardianIncidentSummary`). Optional model routing: the operator-owned `GuardianModelChoice` reads
  the protected List `guardian_model_routing` (shipped empty, so every call uses the instance's configured model) and can
  send the triage and the investigation to different models; `GuardianAgentLoop` is never routed.
  Duplicate check: before the triage model, the operator-owned `GuardianIncidentDuplicateCheck` (no model, one `getIncidents`
  search, on the denylist) finds an incident that repeats a lower-numbered open incident of the same type, name and source
  on the same entities (host, user, addresses, file hash, URL, email sender), writes a note with a proposed pre-process rule or
  fetch filter and skips the model. Playbook inputs: `check_duplicates` (default `true`) and `close_duplicates` (default
  `false`; `true` links the duplicate to the original and closes it as a duplicate, never the original). It fails open and
  complements XSOAR's native deduplication (pre-process rules, `FindSimilarIncidentsV2`); it does not replace it. The answer
  is at `Guardian.Duplicate`.
- **Core scripts**: `GuardianReasoningTick` (the loop itself), `GuardianToolBridge` (policy-gated tool
  dispatch), `GuardianToolCatalogBuilder` / `GuardianPromptBuilder` (assemble what the model sees each
  tick), `GuardianCompact` (transcript summarization when a run runs long), `GuardianMemory` /
  `GuardianKBSearch` (cross-incident memory and a curated investigation knowledge base),
  `GuardianCostLedger` (per-model/day cost and token tracking), `GuardianBootstrap` (one-time List
  seeding), `GuardianProbeModel` (`!guardian-probe-model`, described above).
- **Operator commands**: `!guardian-model` (shows which LLM instance/tier is actually configured),
  `!guardian-probe-model`, plus a small set of `!guardian-*` chat/plan/approval commands for driving
  or inspecting a run from the CLI.
- **Dashboard**: *Guardian Observability* — cost, tool-call activity, loop health, the approvals
  queue, and a live event feed.

## Model-size tiers

Different model sizes need different tool-catalogue treatment: a small model needs a narrower,
tick-0-gated catalogue and gets forced to commit to a tool call after an empty turn; a larger model
can be given a wider catalogue and more per-tool-name headroom. This is controlled by
`GUARDIAN_TIER_PROFILES` in `GuardianCommon.py`. The tier a run uses is the operator's pin
(`overrides.model_tier` in `guardian_model_profile`), else the model's size class in the model catalogue, else
`guardian_settings.model_tier` (for a model that is not in the catalogue), else `small` — **this is
the only thing that governs real tiering behavior**. The LLM integration instance's own "Model size"
dropdown is a separate, informational-only value; if it disagrees with the tier the run uses, the tick will
warn about the mismatch once per run rather than silently using either value. The limits that scale with the
model (the per-result limit, the incident details pinned into the prompt, the tool-list budget of a large
model, the history rule) are derived from the input budget by `guardian_derive_limits`. The turn limit per run (`MAX_TICKS`) follows the size as well: 25 small, 40 medium, 60 large; an explicit `MAX_TICKS` in `guardian_settings` or `overrides.max_ticks` in `guardian_model_profile` wins.

Only the tool catalogue's size/truncation and a couple of retry/dispatch knobs are tiered today —
the system prompt, skills, and memory mechanism are identical across all three tiers.

## Design notes

- **`guardian_model_catalog`** is pack-seeded reference data like `guardian_pricing`: the documented context
  limits of commonly used models. It is only read (never written at runtime) and does not widen what the agent
  may do. Rebuild it with `python3 scripts/build_model_catalog.py`.
- **`guardian_settings` and the other control-plane Lists (policy, tool allow/deny-lists) are
  pack-seeded and cannot be edited live** via `!setList` — this is deliberate: an agent should never
  be able to (directly or via a model-issued tool call) widen its own operating envelope. Change
  these by editing the pack source and re-deploying.
- **Runtime-mutable Lists** (audit log, cost ledger, memory, approvals ledger, jobs registry, model
  calibration history, model profile) are seeded once by `GuardianBootstrap` and then read/written
  normally by the scripts that own them.
- **`guardian_model_calibration`** (written by `!guardian-probe-model`) is a history only. The list the
  investigation reads is **`guardian_model_profile`**: the daily `GuardianModelAdaptation` job probes the
  enabled model and `GuardianModelProfileUpdate` saves a trustworthy result there (input budget, tool-list
  budget, capabilities), with an operator `overrides` section. It is a runtime List on purpose, written by
  a Job task and not by the agent; the model *size* is not measured: it is the model's size in the model
  catalogue, and `guardian_settings.model_tier` is used only for a model that is not in the catalogue.
- Guardian never fabricates an incident, entry, or indicator identifier it hasn't actually seen from a
  tool result this turn, and treats every tool result / War Room entry as untrusted case data, not as
  an instruction — see the always-injected system prompt for the full discipline the model is held to.

## Known limitations

- The `large` tier (100B+/large-MoE class models, e.g. Command R+/Command A+) has been validated for
  its configuration and token-budget arithmetic, but not against a real model of that size — testing
  so far has used 7B and ~32B local models. Run the `GuardianModelAdaptation` job against your real endpoint
  before trusting its measured `max_input_tokens`.
- Guardian requires roughly 20K+ tokens of usable context at minimum (the system prompt + tool
  catalogue alone run ~13.5K on a full command allowlist) — a model with a smaller effective window
  will compact its own context away every tick.
