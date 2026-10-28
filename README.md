# Bring Your Own Model: Guardian, an AI incident-investigation agent for Cortex XSOAR 6 and the Cortex platform

Guardian is an autonomous SOC-analyst agent that runs **entirely inside Cortex XSOAR 6** as a single
content pack (`Packs/Guardian`) — no external harness, no sidecar service. A separately maintained edition,
`Packs/GuardianXSIAM`, does the same on the **Cortex platform** (developed and tested on Cortex XSIAM 8.15). A re-entrant reasoning loop
drives a Bring-Your-Own-Inference LLM that selects native XSOAR commands as tools, investigates
incidents, and proposes actions — every one of which passes through a single security chokepoint before
it can touch anything.

Bring Your Own Model: the agent talks to the model through one command, so you choose the provider (Microsoft Foundry, Google Vertex AI,
Cohere North, or any OpenAI-compatible endpoint) and the size of model. It runs as Cortex SOAR content rather than as a separate product.

> **Community project.** This repository is community-supported. It is licensed under Apache-2.0, with no warranty.

---

## Install

Guardian ships as **two editions, one per platform**. They are different content: install only the one for your platform.

| Your platform | Content | Install guide |
|---|---|---|
| **Cortex XSOAR 6** (6.10+) | `Packs/Guardian` | [`docs/xsoar/README.md`](docs/xsoar/README.md) |
| **Cortex platform** | `Packs/GuardianXSIAM` | [`docs/cortex-platform/README.md`](docs/cortex-platform/README.md) |

Each guide lists the content types in that edition and gives three ways to install it: an install script, the console's pack upload, or **item by item in the
right order** (which content type first, and what each one needs). Everything in the packs is unified YAML, so nothing has to be built and `demisto-sdk` is
not needed. Download `Guardian-v<version>.zip` from this repository's Releases page, unzip it and start at `INSTALL.md`.
Model setup, including Microsoft Foundry with a resource key or Microsoft Entra ID: [`docs/MODEL_SETUP.md`](docs/MODEL_SETUP.md).
What it does, who uses it and how to test it: [`docs/GUARDIAN_GUIDE.md`](docs/GUARDIAN_GUIDE.md). Build the download from this repository with `python3 scripts/build_release.py`.

## Table of contents
- [What it does](#what-it-does)
- [Architecture](#architecture)
- [The security chokepoint](#the-security-chokepoint-default-deny)
- [The model plane (provider-agnostic)](#the-model-plane-provider-agnostic)
- [What's in the pack](#whats-in-the-pack)
- [Deploy](#deploy)
- [Use it (operator flow)](#use-it-operator-flow)
- [Self-hosted model lab & small-model tuning](#self-hosted-model-lab--small-model-tuning)
- [Repository layout](#repository-layout)
- [Documentation index](#documentation-index)

---

## What it does

A scheduled **Job** creates a *Guardian Agent Run* incident and starts the **GuardianAgentLoop**
playbook. From there:

0. **Preparation, as visible playbook tasks.** Before any model call the playbook checks the kill switch,
   the job guard, resolves the model profile (size, input budget and tool-list budget, measured daily by the
   `GuardianModelAdaptation` job), then builds the system prompt and the tool list (each its own task, no
   model involved).
1. **Reasoning loop.** `GuardianReasoningTick` is the one task that talks to the model: it takes the
   prompt and tool list built above (building them itself if run by hand) + the running transcript, and
   calls the LLM via one command: `guardian-llm-chat`. The tick **self-reschedules** each turn via `ScheduledCommand`, so the whole
   multi-tick investigation runs re-entrantly inside XSOAR with no external orchestrator.
2. **Tool use through a chokepoint.** Every tool call the model emits is dispatched through
   **GuardianToolBridge** — read-only investigation happens freely; anything state-changing is gated
   to a human (or a narrow pre-approved autonomous class).
3. **Investigation.** It pulls the case, reads the War Room, correlates related incidents, enriches
   indicators, and produces a grounded verdict + recommended action.
4. **Human-in-the-loop.** Analysts talk to it mid-run (`!guardian-chat`), approve/deny proposed
   actions (`!guardian-approve` / `!guardian-deny`), toggle autonomy per incident, or hit the
   **kill-switch**.
5. **Observability.** A layout shows the reasoning trace, tool-call ledger, recommended actions, cost,
   and verdict; a dashboard rolls up loop health, cost, approvals, and denials across all runs.

---

## Architecture

```
                          ┌──────────────────────────────────────────────────────────┐
   Scheduled Job          │                    Guardian Agent Run incident            │
  (GuardianIntakeSweep) ─▶│   GuardianAgentLoop playbook ─▶ GuardianReasoningTick ◀┐  │
                          │                                     │ self-reschedules ─┘  │
                          │        ┌────────────────────────────┼───────────────────┐ │
                          │        ▼                            ▼                    │ │
                          │  GuardianPromptBuilder     guardian-llm-chat (model turn)│ │
                          │  GuardianToolCatalogBuilder        │                     │ │
                          │        (system + tools)            ▼                     │ │
                          │                            model emits tool_calls        │ │
                          │                                    │                     │ │
                          │                                    ▼                     │ │
                          │                        ┌───────────────────────┐         │ │
                          │   the ONE chokepoint ─▶│   GuardianToolBridge  │         │ │
                          │                        │ kill-switch → denylist│         │ │
                          │                        │ → allowlist(DEFAULT-  │         │ │
                          │                        │   DENY) → policy tier │         │ │
                          │                        │ → approve / auto / run│         │ │
                          │                        │ → audit               │         │ │
                          │                        └───────────┬───────────┘         │ │
                          │                                    ▼                     │ │
                          │                        native XSOAR commands ────────────┘ │
                          │                        (getIncidents, ip, splunk-search…)   │
                          └──────────────────────────────────────────────────────────┘
        model plane (interchangeable):  guardian-llm-chat  ─▶  Guardian Vertex (Gemini) | Guardian Cohere (North) | Guardian Foundry (Azure)
```

**Key design properties**

- **Re-entrant, not blocking.** The reasoning loop is one self-rescheduling script, bounded by
  a turn limit that follows the model's size (25 small, 40 medium, 60 large; `MAX_TICKS` overrides). XSOAR's own scheduler drives the ticks; nothing polls or blocks a worker.
- **Default-DENY security.** The bridge executes a tool call *only* if it is explicitly permitted;
  everything else is denied or gated. (See below.)
- **Provider-agnostic model plane.** All reasoning content depends on exactly one command
  (`guardian-llm-chat`) and one normalized output shape — never on a provider brand.
- **No cross-script imports.** XSOAR 6 automations can't `import` each other, so the shared helper
  library (`GuardianCommon`) is injected into every consumer at build time (`scripts/inject_common.py`).

---

## The security chokepoint (default-DENY)

`GuardianToolBridge` is the single point every model-requested action funnels through. In order:

1. **Kill-switch** — if on, halt (fail-closed in autonomous mode).
2. **Denylist** — explicitly blocked commands never run.
3. **Allowlist (default-DENY)** — a command runs only if it is on `guardian_tool_allowlist` **or** in
   the policy; anything unknown is denied. (A critical review caught an early default-*allow* bug — the
   model could have emitted raw `demisto-api-post` — which was fixed to default-deny.)
4. **Policy tier** — read-only vs. `require_approval` (via `guardian_policy`).
5. **Human gate** — a gated action is parked (not executed) and posted to the approvals queue;
   the agent executes it **once** only after an operator approves (single-use token), or
6. **Pre-approved autonomous class** — a *narrow, code-defined* set (`GUARDIAN_AUTO_APPROVABLE_COMMANDS`
   frozenset **and** the `guardian_preapproved` list; both required) may auto-execute in `bypass` mode.
   **High-impact actions are always gated regardless of mode.** Widening autonomy requires a code change,
   not just a list edit.
7. **Audit** — every dispatch is an immutable, redacted row + a War Room entry.

The agent **cannot approve its own requests** (structural self-resolve prevention).

---

## The model plane (provider-agnostic)

The whole reasoning stack talks to the model through one command — **`guardian-llm-chat`** — and reads
one normalized output — **`Guardian.LLM.Completion`** (OpenAI Chat-Completions shape). Each provider
ships as its **own integration** implementing that same command identically; you **enable exactly one**
at a time and swap models with zero content changes.

| Integration | Backend | Notes |
|---|---|---|
| **Guardian Vertex** | Google Vertex AI (Gemini), + OpenAI-compatible / Azure adapters | Mints a per-call OAuth token from a service account; translates OpenAI↔Gemini. |
| **Guardian Foundry** | Microsoft **Foundry** (Azure AI Foundry): OpenAI models and the other chat models deployed in a Foundry resource | OpenAI-compatible v1 API (`/openai/v1/chat/completions`); resource key or Entra ID service principal; reasoning-model parameter handling. |
| **Guardian Cohere** | A private **Cohere North** deployment | Two-hop protocol (`POST /api/v1/chat` → poll `/api/v1/conversations/{id}`); `per_run`/`stateless`/`reuse` conversation modes; `openai`/`cohere` tool formats. |

Adding a provider (e.g. Guardian Claude) = one new integration implementing `guardian-llm-chat`; the
tick, tools, skills, cost ledger, and slash commands are untouched. See
[`docs/GUARDIAN_LLM_CHAT_CONTRACT.md`](docs/GUARDIAN_LLM_CHAT_CONTRACT.md).

**Model calibration.** `!guardian-probe-model` empirically probes the enabled provider (real
tokens-per-char, effective context window via needle + truncation-plateau search, tool/structured-output
support). The daily `GuardianModelAdaptation` job runs it and saves a trustworthy result to the runtime
`guardian_model_profile` List, which every investigation reads (an operator override beats the measured
value, which beats `guardian_settings`, which beats the built-in default) — so the context budget is
measured once a day per model, never a hard-coded guess. The model *size* is not measured: it is taken from the
model catalogue on every run (`guardian_settings.model_tier` is only for a model that is not in it).

---

## What's in the pack

`Packs/Guardian` — **3 integrations · 80 automations · 17 playbooks · 19 lists · 15 fields · 2 incident
types · 6 jobs · 2 layouts · 1 dashboard · 1 pre-process rule.** The Cortex platform edition, `Packs/GuardianXSIAM`, is a separately
maintained copy (21 playbooks, no pre-process rule; see its `DIVERGENCE.md`).

- **Reasoning core** — `GuardianReasoningTick` (the loop), `GuardianPromptBuilder`,
  `GuardianToolCatalogBuilder` (native commands → OpenAI tools, priority-ordered + token-budgeted),
  `GuardianToolBridge` (the chokepoint), `GuardianCompact` (transcript compaction).
- **Agent tools** — `GuardianAskAnalyst`, `GuardianMemory` (durable keyword memory w/ temporal decay +
  TTL), `GuardianKBSearch`, `GuardianSkillRead`, `GuardianSubagentDispatch` (specialist sub-agents),
  `GuardianPlaybookMonitor`, `GuardianDiagnostics`, `GuardianPlanApprove`.
- **Approvals & safety** — `GuardianApprovalResolve`/`GuardianDeny` (operator-only),
  `GuardianKillSwitchToggle`, `GuardianAuditWrite`.
- **Operator slash commands** — `!guardian-chat`, `!guardian-model`, `!guardian-probe-model`,
  `!guardian-cost`, `!guardian-tools`, `!guardian-plan`, `!guardian-compact`, `!guardian-help`.
- **Self-test** — `!GuardianHealthCheck` (operator-owned, read-only) checks the package, the Lists, the integrations, the model, the core
  scripts and the tool chokepoint after an install or an upgrade, and reports PASS, WARN or FAIL with the likely cause and the fix.
- **Lifecycle / ops** — `GuardianHousekeeping` (reap stale approvals/memory, rotate audit, re-arm
  stalled runs), `GuardianJobGuard`, `GuardianIntakeHygiene`, `GuardianBootstrap`,
  `GuardianContentBackup`, `GuardianSimulateIncidents`, `GuardianEval`, `GuardianCostLedger`.
- **Playbooks** — `GuardianAgentLoop` (preflight and prep tasks, then one model-session task that re-schedules itself), `GuardianApprovalGate`,
  `GuardianSubagentRunner`, `GuardianHousekeeping`, `GuardianEvalScore`.
- **Triage and investigation** — `GuardianTriageAndInvestigateIncident` routes an incident (`GuardianIncidentRoute`, List
  `guardian_incident_routes`), pre-fetches its evidence (`GuardianIncidentEvidence`), runs a short triage session that
  ends with a fixed block (with an optional analysis, recommendations and complexity), validates it
  (`GuardianTriageResult`, one repair call, then a fallback), sets severity and phase behind guards
  (`GuardianTriageApply`, operator-owned), writes the triage summary (`GuardianIncidentSummary`), then branches to one of
  six typed sub-playbooks (phishing, identity, endpoint, network, data exposure, vulnerability) or `GuardianTriageOther`.
  Each branch runs read-only lookups (none for `Other`), adds them to the evidence packet and runs a full investigation;
  `GuardianRunCapture` remembers the outcome and `GuardianIncidentSummary` writes the conclusion as a War Room note and
  one Guardian section at the end of the incident's details. Optional model routing (`GuardianModelChoice`, List
  `guardian_model_routing`, shipped empty) can send the triage and the investigation to different models. Taxonomy: List
  `guardian_triage_types`; skill `xsoar_triage`. Before the triage model, the operator-owned `GuardianIncidentDuplicateCheck`
  (no model, one `getIncidents` search) skips the model for an incident that repeats a lower-numbered open incident of the
  same type, name and source on the same entities; playbook inputs `check_duplicates` (default `true`) and `close_duplicates`
  (default `false`).
- **Config lists** — `guardian_settings`, `guardian_persona`, `guardian_prompt_head/tail`,
  `guardian_pricing`, `guardian_model_catalog` (documented model limits), `guardian_policy`, `guardian_preapproved`, `guardian_tool_allowlist`/`denylist`,
  `guardian_skills_index` + 5 `guardian_skill_*` skills, `guardian_kb_soc_investigation`, `guardian_incident_routes`,
  `guardian_triage_types`, `guardian_model_routing`.
- **Fields** — `guardianverdict`, `guardianconfidence`, `guardianblastradius`, `guardiancostusd`,
  `guardiantickcount`, `guardianapprovalmode`, `guardiantriggersource`, `guardianattacktechniques`.
- **UI** — the *Guardian Agent Run* layout (trace / tool-ledger / recommended-actions widgets) and the
  *GuardianObservability* dashboard (cost, loop health, approvals queue, event feed).

---

## Deploy

```bash
# .env holds DEMISTO_BASE_URL / DEMISTO_API_KEY / DEMISTO_VERIFY_SSL
bash scripts/deploy.sh
```

`deploy.sh` re-syncs the shared helper block (`scripts/inject_common.py`), uploads the pack as a zip
(`demisto-sdk upload -z --override-existing`), and creates the Jobs via REST (`scripts/deploy_jobs.py`)
— pack-zip upload alone doesn't create Jobs on 6.14.0. Re-run it for any content change (pack-installed
items are `system:true` and can't be edited item-by-item).

---

## Use it (operator flow)

Full detail in [`docs/OPERATOR_RUNBOOK.md`](docs/OPERATOR_RUNBOOK.md). In short:

1. **Configure a model** — add an instance of one Guardian provider integration (Guardian Vertex or
   Guardian Cohere); disable the others. `!guardian-model` shows what's live.
2. **Calibrate** — run the `GuardianModelAdaptation` job once (create it by hand on a manual install); it
   then refreshes the measured model profile daily. The size comes from the model catalogue (`guardian_settings.model_tier` is only for a model that is not in it).
3. **Run** — the `GuardianIntakeSweep` job triages open incidents every 6h, or create a *Guardian Agent
   Run* incident to investigate on demand.
4. **Watch** — the incident layout shows the live reasoning trace; the War Room narrates each tick.
5. **Steer** — `!guardian-chat message="focus on the 10.x lateral movement"`.
6. **Approve/deny** — `!guardian-approve approval_id=<id>` (add `confirm=CONFIRM` for high-impact) /
   `!guardian-deny …`.
7. **Autonomy** — set an incident's *Guardian Approval Mode* to `bypass` for the narrow pre-approved
   containment class (high-impact still gated).
8. **Kill-switch** — `!guardian-killswitch state=on` halts all agent activity within one poll cycle.

---

## Self-hosted model lab & small-model tuning

`lab/cohere-north/` is a self-contained rig to test the **unchanged** Guardian Cohere integration
against Cohere North's exact wire contract, backed by a **real open-weights model on a GPU** — no
mocked inference. A small middleware reproduces North's API in front of Ollama; the Guardian agent then
runs against it. This exercise:

- **Caught a real production bug** (`_headers()` shadowed by `BaseClient.self._headers`) that would have
  broken the integration against a real North endpoint too.
- **Characterized small-model behavior** across 20 real incidents (grounding drift, non-convergence,
  wasted internal-IP enrichment) — see [`lab/cohere-north/SMALL_MODEL_FINDINGS.md`](lab/cohere-north/SMALL_MODEL_FINDINGS.md).
- Drove three tunability features, all **model-agnostic** (help every size):
  - **`max_input_tokens`** — provider-agnostic context budget (orchestrator compacts the transcript to
    fit); measured daily into `guardian_model_profile`, with `guardian_settings` as the fallback.
  - **Priority-ordered tool catalogue + enforced `max_tool_def_tokens`** — small models get a trimmed
    ~10-tool triage catalogue (base prompt ~19K→~3K tokens); large models keep the full 33-tool set.
  - **Grounding + guardrails + verdict format** added to the `xsoar_case_triage` skill.

See [`lab/cohere-north/README.md`](lab/cohere-north/README.md) for the GCP GPU provisioning + bring-up.

---

## Repository layout

```
Packs/Guardian/          Cortex XSOAR 6 edition (content pack)
Packs/GuardianXSIAM/     Cortex platform edition (content pack)
docs/xsoar/              XSOAR 6: install and first-run guide
docs/cortex-platform/    Cortex platform: install, manual upload guide, test workbook
docs/                    shared: runbooks, model setup, content reference, chat contract, decks
scripts/                 deploy, inject_common, release build, smoke checks
lab/tools/               tenant tooling used by the runbooks
lab/cohere-north/        self-hosted small-model lab
Tests/                   content tests and demisto mocks
```

---

## Documentation index

| Doc | What it covers |
|---|---|
| [`docs/INSTALL.md`](docs/INSTALL.md) | Start here: choose XSOAR 6 or Cortex platform, what is in the download, quick start. |
| [`docs/xsoar/README.md`](docs/xsoar/README.md) | Cortex XSOAR 6: content, install by script, console or item by item in order, Jobs, first run. |
| [`docs/cortex-platform/README.md`](docs/cortex-platform/README.md) | Cortex platform: content, install, adopting the playbooks, Jobs, first run. |
| [`docs/CONTENT_REFERENCE.md`](docs/CONTENT_REFERENCE.md) | What each object in the packs is for, one content type at a time (Lists first). |
| [`docs/MODEL_SETUP.md`](docs/MODEL_SETUP.md) | Add a model provider: Foundry (key or Entra ID), Vertex, Cohere; model size. |
| [`docs/GUARDIAN_GUIDE.md`](docs/GUARDIAN_GUIDE.md) | Capabilities, who uses it, how to use and test it, Microsoft Foundry details, lab results and limits. |
| [`docs/CORTEX_PLATFORM_RUNBOOK.md`](docs/CORTEX_PLATFORM_RUNBOOK.md) | Operating the Cortex platform edition. |
| [`docs/OPERATOR_RUNBOOK.md`](docs/OPERATOR_RUNBOOK.md) | Configure a model, run intake, approve actions, toggle autonomy, kill-switch, observability. |
| [`docs/GUARDIAN_LLM_CHAT_CONTRACT.md`](docs/GUARDIAN_LLM_CHAT_CONTRACT.md) | The `guardian-llm-chat` command + `Guardian.LLM.Completion` shape every provider must implement. |
| [`lab/cohere-north/README.md`](lab/cohere-north/README.md) | The self-hosted GPU lab (real model behind Cohere North's wire contract). |
| [`lab/cohere-north/SMALL_MODEL_FINDINGS.md`](lab/cohere-north/SMALL_MODEL_FINDINGS.md) | 20-incident small-model evaluation + tuning recommendations. |
