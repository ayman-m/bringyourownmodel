# Guardian content reference: what each object is for

This page explains the role of every object in the Guardian packs, one content type at a time, so you know what you are importing and what each piece does.
It applies to both editions (Cortex XSOAR 6 and the Cortex platform); where they differ, the text says so. Counts are for the XSOAR 6 pack unless stated.

| Chapter | Status |
|---|---|
| [1. Lists](#1-lists) | written |
| [3. Automations (scripts)](#3-automations-scripts) | written |
| 2. Integrations, 4. Playbooks, 5. Incident fields and types, 6. Layouts, 7. Widgets and dashboard, 8. Jobs, 9. Pre-process rule | written as each is reviewed |

---

## 1. Lists

**What a List is.** A named piece of data stored on the server, readable and writable by automations (`!getList`, `!setList`). Guardian uses Lists for three different jobs:
its **rules** (what the agent may do), its **text** (what the model is told), and its **state** (what happened). The 16 Lists you import are rules, text and reference data. State is kept in
**runtime Lists** that Guardian creates itself (last section).

**Why this matters for import.** A List installed from a pack becomes protected content: it cannot be changed with `!setList` afterwards. That is deliberate. The rules that limit the agent
live in these Lists, so the agent can never widen its own limits from inside a run. To change a rule or a prompt, edit the List's JSON file and install the pack again. Lists have no
dependencies, so they can be imported in any order, but they must exist before the first run.

| # | List | Kind | One-line role |
|---|---|---|---|
| 1 | `guardian_policy` | rules | Which commands need a human's approval |
| 2 | `guardian_tool_allowlist` | rules | The only tools the agent may use or be offered |
| 3 | `guardian_tool_denylist` | rules | Commands and lists the agent can never touch |
| 4 | `guardian_preapproved` | rules | The narrow set of actions allowed to run without a human |
| 5 | `guardian_settings` | settings | Limits and tuning for every run |
| 6 | `guardian_persona` | text | Who the agent is and how it behaves |
| 7 | `guardian_prompt_head` | text | The start of the system prompt |
| 8 | `guardian_prompt_tail` | text | The end of the system prompt: methodology and discipline |
| 9 | `guardian_pricing` | settings | Per-model prices, so cost can be calculated |
| 10 | `guardian_skills_index` | text | The menu of skills the agent can load |
| 11-14 | `guardian_skill_*` (four lists) | text | The skills themselves |
| 15 | `guardian_kb_soc_investigation` | content | A searchable knowledge base of investigation guides |
| 16 | `guardian_model_catalog` | reference | Documented context limits of commonly used models, so a known model needs no probe |

### 1. `guardian_policy`: the approval policy

**Role.** It decides, for each command the agent asks to run, what happens next. It maps a command name to one of three **tiers**:

| Tier | What happens when the agent asks for the command |
|---|---|
| `allow` | It runs. |
| `require_approval` | It does **not** run. It is parked in the approvals queue until a person runs `!guardian-approve` (once, single-use) or `!guardian-deny`. |
| `deny` | It never runs, as if it were on the denylist. |

**What it contains.** The XSOAR 6 pack ships 41 entries, all `require_approval`: every command that changes something.
- Incident, indicator, list and playbook writes: `setIncident`, `closeInvestigation`, `createNewIncident`, `setList`, `addToList`, `createList`, `deleteList`, `setPlaybook`, `importPlaybook`, `taskComplete`, `createNewIndicator`, `setIndicator`.
- Guardian's own control automations: jobs, persona, settings and skills writers, and the simulated containment `GuardianContainmentSimulate`.
- Cortex XDR response commands (15): isolate or un-isolate an endpoint, blocklist or quarantine files, run scripts or kill processes on an endpoint, delete endpoints, tag changes, `xdr-update-incident`, `xdr-set-user-role`.
- Mail (5): `send-mail`, `reply-mail`, and Exchange delete, move and mark-as-junk.
- Splunk writes (2): `splunk-submit-event`, `splunk-job-create`.

The Cortex platform pack adds every non-read `core-*` and `xdr-*` command of the Cortex platform, also as `require_approval`. Commands that only read are not listed: they are controlled by the allowlist.

**Where it is used.**
- **`GuardianToolBridge`** enforces it. It is step 4 of the bridge's order (kill switch, denylist, allowlist, **policy**, approval, run, audit).
- **`GuardianPromptBuilder`** reads it to write an *Action policy* section into the system prompt, so the model knows in advance which commands will wait for a person. If the list cannot be read,
  the prompt says to assume every state-changing command needs approval (the policy fails closed).
- `GuardianSubagentDispatch` uses it to keep specialist sub-agents to tools that are not gated.

**How it fits with the other rules.** A command reaches the policy only if it is on the allowlist **or** is a key in the policy; a command in neither is denied by default. A command on the
allowlist but absent from the policy is a read and runs. `guardian_preapproved` can let a few `require_approval` commands skip the human step, only in `bypass` mode (see its entry).

**Changing it.** Edit `Lists/list-guardian_policy.json` and install the pack again. The agent cannot change it: `setList` and `addToList` on any target are themselves `require_approval`, and
writes to this list are on the denylist. Review changes to this file with care, because it controls what can run without a person.

### 2. `guardian_tool_allowlist`: what the agent may use

**Role.** The curated list of **read-oriented** tools. It does two jobs: `GuardianToolCatalogBuilder` turns it into the tool definitions the model is *offered* (and that is the lever for keeping the tool list within the model's token budget), and
`GuardianToolBridge` refuses any command that is neither on it nor in the policy.
**Contents.** 34 commands on XSOAR 6 (40 on the Cortex platform): case data (`getIncidents`, `getEntries`, `SearchIncidentsV2`, `findIndicators`), enrichment (`ip`, `domain`, `url`, `file`, `whois`, `endpoint`, WildFire, Unit 42, MITRE),
hunting (`splunk-search`, `xdr-get-*`, mailbox read), and Guardian's own tools (`GuardianMemory`, `GuardianKBSearch`, `GuardianSkillRead`, `GuardianCaseNote`, `GuardianAskAnalyst`, `GuardianPlanApprove`, `GuardianSubagentDispatch`, and others).
The Cortex platform adds `core-get-issues`, `core-get-cases`, `core-get-endpoints`, risky hosts and users, and `xdr-xql-generic-query`. A command that is not installed on your tenant is dropped from the offered list automatically.
**Changing it.** Edit the JSON and install again (or use the SOC Agent layout's policy tools, which write the runtime copy the layout manages).

### 3. `guardian_tool_denylist`: what the agent can never touch

**Role.** A hard stop that wins over every other rule. It has two parts: `protected_lists`, the 13 control Lists the agent may never write (policy, allowlist, denylist, kill switch, approvals, audit, pre-approved, prompts, persona,
settings, skills), and `denied`, specific commands and arguments: `setList` or `addToList` aimed at a control list, integration and API-key management (`setIntegration`, `configureInstance`, `createAPIKey`, the Guardian key and instance
writers), the generic REST verbs (`demisto-api-post`, `demisto-api-delete`, `core-api-delete`, and so on), pack installs and incident deletion.
**Why.** Defense in depth: even if the allowlist were misconfigured, these remain refused. It is enforced at step 2 of the bridge, and the denied tools are never shown to the model.

### 4. `guardian_preapproved`: the only actions that may skip a human

**Role.** A small map of `{command, argument constraints}` classes that may run **without** a person, and only when **all** of these hold: the issue's *Guardian Approval Mode* is `bypass`; the command is `require_approval` in the policy;
it is not a destructive or credential-class action; it matches a class here; and it is also in the code-side `GUARDIAN_AUTO_APPROVABLE_COMMANDS` set inside `GuardianToolBridge`. Today there are two classes: `xdr-endpoint-tag-add` (tag value limited to a
small allowed set) and `GuardianContainmentSimulate` (an inert test action). Everything else, including isolation, quarantine, script execution, close, mail and settings changes, always waits for a person in every mode.
**Changing it.** Widening autonomy needs a code change as well as an edit to this list. The list alone can never add a command to autonomy.

### 5. `guardian_settings`: limits and tuning

**Role.** The knobs every run reads at the start of each tick. Shipped values: no `MAX_TICKS` (the turn limit per run follows the model's size: 25 small, 40 medium, 60 large; an explicit `MAX_TICKS` or `overrides.max_ticks` in `guardian_model_profile` wins), `tick_cadence_seconds` 15, `model_tier` (`auto` by default: the model's size comes from the model catalogue; set `small`, `medium` or `large` only for a model that is not in the catalogue),
`max_input_tokens` (the fallback context budget: the measured profile from the daily adaptation job overrides it), `output_reserve_tokens`, loop-safety limits (`max_same_call`, `max_repeats`, `max_ask_analyst_per_run`, `max_awaiting_ticks`),
`compact_after_dropped` (the per-result limit, the incident-details limit and the history rule are derived from the input budget on every run; `evidence_truncate_bytes`, `evidence_head_tail_bytes` and `batch_cap` are optional overrides that are absent by default), `approval_sla_minutes` 60, `audit_retention_days` 30, `stalled_run_minutes` 15 with the `watchdog_policy`, and `job_guard_max_consecutive_failures` 10. Optional keys you can add: `content_filter_retries` (default 2) and `max_tool_calls_per_turn`
(default off). The **model itself is not set here**: the provider integration instance is the single source of truth (`!guardian-model`).
**Changing it.** Edit the JSON and install again. The per-model overrides you can change live are in the runtime list `guardian_model_profile`.

### 6. `guardian_persona`: who the agent is

**Role.** The agent's identity and operating rules: a SOC incident-investigation analyst working inside the platform. `GuardianPromptBuilder` reads it at the start of every run, and the SOC Agent layout shows it in the persona view.
Changing it changes how the agent introduces and conducts itself, without touching any rule that limits it.

### 7. `guardian_prompt_head` and 8. `guardian_prompt_tail`: the system prompt

**Role.** Together with the persona, they are the system prompt the model receives. The **head** is the stable opening (the mission). The **tail** is the long stable closing: memory discipline, how to research threat intelligence, the boundary on
self-modification, the eight-step investigation workflow, how to treat untrusted case data (it is delimited and never obeyed), and tool-use and anti-hallucination discipline. They are kept stable on purpose, so the provider's prompt cache can reuse them.
`GuardianPromptBuilder` assembles them with the persona, the action policy and the skills index.

### 9. `guardian_pricing`: what a turn costs

**Role.** Prices per million tokens for each model (`input_per_1m`, `output_per_1m`, `cached_input_per_1m`). `GuardianCostLedger` looks the model up by the name the provider reports to turn token counts into US dollars.
**Important.** It ships with one model (`gemini-2.5-flash`). A model with no row, such as a Foundry deployment, shows **USD 0.00** while tokens are still counted. Add a row for your deployment's model name and install again.

### 10. `guardian_skills_index` and 11-14. the four `guardian_skill_*` lists: skills

**Role.** A *skill* is a long reference document the agent loads only when it needs it, so it does not fill every prompt. The **index** is the menu: `GuardianPromptBuilder` puts it in the system prompt, which is built once per run; the agent then calls
`GuardianSkillRead name=<skill>` to open one. The XSOAR 6 pack ships four skills, and the Cortex platform pack ships eleven: the four below plus seven more:
`cortex_xql`, `cortex_detection_investigation`, `cortex_posture_misconfiguration`, `cortex_identity_risk`,
`cortex_vulnerability_triage`, `cortex_attack_path` and `cortex_data_health` (a data-collection health issue: a silent
source, a modeling yield collapse, misrouted events).

| List (XSOAR 6 / Cortex platform) | Skill (XSOAR 6 / Cortex platform) | What it teaches |
|---|---|---|
| `guardian_skill_xsoar_case_triage` / `guardian_skill_cortex_triage` | `xsoar_case_triage` / `cortex_triage` | Triage reference: severity and status codes, close reasons, how to rank a queue |
| `guardian_skill_xsoar_case_investigation` / `guardian_skill_cortex_case_investigation` | `xsoar_case_investigation` / `cortex_case_investigation` | The end-to-end procedure for investigating a case |
| `guardian_skill_xsoar_platform_reference` / `guardian_skill_cortex_issue_reference` | `xsoar_platform_reference` / `cortex_issue_reference` | The War Room, commands and query syntax |
| `guardian_skill_build_xsoar_playbook` / `guardian_skill_build_cortex_playbook` | `build_xsoar_playbook` / `build_cortex_playbook` | How to build a playbook from examples |

A playbook input can preload a skill; by default skills are loaded on demand.

### 15. `guardian_kb_soc_investigation`: the knowledge base

**Role.** A searchable knowledge base of 20 MITRE ATT&CK technique investigation guides and 10 incident-response playbooks. The agent searches it with `GuardianKBSearch` while investigating, to ground its reasoning in a procedure instead of improvising.

### 16. `guardian_model_catalog`: documented limits of known models

**Role.** The published context limits of commonly used models (146 entries, checked 2026-10-09; see `docs/reference/model-catalog/`). Each entry has the vendor's context window, maximum input and maximum output, whether the model supports tools and structured output, the cloud provider's own cap where it differs (`provider_limits`: Azure Foundry, Vertex AI, Amazon Bedrock) and `probe`: `skip` for a closed frontier model, `confirm` for an open-weight model whose served window depends on the runtime.
**How it is used.** `GuardianModelProfileCheck` (the "Resolve model profile" task) looks the enabled model up by name or alias and, for a model that needs no probe, saves a `documented` profile; `!guardian-probe-model` uses it as the search ceiling and as the figure the measured window is compared with (within 20% confirms it); `!guardian-model` shows it. It is pack-seeded data like `guardian_pricing`: it is only read, never written at runtime, and it does not widen what the agent may do.
**To change it.** Edit `docs/reference/model-catalog/model_catalog.json`, run `python3 scripts/build_model_catalog.py` (it regenerates the List in both packs; do not hand-edit the List file) and install the pack again.

### Runtime Lists: created by Guardian, not imported

These hold state, so they must stay writable. A pack-installed List is locked, so `!GuardianBootstrap` creates them at run time instead (run it once, from any War Room, on a new tenant; the Jobs and first run also create them on first use).

| List | Holds |
|---|---|
| `guardian_audit` | One redacted row for every tool dispatch (the audit trail) |
| `guardian_approvals_ledger` | Every parked approval and its status (pending, approved, denied, consumed) |
| `guardian_kill_switch` | The kill switch state (on or off) |
| `guardian_memory` | The agent's durable memory across runs |
| `guardian_cost_ledger` | The rolled-up cost by day, model and trigger |
| `guardian_model_profile` | The measured context budget of the model, plus operator `overrides` you may edit |
| `guardian_model_calibration` | The history of model probes |
| `guardian_skills_crud_index` | Skills created or changed at run time (the pack's own skill index stays fixed) |
| `guardian_jobs_registry`, `guardian_seed_version` | Internal bookkeeping |

Lists the SOC Agent layout manages (such as a runtime copy of the allowlist written by **Apply Policy**) are also runtime Lists.

---

## 3. Automations (scripts)

**What an automation is.** A Python script stored on the server and run in a container. It is called by a command (`!GuardianPing`), by a playbook task, by a layout button, by a dashboard widget, by a Job, or by another script. Guardian ships **71** of them.
They are grouped below by **who runs them**, because that decides which gate a script sits behind. Each script appears once, in its main class; other places it is used are in the *Called by* column.
*Workflow* refers to the numbered Workflow sections of the animated deck (`docs/Guardian-Overview.html`): 1 Approval policy (the 7 checks), 2 Tool catalogue, 3 The system prompt, 4 One reasoning turn, 5 Skills and knowledge, 6 A run starts and ends, 7 Keeping the system healthy, 8 Install and upgrade.

| Class | Who runs it | Scripts |
|---|---|---|
| A | The agent: a tool the model calls | 10 |
| B | The loop engine | 8 |
| C | An operator, as a War Room command | 11 |
| D | A playbook preflight task, or the intake gate | 4 |
| E | A layout section or button | 21 |
| F | A dashboard widget | 5 |
| G | Install, upgrade and maintenance | 7 |
| H | Evaluation and testing | 4 |
| I | The shared library | 1 |

Every script is a command whose name is the script name (`!GuardianMemory`), except the operator commands, which are registered as `!guardian-*`. A script that has no typed command (a layout section, a widget, a pre-process script) shows "none" in the *Command* column.
Argument lists show the main arguments; the full list is in each script's `.yml`.

### A. Tools the agent calls

These are the only scripts the model can name in a tool call. Nine are on `guardian_tool_allowlist`, so the tool catalogue offers them to the model. The tenth, `GuardianSkillsCRUD`, is classified only in `guardian_policy` (`require_approval`): the bridge accepts it but always parks it for a person, and the shipped allowlist does not offer it.

| Script | Command (as typed) | Purpose | Called by | Workflow |
|---|---|---|---|---|
| `GuardianSkillRead` | `!GuardianSkillRead name=<skill>` | Loads one skill's full text on demand. Rejects any name that is not listed and enabled in the skills index. | The model; the optional "Load skill" task of GuardianAgentLoop | 5 Skills and knowledge |
| `GuardianMemory` | `!GuardianMemory op=store\|search key= value= query=` | Stores or recalls durable notes across incidents in `guardian_memory`, ranked by keyword, recency and recall count; expired rows are dropped. | The model; GuardianCaseCapture | 5 Skills and knowledge |
| `GuardianKBSearch` | `!GuardianKBSearch query=<words> [tags= technique= limit=]` | Searches the investigation knowledge base. Returns title, technique and a snippet, ranked; no match returns an empty result. | The model; the phishing specialist in GuardianSubagentDispatch | 5 Skills and knowledge |
| `GuardianAskAnalyst` | `!GuardianAskAnalyst question="..."` | Posts a question to the War Room and pauses the loop until an analyst answers with `!guardian-chat`, or a tick limit passes. | The model | 4 One reasoning turn |
| `GuardianCaseNote` | `!GuardianCaseNote content="..."` | Writes one bounded, secret-scrubbed note tagged `guardian-case-note` to the current incident only. | The model | 2 Tool catalogue; 4 One reasoning turn |
| `GuardianPlanApprove` | `!GuardianPlanApprove steps='[{tool_name, tool_args}]' [summary=]` | Parks a multi-step plan as one approval. After `!guardian-approve`, each step runs through the bridge with its own single-use token. | The model | 1 Approval policy |
| `GuardianPlaybookMonitor` | `!GuardianPlaybookMonitor incident_id=<id>` | Reports whether an incident's playbook ran to success and, if not, which tasks failed and why, including sub-playbooks. | The model | 2 Tool catalogue; 4 One reasoning turn |
| `GuardianDiagnostics` | `!GuardianDiagnostics [name= limit=]` | Summarises integration instance health, or re-tests one instance and reads its fetch history. Catches HTTP 200 replies that report failure. | The model | 2 Tool catalogue; 4 One reasoning turn |
| `GuardianSubagentDispatch` | `!GuardianSubagentDispatch specialist= task= [max_iterations=]` | Runs one bounded, read-only specialist investigation (today the phishing analyst) and returns a single summary. | The model; the GuardianSubagentRunner playbook (a test form) | 4 One reasoning turn |
| `GuardianSkillsCRUD` | `!GuardianSkillsCRUD op=create\|update\|delete\|toggle name= ...` | Creates, updates, soft-deletes or toggles run-time skills, only after a person approves. A delete also needs `confirm=CONFIRM`. | The model, through the approval gate | 1 Approval policy; 5 Skills and knowledge |

`GuardianSkillsCRUD` manages only skills recorded in `guardian_skills_crud_index`; the skills shipped with the pack stay read-only. Every update or delete saves a snapshot first, with a SHA-256 before and after, and a delete is restorable.
`GuardianSkillRead` and `GuardianPromptBuilder` both read that index, so a skill created this way appears in the skills menu and can be loaded.

### B. The loop engine

These scripts are the machinery of a run. The model never names them; `GuardianReasoningTick` and its neighbours call them.

| Script | Command (as typed) | Purpose | Called by | Workflow |
|---|---|---|---|---|
| `GuardianReasoningTick` | `!GuardianReasoningTick prompt="..." [skill= use_prebuilt=true]` | One step of the loop: kill-switch check, one model turn, cost charge, tool calls through the bridge, state saved, next tick scheduled. | The "Run Guardian model session" task of GuardianAgentLoop and GuardianEvalInvestigate; then itself, once per turn. By hand it runs once and does not reschedule | 4 One reasoning turn; 6 A run starts and ends |
| `GuardianToolBridge` | `!GuardianToolBridge tool_name= [tool_args= approval_id= ...]` | The single checkpoint for every agent tool call: kill switch, denylist, allowlist, policy, approval, then run, redact, audit. Never raises. | GuardianReasoningTick; GuardianSubagentDispatch | 1 Approval policy |
| `GuardianPromptBuilder` | `!GuardianPromptBuilder [summary_only=]` | Assembles the system prompt in a fixed order: head, action policy, persona, skills menu, approval mode, tail. | GuardianReasoningTick when a run starts; the "Build system prompt" task of the two run playbooks; `!guardian-plan` | 3 The system prompt |
| `GuardianToolCatalogBuilder` | `!GuardianToolCatalogBuilder [use_snapshot=]` | Builds the tool definitions offered to the model: live commands, limited to the effective allowlist minus the denylist, trimmed to the token budget. | GuardianReasoningTick; the "Build tool list" task; `!guardian-tools`; GuardianSubagentDispatch | 2 Tool catalogue |
| `GuardianCostLedger` | `!GuardianCostLedger usage= model= [run_id= trigger=]` | Prices one model call from `guardian_pricing` and adds tokens and US dollars to the day, model and trigger totals in `guardian_cost_ledger`. | GuardianReasoningTick (every model turn); GuardianCompactCommand; GuardianPlanCommand; GuardianSubagentDispatch | 4 One reasoning turn |
| `GuardianAuditWrite` | `!GuardianAuditWrite action= status= [target= tick_id= run_id= detail=]` | Writes one redacted row to `guardian_audit` and one tagged War Room note for a tool call or control action. Append-only. | GuardianToolBridge (every dispatch); GuardianReasoningTick; GuardianApprovalResolve; GuardianKillSwitchToggle; GuardianJobGuard; GuardianHousekeeping; GuardianSubagentDispatch; the Apply Policy and New Investigation buttons | 1 Approval policy |
| `GuardianCompact` | `!GuardianCompact messages= [keep_recent=]` | Summarises the older part of a transcript into one checkpoint message, copying identifiers exactly. Returns ok=false on failure instead of raising. | GuardianReasoningTick (automatic compaction); GuardianCompactCommand | 4 One reasoning turn |
| `GuardianJobGuard` | `!GuardianJobGuard action=check\|report [job_name= outcome=]` | The per-job safety valve. `check` says whether a job may run; `report` counts consecutive failures and disables the job at the limit (default 10). | GuardianReasoningTick (checks each tick, reports when the run ends); GuardianJobGuardCheck | 6 A run starts and ends; 7 Keeping the system healthy |

### C. Operator commands

Typed in a War Room by an analyst. None is on the allowlist or in the policy, so the agent cannot call them: it cannot approve its own requests or flip its own kill switch.

| Script | Command (as typed) | Purpose | Called by | Workflow |
|---|---|---|---|---|
| `GuardianApprovalResolve` | `!guardian-approve approval_id=<id> [action= reason= confirm=CONFIRM]` | Approves a pending request (`action=deny` denies it). The next tick runs it once with a single-use token. Credential-class actions need `confirm=CONFIRM`. | An analyst | 1 Approval policy |
| `GuardianDeny` | `!guardian-deny approval_id=<id> [reason=]` | Denies a pending approval. Nothing runs and the model is told on the next tick. A thin wrapper over the same resolve code. | An analyst | 1 Approval policy |
| `GuardianKillSwitchToggle` | `!guardian-killswitch state=on\|off [reason=]` | The only writer of `guardian_kill_switch`. `on` halts the agent within one poll cycle; `off` resumes it. The change is audited. | An analyst; GuardianSocAgentSetState | 1 Approval policy |
| `GuardianChatCommand` | `!guardian-chat message="..." [incident_id=]` | Queues an analyst message for the next tick and answers a paused question. A finished loop is re-opened but must be run again. | An analyst | 4 One reasoning turn |
| `GuardianCompactCommand` | `!guardian-compact [incident_id= keep_recent=]` | Compacts this incident's transcript now instead of waiting for the threshold, and charges the summary call to the cost ledger. | An analyst | 4 One reasoning turn |
| `GuardianCostCommand` | `!guardian-cost` | Shows spend per day and per model from `guardian_cost_ledger`, plus this run's cost. Read-only; works with no model configured. | An analyst | 4 One reasoning turn |
| `GuardianPlanCommand` | `!guardian-plan [incident_id=]` | Makes one billed model call with no tools to draft an investigation plan, posts it to the War Room and records the cost. | An analyst | 4 One reasoning turn |
| `GuardianToolsCommand` | `!guardian-tools` | Shows the tools the model can actually call: the allowlist after live discovery, denylist filtering and the token trim, with dropped or missing commands. | An analyst | 2 Tool catalogue |
| `GuardianModelCommand` | `!guardian-model` | Shows each configured model integration instance (provider, model) and the size and budgets a new run would use. Read-only. | An analyst | 7 Keeping the system healthy |
| `GuardianProbeModel` | `!guardian-probe-model [max_probe_tokens= output_reserve= safety_margin= max_response_seconds= warm_up= force=]` | Measures the enabled model: characters per token, usable context window, tool and structured-output support, and a recommended input budget. A documented frontier model (see `guardian_model_catalog`) gets no window search unless `force=true`; any other known model is searched up to its documented limit and compared with it (within 20% confirms it). Billable; changes no settings. | An analyst; the "Probe the model" task of GuardianModelAdaptation | 7 Keeping the system healthy |
| `GuardianHelpCommand` | `!guardian-help` | Prints the operator command reference. Needs no Lists or context, so it works straight after install. | An analyst | not a flow step |

### D. Playbook preflight and the intake gate

The three checks are the visible set-up tasks at the front of a run. They show the operator what the run will use and give an early exit. They are not the controls themselves: the tick checks the kill switch and the job guard again on every turn, and the bridge checks the kill switch before every command.

| Script | Command (as typed) | Purpose | Called by | Workflow |
|---|---|---|---|---|
| `GuardianKillSwitchCheck` | `!GuardianKillSwitchCheck` | Reads `guardian_kill_switch` and sets `Guardian.Preflight.KillSwitch.proceed`; the playbook branches to a Halted task. Read-only. An unreadable List lets the run proceed. | The first task of GuardianAgentLoop, GuardianEvalInvestigate and GuardianModelAdaptation | 6 A run starts and ends |
| `GuardianJobGuardCheck` | `!GuardianJobGuardCheck` | For a run started by a scheduled job, asks GuardianJobGuard whether that job was auto-disabled. A run with no job, or any error, proceeds. | The "Check job guard" task of GuardianAgentLoop and GuardianEvalInvestigate | 6 A run starts and ends |
| `GuardianModelProfileCheck` | `!GuardianModelProfileCheck` | Resolves model size, input budget and tool-list budget (override, profile, settings, default), shows each source (documented, confirmed, measured, override), and saves `Guardian.ModelProfile`. For a known model with nothing better on file it first saves a `documented` profile from `guardian_model_catalog`. Never blocks. | The "Resolve model profile" task of GuardianAgentLoop and GuardianEvalInvestigate | 6 A run starts and ends |
| `GuardianIntakeHygiene` | none (pre-process script) | Drops a new "Guardian Agent Run" incident while the kill switch is on, and drops an intake sweep when no open work exists. Fails open. | The `GuardianIntakeHygiene` pre-process rule | 6 A run starts and ends |

`GuardianModelProfileCheck` also warns when the resolved model size differs from the provider instance's "Model size" setting, when the probed profile is old, and when the probe (or the model catalogue) says the model does not honour tools.
The intake gate only stops new runs; a run already in flight is stopped by the tick and the bridge.

### E. Layout sections and buttons

Display scripts run when an analyst opens a layout; button scripts run on a click and act as the operator. None is on the allowlist. The display scripts only read.
Every display script returns an HTML entry built with the shared `guardian_html_*` helpers (every value is escaped; no script, style block, image or external resource) and falls back to the earlier text or markdown if the HTML cannot be built, so a section never shows an error.

**Guardian Agent Run layout (Guardian tab sections).**

| Script | Command (as typed) | Purpose | Called by | Workflow |
|---|---|---|---|---|
| `GuardianLayoutRecommendedActions` | none (layout section) | Shows the actions waiting for approval on this incident (from `guardian_approvals_ledger`) as a table with risk tier, time left before the approval expires, a redacted argument summary and how to resolve each, then the agent's final conclusion as a card. | GuardianAgentRunLayout; the task in GuardianApprovalGate | 1 Approval policy |
| `GuardianLayoutToolLedger` | none (layout section) | Shows this incident's rows from `guardian_audit` as an HTML table (tick, time, tool, status badge, target, duration, note) under a count per status. | GuardianAgentRunLayout | 1 Approval policy |
| `GuardianLayoutTrace` | none (layout section) | Turn-by-turn trace from `Guardian.Loop.messages`: status, tick, cost, verdict, then one card per turn with its reasoning and a table of its tool calls and their outcome. | GuardianAgentRunLayout | 4 One reasoning turn |

**Guardian Agent Run layout (action buttons).** Each runs as the operator, takes only mandatory arguments (so the pop-up asks for all of them), and is listed in the code-level operator-only sets of `GuardianToolBridge` and `GuardianToolCatalogBuilder`, so the model can neither see nor call it. Approve and Deny refuse an approval that belongs to another incident.

| Script | Command (as typed) | Purpose | Called by | Workflow |
|---|---|---|---|---|
| `GuardianButtonApprove` | none (button "Approve") | Approves a pending action by its approval ID through `guardian-approve`; the agent runs it once on its next tick. | GuardianAgentRunLayout | 1 Approval policy |
| `GuardianButtonApproveCredential` | none (button "Approve (credential tier)") | The same for a credential-tier request; it also asks for the word CONFIRM. | GuardianAgentRunLayout | 1 Approval policy |
| `GuardianButtonDeny` | none (button "Deny") | Denies a pending action by its approval ID and a reason through `guardian-deny`; the reason is passed back to the model. | GuardianAgentRunLayout | 1 Approval policy |
| `GuardianButtonReply` | none (button "Reply to agent") | Queues a message for the agent through `guardian-chat`. | GuardianAgentRunLayout | 4 One reasoning turn |
| `GuardianButtonCompact` | none (button "Compact transcript") | Compacts this run's transcript now through `guardian-compact` (one billed model call). | GuardianAgentRunLayout | 4 One reasoning turn |
| `GuardianButtonPause` | none (button "Pause all runs") | Turns the global kill switch on through `guardian-killswitch`. It halts every run, not only this one: there is no per-run pause. | GuardianAgentRunLayout | 1 Approval policy |
| `GuardianButtonResume` | none (button "Resume all runs") | Turns the global kill switch off through `guardian-killswitch`. | GuardianAgentRunLayout | 1 Approval policy |

**SOC Agent indicator layout (sections).**

| Script | Command (as typed) | Purpose | Called by | Workflow |
|---|---|---|---|---|
| `GuardianSocAgentReadiness` | none (section and button) | Read-only readiness report: an overall badge and one row per check (kill switch, runtime allowlist, tool discovery, provider command) with its state and next step. Never refreshes discovery. | The "Agent Readiness" section of GuardianSocAgentLayout; GuardianSocAgentReadinessCheck | 7 Keeping the system healthy |
| `GuardianLayoutSocAgentTools` | none (layout section) | Shows the effective allowlist, whether each allowed command is on the last discovery snapshot (`guardian_tool_available`), and the available commands by instance. | GuardianSocAgentLayout | 2 Tool catalogue |
| `GuardianLayoutSocAgentMemory` | none (layout section) | Shows redacted metadata of `guardian_memory`: key, scope, tags, retention, freshness, recall count. Never the stored values. | GuardianSocAgentLayout | 5 Skills and knowledge |
| `GuardianLayoutSocAgentPersona` | none (layout section) | Shows the active persona from `guardian_persona`, the same text the prompt builder reads. | GuardianSocAgentLayout | 3 The system prompt |

**SOC Agent indicator layout (action buttons).** Each runs as the operator and is not reachable by the agent.

| Script | Command (as typed) | Purpose | Called by | Workflow |
|---|---|---|---|---|
| `GuardianToolRegistryRefresh` | none (button "Refresh Tools") | Discovers the live command surface into `guardian_tool_available`. On first use it creates the editable `guardian_tool_allowlist_runtime` from the pack allowlist; never overwrites it later. | GuardianSocAgentLayout | 2 Tool catalogue |
| `GuardianSocAgentValidateToolPolicy` | none (button "Validate Tools") | Checks the effective allowlist against the last discovery snapshot. Read-only. | GuardianSocAgentLayout | 2 Tool catalogue |
| `GuardianSocAgentApplyToolPolicy` | none (button "Apply Policy") | Validates the approved JSON policy against the snapshot, replaces `guardian_tool_allowlist_runtime` and audits. The pack's own allowlist never changes. | GuardianSocAgentLayout | 2 Tool catalogue |
| `GuardianSocAgentSetState` | none (buttons "Pause Agent", "Resume Agent") | Maps pause and resume to the audited `guardian-killswitch` command, so the layout does not write the kill switch itself. | GuardianSocAgentLayout | 1 Approval policy |
| `GuardianSocAgentReadinessCheck` | none (button "Agent Readiness") | Re-runs GuardianSocAgentReadiness and returns a short confirmation; the full report is in the readiness panel. | GuardianSocAgentLayout | 7 Keeping the system healthy |
| `GuardianSocAgentCreateInvestigation` | none (button "New Investigation") | After an analyst supplies a name and details, creates a "Guardian Agent Run" incident and writes an audit entry. | GuardianSocAgentLayout | 6 A run starts and ends |
| `GuardianSocAgentExportConfiguration` | none (button "Export Config") | Writes a redacted configuration snapshot (hashes, counts, timestamps, state) to the War Room. No secrets, persona text or memory values. | GuardianSocAgentLayout | not a flow step |

### F. Dashboard widgets

All five belong to the GuardianObservability dashboard. Each only reads, never creates a missing List, and shows an empty widget instead of an error.

| Script | Command (as typed) | Purpose | Called by | Workflow |
|---|---|---|---|---|
| `GuardianWidgetApprovalsQueue` | none (widget) | Table of pending approvals from `guardian_approvals_ledger`, oldest first, with age in minutes. | GuardianObservability dashboard | 1 Approval policy |
| `GuardianWidgetToolLedger` | none (widget) | Pie chart of tool calls from `guardian_audit` across all runs, by status. | GuardianObservability dashboard | 1 Approval policy |
| `GuardianWidgetCost` | none (widget) | Line chart of cost in US dollars per day and per model from `guardian_cost_ledger`. | GuardianObservability dashboard | 4 One reasoning turn |
| `GuardianWidgetEventFeed` | none (widget) | Feed of recent denials, failures, kill-switch changes and disabled jobs from `guardian_audit`, newest first. | GuardianObservability dashboard | 7 Keeping the system healthy |
| `GuardianWidgetLoopHealth` | none (widget) | Table of runs by loop status, average ticks, stalled runs and the kill-switch state. Reads each run's state through `!GuardianHousekeeping probe_key=Loop`, capped per refresh. | GuardianObservability dashboard | not a flow step |

### G. Install, upgrade and maintenance

| Script | Command (as typed) | Purpose | Called by | Workflow |
|---|---|---|---|---|
| `GuardianBootstrap` | `!GuardianBootstrap` | Creates the run-time Lists that cannot ship with the pack, only where missing or empty; never overwrites data. Safe to repeat. | An operator after every install or reinstall; GuardianSeedContent | 8 Install and upgrade |
| `GuardianSeedContent` | `!GuardianSeedContent` | Version-aware seeding: runs Bootstrap, then ensures the configuration Lists and skill entries exist, overwriting a List only if unchanged since last seeded, after a snapshot. | An operator at install and on each upgrade | 8 Install and upgrade |
| `GuardianPing` | `!GuardianPing` | Liveness check. Always returns "pong", confirming that Guardian automations run on this server. | An operator | 8 Install and upgrade |
| `GuardianHealthCheck` | `!GuardianHealthCheck [test_model= test_routing= test_bridge= max_model_calls= verbose=]` (Cortex platform also `include_xql=`) | Read-only self-test: checks the package content, the Lists, the integrations, the model (a tiny call), the core scripts and the tool chokepoint, and returns one report with PASS, WARN or FAIL for every check and the likely cause and fix for every problem. It never writes a List, toggles the kill switch or runs a Job or playbook. | An operator after an install or an upgrade | 8 Install and upgrade |
| `GuardianContentBackup` | `!GuardianContentBackup` | Exports all custom content as a tar.gz attached to the War Room, with item counts by type. For backup or comparison with the pack files. | An operator | 8 Install and upgrade |
| `GuardianHousekeeping` | `!GuardianHousekeeping [probe_key=]` | The hourly sweep of five independent steps (below). Also answers `probe_key=<key>` so a widget can read another incident's context. | The GuardianHousekeeping job, through its playbook; an operator; GuardianWidgetLoopHealth | 7 Keeping the system healthy |
| `GuardianModelProfileUpdate` | `!GuardianModelProfileUpdate [force=]` | Saves the latest probe result (`Guardian.ModelProbe`) to `guardian_model_profile` as a `documented`, `confirmed`, `measured` or `quota` record (the 20% rule against `guardian_model_catalog`). Keeps the old profile if the result is untrustworthy; applies `guardian_settings.max_input_tokens_cap` when set; never touches `overrides`. | The "Save the model profile" task of GuardianModelAdaptation; an operator | 7 Keeping the system healthy |
| `GuardianCaseCapture` | `!GuardianCaseCapture` | Writes one `guardian_memory` case record per incident closed in the last 30 hours with a verdict, updated in place, independent of the model. | The GuardianCaseCapture job (every four hours), through its playbook | 5 Skills and knowledge |

**What `GuardianBootstrap` creates.** Ten Lists: `guardian_kill_switch`, `guardian_audit`, `guardian_cost_ledger`, `guardian_memory`, `guardian_approvals_ledger`, `guardian_jobs_registry`, `guardian_seed_version`, `guardian_skills_crud_index`, `guardian_model_calibration` and `guardian_model_profile`.
**What `GuardianSeedContent` does on a normal install.** The configuration Lists delivered by the pack are protected, so for them it only verifies and records them as the baseline. It writes a placeholder only to restore a List that is missing, and it does not recreate skills listed in `guardian_seed_version.deleted_skills`.
**The five steps of `GuardianHousekeeping`.** Each runs on its own, so one failure does not stop the others: (1) consolidate each active run's audit buffer into `guardian_audit`; (2) move `guardian_audit` rows older than `audit_retention_days` (30) into per-day archive Lists;
(3) mark approvals still pending after `approval_sla_minutes` (60) as expired; (4) remove `guardian_memory` rows past their time to live; (5) the stalled-run watchdog: find runs still marked running whose incident has not changed for `stalled_run_minutes` (15), then restart the loop or stop it and release any pending approval, as `watchdog_policy` says.

### H. Evaluation and testing

| Script | Command (as typed) | Purpose | Called by | Workflow |
|---|---|---|---|---|
| `GuardianEval` | `!GuardianEval action=run\|score\|report\|compare [case_ids= incident_ids= run_label= ...]` | Replays canned cases through the real loop and records outcome metrics in `guardian_eval_results`. `action` defaults to `run`, which starts billable runs. | An operator; the GuardianEvalScore job (`action=score`) | not a flow step |
| `GuardianEvalHarvest` | `!GuardianEvalHarvest` | Turns real closed incidents with a verdict into evaluation cases in `guardian_eval_cases_runtime`. Synthetic runs are excluded; the expected verdict is Guardian's own conclusion. | The GuardianEvalHarvest job (daily), through its playbook | not a flow step |
| `GuardianSimulateIncidents` | `!GuardianSimulateIncidents [scenario= count= incidenttype= investigate=]` | Creates synthetic test incidents tagged `guardiantriggersource=simulate`. They are only investigated if `investigate=true`, which costs model calls. | An operator | not a flow step |
| `GuardianContainmentSimulate` | `!GuardianContainmentSimulate endpoint_id= [reason=]` | A harmless stand-in for isolating an endpoint: writes one War Room note and one context entry describing what isolation would do. Changes nothing. | Through the bridge as a `require_approval` command and one of the two pre-approved classes; used to test the approval flow | 1 Approval policy |

### I. The shared library

| Script | Command (as typed) | Purpose | Called by | Workflow |
|---|---|---|---|---|
| `GuardianCommon` | `!GuardianCommon` | Source of the shared `guardian_*` helpers, copied into every other script when the pack is built. Run directly, it self-checks every helper and returns "ok". | The build step; an operator for the self-check | not a flow step |

Scripts cannot import one another on the server, which is why the helpers are copied rather than imported. Operators never run the copy step: it happens when the release is built.

### How a script is reached

**The agent** can reach a script only through `GuardianToolBridge`. The catalogue offers the model the commands on the effective allowlist (`guardian_tool_allowlist_runtime` once the SOC Agent layout has created it, otherwise the pack's `guardian_tool_allowlist`), minus the denylist.
If the model names a command it was not offered, the bridge still applies the same order: kill switch, denylist, allowlist, policy, approval, run, audit. A command that is neither on the allowlist nor a key in `guardian_policy` is denied by default.
A command in the policy as `require_approval` (such as `GuardianSkillsCRUD` or `GuardianContainmentSimulate`) is parked until a person approves it. A command on the allowlist but absent from the policy is a read and runs.

**Operator-only commands** (class C, the layout buttons, `GuardianBootstrap`, `GuardianSeedContent`, `GuardianContentBackup`, the evaluation and simulation commands) are on neither list, so the bridge refuses them even if the model names them. They run when a person types them or clicks the button.
The agent can ask a person for a decision, through `GuardianAskAnalyst` and `GuardianPlanApprove`; it can never give itself one.

**Scripts the platform runs** (playbook tasks, Job sweeps, layout sections, widgets, the pre-process rule) run with the platform's own rights and do not pass through the bridge. They are not agent tools.

### Differences on the Cortex platform

All 71 scripts exist in both editions, and no script is present in only one of them. The two editions carry the same logic apart from the rows below. Other differences are wording (for example "issue" for "incident") and the marketplace flag in each `.yml`.

| Script | XSOAR 6 | Cortex platform |
|---|---|---|
| `GuardianIntakeHygiene` | Runs from the pre-process rule and drops runs while the kill switch is on. | The script ships, but no pre-process rule is installed because pre-process rules do not run. The tick and the bridge still check the kill switch. |
| `GuardianHousekeeping` | The watchdog sees every stalled "Guardian Agent Run" incident. | The watchdog sees only runs that have an issue; a Job run has none. |
| `GuardianSimulateIncidents` | Creates the incident with `createNewIncident`. | Creates an issue by inserting an alert, then finds it by name (up to about a minute). The `incidenttype` argument has no effect. |
| `GuardianSocAgentCreateInvestigation` | Creates a "Guardian Agent Run" incident. | Creates an issue by inserting an alert through the Core REST API integration, then finds it by name. The returned id is empty if the issue is not visible after about a minute. |
| `GuardianReasoningTick`, `GuardianCompact`, `GuardianCompactCommand`, `GuardianPlanCommand`, `GuardianProbeModel`, `GuardianSubagentDispatch` | Send the model call's JSON arguments as plain text. | Send `messages`, `tools`, `response_format` and the compaction transcript as `b64:` base64 JSON. The model integrations and `GuardianCompact` accept both forms. |
| `GuardianCommon` | Shared block without the encoder. | The shared block adds `guardian_arg_encode` and `guardian_arg_decode`. |
| `GuardianToolBridge`, `GuardianPlanApprove` | The destructive risk tier names the `xdr-*` containment commands. | The tier also holds every non-read `core-*` and `xdr-*` command. Endpoint tag commands stay in the soft tier. |
| `GuardianToolBridge`, `GuardianPlanApprove` (list arguments) | The bridge joins a list of plain values into one comma-separated string before any gate runs, except for `setIncident` and the `Guardian*` scripts; `GuardianPlanApprove` does the same to each plan step so the approved arguments match. | The same, and `core-get-case-extra-data` keeps its list: a one-item list is passed on as its item and a longer list is refused. |
| `GuardianSkillRead` | Skill names `xsoar_case_triage`, `xsoar_case_investigation`, `xsoar_platform_reference`, `build_xsoar_playbook`. | The same four skills under `cortex_*` and `build_cortex_playbook` names. |
| The five widget scripts (class F) | Installed with the dashboard. | In the pack, but the platform does not install the dashboard and widgets. |
| Scripts called by playbooks (class D, the Job sweeps) | Run once the pack is installed. | Run only after the pack's playbooks are adopted. |

The Cortex platform pack also adds six read commands to the allowlist (`core-get-issues`, `core-get-cases`, `core-get-endpoints`, `core-list-risky-hosts`, `core-list-risky-users`, `xdr-xql-generic-query`); these are native commands, not Guardian scripts.

### Scripts not yet in a workflow

These have no natural step in the eight flows and can be added later: `GuardianHelpCommand`, `GuardianSocAgentExportConfiguration`, `GuardianWidgetLoopHealth` (a dashboard widget, left out on purpose), `GuardianEval`, `GuardianEvalHarvest`, `GuardianSimulateIncidents` and `GuardianCommon`.
