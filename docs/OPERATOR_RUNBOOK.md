# Guardian on Cortex XSOAR 6 — Operator Runbook

Guardian is an AI incident-investigation agent that runs entirely inside XSOAR 6 as the `Guardian`
content pack. This runbook covers the day-to-day operator tasks: configuring the model, running the
autonomous intake, approving actions, toggling autonomy, and the emergency kill-switch.

> **Mental model.** A scheduled **Job** creates a *Guardian Agent Run* incident and starts the
> **GuardianAgentLoop** playbook. The playbook shows each step: check the kill switch, check the job
> guard, resolve the model profile, build the system prompt, build the tool list, then one task that holds the
> whole conversation with the model. The loop calls an LLM (Gemini via Vertex) which picks XSOAR commands
> as tools. Every tool call passes through **GuardianToolBridge**, the single security chokepoint:
> *kill-switch → denylist → allowlist (default-deny) → policy tier → human approval (or pre-approved
> autonomous execution) → run → audit.* Read-only investigation happens freely; anything that changes
> state is gated to a human unless you explicitly enable autonomy for that incident.

---

## 0. Prerequisites & deployment

- **Reach the tenant:** point `demisto-sdk` at your Cortex XSOAR 6 server. If the server has no
  externally routable address, establish whatever access path your environment provides (bastion,
  VPN, or cloud-provider tunnel) and map it to a local port first.
  `.env` (repo root) holds `DEMISTO_BASE_URL`, `DEMISTO_API_KEY`, and `DEMISTO_VERIFY_SSL`
  (`false` only if the server presents a self-signed certificate).
- **Deploy the pack** (delivers all content + creates the Jobs, which pack-zip alone can't):
  ```bash
  bash scripts/deploy.sh          # pack-zip upload + scripts/deploy_jobs.py (REST job create)
  ```
  Re-run `deploy.sh` for any content change — pack-installed items are `system:true` and can't be
  edited item-by-item.
- **Manual install (no `demisto-sdk`):** Settings → Integrations → **Upload pack** → select
  `Guardian.zip` from the release bundle. Every integration and script in it is a unified YAML, so
  nothing needs building. The upload installs everything **except the Jobs** — XSOAR 6 does not
  create Jobs from a pack upload — so create these six by hand on the Jobs page (time-triggered,
  recurring; the settings for each are in the pack's `Jobs/job-*.json`, including `closePrevRun: true`):

  | Job | Incident type | Playbook | Every |
  |---|---|---|---|
  | `GuardianIntakeSweep` | Guardian Agent Run | `GuardianAgentLoop` | 6 hours |
  | `GuardianHousekeeping` | Unclassified | `GuardianHousekeeping` | 1 hour |
  | `GuardianCaseCapture` | Unclassified | `GuardianCaseCapture` | 4 hours |
  | `GuardianEvalScore` | Unclassified | `GuardianEvalScore` | 1 hour |
  | `GuardianEvalHarvest` | Unclassified | `GuardianEvalHarvest` | 24 hours |
  | `GuardianModelAdaptation` | Unclassified | `GuardianModelAdaptation` | 24 hours |

- **Match Guardian to your model.** The size follows the model; the daily job measures the rest.
  - **Size (from the catalogue).** Every run looks the enabled model up in the model catalogue and uses its size class:
    `small` under 13B parameters, `medium` 13B to 40B, `large` over 40B (a closed hosted model of unpublished size counts as large). Nothing is declared
    and nothing is stored: the lookup is made on every run. `model_tier` in `guardian_settings` ships as `auto`. Set it to
    `small`, `medium` or `large` only for a model that is **not** in the catalogue; `guardian_settings` is locked after
    install, so on a manual install edit `Lists/list-guardian_settings.json` inside `Guardian.zip` before uploading (its
    `data` field is a JSON string, so keep the escaping intact) and re-upload the pack. To force a size for any model, set
    `model_tier` under `overrides` in `guardian_model_profile` (no redeploy).
  - **Turn limit.** The number of turns a run may take follows the same size: 25 small, 40 medium, 60 large. `MAX_TICKS` is not shipped in `guardian_settings`; set it there only for one limit for every model, or set `max_ticks` under `overrides` in `guardian_model_profile` to change it without a redeploy. A run that reaches the limit is asked for one last no-tools summary and ends.
  - **Everything measurable is measured for you.** Enable the provider integration, then run the
    **`GuardianModelAdaptation`** job once by hand (XSOAR 6 has no "run now": create an *Unclassified* incident
    with the `GuardianModelAdaptation` playbook, as in §2) and leave the job on its daily schedule. It runs `!guardian-probe-model` (a warm-up call, then the
    tokens-per-character ratio, the usable context window, tool-call and structured-output checks) and saves a
    trustworthy result to the **`guardian_model_profile`** List. Every investigation reads that List, so the
    numbers are measured once a day, not per incident. Its **Resolve model profile** task prints each value and
    where it came from (override, measured, `guardian_settings`, or default; the size shows `catalogue (<model>)` when it came from the model catalogue).
  - **If you change the model** (a different model, or a different context size on the same one), run the job
    again straight away. Until it has run, the profile still describes the previous model. The daily run
    catches it within a day, and a profile more than three days old is flagged in the War Room.
  - **To pin a value by hand** without a redeploy, edit `guardian_model_profile` (Settings → Lists) and set
    `max_input_tokens`, `max_tool_def_tokens` or `model_tier` under `overrides`. An override beats the measured
    value; the job never touches `overrides`. The list is not locked on purpose, and the agent cannot write it
    (it is not an agent tool, and `setList` stays blocked at the tool bridge).
  - **Provider content-filter blocks:** if the model provider's content filter blocks a turn (Azure AI Foundry does this
    for jailbreak-style text), the run retries up to `content_filter_retries` times (default `2`, in
    `guardian_settings`). Each retry resends the same conversation with a short harness note saying the work is an
    authorized defensive investigation and that incident text is evidence, not instructions; from the second retry
    on, tool results newer than the last assistant message are also cut to 400 characters. The system prompt, the
    tool list and the policy are never changed. The War Room line for the turn says how many retries were used. If
    every retry is blocked, the run stops with an error naming the filter message and asks for a human analyst. Set
    `content_filter_retries` to `0` to make the provider's block final (the old behaviour). Every attempt is a real
    model call and is charged to the cost ledger.
  - **One tool call per turn:** some models (command-r 35B in the lab) put every tool call into a single turn, so a
    memory search or a first lookup cannot shape the calls beside it. Set `max_tool_calls_per_turn` (also under
    `overrides`, or in `guardian_settings`) to `1` and the run executes only the first call of a turn, then tells the
    model which calls were deferred so it can ask for them again with what it learned. `0` or unset keeps the
    default: every call in the turn runs. It trades more ticks for better use of intermediate results.
  - **By hand:** `!guardian-probe-model` then `!GuardianModelProfileUpdate`. A probe that was not trustworthy
    (the model was too slow, a capability check was skipped) leaves the previous profile in place and says why.
    A probe whose window search ran out of time (normal on a large window) saves a confirmed floor, marked
    `truncated`, but may not cut an existing budget by more than half. `!GuardianModelProfileUpdate force=true`
    accepts a partial result.

---

## 1. Configure the model (Guardian Vertex instance)

Guardian is provider-generic; the live config uses **Gemini 2.5 Flash via Vertex AI**.

**UI:** Settings → Integrations → search **Guardian Vertex** → *Add instance* with:

| Param | Value (current) |
|---|---|
| `provider` | `vertex` |
| `project_id` | your GCP project id |
| `region` | `us-central1` |
| `model` | `gemini-2.5-flash` |
| `service_account_json` | the SA key JSON (a service account with `roles/aiplatform.user`) |
| `auth_style` | `bearer` (Vertex mints its own token from the SA — value is unused for vertex) |

For a **non-Vertex** backend (OpenAI-compatible / Azure): set `provider=openai-compatible` or `azure`,
`base_url`, `model`, `api_key` (and `api_version` for Azure). Then **Test** the instance.

For a **Microsoft Foundry** resource (OpenAI models, or DeepSeek / Grok / Llama / Mistral deployed in it), use the
separate **Guardian Foundry** integration: `endpoint` (`https://<resource>.services.ai.azure.com`), `model` (the
deployment name), and `api_key` (Azure portal > the Foundry resource > Keys and Endpoint) or an Entra ID service
principal. Leave `model_family` on `auto`; use `omit_params` if a deployment answers HTTP 400 for a parameter such as
`response_format`. After pointing it at a different model, run `!guardian-probe-model` and set the model size in
`guardian_settings`.

*Switching models:* the instance's `model` is authoritative. `!guardian-model` in a War Room shows the
current model.

*Switching providers:* each model provider ships as its **own** Guardian integration (`Guardian Vertex`
today; `Guardian Claude`, `Guardian Cohere`, … later). They all implement the same `guardian-llm-chat`
command, so the rest of the pack is provider-agnostic. **Enable exactly one** provider integration at a
time (disable the others); XSOAR routes `guardian-llm-chat` to the enabled one and `!guardian-model`
reports which is live. See [docs/GUARDIAN_LLM_CHAT_CONTRACT.md](GUARDIAN_LLM_CHAT_CONTRACT.md).

---

## 2. Run the autonomous intake

The **`GuardianIntakeSweep`** Job (scheduled every 6h) creates a *Guardian Agent Run* incident and runs
an SLA-first triage sweep read-only.

- **Verify it's scheduled:** Jobs page → `GuardianIntakeSweep` (or `POST /jobs/search {"query":"name:\"GuardianIntakeSweep\""}`).
- **Run any job now, without waiting for its schedule (v6 has no "run now"):** create an incident of
  the job's type with the job's playbook — that *is* one job run, and it is also how to test a job
  without creating it. New Incident → set the **Type** and **Playbook** from the table in §0. Created
  with its playbook set, the incident starts straight away; the five maintenance playbooks close their
  own incident when they finish. *Guardian Agent Run* already defaults to `GuardianAgentLoop` — if a new
  Agent Run incident sits in **Pending**, click **Investigate** to start it. For a custom investigation
  instead of the default triage sweep, set the playbook's `prompt` input.
- **Rerunning or switching playbooks on an incident.** Create a test incident with its type's own
  playbook (type *Guardian Eval Case* uses `GuardianEvalInvestigate`; *Guardian Agent Run* uses
  `GuardianAgentLoop`). Changing the playbook after a first run has ended leaves the old loop state in
  place and the new run stops at once with "loop already … ignoring stray re-entry". Clear it with
  `!DeleteContext key=Guardian` in that incident's War Room and restart the playbook, or just start a
  new incident. It is not cleared automatically because the same state protects a run that is waiting
  for an approval.
- **What the playbook shows.** Each run lists its steps as tasks: kill-switch, job guard and model-tier
  checks, then building the system prompt and tool list, optionally loading a skill, and finally one task, *Run Guardian model session*, that holds the whole
  conversation with the model. Skill loading is off by default. Set the playbook input `preload_skill` to
  `true` to add the skill named by `skill` to the system prompt (only if it fits within 15% of
  `max_input_tokens`; otherwise the first War Room entry says so and the model can load it itself with
  `GuardianSkillRead`). Measure it for your model and task first: on a 35B model no effect of the triage skill
  could be told apart from run-to-run variation, and it costs a few thousand tokens a run.
- **Watch it work:** open the incident → the **Guardian Agent Run layout** shows the reasoning trace,
  tool-call ledger, recommended actions, cost, tick count, and verdict. The **War Room** carries the
  agent's narration per tick. When the run ends, a last task builds the report page the Guardian tab shows (see
  *The report step* below).
- **Talk to it mid-run:** in the incident War Room, `!guardian-chat message="focus on the 10.x lateral
  movement first"` — the agent picks it up on its next tick and can change course. If the agent asks you
  a question it pauses until you reply via `!guardian-chat`.

> **Guardian Agent Run incidents never start on their own.** The incident type does not auto-run its
> playbook, so alerts a fetch integration maps to *Guardian Agent Run* sit in Pending and never run the
> agent. That is the safe default — one agent loop per fetched alert would overwhelm both the tenant and
> the model. Map fetched alerts to their normal incident types and let `GuardianIntakeSweep` triage them.

**War Room operator commands:** `!guardian-help` (list them), `!guardian-cost` (spend), `!guardian-tools`
(the tool catalogue), `!guardian-plan` (a plan-only preview), `!guardian-compact` (compact the
transcript), `!guardian-model` (current model).

### Triage and investigation of one incident (`GuardianTriageAndInvestigateIncident`)

Attach **`GuardianTriageAndInvestigateIncident`** to an incident (as its type's playbook, or with `!setPlaybook
name="GuardianTriageAndInvestigateIncident"` in its War Room) to triage that one incident by fixed rules and then
investigate it:

1. **Route** (`GuardianIncidentRoute`): the List `guardian_incident_routes` maps the incident's type, category, source,
   name and labels to a family, a domain (`detection` or `posture`) and an evidence plan. Guardian's own run and eval
   incidents, simulations and jobs get a note and no model session. Add a row for your own incident types there.
   **Duplicate check** (`GuardianIncidentDuplicateCheck`, no model, on by default; playbook input `check_duplicates`): an
   incident that repeats a lower-numbered open incident with the same type, name and source on the same host, user, addresses,
   file hash, URL or email sender gets a note that names the original and proposes a pre-process rule or fetch filter, and
   the model is skipped. Set `close_duplicates` to `true` to also link it to the original and close it as a duplicate (default
   `false`; closing ends the investigation, so the note may not appear and the check's own War Room entry is the record). When it cannot decide, the model runs. It complements XSOAR's native deduplication.
2. **Evidence** (`GuardianIncidentEvidence`): the linked indicators with their reputation, other open incidents with the
   same name, how earlier ones were closed, and Guardian memory, pinned at the start of the model session. Read-only.
3. **Triage session**: a short session (`triage_max_ticks`, default 6) on the `xsoar_triage` skill that ends with a
   fixed block: severity, type, confidence, likely benign, escalate, key entities, and optionally an analysis, up to five
   recommendations and a complexity rating (low, medium or high). The model is chosen first (`Choose the triage model`,
   see model routing below).
4. **Validate** (`GuardianTriageResult`): an invalid block gets one repair call, then a fallback to `other`; a type that
   does not fit the incident's domain also goes to `other`. The result is `Guardian.Triage`.
5. **Apply** (`GuardianTriageApply`): sets the incident's **severity** and **phase** (`Guardian triage: <type>`) through
   `setIncident`, and nothing else. It raises severity only on a structured result, lowers it only at confidence 80+
   without escalation, and skips an incident that has an owner, is closed, or was already triaged (its phase starts with
   `Guardian triage:`; clear the phase to allow a new write). Set the playbook input `apply_changes` to `false` for a
   dry run that only writes the note.
6. **Triage summary** (`GuardianIncidentSummary stage=triage`): a short "Guardian triage" War Room note and the
   `Triage:` line of one Guardian section at the end of the incident's details (below).
7. **Investigation model**: `Choose the investigation model`, `Resolve the investigation model profile`, `Gather evidence
   for the investigation model` (the packet again, sized for that model) and the system prompt and tool list rebuilt for it.
8. **Branch** to one typed sub-playbook (`GuardianTriagePhishing`, `IdentityThreat`, `EndpointThreat`, `NetworkThreat`,
   `DataExposure`, `Vulnerability`) or `GuardianTriageOther`. Each typed one runs read-only lookups
   (`ip`/`domain`/`url`/`file` reputation, `endpoint`, `cve`, `GetUserData`, `GetEndpointData`, all run through
   `GuardianLookup` so that an integration or content script that is not installed ends in a note and never stops the
   playbook, plus a narrow `SearchIncidentsV2`), each skipped when its input is empty and continuing on error, adds them to the evidence packet,
   and runs a full investigation (`Run the investigation session`: the same judging, memory and calibration rules in every
   branch) that writes a case note and a verdict, and stores a memory row (`GuardianRunCapture`). `Other` has no lookups
   and runs the same investigation on the skill the incident route chose.
9. **Investigation conclusion** (`GuardianIncidentSummary stage=investigation`): a short "Guardian investigation" note
   (the model it ran on, verdict, confidence, techniques, summary) and the `Investigation:` line of the Guardian section.
10. **Report** (`GuardianReportBuild`): the structured report the Guardian tab draws (next paragraph).

**The report step.** The last task of both `GuardianAgentLoop` and this playbook, `Build the Guardian report`, runs
`GuardianReportBuild` after the investigation and leaves the investigation as it is. It asks the run's model for a JSON
report in three short calls (headline, entities and relationships; attack chain, timeline and process tree; findings,
recommended actions and gaps) over a numbered list of the run's tool calls and the conclusion, checks every item against
them and saves the result as `Guardian.Report`. Verdict, confidence and severity are not the model's: they are the run's
own, so the tab always agrees with the incident fields. The Guardian tab then shows the report page, as three sections (Guardian Assessment, Guardian Attack Story and Guardian Findings), because the incident page limits how much one section may show; a very large report is shortened from the end of its biggest section, with a note, and `!GuardianLayoutAssessment part=all` in the War Room shows all of it. Every item says
whether it rests on tool results (`✓ 2 refs`) or is **unverified**, an entity found in neither the results nor the
conclusion is dropped, and a suggested command must be one of the run's tools. The step costs up to three model calls,
and at worst six (one repair request for each part whose reply has no usable JSON), charged to the cost ledger under the trigger `report_build`,
with one `report_build` audit row and a short War Room note (calls, seconds, entities, techniques, unverified items,
errors). It never fails the run: when it cannot build a report the tab shows the assessment card as before, and a report
of an earlier run on the same incident is never shown. **To turn it off**, set `report_enabled` to `false` in
`Lists/list-guardian_settings.json` and install the pack again (no model call is then made); `report_max_calls` (default 3)
limits how many of the three parts are asked for. The prompt is the List `guardian_prompt_report`. With the kill switch
on, the step does nothing, and the kill switch is read again before every later call. It is also skipped, with a note, for a
run started by a scheduled Job (the intake sweep covers the whole queue and has no single incident to report on): a
skipped step deletes `Guardian.Report`, so an old report is never shown. A triage dry run (`apply_changes` false) still
builds the report: about three short calls, and only to context (nothing on the incident is changed). When a very small
input budget leaves no room for the prompts, no call is made and `errors` says so.

**The Guardian section of the details.** `GuardianIncidentSummary` keeps one section at the end of the incident's
details, behind the line `--- Guardian (automated) ---`. The original text is never changed; a re-run replaces only the
section, and each stage keeps the other's line. It is written through the Core REST API (read the incident, change only
`details`, write it back), and not written at all when the incident cannot be read. The evidence packet, the incident pin,
every tool result and the eval harvest leave the section out, so the model never reads its own earlier conclusion back.

**Model routing (optional).** The List `guardian_model_routing` (protected, shipped empty: every call uses the provider
instance's configured model) can name the model of the triage session and a model, and an optional `max_ticks`, per
investigation complexity level. The level starts at the triage block's `complexity` (medium without one), is raised to
at least medium by an escalate or a high or critical severity, and by one more level for a confidence under 60. The input
`investigate_max_ticks`, when set, wins over the level's `max_ticks`. A model the provider cannot serve is dropped once,
with a line in the narration, and the run carries on with the configured model; a Cohere North provider cannot route.
Only this playbook routes: `GuardianAgentLoop` (Guardian Agent Run incidents and the intake Job) always runs on the
configured model. If `Choose the investigation model` fails, its result is empty, so the investigation runs on the
configured model with the model size's own turn limit (`investigate_max_ticks` is not applied either), and the triage
repair call of `GuardianTriageResult` always uses the configured model.

`GetUserData` and `GetEndpointData` come from the Aggregated Scripts pack; their tasks are skipped when it is not
installed. The reputation commands need at least one enabled integration that implements them. Containment and every
other change still go through the approval gate.

---

## 3. Approve or deny agent actions

Any state-changing action (close/update incident, send/delete mail, EDR containment, list writes, etc.)
is **gated**: the agent proposes it, the bridge parks it (it does **not** execute), and posts an approval
request to the War Room + the approvals queue.

- **See pending approvals:** the **GuardianObservability dashboard** (Approvals Queue widget), or the
  incident's recommended-actions section, or `GET /lists/download/guardian_approvals_ledger`.
- **Approve:** in the incident War Room,
  ```
  !guardian-approve approval_id=<id>
  ```
  On approval the agent executes that exact action **once** (single-use token, tightly matched) on its
  next tick, and audits it. Denied actions never run:
  ```
  !guardian-deny approval_id=<id> reason="not this host"
  ```
- **Destructive** actions (e.g. `xdr-isolate-endpoint`, `closeInvestigation`) are posted under a red
  *DESTRUCTIVE ACTION* heading and never run on their own, even in `bypass` mode; approve them with the
  normal `!guardian-approve approval_id=<id>`. **Credential-class** actions (anything carrying an API
  key, password or token) also require a typed confirmation:
  `!guardian-approve approval_id=<id> confirm=CONFIRM`.
- **Splunk searches that write** are held the same way. `splunk-search` runs freely for ordinary
  searches, but a query containing a write-capable SPL command (`collect`, `outputlookup`,
  `sendemail`, `sendalert`, `delete`, `map`, `savedsearch`, …) is treated as destructive and waits for
  approval. The audit row's `spl_write_commands` names the command that caused the hold.
- **You cannot approve as the agent** — approvals are operator-only (self-resolve is blocked). Restrict
  `!guardian-approve`/`!guardian-deny` to your approver roles via XSOAR RBAC before production.

If no one responds within the SLA the action is **held and escalated** (never auto-executed); the
housekeeping sweep also reaps stale pending approvals.

---

## 4. Toggle autonomy (pre-approved containment)

By default every incident is in **`manual`** mode — everything gated. To let a **narrow, pre-approved,
low-risk** containment class execute **without** a human on a specific incident:

- Set the incident field **`Guardian Approval Mode`** to **`bypass`** (Edit the incident, or the agent
  proposes it — but flipping to bypass is itself a gated `setIncident`, so a human confirms it).
- In `bypass` mode, only commands in **both** the code-side `GUARDIAN_AUTO_APPROVABLE_COMMANDS` allowlist
  **and** the `guardian_preapproved` policy class auto-execute (today: `xdr-endpoint-tag-add`, tag-value
  constrained). Every autonomous action is audited `auto_approved=true`.
- **High-impact always stays gated** regardless of mode — isolation, quarantine, script-run, close, mail,
  job/settings/persona writes, etc. are never auto-executed. Widening autonomy requires a **code change**
  (editing the config List alone cannot add a command to autonomy).
- To expand the pre-approved set: add the command to `guardian_preapproved` **and** to
  `GUARDIAN_AUTO_APPROVABLE_COMMANDS` in `GuardianToolBridge.py`, and get it code-reviewed. Keep it
  low-risk and reversible.

Per-Job autonomy: set the intake Job's incidents to `manual` (default) until you trust a specific
containment class in production.

---

## 5. Emergency kill-switch

Halts **all** agent activity — running loops stop within one poll cycle, and every tool dispatch is
blocked (including pre-approved/autonomous ones).

```
!guardian-killswitch state=on reason="incident-response freeze"     # HALT
!guardian-killswitch state=off                                       # resume
```

- ON: any running agent exits cleanly on its next tick; the bridge denies every dispatch. In `bypass`
  mode the kill-switch is **fail-closed** (an unreadable switch halts).
- The kill-switch List is operator-writable only (the agent can't touch it).
- A new agent run started while the switch is ON does no work (it halts on its first tick). *(Note: the
  intake pre-process drop only fires for ingested events on 6.14.0 — the tick/bridge halt is the
  load-bearing stop.)*
- Check current state on the **GuardianObservability dashboard** (kill-switch widget) or
  `GET /lists/download/guardian_kill_switch`.

---

## 6. Observability & housekeeping

- **Dashboard:** *GuardianObservability* — cost rollups, tool-call ledger, loop health (running/done/
  stalled), pending-approvals queue, recent denials/failures/kill-switch events. (Share it to your team
  in the UI — one-time.)
- **Audit:** every tool call is an immutable row in `guardian_audit` + a War Room entry (redacted at
  capture). The audit and approvals Lists are protected — the agent cannot rewrite them.
- **Housekeeping** (hourly `GuardianHousekeeping` Job): reaps stale approvals + expired memory, rotates
  audit, and **re-arms or reaps stalled agent runs** (a run stuck with no tick progress).
- **Job safety:** `GuardianJobGuard` auto-disables a Job after repeated failures and won't start a run
  while the kill-switch is on.

---

## 7. Quick reference

| Task | Command / action |
|---|---|
| Deploy content + jobs | `bash scripts/deploy.sh` |
| Configure model | Settings → Integrations → Guardian Vertex instance (or any enabled Guardian provider) |
| Start a run | New Incident → type *Guardian Agent Run* (or wait for the intake Job) |
| Talk to the agent | `!guardian-chat message="…"` in the incident War Room |
| See pending approvals | Dashboard (Approvals Queue) / `guardian_approvals_ledger` |
| Approve / deny | `!guardian-approve approval_id=<id>` / `!guardian-deny approval_id=<id> reason=…` |
| Confirm high-impact | `!guardian-approve approval_id=<id> confirm=CONFIRM` |
| Enable autonomy (an incident) | set *Guardian Approval Mode* = `bypass` (high-impact still gated) |
| **KILL-SWITCH** | `!guardian-killswitch state=on` / `state=off` |
| Cost / tools / help | `!guardian-cost` / `!guardian-tools` / `!guardian-help` |

**Production hardening before go-live:** restrict `!guardian-approve`/`-deny` and the kill-switch to
approver roles (XSOAR RBAC); run the agent's Jobs under a least-privilege service account; confirm the
LLM provider's data-residency posture; and review the `guardian_policy` gate tiers against the box's
actual integration inventory.

**Give Guardian read-only accounts on the tools it queries.** The chokepoint gates commands, and for
`splunk-search` it also holds queries that contain write-capable SPL. But it can't see inside a Splunk
macro or an app's custom commands. Configure the SplunkPy instance with a Splunk role that can search
the indexes Guardian needs and nothing else: no write access to indexes or lookups, no `can_delete`,
no email or alert actions. The same rule applies to any other query-language integration you allowlist.
