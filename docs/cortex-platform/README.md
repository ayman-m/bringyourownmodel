# Guardian for the Cortex platform: install

This guide is for the **Cortex platform** (the edition was developed and tested on Cortex XSIAM 8.15) and the pack `GuardianCortexPlatform-<ver>.zip`. If you run Cortex XSOAR 6, use [`../xsoar/README.md`](../xsoar/README.md): the two editions are different content,
in separate downloads and separate releases, and must not be mixed. The Cortex platform calls incidents *issues*.

Paths below are relative to the unzipped download (`Guardian-Cortex-Platform-v<version>/`).

## What this edition contains

| Content type | Count | Folder inside the pack zip | On Cortex platform |
|---|---|---|---|
| Issue (incident) fields | 15 | `IncidentFields/` | installed |
| Indicator fields | 10 | `IndicatorFields/` | installed, used by the SOC Agent indicator layout |
| Lists | 27 | `Lists/` | installed |
| Integrations (Foundry, Vertex, Cohere), unified YAML | 3 | `Integrations/` | installed |
| Automations, unified YAML | 80 | `Scripts/` | installed |
| Playbooks | **21** | `Playbooks/` | installed, **then adopted** (below) |
| Layouts (1 issue layout, 1 indicator layout) | 2 | `Layouts/` | installed |
| Issue (incident) types | 2 | `IncidentTypes/` | installed |
| Indicator type | 1 | `IndicatorTypes/` | installed |
| Widgets, dashboard | 5, 1 | `Widgets/`, `Dashboards/` | **in the zip, not installed by Cortex platform**: use the `!GuardianWidget...` commands |
| Guardian Performance dashboard (Cortex format) | 1 | `XSIAMDashboards/` | installed with the pack; for a manual install, import the JSON in Dashboards & Reports |
| Jobs | 6 | `Jobs/` | created by the script or by hand; the type is the platform default |

There is **no pre-process rule** in this edition (it does not fire on Cortex platform). Every integration and automation is a single unified YAML file. Differences from the XSOAR 6 edition, in full:
`Packs/GuardianXSIAM/DIVERGENCE.md` in the repository.

## Choose how to install

| | Method | Use it when |
|---|---|---|
| **A** | Install script (in this download) | You can run Python 3 with network access to the tenant |
| **B** | Pack upload in the console | Your console offers a pack upload (see its note) |
| **C** | `demisto-sdk upload -x -z` of the pack, from a clone of the repository | You already use the SDK |
| **D** | Item by item, in order (the separate **Manual Upload** download) | None of A to C is possible. A fallback: see its limits |

A, B and C install everything in the right order for you. All four finish with the same follow-ups: adopt the playbooks, create the Jobs and add a model provider.

## Prerequisites

- A Cortex platform tenant.
- A **Standard**-level API key and its **key ID**. Create one at **Settings > Configurations > Integrations > API Keys > New Key** (Security Level: Standard), then **Generate** and copy
  the key. The ID is in the **ID** column of the API Keys table. **Copy API URL** on the same page gives the base URL. Export them in your shell; never write them into a file you share.
  (The SDK documentation asks for a Standard key held by an Instance Administrator or Account Admin.)
- The **Core REST API** integration, with an instance configured (Core Server URL from **Copy API URL**, an API key ID and key; a Standard key is enough). **Guardian needs it, not just for
  creating issues:** the platform has no Demisto REST API, so Guardian reaches the tenant's own API through this integration's `core-api-post` command. It is how Guardian writes the verdict, cost and
  tick count onto the issue, reads and checks the model provider instances (`!guardian-model`, the probe and the daily adaptation), runs the job guard, housekeeping and case capture, and inserts simulated issues.
  Without a working instance a run can still investigate, but the Run Summary stays empty and `!guardian-model` and the profile update fail. It is not installed by default:
  add the *Core REST API* instance under **Settings > Integrations**. Check it with `!core-api-post uri=/settings/integration/search body={"size":1}`.
- An account on a model provider ([`../MODEL_SETUP.md`](../MODEL_SETUP.md)).
- Check the download: `shasum -a 256 -c SHA256SUMS` in the unzipped folder.

## Method A: install script

```bash
cd Guardian-Cortex-Platform-v<version>
export DEMISTO_BASE_URL="https://<your API URL>"      # as shown by Copy API URL, without a path
export DEMISTO_API_KEY="<standard api key>"
export XSIAM_AUTH_ID="<key id>"
# TLS-inspecting proxy: export SSL_CERT_FILE=/path/to/ca-bundle.pem      self-signed certificate (lab only): export DEMISTO_VERIFY_SSL=false
python3 tools/install_pack.py pack/GuardianCortexPlatform-<ver>.zip
python3 tools/adopt_playbooks.py
```

`install_pack.py` sends the zip to the tenant's pack-upload endpoint (under `/xsoar`) and checks that the pack is listed as installed. Guardian is a custom (unsigned) pack, so the request
carries `skipVerify=true&skipValidation=true`; without them the tenant answers "Pack does not have a valid signature".

## Method B: pack upload in the console

Packs are managed at **Settings > Configurations > Marketplace** (Browse, Installed Content Packs, Cart). The XSIAM administrator guide describes the permission to "install, uninstall,
upload, and upgrade content packs" but does not name the upload button or say how an unsigned pack is treated. If your Marketplace page offers an upload option, choose
`pack/GuardianCortexPlatform-<ver>.zip` there and then adopt the playbooks. If it does not, or it refuses the pack, use method A or C.

## Method C: `demisto-sdk upload -x -z` (from a clone of the repository)

The SDK builds the unified YAML files itself from the repository's split sources, so this method needs a clone, not the download.

```bash
git clone <this repository> && cd <the clone>
python3 -m venv .venv && .venv/bin/pip install demisto-sdk
export DEMISTO_BASE_URL="https://<your API URL>"       # without a path
export DEMISTO_API_KEY="<standard api key>"
export XSIAM_AUTH_ID="<key id>"
.venv/bin/demisto-sdk upload -i Packs/GuardianXSIAM -x -z --skip_validation --override-existing
python3 scripts/adopt_playbooks.py                      # defaults to Packs/GuardianXSIAM/Playbooks
GUARDIAN_PACK=GuardianXSIAM GUARDIAN_SKIP_JOBS=GuardianIntakeSweep python3 scripts/deploy_jobs.py
```

`-x` targets Cortex platform and **must be used together with `-z`** (it uploads the pack as a pack, to the Marketplace); `--override-existing` replaces an installed copy.
The SDK reads a `.env` file at the repository root: if your clone has one that points at another server, it wins over the variables above, so run from a copy without it.

## Adopt the playbooks (after method A, B or C)

Cortex platform treats the playbooks of an installed pack as system objects: public and read-only. A playbook that has not been adopted cannot be attached to an issue or run by a Job (the
platform answers "playbook is not adopted"). Run `python3 tools/adopt_playbooks.py` with the environment from method A: it detaches and re-saves each of the pack's playbooks and prints
`adopted=True` for each. (Detaching a system playbook turns it into a custom object that you own.) It is safe to run any number of times.

## Method D: item by item, in order

Use this only if no pack install is possible. It is a **separate download**, `Guardian-Cortex-Platform-Manual-Upload-v<version>.zip` (from the same Releases page), because the console's one-file-at-a-time upload does not read
the pack's files the way a pack install does. In particular a pack's list file, uploaded on its own, creates a list named `list-guardian_policy` that holds the whole file as its data, and Guardian cannot read it.
The manual package carries every item in the form the console expects (lists as plain data files named exactly as the list must be named), the order to import them in, where to click for each type, the API call for the types
that have no import button, and a check to run after each list. Do not mix it with the files inside the pack zip.

## Create the Jobs (all methods)

The platform does not create Jobs from a pack install. With the environment from method A:

```bash
# leave the triage sweep off unless you want a model to triage the real issue queue
GUARDIAN_JOBS_DIR=tools/jobs GUARDIAN_SKIP_JOBS=GuardianIntakeSweep python3 tools/create_jobs.py
```

It is safe to run again: it updates a Job it already created and never duplicates one. The settings are in `tools/jobs/job-*.json`:

| Job | Playbook | Every |
|---|---|---|
| `GuardianIntakeSweep` | `GuardianAgentLoop` | 6 hours. Triages the real issue queue with a model. **Leave it off** on a tenant you do not want triaged |
| `GuardianHousekeeping` | `GuardianHousekeeping` | 1 hour |
| `GuardianCaseCapture` | `GuardianCaseCapture` | 4 hours |
| `GuardianEvalScore` | `GuardianEvalScore` | 1 hour |
| `GuardianEvalHarvest` | `GuardianEvalHarvest` | 24 hours |
| `GuardianModelAdaptation` | `GuardianModelAdaptation` | 24 hours |

A Job run on Cortex platform is a job investigation with no issue attached, so verdict fields cannot be written back on a Job run; they are written when you run the agent on an issue.

On a tenant that cannot store custom issue fields (for example Cortex Cloud), set `incident_fields_enabled` to `false` in `guardian_settings` and redeploy the pack. Guardian then writes no issue field: the verdict is in the conclusion, the case note and `guardian_audit`, and the cost is in `guardian_cost_ledger`. Bypass mode, case capture, the evaluation Jobs and the Guardian Performance dashboard need those fields and are unavailable. If you leave the setting on and the tenant rejects the write, the run turns issue-field writes off after the first failure, says so once in its output, and carries on.

## Which issues to run Guardian on

A production tenant raises thousands of issues an hour, and most are posture findings (misconfigurations, vulnerable packages, identity and attack-path findings), not threat detections. Running a model on all of them is neither useful nor affordable, so choose the scope with an automation rule that attaches `GuardianInvestigateIssue`:

| Mode | Filter (automation rule) | What you get |
|---|---|---|
| **Threat detections** | issue domain is Security | One investigation per detection, with the identity's surrounding activity from the cloud audit log |
| **Narrow posture rule** | domain is Posture and, for example, severity is Critical, or the issue is internet-exposed, or it is an identity finding on an administrator | One assessment per finding: still present or not, exposure, owner, fix and a P1-P4 priority |
| **Rule digest** | the same narrow filter, with the playbook input `mode` set to `digest` | One report per rule per day: the open issues of the rule grouped by asset and ranked. The first issue of a rule writes the report; the others get a one-line note and no model run |

Severity alone is not a filter: on a typical tenant about 95% of issues are High. A data-collection health issue (a silent data source, a modeling yield collapse, misrouted events) gets a model session with the `cortex_data_health` skill; any other health issue (platform telemetry) gets a short note and no model session.

How the run is shaped: the **Route issue** task reads the issue's own domain, category and scanner and picks a skill (threat detection, misconfiguration, Kubernetes policy, identity, vulnerable package, attack path), using the `guardian_issue_routes` list; **Gather evidence** fetches, at no compute-unit cost, the issue's status, the platform's remediation text, the asset, the case, how analysts closed earlier issues of the same rule and Guardian's memory, and the model starts with that in front of it; **Remember the outcome** stores the result in memory after the run, with no Job. `!guardian-tools` lists the commands installed on your tenant that Guardian is not allowed to use.

Telemetry queries: the model may run any XQL it judges useful, through `GuardianXQL query=` or `xdr-xql-generic-query`, and `GuardianXQL` also offers ready-made queries from the `guardian_xql_templates` list (among them four for data-collection health: `source_ingestion_health`, `reporter_sources`, `dataset_raw_volume` and `datamodel_volume`). The skill `cortex_xql` (list `guardian_skill_cortex_xql`) teaches the model to try a template first, to pass a `DOMAIN\user` account with one backslash, to use only datasets and fields known to exist, and to keep a query cheap (filter first, aggregate, never read issue data through the `issues` dataset); it is indexed in `guardian_skills_index` and the prompt tail points the model to it before a raw query. `GuardianXQL` waits for the rows; a query still running after about a minute returns its `execution_id`, and fetching it again with `execution_id=` (or `xdr-xql-get-query-results`) costs nothing. Every query's cost in compute units is recorded and shown at the end of the run. The daily XQL quota is shared with your own rules and dashboards; to protect it, set `xql_max_queries_per_run` or `xql_daily_share_pct` in `guardian_settings` (both off by default).

## Triage and investigation: rate an issue, then investigate it by type

`GuardianTriageAndInvestigateIssue` is a second playbook beside `GuardianInvestigateIssue` (which is unchanged). Where the investigation playbook runs one open-ended model session per issue, this one first asks a short model session for a fixed answer, lets fixed rules act on it, and then runs a full investigation through the sub-playbook for the issue's type.

1. **Prepare**, as for an investigation: kill switch, Job guard, issue routing (a health issue that is not about data collection gets a note and stops), the duplicate check (below), model profile, evidence packet, system prompt and tool list.
2. **Triage session** (`GuardianReasoningTick` with `assessment_mode=triage`, the `cortex_triage` skill, at most `triage_max_ticks` turns, default 6). The model reads the evidence packet, makes a few lookups at most, and ends with a block of fixed fields: severity, investigation type, confidence, `likely_benign`, `escalate`, summary, key entities and next step, and optionally an `analysis` (2 to 4 sentences, at most 800 characters), up to 5 `recommendations` (each at most 200 characters) and a `complexity` (`low`, `medium` or `high`: how much investigation the issue needs). It writes no case note, no memory row and no verdict field.
3. **Validate** (`GuardianTriageResult`). Every value is checked against the `guardian_triage_types` list. A missing or invalid block gets one repair request over the conclusion text (JSON mode; sent once more without JSON mode only when the provider rejects JSON mode, so at most two model calls); if that fails too, the result is a fallback. A type that does not fit the issue's domain (for example a posture finding called an identity threat) goes to `other`. The decision (with the `analysis` and `recommendations`, empty when the block has none) is written to `Guardian.Triage`, and the branch comes from `Guardian.Triage.branch`, never from the model's words.
4. **Apply** (`GuardianTriageApply`, after a second kill switch check). The only step that changes the issue's `severity` and `phase`: it sets them (the phase is `Guardian triage: <type>`), and never touches the type, the description or the status. A structured result may raise severity; lowering needs a structured result of confidence 80 or more that does not say `escalate`; a repaired or fallback result never changes severity. It skips an issue that has an owner, is resolved or was already triaged (in this context, or because the issue's own `phase` already starts with `Guardian triage:`). Guardian cannot clear a phase on Cortex Cloud (`core-update-issue` ignores an empty value), so an issue that has been triaged is never written to again; running the playbook on it again still runs the model and adds a case note. The model cannot call it. The investigation session of a sub-playbook is a separate step: it proposes actions but takes none, and it writes the verdict fields, a case note and a memory row, as an investigation does. Set the playbook input `apply_changes` to `false` for a dry run that writes only a case note.
5. **Write the triage summary** (`GuardianIssueSummary stage=triage`). A short "Guardian triage" War Room note (type, severity before and after, confidence, escalate, summary, analysis, recommendations), and the same text as the `Triage:` line of one **Guardian section** at the end of the issue's description (below). It skips an issue the apply step skipped. With `apply_changes` set to `false` it writes nothing.
6. **Branch** to one sub-playbook per type: `GuardianTriageIdentityThreat`, `CloudChange`, `EndpointThreat`, `DataExposure`, `Misconfiguration`, `Vulnerability`, `CodeRisk`, `ExcessivePrivilege`, `AttackPath` and `Other`. Each of the nine typed ones runs read-only lookups first (every one is skipped quietly when its input is empty and continues on error), adds the results to the evidence packet (`GuardianIssueEvidence mode=append`), and then runs a full investigation (`Run the investigation session`: the same turn limit, tools, judgment and calibration rules as `GuardianInvestigateIssue`, see `investigate_max_ticks` below) on the skill for that type, ending with the usual verdict or posture block. `Other` has no type-specific lookups, but it runs the same investigation on the skill the issue route chose.
7. **Write the investigation conclusion** (`GuardianIssueSummary stage=investigation`). A short "Guardian investigation" note (the model it ran on, verdict or assessment, confidence or priority, techniques, summary, and exposure, owner and fix for a posture finding) and the `Investigation:` line of the Guardian section. The model's own case note stays the full report. It skips a run that ended without a verdict.

The inputs the lookups use come from the issue's own fields first (user name, host IP, referenced resource, asset ids, rule id), and the model's key entities only fill the gaps; each is shape-checked (IPs must parse, hashes must be hex).

| Playbook input (`GuardianTriageAndInvestigateIssue`) | Default | Meaning |
|---|---|---|
| `apply_changes` | `true` | `false` is a dry run: the apply task writes only its case note and the two summary tasks write nothing |
| `triage_max_ticks` | `6` | turns for the triage session |
| `investigate_max_ticks` | empty | optional cap on the turns of the sub-playbook's investigation session (it overrides the routing's `max_ticks` for the level); empty gives it the same limit `GuardianInvestigateIssue` gets (25, 40 or 60 by model size, or the `guardian_settings` and model profile override). A number can only lower that limit |
| `prompt` | the triage prompt | what the triage session is told |
| `check_duplicates` | `true` | run the duplicate check (below) before the triage model; `false` triages every issue |
| `close_duplicates` | `false` | `true` also closes a duplicate as `Resolved - Duplicate Issue` (only that issue, never the original) |

**The Guardian section of the description.** `GuardianIssueSummary` appends one section to the end of the issue's description, behind the line `--- Guardian (automated) ---`, with a `Triage:` line and an `Investigation:` line (one line of plain text each, scrubbed of secrets, at most 700 characters; the section is at most 1500). The original text is never changed: the new description is the original, a blank line and the section. A re-run replaces only the section, and each stage keeps the other's line. The evidence packet, the issue pin and every tool result (`GuardianToolBridge`) leave the section out, so the model never reads Guardian's own earlier conclusion back as evidence. The current description is read from the platform first; if it cannot be read, the description is not written (the notes still are).

**Model routing (optional).** The triage session and the investigation can run on different models, to save tokens. The choice is data, in the List `guardian_model_routing`, and it ships empty: every call then uses the provider instance's configured model, exactly as before.

- `triage` is the model of the short triage session.
- `complexity.low`, `.medium` and `.high` are the models of the investigation. The level starts at the triage block's `complexity` rating (medium without one), is raised to at least medium when triage says `escalate` or rates the severity high or critical, and by one more level when its confidence is under 60.
- A level may also carry `max_ticks` to lower that investigation's turn limit (add `"max_ticks": 15` to the entry). The playbook input `investigate_max_ticks`, when set, wins over it.
- Names are the provider's own: a Foundry deployment name, a Gemini model id. A Cohere North instance runs a fixed agent and cannot route, so the choice is ignored there. A model that is not in `guardian_model_catalog` is kept, with a warning that its limits are guessed. A model the provider does not know (`MODEL_NOT_AVAILABLE:`) is dropped at run time with a line in the run's narration, and the rest of the run uses the instance's model.
- The playbook does this with `Choose the triage model` before `Resolve model profile`, and `Choose the investigation model`, `Resolve the investigation model profile`, `Gather evidence for the investigation model`, `Build the investigation system prompt` and `Build the investigation tool list` after the triage summary. The routed model is passed to the provider as the `model` argument of `guardian-llm-chat`, and cost is priced by the model that answered (add each routed model to `guardian_pricing`, or its cost is recorded as $0 with a warning). The evidence packet is gathered with the triage model's limits for the triage session, and again with the investigation model's limits before the branch (same arguments; it replaces the first packet, and the sub-playbook's lookups are appended to the new one), so a smaller investigation model never pins a packet larger than its budget.
- Each choice task empties `Guardian.ModelChoiceCurrent` first, so a choice task that fails leaves no model (the instance's configured model) rather than an earlier run's or the triage stage's choice.
- Known limits, by design for now: if `Choose the investigation model` fails, the operator's `investigate_max_ticks` is not applied either (the sub-playbooks read the turn limit from the choice), so the investigation gets the model size's own limit. The one repair call `GuardianTriageResult` makes for a triage answer it cannot read uses the provider instance's configured model, not the routed triage model.

Upload the ten sub-playbooks before the parent. To widen what triage may write, change `GuardianTriageApply`: it is on the denylist and is not on the allowlist, so the model can never reach it. `GuardianIssueSummary` is on the denylist too.

**Duplicate check.** A noisy rule raises the same issue again and again, and a model session on each costs tokens and tells the analyst nothing new. Before the triage model runs, `GuardianIssueDuplicateCheck` (no model, one search) asks whether this issue repeats a lower-numbered **open** issue of the same rule on the same thing: the same asset ids or, for a rule without assets (a data-collection health rule), the same vendor, product, host, user, address, file hash and domain values. A duplicate gets a note that names the original, says how many issues are open in the group, gives a **proposed exclusion** (rule, scope, review after 7 days; a proposal, nothing is applied) and says no model ran, and the playbook ends. The lowest-numbered issue of a group is never a duplicate, so two issues running at the same moment never mark each other. Any failure means "not a duplicate" and the model runs as before. With `close_duplicates` set to `true` the duplicate is also closed as `Resolved - Duplicate Issue`; the original and every other issue are never changed. The automation is on the denylist: the model can never call it. The answer is left at `Guardian.Duplicate`.

**Data-collection health.** An issue of domain `DOMAIN_HEALTH` whose name mentions a silent data source, a yield collapse, misrouted events, a source that stopped sending, no events, ingestion, parsing or modeling is routed (`guardian_issue_routes`, row `data-health`) to the `cortex_data_health` skill in `posture` mode, through the `Other` sub-playbook. The mode is `posture` so that the run ends with the Confirmed / Not reproducible / Accepted risk candidate block with a priority, never with a threat verdict. The skill checks whether the source is still silent (`source_ingestion_health`), whether every source behind the same sender stopped together or only this one (`reporter_sources`), and for a yield issue the raw and modeled counts per hour (`dataset_raw_volume`, `datamodel_volume`); it concludes with the cause class, since when, the blast radius, the owner (data onboarding) and the fix, and proposes whether repeats should be suppressed. Every other health issue keeps the no-model route.

## Add a model provider

Follow [`../MODEL_SETUP.md`](../MODEL_SETUP.md): Microsoft Foundry (a resource key **or** Microsoft Entra ID), Google Vertex, or Cohere North. A cloud tenant cannot reach a model on a private
network: run the instance on an engine that can. Then run `!guardian-model` to confirm it.

## First run

1. Open any issue's War Room and run `!GuardianBootstrap` once. It creates the runtime lists.
2. Run `!guardian-probe-model`, then the `GuardianModelAdaptation` job once.
3. Investigate an issue: in its War Room run `!DeleteContext key=Guardian`, then `!setPlaybook name=GuardianInvestigateIssue`. A run of four to six ticks takes a few minutes.
   To triage it instead (rate it, name its type, set its severity), run `!setPlaybook name=GuardianTriageAndInvestigateIssue` (see [Triage and investigation](#triage-and-investigation-rate-an-issue-then-investigate-it-by-type)).
4. To see the **Guardian** tab (verdict, reasoning trace, tool ledger, recommended actions), map your issue type to the `GuardianAgentRunLayout` layout. Without it, the same content is
   available as text: `!GuardianLayoutTrace`, `!GuardianLayoutToolLedger`, `!GuardianLayoutRecommendedActions`.
5. Approve or deny a proposed action with `!guardian-approve approval_id=<id>` and `!guardian-deny approval_id=<id> reason="..."`. The kill switch is `!guardian-killswitch state=on`.
6. The **Guardian Performance** dashboard (Dashboards & Reports) charts verdicts, confidence, cost, ticks, models, tool use, failures and approvals from the issue fields. The older dashboard data is also available as commands: `!GuardianWidgetCost`, `!GuardianWidgetToolLedger`, `!GuardianWidgetLoopHealth`, `!GuardianWidgetApprovalsQueue`.
7. To try it on a synthetic case: `!GuardianSimulateIncidents scenario=malware_beacon count=1`, then run step 3 on the new issue.

More: [`../CORTEX_PLATFORM_RUNBOOK.md`](../CORTEX_PLATFORM_RUNBOOK.md) (operation), [`../GUARDIAN_GUIDE.md`](../GUARDIAN_GUIDE.md) (capabilities, who uses it, testing) and
[`TEST_PLAN.xlsx`](TEST_PLAN.xlsx) (a manual test plan and results checklist for a new tenant, including one where Jobs and layouts are not available; open it in Google Sheets or Excel and make one copy per tenant).

## Upgrading

Install the new pack (method A, B or C, or repeat D), run `tools/adopt_playbooks.py` and `tools/create_jobs.py` again. Runtime lists (memory, audit, model profile) are kept.

## If something goes wrong

| Symptom | Fix |
|---|---|
| "Pack does not have a valid signature" | Install with `tools/install_pack.py` (or `demisto-sdk upload -x -z`) |
| "playbook is not adopted" | Run `tools/adopt_playbooks.py` |
| `CERTIFICATE_VERIFY_FAILED` from a script | Your network inspects TLS: `export SSL_CERT_FILE=/path/to/ca-bundle.pem` (`DEMISTO_VERIFY_SSL=false` only for a lab) |
| Foundry **Test** says HTTP 429 | Raise the deployment's tokens-per-minute quota |
| Foundry **Test** says 401 or 403 | Wrong key, or the Entra principal lacks the role on the resource |
| Creating a simulated or follow-up issue fails | Install the Cortex REST API pack and add an enabled instance |
| A new run stops at once ("loop already ... ignoring stray re-entry") | `!DeleteContext key=Guardian` in that issue's War Room, then start again |
| No **Guardian** tab on an issue | Map the issue type to `GuardianAgentRunLayout`, or use the `!GuardianLayout...` commands |

## Sources

Checked against the Cortex XSIAM administrator guide and the demisto-sdk documentation on `cortex-docs.paloaltonetworks.com`: Marketplace (manage content packs), Marketplace permissions,
API Keys (create a new key, get the key ID, get the API URL), issue fields and layouts (create custom issue fields / layouts, with layout **Import**), Lists, Jobs (create a time-triggered
job), playbook and script access (system objects are read-only; detach), and the SDK's `upload` (`-x` with `-z`) and environment-variable pages. Menu names can differ between versions.
