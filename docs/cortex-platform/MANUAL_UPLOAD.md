# Guardian for the Cortex platform: manual upload, file by file

Use this package only when you cannot install the pack (the **Guardian-...-v<version>.zip** download does that in one step, with the install script, the console pack upload or `demisto-sdk`).
Here every file is imported **one at a time**, in order. The files are prepared for that: they are not the same as the files inside the pack.

**Why a separate package.** A pack install reads each item in the pack's own format. The console's one-by-one upload does not: it takes the **file name** as the item's name and the **file text** as its content.
That is harmless for scripts, integrations and playbooks (the name is inside the file) but wrong for Lists, where a pack's list file is a wrapper around the data. A list uploaded from a pack file ends up named
`list-guardian_policy` and holds the whole wrapper, so Guardian cannot read it. In this package the `Lists/` files hold **only the data** and are named exactly as the list must be named.

**Limits.**
- Items imported one by one are ordinary content, not an installed pack. The lists that hold the security policy are **editable** by operators; with a pack install they are locked. The agent itself is still blocked from writing them, because `GuardianToolBridge` and its denylist refuse those writes either way.
- You repeat the import for every upgrade.
- The console documents an import button for few content types (marked below). For the rest, use the API call, or the pack install.

## Lists: do this exactly

Settings > Configurations > Object Setup > **Lists** > **Add a List**. For each file in `Lists/`:
1. **Name** = the file name without its extension (for example `guardian_policy`). Never `list-guardian_policy`.
2. **Type** = the type in the table below.
3. **Content** = the whole file, as is.

| List name | Type | File | What it is |
|---|---|---|---|
| `guardian_policy` | JSON | `Lists/guardian_policy.json` | Which commands need a human's approval |
| `guardian_tool_allowlist` | JSON | `Lists/guardian_tool_allowlist.json` | The only tools the agent may use or be offered |
| `guardian_tool_denylist` | JSON | `Lists/guardian_tool_denylist.json` | Commands and lists the agent can never touch |
| `guardian_preapproved` | JSON | `Lists/guardian_preapproved.json` | The narrow set of actions allowed to run without a person |
| `guardian_settings` | JSON | `Lists/guardian_settings.json` | Limits and tuning for every run |
| `guardian_persona` | JSON | `Lists/guardian_persona.json` | Who the agent is and how it behaves |
| `guardian_prompt_head` | JSON | `Lists/guardian_prompt_head.json` | The start of the system prompt |
| `guardian_prompt_tail` | JSON | `Lists/guardian_prompt_tail.json` | The end of the system prompt |
| `guardian_pricing` | JSON | `Lists/guardian_pricing.json` | Per-model prices, so cost can be calculated |
| `guardian_model_catalog` | JSON | `Lists/guardian_model_catalog.json` | Documented context limits of commonly used models, so a known model needs no probe |
| `guardian_skills_index` | JSON | `Lists/guardian_skills_index.json` | The menu of skills the agent can load |
| `guardian_kb_soc_investigation` | JSON | `Lists/guardian_kb_soc_investigation.json` | Searchable investigation guides |
| `guardian_issue_routes` | JSON | `Lists/guardian_issue_routes.json` | Which skill and evidence each kind of issue gets |
| `guardian_xql_templates` | JSON | `Lists/guardian_xql_templates.json` | Ready-made XQL queries for the common questions |
| `guardian_triage_types` | JSON | `Lists/guardian_triage_types.json` | The severities and investigation types a triage run may name |
| `guardian_skill_cortex_issue_reference` | Markdown | `Lists/guardian_skill_cortex_issue_reference.md` | Skill: issues, cases and where their data lives |
| `guardian_skill_cortex_xql` | Markdown | `Lists/guardian_skill_cortex_xql.md` | Skill: write XQL safely and cheaply (templates, fields, cost) |
| `guardian_skill_cortex_case_investigation` | Markdown | `Lists/guardian_skill_cortex_case_investigation.md` | Skill: investigate an issue end to end |
| `guardian_skill_cortex_detection_investigation` | Markdown | `Lists/guardian_skill_cortex_detection_investigation.md` | Skill: threat detections |
| `guardian_skill_cortex_posture_misconfiguration` | Markdown | `Lists/guardian_skill_cortex_posture_misconfiguration.md` | Skill: cloud misconfiguration and Kubernetes findings |
| `guardian_skill_cortex_identity_risk` | Markdown | `Lists/guardian_skill_cortex_identity_risk.md` | Skill: identity and entitlement risk |
| `guardian_skill_cortex_vulnerability_triage` | Markdown | `Lists/guardian_skill_cortex_vulnerability_triage.md` | Skill: vulnerable and risky packages |
| `guardian_skill_cortex_attack_path` | Markdown | `Lists/guardian_skill_cortex_attack_path.md` | Skill: attack paths |
| `guardian_skill_build_cortex_playbook` | Markdown | `Lists/guardian_skill_build_cortex_playbook.md` | Skill: build a playbook from examples |
| `guardian_skill_cortex_triage` | Markdown | `Lists/guardian_skill_cortex_triage.md` | Skill: triage an issue (severity and type) |

Check each list after you add it: in the War Room (or the Playground) run `!getList listName=guardian_policy`. The result must start with the list's own content (for the policy: `{"_comment": ...`), not with `{"id": "guardian_policy", "version": -1, ...`.
A list that shows a wrapper like that was loaded from a pack file: delete it and add it again from this package.

## Order and where to import

| Step | Content type | Folder | Needs | Console (as documented) | API |
|---|---|---|---|---|---|
| 1 | Issue fields | `IncidentFields/` | nothing | Settings > Configurations > Object Setup > Issues > **Fields** > New Field. The guide describes **export** of fields; no import is documented | `POST /incidentfields/import` |
| 2 | Indicator fields | `IndicatorFields/` | nothing | Settings > Configurations > Object Setup > Indicators > **Fields** > New Field. No import documented | `POST /incidentfields/import` |
| 3 | Lists (what each one does: [`../CONTENT_REFERENCE.md`](../CONTENT_REFERENCE.md#1-lists)) | `Lists/` | nothing | Settings > Configurations > Object Setup > **Lists** > **Add a List**. No import documented | `POST /lists/save` |
| 4 | Integrations | `Integrations/` | nothing | No console import is documented | `POST /settings/integration-conf/upload` |
| 5 | Automations | `Scripts/` | nothing (no order among the 78) | No console import is documented (an object created "by importing a file" counts as a custom object) | `POST /automation/import` |
| 6 | Playbooks | `Playbooks/` | the automations (the playbooks run 22 of the pack's automations, plus commands of the Core, XQL and Attack Surface Management integrations). **Upload the ten `GuardianTriage<Type>` sub-playbooks before `GuardianTriageAndInvestigateIssue`**, which calls them | No console import is documented. Their YAML carries `adopted: true`, so a playbook saved through the API is already adopted | `POST /playbook/save/yaml` |
| 7 | Layouts | `Layouts/` | the fields | Settings > Configurations > Object Setup > Issues > **Layouts** > **Import** (JSON): documented | `POST /layouts/import` |
| 8 | Issue types | `IncidentTypes/` | the layout and the playbooks | No page for importing issue types is documented | `POST /incidenttypes/import` |
| 9 | Indicator type | `IndicatorTypes/` | the indicator layout (step 7) | Settings > Configurations > Object Setup > Indicators > **Types** > New. No import documented | `POST /reputation/import` |
| 10 | Jobs | `Jobs/` | the playbooks | **Investigation & Response > Automation > Jobs** > **New Job** > Time triggered > **Create new job** (no import documented) | `POST /jobs`, or `tools/create_jobs.py` |
| 11 | Model instance | | the integrations | Settings > Configurations > Integrations, add an instance | see MODEL_SETUP |

Skip the widgets and the `Dashboards/` folder: Cortex platform does not install them, and that dashboard is in the XSOAR format. There is no pre-process rule.

**Dashboard (optional, after the first runs).** `XSIAMDashboards/dashboard-GuardianPerformance.json` is a native Cortex dashboard of 17 XQL widgets over the `issues` dataset: verdicts, confidence, cost, ticks, model, tool calls, tool failures, approvals, calibration-gate actions and the latest runs. Import it from **Dashboards & Reports > Dashboard Manager > Import** (JSON); you become its owner and its access is Restricted until you share it. It reads the fields Guardian writes on each issue (`guardianverdict`, `guardianconfidence`, `guardiancostusd`, `guardiantickcount`, `guardianmodel`, `guardiantoolcalls`, `guardiantoolfailures`, `guardianapprovalsrequested`, `guardiantoolsused`, `guardiangateaction`), so import the issue fields first. Runs made before the activity fields existed show verdict, confidence, cost and ticks only. Every widget runs an XQL query, so each refresh uses compute units from the tenant's daily XQL quota.

**API payloads** (when you use the API column). Send each file on its own, one call at a time, with a pause between calls:
- Fields and indicator fields: a JSON file `{"incidentFields": [ <the file's content> ]}`, as multipart form field `file`.
- Incident types and the indicator type: a JSON file holding an **array** with the file's content as its one element, as multipart form field `file`.
- Layouts, integrations, automations (scripts) and playbooks: the file as it is, as multipart form field `file`.
- Lists: a JSON body `{"id": "<name>", "name": "<name>", "data": "<the file's whole text>", "type": "json" or "markdown", "version": -1}`.
