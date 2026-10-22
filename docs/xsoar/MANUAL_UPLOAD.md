# Guardian for Cortex XSOAR 6: manual upload, file by file

Use this package only when you cannot install the pack (the **Guardian-...-v<version>.zip** download does that in one step, with the install script, the console pack upload or `demisto-sdk`).
Here every file is imported **one at a time**, in order. The files are prepared for that: they are not the same as the files inside the pack.

**Why a separate package.** A pack install reads each item in the pack's own format. The console's one-by-one upload does not: it takes the **file name** as the item's name and the **file text** as its content.
That is harmless for scripts, integrations and playbooks (the name is inside the file) but wrong for Lists, where a pack's list file is a wrapper around the data. A list uploaded from a pack file ends up named
`list-guardian_policy` and holds the whole wrapper, so Guardian cannot read it. In this package the `Lists/` files hold **only the data** and are named exactly as the list must be named.

**Limits.**
- Items imported one by one are ordinary content, not an installed pack. The lists that hold the security policy are **editable** by operators; with a pack install they are locked. The agent itself is still blocked from writing them, because `GuardianToolBridge` and its denylist refuse those writes either way.
- You repeat the import for every upgrade.
- Several content types have no documented import button in the console (marked below). For those, use the API call, or the pack install.

## Lists: do this exactly

Settings > Advanced > Lists > **Add a List** (the console can also upload a file). For each file in `Lists/`:
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
| `guardian_incident_routes` | JSON | `Lists/guardian_incident_routes.json` | How an incident is routed to a skill, by type, source and category |
| `guardian_triage_types` | JSON | `Lists/guardian_triage_types.json` | The triage types, the only values a triage result may use |
| `guardian_model_routing` | JSON | `Lists/guardian_model_routing.json` | Which model the triage session and each investigation level uses; every model is empty as shipped, so the provider instance's configured model is used |
| `guardian_kb_soc_investigation` | JSON | `Lists/guardian_kb_soc_investigation.json` | Searchable investigation guides |
| `guardian_skill_xsoar_case_triage` | Markdown | `Lists/guardian_skill_xsoar_case_triage.md` | Skill: triage reference |
| `guardian_skill_xsoar_triage` | Markdown | `Lists/guardian_skill_xsoar_triage.md` | Skill: triage an incident (severity and type) |
| `guardian_skill_xsoar_case_investigation` | Markdown | `Lists/guardian_skill_xsoar_case_investigation.md` | Skill: investigate a case end to end |
| `guardian_skill_xsoar_platform_reference` | Markdown | `Lists/guardian_skill_xsoar_platform_reference.md` | Skill: War Room, commands and query syntax |
| `guardian_skill_build_xsoar_playbook` | Markdown | `Lists/guardian_skill_build_xsoar_playbook.md` | Skill: build a playbook from examples |

Check each list after you add it: in the War Room (or the Playground) run `!getList listName=guardian_policy`. The result must start with the list's own content (for the policy: `{"_comment": ...`), not with `{"id": "guardian_policy", "version": -1, ...`.
A list that shows a wrapper like that was loaded from a pack file: delete it and add it again from this package.

## Order and where to import

| Step | Content type | Folder | Needs | Console (as documented) | API |
|---|---|---|---|---|---|
| 1 | Incident fields | `IncidentFields/` | nothing | Settings > Objects Setup > Incidents > Incident Fields. The guide documents **New Field**; no import is documented | `POST /incidentfields/import` |
| 2 | Indicator fields | `IndicatorFields/` | nothing | Settings > Objects Setup > Indicators > Fields. No import documented | `POST /incidentfields/import` |
| 3 | Lists (what each one does: [`../CONTENT_REFERENCE.md`](../CONTENT_REFERENCE.md#1-lists)) | `Lists/` | nothing | Settings > Advanced > Lists > **Add a List** (the guide also lists uploading and downloading a list) | `POST /lists/save` |
| 4 | Integrations | `Integrations/` | nothing | Settings > Integrations > Instances. The guide does not describe importing an integration file; the toolbar has an upload icon | `POST /settings/integration-conf/upload` |
| 5 | Automations | `Scripts/` | nothing (no order among the 79) | **Automation** page > the upload automation icon | `POST /automation/import` |
| 6 | Playbooks | `Playbooks/` | the automations (the playbooks run 23 of the pack's automations). **Upload the seven `GuardianTriage<Type>` sub-playbooks before `GuardianTriageAndInvestigateIncident`**, which calls them | **Playbooks** page > the upload button, top right | `POST /playbook/save/yaml` |
| 7 | Layouts | `Layouts/` | the incident and indicator fields | Settings > Objects Setup > Incidents > **Layouts**. No import documented | `POST /layouts/import` |
| 8 | Incident types | `IncidentTypes/` | the layout and the playbooks | Settings > Objects Setup > Incidents > **Types**: the guide lists "create, duplicate, import, export" | `POST /incidenttypes/import` |
| 9 | Indicator type | `IndicatorTypes/` | the indicator layout (step 7) | Settings > Objects Setup > Indicators > **Types**. No import documented | `POST /reputation/import` |
| 10 | Widgets | `Widgets/` | the automations | In a dashboard: **Widget Library** > add > **Upload** (JSON) | `POST /widgets/import` |
| 11 | Dashboard | `Dashboards/` | the widgets | **Dashboards** tab > the gear > **Import** (JSON) | `POST /dashboards/import` |
| 12 | Pre-process rule | `PreProcessRules/` | the `GuardianIntakeHygiene` automation and the incident types | Settings > Objects Setup > Incidents > Pre-Process Rules > **New Rule** (only creation is documented: copy the settings from the JSON) | `POST /preprocess/rule` |
| 13 | Jobs | `Jobs/` | the incident types and playbooks | **Jobs** > **New Job** > Time triggered > **Create new job** (no import documented) | `POST /jobs` |
| 14 | Model instance | | the integrations | Settings > Integrations > Instances, add an instance | see MODEL_SETUP |

Notes:
- Steps 1 to 3 need nothing, so they can be done in any order among themselves.
- Dashboard sharing is a per-user setting: share the dashboard with your team after importing it.
- After step 8, confirm that a new *Guardian Agent Run* incident shows the **Guardian** layout tab.
- Upgrading from a version that shipped `GuardianTriageIncident`: that playbook is now `GuardianTriageAndInvestigateIncident`. Re-point any incident type or Job that used the old name, then delete the old playbook. Upload the new automations `GuardianModelChoice` and `GuardianIncidentSummary` and the new list `guardian_model_routing` before the playbooks.
- Upgrading to the version with the duplicate check: upload the new automation `GuardianIncidentDuplicateCheck` and replace the list `guardian_tool_denylist` (it now names that automation, and control lists change only when they are replaced), both before `GuardianTriageAndInvestigateIncident`.

**API payloads** (when you use the API column). Send each file on its own, one call at a time, with a pause between calls:
- Fields and indicator fields: a JSON file `{"incidentFields": [ <the file's content> ]}`, as multipart form field `file`.
- Incident types and the indicator type: a JSON file holding an **array** with the file's content as its one element, as multipart form field `file`.
- Layouts, integrations, automations (scripts) and playbooks: the file as it is, as multipart form field `file`.
- Lists: a JSON body `{"id": "<name>", "name": "<name>", "data": "<the file's whole text>", "type": "json" or "markdown", "version": -1}`.
