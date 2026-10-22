# Guardian for Cortex XSOAR 6: install

This guide is for **Cortex XSOAR 6** (6.10 or later) and the pack `Guardian-<ver>.zip`. If you run Cortex platform, use
[`../cortex-platform/README.md`](../cortex-platform/README.md): the two editions are different content, in separate downloads and separate releases, and must not be mixed.

Paths below are relative to the unzipped download (`Guardian-XSOAR-v<version>/`).

## What this edition contains

| Content type | Count | Folder inside the pack zip |
|---|---|---|
| Incident fields | 15 | `IncidentFields/` |
| Indicator fields | 10 | `IndicatorFields/` |
| Lists | 20 | `Lists/` |
| Integrations (Foundry, Vertex, Cohere), unified YAML | 3 | `Integrations/` |
| Automations, unified YAML | 79 | `Scripts/` |
| Playbooks | 17 | `Playbooks/` |
| Layouts (1 incident layout, 1 indicator layout) | 2 | `Layouts/` |
| Incident types | 2 | `IncidentTypes/` |
| Indicator type | 1 | `IndicatorTypes/` |
| Widgets | 5 | `Widgets/` |
| Dashboard | 1 | `Dashboards/` |
| Pre-process rule | 1 | `PreProcessRules/` |
| Jobs | 6 | `Jobs/` |

Every integration and automation in the pack zip is a single unified YAML file: you never build anything.

## Choose how to install

| | Method | Use it when |
|---|---|---|
| **A** | Install script (in this download) | You can run Python 3 with network access to the server |
| **B** | Pack upload in the console | You prefer the console |
| **C** | `demisto-sdk` upload of the pack, from a clone of the repository | You already use the SDK |
| **D** | Item by item, in order (the separate **Manual Upload** download) | None of A to C is possible. A fallback: see its limits |

A, B and C install everything in the right order for you. All four finish with the same follow-ups: create the Jobs and add a model provider.

## Prerequisites

- Cortex XSOAR 6.10 or later.
- For methods A and C and for the Jobs: an **API key** (Settings > Integrations > API Keys). Keys inherit the roles of the user who creates them. Export it in your shell;
  never write it into a file you share.
- An account on a model provider ([`../MODEL_SETUP.md`](../MODEL_SETUP.md)).
- Check the download: `shasum -a 256 -c SHA256SUMS` in the unzipped folder.

## Method A: install script

```bash
cd Guardian-XSOAR-v<version>
export DEMISTO_BASE_URL="https://<your server>"
export DEMISTO_API_KEY="<api key>"
# self-signed certificate: export DEMISTO_VERIFY_SSL=false      TLS-inspecting proxy: export SSL_CERT_FILE=/path/to/ca-bundle.pem
python3 tools/install_pack.py pack/Guardian-<ver>.zip
```

The script sends the zip to the server's pack-upload endpoint and then checks that the pack is listed as installed. Guardian is a custom (unsigned) pack, so the request
carries `skipVerify=true&skipValidation=true`; the API documents `skipVerify` as the option "when uploading a custom or dev pack".

## Method B: pack upload in the console

1. **Marketplace**, then the **gear icon**, then **Upload Content Packs**, and choose `pack/Guardian-<ver>.zip`. (The Cortex XSOAR admin guide describes this button in its
   offline-install procedure; the SDK documentation calls the same button "Upload pack".)
2. Wait for the install to finish.

**If the console refuses the pack as not signed:** the server configuration `content.pack.verify` (default `true`) controls whether custom packs that are not provided by
Cortex XSOAR are imported. Set it to `false` under **Settings > About > Troubleshooting > Add Server Configuration** (key, value, Save), upload again, and set it back if
your policy requires. Or use method A, which does not depend on it.

## Method C: `demisto-sdk` upload (from a clone of the repository)

The SDK builds the unified YAML files itself from the repository's split sources, so this method needs a clone, not the download.

```bash
git clone <this repository> && cd <the clone>
python3 -m venv .venv && .venv/bin/pip install demisto-sdk
export DEMISTO_BASE_URL="https://<your server>"
export DEMISTO_API_KEY="<api key>"
unset XSIAM_AUTH_ID                      # if it is set, the SDK switches to Cortex platform mode
.venv/bin/demisto-sdk upload -i Packs/Guardian -z --skip_validation --override-existing
python3 scripts/deploy_jobs.py           # the SDK does not create Jobs
```

`-z` zips the pack and uploads it as a pack (the same result as method B); `--override-existing` replaces an installed copy. `bash scripts/deploy.sh` does the same and also
re-syncs the shared helper code first. The repository is already shaped the way the SDK needs (a git repository, `Packs/`, `.private-repo-settings`, `Tests/secrets_white_list.json`).

## Method D: item by item, in order

Use this only if no pack install is possible. It is a **separate download**, `Guardian-XSOAR-Manual-Upload-v<version>.zip` (from the same Releases page), because the console's one-file-at-a-time upload does not read
the pack's files the way a pack install does. In particular a pack's list file, uploaded on its own, creates a list named `list-guardian_policy` that holds the whole file as its data, and Guardian cannot read it.
The manual package carries every item in the form the console expects (lists as plain data files named exactly as the list must be named), the order to import them in, where to click for each type, the API call for the types
that have no import button, and a check to run after each list. Do not mix it with the files inside the pack zip.

## Create the Jobs (all methods)

The platform does not create Jobs from a pack install. Create the six Jobs with the script (recommended), using the environment from method A:

```bash
GUARDIAN_JOBS_DIR=tools/jobs python3 tools/create_jobs.py
```

It is safe to run again: it updates a Job it already created and never duplicates one. Or create them by hand (**Jobs** > **New Job** > Time triggered; recurring; **close
previous run** on); the same settings are in `tools/jobs/job-*.json`:

| Job | Incident type | Playbook | Every |
|---|---|---|---|
| `GuardianIntakeSweep` | Guardian Agent Run | `GuardianAgentLoop` | 6 hours |
| `GuardianHousekeeping` | Unclassified | `GuardianHousekeeping` | 1 hour |
| `GuardianCaseCapture` | Unclassified | `GuardianCaseCapture` | 4 hours |
| `GuardianEvalScore` | Unclassified | `GuardianEvalScore` | 1 hour |
| `GuardianEvalHarvest` | Unclassified | `GuardianEvalHarvest` | 24 hours |
| `GuardianModelAdaptation` | Unclassified | `GuardianModelAdaptation` | 24 hours |

`GuardianIntakeSweep` triages open incidents with a model every six hours, read-only. Create it once you have chosen the model and checked the cost.

## Add a model provider

Follow [`../MODEL_SETUP.md`](../MODEL_SETUP.md): Microsoft Foundry (a resource key **or** Microsoft Entra ID), Google Vertex, or Cohere North. Then run `!guardian-model` to confirm it,
and `!guardian-probe-model` followed by the `GuardianModelAdaptation` job once.

## First run

Create an incident of type **Guardian Agent Run** (click Investigate if it sits in Pending). Watch the War Room and the **Guardian** tab: verdict, reasoning trace, tool ledger and
recommended actions. Approve or deny a proposed action with `!guardian-approve approval_id=<id>` and `!guardian-deny approval_id=<id> reason="..."`. The kill switch is
`!guardian-killswitch state=on`.

More: [`../OPERATOR_RUNBOOK.md`](../OPERATOR_RUNBOOK.md) (operation) and [`../GUARDIAN_GUIDE.md`](../GUARDIAN_GUIDE.md) (capabilities, who uses it, testing).

## Triage and investigation of one incident

To have Guardian rate an incident and then investigate it, attach the playbook **`GuardianTriageAndInvestigateIncident`**
to the incident (as its type's playbook, or `!setPlaybook name="GuardianTriageAndInvestigateIncident"` in its War Room).
It runs a short triage session that ends with a fixed block (severity, type, confidence, and optionally an analysis,
recommendations and a complexity rating), sets the incident's severity and phase behind guards, writes a "Guardian
triage" note, and then runs a full investigation through the sub-playbook for the incident's type (`GuardianTriagePhishing`,
`IdentityThreat`, `EndpointThreat`, `NetworkThreat`, `DataExposure`, `Vulnerability`, or `GuardianTriageOther`, which
investigates on the skill the incident route chose). The triage summary and the conclusion are also kept in one section
at the end of the incident's details, behind the line `--- Guardian (automated) ---`; the original text is never
changed. That write uses the Core REST API integration Guardian already needs.

**Model routing (optional).** The protected list `guardian_model_routing` ships empty: every call uses the provider
instance's configured model, exactly as before. Fill it (edit `Lists/list-guardian_model_routing.json` and redeploy) to
send the triage session and each investigation complexity level to a model of your choice; the routing rules are in
[`../OPERATOR_RUNBOOK.md`](../OPERATOR_RUNBOOK.md). Only this playbook routes: the *Guardian Agent Run* incidents and the
intake Job (`GuardianAgentLoop`) always use the configured model.

Upgrading from a version with `GuardianTriageIncident`: that playbook is now `GuardianTriageAndInvestigateIncident`.
Re-point any incident type or Job that used the old name, then delete the old playbook.

## Upgrading

Install the new pack (method A, B or C, or repeat D), run `tools/create_jobs.py` again, and keep your runtime lists (memory, audit, model profile): a pack install does not delete them.

## If something goes wrong

| Symptom | Fix |
|---|---|
| The console says the pack is not signed | Set `content.pack.verify` to `false` (method B), or use `tools/install_pack.py` |
| `CERTIFICATE_VERIFY_FAILED` from a script | Your network inspects TLS: `export SSL_CERT_FILE=/path/to/ca-bundle.pem` (`DEMISTO_VERIFY_SSL=false` only for a lab) |
| `demisto-sdk` behaves as if it were on Cortex platform | `unset XSIAM_AUTH_ID` |
| Foundry **Test** says HTTP 429 | Raise the deployment's tokens-per-minute quota |
| Foundry **Test** says 401 or 403 | Wrong key, or the Entra principal lacks the role on the resource |
| `create_jobs.py` says the spec was rejected | Create that Job by hand from the table |
| A new run stops at once ("loop already ... ignoring stray re-entry") | `!DeleteContext key=Guardian` in that incident's War Room, then start again |
| A *Guardian Agent Run* incident sits in Pending | By design: it never starts on its own. Click Investigate, or let the intake job triage normal incidents |

## Sources

Checked against the Cortex XSOAR 6.14 administrator guide and the demisto-sdk and XSOAR API documentation on `cortex-docs.paloaltonetworks.com`: Marketplace > Upload Content Packs
(install a content pack offline); server configurations (`content.pack.verify`) and Add Server Configuration (Marketplace troubleshooting); API Keys; Lists; Incident Fields; Incident
Types; Pre-Process Rules; Jobs (create a time-triggered job); dashboards and the widget library; the content-packs API (`skipVerify`, `skipValidation`); the SDK's `upload`,
`zip-packs` and environment-variable pages. Menu names can differ between versions.
