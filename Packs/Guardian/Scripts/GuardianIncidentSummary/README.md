Operator-owned automation that writes Guardian's triage summary or investigation conclusion to the current incident, in
two places: a short War Room note, and one delimited section at the end of the incident's details. The model never calls
it; it is on the denylist and not on the allowlist. The playbook `GuardianTriageAndInvestigateIncident` runs it twice,
once per stage.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | - |
| Cortex XSOAR Version | 6.10.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| stage | `triage` writes the triage summary (from `Guardian.Triage` and `Guardian.TriageApply`). `investigation` writes the conclusion of the model investigation (from `Guardian.Loop.verdict`). |
| apply_changes | `true` (the default) posts the note and writes the details section. `false` computes the text and writes nothing. |

## What it writes
---

The note is posted like a `GuardianCaseNote` note (markdown, tag `guardian-incident-summary`).

The details get one section, starting at this line (the same marker the Cortex platform edition uses in an issue's
description):

```
--- Guardian (automated) ---
Triage: <one line>
Investigation: <one line>
```

- The text above the marker is never changed. The new details are the original text, a blank line and the section.
- A re-run replaces the section (from the marker to the end) and never adds a second one. A stage keeps the other stage's
  line when it is there.
- Each line is one line of plain text, scrubbed of secrets and cut to 700 characters; the section is at most 1500.
- The details are written through the Core REST API, like Guardian's own incident fields: the incident record is read
  (`/incidents/search`), the new text is built from the details in that record, and the record is written back
  (`/incident`) with only the details changed. A version collision rebuilds the text from a fresh read once. If the
  record cannot be read, or holds no details text, the details are not written and the reason says why. It needs the
  Core REST API integration that Guardian already uses.
- The triage stage writes the summary even when the apply task skipped the incident (an owner, a closed incident, an
  earlier triage): the line then says the severity was left unchanged and why.
- The investigation note and line also name the model the investigation ran on (from `Guardian.ModelChoiceCurrent`: the
  model or the provider's configured model, the level and, in the note, the reason) when the model-choice task ran.
- `GuardianIncidentEvidence`, the incident pin of the reasoning loop, the tool bridge (every tool result) and
  `GuardianEvalHarvest` drop the section, so the model never reads Guardian's own earlier conclusion back as evidence.

## Outputs
---

One entry per stage, merged by `stage`.

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Guardian.IncidentSummary.stage | triage or investigation. | String |
| Guardian.IncidentSummary.status | written, dry_run, skipped or error. | String |
| Guardian.IncidentSummary.note_posted | True when the War Room note was posted. | Boolean |
| Guardian.IncidentSummary.details_updated | True when the incident's details were updated. | Boolean |
| Guardian.IncidentSummary.section_chars | Length of the Guardian section. | Number |
| Guardian.IncidentSummary.reason | Why nothing was written, or why the details were not. | String |

## Command Example
```!GuardianIncidentSummary stage=triage```
