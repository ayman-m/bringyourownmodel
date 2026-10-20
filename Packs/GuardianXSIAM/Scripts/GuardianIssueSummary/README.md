Operator-owned automation that writes Guardian's triage summary or investigation conclusion to the current issue, in two
places: a short War Room note, and one delimited section at the end of the issue's description. The model never calls it;
it is on the denylist and not on the allowlist. The playbook `GuardianTriageAndInvestigateIssue` runs it twice, once per
stage.

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
| apply_changes | `true` (the default) posts the note and writes the description section. `false` computes the text and writes nothing. |

## What it writes
---

The note is posted like a `GuardianCaseNote` note (markdown, tag `guardian-issue-summary`).

The description gets one section, starting at this line:

```
--- Guardian (automated) ---
Triage: <one line>
Investigation: <one line>
```

- The text above the marker is never changed. The new description is the original text, a blank line and the section.
- A re-run replaces the section (from the marker to the end) and never adds a second one. A stage keeps the other stage's
  line when it is there.
- Each line is one line of plain text, scrubbed of secrets and cut to 700 characters; the section is at most 1500.
- The current description is read from the platform (`core-get-issues`), with the issue's own `details` or `description`
  as the fallback. If neither shows it, the description is not written and the reason says why.
- The investigation note and line also name the model the investigation ran on (from `Guardian.ModelChoiceCurrent`: the model or
  `default`, the level and, in the note, the reason) when the model-routing task ran.
- `GuardianIssueEvidence`, the issue pin of the reasoning loop and the tool bridge (every tool result) drop the section,
  so the model never reads Guardian's own earlier conclusion back as evidence.

## Outputs
---

One entry per stage, merged by `stage`.

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Guardian.IssueSummary.stage | triage or investigation. | String |
| Guardian.IssueSummary.status | written, dry_run, skipped or error. | String |
| Guardian.IssueSummary.note_posted | True when the War Room note was posted. | Boolean |
| Guardian.IssueSummary.description_updated | True when the issue's description was updated. | Boolean |
| Guardian.IssueSummary.section_chars | Length of the Guardian section. | Number |
| Guardian.IssueSummary.reason | Why nothing was written, or why the description was not. | String |

## Command Example
```!GuardianIssueSummary stage=triage```
