Operator-owned automation that turns a finished Guardian run into the structured report the Guardian tab of an Agent Run
incident draws. It is the last task of `GuardianAgentLoop` and of the investigation branch of
`GuardianTriageAndInvestigateIncident`, runs after the investigation and does not change it. The model never calls it: it
is on the denylist and not on the allowlist.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | - |
| Cortex XSOAR Version | 6.10.0 |

## Inputs
---

There are no arguments. It reads the run's state (`Guardian.Loop`, `Guardian.Triage`, `Guardian.TriageApply`,
`Guardian.ToolCatalog`), the incident, the Lists `guardian_settings`, `guardian_kill_switch` and `guardian_prompt_report`,
and, for a run that was compacted, `guardian_dropped_transcript_archive`.

## What it does
---

1. **Evidence.** Every tool call of the run, in order, numbered `t1`..`tn`: the tool, its arguments and the head of its
   result. Procedure and self-referential tools (skill reads, knowledge base search, memory, analyst questions, case notes,
   plan approval) are left out. The heads are cut so that the largest prompt fits the run's input budget; when even the
   shortest heads do not fit, the oldest calls are left out.
2. **Three model calls**, one per part, in this order: the headline, entities and relationships (`core`); the attack chain,
   timeline and process tree (`story`, given the entity ids of `core`); the findings, recommended actions and gaps
   (`close`). They use the model of the run, with no tools and no JSON mode: the JSON is taken out of the reply text. A reply
   with no usable JSON gets one repair request ("return only the JSON object"). Each call is charged to the cost ledger
   under the trigger `report_build`.
3. **Not asked of the model.** The verdict, confidence and severity come from the run's recorded verdict
   (`Guardian.Loop.verdict`, else the incident's `guardianverdict` and `guardianconfidence`) and the severity change
   `GuardianTriageApply` made, so the page always matches the incident fields.
4. **Validation.** Enums, list caps and string lengths are applied (the same ones the page applies). A reference that is not
   one of the run's calls is dropped, and an item with no valid reference is shown as unverified. An entity found neither in
   the tool results nor in the conclusion is dropped; one found only in the conclusion has no references. A generic word
   ("workstation") is not an entity. An action's command must be a command of the run's tool list, and an action about
   Guardian's own bookkeeping is dropped. Secrets in any text are masked.
5. **When it does not run.** `report_enabled` false, the kill switch on (read again before every later call), or a run started
   by a scheduled Job (`guardiantriggersource` starts with `job:`, for example the intake sweep): no model call, no report, and
   the old `Guardian.Report` is deleted. When the fixed text of the prompts does not fit the run's input budget, no call is
   made and `errors` says so. Only the archive rows of this run's own session (`Guardian.Loop.session_id`) are read.
6. **Output.** `Guardian.Report`, one `report_build` audit row, and a short War Room note (calls, seconds, entities,
   techniques, unverified items, errors).

## Settings
---

| **Setting** (`guardian_settings`) | **Description** |
| --- | --- |
| report_enabled | `true` by default. `false` skips the step: no model call, nothing written, and the tab shows the assessment card. |
| report_max_calls | `3` by default: how many of the three parts are asked for. Repair requests are extra. |

The prompt text is the deploy-time List `guardian_prompt_report`; the script has a built-in copy for a tenant where the List
is missing. With the kill switch on, the step does nothing.

## When it fails
---

It never fails the playbook. On an error `Guardian.Report` holds `errors` and no `report`, and the page shows the assessment
card. The page shows a report only while its `run_id`, `tick` and `fingerprint` match the run state, so a report of an earlier run is never
shown.

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Guardian.Report.v | The record version (1). | Number |
| Guardian.Report.run_id | The run the report is about. | String |
| Guardian.Report.tick | The run's tick when the report was built. | Number |
| Guardian.Report.fingerprint | The run's last assistant fingerprint when the report was built; the page shows the report only while it matches. | String |
| Guardian.Report.generated_at | When the report was built (UTC). | String |
| Guardian.Report.model | The model that answered. | String |
| Guardian.Report.calls | Model calls made, repair requests included. | Number |
| Guardian.Report.tokens | Tokens used by those calls. | Number |
| Guardian.Report.cost_usd | Cost of those calls in USD. | Number |
| Guardian.Report.seconds | Time the step took. | Number |
| Guardian.Report.report | The validated report, or null when no part gave one. | Unknown |
| Guardian.Report.refs | The tool calls the report cites: id to tool and arguments. | Unknown |
| Guardian.Report.errors | What went wrong, if anything. | Unknown |

## Command Example
```!GuardianReportBuild```
