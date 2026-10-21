Operator-owned automation that chooses the model of the triage session or of the investigation from the control-plane List
`guardian_model_routing`. The model never calls it; it is on the denylist and not on the allowlist. The playbook
`GuardianTriageAndInvestigateIssue` runs it twice, once per stage, and passes the answer to `GuardianModelProfileCheck`
and, through the model snapshot, to the reasoning loop.

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
| stage | `triage` chooses `routing.triage`. `investigation` chooses by the triage result. |
| investigate_max_ticks | Optional. The playbook input of the same name; when set it is the investigation's turn limit and wins over the level's `max_ticks`. |

## How the investigation model is chosen
---

1. The level starts at the triage block's `complexity` (`low`, `medium` or `high`); without one it is `medium`.
2. Floors: a triage result that says `escalate`, or a severity of high or critical (the model's, or the one on the issue
   after the apply task), makes it at least `medium`.
3. A triage confidence under 60 raises it by one level. A failed triage has confidence 0, so it ends at `high`.
4. The model is `complexity.<level>.model` of the List, and `max_ticks` is the level's `max_ticks` (or the
   `investigate_max_ticks` input). An empty model means the provider instance's configured model.

The List ships with every model empty, so a run behaves as it always did. To limit the turns of cheap investigations, add
`"max_ticks": 15` to a level's entry in `Lists/list-guardian_model_routing.json` and redeploy the pack.

A Cohere North provider cannot choose a model per call: the default is kept. A model that is not in
`guardian_model_catalog` is kept, with a warning that its limits will be guessed. If the provider does not know the model
at run time, the reasoning loop drops it and carries on with the instance's model.

## When the task fails
---

The script empties `Guardian.ModelChoiceCurrent` before it does anything else, and again when it fails, so the playbook
never reads an earlier run's choice, or the triage stage's, as this one: a failed choice means the configured model and the
model size's own turn limit. Two consequences are known and left as they are:

- if the investigation choice fails, the playbook input `investigate_max_ticks` is not applied either (the sub-playbooks
  take their turn limit from `Guardian.ModelChoiceCurrent.max_ticks`), so the investigation runs with the model size's
  own limit;
- the one repair call `GuardianTriageResult` makes for a triage answer it cannot read goes to the provider instance's
  configured model, not to the routed triage model.

## Outputs
---

`Guardian.ModelChoice` has one entry per stage (merged by `stage`). `Guardian.ModelChoiceCurrent` holds the latest stage as
one flat object, which the playbook reads.

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Guardian.ModelChoice.stage | triage or investigation. | String |
| Guardian.ModelChoice.level | The investigation level; empty for triage. | String |
| Guardian.ModelChoice.model | The model chosen; empty means the configured model. | String |
| Guardian.ModelChoice.max_ticks | The investigation's turn limit; empty means the model size's own. | Number |
| Guardian.ModelChoice.reason | How the choice was made. | String |
| Guardian.ModelChoice.warnings | Problems that did not stop the choice. | Unknown |
| Guardian.ModelChoice.provider | The provider brand when a model was chosen. | String |

## Command Example
```!GuardianModelChoice stage=investigation```
