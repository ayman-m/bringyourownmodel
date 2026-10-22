Operator-owned automation that decides, without a model, whether the current incident repeats a lower-numbered open incident
of the same type and name on the same thing. The playbook `GuardianTriageAndInvestigateIncident` runs it before the triage
model session, and a duplicate gets a short note and skips the model, so a noisy source costs no tokens. The model never
calls it; it is on the denylist and not on the allowlist.

XSOAR 6 also ships native deduplication (pre-process rules, and the Deduplication content with `FindSimilarIncidentsV2`).
This check does not replace them. It is a lightweight, no-model gate in front of Guardian's own triage, so that a repeat of
an open incident does not cost a model session; keep using the native tools to stop duplicates from being created at all.

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
| max_candidates | Optional. How many open incidents of the same type and name to read, oldest first. Default 50, at most 100. |
| close_duplicates | Optional. `true` links THIS incident to the original and closes it as a duplicate when it is one. Default `false`. |

## How the answer is decided
---

1. The script reads the incident's `type`, `name`, `sourceBrand`, `sourceInstance` and an entity fingerprint: the normalized
   (lowercase, whitespace collapsed, sorted, de-duplicated) values of the host (`hostname`, `devicename`, `agenthostname`),
   user (`username`, `users`, `account`), source address (`sourceip`, `srcip`), destination address (`destinationip`,
   `dstip`), file hash (`filesha256`, `filehash`, `sha256`), URL (`url`) and email sender (`emailfrom`, `emailsender`). Field
   names are read without regard to case and separators, from `CustomFields`, then the top level of the incident, then its
   `labels`; the first place that has a value wins. A field the incident does not carry is left out. The external id of the
   incident is not part of the fingerprint.
2. One search (the built-in `getIncidents`, `query=type:"<type>" and name:"<name>" and -status:closed`, `sort=id.asc`) returns
   the open incidents of the type and name. The query only narrows the list: every candidate is compared again. `getIncidents`
   is used instead of the Core REST API because it needs no integration, and the reply is the incident list itself.
3. A candidate matches when it has the same type, the same normalized name, the same source brand and the same source instance
   (an empty value equals only another empty value), and its fingerprint is equal to this incident's and not empty. An
   incident with no type, no name or an empty fingerprint is never a duplicate.
4. Tie-break: the incident is a duplicate only when a matching open incident has a **lower** numeric id; the original is the
   lowest such id. Two incidents running at the same time never mark each other, and the lowest-numbered incident of a group
   is never a duplicate.
5. `open_in_group` counts this incident and every matching open incident. For a duplicate, and for an original with later
   matches (`open_in_group` above 1), `proposed_exclusion` is what an analyst could put into a pre-process rule or into the
   fetch filter of the integration that raises these incidents, to drop or link new incidents of this type and name for this
   scope. It is a proposal; nothing is applied.

The script fails open: no type or name, an empty fingerprint, a value that cannot go into a search, a failed or unreadable
search, or any unexpected error gives `is_duplicate: "false"` with a `reason`. It never ends in an error that would stop the
playbook.

With `close_duplicates=true` and a duplicate, only this incident is changed, with the platform's own close-as-duplicate call:
`linkIncidents incidentId=<original> linkedIncidentIDs=<this incident> action=duplicate`, which links it to the original and
closes it. When the platform could not close it (it answers `0 incidents marked as duplicates`, for example because a
mandatory field of the incident type is empty), `closed` stays `false` and `close_error` says to check the mandatory fields.
The original and every other incident are never changed. Closing an incident ends its investigation, so a playbook task that
runs after the close may not run; the answer and the result of this task are the record.

## Outputs
---

`Guardian.Duplicate` is overwritten on every run (and emptied when the task starts), never appended to.

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Guardian.Duplicate.incident_id | The incident that was checked. | String |
| Guardian.Duplicate.is_duplicate | `true` or `false`. | String |
| Guardian.Duplicate.original_id | The lowest-numbered matching open incident; empty if not a duplicate. | String |
| Guardian.Duplicate.matching_open_ids | Matching open incident ids, lowest first (at most 20). | Unknown |
| Guardian.Duplicate.open_in_group | Open incidents of the type and name on the same entities, counting this one. | Number |
| Guardian.Duplicate.incident_type | The type of the incident. | String |
| Guardian.Duplicate.incident_name | The name of the incident. | String |
| Guardian.Duplicate.fingerprint | The entity fingerprint the comparison used. | Unknown |
| Guardian.Duplicate.reason | Why the answer is what it is. | String |
| Guardian.Duplicate.proposed_exclusion | The proposed pre-process rule or fetch filter (incident_type, incident_name, scope, mechanism, reason, suggested_review_days). | Unknown |
| Guardian.Duplicate.proposed_exclusion_text | The proposal as one sentence, for a note. | String |
| Guardian.Duplicate.closed | `true` when this incident was linked and closed as a duplicate. | String |
| Guardian.Duplicate.close_error | Why closing failed; empty otherwise. | String |

## Command Example
```!GuardianIncidentDuplicateCheck close_duplicates=false```
