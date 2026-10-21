Operator-owned automation that decides, without a model, whether the current issue repeats a lower-numbered open issue of
the same rule on the same thing. The playbook `GuardianTriageAndInvestigateIssue` runs it before the triage model session,
and a duplicate gets a short note and skips the model, so a noisy rule costs no tokens. The model never calls it; it is on
the denylist and not on the allowlist.

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
| max_candidates | Optional. How many open issues of the same rule to read, oldest first. Default 50, at most 100. |
| close_duplicates | Optional. `true` closes THIS issue as `Resolved - Duplicate Issue` when it is a duplicate. Default `false`. |

## How the answer is decided
---

1. The script reads the issue's rule id (`ruleid`), name, `asset_ids` and an entity fingerprint: the normalized (lowercase,
   sorted, de-duplicated) values of `_vendor`, `_product`, `hostname` / `agent_hostname`, `username` / `user_name` /
   `actor_effective_username`, `localip`, `remoteip`, `filesha256` / `action_file_sha256` and `domain`. Field names are read
   without regard to case and separators. A field the issue does not carry is left out.
2. One search (`/incidents/search`, `ruleid:"<rule id>" and -status:closed`, oldest first) returns the open issues of the rule.
3. A candidate matches when it is another issue of the same rule and either both issues carry asset ids and the sets
   intersect, or neither carries asset ids and both fingerprints are non-empty and equal. An issue with asset ids is never
   matched on its fingerprint; an issue with an empty fingerprint and no asset ids is never a duplicate.
4. Tie-break: the issue is a duplicate only when a matching open issue has a **lower** numeric id; the original is the lowest
   such id. Two issues running at the same time never mark each other, and the lowest-numbered issue of a group is never a
   duplicate.
5. `open_in_group` counts this issue and every matching open issue. For a duplicate, and for an original with later matches
   (`open_in_group` above 1), `proposed_exclusion` is what an analyst would put into an issue exclusion or a correlation
   suppression for this rule and scope. It is a proposal; nothing is applied.

The script fails open: no rule id, a rule id that cannot go into a search, a failed or unreadable search, or any unexpected
error gives `is_duplicate: "false"` with a `reason`. It never ends in an error that would stop the playbook.

With `close_duplicates=true` and a duplicate, only this issue is closed, with `core-update-issue status="Resolved - Duplicate Issue"`.
The original and every other issue are never changed. A failed close is recorded in `close_error`.

## Outputs
---

`Guardian.Duplicate` is overwritten on every run (and emptied when the task starts), never appended to.

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Guardian.Duplicate.issue_id | The issue that was checked. | String |
| Guardian.Duplicate.is_duplicate | `true` or `false`. | String |
| Guardian.Duplicate.original_id | The lowest-numbered matching open issue; empty if not a duplicate. | String |
| Guardian.Duplicate.matching_open_ids | Matching open issue ids, lowest first (at most 20). | Unknown |
| Guardian.Duplicate.open_in_group | Open issues of the rule on the same assets or source, counting this one. | Number |
| Guardian.Duplicate.rule_id | The rule id of the issue. | String |
| Guardian.Duplicate.rule_name | The name of the issue. | String |
| Guardian.Duplicate.fingerprint | The entity fingerprint the comparison used. | Unknown |
| Guardian.Duplicate.reason | Why the answer is what it is. | String |
| Guardian.Duplicate.proposed_exclusion | The proposed exclusion (rule_name, rule_id, scope, reason, suggested_review_days). | Unknown |
| Guardian.Duplicate.proposed_exclusion_text | The proposal as one sentence, for a note. | String |
| Guardian.Duplicate.closed | `true` when this issue was closed as a duplicate. | String |
| Guardian.Duplicate.close_error | Why closing failed; empty otherwise. | String |

## Command Example
```!GuardianIssueDuplicateCheck close_duplicates=false```
