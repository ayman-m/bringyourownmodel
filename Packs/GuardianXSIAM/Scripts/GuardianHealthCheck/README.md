Operator-owned self-test for the Cortex platform edition. Run `!GuardianHealthCheck` in the Playground, or in an issue, after an
install or an upgrade. It checks that the whole package is present and working, that the Lists agree with one another, that
the model provider is set up and the model answers, that the core scripts run, and that the tool chokepoint enforces the
allowlist and the denylist. It returns ONE markdown report: every check is PASS, WARN, FAIL or SKIP with a one-line detail,
and every WARN and FAIL carries the likely cause and the fix. The model never calls it; it is on the denylist and not on the
allowlist.

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
| test_model | Optional, default `true`. One tiny model call to check that the enabled provider answers. |
| test_routing | Optional, default `true`. One tiny call per distinct model named in `guardian_model_routing` (passed as `model=`), to check that the provider serves it. |
| test_bridge | Optional, default `true`. Probes the tool chokepoint (`GuardianToolBridge`). |
| include_xql | Optional, default `false`. `true` runs ONE tiny XQL query through `GuardianXQL` (`dataset = cloud_audit_logs | limit 1`, a 1-hour window), which costs a little compute units. |
| max_model_calls | Optional, default `4`, at most `6`. The most model calls the check makes: one for the provider plus one per distinct routed model, never more than this. Calls that do not fit are SKIPped and named. |
| verbose | Optional, default `false`. `true` adds the detail lines under every PASS. |

## What it checks
---

1. **Package content.** The automations, playbooks, Lists, issue fields, issue types and layouts the pack ships, compared with the tenant by name: one search per kind, no loop. A missing item is a FAIL, an extra `Guardian*` item is a WARN (an older version, a copy or your own). A search the tenant answers in a shape this check does not know is a WARN ("unverified"), never a false FAIL.
2. **Lists valid.** Every JSON control List parses and is the List's own content (not a pasted pack file with an `id`/`name`/`version`/`data` wrapper). They agree with one another: the settings, policy, preapproved, allowlist and denylist have their required keys; no command is both allowed and denied; every route names an enabled skill; every skill in the index has its List; the models in `guardian_model_routing` are in `guardian_model_catalog` (a WARN when not).
   The XQL templates are checked for well-formedness (name, parameters, query; every `{placeholder}` is a declared parameter).
3. **Integrations.** Exactly one Guardian model provider instance is enabled (none is a FAIL, more than one a WARN), its `lastError` is empty, the pack's provider integrations are uploaded, and the Core REST API integration instance with "Use tenant" is present and enabled (a FAIL when not: verdict fields and notes cannot be written). The `xdr-xql-generic-query` command must exist (a WARN when absent: `GuardianXQL` is unavailable).
4. **Model.** `GuardianModelProfileCheck` runs with `read_only=true` (size, input and tool budgets, turn limit; a WARN when the run uses a smaller size than the catalogue gives the model). Then one `guardian-llm-chat` call with a tiny prompt asking for the word OK (latency, tokens, cost from `guardian_pricing`), and, with `test_routing`, one call per distinct routed model. `MODEL_NOT_AVAILABLE:` is a FAIL, `MODEL_SELECTION_UNSUPPORTED:` a WARN. The total cost of the check is shown. The `guardian-llm-chat` contract has no max-tokens argument, so the prompt is what keeps the answers short; the calls are not added to the cost ledger.
5. **Core scripts.** Run through `executeCommand`: `GuardianKillSwitchCheck` (the kill switch on is a WARN), `GuardianJobGuardCheck`, `GuardianIssueRoute` (only inside an issue), `GuardianSkillRead name=cortex_triage summary_only=true`, `GuardianPromptBuilder summary_only=true`, `GuardianModelChoice stage=triage`, and `GuardianIssueDuplicateCheck` (only inside an issue). The memory List is checked by reading it with `getList` (the `GuardianMemory` search would update hit counts, remove expired rows and could create the List).  `GuardianXQL template=list` runs (read-only); the one query runs only with `include_xql=true`.
6. **Security gate.** Through `GuardianToolBridge`, exactly the way the reasoning loop calls it: `GuardianSkillRead` must come back with `status=ok`, and the denylisted `GuardianModelChoice` must come back with `status=denied`. The verdict is the bridge's own `status`, never a keyword in its text. If either is wrong, the check says the tool chokepoint is not enforcing the lists. With the kill switch on the bridge answers `halted` before it reads the lists: that is a WARN and the lists are not tested. The probe is `GuardianModelChoice` because it is on the plain denylist and harmless if the gate ever failed (it reads one List, writes its own context key and one audit row).
7. **Summary.** The overall status, the counts, every WARN and FAIL with its fix in the order to do them, the model cost and the time taken. If the run reaches 200 seconds it stops starting new work, marks the rest SKIP ("time budget") and still returns the report.

## What it never does
---

It never runs `GuardianToolRegistryRefresh`; never writes, creates or deletes a List; never toggles the kill switch; never creates, enables or runs a Job or a playbook; never approves or denies anything; never changes an issue field. It runs XQL only with `include_xql=true`, one query with `| limit 1` over a 1-hour window. It executes only the commands in `GUARDIAN_HC_COMMANDS`, posts only to the read-only search URIs and gets only the read-only URIs named in the script, and the tests pin all three sets. Model calls are at most 1 plus the distinct routed models, capped by `max_model_calls`.

The scripts it runs have their usual side effects, and the health check adds nothing to them: they overwrite their own Guardian context keys (`Guardian.SystemPrompt`, `Guardian.SkillBody`, `Guardian.Route`, `Guardian.Duplicate`, `Guardian.ModelChoiceCurrent`, `Guardian.ModelProfile`, `Guardian.Preflight.*`), and `GuardianToolBridge` and `GuardianModelChoice` write their normal audit rows. Run it in the Playground, or in an issue that has no Guardian run in progress.

Every check is isolated: an error in one is that check's FAIL with the error text, never the end of the report. The script never raises.

## Notes
---

- The tenant REST answers (the search results, the Lists, fields, types and layouts) are read in several shapes, and an answer in a shape the script does not know is reported as a WARN, not a FAIL. A search that does not return this very script is not trusted. A List that `getList` can read is never reported missing.
- Run it again after fixing a WARN or a FAIL. A tenant where the Core REST API integration is missing reports it once at the top and SKIPs or WARNs the checks that need it.
- The upgrade needs the changed `GuardianModelProfileCheck` (it gained the `read_only` argument) uploaded before the health check is used; an older copy saves the model profile, and the check says so.

## Outputs
---

`Guardian.HealthCheck` is overwritten on every run, keyed by `ts`.

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Guardian.HealthCheck.status | The overall result: `PASS`, `WARN` or `FAIL`. | String |
| Guardian.HealthCheck.pass / warn / fail / skip | The counts. | Number |
| Guardian.HealthCheck.failed | The names of the checks that failed. | Unknown |
| Guardian.HealthCheck.warned | The names of the checks that warned. | Unknown |
| Guardian.HealthCheck.ts | When the check ran (UTC). | String |
| Guardian.HealthCheck.edition | `cortex`. | String |
| Guardian.HealthCheck.seconds | How long the check took. | Number |
| Guardian.HealthCheck.model_calls | The model calls made. | Number |
| Guardian.HealthCheck.model_cost_usd | Their cost from `guardian_pricing`. | Number |

## Sample report
---

A tenant that works, with an extra automation, a routed model that is not in the catalogue and no XQL integration:

```
# Guardian health check (Cortex platform)

**Overall: WARN** -- 29 PASS, 3 WARN, 0 FAIL, 3 SKIP

## 1. Package content
- PASS Automations: all 81 present
- WARN Automations (extra): 1 not part of this pack: GuardianScratchPad
    - Likely cause: An item named Guardian* is on the server but is not part of this version of the pack (an older version, a copy or your own).
    - Fix: If it is a leftover of an older version, delete it; if it is yours, ignore this line.
- PASS Playbooks: all 21 present
- PASS Lists: all 27 present
- PASS Issue fields: all 15 present
- PASS Issue types: all 2 present
- PASS Layouts: all 2 present

## 2. Lists valid
- PASS JSON control lists: 16 of 16 parse and are the lists' own content
- PASS Settings, policy and approvals: settings, policy, preapproved, allowlist and denylist have their required keys
- PASS Allowlist against denylist: 64 allowed commands, none of them on the denylist
- PASS Skills index and routes: 11 skills indexed, each with its List; every route names an enabled skill
- WARN Routing models in the catalogue: not in guardian_model_catalog (their limits will be guessed): my-finetune-v2
    - Likely cause: A routed model is not in guardian_model_catalog, so Guardian guesses its limits (context window, tool support) and sizes the run for a small model.
    - Fix: Add the model to the catalogue (edit the pack's guardian_model_catalog file and upload it again) or probe it with !guardian-probe-model.
- PASS XQL templates: 9 templates, every {placeholder} is a declared parameter

## 3. Integrations
- PASS Model provider: lab-model (GuardianFoundry) is the one enabled provider
- PASS Provider health: no last error on the enabled provider
- PASS Core REST API: rest is enabled and answers
- PASS Provider integrations: all 3 provider integrations are uploaded
- WARN XQL query command: no enabled integration offers xdr-xql-generic-query; GuardianXQL is unavailable
    - Likely cause: No integration offers xdr-xql-generic-query, so GuardianXQL cannot run queries.
    - Fix: Add and enable the Cortex Core - XQL Query Engine (or Cortex XDR) integration instance if you want telemetry lookups; otherwise ignore this line.

## 4. Model
- PASS Model profile: size large (from catalogue (gpt-5-mini)), input budget 200000 tokens, tool budget 24000 tokens, turn limit 60
- PASS Model answers: gpt-5-mini answered OK; 0.0 s, 20 prompt + 2 answer tokens, cost $0.00001
- PASS Routed model gpt-5: 0.0 s, 20 prompt + 2 answer tokens, cost unknown (model not in guardian_pricing)
- PASS Routed model my-finetune-v2: 0.0 s, 20 prompt + 2 answer tokens, cost unknown (model not in guardian_pricing)
- PASS Model cost of this check: 3 call(s), 66 tokens, >= $0.00001 (a model is not in guardian_pricing)

## 5. Core scripts
- PASS Kill switch: GuardianKillSwitchCheck ran and returned a result
- PASS Job guard: GuardianJobGuardCheck ran and returned a result
- SKIP Route (GuardianIssueRoute): not inside an issue
- PASS Skill read: GuardianSkillRead ran and returned a result
- PASS Memory list: guardian_memory holds 0 row(s) and reads fine
- PASS Prompt builder: GuardianPromptBuilder ran and returned a result
- PASS Model choice: GuardianModelChoice ran and returned a result
- SKIP Duplicate check (GuardianIssueDuplicateCheck): not inside an issue
- PASS XQL templates (GuardianXQL template=list): GuardianXQL ran and returned a result
- SKIP XQL query: include_xql is false (no query was run)

## 6. Security gate
- PASS Allowed tool passes: GuardianSkillRead came back status=ok
- PASS Denylisted script is denied: GuardianModelChoice came back status=denied and was not run

## 7. Summary
- Overall: **WARN**. 29 PASS, 3 WARN, 0 FAIL, 3 SKIP.
- To fix, in this order:
    - WARN Automations (extra): If it is a leftover of an older version, delete it; if it is yours, ignore this line.
    - WARN Routing models in the catalogue: Add the model to the catalogue (edit the pack's guardian_model_catalog file and upload it again) or probe it with !guardian-probe-model.
    - WARN XQL query command: Add and enable the Cortex Core - XQL Query Engine (or Cortex XDR) integration instance if you want telemetry lookups; otherwise ignore this line.
- Model calls: 3, total model cost >= $0.00001 (a model is not in guardian_pricing). Time taken: 4.2 s.
```

## Command Example
```!GuardianHealthCheck```
