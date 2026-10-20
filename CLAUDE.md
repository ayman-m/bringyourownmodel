# Bring Your Own Model: Guardian

Guardian is an autonomous SOC-analyst agent that runs inside Cortex as content. A re-entrant reasoning loop drives a
Bring-Your-Own-Model LLM that selects native platform commands as tools, investigates incidents, and proposes actions.
Every action passes one security chokepoint (`GuardianToolBridge`): kill-switch, denylist, allowlist (default-deny),
policy tier, human approval (or a narrow pre-approved class), run, audit.

Two editions, kept apart:

| Edition | Content | Docs |
|---|---|---|
| Cortex XSOAR 6 | `Packs/Guardian` | `docs/xsoar/` |
| Cortex platform | `Packs/GuardianXSIAM` | `docs/cortex-platform/` |

Start with `README.md`, `docs/INSTALL.md` and `docs/OPERATOR_RUNBOOK.md`.

## Rules for this repository

This repository ships a final product. It is public.

1. **This is the only repository we work in.** The earlier private development repository is frozen. Nothing new is built
   there. The only reason to open it is to fetch something that was missed in the copy, or to check something against it.
2. **Nothing confidential, ever.** No customer names or customer data (tenant names, issue ids, hostnames, users), no
   secrets (keys, tokens, passwords, certificates, connection strings), no personal emails, no lab hosts or internal
   addresses. Test fixtures use obvious fakes, and a token-shaped fake is split in the source (`"xo" "xb-..."`) so that
   secret scanners do not flag it.
3. **Nothing a customer would not use.** No research notes, planning documents, evidence dumps, QA captures, old drafts,
   or agent and assistant configuration. If a file does not help someone install, run, operate or extend Guardian, it does
   not belong here.
4. **No debug leftovers in committed files.** No debug prints, commented-out code, temporary comments or TODO notes about
   work in progress. Comments explain why, and stay few. `demisto.debug` is operational logging and is fine.
5. **Debug and local testing live in `.local/`.** The folder is ignored by git. Put scratch scripts, test runs, tenant
   notes and the list of forbidden terms there. Nothing in `.local/` is ever added to a commit.
6. **Check before every push.** The pre-push check runs `gitleaks` and searches tracked files for every term listed in
   `.local/forbidden-terms.txt` (one regular expression per line; keep customer and personal names there, never in a
   tracked file). Install it once per clone:
   `ln -sf ../../scripts/pre-push.sh .git/hooks/pre-push`
7. **One history, clean.** Commit messages and pull requests follow the same rules as files.

## Conventions

- **No cross-script imports.** XSOAR automations cannot import each other. `Scripts/GuardianCommon/GuardianCommon.py`
  holds the shared `guardian_*` helpers inside the `# <GUARDIAN_COMMON>` block. `python3 scripts/inject_common.py` copies
  that block into every script's `# <GUARDIAN_COMMON_INJECT>` placeholder (`scripts/deploy.sh` runs it). Edit only the
  canonical block, then re-run the script.
- **Control-plane Lists are deploy-time only.** `guardian_settings`, `guardian_policy`, `guardian_preapproved`, the tool
  allowlist and denylist, persona and prompt lists are pack-seeded and read-only once installed. Change them by editing the
  JSON under `Lists/` and redeploying, never with a live `setList`.
- **Widening autonomy needs a code change** to `GUARDIAN_AUTO_APPROVABLE_COMMANDS` in `GuardianToolBridge.py` and a change
  to `guardian_preapproved`. Review changes to `GuardianToolBridge`, `guardian_policy`, the denylist,
  `GuardianContainmentSimulate` and `GuardianTriageApply` with extra care.
- **The model plane is provider-agnostic.** Everything talks to the model through the `guardian-llm-chat` command and the
  `Guardian.LLM.Completion` shape (`docs/GUARDIAN_LLM_CHAT_CONTRACT.md`). Enable one provider integration at a time.
- **Platform-neutral fixes go into both editions.** `Packs/GuardianXSIAM/DIVERGENCE.md` lists how they differ. Do not
  bring Cortex-platform-only patterns into the XSOAR 6 pack or the other way round.
- **Jobs are not created by a pack upload alone.** `scripts/deploy_jobs.py` creates them by name on XSOAR 6.

## Live tenants

Work against a tenant one call at a time: no parallel calls, at least a second between calls, no loops over bulk
endpoints, and stop at the first sign of trouble. Credentials come from a `.env` file at the repository root, which is
ignored by git (`.env.example` shows the shape). Never print or commit its contents.

## Dev workflow

```bash
bash scripts/deploy.sh        # inject_common, pack upload, jobs
python3 scripts/smoke.py      # post-deploy checks
```

Unit tests run per script directory, next to the script (`pytest` inside `Packs/<pack>/Scripts/<Name>/`).
`Tests/` holds the content tests.
