# Guardian for Cortex platform — operator runbook

For the XSOAR 6 edition see [`OPERATOR_RUNBOOK.md`](OPERATOR_RUNBOOK.md). This edition is `Packs/GuardianXSIAM`; the differences are
in [`Packs/GuardianXSIAM/DIVERGENCE.md`](../Packs/GuardianXSIAM/DIVERGENCE.md).

## 1. Install
1. Install the pack: console **Upload pack** with the release `GuardianXSIAM.zip`, or
   `demisto-sdk upload -i Packs/GuardianXSIAM -x -z --skip_validation --override-existing` with a **Standard** API key
   (`DEMISTO_BASE_URL`, `DEMISTO_API_KEY`, `XSIAM_AUTH_ID`). Run the SDK from a directory without a `.env` that points elsewhere
   (`lab/tools/deploy_xsiam_pack.sh` does this).
2. **Adopt the playbooks.** A pack install leaves the nine Guardian playbooks "not adopted"; attaching one to an issue or running
   it from a Job then fails with *playbook is not adopted*. Detach each playbook and save it again (the YAML carries
   `adopted: true`), or run `python3 lab/tools/xsiam_adopt_playbooks.py` against your tenant.
3. Dashboards and widgets are not installed by Cortex platform; the SOC Agent layouts and incident fields are.
4. Run `!GuardianBootstrap` once (from an issue's War Room) to create the runtime lists.

## 2. The model
Configure **Guardian Cohere** or **Guardian Vertex** exactly as in the XSOAR runbook. A cloud tenant cannot reach a model on a private
network: run the instance on an **engine** that can (`lab/tools/xsiam_instance.py` shows the REST shape). Check it with
`!guardian-model`, then `!guardian-probe-model`.

The model size follows the model: it is read from the model catalogue on every run, and so is the turn limit per run (25 small, 40 medium, 60 large; `max_ticks` under `overrides` in `guardian_model_profile` changes it). Set `guardian_settings.model_tier` (pack-seeded, so redeploy to change it) only for a model that is not in the catalogue, and let the daily
**GuardianModelAdaptation** job measure the context budget into `guardian_model_profile` (see the XSOAR runbook, "Match Guardian to
your model"). Start one run by hand first.

## 3. Jobs
Create the six Jobs by hand (Settings → Jobs) from `Packs/GuardianXSIAM/Jobs/job-*.json`; the type is the platform default. A Job run
is a `job-<id>` investigation with no issue attached. **Do not enable `GuardianIntakeSweep` on a tenant you do not want triaged
by a model**: it reads the real issue queue. To run a playbook once without a schedule, create a Job that fires once, then delete it
(`lab/tools/xsiam_oneshot_job.py`).

## 4. Running an investigation
- On an existing issue: attach the playbook (`!setPlaybook name=GuardianEvalInvestigate` in the issue's War Room, or an automation
  rule). Always run the loop through its playbook: a bare War Room command re-runs only every 75-120 s and its chain dies at the
  first timeout.
- Scheduled: the `GuardianIntakeSweep` Job runs `GuardianAgentLoop` and triages the queue read-only.
- The agent writes `guardianverdict`, `guardianconfidence`, `guardianattacktechniques`, `guardiantickcount` and `guardiancostusd`
  onto the issue it investigates (not on a Job run, which has no issue).

## 5. What the agent can do here
Same bridge as the XSOAR edition: kill switch, denylist, default-deny allowlist, policy, approval, audit. Cortex platform-native reads
(`core-get-issues`, `core-get-cases`, `core-get-endpoints`, `core-list-risky-hosts/users`, `xdr-xql-generic-query`) are offered; every
other `core-*` / `xdr-*` command that is not a read is both absent from the allowlist and `require_approval` in the policy, and shown
at the destructive tier if an operator ever allowlists one. `core-api-*` and `demisto-api-*` are denied.

## 6. Known limits
- The stalled-run watchdog only sees runs that have an issue.
- A tick takes about 20 s between turns inside a playbook; an investigation of 4-6 ticks takes a few minutes.
- No pre-process rule (it never fires on Cortex platform), no dashboard.
