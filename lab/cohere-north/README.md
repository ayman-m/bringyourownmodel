# Guardian Cohere — self-hosted lab (real model behind Cohere North's wire contract)

Tests the **unchanged** `GuardianCohere` integration against the **exact API shape a production Cohere North
uses**, backed by a **real open-weights Cohere model** (Command R7B via Ollama on a GPU). Nothing in
the integration is modified — the lab presents North's *wire contract*; a middleware translates it to a
real model.

```
GuardianCohere (unchanged)  ──North API──▶  north_mock.py  ──/api/chat──▶  Ollama + command-r7b
  POST /api/v1/chat  {agent,conversation,messages,tools}     (stateful convo store,     (real Cohere model
  GET  /api/v1/conversations/{id}                             North-shaped I/O)          on an NVIDIA L4)
```

Why a middleware and not the real Cohere Toolkit: the open-source Toolkit's API is the *older* shape
(`message` string + flat `agent_id`/`conversation_id`, reply returned directly) — it does **not** match
the *commercial* North envelope (nested `agent:{id}`/`conversation:{id}` + `messages` array + poll
`/conversations/{id}`). So the Toolkit can't drive our North-targeted integration unchanged. `north_mock.py`
reproduces that envelope faithfully; the real model does the actual inference.

## Files
- **`north_mock.py`** — the North wire-contract middleware (stdlib only). `POST /api/v1/chat` +
  poll `GET /api/v1/conversations/{id}`, Bearer auth, nested `agent`/`conversation`, content-blocks,
  `tool_calls`, stateful conversation store. Translates to/from Ollama.
- **`drive.py`** — runs the real `GuardianCohere.py` command functions (test-module, simple turns, a
  full tool round-trip) in both `reuse` and `stateless` modes against the middleware.
- **`CommonServerPython.py` / `demistomock.py` / `CommonServerUserPython.py`** — a faithful XSOAR shim
  whose `BaseClient._http_request` does **real HTTP** with the exact kwargs the integration passes, so
  `GuardianCohere.py` runs verbatim off-platform.

## Provision the GPU VM (GCP)
Spot L4 is often stocked out; this used on-demand. Same VPC as `xsoar6` (`cortex-labs-vpc`), no external
IP (Cloud NAT provides egress), IAP for SSH.
```bash
gcloud compute instances create guardian-cohere-lab \
  --project=cortex-gcp-labs --zone=us-central1-c \
  --machine-type=g2-standard-4 \            # 4 vCPU / 16 GB + 1x NVIDIA L4 (24 GB)
  --maintenance-policy=TERMINATE \
  --network=cortex-labs-vpc --subnet=cortex-labs-vpc-us-subnet --no-address \
  --image-family=common-cu129-ubuntu-2204-nvidia-580 --image-project=deeplearning-platform-release \
  --boot-disk-size=100GB --boot-disk-type=pd-balanced \
  --metadata=install-nvidia-driver=True --labels=purpose=guardian-cohere-lab
# For Spot: add  --provisioning-model=SPOT --instance-termination-action=STOP  (retry zones on stockout)

# IAP SSH firewall (tag-scoped) + tag the VM:
gcloud compute firewall-rules create allow-iap-guardian-cohere-lab \
  --project=cortex-gcp-labs --network=cortex-labs-vpc --direction=INGRESS --action=ALLOW \
  --rules=tcp:22,tcp:8000 --source-ranges=35.235.240.0/20 --target-tags=guardian-cohere-lab
gcloud compute instances add-tags guardian-cohere-lab --zone=us-central1-c --tags=guardian-cohere-lab
```

## Bring up the model + middleware (on the VM)
```bash
gcloud compute ssh guardian-cohere-lab --zone=us-central1-c --tunnel-through-iap
# --- on the VM ---
curl -fsSL https://ollama.com/install.sh | sh          # auto-uses the L4
ollama pull command-r7b                                 # real Cohere small model (5.1 GB)
mkdir -p ~/lab   # then scp north_mock.py, drive.py, GuardianCohere.py, CommonServer*.py, demistomock.py here
# run the middleware as a detached transient unit (fully survives SSH exit):
sudo systemd-run --unit=north-mock --setenv=LAB_BEARER_TOKEN=lab-secret-token \
  --setenv=MODEL=command-r7b /usr/bin/python3 /home/$USER/lab/north_mock.py
curl -s -H "Authorization: Bearer lab-secret-token" http://127.0.0.1:8000/healthz
python3 ~/lab/drive.py                                   # runs the unchanged integration
```

## Results (2026-07-07)
Against `north_mock.py` + real model, the unchanged integration passed every path:
- `test-module` — reuse (read-only probe, no write to the shared conversation) + stateless (round-trip)
- reuse + stateless **simple turns** on **Command R7B** (real Cohere model)
- **tool round-trip** — `finish_reason=tool_calls` → tool result fed back → final answer
- baseline-count / new-reply **poll**, token accounting, content-block extraction

**Model note:** Command R7B validated all conversational paths, but its **Ollama build does not inject
tool schemas into the prompt** (it replies "I don't have access to any tools"), so the *tool-calls* path
was exercised with **`qwen2.5:7b`** (a reliable Ollama tool-caller) through the *same* middleware — the
integration + middleware are model-agnostic, so this validates the integration's tool handling, not a
specific model. The `Guardian.LLM.Completion.model` field is the configured display label (cosmetic), so
it reads `command-r7b` regardless of which model generated.

## Teardown / cost
**Sizing for command-r 35B (measured, 2026-10-06):** a single L4 (24 GB) holds the 4-bit weights (~21 GB) but only a 16K context, and Guardian's own prompt is 16.5K tokens on the small tier and ~23K on the medium tier: at 16K Ollama silently cuts the start of the prompt (half of it was lost) and the model drops its instructions. Use an **A100 40 GB** (`a2-highgpu-1g`, ≈ $3.67/hr, ~3x the generation speed: 31 vs 11 tokens/s) with `NUM_CTX=65536` (25 GB used) and declare the tier `medium` with `max_input_tokens` ≈ 56000 in the `guardian_model_profile` overrides. A100 capacity was out of stock in us-central1-a/b/c (zone f worked); a stopped VM keeps its disk.

On-demand `g2-standard-4` + L4 ≈ **$0.71/hr** while RUNNING. Stop when idle; delete when done:
```bash
gcloud compute instances stop   guardian-cohere-lab --zone=us-central1-c   # keep disk (~$1/mo), stop compute
gcloud compute instances start  guardian-cohere-lab --zone=us-central1-c   # resume later
gcloud compute instances delete guardian-cohere-lab --zone=us-central1-c   # remove entirely
gcloud compute firewall-rules delete allow-iap-guardian-cohere-lab --project=cortex-gcp-labs
```
