# Setting up the model provider

Guardian needs **one** model provider. It supports three: **Microsoft Foundry** (Azure), **Google Vertex AI** (Gemini) and **Cohere North** (a private, usually on-premises, deployment).
The steps are the same on Cortex XSOAR 6 and Cortex platform except where this page says otherwise (the main difference is where the integration runs: see "Where the integration runs").

| | Microsoft Foundry | Google Vertex AI | Cohere North |
|---|---|---|---|
| Integration | Guardian Foundry | Guardian Vertex (`provider = vertex`) | Guardian Cohere |
| Where the model is | Azure, in your Foundry resource | Google Cloud | Your own network |
| Sign-in | Resource key, **or** Microsoft Entra ID | Service-account JSON key | Bearer token |
| Needs an engine? | No (cloud endpoint) | No (cloud endpoint) | **Cortex platform: yes. XSOAR 6: only if the server cannot reach North** |
| Tested | Live, with a resource key, on both platforms | Used for the benchmark on XSOAR 6 | Against a middleware that reproduces North's wire contract, with a real open-weights model; not yet against a production North |

**Rules that apply to all three**
- Enable **exactly one** Guardian provider instance and disable the others. `!guardian-model` shows the one that is live.
- Add the instance at **Settings > Integrations** (XSOAR 6) or **Settings > Configurations > Integrations** (Cortex platform): search the integration name, **Add instance**, fill the fields below, press **Test**.
- The **Test** button proves the endpoint, the credentials and the model name. It does not prove your quota or the model's quality: run `!guardian-llm-chat user_message="Reply with the single word OK"` too.
- Never write keys or secrets into a file you share.

---

## Where the integration runs, and engines

The three integrations are Python integrations, so they run in Docker, either on the server (XSOAR 6) / tenant (Cortex platform) or on an **engine**. You choose with the instance's **Run on** field.

| Situation | What to do |
|---|---|
| Foundry or Vertex (public cloud endpoints), XSOAR 6 or Cortex platform | **No engine.** The server or tenant needs outbound HTTPS to the cloud endpoint. |
| Cohere North on a private network, **XSOAR 6** | If the XSOAR server can reach the North URL, **no engine**. If a firewall or proxy blocks it, put an engine on a host that can, and set **Run on** to it. |
| Cohere North on a private network, **Cortex platform** | **An engine is required.** A cloud tenant cannot reach your private network; run the instance on an engine inside it. (A Broker VM is not an integration runner; use an engine.) |

**Create an engine on XSOAR 6** (Cortex XSOAR 6 administrator guide, "Install a Cortex XSOAR engine")
1. Set the server's external address first: **Settings > About > Troubleshooting > Server Configuration** (the base URL).
2. **Settings > Integrations > Engines > Create New Engine**. Enter a name, pick the installer type (Shell on Linux is recommended; RPM/DEB and Zip also exist), and create it.
3. Run the installer on the host. Docker is required, and the shell installer installs it.
4. Network: the engine always connects **out** to the server's address and port (default TCP 443). It needs no inbound port unless you changed its own port. It must also reach the target (the North URL).
5. In the instance dialog set **Run on** to the engine.

**Create an engine on Cortex platform** (Cortex XSIAM administrator guide, "Install an engine" and "Engine requirements")
1. **Settings > Configurations > Data Broker > Engines > Create New Engine**. Choose the installer (Shell, DEB, RPM, Zip, or a `d1.conf` configuration file) and install it on the host.
2. Host: a supported Linux (Ubuntu 18.04 to 24.04, RHEL 8 to 10, Oracle Linux, Amazon Linux 2 or 2023, Rocky 9.5 or 9.6), x86_64, about 8 CPU / 16 GB / 100 GB for a development engine (16 CPU / 32 GB
   for production), Docker or Podman, the cron package and IPv4 forwarding. Natively running Python integrations on an engine is not supported: Docker (or Podman) is required.
3. Network is outbound only: the engine opens a WebSocket to your tenant's API host (`wss://api-<tenant>.../xsoar/d1ws`) on 443, and must reach the Docker registries on 443 to pull integration images
   (`registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com`, `docker.io`, `registry.docker.io`, `registry.fedoraproject.org`, `registry.access.redhat.com`). If your tenant restricts
   **Approved IP Ranges**, the engine must go out through one of them.
4. Confirm the engine shows as connected on the Engines page, then set the instance's **Run on** to it.

---

## Microsoft Foundry (Guardian Foundry)

### 1. In Azure
1. Create a Foundry resource (kind `AIServices`): Azure portal, create link `portal.azure.com/#create/Microsoft.CognitiveServicesAIFoundry`. Note the resource name.
2. In the Foundry portal: **Discover > Models**, choose a chat model, **Deploy**. The **deployment name** defaults to the model name and can be edited; it is the value Guardian sends as `model`.
   Reasoning models (for example `gpt-5-mini`, `o4-mini`) and non-reasoning models (for example `gpt-4o`) both work.
3. **Set the quota.** Each deployment has a tokens-per-minute (TPM) limit assigned when you create it (Manage > Quota > Token per minute, pencil icon, to change it). A Guardian turn is tens of thousands of
   tokens, so a small quota answers **HTTP 429**. In our tests `gpt-4o` at 10K TPM failed on a normal request and `gpt-5-mini` at 200K TPM worked. The estimate includes `max_tokens`.
4. **Get the endpoint.** Azure portal, your resource: **Overview** shows the Endpoint, and **Resource Management > Keys and Endpoint** lists it with the keys. Use the **resource endpoint**
   (`https://<resource>.services.ai.azure.com` or `https://<resource>.openai.azure.com`). Do **not** use the project endpoint (`.../api/projects/<name>`): that one is for the Foundry SDK and agents.
   Guardian calls `<endpoint>/openai/v1/chat/completions`, which needs no `api-version`.
5. **Choose how to sign in** (the customer's choice):
   - **Resource key:** copy **Key 1** from Keys and Endpoint.
   - **Microsoft Entra ID:**
     1. **Microsoft Entra ID > App registrations > New registration**; record the *Application (client) ID* and the *Directory (tenant) ID*. The registration also creates the app's service
        principal, listed under **Enterprise applications** with the same name; the role in step 3 is given to it. An existing app registration works the same way.
     2. Give the app **one** credential:
        - **Client secret** (`entra-client-credentials`): the app > **Certificates & secrets > Client secrets > New client secret**; copy the secret **Value** at once (it is not shown again; maximum lifetime 24 months).
        - **Certificate** (`entra-client-certificate`; no shared secret leaves Azure): the key must be **RSA** (Guardian signs with RS256). Use a certificate from your own PKI, or create a self-signed one:
          ```bash
          openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes -keyout guardian-foundry.key -out guardian-foundry.crt -subj "/CN=guardian-foundry"
          cat guardian-foundry.key guardian-foundry.crt > guardian-foundry.pem
          ```
          Upload the **public** certificate (`guardian-foundry.crt`) at the app > **Certificates & secrets > Certificates > Upload certificate**, and check that the thumbprint shown there matches
          `openssl x509 -in guardian-foundry.crt -noout -fingerprint -sha1` (ignore the colons). The combined `guardian-foundry.pem` (private key and certificate) goes into the Cortex instance; keep it out of email and tickets.
     3. Your Foundry resource > **Access control (IAM) > Add > Add role assignment**: give the app's service principal **Cognitive Services OpenAI User** (documented for the v1 chat API with OpenAI models). If calls still
        answer 401 or 403, assign **Cognitive Services User** (documented for any Foundry model) or **Foundry User** instead. Microsoft's pages name these three roles in different places, so use the
        smallest that works for your model. Wait up to five minutes after a role assignment.
     4. Entra sign-in **requires a custom subdomain** on the resource. A resource created in the Foundry portal normally has one; if yours does not, add it before using Entra.

### 2. In Cortex
| Field | Value |
|---|---|
| Name | for example `GuardianFoundry` |
| Endpoint | the resource endpoint from step 4 |
| Deployment name | the deployment name from step 2 |
| Authentication | **`api-key`** (recommended for a resource key; the key is sent in an `api-key` header), `bearer-key` (the same key sent as `Authorization: Bearer`; Microsoft's documentation does not say that every resource accepts it), **`entra-client-credentials`** (a service principal with a client secret), or **`entra-client-certificate`** (a service principal with a certificate) |
| API key | the resource key (`api-key` and `bearer-key` only) |
| Tenant ID, Client ID | the Entra values (both Entra types) |
| Client secret | `entra-client-credentials` only |
| Certificate and private key (PEM), passphrase, thumbprint | `entra-client-certificate` only. Paste the private key and the certificate as one PEM text, and upload the public certificate to the app registration. The passphrase is needed only for an encrypted key. The thumbprint is computed from the certificate, so enter it only when you paste the key alone. |
| Token scope | leave `https://ai.azure.com/.default` (the scope Microsoft documents); change it only if your resource rejects it |
| Model family | `auto` (reasoning models are detected from the name; set `reasoning` or `standard` to force it) |
| Parameters to omit | only if a deployment answers HTTP 400 to a parameter, for example `response_format,parallel_tool_calls` |
| Run on | no engine |

### 3. What must be true for it to work
- **Outbound HTTPS (443)** from the server or tenant to `<resource>.services.ai.azure.com` or `<resource>.openai.azure.com` and, for Entra, to `login.microsoftonline.com`.
- If the resource's **Network** setting is *Selected networks*, the egress IP of your server or tenant is in the allowed list; if it is *Disabled*, the resource is reachable only through a private endpoint.
- The deployment has enough TPM quota; the deployment name matches exactly.
- **Content filter:** Azure answers HTTP 400 (`content_filter`) to a prompt it blocks. Guardian retries the turn with a reworded request (`content_filter_retries`, default 2; 0 makes the block final) and then stops and asks a person.
- The Entra service principal has a role on the resource and a custom subdomain exists.

### 4. Check it
**Test** shows *Success*; then `!guardian-llm-chat user_message="Reply with the single word OK"` returns `OK` with the model name and token counts.

| Symptom | Likely cause |
|---|---|
| HTTP 401 or 403 | Wrong key; or Entra: missing role assignment (wait five minutes), wrong tenant or client id, no custom subdomain |
| HTTP 404 | Wrong deployment name, or the project endpoint was used |
| HTTP 429 | Quota too low for the deployment (raise TPM), or temporary capacity throttling |
| HTTP 400 `content_filter` | The provider blocked the prompt (see above) |
| HTTP 400 on a parameter | Add it to **Parameters to omit** |
| Timeout | Network path or private-endpoint DNS; raise nothing until the path is fixed |

---

## Google Vertex AI (Guardian Vertex)

Google now brands Vertex AI as the *Gemini Enterprise Agent Platform*; the API host and the role below are unchanged.

### 1. In Google Cloud
1. **Enable the API** `aiplatform.googleapis.com` on the project (API Library, or `gcloud services enable aiplatform.googleapis.com`). Billing must be on. Enabling needs Owner or Service Usage Admin.
2. **Create a service account** (IAM & Admin > Service accounts > Create) and grant it **`roles/aiplatform.user`** (Vertex AI User) on the project; it includes the `aiplatform.endpoints.predict` permission that prompts need.
3. **Create a JSON key:** Service accounts > the account > **Keys** > **Add key** > **Create new key** > **JSON**. Creating keys needs Service Account Key Admin. If the console says "Service account key creation is
   disabled", an organization policy (`iam.disableServiceAccountKeyCreation`) blocks it and an administrator must exempt the project.
4. **Pick a model and region.** Use a Gemini model that is generally available to your project and region (or `global`). Google's documentation lists `gemini-3.8-flash` and `gemini-3.5-flash` as current
   generally available models. **`gemini-2.5-flash` is scheduled to retire on 20 October 2026**, so do not start a new setup on it. We have not yet run Guardian on the 3.x models: run **Test** and
   `!guardian-probe-model` after you choose one.

### 2. In Cortex
| Field | Value |
|---|---|
| Provider | **`vertex`** |
| Model / deployment name | the Gemini model id, for example `gemini-3.8-flash` |
| Project ID | your GCP project id |
| Region | for example `us-central1`, `europe-west4`, or `global` (uses `aiplatform.googleapis.com`; any other value uses `<region>-aiplatform.googleapis.com`) |
| Service Account JSON | the full contents of the JSON key. Stored encrypted. Guardian signs a short-lived token (scope `https://www.googleapis.com/auth/cloud-platform`) for each session |
| Auth style / API key | leave the default; not used by `vertex` |
| Run on | no engine |

(The same integration also has the `openai-compatible` and `azure` provider modes for other servers; this guide covers `vertex`.)

### 3. What must be true for it to work
- Outbound HTTPS (443) to `oauth2.googleapis.com` (token) and `aiplatform.googleapis.com` or `<region>-aiplatform.googleapis.com`.
- The Vertex AI API is enabled, billing is on, the service account has `roles/aiplatform.user`, and the model is available in the chosen region.
- The integration runs the `demisto/googleapi-python3` Docker image. On an engine (not needed for Vertex) the engine would have to pull it.

### 4. Check it
**Test** shows *Success*; then `!guardian-llm-chat user_message="Reply with the single word OK"`.

| Symptom | Likely cause |
|---|---|
| 403 `PERMISSION_DENIED` | Missing `roles/aiplatform.user`, or the API is not enabled on that project |
| 404 model not found | The model id is wrong, retired, or not offered in that region (try `global`) |
| `invalid_grant` / token error | Malformed JSON key, a deleted key, or the server clock is wrong |
| 429 | Vertex quota for that model and region |

---

## Cohere North (Guardian Cohere)

Cohere North is a private deployment, usually on your own network, so the integration has to reach it from where it runs (see "Where the integration runs, and engines").

### 1. What you need from your North deployment
| Item | Where it goes |
|---|---|
| Base URL (for example `https://north.example.internal`, no path) | Endpoint URL. The integration appends `/api/v1/chat` and `/api/v1/conversations/{id}` |
| Agent id of the North agent that serves the model | Agent ID |
| A **pre-created conversation id** (only for `reuse` mode) | Session ID |
| An API bearer token | Bearer token |
| The size of the model behind the agent | Model size |

### 2. In Cortex
| Field | Value |
|---|---|
| Endpoint URL | the base URL |
| Agent ID | the agent id |
| Session ID | the pre-created conversation id (required in `reuse` mode; not used in `per_run` or `stateless`) |
| Bearer token | the token. Stored encrypted |
| Conversation mode | North keeps the whole history of a conversation and gives all of it to the model on every turn. `per_run` (recommended): one conversation per Guardian run, labelled with the incident (`Guardian run - incident 1234 - 2026-10-27 14:05`); a new run, also a re-run, gets a new conversation, and so does a run after Guardian compacts its transcript. `stateless`: a new conversation for every model call, which clutters North. `reuse` (the default of a new instance): one shared conversation for everything, so the model can answer from an earlier run; use it for one run at a time only. `per_run` and `stateless` need a North that accepts client-supplied conversation ids |
| Tool format | `openai` (default); `cohere` only for North builds that need Cohere-native tool definitions |
| Tool results | `native` (default); `text` when the turn after a tool call never gets a reply from North |
| Model label | cosmetic, shown by `!guardian-model` |
| **Model size** | Informational only; the default is `auto`, which declares nothing (the size comes from the model catalogue). Choose `small` (under 13B), `medium` (13B to 40B, for example Command R 32B) or `large` (over 40B) only to document a model that is not in the catalogue, and set the same value in `guardian_settings.model_tier`. A dropdown that differs from a catalogue-sized model gives one short note; `auto` never does |
| Request timeout | 200 seconds by default; North can be slow |
| Trust any certificate | leave off; if North uses an internal CA, add that CA to the server or engine trust store instead |
| **Run on** | **Cortex platform: the engine. XSOAR 6: no engine if the server can reach the URL, otherwise the engine** |

### 3. What must be true for it to work
- A **network path** from wherever the instance runs (the server, or the engine host) to the North URL on 443, and DNS that resolves the internal name there.
- A **valid TLS certificate** for the North host, trusted by the runtime.
- The agent id is configured in North and serves a chat model; in `reuse` mode the conversation id exists.
- The token is accepted. Docker is available on the engine host (and Docker registries are reachable from it, for the Cortex platform engine).
- Models in the medium class or above (13B and up, for example Command R at 32B) give much better investigations than 7B ones, which in our tests drifted on complex cases and often failed to converge.

### 4. Check it
**Test** does a read-only check in `reuse` mode (endpoint reachable, token accepted, session id resolves) and a one-turn round trip in `per_run` and `stateless` mode. Then `!guardian-llm-chat user_message="Reply with the single word OK"`,
`!guardian-probe-model`, and run the `GuardianModelAdaptation` job.

| Symptom | Likely cause |
|---|---|
| Timeout or connection error | No network path from where the instance runs; on Cortex platform the instance is not set to **Run on** the engine; the engine is offline |
| Certificate error | North's certificate is not trusted by the runtime |
| 401 or 403 | Wrong or expired token |
| "Session ID is required" | `reuse` mode without a Session ID |
| Interleaved or odd answers, or an answer that quotes another run | Several runs share the one conversation in `reuse` mode: switch to `per_run` |

**No North deployment to test with?** The repository's lab rig (`lab/cohere-north/`) runs a real open-weights model behind a small service that reproduces North's wire contract, so the integration can be tested end to end.

---

## After the provider works: model size and measurement

- **The model's size follows the model.** Every run looks the enabled model up in the model catalogue (`guardian_model_catalog`) and uses the size class it gives: `small` (under 13B total parameters), `medium` (13B to 40B) or `large` (over 40B; a closed hosted model whose size is not published, such as the GPT, Claude, Gemini and Grok families, counts as large). For a mixture-of-experts model the total parameter count is used. The size sets how many tools are offered, how much of a tool result the model sees, how much of the incident is pinned into the prompt and how the loop recovers from weak replies; the limits that scale with the input budget are derived from it (see the settings reference). Nothing is stored for this: the lookup is done on every run, so a profile record written earlier gets its size with no rewrite.
- **The turn limit follows the size too.** A run is made to conclude after 25 turns for a small model, 40 for a medium one and 60 for a large one (small models degrade on long transcripts). `MAX_TICKS` is not set in `guardian_settings`; set a number there only to give every model the same limit, or set `max_ticks` under `overrides` in `guardian_model_profile` (no redeploy). `!guardian-model` shows the limit and where it came from. At about 40 seconds a turn, 60 turns take about 40 minutes; the polling window of the self-rescheduling loop is sized from the limit.
- **Only a model that is NOT in the catalogue needs a declared size.** `guardian_settings.model_tier` ships as `auto`, which means "take it from the catalogue"; an unknown model is treated as `small`. For such a model set `model_tier` to `medium` (13B to 40B) or `large` (over 40B) in the `guardian_settings` list: edit `Lists/list-guardian_settings.json` inside the pack zip (its
  `data` field is a JSON string, so keep the escaping), then install the pack again. To force a size for any model, including one in the catalogue, set `overrides` in the `guardian_model_profile` list, which you can change without reinstalling: `!setList listName=guardian_model_profile listData=`{"overrides":{"model_tier":"medium"}}``. An explicit `model_tier` in `guardian_settings` is not used for a model the catalogue knows: `!guardian-model` and the "Resolve model profile" task say so in one line. The instance's **Model size** field is informational only.
- **Serve the model with a large enough context window.** Guardian's fixed prompt (system prompt, task and tool list) is about 17,000 tokens on the small tier and about 23,000 on the medium tier, before any conversation. A window of 16K cannot hold it: the serving layer cuts the start of the prompt without telling Guardian, and the model loses its instructions. Serve at least 32K for a small model and 64K for a medium one, and set `max_input_tokens` (in `overrides`, or let the probe measure it) a few thousand tokens below the served window. `!guardian-probe-model` records a window below about 20,000 tokens but the profile job refuses to save it unless forced.
- A model that proposes several tool calls in one turn skips steps and writes notes before it has the results. For such models set `max_tool_calls_per_turn` to 1 in `overrides`: Guardian runs the first call and tells the model the rest were not run.
- **Known models get their documented limits automatically.** Guardian ships a model catalogue, the `guardian_model_catalog` list (checked 2026-10-09): the published context limits of about 150 commonly used models, with the cloud provider's own cap where it differs from the vendor's (gpt-4.1 is limited to 300,000 tokens on Azure although the vendor documents 1,000,000). When the enabled model is in the catalogue and needs no probe, the "Resolve model profile" task at the start of each run saves a `documented` profile for it, so there is no command to run and no Job is needed. The input budget is the documented usable input limit, times 0.85, scaled for an assumed 3.0 characters per token (SOC content is JSON-heavy; a probe replaces the assumption with the measured ratio). `!guardian-model` shows where each figure comes from: documented (with the catalogue date), confirmed, measured, quota or override.
- **Frontier models are not probed.** For OpenAI's closed models, Anthropic, Google Gemini and xAI the documented limits are used. `!guardian-probe-model` then measures only the characters per token and the tool and structured-output checks, and reports "no window probe needed (documented)". Add `force=true` to search the window anyway.
- **The probe confirms open-weight and self-hosted models.** The window such a model is served with depends on the runtime (the Ollama context setting, the vLLM maximum length), so it never gets an automatic profile: run `!guardian-probe-model`, then `!GuardianModelProfileUpdate` (the `GuardianModelAdaptation` job does both daily). The probe searches up to the documented usable input limit and applies the 20% rule. A measured window of at least 80% of the documented limit is **confirmed** and the documented limit is used. A window more than 20% below it is **measured**: the measured figure is used and the report gives the evidence, for example "past 60000 tokens the first response took 41.2 s, above the acceptable 30 s". If the probe stops on a quota error (HTTP 429, tokens per minute), the documented limit is kept and the report says the window was not reached. A first response counts as too slow only when it takes longer than the model's own small-prompt time plus the latency budget, so a reasoning model's fixed thinking delay is not counted as slowness. The probe asks for a one-word answer at the lowest reasoning effort.
- **A model that is not in the catalogue** is probed from scratch, as before, up to 131,072 tokens; if the report says "at ceiling", raise it with `max_probe_tokens`. The catalogue is pack data: to add or change a model, edit `docs/reference/model-catalog/model_catalog.json`, run `python3 scripts/build_model_catalog.py` (it regenerates `Lists/list-guardian_model_catalog.json` in both packs; do not hand-edit that file) and install the pack again.
- **Optional cap.** There is no default cap on a very large window. If one makes runs too slow or too costly, add `max_input_tokens_cap` to `guardian_settings` (edit `Lists/list-guardian_settings.json` and install the pack again): no saved input budget will exceed it. It is unset by default.
- The rest is measured: for an unlisted or open-weight model run `!guardian-probe-model`, then run the `GuardianModelAdaptation` job once (it then refreshes daily). `!guardian-model` shows the live provider, deployment, size and the budgets in force.
- Foundry cost shows USD 0.00 until a row for your deployment is added to the `guardian_pricing` list; tokens are counted correctly.
- Provider test commands (plain chat, tool-call request, structured output, timeout) are in the guide (`GUARDIAN_GUIDE.md`, section 10).

## Sources

Checked against: Microsoft Learn (Foundry resource and deployment, the OpenAI v1 API and its key and Entra authentication, role-based access, quota, private link, content filter); Microsoft Entra
(register an app, add a client secret, the client-credentials flow); Google Cloud (enable the API, the Vertex AI User role, service-account keys and the key-creation organization policy, the
OAuth service-account flow, Gemini model lifecycle); and the Cortex XSOAR 6 and Cortex XSIAM administrator guides (engines: install, requirements, networking). Menu names can differ between versions.
