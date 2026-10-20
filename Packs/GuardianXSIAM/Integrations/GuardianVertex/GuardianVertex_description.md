## Guardian Vertex Help

Guardian Vertex is the **model plane** for the Guardian agent: a provider-generic Bring-Your-Own-Inference
(BYOI) integration that every Guardian reasoning tick calls (`guardian-llm-chat`) to get a chat
completion. It is **not** tied to any single vendor — the OpenAI Chat-Completions wire format is
treated as the canonical shape, and a small provider-adapter layer translates to/from whichever
backend you point it at.

### Supported providers

- **openai-compatible** (default) — any server that speaks the plain OpenAI Chat Completions API:
  OpenAI itself, a self-hosted vLLM/TGI server, Ollama's OpenAI-compat endpoint, LiteLLM, etc.
  - **Base URL**: the server root, e.g. `https://api.openai.com` or `http://my-vllm-host:8000`.
    You may include a trailing `/v1` or not — the integration appends `/chat/completions` (or
    `/v1/chat/completions` if you didn't already include `/v1`).
  - **Auth style**: `bearer` sends `Authorization: Bearer <API Key>` (the OpenAI-standard style).
    `api-key` sends an `api-key: <API Key>` header instead, for OpenAI-compatible servers that use
    that convention.
- **azure** — an Azure OpenAI deployment.
  - **Base URL**: the resource endpoint only, e.g. `https://<resource>.openai.azure.com` (no path).
  - **Model / deployment name**: your Azure **deployment name** (not necessarily the underlying
    model name).
  - **API version**: the Azure OpenAI `api-version` query parameter (defaults to `2024-10-21`;
    override if your deployment requires a different one).
  - **Auth style**: `api-key` sends Azure's native `api-key: <API Key>` header. `entra-token` sends
    `Authorization: Bearer <token>`, where the configured API Key field holds a **pre-acquired**
    Entra ID (AAD) access token rather than a static key — token acquisition/refresh is out of
    scope for this integration.
  - Azure-side content-filter rejections (both a blocked prompt returned as HTTP 400, and a blocked
    completion signalled by `finish_reason: "content_filter"`) are surfaced as a structured,
    non-silent result (`Guardian.LLM.Completion.content_filter = true`) rather than a generic error
    or a silently empty completion.
- **vertex** — Google Vertex AI's Gemini models (e.g. `gemini-2.5-flash`, `gemini-2.5-pro`), called
  via the `generateContent` API.
  - **Project ID**: the GCP project with Vertex AI / Gemini access.
  - **Region**: the Vertex AI region, e.g. `us-central1` (default) or `europe-west4`, or the literal
    string `global` to use the global `aiplatform.googleapis.com` endpoint instead of a regional one.
  - **Model / deployment name**: the Gemini model name, e.g. `gemini-2.5-flash`.
  - **Service Account JSON**: the full GCP service-account JSON key, granted `roles/aiplatform.user`.
    A short-lived OAuth2 access token (scope `https://www.googleapis.com/auth/cloud-platform`) is
    minted from this key for every call — there is no static API key for this provider, and
    **Base URL / Auth style / API Key / API version are all ignored**.
  - Requests are translated from the canonical OpenAI messages/tools/tool_choice shape into
    Gemini's `contents`/`systemInstruction`/`tools`/`toolConfig`/`generationConfig` shape, and
    responses are translated back the same way every other provider's are — the rest of Guardian
    never has to know it's talking to Gemini.
  - Gemini-side content-filtering — either the prompt itself blocked pre-generation
    (`promptFeedback.blockReason`) or a candidate blocked post-generation
    (`finishReason` of `SAFETY`/`PROHIBITED_CONTENT`/`BLOCKLIST`) — is surfaced the same
    non-silent way as Azure's: `Guardian.LLM.Completion.content_filter = true` with a structured
    detail, never a generic error or a silently empty completion.

### Getting an API key

- **OpenAI**: create a key at https://platform.openai.com/api-keys.
- **Azure OpenAI**: use a key from your Azure OpenAI resource's "Keys and Endpoint" blade, or an
  Entra ID access token scoped to `https://cognitiveservices.azure.com/.default` if using
  `entra-token`.
- **Vertex AI**: create a service account in the target GCP project, grant it
  `roles/aiplatform.user`, and download a JSON key for it (IAM & Admin → Service Accounts →
  Keys → Add Key → JSON). Paste the entire JSON file's contents into the Service Account JSON
  field.
- **Self-hosted (vLLM/TGI/Ollama/etc.)**: use whatever bearer token (if any) your deployment
  requires; leave the API Key field blank for servers with no auth in front of them.

### Adding another provider

The adapter layer is designed to be extended with one class per provider. See the module
docstring at the top of `GuardianVertex.py` for the exact extension points
(`build_url`/`build_params`/`build_headers`/`build_request_body`/`normalize_response`/
`handle_input_content_filter`), then register the new adapter in `ADAPTERS_BY_PROVIDER` and add its
name to the `provider` configuration dropdown.

### Output shape

Regardless of provider, `guardian-llm-chat` always returns the same normalized shape under
`Guardian.LLM.Completion`: `choices` (with `message.content` / `message.tool_calls` /
`finish_reason`), a top-level normalized `finish_reason`, a `content_filter` boolean, and `usage`
(including a normalized `cached_tokens` count where the provider reports one).
