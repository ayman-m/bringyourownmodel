Provider-generic Bring-Your-Own-Inference (BYOI) model-plane integration for the Guardian agent. Every Guardian reasoning tick calls the guardian-llm-chat command, which talks to any OpenAI Chat-Completions-compatible endpoint (self-hosted vLLM/TGI/Ollama, OpenAI itself, or Azure OpenAI), or to Google Vertex AI's Gemini models, through a small provider-adapter layer and normalizes every response to the canonical OpenAI Chat-Completions shape, so the rest of Guardian never has to branch on which provider is configured.
This integration was integrated and tested with Guardian Vertex.

## Configure Guardian Vertex in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Provider | Selects the provider adapter. "openai-compatible" targets any server that speaks the plain OpenAI Chat Completions wire format \(OpenAI itself, vLLM, TGI, Ollama's OpenAI-compat endpoint, LiteLLM, etc\). "azure" targets Azure OpenAI deployments \(adds the api-version query parameter, the /openai/deployments/&lt;model&gt;/chat/completions URL shape, and content-filter detection\). "vertex" targets Google Vertex AI's Gemini models \(generateContent API, service-account OAuth2 auth, and Gemini request/response translation — see Project ID / Region / Service Account JSON below\). See the integration description for how to add another provider adapter. | True |
| Base URL | For provider=openai-compatible: the server root, e.g. https://api.openai.com or http://localhost:8000 — the adapter appends /v1/chat/completions \(or just /chat/completions if the URL you give already ends in /v1\). For provider=azure: the resource endpoint, e.g. https://&lt;resource&gt;.openai.azure.com \(no path suffix\). Ignored for provider=vertex \(the endpoint is derived from Project ID / Region instead\). | False |
| Model / deployment name | The model name \(openai-compatible\), the Azure deployment name \(azure\), or the Gemini model name \(vertex\), e.g. gemini-2.5-flash or gemini-2.5-pro. | True |
| API version (Azure only) | Azure OpenAI api-version query parameter. Ignored by the openai-compatible and vertex providers. | False |
| Project ID (Vertex only) | GCP project ID with Vertex AI / Gemini access. Required for provider=vertex; ignored by the other providers. | False |
| Region (Vertex only) | Vertex AI region, e.g. us-central1, europe-west4, or "global" \(uses the global aiplatform.googleapis.com endpoint instead of a regional one\). Only used for provider=vertex. | False |
| Service Account JSON (Vertex only) | The full GCP service-account JSON key \(granted roles/aiplatform.user\) used to mint a short-lived OAuth2 access token for Vertex AI calls. Required for provider=vertex; stored encrypted; ignored by the other providers. | False |
| Auth style | How the credential below is sent. "bearer": Authorization: Bearer &lt;key&gt; \(OpenAI and most OpenAI-compatible servers\). "api-key": api-key: &lt;key&gt; header \(Azure OpenAI's native key style\). "entra-token": Authorization: Bearer &lt;token&gt;, where the credential is a pre-acquired Entra ID / AAD access token rather than a static API key \(Azure only\). | True |
| API Key | The API key \(or Entra ID token, if Auth style = entra-token\). Stored encrypted. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### guardian-llm-chat

***
Provider-independent chat completion. Sends OpenAI-Chat-Completions-shaped messages (and optional tool definitions / structured-output schema) through the configured provider adapter, and returns a normalized completion under Guardian.LLM.Completion regardless of which provider served the request.

#### Base Command

`guardian-llm-chat`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| messages | JSON array of OpenAI Chat-Completions message objects, e.g. [{"role":"system","content":"..."},{"role":"user","content":"..."}]. Supports the full message shape including "name", "tool_call_id", and assistant "tool_calls". | Required | 
| tools | JSON array of OpenAI "tools" (function) definitions to make available for tool/function calling, e.g. [{"type":"function","function":{"name":"...","parameters":{...}}}]. | Optional | 
| tool_choice | Either a plain string ("auto" \| "none" \| "required") or a JSON object selecting one specific tool, e.g. {"type":"function","function":{"name":"my_tool"}}. | Optional | 
| response_format | JSON object requesting structured output, e.g. {"type":"json_object"} or {"type":"json_schema","json_schema":{...}}. Only honored if the configured model/provider supports structured outputs; unsupported providers will surface the provider's own error. | Optional | 
| temperature | Sampling temperature (provider-dependent range, typically 0-2). | Optional | 
| reasoning_effort | Reasoning effort hint for reasoning-capable models: low \| medium \| high. Possible values are: low, medium, high. | Optional | 
| parallel_tool_calls | Whether the model may return multiple tool calls in one response (true/false). Possible values are: true, false. | Optional | 
| model | Run this call on another model than the instance's configured one: the Gemini model id (Vertex), the deployment name (Azure) or the model name (an OpenAI-compatible server). Empty uses the configured model. A model the provider does not know gives an error that starts with `MODEL_NOT_AVAILABLE:`. | Optional | 

#### Command Example

```
!guardian-llm-chat messages=`[{"role":"user","content":"say hi in exactly two words"}]`
!guardian-llm-chat messages=`[{"role":"system","content":"You are a SOC analyst assistant."},{"role":"user","content":"Summarize this alert."}]` temperature=0.2
!guardian-llm-chat messages=`[{"role":"user","content":"What is the reputation of 8.8.8.8?"}]` tools=`[{"type":"function","function":{"name":"ip_reputation","description":"Look up IP reputation","parameters":{"type":"object","properties":{"ip":{"type":"string"}},"required":["ip"]}}}]` tool_choice=auto
!guardian-llm-chat messages=`[{"role":"user","content":"Return the verdict as JSON."}]` response_format=`{"type":"json_object"}`
```

Note: these examples are illustrative only (see `command_examples.txt`), not live-captured output.
The command itself is provider-independent — the same `guardian-llm-chat` arguments are sent
regardless of which `provider` (openai-compatible / azure / vertex) the instance is configured
with. Run `test-module` and a `guardian-llm-chat` call against your own endpoint to see real output.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Guardian.LLM.Completion.id | String | Provider-assigned completion id \(null for a request blocked by a content filter before generation\). | 
| Guardian.LLM.Completion.model | String | Model \(or deployment\) that served the request. | 
| Guardian.LLM.Completion.created | Number | Unix timestamp of the completion, as reported by the provider. | 
| Guardian.LLM.Completion.choices.index | Number | Choice index. | 
| Guardian.LLM.Completion.choices.message.role | String | Role of the returned message \(normally "assistant"\). | 
| Guardian.LLM.Completion.choices.message.content | String | Text content of the returned message \(may be null when only tool_calls are returned\). | 
| Guardian.LLM.Completion.choices.message.tool_calls | Unknown | Tool/function calls requested by the model, in OpenAI tool_calls shape. | 
| Guardian.LLM.Completion.choices.finish_reason | String | Per-choice normalized finish reason: stop | length | tool_calls | content_filter | other provider-reported values. | 
| Guardian.LLM.Completion.finish_reason | String | Normalized finish reason of the first choice, surfaced at the top level for convenience. | 
| Guardian.LLM.Completion.content_filter | Boolean | True if this request or response was blocked/flagged by the provider's content filter. | 
| Guardian.LLM.Completion.content_filter_detail | Unknown | Structured detail \(message, raw provider error\) when content_filter is true and the block happened on the input \(pre-generation\) side. | 
| Guardian.LLM.Completion.usage.prompt_tokens | Number | Prompt tokens billed for the request. | 
| Guardian.LLM.Completion.usage.completion_tokens | Number | Completion tokens billed for the request. | 
| Guardian.LLM.Completion.usage.total_tokens | Number | Total tokens billed for the request. | 
| Guardian.LLM.Completion.usage.cached_tokens | Number | Cached prompt-token count, when the provider reports one \(e.g. OpenAI prompt_tokens_details.cached_tokens\); null otherwise. | 
