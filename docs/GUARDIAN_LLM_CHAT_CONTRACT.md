# The `guardian-llm-chat` contract — the model-plane interface

Guardian's design decouples the *choice of model provider* from everything else. All the reasoning
content (the tick, prompt builder, tool-catalogue builder, compaction, cost ledger, slash commands,
subagents) is **provider- and integration-agnostic**: it only ever calls the **`guardian-llm-chat`**
command and reads its normalized output. It never references a provider integration by name.

Each model provider ships as its **own Guardian integration** — today `Guardian Vertex` (Gemini via
Vertex) `Guardian Cohere` (a private Cohere North deployment) and `Guardian Foundry` (Microsoft Foundry, OpenAI-compatible v1 API), with `Guardian Claude` etc. to
follow. Their internal code and instance parameters are completely different (Vertex mints an OAuth2
token per call and hits `generateContent`; Cohere North uses a Bearer token, a two-hop
`POST /api/v1/chat` + poll `GET /api/v1/conversations/{id}` protocol, and a configured agent id +
session/conversation id), but **every one of them MUST implement the `guardian-llm-chat` command below,
identically.** That is the only thing the rest of the pack depends on.

> **Rule:** exactly one Guardian provider integration is *enabled* at a time (they all provide the same
> command, so XSOAR routes `guardian-llm-chat` to the enabled one). Enable the provider you want; disable
> the rest. `!guardian-model` shows which provider/model is live (it discovers providers by this command,
> not by brand).

---

## Command: `guardian-llm-chat`

**Name (exact):** `guardian-llm-chat` — never change it; it is the contract key.

### Arguments (name, required, meaning — identical across all provider integrations)

| Arg | Req | Meaning |
|---|---|---|
| `messages` | conditional | JSON array of OpenAI-shaped chat messages (`{role, content, tool_calls?, tool_call_id?}`). The orchestrator owns the full transcript and passes it every turn. Required unless `user_message` is given instead. |
| `system_message` | no | Convenience alternative to `messages`, for one interactive turn (e.g. testing from the Playground) without hand-formatting a JSON array. Optional system-role text; mutually exclusive with `messages`. |
| `user_message` | conditional | Convenience alternative to `messages`: the user-role text for one turn. Required if `messages` is not given; combined with `system_message` (if set) into a two-message array. Mutually exclusive with `messages`. |
| `tools` | no | JSON array of OpenAI function-tool defs (`{"type":"function","function":{name,description,parameters}}`). |
| `tool_choice` | no | `auto` \| `required` \| `none` (OpenAI semantics). |
| `response_format` | no | Structured-output request (OpenAI `json_schema` shape) when the provider supports it. |
| `temperature` | no | Sampling temperature (provider-dependent range). |
| `reasoning_effort` | no | `low` \| `medium` \| `high` — hint for reasoning-capable models. |
| `parallel_tool_calls` | no | `true`/`false` — may the model emit multiple tool calls in one turn. |
| `timeout` | no | Per-call time limit in seconds (see below). |
| `model` | no | Run this call on another model than the instance's configured one (see below). |

**`timeout` is a hard bound, and every integration MUST honor it.** When given, the whole call —
every HTTP step it makes, including a submit-then-poll flow like North's — finishes or fails within
`min(timeout, the instance's request timeout)` seconds, with **no transparent retries** (a retry would
silently extend the bound). The failure is an ordinary error entry whose text contains "timeout".
When omitted, the call behaves exactly as before: the instance's own timeout per step, with the
integration's normal retry policy. Callers with their own wall-clock budget use it — today
`GuardianProbeModel`, so one slow call can't outlive XSOAR's script timeout. It is a transport bound,
never sent to the provider.

**`model` is optional, and empty or absent means the instance's configured model, exactly as before.** When given
and different from the configured one, the call runs on that model, and `Guardian.LLM.Completion.model` reports the model
that served it. Only the caller that routes models passes it (today `GuardianReasoningTick`, when the operator set
`guardian_model_routing`). The value is the provider's own name for the model:

| Provider | `model` means | Unknown model |
|---|---|---|
| Foundry | the deployment name, sent as the request's `model`; the model family ("auto") is decided from this name | error text starting `MODEL_NOT_AVAILABLE:` (HTTP 404 `DeploymentNotFound`, or an HTTP 400 that names the model or deployment) |
| Vertex | the Gemini model id, built into the request URL (an Azure instance: the deployment name; an OpenAI-compatible server: the model name) | error text starting `MODEL_NOT_AVAILABLE:` |
| Cohere North | cannot be chosen per call: the agent is fixed. Empty, or equal to the instance's Model label, is accepted | error text starting `MODEL_SELECTION_UNSUPPORTED:` for any other value, with no call made |

A caller that routes models treats both prefixes as "use the instance default instead" and carries on; they are
ordinary error entries, so they are matched on the start of their text.

Each integration translates these to/from its provider's native wire format internally (e.g. the Vertex
integration maps `messages`→Gemini `contents`, `tools`→`functionDeclarations`, `tool_calls`↔`functionCall`).

**`messages` vs. `system_message`/`user_message` — pick one, not both.** `messages` is what every
production caller (`GuardianReasoningTick`, `GuardianCompact`, `GuardianCompactCommand`,
`GuardianPlanCommand`, `GuardianSubagentDispatch`, `GuardianProbeModel`) uses — the orchestrator already
owns the full transcript as a JSON array, so building it there costs nothing extra. `system_message` /
`user_message` exist purely so an operator testing from the Playground can run
`!guardian-llm-chat user_message="hi"` directly, without hand-formatting JSON for a single turn. The two
shapes are mutually exclusive by design, not by convention: supplying both raises
`Provide either "messages", or "system_message"/"user_message" -- not both.` rather than silently
preferring one — an operator who supplies both by mistake should see why, not get a transcript built
from whichever branch happened to win. Supplying neither (no `messages` and no `user_message`) raises
the equivalent "provide one or the other" error. Every provider integration MUST implement this
resolution identically (see `_resolve_messages()` in `GuardianVertex.py` / `GuardianCohere.py`), the same
requirement that already applies to the rest of this contract.

### Output — `Guardian.LLM.Completion` (normalized OpenAI Chat-Completions shape)

The integration MUST normalize the provider's response to this exact context structure:

| Context path | Meaning |
|---|---|
| `Guardian.LLM.Completion.id` | provider completion id (null if content-filtered pre-generation) |
| `.model` | model/deployment that served the request |
| `.created` | provider Unix timestamp |
| `.choices[].index` | choice index |
| `.choices[].message.role` | normally `assistant` |
| `.choices[].message.content` | text (may be null when only tool_calls returned) |
| `.choices[].message.tool_calls` | OpenAI `tool_calls` shape (`{id, type:"function", function:{name, arguments}}`) |
| `.choices[].finish_reason` | normalized: `stop` \| `length` \| `tool_calls` \| `content_filter` \| … |
| `.finish_reason` | first choice's finish_reason, surfaced top-level |
| `.content_filter` | **bool** — true if the provider blocked/flagged input or output |
| `.content_filter_detail` | structured detail when an input-side block occurred |
| `.usage.prompt_tokens` / `.usage.completion_tokens` | billed tokens (add `total_tokens` / cached-token count where the provider reports them) |

### Behavioral requirements (all providers)

- **Never raise on a provider error** — return a structured result the caller can inspect (the tick reads
  the completion from the `executeCommand` response `Contents`).
- **Content filtering is non-silent** — if the provider filters, set `content_filter: true` and surface
  detail; never drop silently. Escalation is the orchestrator's job.
- **`test-module`** — a minimal 1-token completion that proves the instance's credentials/endpoint work.
- Retry on transient/429 with backoff; honor the system proxy; keep secrets in type-4 encrypted params.

---

## Adding a new provider (e.g. Guardian Claude)

1. Scaffold a new integration `Packs/Guardian/Integrations/GuardianClaude/` (its own `.py`/`.yml`/image),
   `id`/`name` `GuardianClaude`, `display` `Guardian Claude`.
2. Implement the `guardian-llm-chat` command **exactly** per this doc (same args, same
   `Guardian.LLM.Completion` output), translating to/from Anthropic's Messages API internally, with its
   own instance params (`api_key`, `model`, `base_url`, …).
3. Deploy, create an instance, **enable only that provider** (disable the others). Nothing else in the
   pack changes — the tick and all content route `guardian-llm-chat` to it automatically.
4. `!guardian-model` will list it (it discovers any integration offering `guardian-llm-chat`).

That's the whole extension surface: one command, one output shape.
