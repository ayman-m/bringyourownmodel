# Guardian Cohere

Cohere North provider integration for the Guardian model plane. One of the interchangeable Guardian
provider integrations (alongside **Guardian Vertex**); it implements the shared `guardian-llm-chat`
command against a private **Cohere North** deployment and returns the canonical
`Guardian.LLM.Completion` context, so the rest of the Guardian pack is unaffected by the model choice.

> Enable **exactly one** Guardian provider integration at a time — they all provide `guardian-llm-chat`.
> See [`docs/GUARDIAN_LLM_CHAT_CONTRACT.md`](../../../../docs/GUARDIAN_LLM_CHAT_CONTRACT.md).

## Wire protocol

North is a **stateful conversation** service reached in two hops per turn:

| Step | Call | Purpose |
|---|---|---|
| 1 | `POST {endpoint}/api/v1/chat` | Submit the turn — body carries `agent:{id}`, `conversation:{id}`, `stream:true`, `messages`, optional `system` / `tools`. Bearer auth. The streamed body is drained and discarded. |
| 2 | `GET {endpoint}/api/v1/conversations/{id}` | Read the assembled conversation; the last CHATBOT/assistant message is the reply. `content` is a list of text blocks. |

## Configuration

| Parameter | Required | Notes |
|---|---|---|
| Endpoint URL | yes | North base URL, e.g. `https://core.example.com` (no path suffix). |
| Agent ID | yes | Sent as `agent.id`. |
| Session ID (conversation id) | reuse mode | Sent as `conversation.id`. Required in `reuse` mode (a pre-created conversation reused every call); ignored in `stateless` mode. |
| Bearer token | yes | `Authorization: Bearer <token>`. Stored encrypted (type 4). |
| Conversation mode | yes | `reuse` (default) or `stateless` — see below. |
| Tool format | yes | `openai` (default, pass-through) or `cohere` (`parameter_definitions`). |
| Model label | no | Cosmetic; reported as `Guardian.LLM.Completion.model` and by `!guardian-model`. Default `cohere-north`. |
| Request timeout (seconds) | no | Per-HTTP-call timeout. Default `200`. |
| Trust any certificate | no | For a private/self-signed endpoint. |
| Use system proxy settings | no | Standard XSOAR proxy handling. |

### Conversation mode

- **`reuse`** (default) — the configured **Session ID** *is* `conversation.id` on every call, and only
  the turn's *new* messages (everything after the last assistant message) are submitted; North holds
  the running conversation history. Matches a fixed, pre-created North conversation id. *Caveat:* this
  assumes the orchestrator's transcript and North's server-side history stay in sync — if the Guardian
  tick compacts/edits the transcript, that change is not reflected in North's stored conversation.
- **`stateless`** — a fresh `conversation.id` (UUID) is minted per call and the **full transcript** is
  submitted, for North deployments that accept client-supplied conversation UUIDs and want
  per-investigation isolation. The Session ID field is ignored.

> **⚠ Concurrency & isolation (reuse mode).** In `reuse` mode all incidents on the instance share the
> **one** configured Session ID conversation, so **concurrent** investigations interleave into a single
> North history (cross-incident bleed). Use `reuse` for a single investigation at a time (e.g. a
> brief-generator); for concurrent multi-incident isolation use `stateless` (if North accepts
> client-supplied UUIDs) or provision one North conversation per investigation. Reuse also relies on
> server-side history, so a mid-run transcript compaction/empty-turn retry in the Guardian tick can
> resubmit a turn (minor duplicate history server-side). `stateless` mode has none of these caveats.

### Correctness hardening

The client is built for a stateful, sometimes-async North endpoint:
- **New-reply detection.** Before submitting (reuse mode) it reads the conversation's message count as a
  baseline; the poll only returns once the count has grown **and** the last message is an assistant
  reply — so it can never hand back the *previous* turn's answer.
- **No fabricated answers.** If no new assistant reply arrives within the poll window it **raises**
  (surfaced to the tick as an error entry) rather than echoing the just-sent prompt back as a completion.
- **Idempotency.** The non-idempotent chat `POST` is retried **only on 429**, never on 5xx, so a turn is
  never double-submitted. Each poll `GET` is bounded to the remaining poll budget so one call can't hang
  the reasoning tick.
- **Non-invasive test.** `test-module` in reuse mode is a read-only `GET` (no ping turn is written into
  the shared production conversation); stateless mode does a throwaway round-trip.

## Commands

### guardian-cohere-list-models

Lists the models the North endpoint offers (read-only), so a model name can be checked before it is configured.
North's models route is not public: the command tries `/api/v1/models`, then `/v1/models`, and shows what each
answered when neither works. Output: `GuardianCohere.Model` (`id`, `name`, `default`, `capabilities`).

```
!guardian-cohere-list-models
```

### guardian-llm-chat

Provider-independent chat completion (identical arguments and `Guardian.LLM.Completion` output across
every Guardian provider). See the pack-level contract doc for the full argument/output tables.

The optional `model` argument cannot select a model here: the agent behind the instance is fixed. An empty value, or one
equal to the instance's Model label, is accepted; any other value is refused with an error that starts with
`MODEL_SELECTION_UNSUPPORTED:`, without a call to North.

```
!guardian-llm-chat messages=`[{"role":"user","content":"say hi in exactly two words"}]`
```

## Adding / switching providers

To make Guardian use Cohere North: deploy the pack, create a **Guardian Cohere** instance, enable it,
and **disable** the other Guardian provider instance(s). Nothing else in the pack changes — the tick
and all content route `guardian-llm-chat` to the enabled provider automatically, and `!guardian-model`
reports the live one.

## Testing notes

Unit tests (`GuardianCohere_test.py`) mock `_http_request` at the client boundary (no live North
endpoint is required) and cover request translation (reuse-delta vs stateless-full, system extraction,
tool formats), the conversation poll/completion signal, response normalization (text-block extraction,
Cohere→OpenAI tool_calls, usage mapping), argument parsing, and `test-module`. A live `test-module` /
`guardian-llm-chat` run requires a real North endpoint + agent id + session id + bearer token.
