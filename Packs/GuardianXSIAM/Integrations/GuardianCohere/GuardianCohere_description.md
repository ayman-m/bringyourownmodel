## Guardian Cohere Help

Guardian Cohere is a **model-plane provider** for the Guardian agent, backed by a private **Cohere
North** deployment. Like every Guardian provider it implements the single `guardian-llm-chat` command
and returns the canonical `Guardian.LLM.Completion` shape, so the rest of the Guardian pack (the
reasoning tick, tool bridge, sub-agents, cost ledger, slash commands, dashboards) works unchanged —
switching Guardian from Gemini to Cohere North is purely an operator choice.

> **Enable exactly one Guardian provider integration at a time.** They all provide `guardian-llm-chat`,
> so Cortex platform routes it to whichever one is enabled. Enable Guardian Cohere and disable Guardian Vertex
> (or vice-versa). `!guardian-model` shows which provider/model is live.

### How it talks to Cohere North

North is a **stateful conversation** service reached in two hops per turn:

1. `POST {Endpoint URL}/api/v1/chat` — submits the turn with `agent:{id}` + `conversation:{id}` and
   `stream:true`, authenticated with `Authorization: Bearer <token>`. The streamed body is drained and
   discarded.
2. `GET {Endpoint URL}/api/v1/conversations/{id}` — reads the assembled conversation; the last message
   (a CHATBOT/assistant reply) is returned to Guardian.

### Configuration

- **Endpoint URL** — the North base URL, e.g. `https://core.example.com` (no path). The integration
  appends the `/api/v1/...` paths.
- **Agent ID** — the North agent id (`agent.id`), identifying the pre-configured agent/persona.
- **Session ID (conversation id)** — the North conversation id used as `conversation.id`.
  - In **`reuse`** mode (default) this is a **pre-created** North conversation, reused on every call —
    **required**. Only the turn's *new* messages are sent; North holds the running history. This
    matches a fixed, pre-created conversation id.
  - In **`stateless`** mode a fresh conversation id is minted per call (this field is ignored) and the
    full transcript is sent — for North builds that accept client-supplied conversation UUIDs and want
    per-investigation isolation.
- **Bearer token** — the API token, stored encrypted.
- **Conversation mode** — `reuse` (default) or `stateless` (see above).
  > **Concurrency / isolation caveat (reuse mode).** In `reuse` mode *every* Guardian incident on this
  > instance sends its turns to the **one** configured Session ID conversation, and North holds the
  > history server-side. If two incidents investigate concurrently their turns **interleave into one
  > shared North conversation** (cross-incident context bleed). Use `reuse` only for a single
  > investigation at a time (e.g. the brief-generator pattern). For concurrent multi-incident use, use
  > **`stateless`** (fresh isolated conversation per call — requires a North build that accepts
  > client-supplied conversation UUIDs) or provision a separate North conversation per investigation.
  > Also, because reuse relies on server-side history, a mid-run transcript compaction/retry in the
  > Guardian tick can leave the local transcript and North's stored history slightly out of sync.
- **Tool format** — how tool/function definitions are serialized when the tick sends tools. `openai`
  (default) forwards OpenAI function tools as-is (the North messages layer is OpenAI-compatible);
  `cohere` converts them to Cohere-native `parameter_definitions`.
- **Tool results** — how a tool call and its result go back to North. `native` (default) sends OpenAI
  `tool_calls` and `role: tool` messages. Choose `text` when the turn after a tool call never gets a reply
  (the poll times out, or North shows an empty conversation): the call is then sent as a plain assistant
  line and the result as a plain user message. Tool definitions are still sent.
- **Model label** — cosmetic; reported as `Guardian.LLM.Completion.model` and by `!guardian-model`
  (North does not return a model name — the served model is fixed by the agent).
- **Request timeout** — per-HTTP-call timeout in seconds (default 200; North generation can be slow).
- **Trust any certificate** — for a private/self-signed North endpoint whose CA is not in the Docker
  image trust store. Prefer adding the CA to the trust store for production.

### Output shape

`guardian-llm-chat` always returns the same normalized `Guardian.LLM.Completion` context as every other
Guardian provider: `choices[].message.content` / `.tool_calls`, a normalized `finish_reason`, a
`content_filter` boolean, and `usage` (`prompt_tokens` / `completion_tokens` from North's
`meta.tokens`). See `docs/GUARDIAN_LLM_CHAT_CONTRACT.md` for the full contract.
