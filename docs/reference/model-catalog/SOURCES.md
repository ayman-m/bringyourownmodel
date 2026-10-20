# Model limits catalogue: sources and uncertainties

Checked: 2026-10-09. 146 model entries in `model_catalog.json`. Every number was read from a page fetched on the check date (vendor model docs, the cloud provider's own model pages, or the vendor's own Hugging Face / GitHub files); nothing is from memory. Raw copies of the fetched pages are under `raw/`.

## How to read the catalogue

- `context_window`, `max_input_tokens`, `max_output_tokens` hold the VENDOR's own published figures. Cloud-provider figures that differ (Azure Foundry, Vertex, Bedrock) sit in `provider_limits` (list of `{provider, url, context_window, max_input_tokens, max_output_tokens, note}`), and are repeated in `notes`. When the endpoint is a cloud provider, use its `provider_limits` row, not the vendor row.
- `max_input_tokens` is set only where a source states an input limit separately (never derived by subtraction). The context window is shared by input, reasoning and output tokens for almost every model, so an input budget must leave room for `max_tokens`.
- Exception: for Gemini the stored `context_window` equals the 'Input token limit' (1,048,576) and the 'Output token limit' (65,536) is a separate allowance; do not subtract output from it twice. Gemma 3 output (8,192) is a total-output figure on the Hugging Face cards.
- `aliases` are exact lookup strings: bare ids as the vendor API takes them, or `provider:exact-id` with provider in `foundry` (Azure Foundry deployment/model id), `bedrock`, `vertex`, `hf` (Hugging Face repo), `oci`, `ollama` (the prefix ends at the first colon). Dated snapshots are listed as aliases only when their published limits equal the entry's; versions with different limits (for example `mistral-small-2503`, `mistral-medium-2505`, `gpt-4o-2024-05-13`) are deliberately NOT aliases and appear as `provider_limits` rows carrying a `version` label. `alias_notes` maps an alias (or a dropped candidate) to the original annotation or the reason it was not aliased.
- `null` means no primary source states the value; every null has a `<field> null:` clause or equivalent explanation in `notes`.
- Rounded vendor figures ('128K', '1M', '256k') are stored as the literal decimal (128000, 1000000, 256000) unless a vendor config or page prints an exact integer (131072, 262144, 1048576). The decimal reading may be below the true power-of-two length, which is the conservative direction for budgeting. The original string is kept in `notes` (or `stated_as` inside `provider_limits`).
- `status` is free text: active / legacy / deprecated / retired / shut down, with dates where the source gives them. Retired models are kept only when a cloud provider still serves them or the model was explicitly requested.
- Open-weight models: the context actually served depends on the runtime (Ollama `num_ctx`, vLLM `max_model_len`), not on the model alone. Where a vendor card and its `config.json` disagree, the documented figure is stored and the config value quoted in `notes`.

## Table: model, context, max input, max output, source

| vendor | model | context | max input | max output | status | source |
|---|---|---:|---:|---:|---|---|
| OpenAI | `gpt-5` | 400,000 | 272,000 | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-5.md |
| OpenAI | `gpt-5-mini` | 400,000 | 272,000 | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-5-mini.md |
| OpenAI | `gpt-5-nano` | 400,000 | 272,000 | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-5-nano.md |
| OpenAI | `gpt-5.1` | 400,000 | null | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-5.1.md |
| OpenAI | `gpt-5.2` | 400,000 | null | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-5.2.md |
| OpenAI | `gpt-5.4` | 1,050,000 | null | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-5.4.md |
| OpenAI | `gpt-5.4-mini` | 400,000 | 272,000 | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-5.4-mini.md |
| OpenAI | `gpt-5.4-nano` | 400,000 | 272,000 | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-5.4-nano.md |
| OpenAI | `gpt-5.5` | 1,050,000 | null | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-5.5.md |
| OpenAI | `gpt-5.6-sol` | 1,050,000 | 922,000 | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-5.6-sol.md |
| OpenAI | `gpt-5.6-terra` | 1,050,000 | 922,000 | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-5.6-terra.md |
| OpenAI | `gpt-5.6-luna` | 1,050,000 | 922,000 | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-5.6-luna.md |
| OpenAI | `gpt-6-astra` | 1,050,000 | 922,000 | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-6-astra.md |
| OpenAI | `gpt-6-sol` | 1,050,000 | 922,000 | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-6-sol.md |
| OpenAI | `gpt-6-luna` | 1,050,000 | 922,000 | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-6-luna.md |
| OpenAI | `gpt-6.1-sol` | 1,050,000 | 922,000 | 128,000 | active | https://developers.openai.com/api/docs/models/gpt-6.1-sol.md |
| OpenAI | `gpt-4.1` | 1,047,576 | null | 32,768 | active | https://developers.openai.com/api/docs/models/gpt-4.1.md |
| OpenAI | `gpt-4.1-mini` | 1,047,576 | null | 32,768 | active | https://developers.openai.com/api/docs/models/gpt-4.1-mini.md |
| OpenAI | `gpt-4.1-nano` | 1,047,576 | null | 32,768 | active | https://developers.openai.com/api/docs/models/gpt-4.1-nano.md |
| OpenAI | `gpt-4o` | 128,000 | null | 16,384 | active | https://developers.openai.com/api/docs/models/gpt-4o.md |
| OpenAI | `gpt-4o-mini` | 128,000 | null | 16,384 | active | https://developers.openai.com/api/docs/models/gpt-4o-mini.md |
| OpenAI | `o3` | 200,000 | null | 100,000 | active | https://developers.openai.com/api/docs/models/o3.md |
| OpenAI | `o4-mini` | 200,000 | null | 100,000 | active | https://developers.openai.com/api/docs/models/o4-mini.md |
| OpenAI | `o3-mini` | 200,000 | null | 100,000 | active | https://developers.openai.com/api/docs/models/o3-mini.md |
| OpenAI | `gpt-oss-120b` | 131,072 | null | 131,072 | active | https://developers.openai.com/api/docs/models/gpt-oss-120b.md |
| OpenAI | `gpt-oss-20b` | 131,072 | null | 131,072 | active | https://developers.openai.com/api/docs/models/gpt-oss-20b.md |
| xAI | `grok-4.7` | 500,000 | null | null | active (latest) | https://docs.x.ai/developers/models/grok-4.7.md |
| xAI | `grok-4.6` | 500,000 | null | null | active | https://docs.x.ai/developers/models/grok-4.6.md |
| xAI | `grok-4.5` | 500,000 | null | null | active | https://docs.x.ai/developers/models/grok-4.5.md |
| xAI | `grok-4.3` | 1,000,000 | null | null | active | https://docs.x.ai/developers/models/grok-4.3.md |
| xAI | `grok-4.20-0309-reasoning` | 1,000,000 | null | null | active | https://docs.x.ai/developers/models/grok-4.20-0309-reasoning.md |
| xAI | `grok-4.20-0309-non-reasoning` | 1,000,000 | null | null | active | https://docs.x.ai/developers/models/grok-4.20-0309-non-reasoning.md |
| xAI | `grok-4.20-multi-agent-0309` | 1,000,000 | null | null | active (beta) | https://docs.x.ai/developers/models/grok-4.20-multi-agent-0309.md |
| xAI | `grok-build-0.1` | 256,000 | null | null | active | https://docs.x.ai/developers/models/grok-build-0.1.md |
| xAI | `grok-4` | null | null | null | RETIRED on the xAI API (2026-05-15; slug redirec | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| xAI | `grok-4-1-fast-reasoning` | null | null | null | RETIRED on the xAI API (2026-05-15; slug redirec | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| xAI | `grok-4-1-fast-non-reasoning` | null | null | null | RETIRED on the xAI API (2026-05-15; slug redirec | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| Anthropic | `claude-fable-5-1` | 1,000,000 | null | 128,000 | active (latest) | https://platform.claude.com/docs/en/models/fable-5-1/overview.md |
| Anthropic | `claude-fable-5` | 1,000,000 | null | 128,000 | active (legacy) | https://platform.claude.com/docs/en/models/fable-5/overview.md |
| Anthropic | `claude-mythos-5-1` | 1,000,000 | null | 128,000 | active (verification required) | https://platform.claude.com/docs/en/models/mythos-5-1/overview.md |
| Anthropic | `claude-mythos-5` | 1,000,000 | null | 128,000 | active (verification required) | https://platform.claude.com/docs/en/models/mythos-5/overview.md |
| Anthropic | `claude-opus-5-5` | 1,000,000 | null | 128,000 | active (latest) | https://platform.claude.com/docs/en/models/opus-5-5/overview.md |
| Anthropic | `claude-opus-5` | 1,000,000 | null | 128,000 | active (legacy) | https://platform.claude.com/docs/en/models/opus-5/overview.md |
| Anthropic | `claude-opus-4-8` | 1,000,000 | null | 128,000 | active (legacy) | https://platform.claude.com/docs/en/models/opus-4-8/overview.md |
| Anthropic | `claude-opus-4-7` | 1,000,000 | null | 128,000 | active (legacy) | https://platform.claude.com/docs/en/models/opus-4-7/overview.md |
| Anthropic | `claude-opus-4-6` | 1,000,000 | null | 128,000 | active (legacy) | https://platform.claude.com/docs/en/models/opus-4-6/overview.md |
| Anthropic | `claude-opus-4-5-20251101` | 200,000 | null | 64,000 | active (legacy) | https://platform.claude.com/docs/en/models/opus-4-5/overview.md |
| Anthropic | `claude-opus-4-1-20250805` | 200,000 | null | 32,000 | RETIRED on the Claude API (2026-08-05); still 'L | https://platform.claude.com/docs/en/about-claude/models/overview.md |
| Anthropic | `claude-sonnet-5-5` | 1,000,000 | null | 128,000 | active (latest) | https://platform.claude.com/docs/en/models/sonnet-5-5/overview.md |
| Anthropic | `claude-sonnet-5` | 1,000,000 | null | 128,000 | active (legacy) | https://platform.claude.com/docs/en/models/sonnet-5/overview.md |
| Anthropic | `claude-sonnet-4-6` | 1,000,000 | null | 128,000 | active (legacy) | https://platform.claude.com/docs/en/models/sonnet-4-6/overview.md |
| Anthropic | `claude-sonnet-4-5-20250929` | 200,000 | null | 64,000 | deprecated 2026-09-30; Claude API retirement 202 | https://platform.claude.com/docs/en/models/sonnet-4-5/overview.md |
| Anthropic | `claude-sonnet-4-20250514` | 200,000 | null | 64,000 | RETIRED on the Claude API (2026-06-15); still 'L | https://platform.claude.com/docs/en/about-claude/models/overview.md |
| Anthropic | `claude-3-7-sonnet-20250219` | 200,000 | null | 64,000 | RETIRED on the Claude API (2026-02-19) | https://platform.claude.com/docs/en/about-claude/models/overview.md |
| Anthropic | `claude-haiku-5-5` | 1,000,000 | null | 128,000 | active (latest) | https://platform.claude.com/docs/en/models/haiku-5-5/overview.md |
| Anthropic | `claude-haiku-4-5-20251001` | 200,000 | null | 64,000 | active (legacy) | https://platform.claude.com/docs/en/models/haiku-4-5/overview.md |
| Anthropic | `claude-3-5-haiku-20241022` | 200,000 | null | 8,192 | RETIRED on the Claude API (2026-02-19) | https://web.archive.org/web/20250930051852/https://docs.claude.com/en/docs/about-claude/models/overview |
| Google | `gemini-3.8-flash` | 1,048,576 | 1,048,576 | 65,536 | active (latest, GA) | https://ai.google.dev/gemini-api/docs/models/gemini-3.8-flash.md.txt |
| Google | `gemini-3.7-flash` | 1,048,576 | 1,048,576 | 65,536 | active (Vertex retirement announced 2027-01-28) | https://ai.google.dev/gemini-api/docs/models/gemini-3.7-flash.md.txt |
| Google | `gemini-3.6-flash` | 1,048,576 | 1,048,576 | 65,536 | active (Vertex retirement announced 2026-11-19) | https://ai.google.dev/gemini-api/docs/models/gemini-3.6-flash.md.txt |
| Google | `gemini-3.5-flash` | 1,048,576 | 1,048,576 | 65,536 | active | https://ai.google.dev/gemini-api/docs/models/gemini-3.5-flash.md.txt |
| Google | `gemini-3.5-flash-lite` | 1,048,576 | 1,048,576 | 65,536 | active | https://ai.google.dev/gemini-api/docs/models/gemini-3.5-flash-lite.md.txt |
| Google | `gemini-3.1-flash-lite` | 1,048,576 | 1,048,576 | 65,536 | active | https://ai.google.dev/gemini-api/docs/models/gemini-3.1-flash-lite.md.txt |
| Google | `gemini-3.1-pro-preview` | 1,048,576 | 1,048,576 | 65,536 | active (preview) | https://ai.google.dev/gemini-api/docs/models/gemini-3.1-pro-preview.md.txt |
| Google | `gemini-3-flash-preview` | 1,048,576 | 1,048,576 | 65,536 | active (preview; docs name gemini-3.6-flash as r | https://ai.google.dev/gemini-api/docs/models/gemini-3-flash-preview.md.txt |
| Google | `gemini-2.5-pro` | 1,048,576 | 1,048,576 | 65,536 | active (legacy; API access limited to existing u | https://ai.google.dev/gemini-api/docs/models/gemini-2.5-pro.md.txt |
| Google | `gemini-2.5-flash` | 1,048,576 | 1,048,576 | 65,536 | active (legacy; API access limited to existing u | https://ai.google.dev/gemini-api/docs/models/gemini-2.5-flash.md.txt |
| Google | `gemini-2.5-flash-lite` | 1,048,576 | 1,048,576 | 65,536 | active (legacy; API access limited to existing u | https://ai.google.dev/gemini-api/docs/models/gemini-2.5-flash-lite.md.txt |
| Google | `gemini-2.0-flash` | 1,048,576 | 1,048,576 | 8,192 | SHUT DOWN on the Gemini API (2026-06-01) | https://ai.google.dev/gemini-api/docs/models/gemini-2.0-flash.md.txt |
| Google | `gemma-4-31b-it` | 262,144 | null | null | active | https://ai.google.dev/gemma/docs/core.md.txt |
| Google | `gemma-4-26b-a4b-it` | 262,144 | null | null | active | https://ai.google.dev/gemma/docs/core.md.txt |
| Google | `gemma-4-12b-it` | 262,144 | null | null | active | https://ai.google.dev/gemma/docs/core.md.txt |
| Google | `gemma-4-e4b-it` | 131,072 | null | null | active | https://ai.google.dev/gemma/docs/core.md.txt |
| Google | `gemma-4-e2b-it` | 131,072 | null | null | active | https://ai.google.dev/gemma/docs/core.md.txt |
| Google | `gemma-3-27b-it` | 131,072 | null | 8,192 | active (legacy; superseded by Gemma 4) | https://ai.google.dev/gemma/docs/core/model_card_3.md.txt |
| Google | `gemma-3-12b-it` | 131,072 | null | 8,192 | active (legacy; superseded by Gemma 4) | https://ai.google.dev/gemma/docs/core/model_card_3.md.txt |
| Google | `gemma-3-4b-it` | 128,000 | null | 8,192 | active (legacy; superseded by Gemma 4) | https://ai.google.dev/gemma/docs/core/model_card_3.md.txt |
| Google | `gemma-3-1b-it` | 32,768 | null | 8,192 | active (legacy; superseded by Gemma 4) | https://ai.google.dev/gemma/docs/core/model_card_3.md.txt |
| Google | `gemma-3n-e4b-it` | 32,000 | null | null | active (legacy) | https://ai.google.dev/gemma/docs/gemma-3n/model_card.md.txt |
| Google | `gemma-3n-e2b-it` | 32,000 | null | null | active (legacy) | https://ai.google.dev/gemma/docs/gemma-3n/model_card.md.txt |
| Meta | `llama-3.1-8b-instruct` | 128,000 | null | null | active (legacy; Bedrock EOL 2027-03-30) | https://raw.githubusercontent.com/meta-llama/llama-models/main/models/llama3_1/MODEL_CARD.md |
| Meta | `llama-3.1-70b-instruct` | 128,000 | null | null | active (legacy; Bedrock EOL 2027-03-30) | https://raw.githubusercontent.com/meta-llama/llama-models/main/models/llama3_1/MODEL_CARD.md |
| Meta | `llama-3.1-405b-instruct` | 128,000 | null | null | active (legacy; Bedrock EOL 2026-07-07) | https://raw.githubusercontent.com/meta-llama/llama-models/main/models/llama3_1/MODEL_CARD.md |
| Meta | `llama-3.3-70b-instruct` | 128,000 | null | null | active (legacy; Vertex MaaS endpoint retires 202 | https://raw.githubusercontent.com/meta-llama/llama-models/main/models/llama3_3/MODEL_CARD.md |
| Meta | `llama-4-scout-17b-16e-instruct` | 10,000,000 | null | null | active (newest Llama generation found) | https://raw.githubusercontent.com/meta-llama/llama-models/main/models/llama4/MODEL_CARD.md |
| Meta | `llama-4-maverick-17b-128e-instruct` | 1,000,000 | null | null | active (newest Llama generation found) | https://raw.githubusercontent.com/meta-llama/llama-models/main/models/llama4/MODEL_CARD.md |
| Cohere | `command-a-03-2025` | 256,000 | null | 8,000 | active | https://docs.cohere.com/docs/models.md |
| Cohere | `command-a-reasoning-08-2025` | 256,000 | null | 32,000 | active | https://docs.cohere.com/docs/models.md |
| Cohere | `command-a-vision-07-2025` | 128,000 | null | 8,000 | active | https://docs.cohere.com/docs/models.md |
| Cohere | `command-a-translate-08-2025` | 16,000 | 8,000 | 8,000 | active | https://docs.cohere.com/docs/models.md |
| Cohere | `command-a-plus-05-2026` | 128,000 | null | 64,000 | active | https://docs.cohere.com/docs/models.md |
| Cohere | `command-r-plus-08-2024` | 128,000 | null | 4,000 | active | https://docs.cohere.com/docs/models.md |
| Cohere | `command-r-08-2024` | 128,000 | null | 4,000 | active | https://docs.cohere.com/docs/models.md |
| Cohere | `command-r7b-12-2024` | 128,000 | null | 4,000 | active | https://docs.cohere.com/docs/models.md |
| Mistral AI | `mistral-large-4` | 1,000,000 | null | null | active | https://docs.mistral.ai/models |
| Mistral AI | `mistral-large-2512` | 262,144 | null | null | active | https://docs.mistral.ai/models |
| Mistral AI | `mistral-medium-3-5` | 262,144 | null | null | active | https://docs.mistral.ai/models |
| Mistral AI | `mistral-small-2603` | 262,144 | null | null | active | https://docs.mistral.ai/models |
| Mistral AI | `ministral-14b-2512` | 262,144 | null | null | active | https://docs.mistral.ai/models |
| Mistral AI | `ministral-8b-2512` | 262,144 | null | null | active | https://docs.mistral.ai/models |
| Mistral AI | `ministral-3b-2512` | 262,144 | null | null | active | https://docs.mistral.ai/models |
| Mistral AI | `devstral-2512` | 262,144 | null | null | DEPRECATED 2026-05-22 | https://docs.mistral.ai/models |
| Mistral AI | `labs-devstral-small-2512` | 262,144 | null | null | DEPRECATED 2026-02-27 | https://docs.mistral.ai/models |
| Mistral AI | `codestral-2508` | 128,000 | null | null | active | https://docs.mistral.ai/models |
| Mistral AI | `codestral-2501` | 128,000 | null | null | RETIRED on Mistral API 2025-11-30 | https://docs.mistral.ai/models/codestral-25-01 |
| Mistral AI | `mistral-large-2411` | 131,072 | null | null | DEPRECATED 2026-02-27 | https://docs.mistral.ai/models/mistral-large-2-1-24-11 |
| Mistral AI | `mistral-medium-2508` | 128,000 | null | null | DEPRECATED 2026-05-22; alias mistral-medium-2505 | https://docs.mistral.ai/models/mistral-medium-3-1-25-08 |
| Mistral AI | `mistral-small-2506` | 131,072 | null | null | DEPRECATED 2026-04-30; alias mistral-small-2503  | https://docs.mistral.ai/models/mistral-small-3-2-25-06 |
| Mistral AI | `magistral-medium-2509` | 128,000 | null | null | DEPRECATED 2026-05-22 | https://docs.mistral.ai/models/magistral-medium-1-2-25-09 |
| Mistral AI | `magistral-small-2509` | 131,072 | null | null | DEPRECATED 2026-04-30 | https://docs.mistral.ai/models/magistral-small-1-2-25-09 |
| Mistral AI | `ministral-8b-2410` | 128,000 | null | null | DEPRECATED 2025-12-02 | https://docs.mistral.ai/models/ministral-8b-24-1 |
| Mistral AI | `ministral-3b-2410` | 128,000 | null | null | DEPRECATED 2025-12-02 | https://docs.mistral.ai/models/ministral-3b-24-1 |
| DeepSeek | `deepseek-flash` | 1,048,576 | null | 384,000 | active | https://api-docs.deepseek.com/quick_start/pricing |
| DeepSeek | `deepseek-v4-pro` | 1,048,576 | null | 384,000 | active | https://api-docs.deepseek.com/quick_start/pricing |
| DeepSeek | `DeepSeek-V4-Flash` | 1,048,576 | null | 384,000 | retired on the DeepSeek API (routed to V4.1-Flas | https://api-docs.deepseek.com/updates |
| DeepSeek | `DeepSeek-V3.2` | 163,840 | null | null | not on the current DeepSeek API model list (open | https://api-docs.deepseek.com/updates |
| DeepSeek | `DeepSeek-V3.1` | 128,000 | null | null | not on the current DeepSeek API model list (open | https://api-docs.deepseek.com/updates |
| DeepSeek | `DeepSeek-R1-0528` | 163,840 | null | null | not on the current DeepSeek API model list (open | https://api-docs.deepseek.com/updates |
| Qwen | `Qwen3.8-2.4T-A95B` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3.8-2.4T-A95B |
| Qwen | `Qwen3.8-27B` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3.8-27B |
| Qwen | `Qwen3.8-Flash-Next` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3.8-Flash-Next |
| Qwen | `Qwen3.6-35B-A3B` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3.6-35B-A3B |
| Qwen | `Qwen3.6-27B` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3.6-27B |
| Qwen | `Qwen3.5-397B-A17B` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3.5-397B-A17B |
| Qwen | `Qwen3.5-122B-A10B` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3.5-122B-A10B |
| Qwen | `Qwen3.5-35B-A3B` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3.5-35B-A3B |
| Qwen | `Qwen3.5-27B` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3.5-27B |
| Qwen | `Qwen3-Coder-Next` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3-Coder-Next |
| Qwen | `Qwen3-Next-80B-A3B-Instruct` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3-Next-80B-A3B-Instruct |
| Qwen | `Qwen3-Next-80B-A3B-Thinking` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3-Next-80B-A3B-Thinking |
| Qwen | `Qwen3-235B-A22B-Instruct-2507` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3-235B-A22B-Instruct-2507 |
| Qwen | `Qwen3-235B-A22B-Thinking-2507` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3-235B-A22B-Thinking-2507 |
| Qwen | `Qwen3-235B-A22B` | 32,768 | null | null | active | https://huggingface.co/Qwen/Qwen3-235B-A22B |
| Qwen | `Qwen3-32B` | 32,768 | null | null | active | https://huggingface.co/Qwen/Qwen3-32B |
| Qwen | `Qwen3-30B-A3B-Instruct-2507` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3-30B-A3B-Instruct-2507 |
| Qwen | `Qwen3-30B-A3B-Thinking-2507` | 262,144 | null | null | active | https://huggingface.co/Qwen/Qwen3-30B-A3B-Thinking-2507 |
| Qwen | `Qwen3-14B` | 32,768 | null | null | active | https://huggingface.co/Qwen/Qwen3-14B |
| Qwen | `Qwen3-8B` | 32,768 | null | null | active | https://huggingface.co/Qwen/Qwen3-8B |
| Qwen | `Qwen2.5-72B-Instruct` | 32,768 | null | 8,192 | active | https://huggingface.co/Qwen/Qwen2.5-72B-Instruct |
| Moonshot AI | `kimi-k3` | 1,048,576 | null | null | active | https://platform.kimi.ai/docs/models.md |
| Moonshot AI | `kimi-k2.7-code` | 262,144 | null | null | active | https://platform.kimi.ai/docs/models.md |
| Moonshot AI | `kimi-k2.6` | 262,144 | null | null | active | https://platform.kimi.ai/docs/models.md |
| Moonshot AI | `kimi-k2.5` | 262,144 | null | null | DISCONTINUED on Kimi API 2026-08-31 | https://platform.kimi.ai/docs/models.md |
| Moonshot AI | `kimi-k2-thinking` | 262,144 | null | null | DISCONTINUED on Kimi API 2026-05-25 | https://platform.kimi.ai/docs/models.md |
| Moonshot AI | `kimi-k2-0905-preview` | 262,144 | null | null | DISCONTINUED on Kimi API 2026-05-25 | https://platform.kimi.ai/docs/models.md |
| Moonshot AI | `kimi-k2-0711-preview` | 131,072 | null | null | DISCONTINUED on Kimi API 2026-05-25 | https://platform.kimi.ai/docs/models.md |

## Provider caps that differ from the vendor figure

Only rows where a cloud provider's published context, input or output figure differs from the vendor's. Rounded provider figures (Bedrock '128K') are shown as stored.

| model | provider | provider context | provider input | provider output | vendor context / input / output | provider URL |
|---|---|---:|---:|---:|---|---|
| `gpt-5.1` | azure-foundry | 400,000 | 272,000 | 128,000 | 400,000 / null / 128,000 | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `gpt-5.2` | azure-foundry | 400,000 | 272,000 | 128,000 | 400,000 / null / 128,000 | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `gpt-5.4` | azure-foundry | 1,050,000 | 922,000 | 128,000 | 1,050,000 / null / 128,000 | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `gpt-5.5` | azure-foundry | 1,050,000 | 922,000 | 128,000 | 1,050,000 / null / 128,000 | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `gpt-4.1` | azure-foundry | 300,000 | null | 32,768 | 1,047,576 / null / 32,768 | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `gpt-4.1-mini` | azure-foundry | 300,000 | null | 32,768 | 1,047,576 / null / 32,768 | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `gpt-4.1-nano` | azure-foundry | 300,000 | null | 32,768 | 1,047,576 / null / 32,768 | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `gpt-4o` | azure-foundry | null | 128,000 | 4,096 | 128,000 / null / 16,384 | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `grok-4.7` | azure-foundry | 500,000 | 500,000 | 500,000 | 500,000 / null / null | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `grok-4.6` | azure-foundry | 200,000 | null | 128,000 | 500,000 / null / null | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `grok-4.3` | azure-foundry | null | 200,000 | 8,192 | 1,000,000 / null / null | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `grok-4.20-0309-reasoning` | azure-foundry | null | 262,000 | 8,192 | 1,000,000 / null / null | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `grok-4.20-0309-non-reasoning` | azure-foundry | null | 262,000 | 8,192 | 1,000,000 / null / null | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `grok-build-0.1` | azure-foundry | null | 256,000 | 8,192 | 256,000 / null / null | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `grok-4` | azure-foundry | null | 262,000 | 8,192 | null / null / null | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `grok-4-1-fast-reasoning` | azure-foundry | null | 128,000 | 128,000 | null / null / null | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `grok-4-1-fast-non-reasoning` | azure-foundry | null | 128,000 | 128,000 | null / null / null | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `claude-sonnet-4-6` | aws-bedrock | 1,000,000 | null | 64,000 | 1,000,000 / null / 128,000 | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-anthropic-claude-sonnet-4-6.html |
| `gemma-4-31b-it` | bedrock | 256,000 | null | null | 262,144 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-google-gemma-4-31b.html |
| `gemma-4-26b-a4b-it` | vertex | 262,144 | null | 128,000 | 262,144 / null / null | https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/maas/google/gemma-4-26b-a4b-it |
| `gemma-4-26b-a4b-it` | bedrock | 256,000 | null | null | 262,144 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-google-gemma-4-26b-a4b.html |
| `gemma-4-e2b-it` | bedrock | 128,000 | null | null | 131,072 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-google-gemma-4-e2b.html |
| `gemma-3-27b-it` | bedrock | 128,000 | null | 8,000 | 131,072 / null / 8,192 | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-google-gemma-3-27b-pt.html |
| `gemma-3-12b-it` | bedrock | 128,000 | null | 8,000 | 131,072 / null / 8,192 | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-google-gemma-3-12b-it.html |
| `gemma-3-4b-it` | bedrock | 128,000 | null | 8,000 | 128,000 / null / 8,192 | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-google-gemma-3-4b-it.html |
| `llama-3.1-8b-instruct` | bedrock | 128,000 | null | 4,000 | 128,000 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-meta-llama-3-1-8b-instruct.html |
| `llama-3.1-70b-instruct` | bedrock | 128,000 | null | 4,000 | 128,000 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-meta-llama-3-1-70b-instruct.html |
| `llama-3.1-405b-instruct` | bedrock | 128,000 | null | 4,000 | 128,000 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-meta-llama-3-1-405b-instruct.html |
| `llama-3.3-70b-instruct` | azure-foundry | null | 128,000 | 8,192 | 128,000 / null / null | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `llama-3.3-70b-instruct` | vertex | 128,000 | null | 8,192 | 128,000 / null / null | https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/partner-models/llama/llama3-3 |
| `llama-3.3-70b-instruct` | bedrock | 128,000 | null | 4,000 | 128,000 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-meta-llama-3-3-70b-instruct.html |
| `llama-4-scout-17b-16e-instruct` | azure-foundry | null | 128,000 | 8,192 | 10,000,000 / null / null | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-from-partners |
| `llama-4-scout-17b-16e-instruct` | vertex | 1,310,720 | null | 8,192 | 10,000,000 / null / null | https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/partner-models/llama/llama4-scout |
| `llama-4-scout-17b-16e-instruct` | bedrock | 10,000,000 | null | 8,000 | 10,000,000 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-meta-llama-4-scout-17b-instruct.html |
| `llama-4-maverick-17b-128e-instruct` | azure-foundry | null | 1,000,000 | 1,000,000 | 1,000,000 / null / null | https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `llama-4-maverick-17b-128e-instruct` | vertex | 524,288 | null | 8,192 | 1,000,000 / null / null | https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/partner-models/llama/llama4-maverick |
| `llama-4-maverick-17b-128e-instruct` | bedrock | 1,000,000 | null | 8,000 | 1,000,000 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-meta-llama-4-maverick-17b-instruct.html |
| `command-a-03-2025` | azure-foundry | null | 131,072 | 8,182 | 256,000 / null / 8,000 | https://learn.microsoft.com/en-us/azure/ai-foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `mistral-large-2512` | bedrock | 256,000 | null | 32,000 | 262,144 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-mistral-ai-mistral-large-3.html |
| `mistral-medium-3-5` | azure-foundry | null | 128,000 | 128,000 | 262,144 / null / null | https://learn.microsoft.com/en-us/azure/ai-foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `ministral-14b-2512` | bedrock | 128,000 | null | 8,000 | 262,144 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-mistral-ai-ministral-14b-3-0.html |
| `ministral-8b-2512` | bedrock | 128,000 | null | 8,000 | 262,144 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-mistral-ai-ministral-3-8b.html |
| `ministral-3b-2512` | bedrock | 128,000 | null | 8,000 | 262,144 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-mistral-ai-ministral-3b.html |
| `devstral-2512` | bedrock | 256,000 | null | 32,000 | 262,144 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-mistral-ai-devstral-2-123b.html |
| `codestral-2501` | azure-foundry | null | 262,144 | 4,096 | 128,000 / null / null | https://learn.microsoft.com/en-us/azure/ai-foundry/foundry-models/concepts/models-from-partners |
| `mistral-medium-2508` | azure-foundry | null | 128,000 | 128,000 | 128,000 / null / null | https://learn.microsoft.com/en-us/azure/ai-foundry/foundry-models/concepts/models-from-partners |
| `mistral-small-2506` | azure-foundry | null | 32,768 | 4,096 | 131,072 / null / null | https://learn.microsoft.com/en-us/azure/ai-foundry/foundry-models/concepts/models-from-partners |
| `mistral-small-2506` | vertex | 128,000 | null | null | 131,072 / null / null | https://cloud.google.com/gemini-enterprise-agent-platform/models/partner-models/mistral/mistral-small-3-1 |
| `magistral-small-2509` | bedrock | 128,000 | null | 40,000 | 131,072 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-mistral-ai-magistral-small-2509.html |
| `ministral-3b-2410` | azure-foundry | null | 131,072 | 4,096 | 128,000 / null / null | https://learn.microsoft.com/en-us/azure/ai-foundry/foundry-models/concepts/models-from-partners |
| `deepseek-v4-pro` | azure-foundry | null | 1,000,000 | 384,000 | 1,048,576 / null / 384,000 | https://learn.microsoft.com/en-us/azure/ai-foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `DeepSeek-V4-Flash` | azure-foundry | null | 1,000,000 | 384,000 | 1,048,576 / null / 384,000 | https://learn.microsoft.com/en-us/azure/ai-foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `DeepSeek-V3.2` | azure-foundry | null | 128,000 | 128,000 | 163,840 / null / null | https://learn.microsoft.com/en-us/azure/ai-foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `DeepSeek-V3.2` | vertex | 163,840 | null | 65,536 | 163,840 / null / null | https://cloud.google.com/gemini-enterprise-agent-platform/models/maas/deepseek/deepseek-v32 |
| `DeepSeek-V3.2` | bedrock | 164,000 | null | 8,000 | 163,840 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-deepseek-deepseek-v3-2.html |
| `DeepSeek-V3.1` | vertex | 163,840 | null | 32,768 | 128,000 / null / null | https://cloud.google.com/gemini-enterprise-agent-platform/models/maas/deepseek/deepseek-v31 |
| `DeepSeek-V3.1` | bedrock | 128,000 | null | 8,000 | 128,000 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-deepseek-deepseek-v3-1.html |
| `DeepSeek-R1-0528` | vertex | 163,840 | null | 32,768 | 163,840 / null / null | https://cloud.google.com/gemini-enterprise-agent-platform/models/maas/deepseek/r1-0528 |
| `DeepSeek-R1-0528` | bedrock | 128,000 | null | 8,000 | 163,840 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-deepseek-deepseek-r1.html |
| `Qwen3-Coder-Next` | bedrock | 256,000 | null | 16,000 | 262,144 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-qwen-qwen3-coder-next.html |
| `Qwen3-Next-80B-A3B-Instruct` | vertex | 262,144 | null | 262,144 | 262,144 / null / null | https://cloud.google.com/gemini-enterprise-agent-platform/models/maas/qwen/qwen3-next-instruct |
| `Qwen3-Next-80B-A3B-Instruct` | bedrock | 256,000 | null | 8,000 | 262,144 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-qwen-qwen3-next-80b-a3b.html |
| `Qwen3-235B-A22B-Instruct-2507` | vertex | 262,144 | null | 16,384 | 262,144 / null / null | https://cloud.google.com/gemini-enterprise-agent-platform/models/maas/qwen/qwen3-235b |
| `Qwen3-235B-A22B-Instruct-2507` | bedrock | 256,000 | null | 8,000 | 262,144 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-qwen-qwen3-235b-a22b-2507.html |
| `Qwen3-32B` | bedrock | 32,000 | null | 8,000 | 32,768 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-qwen-qwen3-32b.html |
| `kimi-k3` | bedrock | 1,000,000 | null | null | 1,048,576 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-moonshot-ai-kimi-k3.html |
| `kimi-k2.7-code` | azure-foundry | null | 262,144 | 262,144 | 262,144 / null / null | https://learn.microsoft.com/en-us/azure/ai-foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `kimi-k2.6` | azure-foundry | null | 262,144 | 262,144 | 262,144 / null / null | https://learn.microsoft.com/en-us/azure/ai-foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `kimi-k2.5` | azure-foundry | null | 262,144 | 262,144 | 262,144 / null / null | https://learn.microsoft.com/en-us/azure/ai-foundry/foundry-models/concepts/models-sold-directly-by-azure |
| `kimi-k2.5` | bedrock | 256,000 | null | 16,000 | 262,144 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-moonshot-ai-kimi-k2-5.html |
| `kimi-k2-thinking` | vertex | 262,144 | null | 262,144 | 262,144 / null / null | https://cloud.google.com/gemini-enterprise-agent-platform/models/maas/kimi/kimi-k2-thinking |
| `kimi-k2-thinking` | bedrock | 256,000 | null | 16,000 | 262,144 / null / null | https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-moonshot-ai-kimi-k2-thinking.html |

(72 rows)

## Headline conflicts and uncertainties (read these before trusting a row)

### 1. Cloud provider caps lower than the vendor figure (use `provider_limits` for that endpoint)
- **OpenAI gpt-4.1 / mini / nano on Azure:** 300,000 context on standard deployments, 128,000 on provisioned/batch, versus 1,047,576 at OpenAI; tool definitions above 300,000 tokens fail on Azure.
- **gpt-5.5 on Azure:** combined prompt+generation budget about 922,000 in the Responses API versus a 1,050,000 window.
- **gpt-oss-120b / 20b on AWS Bedrock:** "128K" context and "16K" max output (OpenAI and Azure: 131,072 / 131,072).
- **Claude Sonnet 4.6 on Bedrock:** max output 64K versus 128K at Anthropic and on Azure Foundry.
- **xAI Grok on Azure:** grok-4.6 200,000 context (xAI 500,000); grok-4.3 input 200,000 / output 8,192 (xAI 1,000,000 context); grok-4.20 input 262,000 / output 8,192 (xAI 1,000,000). xAI itself publishes no numeric max output for any model.
- **Llama 4 Scout / Maverick:** native "10M" / "1M" versus Vertex 1,310,720 / 524,288, Azure 128,000 input (Scout), output capped at 8,192 on Vertex and Azure and 4K to 8K on Bedrock; Azure marks tool calling "No" for Llama 4 and Llama 3.3 while Vertex lists function calling.
- **Cohere Command A on Azure:** input 131,072 / output 8,182 (printed that way; possibly a typo for 8,192) versus Cohere's 256k / 8k.
- **DeepSeek V3.2:** Azure 128,000, Vertex 163,840 context with 65,536 output, Bedrock 164K with 8K output, HF config 163,840.
- **Other Azure caps below vendor figures:** Mistral Small 3.1 (32,768 / 4,096 versus 128k), Codestral 2501 (262,144 / 4,096 versus 128k), Ministral 3B 2410 (131,072 / 4,096), Mistral Medium 3.5 (128,000 / 128,000, tool calling "No", versus Mistral 256k with function calling), Ministral 3 on Bedrock (128K / 8K versus 256k).
- **Qwen3-Next / Qwen3-235B-2507 on Bedrock:** 256K context / 8K output versus Vertex 262,144 with 262,144 (Next) or 16,384 (235B) output; Kimi K2.5 / K2-Thinking on Bedrock 256K / 16K versus Vertex K2-Thinking 262,144 / 262,144.

### 2. Vendor documentation versus vendor config / card disagreements (documented figure stored, config value quoted in notes)
- Mistral Small 4: docs 256k (262,144) versus HF config 1,048,576. Mistral Large 3: docs 256k versus params.json 294,912. Devstral Small 2: 256k versus config 393,216. Ministral 8B 2410: 128k versus config 32,768.
- Cohere Command A+: docs 128k versus HF config 200,000. Command A: supports 256K but HF card says "configured in Hugging Face for 128K". Command A Vision: table 128K versus HF card 32K. Command A Translate: models table 8K versus model page and card 16K total (8K in + 8K out).
- Qwen3 original (235B-A22B, 32B, 14B, 8B): card 32,768 native / 131,072 with YaRN versus config.json 40,960; stored 32,768. Qwen2.5-72B: card 131,072 (YaRN) versus shipped config 32,768.
- Gemma 3 max output: HF cards say 8,192 total output; the ai.google.dev card says up to 128K (32K for 1B) shared with input. Stored 8,192.
- DeepSeek V4 Pro: the news post says it is being phased out (rerouted from 2026-09-14) while the changelog text says service continues; the pricing page still lists it.

### 3. Values that are rounded decimals, not exact counts
- All Cohere figures (256k / 128k / 8k / 4k; the Cohere HF repos are gated, so no config could be read), all Meta Llama figures (128k, 10M, 1M; Meta HF repos gated), Gemma 3 4B (128K), Gemma 3n (32K), all Bedrock rows, Anthropic's 1M / 128K / 200K / 64K. True lengths are probably 131,072 / 262,144 / 32,768 where these round, but are unverified, so the lower decimal is stored.

### 4. Not found, retired, or unverifiable
- **grok-3, grok-3-mini, grok-4-fast-*:** no model page on docs.x.ai (retired 2026-05-15 or never listed); no entries. grok-4 and the grok-4-1-fast ids are kept only because Azure still lists them, with every vendor number null. grok-code-fast-1 is now an alias of grok-build-0.1. Newest xAI model found: grok-4.7 (no grok-5).
- **Gemini 2.0 Flash** is shut down (2026-06-01), kept flagged; Gemini 2.5 models retire on Vertex 2026-10-20; Llama 3.3 on Vertex 2026-10-21; Bedrock Llama 3.1 405B EOL 2026-07-07.
- **No Llama newer than Llama 4**, no Gemini Pro newer than 3.1 Pro Preview.
- **Mistral Large 4:** no Hugging Face repo; only "1M" stated. **Mistral Large 3 on Azure:** id verified, but Microsoft prints no token limits.
- **DeepSeek V3.1 / V3.2 / R1 vendor-API limits** are no longer on api-docs.deepseek.com (Wayback copy blocked by HTTP 429), so their output caps are null; context comes from HF configs / cards.
- **Alibaba hosted Qwen API limits** could not be fetched (JS-rendered), so Qwen figures come from HF cards, Bedrock and Vertex only.
- **Azure ids requested:** `cohere-command-a` is listed as `Cohere-command-a`; `Mistral-Large-3` (Preview), `DeepSeek-V3.2` and `Kimi-K2.6` (Preview) are found on the Microsoft Learn table; `Llama-4-Maverick-17B-128E-Instruct-FP8` is found (Input 1M / Output 1M, no combined window printed). The ai.azure.com catalogue was not used (JS-rendered).
- **Structured-output support** is null for the open-weight Gemma and Llama models and many Qwen models (vendors state no feature; cloud services list it separately). Reasoning flags for Gemma 3 / Llama are false by absence of mention.
- **OpenRouter slugs** are not recorded for any model; Ollama tags only where seen on an Ollama page (gpt-oss).

## Detailed log: OpenAI and Anthropic

### Method and sources
- OpenAI: `https://developers.openai.com/api/docs/models/<id>.md` (raw markdown; the HTML page is the same data). Lines read: "N context window", "Maximum input tokens: N", "N max output tokens", default snapshot, supported features. Azure OpenAI: the server-rendered table at `https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure`. gpt-oss: OpenAI model page, `huggingface.co/openai/<m>/raw/main/config.json`, the AWS Bedrock model card, the Ollama library page (tag names only).
- Anthropic: `https://platform.claude.com/docs/en/models/<slug>/overview.md` for each current model, the models overview, the context-windows doc, the structured-outputs doc (its `supportedModels` list drives `supports_structured_output`), the model-deprecations page, AWS Bedrock model cards (`model-card-anthropic-claude-*.html`), Azure Foundry partner table, and Anthropic's Vertex doc. Retired models (Opus 4.1, Sonnet 4, Sonnet 3.7, Haiku 3.5) no longer have pages (HTTP 404); their numbers come from the Internet Archive copy of Anthropic's own models overview dated 2025-09-30 (`web.archive.org/web/20250930051852/...`) and, where one exists, the Bedrock card.
- WebFetch's summariser was NOT used for any recorded number; all figures were read from raw text. Every OpenAI and current-Anthropic figure was re-fetched fresh at the end and compared programmatically (42 pages, 0 mismatches).

### OpenAI uncertainties and conflicts
1. **Separate input limit is stated only for some models.** OpenAI's pages print "Maximum input tokens" for gpt-5, gpt-5-mini, gpt-5-nano (272,000), gpt-5.4-mini/nano (272,000), gpt-5.6-*, gpt-6-*, gpt-6.1-sol (922,000). They print none for gpt-5.1, gpt-5.2, gpt-5.4, gpt-5.5, the gpt-4.1 family, gpt-4o family and the o-series, so `max_input_tokens` is null there. Azure does state Input 272,000 (gpt-5.1, gpt-5.2) and 922,000 (gpt-5.4, gpt-5.5); those sit in `provider_limits`, not in the vendor field.
2. **gpt-5.5 combined budget.** Azure documents that for the Responses API the effective combined prompt+generation budget is about 922,000 tokens, below the 1,050,000 window ("You can't combine a 922,000-token prompt with 128,000 generated tokens"). OpenAI's gpt-5.5 page says nothing about this. For gpt-5.6, gpt-6 and gpt-6.1 OpenAI states Maximum input tokens 922,000 beside a 1,050,000 window and 128,000 output; whether input+output may reach 1,050,000 or is capped at 922,000 in total is not stated by OpenAI. Safe budgeting: treat 922,000 as the total for prompt plus output on every 1.05M-window OpenAI/Azure model unless proven otherwise by the probe.
3. **gpt-4.1 family on Azure is capped at 300,000 context** (standard deployments; 128,000 on provisioned-managed and batch) versus 1,047,576 on OpenAI. Azure also documents a known issue: tool/function definitions above 300,000 tokens fail even though the 1M limit is not reached. Relevant for large tool catalogues.
4. **gpt-5-chat-latest and gpt-5.3-chat-latest pages are internally inconsistent** (128,000 context but "Maximum input tokens: 272,000"; Azure's chat models show Input 111,616 + Output 16,384). These ChatGPT-alias models are not catalogued.
5. **gpt-oss.** OpenAI and Azure print max output 131,072, equal to the context window, so it is a ceiling only. AWS Bedrock's card prints "Context window: 128K tokens" and "Max output tokens: 16K" (rounded; stored as null in `provider_limits` because no exact integers are printed). The Hugging Face config gives max_position_embeddings 131072 with YaRN factor 32 over a 4096 original length. OpenAI's own API serves these only via the Responses API. The Ollama library page labels the tags "128K context window" but does not state the default `num_ctx`.
6. **Dated snapshot versus Azure version.** gpt-5.5's OpenAI snapshot is `gpt-5.5-2026-04-23`; Azure lists version 2026-04-24. gpt-5.6-*, gpt-6-* and gpt-6.1-sol have no dated OpenAI snapshot (the id is the snapshot); the `gpt-5.6` alias routes to gpt-5.6-sol.
7. **Chat Completions and tools.** gpt-6.1-sol: Chat Completions only without tool calling. gpt-6-sol, gpt-6-luna and (per Azure) gpt-5.6-*: function calling in Chat Completions only with reasoning_effort none; use the Responses API for tools. `supports_tools` is true for all of them (Responses API).
8. **Not catalogued** (out of scope or no limit relevance): gpt-5 pro / codex / codex-max variants, gpt-5.3-codex, o3-pro, o3-deep-research, the `chat-latest` aliases, audio/realtime/image/embedding models, the Daybreak aliases, deprecated gpt-4.5-preview, gpt-4-turbo, gpt-3.5-turbo.
9. OpenRouter slugs were not recorded for any model (no primary page fetched shows them). Ollama tags are recorded only for gpt-oss (seen on ollama.com).

### Anthropic uncertainties and conflicts
1. **Exact integers.** Anthropic pages print "1M tokens", "128K tokens", "200K tokens", "64K tokens". Stored as 1000000 / 128000 / 200000 / 64000. The exact `max_input_tokens` is exposed only through the Models API (API key needed, not queried), so `max_input_tokens` is null for every Claude entry. The archived 2025-09-30 overview did print exact output integers for old models (64000, 32000, 8192).
2. **Claude Sonnet 4.6 max output conflict.** Anthropic's page and Azure Foundry: 128K (128,000). AWS Bedrock model card: 64K. Both are recorded (vendor field 128000; Bedrock row 64000).
3. **Long-context beta.** On every current 1M-window model 1M is the default: no beta header, standard pricing, except Claude Haiku 5.5 where prompts over 100,000 tokens cost more. The earlier 1M beta for Sonnet 4 and Sonnet 4.5 (header `context-1m-2025-08-07`, long-context pricing above 200K) is documented only in the archived 2025-09-30 overview; the current Sonnet 4.5 page and the context-windows doc state a 200k window, so the beta is treated as ended. The 300k output beta (`output-300k-2026-03-24`) applies only to the Message Batches API and is not in `max_output_tokens`.
4. **Retired on the Claude API but still served on Bedrock.** Opus 4.1 (Anthropic retired 2026-08-05; Bedrock Legacy, EOL 2027-01-08; card 200K / 32K) and Sonnet 4 (retired 2026-06-15; Bedrock EOL 2026-10-14; 200K / 64K). Sonnet 3.7 and Haiku 3.5 are retired (2026-02-19) and have no Bedrock card; their entries rely on the archived Anthropic page only. Sonnet 4.5 is deprecated (retirement 2026-11-30 on the Claude API). Their release dates are not stated in any fetched source and are left out.
5. **Tool-use evidence for retired models** comes from Anthropic's archived tool-use doc (token-count table lists Opus 4.1, Sonnet 4, Sonnet 3.7, Haiku 3.5). `supports_structured_output` is null for the four retired models (not on the structured-outputs supportedModels list).
6. **Mythos 5 / 5.1** are access-gated ("Active (verification required)"); Mythos Preview is deprecated and not catalogued. Release dates of Mythos 5/5.1 are not stated on their pages. Mythos is not named in Anthropic's Vertex context-window sentence, so no Vertex figure is recorded.
7. **Vertex.** Anthropic's Vertex doc gives only the 1M/200k context split by model name and states no separate output cap; the `provider_limits` Vertex rows therefore have output null. No Google-hosted Vertex model-card page for Claude was fetched.
8. **Foundry ids.** Foundry deployments default to the Claude API id (alias where one exists); the Azure partner table prints Opus 4.5 / Sonnet 4.5 / Haiku 4.5 at 200,000 context and 64,000 output, matching Anthropic.
9. **Forced tool use.** Claude Sonnet 5.5 returns an error for forced tool use (tool_choice any/tool); relevant to a tool bridge that forces calls.

## Detailed log: xAI, Google, Meta

## Rules applied
- **K/M figures**: an integer is used only where an exact count is published (config value, `1,048,576`, `131_072`, `500,000`). Where a source gives only rounded notation (`128k`, `10M`, `4K`) the literal decimal is recorded (128000, 10000000, 4000) and the original string stays in `stated_as`/notes. This includes Meta's `128k`/`10M`/`1M`, Gemma 3 4B `128K`, Gemma 3n `32K`, and all Bedrock rows. Where a vendor config is readable (Gemma 4, Gemma 3 1B/12B/27B via Google's own gemma_pytorch config.py) the exact value is used. Decimal readings may be below the true power-of-two length, which is the conservative direction for budgeting.
- **Vendor-level fields hold vendor numbers.** Provider caps (Azure, Vertex, Bedrock) live in `provider_limits` and are mentioned in notes.
- **Retired / shut-down models**: entries are kept only where a cloud provider still serves the id or the model was explicitly requested, and are labelled in `status` (gemini-2.0-flash, grok-4, grok-4-1-fast-*). Retired ids with no remaining published figures (grok-3, grok-4-fast-*, gemini-2.0-flash-lite, gemini-3-pro-preview) have no entry. Retired xAI slugs have all top-level numerics null because xAI no longer publishes them and the API now serves grok-4.3; Azure's figures are in `provider_limits` only.
- **Nulls**: every null among context_window, max_input_tokens, max_output_tokens, supports_tools, supports_structured_output, snapshot_or_version has an explicit `<field> null: ...` clause in notes (checked by script).

## Verification pass (8 figures re-fetched live with the verbatim-quote method; no mismatches)
- grok-4.3 context: `- **Context window:** 1,000,000 tokens` (docs.x.ai/developers/models/grok-4.3.md) - matches.
- gemini-2.5-pro: `**Input token limit** 1,048,576 **Output token limit** 65,536` - matches.
- gemini-3.8-flash: same 1,048,576 / 65,536 - matches.
- google/gemma-4-E4B-it config.json text_config `"max_position_embeddings": 131072` - matches.
- Vertex Llama 4 Maverick: `Max output: 8,192` / `Context length: 524,288` - matches.
- Azure grok-4.6: `Context window: 200,000 tokens` and `Output: text (128,000 tokens max)`; grok-4.3 `Output: text (8,192 tokens)` - matches.
- google/gemma_pytorch config.py: `max_position_embeddings=131_072` for 12B and 27B_v3, `32_768` for 1B - matches.
- Bedrock Llama 4 Scout: `Context window: 10M tokens`, `Max output tokens: 8K` - matches.

## Models asked for that do not exist / are retired / not found
- **grok-3, grok-3-mini**: no model page on docs.x.ai (HTTP 404 for `/developers/models/grok-3.md`, `grok-3-mini.md`). grok-3 is listed in the 2026-05-15 retirement notice (redirects to grok-4.3 at `none` effort). grok-3-mini is not mentioned anywhere on the pages fetched. No entry created.
- **grok-4-fast-reasoning / grok-4-fast-non-reasoning**: retired 2026-05-15 (retirement notice), no model page. No entry. (Azure does not list a "grok-4-fast" either; it lists grok-4.1-fast-*.)
- **grok-4 (grok-4-0709), grok-4-1-fast-reasoning/non-reasoning**: retired on the xAI API but still listed by Azure Foundry. Entries exist with ALL top-level numerics null (xAI publishes none; on the xAI API these slugs are served by grok-4.3 with 1,000,000 context). Azure's input/output figures are in provider_limits only (grok-4: 262,000 in / 8,192 out; grok-4.1-fast: 128,000 in / 128,000 out).
- **grok-code-fast-1**: not a separate model on xAI now; it is an alias of grok-build-0.1 (per the grok-build-0.1 page and the retirement notice). Azure still lists grok-code-fast-1 with 256,000 in / 8,192 out.
- **grok-5 or any newer generation**: none listed on docs.x.ai/developers/models.md (newest is grok-4.7). 
- **Gemini 2.0 Flash**: exists but SHUT DOWN 2026-06-01 (model page + deprecations page). Entry kept, flagged. gemini-2.0-flash-lite (also shut down) and gemini-3-pro-preview (shut down 2026-03-09) not given entries.
- **Gemma 3 270M**: exists (google/gemma-3-270m-it, gated) but was not in the requested list; no entry. Model card text says 32K context.
- **Newer Llama than Llama 4**: none found. The newest repos in the meta-llama HF org are Llama 4 (April 2025) plus Llama Guard 4 / Prompt Guard 2; llama.com model-cards page lists Llama 4, 3.3, 3.1 and earlier. Meta may have non-open models that are not documented on the pages fetched.
- **Newer Gemini Pro than 3.1**: none on the models index (3.1 Pro Preview, Feb 2026, is the only Pro in the Gemini 3 section; newest Flash is 3.8). Not covered: Live/TTS/image/embedding/agent models (not text-chat models for this catalogue).

## Conflicts between sources (recorded in notes and provider_limits)
- **Azure Foundry caps Grok lower than xAI**: grok-4.6 (xAI 500,000 ctx) vs Azure 200,000 ctx / 128,000 out; grok-4.3 (xAI 1,000,000) vs Azure input 200,000 / output 8,192; grok-4.20 (xAI 1,000,000) vs Azure input 262,000 / output 8,192. grok-4.7 matches (500,000) and Azure additionally states "input and output combined".
- **Llama 4 served limits are far below native**: Scout native "10M" vs Vertex 1,310,720, Azure 128,000 input; Maverick native "1M" vs Vertex 524,288, Azure 1M in/out. Llama 3.3 / Vertex / Azure all give 8,192 max output; Bedrock gives 4K for Llama 3.x and 8K for Llama 4.
- **Azure says tool calling "No" for Llama 4 Scout/Maverick and Llama 3.3**, whereas Vertex lists function calling Supported and Meta documents tool-calling formats; top-level supports_tools=true reflects Meta, provider_limits notes the Azure restriction.
- **Gemma 3 max output**: HF model cards (1B/4B/12B/27B) say "Total output context of 8192 tokens"; the ai.google.dev Gemma 3 card says up to 128K (4B/12B/27B) or 32K (1B) "subtracting the request input tokens". Recorded 8192 (HF card, matches Bedrock "8K") with the conflict in notes. Gemma 3n card: output "up to 32K tokens, subtracting the request input tokens" -> null.
- **Vertex retires**: gemini-2.5-pro/flash/flash-lite on 2026-10-20; gemini-3.6-flash 2026-11-19; gemini-3.7-flash 2027-01-28; llama-3.3-70b MaaS 2026-10-21. The Gemini API (ai.google.dev) says 2.5 models are not deprecated but access is limited to existing users.
- **Bedrock Llama 3.1 405B** is in Legacy with EOL July 7, 2026 (may already be gone); other Bedrock Llama/Gemma 3 cards are Legacy with EOL March 30, 2027.

## Derived / unverifiable values (flagged, not silently asserted)
- **Meta Llama exact native context**: HF config.json for every meta-llama repo is gated (HTTP 401) and no ungated Meta source gives an exact token count. Meta's own model cards say "128k" (3.1, 3.3), "10M" (Scout), "1M" (Maverick). Recorded as the literal decimal: 128000 / 10000000 / 1000000. The true 128k config value may be 131072 but was NOT verified; 128000 is the conservative choice and equals what Azure and Vertex publish for Llama 3.3. The Llama 3.1 note does not claim native vs RoPE-extended (not stated on fetched pages); for Scout, Meta's llama4/args.py says "Only Llama-4-Scout uses scaled rope".
- **Gemma 3 4B = 128000**: model card says only "128K tokens"; Google's gemma_pytorch `get_config_for_4b` sets no max_position_embeddings and the HF config is gated. Literal decimal recorded; true value is probably 131072 (12B/27B configs say 131_072) but unverified.
- **Gemma 3n = 32000**: card says "32K tokens"; HF config gated. Literal decimal recorded; probably 32768 (Gemma 3 1B config says 32_768) but unverified.
- **Exact values** (published configs): Gemma 4 E2B/E4B 131072, 12B/26B/31B 262144 (HF config max_position_embeddings); Gemma 3 1B 32_768, 12B and 27B 131_072 (Google gemma_pytorch config.py).
- **Gemma 3 HF config.json** (all sizes, incl. 3n) returned HTTP 401 (gated); numbers come from model cards and Google's gemma_pytorch config.py.
- **Llama 4 Maverick on Azure**: Azure's row gives only Input 1M / Output 1M (no combined window), so it fills max_input_tokens/max_output_tokens in provider_limits and leaves its context_window null.
- **Gemini context_window**: the Gemini API docs give only "Input token limit" and "Output token limit". context_window is set equal to the input limit (Vertex's page literally labels 1,048,576 as "Context window"); max_input_tokens is also set per the brief.
- **xAI max_output_tokens**: no numeric cap on any docs.x.ai model page (grok-4.7 get-started says "Output limit | No text output limit"). All xAI max_output_tokens are null by design; only Azure publishes caps.
- **supports_structured_output for open-weight models** (Gemma 3/3n/4, Llama) is null: the vendors state no such feature; Vertex/Bedrock list it as a service capability (see provider_limits/notes).
- **Reasoning flags for Gemma 3/3n and Llama** are false because the cards do not describe thinking modes (absence of mention, not an explicit "No"). grok-4 reasoning=true is inferred from the retirement notice grouping grok-4-0709 with reasoning models.
- **Aliases**: only IDs seen on fetched pages are listed (docs.x.ai alias lists, Azure/Bedrock/Vertex model IDs, HF repo ids from the HF API). No Ollama tags or OpenRouter slugs were fetched, so none are listed. Prefixes like "azure-foundry:" mark the provider namespace.

## Pages that did not work / notes on fetching
- ai.google.dev model pages: the plain URL returns the HTML app shell; appending `.md.txt` returns clean markdown (used).
- docs.x.ai: appending `.md` works.
- Vertex AI docs now live at docs.cloud.google.com/gemini-enterprise-agent-platform/... (cloud.google.com/vertex-ai/... redirects there); server-rendered HTML, stripped with a script. The Vertex 2.0 Flash URL redirects to the model list (no data).
- huggingface.co/google/gemma-3*, gemma-3n*, and all meta-llama/* raw files: 401 (gated). Only gemma-4-* configs were readable. The public HTML card pages of the Gemma repos were readable; the Meta HF card pages were not used (Meta's GitHub llama-models MODEL_CARD.md used instead).
- ai.azure.com catalogue not attempted (JS-rendered); learn.microsoft.com pages used instead (models-sold-directly-by-azure and models-from-partners). Azure marks grok-4.6, 4.3 and 4.20 as Preview.

## Detailed log: Cohere, Mistral, DeepSeek, Qwen, Moonshot

## 1. Conventions used (read first)

- Top-level `context_window` / `max_output_tokens` are the VENDOR's own figures. Cloud-provider caps are in `provider_limits` (added on request of the coordinating session; `[]` when none) and are also mentioned in `notes`.
- Provider fields: Azure Foundry prints `Input: text (N tokens)` / `Output: text (M tokens)` and never says whether Input is the whole context, so N is stored as `max_input_tokens` with `context_window` null. Bedrock prints rounded `128K`/`8K` which are stored as 128000/8000 and flagged as rounded. Vertex prints exact integers (`65,536 maximum output, 163,840 context length`).
- Rounding policy for vendor figures: when a vendor writes `256k`/`1M`/`4k` and the same vendor's readable config or card gives a consistent exact figure (262144 = 256*1024, 1048576 = 1M, 131072 = 128K) the exact figure is recorded; when only the rounded figure exists it is recorded as a decimal (256000, 8000) and the notes say so. Cohere's gated HF repos return 401 for config.json, so every Cohere figure is a rounded decimal.
- Where the vendor's rounded doc figure and the vendor's config.json disagree (Mistral Small 4, Mistral Large 3, Devstral Small 2, Command A+, Qwen3 original, Ministral 8B 2410), the DOCUMENTED figure is recorded and the config value is quoted in notes. These configs are runtime/YaRN ceilings, not product limits.
- `supports_structured_output` = the vendor or provider states `response_format` JSON-schema or JSON mode works. DeepSeek is JSON-object mode only (stated in notes). `null` = not stated by any fetched source, not 'unsupported'.
- Ids are the vendor's own API names where the vendor has them (Cohere, Mistral, `deepseek-flash`, `deepseek-v4-pro`, Kimi API names such as `kimi-k2-0905-preview`); otherwise the HF/Azure model name (`DeepSeek-V3.2`, `DeepSeek-R1-0528`, `Qwen3-32B`). `vendor` strings: Cohere, Mistral AI, DeepSeek, Qwen, Moonshot AI. `status` is set explicitly (active / deprecated / retired / discontinued with date).
- Aliases: one exact name per string, no spaces or parentheses. Cloud ids carry the sibling-part prefix convention (`foundry:`, `bedrock:`, `vertex:`); vendor, HF and OCI names are bare. Annotations live in `notes`. A name appears as an alias only when a fetched page ties it to that model; un-dated or snapshot-ambiguous ids (Bedrock Command R/R+, Bedrock DeepSeek V3.1/R1, Vertex `codestral-2`) are named in notes but not asserted as aliases. The retired `deepseek-chat` / `deepseek-reasoner` names are NOT aliases of V3.2: the changelog says they were repointed to V4 Flash on 2026-04-24.
- `max_output_tokens` is null for every Mistral model and almost every open-weight Qwen/DeepSeek model: no vendor page states a hard output cap (Mistral says prompt plus max_tokens must fit in the context). Recommended generation lengths on HF cards are quoted in notes but are not stored as limits.
- Mistral and Kimi both define the context window as input plus output combined (Mistral glossary; Kimi `max_completion_tokens` must fit `input + max_completion_tokens <= context`). Kimi's output ceiling is therefore `context - prompt_tokens`, so Kimi `max_output_tokens` is null with the formula, K3's default 131072 and settable ceiling 1048576 quoted in notes (a stored value equal to the context would give a zero input budget). Azure and Vertex print 262,144 output for Kimi K2.x; those stay in `provider_limits`.
- Context policy for Qwen: the NATIVE figure is stored (card/config), YaRN extension is in notes. That includes Qwen3 original (32,768, config says 40960) and Qwen2.5-72B-Instruct (stored 32768 per the card sentence about config.json, with the card's 'Full 131,072 tokens and generation 8192 tokens' in notes and 8192 stored as the only vendor-stated generation cap).
- Every null field is explained by a generated `NULLS:` clause at the end of `notes` (field name plus reason).
- Open weights != open licence: Cohere weights are CC-BY-NC-4.0 (Command A+ is Apache 2.0); Mistral Large 2.1 and Ministral 8B 2410 are MRL; Qwen3.8-2.4T-A95B / Flash-Next and Kimi K3 use custom licences; Qwen2.5-72B uses the Qwen licence.

## 2. Azure Foundry id verification (learn.microsoft.com 'Foundry Models sold by Azure', fetched as server-rendered HTML; ai.azure.com not used)

| id requested | result | what the page prints |
|---|---|---|
| `cohere-command-a` | FOUND as `Cohere-command-a` | Input 131,072 tokens, Output 8,182 tokens, Tool calling Yes, formats Text, JSON |
| `Mistral-Large-3` | FOUND (Preview) | text+image, Tool calling Yes, formats Text, JSON; NO token limits printed |
| `DeepSeek-V3.2` | FOUND | Input 128,000, Output 128,000, Tool calling Yes, formats Text, JSON |
| `Kimi-K2.6` | FOUND (Preview) | Input text+image 262,144, Output 262,144, Tool calling Yes, formats Text |

Other ids seen on the same page: `Cohere-command-a-plus-05-2026` (Preview, 128,000/64,000), `DeepSeek-V4-Pro`, `DeepSeek-V4-Flash`, `DeepSeek-V4-Flash-0731` (Preview), `DeepSeek-V3.2-Speciale` (all V4: 1,000,000/384,000; Speciale 128,000/128,000), `mistral-medium-3-5` (Preview, 128,000/128,000), `Kimi-K2.7-Code`, `Kimi-K2.5` (both Preview, 262,144/262,144). Partners page also lists `Codestral-2501` (262,144/4,096), `Ministral-3B` (131,072/4,096), `Mistral-small-2503` (32,768/4,096), `Mistral-medium-2505` (128,000/128,000). Qwen appears on Azure only in the fine-tuning table (Qwen3-32B, Qwen3.6-35B-A3B, Qwen3.8-27B) with no token limits.

## 3. Conflicts between sources (recorded, not silently fixed)

- Command A (03-2025): Cohere 256k context / 8k output vs Azure 131,072 / 8,182. HF card says supports 256K but 'configured in Hugging Face for 128K'. The 8,182 on Azure is as printed (maybe a typo for 8,192).
- Command A+ (05-2026): Cohere and Azure 128k/64k vs HF config max_position_embeddings 200000 (bf16 and w4a4 repos).
- Command A Vision: Cohere table 128K / 8K vs HF card 'Context length: 32K' (card also says model supports 128K but is configured for 32K).
- Command A Translate: Cohere models table 8K context vs Cohere model page and HF card 16K total (8K in + 8K out). Recorded 16000 total, 8000 in, 8000 out.
- Mistral Small 4: docs/card 256k (vLLM recipe 262144) vs HF config 1048576. Mistral Large 3: docs/card 256k (262144) vs params.json 294912. Devstral Small 2: docs/card 256k (262144) vs HF config 393216.
- Mistral Medium 3.5 on Azure: 128,000/128,000 and 'Tool calling: No' vs Mistral 256k and Function Calling. Ministral 3 on Bedrock: 128K context / 8K output vs Mistral 256k. Mistral Small 3.1: Azure 32,768/4,096 vs Mistral and Vertex 128k. Codestral 2501: Azure 262,144/4,096 vs Mistral 128k. Ministral 3B 2410: Azure 131,072/4,096 vs Mistral 128k.
- Ministral 8B 2410: docs 128k vs HF config 32768 with sliding_window 32768.
- DeepSeek V3.2: HF config 163840, Azure 128,000, Vertex 163,840 (output 65,536), Bedrock 164K (output 8K). V3.1/R1-0528: Vertex output 32,768 vs Bedrock output 8K. These are provider caps, all kept in provider_limits.
- DeepSeek V4 Pro status: news post 2026-09-10 says V4-Pro is being phased out (rerouted to V4.1-Flash from 2026-09-14), while the changelog 'API changes' text says service continues after Sept 14, 2026. The pricing page still lists deepseek-v4-pro (version DeepSeek-V4-Pro-0813).
- Qwen3 original (235B-A22B, 32B, 14B, 8B): card 32,768 native / 131,072 YaRN vs config.json 40960. Qwen2.5-72B: card 'Full 131,072 tokens and generation 8192 tokens' vs shipped config 32768 (needs YaRN).
- Bedrock Qwen3-Next and Qwen3-235B-2507: 256K context / 8K output vs Vertex 262,144 / 262,144 (Next) and 262,144 / 16,384 (235B). Bedrock Kimi K2.5/K2-Thinking: 256K / 16K vs Vertex K2-Thinking 262,144 / 262,144.

## 4. Not found, not verified, could not fetch

- No requested model was missing: Command A Reasoning (command-a-reasoning-08-2025), Command A Vision, Command A Translate, Command A+ (newer than requested), Command R+/R 08-2024, R7B, Mistral Large 2.1 (2411), Large 3, Medium 3/3.1/3.5, Small 3.1/3.2/4, Magistral Small/Medium, Codestral, Ministral 3B/8B and Ministral 3, Devstral, DeepSeek V3.1/V3.2/R1, Qwen3/2507/Next/3.5/3.6/3.8, Qwen2.5-72B, Kimi K2/0905/Thinking/K2.5/K2.6/K2.7-Code/K3 all exist (many are deprecated or retired; status is in `snapshot_or_version`).
- Newer lines found that the brief did not name (included): Cohere Command A+, Mistral Large 4 (Public Preview) / Medium 3.5 / Small 4 / Ministral 3, DeepSeek V4.1-Flash / V4-Pro / V4-Flash, Qwen3.5 / 3.6 / 3.8, Kimi K3 / K2.6 / K2.7-Code.
- Cohere HF repos (c4ai-command-a-03-2025, command-a-reasoning, command-a-vision, command-a-translate, R+ 08-2024, R 08-2024, R7B) are gated: `raw/main/config.json` returns HTTP 401, so max_position_embeddings could not be read. Figures come from docs.cohere.com and the public HF model-card text. Command A+ repos (bf16, w4a4) are public and were read.
- Mistral Large 4: no Hugging Face repository found in the mistralai org listing (page says open-weight); no exact context figure, only '1M'.
- Mistral Large 3 on Azure: id verified but Microsoft prints no token limits. Cohere Command A on Bedrock: Cohere's table says '(Coming Soon)', no Bedrock model card exists for it; Command A Reasoning/Vision/Translate and R7B have no Azure/Bedrock/Vertex listing found.
- DeepSeek vendor-API limits for V3.1 / V3.2 / R1 (context 128K, output defaults) are no longer on the live api-docs.deepseek.com pricing page (it now lists only deepseek-flash and deepseek-v4-pro). A Wayback copy was attempted and the archive answered HTTP 429, so those numbers were NOT filled in; max_output_tokens is null for them and context comes from HF config (V3.2, R1) or the V3.1 HF card table (128K).
- Alibaba Cloud Model Studio (hosted Qwen API) pages are JS-rendered (alibabacloud.com returned a 28 KB shell with no model table; help.aliyun.com/zh/model-studio/models returned about 4 KB of navigation text); no hosted-Qwen API figures recorded. Qwen figures come from HF cards/configs, Bedrock and Vertex.
- Qwen entries NOT included: Qwen3-Coder-480B-A35B (Vertex/Bedrock-listed), Qwen3-VL, Qwen3.5 small sizes (0.8B-9B), Qwen3.8-Max and other hosted-only tiers. Cohere extras not included: North Mini Code, North Small Translate, Aya, tiny-aya. Mistral extras not included: Pixtral, Voxtral, OCR, Leanstral, Shieldstral, Mistral Nemo, Mixtral, Mistral 7B, Devstral Medium/Small 1.x, Mistral Small Creative, and the Z.ai GLM 5.x third-party models that Mistral's docs list.
- Qwen3.8-* cards contain no explicit tool-calling statement, so supports_tools is null for them; Qwen2.5-72B-Instruct card likewise. Magistral entries have supports_structured_output null (feature not listed on the Mistral page).
- OpenRouter slugs and Ollama tags were not recorded anywhere (not seen on any fetched primary page).

## 5. Re-verification (9 figures re-fetched with independent curl runs after the JSON was written; no mismatches)

| figure | verbatim result of the re-fetch | matches JSON |
|---|---|---|
| Command A models-table row (docs.cohere.com/docs/models.md) | `command-a-03-2025 ... Text | 256k | 8k` | yes (256000 / 8000, rounded) |
| Mistral Large 3 params.json | `"max_position_embeddings": 294912,` | yes (quoted in notes; recorded 262144 from card) |
| DeepSeek pricing page | `CONTEXT LENGTH ... 1M` and `MAX OUTPUT ... MAXIMUM: 384K` | yes |
| Kimi pricing md | `"kimi-k3" ... "1,048,576 tokens"`, `"kimi-k2.6" ... "262,144 tokens"` | yes |
| Azure Cohere-command-a | `Input: text (131,072 tokens) - Output: text (8,182 tokens)` | yes |
| Qwen3-32B | config `"max_position_embeddings": 40960`; card `Context Length: 32,768 natively and 131,072 tokens with YaRN` | yes |
| Vertex DeepSeek-V3.2 | `65,536 maximum output, 163,840 context length` | yes |
| Command A+ HF bf16 config | `"max_position_embeddings": 200000` | yes |
| Bedrock Kimi K2.5 card | `Context window: 256K tokens Max output tokens: 16K` | yes |

Note on the Azure Cohere row: the re-fetch showed `8,182`, confirming it is printed that way and not a transcription slip of mine.
