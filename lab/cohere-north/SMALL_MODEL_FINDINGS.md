# Guardian on a small model — findings from a 20-incident lab run (2026-07-07)

Ran the **real** Guardian reasoning loop against **20 existing Splunk-Finding incidents** on `xsoar6`,
with the LLM served by a **self-hosted small model on the lab GPU** (see `README.md`). Goal: see what a
small model produces on real investigations and what content must change for smaller models. A production
Cohere North model is typically **~70B** (more capable than this lab's 7B) — so these are **worst-case** findings
that harden the content for every model size.

## Setup
- **Model:** `qwen2.5:7b` (7B) on an NVIDIA L4, `num_ctx=32768`, behind the Cohere-North wire middleware.
  *(Command R7B — the real Cohere small model — validated all conversational paths but its Ollama build
  won't emit tool calls, and the Guardian loop is 100% tool-driven, so a reliable 7B tool-caller was used
  as the small-model stand-in. The findings are model-size findings, not model-brand findings.)*
- **Harness:** `eval_incidents.py` — per incident: reset `Guardian.Loop`, run `GuardianReasoningTick`
  with a targeted investigation prompt, advance ticks (cap 4 invocations) until it concludes.
- **Integration health:** **0 crashes across 197 model calls.** (This run also caught a real production
  bug — `_headers()` shadowed by `BaseClient.self._headers` — now fixed.)

## Headline numbers
| Metric | Value | Implication |
|---|---|---|
| Base prompt (tick 0) | **~19,000 tokens** (system prompt + **33 tools**) | Huge fixed cost before any work |
| Per-call input tokens | **median 21.6K, max 26.8K** (197 calls) | **76% of calls >20K tok**; peaks near the 32K ceiling |
| Concluded | **12/20 (60%)**; 40% hit the tick cap with no verdict | Small model doesn't converge |
| Avg ticks to conclude | 3.5 (max 6) | |
| Wall-clock | ~67s/incident (7B on L4) | Every tick re-processes ~21K tokens |

## Failure modes (with examples)

1. **Incident-ID grounding confusion (most serious).** The model loses track of *which* incident it's on
   and drifts to a **neighboring** ID:
   - investigating **25013** → verdict discusses "**incident 25014**"
   - investigating **25005** → "War Room entries for **incident 25007**"
   - investigating **25022** → "unable to fetch War Room for **incident 25023**"
   The specific target ID gets lost inside ~21K tokens of tool catalog + boilerplate.

2. **Non-convergence / wandering (40% never conclude).** The small model repeats the **same tool** without
   synthesizing: `ip, ip` (25008, 25004), `findIndicators, findIndicators` (25012, 25010),
   `splunk-search, splunk-search` (25023). It doesn't track what it already did.

3. **Wasted enrichment on internal IPs.** It repeatedly runs reputation/whois on **RFC1918** addresses
   (10.x / 172.16.x) that have no public reputation (25019, 25016, 25015, 25009), burning ticks and then
   concluding "it's a private IP, no info" — missing the actual detection logic.

4. **Hallucinated / irrelevant tools.** On a **malware/endpoint** alert it ran `whois` on a *hostname*
   (25024) and `ews-search-mailbox` / talked about "phishing, mailbox search" (25020, 24990) — inventing an
   email investigation unrelated to the alert.

5. **It does get simple cases right.** Clear alerts land grounded verdicts: **25025 Brute Force** ("failed
   auths followed by success — brute-force"), **25011 Expired User**, **25021 Anomalous Process**. So the
   loop, protocol, and tool-calling *work*; quality degrades with investigation complexity + context size.

## Recommendations — smaller-model content (prioritized)

1. **Shrink the per-tick context (biggest lever).** Ship a **small-model tool profile**: expose ~8–12
   curated triage tools (getIncidents, getEntries, SearchIncidentsV2, ip/domain/file reputation,
   splunk-search, closeInvestigation) instead of **33**, and a **terse system-prompt variant**. Target a
   base prompt of ~6–8K instead of ~19K. Fixes cost, speed, *and* likely #1/#2 (less to lose the ID in).

2. **Anchor the target incident every tick.** Pin `INVESTIGATING INCIDENT <id>: <name>` at the **top and
   bottom** of each tick's context (a persistent anchor the model can't drift from). Directly targets the
   ID-confusion failure.

3. **Add small-model guardrails to the triage skill:**
   - "Do **not** run reputation/whois/threat-intel on RFC1918 / internal IPs."
   - "Do **not** call a tool you've already called with the same args; if a tool returned nothing, move on."
   - "Conclude within N ticks; if uncertain, escalate — don't keep enriching."

4. **Lower `MAX_TICKS` / tighten the loop for small models** (they wander) and **de-dupe tool calls** in the
   bridge (drop a repeat call with identical args within a run).

5. **Structured-output verdict.** Force the conclusion into a small JSON schema (verdict, confidence,
   indicators, action) via `response_format` so the narration can't ramble.

6. **For a production model:** confirm its tool-call wire format against the live endpoint (our lab used
   `tool_format=openai`; command-r7b needed a different one). One captured tool-calling production request removes
   the guesswork.

## What to build (proposed)
- A **`xsoar_case_triage_small` skill** (terse, grounded, with the RFC1918/convergence guardrails).
- A **`small_model` mode in GuardianToolCatalogBuilder** that emits the curated ~10-tool subset.
- The **incident-ID anchor** in GuardianPromptBuilder.
- Optional: `response_format` verdict schema + tick-cap/tool-dedupe tuning.

~~These are additive (a profile/skill), so the full-size Gemini/70B path is unchanged.~~ **This claim
was wrong and stayed wrong for months** (2026-08-22 correction): the accommodations above — the tier-0
tool-catalogue gate, `max_tool_def_tokens=4000`, the empty-turn `tool_choice="required"` retry, the
punctuation-based trailed-off heuristic, and the per-tool-name dispatch cap — all shipped
**unconditional**, not as an opt-in profile. A customer on Command R+/Command A/Command A+ would have
silently gotten every one of them: a catalogue truncated from 34 tools to ~10 from tick 0, forced tool
calls on turns where the model legitimately had nothing more to say, and a conclusion-detection
heuristic tuned to one 7B's specific failure text. This was discovered via live testing on 2026-08-21/22
(see [`Packs/Guardian/Scripts/GuardianCommon/GuardianCommon.py`](../../Packs/Guardian/Scripts/GuardianCommon/GuardianCommon.py)'s
`GUARDIAN_TIER_PROFILES` docstring for the full audit) and fixed the same day: every accommodation
above is now gated behind `guardian_settings.model_tier` ("small"/"medium"/"large", set via the LLM
provider integration's own "Model size" dropdown — see `GuardianCohere.yml`'s `model_tier` param),
resolved once per tick by `GuardianCommon.guardian_resolve_tier` and consumed via
`guardian_tick_load_settings()["tier_profile"]`. Unset/unreadable/unrecognized still fails safe to
"small" — these findings remain the worst-case, most-constrained baseline; they are just no longer the
ONLY case.
