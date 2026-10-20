#!/usr/bin/env python3
"""Cohere North — wire-contract middleware for the Guardian lab.

Reproduces the *exact* North platform API observed on a production deployment in front of a REAL
Cohere model (Command R7B via Ollama), so the UNCHANGED GuardianCohere integration can be tested
against the protocol production actually uses — no changes to the integration, no stubbed inference.

Contract reproduced (from the North reference client + our integration):
  POST /api/v1/chat
      Authorization: Bearer <token>
      { "stream": true,
        "messages": [ {"role":"user"|"assistant"|"tool","content":"...", "tool_calls"?:[...]} ],
        "agent":        {"id": "<agent id>"},
        "conversation": {"id": "<conversation/session id>"},
        "system"?: "...", "tools"?: [openai function tools], "temperature"?: n }
      -> generates synchronously against the model, appends the assistant reply to the
         server-side conversation, returns 200 (body is drained/ignored by the client).

  GET /api/v1/conversations/{id}
      Authorization: Bearer <token>
      -> { "messages": [ {"role":"USER"|"CHATBOT"|"TOOL",
                          "content":[{"text":"..."}], "tool_calls"?:[{"name","parameters"}]} ],
           "meta": {"tokens": {"input_tokens": n, "output_tokens": n}} }

Stateful: the conversation history lives here (keyed by conversation.id), exactly like North —
so the integration's reuse mode (send only the new turn) and stateless mode (fresh id + full
transcript) both work. Unknown conversation ids read back as empty (200), matching a pre-created
but empty North conversation.

Env: OLLAMA_URL (http://127.0.0.1:11434), MODEL (command-r7b), LAB_BEARER_TOKEN, PORT (8000),
     ASYNC (if "1", POST returns 202 and generates in the background so the client's poll loop
     is exercised; default synchronous).
"""
import json
import os
import re
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OLLAMA = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
MODEL = os.environ.get("MODEL", "command-r7b")
BEARER = os.environ.get("LAB_BEARER_TOKEN", "lab-secret-token")
PORT = int(os.environ.get("PORT", "8000"))
ASYNC = os.environ.get("ASYNC", "0") == "1"
# Ollama defaults num_ctx to ~4-8K regardless of the model's real max — far too small for Guardian's
# system prompt + tool catalog + incident context. Force a large window (env NUM_CTX). This is itself a
# key smaller-model finding: the context window MUST be sized to the prompt or the model silently
# truncates and the agent loses its instructions/tools.
NUM_CTX = int(os.environ.get("NUM_CTX", "32768"))
# Ollama's model-default temperature (~0.8 when unset) is too high for the low-entropy generation
# tasks a tool-calling agent loop needs: well-formed tool-call JSON against a multi-tool schema, and a
# strict terminal ```json{verdict...}``` block. Left unset, small models (qwen2.5:7b) both fail to
# produce ANY output under a wide tool schema (empty turns) and free-associate a plausible-looking
# fabricated value (e.g. an invented IP) when no real indicator is present in the case yet -- both
# symptoms of excess sampling entropy on structured-output turns. Force it down (env TEMPERATURE).
TEMPERATURE = float(os.environ.get("TEMPERATURE", "0.2"))
# Output cap per reply (Ollama `num_predict`). Ollama serves one request at a time, so without a cap
# one rambling reply blocks every later call until Ollama's own 5-minute limit (seen 2026-09-24: a
# 35B generated ~2,600 tokens on one probe call and XSOAR killed the probe). 0 = uncapped.
MAX_OUTPUT_TOKENS = int(os.environ.get("MAX_OUTPUT_TOKENS", "2048"))
# Ollama evicts an idle model from VRAM after ~5 minutes by default. Measured on the lab 4090:
# a cold request spent 3240ms of its 3670ms total on `load_duration` -- 88% of the request was
# re-reading the model into VRAM, against only 399ms of actual decode. Guardian's tick cadence
# (15s) keeps the model warm WITHIN one investigation, but the first tick of every run after an
# idle gap pays that penalty, and any pause past the eviction window drops it again. Sent
# per-request (Ollama accepts `keep_alive` on /api/chat) rather than set as a server-side env var
# on the Ollama service, so the setting lives in this repo with the rest of the lab config instead
# of in undocumented machine state. -1 pins the model in VRAM indefinitely; the lab box has ample
# headroom (a 7B at 32K ctx sits at ~6.6GB of 24GB).
# NOTE the type matters: Ollama accepts EITHER a number of seconds (-1 = pin forever) OR a Go
# duration STRING ("10m", "24h"). A bare "-1" sent as a string is not a valid Go duration and
# Ollama rejects the entire request with HTTP 400 (observed live -- every generate failed until
# this was coerced). So: numeric values go as real ints, anything else passes through as a
# duration string.
_keep_alive_raw = os.environ.get("KEEP_ALIVE", "-1")
try:
    KEEP_ALIVE = int(_keep_alive_raw)
except ValueError:
    KEEP_ALIVE = _keep_alive_raw

# conversation store: id -> {"messages": [internal msgs], "tokens": {...}}
# internal msg: {"role": "user"|"assistant"|"tool", "text": str, "tool_calls": [{"name","parameters"}]}
STORE = {}
LOCK = threading.Lock()

ROLE_OUT = {"user": "USER", "assistant": "CHATBOT", "tool": "TOOL"}


def log(*a):
    print("[north-mock]", *a, file=sys.stderr, flush=True)


def _north_tools_to_ollama(tools):
    """Our integration sends OpenAI function tools by default; Ollama /api/chat accepts them as-is."""
    return tools or None


_ACTION_BLOCK_RE = re.compile(r"Action:\s*```(?:json)?\s*(\[.*?\])\s*```", re.DOTALL)


def parse_action_block(text, tool_names):
    """command-r's native tool-call text -- ``Action: ```json [{"tool_name": ..., "parameters": {...}}]``` `` -- as
    North-style ``[{"name", "parameters"}]`` calls, keeping only tools that were offered. [] if there is none."""
    m = _ACTION_BLOCK_RE.search(text or "")
    if not m:
        return []
    try:
        items = json.loads(m.group(1))
    except (TypeError, ValueError):
        return []
    calls = []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and item.get("tool_name") in tool_names and isinstance(item.get("parameters"), dict):
            calls.append({"name": item["tool_name"], "parameters": item["parameters"]})
    return calls


def parse_inline_call(text, tool_names):
    """command-a sometimes writes its tool call as function-call text -- ``SearchIncidentsV2(query="x", size=5)`` --
    that Ollama's parser leaves in the message. Read the LAST such call to an offered tool, as ``[{"name",
    "parameters"}]`` (``[]`` if none or the arguments are not plain literals)."""
    import ast
    best = []
    for m in re.finditer(r"\b([A-Za-z][A-Za-z0-9_-]*)\(([^()]*)\)", text or ""):
        name, argtxt = m.group(1), m.group(2)
        if name not in tool_names:
            continue
        try:
            call = ast.parse("f(%s)" % argtxt, mode="eval").body
            if call.args:
                continue
            params = {kw.arg: ast.literal_eval(kw.value) for kw in call.keywords if kw.arg}
        except Exception:
            continue
        best = [{"name": name, "parameters": params}]
    return best


def _ollama_chat(internal_msgs, tools, system):
    """Replay the accumulated conversation to the real model and return (text, tool_calls_north,
    input_tokens, output_tokens)."""
    om = []
    if system:
        om.append({"role": "system", "content": system})
    for m in internal_msgs:
        role = m["role"]
        if role == "assistant":
            entry = {"role": "assistant", "content": m.get("text") or ""}
            if m.get("tool_calls"):
                entry["tool_calls"] = [
                    {"function": {"name": tc["name"], "arguments": tc.get("parameters") or {}}}
                    for tc in m["tool_calls"]
                ]
            om.append(entry)
        elif role == "tool":
            om.append({"role": "tool", "content": m.get("text") or ""})
        else:
            om.append({"role": "user", "content": m.get("text") or ""})

    body = {
        "model": MODEL,
        "stream": False,
        "messages": om,
        "keep_alive": KEEP_ALIVE,
        "options": {"num_ctx": NUM_CTX, "temperature": TEMPERATURE},
    }
    if MAX_OUTPUT_TOKENS > 0:
        body["options"]["num_predict"] = MAX_OUTPUT_TOKENS
    ot = _north_tools_to_ollama(tools)
    if ot:
        body["tools"] = ot

    # observability for the smaller-model context analysis: rough input size
    approx_chars = sum(len(str(m.get("content") or "")) for m in om) + len(json.dumps(ot or []))
    log(f"-> model={MODEL} num_ctx={NUM_CTX} max_out={MAX_OUTPUT_TOKENS} temperature={TEMPERATURE} keep_alive={KEEP_ALIVE} msgs={len(om)} tools={len(ot or [])} ~input_chars={approx_chars} (~{approx_chars // 4} tok)")

    req = urllib.request.Request(
        f"{OLLAMA}/api/chat",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=300) as r:
        resp = json.loads(r.read())

    msg = resp.get("message") or {}
    text = msg.get("content") or ""
    tool_calls_north = []
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function") or {}
        args = fn.get("arguments")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (TypeError, ValueError):
                args = {"_raw": args}
        args = _unwrap_ollama_native_tool_args(args)
        tool_calls_north.append({"name": fn.get("name"), "parameters": args or {}})
    if not text.strip() and not tool_calls_north:
        # An empty reply: say why (Ollama's done_reason and token counts, plus the last message's role), so
        # "model said nothing" can be told apart from "output cut off" or "tool call it failed to parse".
        last = om[-1] if om else {}
        # Keep the exact request so the failure can be replayed against Ollama (a handful at most).
        try:
            dump_dir = os.environ.get("EMPTY_DUMP_DIR", "")
            if dump_dir and len([f for f in os.listdir(dump_dir) if f.startswith("empty_req_")]) < 20:
                with open(os.path.join(dump_dir, "empty_req_%d.json" % int(time.time())), "w") as fh:
                    json.dump(body, fh)
        except Exception as exc:  # diagnostics only
            log(f"could not dump the empty-reply request: {exc}")
        log(f"EMPTY REPLY done_reason={resp.get('done_reason')!r} eval_count={resp.get('eval_count')} "
            f"prompt_eval_count={resp.get('prompt_eval_count')} last_msg_role={last.get('role')!r} "
            f"last_msg_chars={len(str(last.get('content') or ''))} raw_message_keys={sorted(msg.keys())}")
    evals = resp.get("eval_count") or 0
    # Also the case where the visible text is far shorter than what was generated: command-a writes a sentence of
    # narration and then the tool call, and Ollama's parser drops the call while keeping the sentence.
    swallowed_after_text = bool(text.strip()) and evals > len(text) // 3 + 40
    if (not text.strip() or swallowed_after_text) and not tool_calls_north and ot and evals > 0:
        # Ollama swallowed the model's output (it wrote a tool call its parser rejected, which makes a reply of
        # "nothing" even though tokens were generated). A real Cohere North returns the tool call, so recover it:
        # ask the same model again WITHOUT tools -- it then writes the call out as text -- and read the call (or
        # the plain answer) from that text.
        try:
            retry_body = dict(body); retry_body.pop("tools", None)
            req2 = urllib.request.Request(f"{OLLAMA}/api/chat", data=json.dumps(retry_body).encode(),
                                          headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req2, timeout=300) as r2:
                text2 = ((json.loads(r2.read()).get("message") or {}).get("content") or "")
            names = {(t.get("function") or {}).get("name") for t in ot}
            calls = parse_action_block(text2, names)
            if calls:
                tool_calls_north = calls
                log(f"RECOVERED swallowed tool call(s): {[c['name'] for c in calls]}")
            elif _ACTION_BLOCK_RE.search(text2):
                # It is a tool call, but for a tool that was not offered (or malformed): not an answer, so the
                # reply stays empty and the loop's own empty-reply handling takes over.
                log("swallowed reply was a tool call for a tool that was not offered -- left empty")
            elif text2.strip() and not text.strip():
                text = text2
                log(f"RECOVERED swallowed reply as text ({len(text2)} chars)")
        except Exception as exc:  # recovery is best-effort; the empty reply stands
            log(f"recovery of the empty reply failed: {exc}")
    if not tool_calls_north and ot:
        inline = parse_inline_call(text, {(t.get("function") or {}).get("name") for t in ot})
        if inline:
            tool_calls_north = inline
            log(f"RECOVERED inline tool call written as text: {inline[0]['name']}")
    return text, tool_calls_north, resp.get("prompt_eval_count"), resp.get("eval_count")


def _unwrap_ollama_native_tool_args(args):
    """Undo an Ollama chat-template bug observed live on command-r:35b-08-2024-q4_K_M
    (confirmed with a raw, Guardian-code-free `/api/chat` call -- not a north_mock or
    GuardianCohere bug): instead of extracting just the real call arguments into
    `function.arguments`, some Ollama tool-calling templates hand back the model's
    OWN native Cohere-shaped tool-call envelope (`{"tool_name": ..., "parameters":
    {...real args...}}` -- literally Cohere's own documented wire shape) as if that
    whole envelope WERE the arguments. Left unfixed, the real args never reach the
    dispatched command (every call errors), AND -- because the transcript replay
    feeds the model's own prior (malformed) call back into its next turn's history
    -- the model imitates the shape it was just shown and wraps AGAIN, so nesting
    compounds every tick (observed live: single-wrapped tick 0, double-wrapped
    tick 2). Unwrap in a loop (not just once) so it self-heals regardless of how
    deep an already-in-flight conversation's nesting has grown.

    Deliberately narrow: only unwraps when `args` looks EXACTLY like this specific
    envelope (a dict whose ONLY meaningful key besides `tool_name` is a dict-shaped
    `parameters`) -- a real call that happens to have a top-level arg named
    `parameters` for some other tool is never plausible here (no Guardian tool
    schema defines one), but this stays conservative rather than unwrapping on any
    dict containing a "parameters" key.
    """
    seen = 0
    while (
        isinstance(args, dict)
        and "tool_name" in args
        and isinstance(args.get("parameters"), dict)
        and set(args.keys()) <= {"tool_name", "parameters", "tool_call_id", "id"}  # command-a also adds the call id
        and seen < 5  # defensive ceiling -- real nesting never observed past 2
    ):
        args = args["parameters"]
        seen += 1
    return args


def _generate(conversation_id, incoming_messages, tools, system):
    """Append the incoming turn to the conversation, generate the assistant reply against the real
    model, append it. Synchronous; called inline (or in a thread for ASYNC mode)."""
    with LOCK:
        convo = STORE.setdefault(conversation_id, {"messages": [], "tokens": {}})
        for m in incoming_messages:
            role = m.get("role") or "user"
            text = m.get("content")
            if isinstance(text, list):  # OpenAI content-parts -> flatten text
                text = "".join(p.get("text", "") for p in text if isinstance(p, dict))
            internal = {"role": role if role in ("user", "assistant", "tool") else "user", "text": text or ""}
            if m.get("tool_calls"):
                internal["tool_calls"] = [
                    {"name": (tc.get("function") or {}).get("name"),
                     "parameters": _args_obj((tc.get("function") or {}).get("arguments"))}
                    for tc in m["tool_calls"]
                ]
            convo["messages"].append(internal)
        history = list(convo["messages"])

    text, tool_calls_north, in_tok, out_tok = _ollama_chat(history, tools, system)

    with LOCK:
        convo = STORE[conversation_id]
        assistant = {"role": "assistant", "text": text}
        if tool_calls_north:
            assistant["tool_calls"] = tool_calls_north
        convo["messages"].append(assistant)
        convo["tokens"] = {"input_tokens": in_tok, "output_tokens": out_tok}
    log(f"generated on {conversation_id}: text={text[:60]!r} tool_calls={len(tool_calls_north)}")


def _args_obj(args):
    if isinstance(args, str):
        try:
            return json.loads(args)
        except (TypeError, ValueError):
            return {}
    return args or {}


def _conversation_out(conversation_id):
    convo = STORE.get(conversation_id) or {"messages": [], "tokens": {}}
    out_msgs = []
    for m in convo["messages"]:
        entry = {"role": ROLE_OUT.get(m["role"], "USER")}
        entry["content"] = [{"text": m["text"]}] if m.get("text") else []
        if m.get("tool_calls"):
            entry["tool_calls"] = m["tool_calls"]
        out_msgs.append(entry)
    # Live-caught 2026-08-24: GuardianCohere's cost/telemetry attribution used
    # the integration instance's static "Model label" param, never anything
    # server-observed -- switching this mock between models (as this session
    # did four times) silently misattributed every subsequent run's cost to
    # whichever label was configured when the instance was last edited. This
    # mock, unlike the real North endpoint, DOES know exactly which model
    # actually served the request (MODEL, from its own env) -- echo it so the
    # client can prefer an observed value over the declared one.
    return {"messages": out_msgs, "meta": {"tokens": convo.get("tokens") or {}, "model": MODEL}}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # quiet default logging

    def _auth_ok(self):
        return self.headers.get("Authorization") == f"Bearer {BEARER}"

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._auth_ok():
            return self._send(401, {"error": "unauthorized"})
        if self.path.startswith("/api/v1/conversations/"):
            cid = self.path[len("/api/v1/conversations/"):].split("?")[0]
            return self._send(200, _conversation_out(cid))
        if self.path == "/healthz":
            return self._send(200, {"ok": True, "model": MODEL, "conversations": len(STORE)})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth_ok():
            return self._send(401, {"error": "unauthorized"})
        if self.path.split("?")[0] != "/api/v1/chat":
            return self._send(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (TypeError, ValueError):
            return self._send(400, {"error": "invalid json"})

        conversation_id = (payload.get("conversation") or {}).get("id")
        if not conversation_id:
            return self._send(400, {"error": "conversation.id required"})
        messages = payload.get("messages") or []
        tools = payload.get("tools")
        system = payload.get("system")

        if ASYNC:
            threading.Thread(target=_generate, args=(conversation_id, messages, tools, system), daemon=True).start()
            return self._send(202, {"status": "accepted", "conversation": {"id": conversation_id}})
        try:
            _generate(conversation_id, messages, tools, system)
        except Exception as exc:  # surface model/transport errors as 5xx (like a real backend)
            log(f"generate error: {exc}")
            return self._send(502, {"error": f"generation failed: {exc}"})
        return self._send(200, {"status": "ok", "conversation": {"id": conversation_id}})


if __name__ == "__main__":
    log(f"starting on :{PORT} model={MODEL} ollama={OLLAMA} async={ASYNC} bearer={'set' if BEARER else 'none'}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
