#!/usr/bin/env python3
"""Drive the UNCHANGED GuardianCohere integration against the Cohere-North middleware + real Command R7B.

Exercises: test-module, a simple turn, and a full tool round-trip (tool_calls -> tool result -> final
answer), in both reuse and stateless conversation modes. Nothing in GuardianCohere.py is modified —
this imports it as-is and calls its real command functions."""
import json
import sys

from GuardianCohere import build_client, guardian_llm_chat_command, test_module

ENDPOINT = "http://127.0.0.1:8000"
BEARER = "lab-secret-token"
AGENT_ID = "lab-agent-0001"
MODEL = "command-r7b"

WEATHER_TOOL = [{
    "type": "function",
    "function": {
        "name": "get_weather",
        "description": "Get the current weather for a city.",
        "parameters": {
            "type": "object",
            "properties": {"city": {"type": "string", "description": "City name"}},
            "required": ["city"],
        },
    },
}]


def _params(mode, session_id, tool_format="openai"):
    return {
        "endpoint_url": ENDPOINT,
        "agent_id": AGENT_ID,
        "session_id": session_id,
        "bearer_token": BEARER,
        "conversation_mode": mode,
        "tool_format": tool_format,
        "model": MODEL,
        "request_timeout": "300",
    }


def _chat(client, messages, tools=None, tool_choice=None):
    args = {"messages": json.dumps(messages)}
    if tools:
        args["tools"] = json.dumps(tools)
    if tool_choice:
        args["tool_choice"] = tool_choice
    res = guardian_llm_chat_command(client, args)
    return res.outputs


def hr(title):
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


def show(tag, out):
    msg = (out.get("choices") or [{}])[0].get("message", {}) or {}
    usage = out.get("usage") or {}
    print(f"[{tag}] finish_reason={out.get('finish_reason')} model={out.get('model')} "
          f"tokens(in/out)={usage.get('prompt_tokens')}/{usage.get('completion_tokens')}")
    if msg.get("content"):
        print(f"[{tag}] content: {msg['content'][:300]}")
    for tc in msg.get("tool_calls") or []:
        print(f"[{tag}] tool_call: {tc['function']['name']}({tc['function']['arguments']})")
    return msg


def _tool_round_trip(label, client, failures):
    """Tool round-trip (tool_calls -> tool result -> final answer). ENV-08/S2:
    a model that never emits a tool call at all is the campaign-halting
    `tools=false` condition ENV-18 declares -- it MUST land in `failures`,
    not just print a "small-model behavior" note and let the run report a
    clean pass."""
    msgs = [{"role": "user", "content": "What's the weather in Riyadh right now? Use the get_weather tool."}]
    out1 = _chat(client, msgs, tools=WEATHER_TOOL, tool_choice="auto")
    m1 = show(f"{label}-tool-call", out1)
    tool_calls = m1.get("tool_calls") or []
    if not tool_calls:
        failures.append(f"{label} tool: no tool_call emitted")
        return
    tc = tool_calls[0]
    # execute the "tool" (canned result) and feed it back
    tool_result = {"role": "tool", "tool_call_id": tc.get("id"), "name": tc["function"]["name"],
                   "content": json.dumps({"city": "Riyadh", "temp_c": 41, "condition": "sunny"})}
    assistant_msg = {"role": "assistant", "content": m1.get("content"), "tool_calls": tool_calls}
    out2 = _chat(client, msgs + [assistant_msg, tool_result], tools=WEATHER_TOOL)
    m2 = show(f"{label}-final", out2)
    if not m2.get("content"):
        failures.append(f"{label} tool: no final content")


def main():
    failures = []

    # ---- REUSE MODE ----
    hr("REUSE MODE — test-module (read-only probe on the session conversation)")
    client = build_client(_params("reuse", "lab-reuse-simple"), verify=False, proxy=False)
    print("test_module ->", test_module(client))

    hr("REUSE MODE — simple turn (real Command R7B)")
    out = _chat(client, [{"role": "user", "content": "Reply with a one-sentence hello from the SOC."}])
    m = show("simple", out)
    if not m.get("content"):
        failures.append("reuse simple: no content")

    hr("REUSE MODE — tool round-trip (tool_calls -> tool result -> final answer)")
    tclient = build_client(_params("reuse", "lab-reuse-tools"), verify=False, proxy=False)
    _tool_round_trip("reuse", tclient, failures)

    # ---- STATELESS MODE ----
    hr("STATELESS MODE — test-module (throwaway round-trip on a fresh conversation)")
    sclient = build_client(_params("stateless", ""), verify=False, proxy=False)
    print("test_module ->", test_module(sclient))

    hr("STATELESS MODE — simple turn (fresh conversation id per call)")
    out = _chat(sclient, [{"role": "user", "content": "In one word, are you operational?"}])
    m = show("stateless", out)
    if not m.get("content"):
        failures.append("stateless simple: no content")

    hr("STATELESS MODE — tool round-trip (tool_calls -> tool result -> final answer)")
    # The reference deployment's default is conversation_mode=stateless (§5.4) -- the reuse
    # leg above doesn't prove stateless tool-calling works at all (ENV-08's own
    # documented coverage gap). Fresh client/session per the stateless
    # convention used elsewhere in this file.
    stclient = build_client(_params("stateless", ""), verify=False, proxy=False)
    _tool_round_trip("stateless", stclient, failures)

    hr("RESULT")
    if failures:
        print("FAILURES:", failures)
        sys.exit(1)
    print("ALL LAB CHECKS PASSED — the unchanged GuardianCohere integration works against the North "
          "wire contract backed by a real Command R7B.")


if __name__ == "__main__":
    main()
