"""GuardianCohere unit tests.

No live Cohere North endpoint is available in this environment, so every HTTP boundary is mocked at
``CohereNorthClient._http_request`` (POST /api/v1/chat drains a discarded stream; GET
/api/v1/conversations/{id} returns a North conversation object). ``time.sleep`` is patched so the
conversation-poll loop never actually sleeps.

Coverage:
  - pure translation helpers (content flattening, system extraction, reuse-delta slicing, North
    message/tool translation, reply text/tool_calls extraction, usage mapping)
  - request-body construction for both conversation modes (reuse-delta vs stateless-full)
  - the conversation poll (immediate hit, poll-then-hit, deadline error)
  - response normalization into the canonical Guardian.LLM.Completion shape
  - end-to-end guardian-llm-chat / test-module
  - build_client validation + bearer-token resolution

``test_module`` (the integration command) is imported aliased to ``run_test_module_command`` so
pytest's ``test_*`` collection doesn't pick up the imported function object itself as a bogus test.
"""

import copy
import json
import re
import time
import uuid

import pytest
from CommonServerPython import DemistoException

from GuardianCohere import (
    CONVERSATION_MODE_PER_RUN,
    CONVERSATION_MODE_REUSE,
    CONVERSATION_MODE_STATELESS,
    RUN_CONTEXT_KEY,
    RUN_MAX_AGE_SECONDS,
    RUN_MAX_ENTRIES,
    CohereNorthClient,
    RUN_STORE_ATTEMPTS,
    _compaction_mark,
    _conversation_continues,
    _investigation_id,
    _prune_runs,
    _run_key,
    _store_run,
    _content_to_text,
    _extract_reply_text,
    _extract_reply_tool_calls,
    _extract_system_text,
    _last_role_is_assistant,
    _messages_after_last_assistant,
    _to_north_messages,
    _to_north_tools,
    _usage_from_conversation,
    build_client,
    guardian_llm_chat_command,
    test_module as run_test_module_command,
)


def _client(
    conversation_mode=CONVERSATION_MODE_REUSE,
    tool_format="openai",
    session_id="sess-123",
    model_label="cohere-north",
    model_tier="small",
):
    return CohereNorthClient(
        endpoint="https://north.example.com",
        agent_id="agent-abc",
        session_id=session_id,
        bearer_token="tok-xyz",
        model_label=model_label,
        model_tier=model_tier,
        conversation_mode=conversation_mode,
        tool_format=tool_format,
        verify=False,
        proxy=False,
        timeout=200,
    )


def _convo(text="hello there", tool_calls=None, role="CHATBOT", input_tokens=11, output_tokens=7, extra_blocks=None):
    """Build a North conversation object whose last message is an assistant reply."""
    content = []
    if extra_blocks:
        content.extend(extra_blocks)
    if text is not None:
        content.append({"text": text})
    last = {"role": role, "content": content}
    if tool_calls is not None:
        last["tool_calls"] = tool_calls
    return {
        "messages": [{"role": "USER", "content": [{"text": "hi"}]}, last],
        "meta": {"tokens": {"input_tokens": input_tokens, "output_tokens": output_tokens}},
    }


def _wire(mocker, client, get_responses, no_sleep=True):
    """Patch _http_request: POST -> "" (a discarded SSE stream); each GET -> the next item in
    ``get_responses`` (a single dict reused for every GET, or a list consumed in order). Returns the
    mock so tests can inspect call order / the POST body."""
    if no_sleep:
        mocker.patch("GuardianCohere.time.sleep")

    get_iter = None if isinstance(get_responses, dict) else iter(get_responses)

    def _side_effect(*args, **kwargs):
        if kwargs.get("method") == "POST":
            return ""
        return get_responses if get_iter is None else next(get_iter)

    return mocker.patch.object(client, "_http_request", side_effect=_side_effect)


""" ------------------------- pure translation helpers ------------------------- """


def test_content_to_text_variants():
    assert _content_to_text("hello") == "hello"
    assert _content_to_text("") is None
    assert _content_to_text(None) is None
    assert _content_to_text([{"text": "a"}, {"text": "b"}, {"type": "image_url"}]) == "ab"
    assert _content_to_text(["x", {"text": "y"}]) == "xy"


def test_extract_system_text_concatenates():
    messages = [
        {"role": "system", "content": "sysA"},
        {"role": "user", "content": "u"},
        {"role": "system", "content": [{"text": "sysB"}]},
    ]
    assert _extract_system_text(messages) == "sysA\nsysB"


def test_messages_after_last_assistant():
    messages = [
        {"role": "system", "content": "s"},
        {"role": "user", "content": "u1"},
        {"role": "assistant", "content": "a1"},
        {"role": "tool", "tool_call_id": "c1", "content": "result"},
        {"role": "user", "content": "u2"},
    ]
    turn = _messages_after_last_assistant(messages)
    assert turn == [
        {"role": "tool", "tool_call_id": "c1", "content": "result"},
        {"role": "user", "content": "u2"},
    ]


def test_messages_after_last_assistant_no_assistant_returns_non_system():
    messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "u1"}]
    assert _messages_after_last_assistant(messages) == [{"role": "user", "content": "u1"}]


def test_to_north_messages_role_and_toolcalls():
    tool_calls = [{"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{}"}}]
    messages = [
        {"role": "system", "content": "sys"},  # excluded
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": None, "tool_calls": tool_calls},
        {"role": "tool", "tool_call_id": "c1", "name": "f", "content": "res"},
    ]
    out = _to_north_messages(messages)
    assert out == [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "tool_calls": tool_calls},
        {"role": "tool", "content": "res", "tool_call_id": "c1", "name": "f"},
    ]


def test_to_north_tools_openai_passthrough():
    tools = [{"type": "function", "function": {"name": "f", "parameters": {"type": "object"}}}]
    assert _to_north_tools(tools, "openai") == tools
    assert _to_north_tools(None, "openai") is None


def test_to_north_tools_cohere_conversion():
    tools = [
        {
            "type": "function",
            "function": {
                "name": "ip_reputation",
                "description": "look up ip",
                "parameters": {
                    "type": "object",
                    "properties": {"ip": {"type": "string", "description": "the ip"}, "n": {"type": "integer"}},
                    "required": ["ip"],
                },
            },
        }
    ]
    out = _to_north_tools(tools, "cohere")
    assert out == [
        {
            "name": "ip_reputation",
            "description": "look up ip",
            "parameter_definitions": {
                "ip": {"description": "the ip", "type": "str", "required": True},
                "n": {"description": "", "type": "int", "required": False},
            },
        }
    ]


def test_last_role_is_assistant():
    assert _last_role_is_assistant({"messages": [{"role": "CHATBOT"}]}) is True
    assert _last_role_is_assistant({"messages": [{"role": "assistant"}]}) is True
    assert _last_role_is_assistant({"messages": [{"role": "USER"}]}) is False
    assert _last_role_is_assistant({"messages": []}) is False
    assert _last_role_is_assistant(None) is False


def test_extract_reply_text_prefers_last_block():
    # 2 blocks -> the last (answer) block, not the leading plan/citation block.
    assert _extract_reply_text({"content": [{"text": "plan"}, {"text": "answer"}]}) == "answer"
    assert _extract_reply_text({"content": [{"text": "only"}]}) == "only"
    assert _extract_reply_text({"content": "plain"}) == "plain"
    assert _extract_reply_text({"message": "fallback"}) == "fallback"
    assert _extract_reply_text({"content": []}) is None


def test_extract_reply_tool_calls_cohere_shape():
    out = _extract_reply_tool_calls({"tool_calls": [{"name": "f", "parameters": {"ip": "8.8.8.8"}}]})
    assert out == [
        {"id": "call_0", "type": "function", "function": {"name": "f", "arguments": json.dumps({"ip": "8.8.8.8"})}}
    ]


def test_extract_reply_tool_calls_openai_shape_passthrough():
    out = _extract_reply_tool_calls(
        {"tool_calls": [{"id": "x", "type": "function", "function": {"name": "f", "arguments": '{"a":1}'}}]}
    )
    assert out == [{"id": "x", "type": "function", "function": {"name": "f", "arguments": '{"a":1}'}}]


def test_extract_reply_tool_calls_none():
    assert _extract_reply_tool_calls({"content": "x"}) is None


def test_usage_from_conversation():
    usage = _usage_from_conversation({"meta": {"tokens": {"input_tokens": 10, "output_tokens": 4}}})
    assert usage == {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14, "cached_tokens": None}
    empty = _usage_from_conversation({})
    assert empty == {"prompt_tokens": None, "completion_tokens": None, "total_tokens": None, "cached_tokens": None}


""" ------------------------- build_request_body ------------------------- """


def test_build_request_body_reuse_sends_delta_and_session_id():
    client = _client(conversation_mode=CONVERSATION_MODE_REUSE, session_id="sess-123")
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "u1"},
        {"role": "assistant", "content": "a1"},
        {"role": "user", "content": "u2"},
    ]
    body = client.build_request_body({"messages": messages}, "sess-123")
    assert body["conversation"] == {"id": "sess-123"}
    assert body["agent"] == {"id": "agent-abc"}
    assert body["stream"] is True
    assert body["system"] == "sys"
    # reuse mode -> only the new turn (after last assistant) goes in messages
    assert body["messages"] == [{"role": "user", "content": "u2"}]


def test_build_request_body_stateless_sends_full_transcript():
    client = _client(conversation_mode=CONVERSATION_MODE_STATELESS)
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "u1"},
        {"role": "assistant", "content": "a1"},
        {"role": "user", "content": "u2"},
    ]
    body = client.build_request_body({"messages": messages}, "fresh-uuid")
    assert body["conversation"] == {"id": "fresh-uuid"}
    assert body["system"] == "sys"
    # stateless -> full transcript minus system
    assert body["messages"] == [
        {"role": "user", "content": "u1"},
        {"role": "assistant", "content": "a1"},
        {"role": "user", "content": "u2"},
    ]


def test_build_request_body_includes_tools_and_temperature():
    client = _client()
    tools = [{"type": "function", "function": {"name": "f", "parameters": {"type": "object"}}}]
    body = client.build_request_body(
        {"messages": [{"role": "user", "content": "hi"}], "tools": tools, "tool_choice": "auto", "temperature": 0.3},
        "sess-123",
    )
    assert body["tools"] == tools
    assert "tool_choice" not in body  # "auto" is North's default; it only accepts REQUIRED or NONE
    assert body["temperature"] == 0.3


def test_stateless_mode_mints_fresh_conversation_id():
    client = _client(conversation_mode=CONVERSATION_MODE_STATELESS, session_id="")
    id1 = client._conversation_id_for_call()
    id2 = client._conversation_id_for_call()
    assert id1 != id2  # fresh UUID per call
    assert _client(conversation_mode=CONVERSATION_MODE_REUSE)._conversation_id_for_call() == "sess-123"


""" ------------------------- poll_conversation ------------------------- """


def test_poll_conversation_returns_on_new_assistant(mocker):
    client = _client()
    convo = _convo(text="done")  # 2 messages, last is CHATBOT
    mocker.patch("GuardianCohere.time.sleep")
    mocker.patch.object(client, "_http_request", return_value=convo)
    assert client.poll_conversation("sess-123", baseline_count=0) is convo


def test_poll_conversation_ignores_stale_prior_reply(mocker):
    """CRITICAL regression (finding #1/#4): on a reused stateful conversation the poll must NOT return
    the PRIOR turn's assistant tail — it must wait for a genuinely new terminal assistant message
    (message count grown past the pre-submit baseline)."""
    client = _client()
    stale = {  # count 2 == baseline: prior turn's reply "OLD" still the tail
        "messages": [{"role": "USER", "content": [{"text": "q1"}]}, {"role": "CHATBOT", "content": [{"text": "OLD"}]}]
    }
    grown = {  # count 4 > baseline, new reply "NEW"
        "messages": [
            {"role": "USER", "content": [{"text": "q1"}]},
            {"role": "CHATBOT", "content": [{"text": "OLD"}]},
            {"role": "USER", "content": [{"text": "q2"}]},
            {"role": "CHATBOT", "content": [{"text": "NEW"}]},
        ]
    }
    mocker.patch("GuardianCohere.time.sleep")
    mocker.patch.object(client, "_http_request", side_effect=[stale, grown])
    convo = client.poll_conversation("sess-123", baseline_count=2)
    assert convo is grown
    assert client.normalize_response(convo, "sess-123")["choices"][0]["message"]["content"] == "NEW"


def test_poll_conversation_waits_for_assistant_terminal(mocker):
    client = _client()
    not_ready = {"messages": [{"role": "USER", "content": [{"text": "hi"}]}]}  # last is USER
    ready = _convo(text="done")
    mocker.patch("GuardianCohere.time.sleep")
    mocker.patch.object(client, "_http_request", side_effect=[not_ready, ready])
    assert client.poll_conversation("sess-123", baseline_count=0) is ready


def test_poll_conversation_raises_on_deadline_never_fabricates(mocker):
    """Findings #2/#3: on deadline exhaustion the poll RAISES; it never returns a user-terminated
    conversation that normalize would echo back as a fake assistant answer."""
    client = _client()
    mocker.patch("GuardianCohere.time.sleep")
    # advancing clock: deadline base, then one in-window tick, then past-deadline
    mocker.patch("GuardianCohere.time.time", side_effect=[1000.0, 1000.0, 9000.0])
    only_user = {"messages": [{"role": "USER", "content": [{"text": "my own prompt"}]}]}
    mocker.patch.object(client, "_http_request", return_value=only_user)
    with pytest.raises(DemistoException) as exc:
        client.poll_conversation("sess-123", baseline_count=0)
    assert "did not return a new assistant reply" in str(exc.value)


def test_poll_conversation_raises_when_reads_all_fail(mocker):
    client = _client()
    mocker.patch("GuardianCohere.time.sleep")
    mocker.patch("GuardianCohere.time.time", side_effect=[1000.0, 1000.0, 9000.0])
    mocker.patch.object(client, "_http_request", side_effect=DemistoException("boom"))
    with pytest.raises(DemistoException) as exc:
        client.poll_conversation("sess-123", baseline_count=0)
    assert "did not return a new assistant reply" in str(exc.value)


""" ------------------------- normalize_response ------------------------- """


def test_normalize_response_text_and_usage():
    client = _client(model_label="cohere-north")
    result = client.normalize_response(_convo(text="the answer", input_tokens=10, output_tokens=4), "sess-123")
    assert result["content_filter"] is False
    assert result["finish_reason"] == "stop"
    assert result["model"] == "cohere-north"
    assert result["choices"][0]["message"]["content"] == "the answer"
    assert result["choices"][0]["message"]["tool_calls"] is None
    assert result["usage"] == {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14, "cached_tokens": None}


def test_normalize_response_prefers_observed_model_over_declared_label():
    # Live-caught 2026-08-24: the declared "Model label" is free text an
    # operator can forget to update when the backing model changes (this
    # session's lab mock was swapped between qwen2.5:7b and command-r 32B
    # four times without updating the instance's Model label, silently
    # misattributing every subsequent run's cost). If North's response
    # carries an observed model identifier, prefer it.
    client = _client(model_label="cohere-north")
    convo = _convo(text="the answer")
    convo["meta"]["model"] = "command-r:35b-08-2024-q4_K_M"
    result = client.normalize_response(convo, "sess-123")
    assert result["model"] == "command-r:35b-08-2024-q4_K_M"


def test_normalize_response_falls_back_to_declared_label_when_no_observed_model():
    # No-op guarantee for a backend (e.g. real production North) that never
    # echoes an observed model: behavior must be byte-for-byte unchanged.
    client = _client(model_label="cohere-north")
    convo = _convo(text="the answer")  # meta has no "model" key
    assert "model" not in convo["meta"]
    result = client.normalize_response(convo, "sess-123")
    assert result["model"] == "cohere-north"


def test_normalize_response_ignores_blank_observed_model():
    client = _client(model_label="cohere-north")
    convo = _convo(text="the answer")
    convo["meta"]["model"] = "   "
    result = client.normalize_response(convo, "sess-123")
    assert result["model"] == "cohere-north"


def test_normalize_response_tool_calls_finish_reason():
    client = _client()
    convo = _convo(text=None, tool_calls=[{"name": "ip_reputation", "parameters": {"ip": "8.8.8.8"}}])
    result = client.normalize_response(convo, "sess-123")
    assert result["finish_reason"] == "tool_calls"
    tc = result["choices"][0]["message"]["tool_calls"]
    assert tc[0]["function"]["name"] == "ip_reputation"
    assert json.loads(tc[0]["function"]["arguments"]) == {"ip": "8.8.8.8"}


def test_normalize_response_id_falls_back_to_conversation_id():
    client = _client()
    result = client.normalize_response({"messages": [{"role": "CHATBOT", "content": "x"}]}, "sess-xyz")
    assert result["id"] == "sess-xyz"


""" ------------------------- end-to-end chat_completion / guardian-llm-chat ------------------------- """


def test_chat_completion_end_to_end_reuse(mocker):
    client = _client(conversation_mode=CONVERSATION_MODE_REUSE, session_id="sess-123")
    baseline = {  # pre-submit state: 2 messages, ends in the PRIOR turn's assistant reply
        "messages": [{"role": "USER", "content": [{"text": "hi"}]}, {"role": "CHATBOT", "content": [{"text": "prev"}]}]
    }
    grown = {  # after our turn: 4 messages, new reply "pong"
        "messages": [
            {"role": "USER", "content": [{"text": "hi"}]},
            {"role": "CHATBOT", "content": [{"text": "prev"}]},
            {"role": "USER", "content": [{"text": "ping"}]},
            {"role": "CHATBOT", "content": [{"text": "pong"}]},
        ],
        "meta": {"tokens": {"input_tokens": 11, "output_tokens": 7}},
    }
    mock_http = _wire(mocker, client, [baseline, grown])  # GET(baseline), then GET(poll)
    result = client.chat_completion({"messages": [{"role": "user", "content": "ping"}]})

    assert result["choices"][0]["message"]["content"] == "pong"
    assert result["finish_reason"] == "stop"

    # Call order in reuse mode: GET(baseline) -> POST(chat) -> GET(poll).
    calls = mock_http.call_args_list
    assert calls[0].kwargs["method"] == "GET"  # baseline read (no write yet)
    post_kwargs = calls[1].kwargs
    assert post_kwargs["method"] == "POST"
    assert post_kwargs["full_url"] == "https://north.example.com/api/v1/chat"
    assert post_kwargs["headers"]["Authorization"] == "Bearer tok-xyz"
    assert post_kwargs["json_data"]["conversation"] == {"id": "sess-123"}
    assert post_kwargs["json_data"]["agent"] == {"id": "agent-abc"}
    assert calls[2].kwargs["method"] == "GET"
    assert calls[2].kwargs["full_url"] == "https://north.example.com/api/v1/conversations/sess-123"
    # POST retries only on 429 (non-idempotent turn must not double-submit on 5xx).
    assert post_kwargs["status_list_to_retry"] == [429]


def test_chat_completion_stateless_no_baseline_read(mocker):
    client = _client(conversation_mode=CONVERSATION_MODE_STATELESS, session_id="")
    mock_http = _wire(mocker, client, _convo(text="pong"))
    result = client.chat_completion({"messages": [{"role": "user", "content": "ping"}]})
    assert result["choices"][0]["message"]["content"] == "pong"
    # stateless: no pre-submit baseline GET -> first call is the POST.
    assert mock_http.call_args_list[0].kwargs["method"] == "POST"


def test_guardian_llm_chat_command_shape(mocker):
    client = _client(conversation_mode=CONVERSATION_MODE_STATELESS)
    _wire(mocker, client, _convo(text="hi there"))
    args = {"messages": json.dumps([{"role": "user", "content": "say hi"}])}
    result = guardian_llm_chat_command(client, args)
    assert result.outputs_prefix == "Guardian.LLM.Completion"
    assert result.outputs["choices"][0]["message"]["content"] == "hi there"
    assert result.outputs["content_filter"] is False
    assert "Guardian LLM Completion" in result.readable_output


def test_guardian_llm_chat_command_requires_messages():
    with pytest.raises(DemistoException):
        guardian_llm_chat_command(client=_client(), args={})


def test_guardian_llm_chat_command_rejects_invalid_json():
    with pytest.raises(DemistoException):
        guardian_llm_chat_command(client=_client(), args={"messages": "not json"})


def test_guardian_llm_chat_command_rejects_non_list_messages():
    with pytest.raises(DemistoException):
        guardian_llm_chat_command(client=_client(), args={"messages": json.dumps({"role": "user"})})


# --- _resolve_messages (Playground convenience shape: system_message/user_message) ----------
#
# messages was required=True before this feature; it is now optional, with system_message
# (optional) + user_message (required) as a single-turn alternative for an operator testing from
# the Playground without hand-formatting a JSON array. Providing both shapes must be rejected.
#
# Adversarial review of this feature caught a real bug (fixed alongside these tests): the
# mutual-exclusion and dispatch checks originally used Python truthiness (`if messages`), so an
# explicitly-supplied EMPTY array (`messages: []` or `"[]"`) was falsy and therefore
# indistinguishable from "not supplied at all" -- it silently bypassed the "not both" rejection
# when combined with user_message/system_message, contradicting this function's own docstring.
# Fixed by checking `messages is not None` instead. The tests below pin both the fix and the
# surrounding contract.


def test_guardian_llm_chat_command_accepts_raw_list_messages(mocker):
    # The real production shape: GuardianReasoningTick passes messages as an actual Python list
    # object (never a JSON string) straight through demisto.executeCommand -- no existing test
    # exercised guardian_llm_chat_command at this exact boundary.
    client = _client(conversation_mode=CONVERSATION_MODE_STATELESS)
    _wire(mocker, client, _convo(text="hi there"))
    args = {"messages": [{"role": "user", "content": "say hi"}]}
    result = guardian_llm_chat_command(client, args)
    assert result.outputs["choices"][0]["message"]["content"] == "hi there"


def test_guardian_llm_chat_command_user_message_only_convenience_shape(mocker):
    client = _client(conversation_mode=CONVERSATION_MODE_STATELESS)
    mock_http = _wire(mocker, client, _convo(text="hi there"))
    result = guardian_llm_chat_command(client, {"user_message": "look up 8.8.8.8"})
    assert result.outputs["choices"][0]["message"]["content"] == "hi there"
    sent_messages = mock_http.call_args_list[0].kwargs["json_data"]
    assert sent_messages is not None  # smoke: the convenience path actually reached the client


def test_resolve_messages_user_message_only():
    from GuardianCohere import _resolve_messages

    assert _resolve_messages({"user_message": "look up 8.8.8.8"}) == [
        {"role": "user", "content": "look up 8.8.8.8"}
    ]


def test_resolve_messages_system_and_user_message_order():
    from GuardianCohere import _resolve_messages

    assert _resolve_messages({"system_message": "sys", "user_message": "hi"}) == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
    ]


def test_resolve_messages_system_message_alone_raises():
    from GuardianCohere import _resolve_messages

    with pytest.raises(DemistoException):
        _resolve_messages({"system_message": "sys only"})


def test_resolve_messages_messages_and_user_message_raises():
    from GuardianCohere import _resolve_messages

    with pytest.raises(DemistoException):
        _resolve_messages({"messages": [{"role": "user", "content": "hi"}], "user_message": "hi again"})


def test_resolve_messages_empty_args_raises_with_exact_message():
    from GuardianCohere import _resolve_messages

    with pytest.raises(DemistoException, match='Provide "messages"'):
        _resolve_messages({})


def test_resolve_messages_blank_messages_string_falls_back_to_user_message():
    # XSOAR commonly sends "" for an unset optional text arg rather than omitting the key --
    # this pins _parse_json_arg's `raw in (None, "")` short-circuit feeding correctly into the
    # convenience-shape fallback, rather than a confusing "must be valid JSON" error.
    from GuardianCohere import _resolve_messages

    assert _resolve_messages({"messages": "", "user_message": "look up 8.8.8.8"}) == [
        {"role": "user", "content": "look up 8.8.8.8"}
    ]


def test_resolve_messages_rejects_empty_list_messages_with_user_message():
    # Regression test for the truthiness bug: an explicitly-empty array must be treated as
    # "messages was supplied" for the mutual-exclusion check, not silently as "absent".
    from GuardianCohere import _resolve_messages

    with pytest.raises(DemistoException, match="not both"):
        _resolve_messages({"messages": "[]", "user_message": "ping"})
    with pytest.raises(DemistoException, match="not both"):
        _resolve_messages({"messages": [], "system_message": "sys", "user_message": "ping"})


def test_resolve_messages_nonempty_messages_plus_user_message_still_rejected():
    from GuardianCohere import _resolve_messages

    with pytest.raises(DemistoException, match="not both"):
        _resolve_messages({"messages": [{"role": "user", "content": "hi"}], "user_message": "ping"})


def test_test_module_reuse_is_readonly_probe(mocker):
    """Finding #6: reuse-mode test-module must NOT write a ping turn into the shared production
    conversation — a single read-only GET proves endpoint + bearer + session id."""
    client = _client(conversation_mode=CONVERSATION_MODE_REUSE, session_id="sess-123")
    mock_http = mocker.patch.object(client, "_http_request", return_value={"messages": []})
    assert run_test_module_command(client) == "ok"
    assert mock_http.call_count == 1
    assert mock_http.call_args.kwargs["method"] == "GET"
    assert mock_http.call_args.kwargs["full_url"] == "https://north.example.com/api/v1/conversations/sess-123"


def test_test_module_stateless_round_trip(mocker):
    client = _client(conversation_mode=CONVERSATION_MODE_STATELESS)
    _wire(mocker, client, _convo(text="pong"))
    assert run_test_module_command(client) == "ok"


""" ------------------------- build_client validation ------------------------- """


def test_build_client_requires_endpoint():
    with pytest.raises(DemistoException):
        build_client({"agent_id": "a", "session_id": "s", "bearer_token": "t"}, verify=True, proxy=False)


def test_build_client_requires_agent_id():
    with pytest.raises(DemistoException):
        build_client({"endpoint_url": "https://h", "session_id": "s", "bearer_token": "t"}, verify=True, proxy=False)


def test_build_client_reuse_requires_session_id():
    with pytest.raises(DemistoException):
        build_client(
            {"endpoint_url": "https://h", "agent_id": "a", "bearer_token": "t", "conversation_mode": "reuse"},
            verify=True,
            proxy=False,
        )


def test_build_client_requires_bearer_token():
    with pytest.raises(DemistoException):
        build_client(
            {"endpoint_url": "https://h", "agent_id": "a", "session_id": "s"}, verify=True, proxy=False
        )


def test_build_client_stateless_does_not_require_session_id():
    client = build_client(
        {
            "endpoint_url": "https://h",
            "agent_id": "a",
            "bearer_token": "t",
            "conversation_mode": "stateless",
        },
        verify=True,
        proxy=False,
    )
    assert client.conversation_mode == "stateless"


def test_build_client_resolves_bearer_from_credentials_object():
    client = build_client(
        {
            "endpoint_url": "https://h",
            "agent_id": "a",
            "session_id": "s",
            "credentials": {"password": "cred-token"},
        },
        verify=True,
        proxy=False,
    )
    assert client.bearer_token == "cred-token"


def test_build_client_strips_trailing_slash_from_endpoint():
    client = build_client(
        {"endpoint_url": "https://h/", "agent_id": "a", "session_id": "s", "bearer_token": "t"},
        verify=True,
        proxy=False,
    )
    assert client.endpoint == "https://h"


# --- per-call timeout: one deadline for the whole turn ---------------------------------------


def _reuse_pair():
    baseline = {"messages": [{"role": "USER", "content": [{"text": "hi"}]}, {"role": "CHATBOT", "content": [{"text": "prev"}]}]}
    grown = {"messages": baseline["messages"] + [
        {"role": "USER", "content": [{"text": "ping"}]}, {"role": "CHATBOT", "content": [{"text": "pong"}]}]}
    return [baseline, grown]


def test_per_call_timeout_bounds_every_step_and_disables_retries(mocker):
    """The contract's per-call `timeout` is ONE deadline for baseline read + submit + poll, not the
    full instance timeout per step (which let one call take ~3x the instance timeout)."""
    client = _client(conversation_mode=CONVERSATION_MODE_REUSE, session_id="sess-123")  # instance timeout 200
    mock_http = _wire(mocker, client, _reuse_pair())
    result = client.chat_completion({"messages": [{"role": "user", "content": "ping"}]}, call_timeout=60)

    assert result["choices"][0]["message"]["content"] == "pong"
    calls = mock_http.call_args_list
    assert [c.kwargs["method"] for c in calls] == ["GET", "POST", "GET"]
    assert all(c.kwargs["timeout"] <= 60 for c in calls)
    assert calls[1].kwargs["retries"] == 0  # a hard bound: no transparent retry may extend it
    assert client._call_deadline is None  # cleared once the call returns


def test_per_call_timeout_never_exceeds_the_instance_timeout(mocker):
    client = _client(conversation_mode=CONVERSATION_MODE_STATELESS, session_id="")
    mock_http = _wire(mocker, client, _convo(text="pong"))
    client.chat_completion({"messages": [{"role": "user", "content": "ping"}]}, call_timeout=900)
    assert mock_http.call_args_list[0].kwargs["timeout"] <= 200


def test_without_a_per_call_timeout_the_turn_is_unchanged(mocker):
    from GuardianCohere import DEFAULT_RETRIES
    client = _client(conversation_mode=CONVERSATION_MODE_STATELESS, session_id="")
    mock_http = _wire(mocker, client, _convo(text="pong"))
    client.chat_completion({"messages": [{"role": "user", "content": "ping"}]})
    post = mock_http.call_args_list[0].kwargs
    assert post["timeout"] == 200
    assert post["retries"] == DEFAULT_RETRIES


def test_poll_gives_up_at_the_per_call_deadline(mocker):
    """A reply that never arrives fails at the per-call deadline (a timeout the probe recognizes),
    not after the instance's whole poll window."""
    client = _client(conversation_mode=CONVERSATION_MODE_STATELESS, session_id="")
    _wire(mocker, client, {"messages": [{"role": "USER", "content": [{"text": "q"}]}]})
    with pytest.raises(DemistoException, match="(?i)timeout"):
        client.chat_completion({"messages": [{"role": "user", "content": "q"}]}, call_timeout=1)
    assert client._call_deadline is None  # cleared even when the call fails


def test_chat_command_forwards_timeout_and_rejects_bad_values(mocker):
    client = _client(conversation_mode=CONVERSATION_MODE_STATELESS, session_id="")
    _wire(mocker, client, _convo(text="hi"))
    spy = mocker.spy(client, "chat_completion")
    messages = json.dumps([{"role": "user", "content": "hi"}])

    guardian_llm_chat_command(client, {"messages": messages, "timeout": "45"})
    guardian_llm_chat_command(client, {"messages": messages})
    assert spy.call_args_list[0].kwargs["call_timeout"] == 45.0
    assert spy.call_args_list[1].kwargs["call_timeout"] is None
    for bad in ("0", "-5", "soon"):
        with pytest.raises(DemistoException):
            guardian_llm_chat_command(client, {"messages": messages, "timeout": bad})


def test_model_size_defaults_to_auto_and_accepts_the_four_choices():
    base = {"endpoint_url": "https://h", "agent_id": "a", "session_id": "s", "bearer_token": "t"}
    assert build_client(dict(base), verify=True, proxy=False).model_tier == "auto"          # absent: auto
    for given, expected in (("auto", "auto"), ("AUTO", "auto"), ("small", "small"), (" Medium ", "medium"),
                            ("large", "large"), ("", "auto"), ("huge", "auto")):
        assert build_client(dict(base, model_tier=given), verify=True, proxy=False).model_tier == expected, given


def test_the_model_size_dropdown_offers_auto_first_and_defaults_to_it():
    import pathlib

    import yaml

    spec = yaml.safe_load((pathlib.Path(__file__).resolve().parent / "GuardianCohere.yml").read_text())
    param = next(p for p in spec["configuration"] if p["name"] == "model_tier")
    assert param["options"] == ["auto", "small", "medium", "large"] and param["defaultvalue"] == "auto"


# --- the optional `model` argument ------------------------------------------------------------------------------------

def test_cohere_without_a_model_arg_or_with_the_configured_one_runs_as_before(mocker):
    for args in ({}, {"model": ""}, {"model": "cohere-north"}):
        client = _client(conversation_mode=CONVERSATION_MODE_STATELESS)
        _wire(mocker, client, _convo(text="hi there"))
        result = guardian_llm_chat_command(client, dict(args, messages=json.dumps([{"role": "user", "content": "x"}])))
        assert result.outputs["choices"][0]["message"]["content"] == "hi there"


def test_cohere_refuses_a_different_model_without_calling_north(mocker):
    client = _client(conversation_mode=CONVERSATION_MODE_STATELESS, model_label="command-a")
    mock_http = _wire(mocker, client, _convo(text="never"))
    with pytest.raises(DemistoException) as err:
        guardian_llm_chat_command(client, {"messages": json.dumps([{"role": "user", "content": "x"}]), "model": "gpt-5"})
    text = str(err.value)
    assert text.startswith("MODEL_SELECTION_UNSUPPORTED: this provider runs a fixed Cohere North agent; choose the model in Cohere, not per call")
    assert not mock_http.called
    same = guardian_llm_chat_command(client, {"messages": json.dumps([{"role": "user", "content": "x"}]), "model": "command-a"})
    assert same.outputs["model"] == "command-a"


def test_cohere_without_a_configured_model_label_refuses_any_named_model(mocker):
    client = _client(conversation_mode=CONVERSATION_MODE_STATELESS, model_label="")
    _wire(mocker, client, _convo(text="never"))
    with pytest.raises(DemistoException) as err:
        guardian_llm_chat_command(client, {"messages": json.dumps([{"role": "user", "content": "x"}]), "model": "gpt-5"})
    assert str(err.value).startswith("MODEL_SELECTION_UNSUPPORTED:")


def test_cohere_yml_declares_the_model_argument():
    import pathlib
    import yaml
    doc = yaml.safe_load((pathlib.Path(__file__).parent / "GuardianCohere.yml").read_text())
    args = {a["name"]: a for a in doc["script"]["commands"][0]["arguments"]}
    assert args["model"]["required"] is False and "MODEL_SELECTION_UNSUPPORTED:" in args["model"]["description"]


def test_the_request_carries_a_model_only_when_a_model_id_is_set():
    plain = _client().build_request_body({"messages": [{"role": "user", "content": "hi"}]}, "c1")
    assert "model" not in plain
    c = _client()
    c.model_id = "openai/gpt-oss-120b"
    assert c.build_request_body({"messages": [{"role": "user", "content": "hi"}]}, "c1")["model"] == "openai/gpt-oss-120b"


def test_build_client_reads_the_model_id_param():
    params = {"endpoint_url": "https://north.example.com", "agent_id": "a", "session_id": "s", "bearer_token": "t",
              "model_id": " google/gemma-4-31B-it "}
    assert build_client(params, verify=True, proxy=False).model_id == "google/gemma-4-31B-it"


def test_list_models_reads_the_v2_shape_and_follows_the_next_token(mocker):
    from GuardianCohere import guardian_cohere_list_models_command

    c = _client()
    pages = [
        {"data": [{"id": "m1", "name": "vendor-llm-v2-pro", "display_name": "Vendor LLM v2 Pro", "provider": {"name": "single_container", "instance": "i-1"},
                   "context_length": 131072, "max_tokens": 8192, "supported_parameters": ["thinking", "vision"]}], "next_token": "t2"},
        {"data": [{"id": "m2", "name": "openai/gpt-oss-120b", "display_name": "gpt-oss", "provider": {"name": "vllm", "instance": "i-2"}}], "next_token": None},
    ]
    seen = []

    def fake(**kw):
        seen.append((kw["full_url"], kw.get("params")))
        return pages[len(seen) - 1]

    mocker.patch.object(c, "_http_request", side_effect=fake)
    res = guardian_cohere_list_models_command(c, {})
    assert seen == [("https://north.example.com/api/v2/models", {"limit": 100}),
                    ("https://north.example.com/api/v2/models", {"limit": 100, "next_token": "t2"})]
    assert [m["name"] for m in res.outputs] == ["vendor-llm-v2-pro", "openai/gpt-oss-120b"]
    first = res.outputs[0]
    assert first["provider"] == "single_container" and first["context_length"] == 131072
    assert first["supported_parameters"] == ["thinking", "vision"]
    assert res.outputs_prefix == "GuardianCohere.Model" and "Vendor LLM v2 Pro" in res.readable_output


def test_list_models_falls_back_to_v1_which_lists_bare_ids(mocker):
    from GuardianCohere import guardian_cohere_list_models_command

    c = _client()
    seen = []

    def fake(**kw):
        seen.append(kw["full_url"])
        if kw["full_url"].endswith("/api/v2/models"):
            raise DemistoException("Error in API call [404] - Not Found")
        return [{"id": "m1"}, "m2", {"nothing": 1}]

    mocker.patch.object(c, "_http_request", side_effect=fake)
    res = guardian_cohere_list_models_command(c, {})
    assert seen == ["https://north.example.com/api/v2/models", "https://north.example.com/api/v1/models"]
    assert [m["id"] for m in res.outputs] == ["m1", "m2"]


def test_list_models_says_what_each_path_answered_when_none_works(mocker):
    from GuardianCohere import guardian_cohere_list_models_command

    c = _client()
    mocker.patch.object(c, "_http_request", side_effect=DemistoException("Error in API call [404] - Not Found"))
    with pytest.raises(DemistoException) as err:
        guardian_cohere_list_models_command(c, {})
    text = str(err.value)
    assert "/api/v2/models" in text and "/api/v1/models" in text and "404" in text


def test_list_models_reports_an_empty_answer(mocker):
    from GuardianCohere import guardian_cohere_list_models_command

    c = _client()
    mocker.patch.object(c, "_http_request", return_value={"data": [], "next_token": None})
    with pytest.raises(DemistoException, match="lists no models"):
        guardian_cohere_list_models_command(c, {})


def test_yml_declares_the_list_models_command_and_the_model_id_param():
    import pathlib
    text = (pathlib.Path(__file__).with_name("GuardianCohere.yml")).read_text()
    assert "- name: guardian-cohere-list-models" in text and "name: model_id" in text


@pytest.mark.parametrize(
    "raw, expected",
    [
        (None, None), ("", None), ("auto", None), ("AUTO", None),
        ("required", "REQUIRED"), ("REQUIRED", "REQUIRED"), ("any", "REQUIRED"),
        ({"type": "function", "function": {"name": "x"}}, "REQUIRED"),
        ("none", "NONE"), ("None", "NONE"), ("NONE", "NONE"),
        ("something-else", None),
    ],
)
def test_tool_choice_is_sent_to_north_only_as_required_or_none(raw, expected):
    body = _client().build_request_body(
        {"messages": [{"role": "user", "content": "hi"}], "tool_choice": raw}, "c1"
    )
    if expected is None:
        assert "tool_choice" not in body
    else:
        assert body["tool_choice"] == expected


def _sse(*events):
    return "".join("event: x\ndata: " + json.dumps(e) + "\n\n" for e in events)


def test_usage_is_read_from_the_stream_end_event():
    from GuardianCohere import _usage_from_stream

    raw = _sse({"type": "content-delta", "delta": {"text": "hi"}},
               {"type": "stream-end", "delta": {"finish_reason": "COMPLETE",
                                                 "usage": {"tokens": {"input_tokens": 1200, "output_tokens": 30}, "cached_tokens": 100}}})
    assert _usage_from_stream(raw) == {"prompt_tokens": 1200, "completion_tokens": 30, "total_tokens": 1230, "cached_tokens": 100}


def test_usage_falls_back_to_billed_units_and_ignores_junk():
    from GuardianCohere import _usage_from_stream

    assert _usage_from_stream(_sse({"usage": {"billed_units": {"input_tokens": 7, "output_tokens": 3}}}))["total_tokens"] == 10
    assert _usage_from_stream("data: not json\n\ndata: {\"usage\": {}}") is None
    assert _usage_from_stream(None) is None and _usage_from_stream("") is None


def test_chat_completion_uses_stream_usage_when_the_conversation_has_none(mocker):
    c = _client()
    convo = {"messages": [{"role": "CHATBOT", "content": [{"type": "text", "text": "ok"}]}]}
    mocker.patch.object(c, "baseline_message_count", return_value=0)
    mocker.patch.object(c, "submit_turn", return_value=_sse({"type": "stream-end", "usage": {"tokens": {"input_tokens": 50, "output_tokens": 5}}}))
    mocker.patch.object(c, "poll_conversation", return_value=convo)
    res = c.chat_completion({"messages": [{"role": "user", "content": "hi"}]})
    assert res["usage"]["prompt_tokens"] == 50 and res["usage"]["total_tokens"] == 55


def test_conversation_usage_wins_over_the_stream(mocker):
    c = _client()
    convo = {"messages": [{"role": "CHATBOT", "content": [{"type": "text", "text": "ok"}]}], "meta": {"tokens": {"input_tokens": 9, "output_tokens": 1}}}
    mocker.patch.object(c, "baseline_message_count", return_value=0)
    mocker.patch.object(c, "submit_turn", return_value=_sse({"usage": {"tokens": {"input_tokens": 50, "output_tokens": 5}}}))
    mocker.patch.object(c, "poll_conversation", return_value=convo)
    assert c.chat_completion({"messages": [{"role": "user", "content": "hi"}]})["usage"]["prompt_tokens"] == 9


def test_a_stream_error_is_read_from_the_last_event():
    from GuardianCohere import _error_from_stream

    raw = _sse({"type": "content-delta", "delta": {"text": "x"}},
               {"type": "stream-end", "delta": {"finish_reason": "ERROR",
                                                 "error": {"error_code": "MODEL_NOT_FOUND", "message": "Model not found.", "context": {"model_id": "command"}}}})
    text = _error_from_stream(raw)
    assert "MODEL_NOT_FOUND: Model not found." in text and "command" in text and "ERROR" in text


def test_stream_errors_ignore_normal_endings_and_junk():
    from GuardianCohere import _error_from_stream

    assert _error_from_stream(_sse({"type": "stream-end", "delta": {"finish_reason": "COMPLETE", "error": None}})) is None
    assert _error_from_stream(_sse({"type": "stream-end", "delta": {"finish_reason": "TOOL_CALL"}})) is None
    assert _error_from_stream("data: not json\n") is None and _error_from_stream(None) is None
    assert "TIMEOUT" in _error_from_stream(_sse({"type": "stream-end", "delta": {"finish_reason": "TIMEOUT"}}))


def test_chat_completion_fails_fast_on_a_stream_error_without_polling(mocker):
    c = _client()
    mocker.patch.object(c, "baseline_message_count", return_value=0)
    mocker.patch.object(c, "submit_turn", return_value=_sse({"type": "stream-end", "delta": {"finish_reason": "ERROR", "error": {"error_code": "BOOM", "message": "bad"}}}))
    poll = mocker.patch.object(c, "poll_conversation")
    with pytest.raises(DemistoException, match="BOOM: bad"):
        c.chat_completion({"messages": [{"role": "user", "content": "hi"}]})
    poll.assert_not_called()


def test_poll_window_follows_the_request_timeout_beyond_90_seconds(mocker):
    """The poll waits as long as the instance's Request timeout (a slow first turn of a large model), not a
    hidden 90 s: with a 250 s timeout a reply that arrives after 150 s is still taken."""
    import GuardianCohere as gc
    client = _client(conversation_mode=CONVERSATION_MODE_STATELESS, session_id="")
    client.request_timeout = 250
    clock = {"t": 1000.0}
    mocker.patch.object(gc.time, "time", side_effect=lambda: clock["t"])
    mocker.patch.object(gc.time, "sleep", side_effect=lambda s: clock.__setitem__("t", clock["t"] + 30))
    pending = {"messages": [{"role": "USER", "content": [{"text": "q"}]}]}
    replies = [pending] * 5 + [_convo(text="late")]
    mocker.patch.object(client, "_get_conversation", side_effect=lambda *a, **k: replies.pop(0) if replies else _convo(text="late"))
    convo = client.poll_conversation("c-1", baseline_count=0)
    assert clock["t"] - 1000.0 >= 150 and gc.POLL_DEADLINE_SECONDS >= 600
    assert convo["messages"][-1]["role"].lower() in ("chatbot", "assistant")


def test_a_namespaced_tool_call_name_is_cleaned_to_the_offered_tool():
    """gpt-oss behind North names a call `function::getIncidents`; the bridge must see `getIncidents`."""
    from GuardianCohere import _extract_reply_tool_calls
    calls = _extract_reply_tool_calls({"tool_calls": [
        {"id": "a", "type": "function", "function": {"name": "function::getIncidents", "arguments": {"size": "3"}}},
        {"name": "functions.ip", "parameters": {"ip": "8.8.8.8"}},
        {"id": "c", "function": {"name": "getEntries", "arguments": "{}"}},
    ]})
    assert [c["function"]["name"] for c in calls] == ["getIncidents", "ip", "getEntries"]


# --- tool_result_format: the tool round-trip as plain text ------------------------------------------------------------

_CALL_1 = {"id": "call_1", "type": "function", "function": {"name": "getIncidents", "arguments": '{"size": "3"}'}}
_CALL_2 = {"id": "call_2", "type": "function", "function": {"name": "ip", "arguments": {"ip": "8.8.8.8"}}}


def _tool_transcript():
    return [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "investigate"},
        {"role": "assistant", "content": "Checking.", "tool_calls": [_CALL_1, _CALL_2]},
        {"role": "tool", "tool_call_id": "call_1", "name": "getIncidents", "content": "3 incidents"},
        {"role": "tool", "tool_call_id": "call_2", "content": "clean"},
    ]


def test_tool_result_format_native_keeps_the_openai_round_trip_unchanged():
    messages = _tool_transcript()[1:]
    assert _to_north_messages(messages, "native") == _to_north_messages(messages)
    out = _to_north_messages(messages)
    assert out[1]["tool_calls"] == [_CALL_1, _CALL_2]
    assert out[2] == {"role": "tool", "content": "3 incidents", "tool_call_id": "call_1", "name": "getIncidents"}
    body = _client(conversation_mode=CONVERSATION_MODE_STATELESS).build_request_body({"messages": _tool_transcript()}, "c")
    assert body["messages"][1]["tool_calls"] == [_CALL_1, _CALL_2] and body["messages"][2]["role"] == "tool"


def test_text_mode_turns_an_assistant_tool_call_into_plain_lines():
    out = _to_north_messages(_tool_transcript()[1:3], "text")
    assert out[1] == {
        "role": "assistant",
        "content": 'Checking.\n[tool call] getIncidents {"size": "3"}\n[tool call] ip {"ip": "8.8.8.8"}',
    }
    assert "tool_calls" not in out[1]


def test_text_mode_assistant_without_text_or_arguments():
    bare = {"id": "c", "function": {"name": "whoami", "arguments": "{}"}}
    out = _to_north_messages([{"role": "assistant", "content": None, "tool_calls": [bare]}], "text")
    assert out == [{"role": "assistant", "content": "[tool call] whoami"}]


def test_text_mode_truncates_long_arguments_and_keeps_unparseable_ones():
    import GuardianCohere as gc

    long_call = {"id": "c", "function": {"name": "f", "arguments": json.dumps({"q": "x" * 2000})}}
    text = _to_north_messages([{"role": "assistant", "tool_calls": [long_call]}], "text")[0]["content"]
    assert text.startswith('[tool call] f {"q": "xxx') and text.endswith("...")
    assert len(text) <= len("[tool call] f ") + gc.TOOL_CALL_TEXT_ARGS_MAX_CHARS + 3
    odd = {"id": "c", "function": {"name": "f", "arguments": "not json"}}
    assert _to_north_messages([{"role": "assistant", "tool_calls": [odd]}], "text")[0]["content"] == "[tool call] f not json"


def test_text_mode_turns_consecutive_tool_results_into_one_user_message():
    out = _to_north_messages(_tool_transcript()[1:], "text", {"call_2": "ip"})
    assert [m["role"] for m in out] == ["user", "assistant", "user"]
    assert out[2] == {
        "role": "user",
        "content": "[tool result for getIncidents (call call_1)]\n3 incidents\n\n[tool result for ip (call call_2)]\nclean",
    }
    assert all(set(m) == {"role", "content"} for m in out)


def test_text_mode_merges_a_user_message_that_follows_tool_results_but_not_two_plain_ones():
    messages = _tool_transcript()[2:] + [{"role": "user", "content": "now summarise"}]
    out = _to_north_messages(messages, "text")
    assert [m["role"] for m in out] == ["assistant", "user"]
    assert out[1]["content"].endswith("clean\n\nnow summarise")
    plain = [{"role": "user", "content": "a"}, {"role": "user", "content": "b"}]
    assert _to_north_messages(plain, "text") == [{"role": "user", "content": "a"}, {"role": "user", "content": "b"}]


def test_text_mode_names_a_tool_result_without_a_name_or_id_sensibly():
    out = _to_north_messages([{"role": "tool", "content": "res"}], "text")
    assert out == [{"role": "user", "content": "[tool result for tool]\nres"}]


def test_text_mode_stateless_sends_the_full_transcript_as_text():
    client = _client(conversation_mode=CONVERSATION_MODE_STATELESS)
    client.tool_result_format = "text"
    tools = [{"type": "function", "function": {"name": "f", "parameters": {"type": "object"}}}]
    body = client.build_request_body({"messages": _tool_transcript(), "tools": tools}, "fresh")
    assert body["system"] == "sys"
    assert body["tools"] == tools  # definitions still sent
    assert [m["role"] for m in body["messages"]] == ["user", "assistant", "user"]
    assert body["messages"][0] == {"role": "user", "content": "investigate"}
    assert body["messages"][1]["content"].startswith("Checking.\n[tool call] getIncidents")
    assert "[tool result for getIncidents (call call_1)]" in body["messages"][2]["content"]
    assert "[tool result for ip (call call_2)]" in body["messages"][2]["content"]
    assert "tool_calls" not in json.dumps(body["messages"]) and "tool_call_id" not in json.dumps(body["messages"])


def test_text_mode_reuse_sends_only_the_tool_results_and_still_names_the_tools():
    client = _client(conversation_mode=CONVERSATION_MODE_REUSE)
    client.tool_result_format = "text"
    body = client.build_request_body({"messages": _tool_transcript()}, "sess-123")
    # the assistant message that made the calls is before the slice; its tool names still come from the transcript
    assert body["messages"] == [
        {
            "role": "user",
            "content": "[tool result for getIncidents (call call_1)]\n3 incidents\n\n"
            "[tool result for ip (call call_2)]\nclean",
        }
    ]
    assert body["conversation"] == {"id": "sess-123"}


def test_text_mode_reuse_chat_completion_end_to_end(mocker):
    client = _client(conversation_mode=CONVERSATION_MODE_REUSE)
    client.tool_result_format = "text"
    baseline = {"messages": [{"role": "USER", "content": [{"text": "hi"}]}, {"role": "CHATBOT", "content": [{"text": "prev"}]}]}
    grown = {"messages": baseline["messages"] + [
        {"role": "USER", "content": [{"text": "[tool result ...]"}]}, {"role": "CHATBOT", "content": [{"text": "done"}]}]}
    mock = _wire(mocker, client, [baseline, grown])
    result = client.chat_completion({"messages": _tool_transcript()})
    post = next(c for c in mock.call_args_list if c.kwargs.get("method") == "POST")
    assert post.kwargs["json_data"]["messages"][0]["role"] == "user"
    assert "tool_call_id" not in json.dumps(post.kwargs["json_data"])
    assert result["choices"][0]["message"]["content"] == "done"


def test_text_mode_reply_tool_calls_are_still_parsed():
    client = _client()
    client.tool_result_format = "text"
    convo = _convo(text=None, tool_calls=[{"id": "t", "function": {"name": "getIncidents", "arguments": "{}"}}])
    out = client.normalize_response(convo, "c-1")
    assert out["choices"][0]["finish_reason"] == "tool_calls"
    assert out["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "getIncidents"


def test_tool_result_format_param_parsing_and_default():
    base = {"endpoint_url": "https://h", "agent_id": "a", "session_id": "s", "bearer_token": "t"}
    assert build_client(dict(base), verify=True, proxy=False).tool_result_format == "native"
    for given, expected in (("native", "native"), ("text", "text"), (" TEXT ", "text"), ("", "native"),
                            ("bogus", "native"), (None, "native")):
        assert build_client(dict(base, tool_result_format=given), verify=True, proxy=False).tool_result_format == expected, given
    assert _client().tool_result_format == "native"
    assert CohereNorthClient(
        endpoint="https://h", agent_id="a", session_id="s", bearer_token="t", model_label="m", model_tier="auto",
        conversation_mode="reuse", tool_format="openai", verify=False, proxy=False, tool_result_format="weird",
    ).tool_result_format == "native"


def test_the_tool_results_dropdown_is_optional_native_first_and_next_to_tool_format():
    import pathlib

    import yaml

    spec = yaml.safe_load((pathlib.Path(__file__).resolve().parent / "GuardianCohere.yml").read_text())
    names = [p["name"] for p in spec["configuration"]]
    param = spec["configuration"][names.index("tool_result_format")]
    assert param["type"] == 15 and not param.get("required") and param["defaultvalue"] == "native"
    assert param["options"] == ["native", "text"] and param["display"] == "Tool results"
    assert names.index("tool_result_format") == names.index("tool_format") + 1


""" ------------------------- per_run conversation mode ------------------------- """

LABEL_RE = re.compile(r"^Guardian run - incident 1234 - \d{4}-\d{2}-\d{2} \d{2}:\d{2}\n\n")
TOOL_CALL = {"id": "c1", "type": "function", "function": {"name": "getIncidents", "arguments": "{}"}}


@pytest.fixture
def run_store(mocker):
    """An in-memory, versioned integration context, and investigation 1234. The context is copied on every read and
    write, as the platform does. A write with a stale version raises ValueError, as the platform does. A test can set
    ``store["before_write"]`` to a function that runs just before the next write (to simulate another call)."""
    store = {"context": {}, "version": 1, "writes": 0, "before_write": None}

    def _get(*args, **kwargs):
        return copy.deepcopy(store["context"])

    def _get_versioned(*args, **kwargs):
        return copy.deepcopy(store["context"]), store["version"]

    def _set(context, sync=True, version=-1):
        hook, store["before_write"] = store["before_write"], None
        if hook:
            hook()
        if version not in (-1, None) and version != store["version"]:
            raise ValueError("version conflict")
        store["context"] = copy.deepcopy(context)
        store["version"] += 1
        store["writes"] += 1

    mocker.patch("GuardianCohere.get_integration_context", side_effect=_get)
    mocker.patch("GuardianCohere.get_integration_context_with_version", side_effect=_get_versioned)
    mocker.patch("GuardianCohere.set_integration_context", side_effect=_set)
    mocker.patch("GuardianCohere.demisto.investigation", return_value={"id": "1234"})
    mocker.patch("GuardianCohere.time.sleep")
    return store


def _per_run_client(session_id=""):
    return _client(conversation_mode=CONVERSATION_MODE_PER_RUN, session_id=session_id)


def _start_messages(first="Investigate this incident"):
    return [{"role": "system", "content": "be careful"}, {"role": "user", "content": first}]


def _later_messages(first="Investigate this incident"):
    return _start_messages(first) + [
        {"role": "assistant", "content": None, "tool_calls": [TOOL_CALL]},
        {"role": "tool", "tool_call_id": "c1", "content": "result"},
    ]


def _reply_convo(total, text="done"):
    """A conversation of ``total`` messages that ends in an assistant text reply."""
    messages = [{"role": "USER", "content": [{"text": "q"}]}, {"role": "CHATBOT", "content": [{"text": "a"}]}] * (total // 2)
    messages[-1] = {"role": "CHATBOT", "content": [{"text": text}]}
    return {"messages": messages, "meta": {"tokens": {"input_tokens": 1, "output_tokens": 1}}}


def _tool_call_convo(total):
    """A conversation of ``total`` messages whose last reply is the tool call of ``_later_messages`` (no text)."""
    convo = _reply_convo(total)
    convo["messages"][-1] = {"role": "CHATBOT", "content": [], "tool_calls": [copy.deepcopy(TOOL_CALL)]}
    return convo


def _wire_conversations(mocker, client, conversations, unreadable=()):
    """POST -> ""; GET of a known conversation id -> that conversation; GET of an id in ``unreadable`` -> a 404; any
    other id (a conversation this call has just started) -> a short reply. Returns the mock."""
    mocker.patch("GuardianCohere.time.sleep")

    def _side_effect(*args, **kwargs):
        if kwargs.get("method") == "POST":
            return ""
        conversation_id = kwargs["full_url"].rsplit("/", 1)[-1]
        if conversation_id in unreadable:
            raise DemistoException("404 not found")
        return conversations.get(conversation_id, _reply_convo(2, "fresh reply"))

    return mocker.patch.object(client, "_http_request", side_effect=_side_effect)


def _posts(mock_http):
    return [c.kwargs for c in mock_http.call_args_list if c.kwargs["method"] == "POST"]


def _entry_for(store, messages):
    return store["context"][RUN_CONTEXT_KEY][_run_key("", "1234", messages)]


def test_per_run_start_of_run_gets_a_new_id_and_the_full_body(mocker, run_store):
    client = _per_run_client()
    mock_http = _wire(mocker, client, _reply_convo(2))
    client.chat_completion({"messages": _start_messages()})

    calls = mock_http.call_args_list
    assert calls[0].kwargs["method"] == "POST"  # no baseline read: the conversation is new
    body = calls[0].kwargs["json_data"]
    conversation_id = body["conversation"]["id"]
    assert str(uuid.UUID(conversation_id)) == conversation_id
    assert body["system"] == "be careful"
    assert [m["role"] for m in body["messages"]] == ["user"]
    entries = run_store["context"][RUN_CONTEXT_KEY]
    assert len(entries) == 1
    (entry,) = entries.values()
    assert entry["conversation_id"] == conversation_id
    assert abs(entry["created"] - time.time()) < 60


def test_per_run_start_of_run_sends_every_non_system_message(mocker, run_store):
    client = _per_run_client()
    body = client.build_request_body({"messages": _start_messages() + [{"role": "user", "content": "more"}]}, "c1")
    assert [m["content"] for m in body["messages"]] == ["Investigate this incident", "more"]


def test_per_run_later_turn_reuses_the_stored_id_and_sends_only_new_messages(mocker, run_store):
    client = _per_run_client()
    mock_http = _wire(mocker, client, [_reply_convo(2), _tool_call_convo(2), _reply_convo(4, "next")])
    client.chat_completion({"messages": _start_messages()})
    first_id = _posts(mock_http)[0]["json_data"]["conversation"]["id"]

    result = client.chat_completion({"messages": _later_messages()})

    assert result["choices"][0]["message"]["content"] == "next"
    calls = mock_http.call_args_list
    # start: POST, GET(poll); later turn: GET(validation and baseline), POST, GET(poll)
    assert [c.kwargs["method"] for c in calls] == ["POST", "GET", "GET", "POST", "GET"]
    assert calls[2].kwargs["full_url"].endswith("/conversations/" + first_id)
    second = calls[3].kwargs["json_data"]
    assert second["conversation"]["id"] == first_id
    assert second["messages"] == [{"role": "tool", "tool_call_id": "c1", "content": "result"}]
    assert "Guardian run" not in json.dumps(second["messages"])
    assert run_store["writes"] == 1  # a later turn reads the store and does not write it


def test_per_run_a_matching_text_reply_reuses_the_id_whatever_the_whitespace(mocker, run_store):
    client = _per_run_client()
    later = _start_messages() + [{"role": "assistant", "content": "Looking at\n  the   host"}, {"role": "user", "content": "go on"}]
    _store_run(_run_key("", "1234", later), "stored-id", time.time())
    mock_http = _wire(mocker, client, [_reply_convo(2, "Looking at the host"), _reply_convo(4, "next")])
    client.chat_completion({"messages": later})
    post = _posts(mock_http)[0]["json_data"]
    assert post["conversation"] == {"id": "stored-id"}
    assert post["messages"] == [{"role": "user", "content": "go on"}]


def test_per_run_baseline_is_the_stored_conversations_message_count(mocker, run_store):
    client = _per_run_client()
    # the stored conversation holds 2 messages; a poll that still shows 2 must not count as a new reply
    _wire(mocker, client, [_reply_convo(2), _tool_call_convo(2), _tool_call_convo(2), _reply_convo(4, "new")])
    client.chat_completion({"messages": _start_messages()})
    result = client.chat_completion({"messages": _later_messages()})
    assert result["choices"][0]["message"]["content"] == "new"


def test_per_run_two_runs_with_the_same_prompt_on_the_same_incident_get_different_ids(mocker, run_store):
    client = _per_run_client()
    mock_http = _wire(mocker, client, _reply_convo(2))
    client.chat_completion({"messages": _start_messages()})
    client.chat_completion({"messages": _start_messages()})
    first, second = _posts(mock_http)
    assert first["json_data"]["conversation"]["id"] != second["json_data"]["conversation"]["id"]
    # the re-run owns the key now: its next turn goes to the new conversation
    (entry,) = run_store["context"][RUN_CONTEXT_KEY].values()
    assert entry["conversation_id"] == second["json_data"]["conversation"]["id"]


def test_per_run_different_incidents_and_prompts_get_different_keys():
    messages = _start_messages()
    assert _run_key("", "1", messages) != _run_key("", "2", messages)
    assert _run_key("", "1", messages) != _run_key("", "1", _start_messages("another prompt"))
    assert _run_key("a", "1", messages) != _run_key("b", "1", messages)
    assert _run_key("", "1", messages) == _run_key("", "1", _later_messages())  # stable across the turns of a run


def test_per_run_later_turn_with_the_key_missing_starts_a_new_conversation_with_the_full_history(mocker, run_store):
    client = _per_run_client()
    mock_http = _wire(mocker, client, _reply_convo(4))
    client.chat_completion({"messages": _later_messages()})

    calls = mock_http.call_args_list
    assert calls[0].kwargs["method"] == "POST"  # no baseline read
    body = calls[0].kwargs["json_data"]
    assert [m["role"] for m in body["messages"]] == ["user", "assistant", "tool"]
    assert LABEL_RE.match(body["messages"][0]["content"])
    assert len(run_store["context"][RUN_CONTEXT_KEY]) == 1  # the next turn finds it


def test_per_run_an_expired_entry_counts_as_missing(mocker, run_store):
    client = _per_run_client()
    key = _run_key("", "1234", _later_messages())
    old = time.time() - RUN_MAX_AGE_SECONDS - 60
    run_store["context"] = {RUN_CONTEXT_KEY: {key: {"conversation_id": "old-conversation", "created": old}}}
    mock_http = _wire(mocker, client, _reply_convo(4))
    client.chat_completion({"messages": _later_messages()})
    assert _posts(mock_http)[0]["json_data"]["conversation"]["id"] != "old-conversation"


def test_per_run_a_stale_entry_and_a_failing_write_do_not_reuse_the_old_conversation(mocker, run_store):
    """Run 1 stored an id. Run 2 (same incident, same fixed prompt, so the same key) starts, but its write fails, so the
    old entry stays. Run 2's second turn finds run 1's id; the conversation does not hold run 2's reply, so it is not used."""
    client = _per_run_client()
    key = _run_key("", "1234", _later_messages())
    run_store["context"] = {RUN_CONTEXT_KEY: {key: {"conversation_id": "run-1", "created": time.time()}}}
    conversations = {"run-1": _reply_convo(6, "run one's own last reply")}
    mock_http = _wire_conversations(mocker, client, conversations)

    mocker.patch("GuardianCohere.set_integration_context", side_effect=RuntimeError("write failed"))
    client.chat_completion({"messages": _start_messages()})  # run 2, turn 1
    run_2_id = _posts(mock_http)[0]["json_data"]["conversation"]["id"]
    assert run_2_id != "run-1"

    client.chat_completion({"messages": _later_messages()})  # run 2, turn 2

    turn_2 = _posts(mock_http)[1]["json_data"]
    assert turn_2["conversation"]["id"] not in ("run-1", run_2_id)
    assert [m["role"] for m in turn_2["messages"]] == ["user", "assistant", "tool"]  # the full history, not the delta
    assert LABEL_RE.match(turn_2["messages"][0]["content"])


def test_per_run_an_overlapping_start_that_restores_the_old_entry_is_caught_by_validation(mocker, run_store):
    client = _per_run_client()
    conversations = {}
    mock_http = _wire_conversations(mocker, client, conversations)

    client.chat_completion({"messages": _start_messages()})  # run 1, turn 1
    run_1_id = _posts(mock_http)[0]["json_data"]["conversation"]["id"]
    run_1_call = copy.deepcopy(TOOL_CALL)
    run_1_call["id"] = "run-1-call"  # North gives every call its own id
    conversations[run_1_id] = {"messages": [{"role": "USER", "content": [{"text": "q"}]},
                                            {"role": "CHATBOT", "content": [], "tool_calls": [run_1_call]}]}
    after_run_1 = copy.deepcopy(run_store["context"])

    client.chat_completion({"messages": _start_messages()})  # run 2, turn 1
    run_2_id = _posts(mock_http)[1]["json_data"]["conversation"]["id"]
    conversations[run_2_id] = _reply_convo(2, "run two's reply")
    run_store["context"] = after_run_1  # another call read before run 2's write and wrote it back afterwards

    client.chat_completion({"messages": _later_messages()})  # run 2, turn 2

    turn_2 = _posts(mock_http)[2]["json_data"]
    assert turn_2["conversation"]["id"] not in (run_1_id, run_2_id)
    assert [m["role"] for m in turn_2["messages"]] == ["user", "assistant", "tool"]


def test_per_run_a_conversation_that_ends_in_our_own_message_is_not_reused(mocker, run_store):
    """A turn was posted and its poll timed out: North's last assistant message still matches the transcript, but the
    conversation ends in a user message, so sending the turn into it again would duplicate it."""
    client = _per_run_client()
    later = _start_messages() + [{"role": "assistant", "content": "Looking at the host"}, {"role": "user", "content": "go on"}]
    _store_run(_run_key("", "1234", later), "stored-id", time.time())
    pending = {
        "messages": [
            {"role": "USER", "content": [{"text": "q"}]},
            {"role": "CHATBOT", "content": [{"text": "Looking at the host"}]},
            {"role": "USER", "content": [{"text": "go on"}]},
        ]
    }
    mock_http = _wire_conversations(mocker, client, {"stored-id": pending})

    client.chat_completion({"messages": later})

    assert mock_http.call_args_list[0].kwargs["full_url"].endswith("/conversations/stored-id")  # the validation read
    post = _posts(mock_http)[0]["json_data"]
    assert post["conversation"]["id"] != "stored-id"
    assert [m["role"] for m in post["messages"]] == ["user", "assistant", "user"]  # the full transcript
    assert LABEL_RE.match(post["messages"][0]["content"])
    assert _entry_for(run_store, later)["conversation_id"] == post["conversation"]["id"]


@pytest.mark.parametrize("failure", ["not found", "missing reply"])
def test_per_run_an_unreadable_or_foreign_stored_conversation_starts_a_new_one(mocker, run_store, failure):
    client = _per_run_client()
    later = _later_messages()
    _store_run(_run_key("", "1234", later), "stored-id", time.time())
    if failure == "not found":
        mock_http = _wire_conversations(mocker, client, {}, unreadable=("stored-id",))
    else:
        mock_http = _wire_conversations(mocker, client, {"stored-id": _reply_convo(4, "another run's reply")})

    client.chat_completion({"messages": later})

    calls = mock_http.call_args_list
    assert calls[0].kwargs["full_url"].endswith("/conversations/stored-id")  # the validation read
    post = _posts(mock_http)[0]["json_data"]
    assert post["conversation"]["id"] != "stored-id"
    assert [m["role"] for m in post["messages"]] == ["user", "assistant", "tool"]
    assert LABEL_RE.match(post["messages"][0]["content"])
    assert _entry_for(run_store, later)["conversation_id"] == post["conversation"]["id"]  # re-stored for the next turn


def test_per_run_a_baseline_of_zero_is_not_the_same_as_unreadable(mocker, run_store):
    """An empty stored conversation is readable but proves nothing about the run, so it is not reused either."""
    client = _per_run_client()
    later = _later_messages()
    _store_run(_run_key("", "1234", later), "stored-id", time.time())
    mock_http = _wire_conversations(mocker, client, {"stored-id": {"messages": []}})
    client.chat_completion({"messages": later})
    assert _posts(mock_http)[0]["json_data"]["conversation"]["id"] != "stored-id"


def test_conversation_continues_compares_text_and_tool_calls():
    mine = [{"role": "assistant", "content": "a  b"}]
    assert _conversation_continues(_reply_convo(2, "a b"), mine)
    assert not _conversation_continues(_reply_convo(2, "a c"), mine)
    calls = [{"role": "assistant", "content": None, "tool_calls": [TOOL_CALL]}]
    assert _conversation_continues(_tool_call_convo(2), calls)
    other_id = copy.deepcopy(TOOL_CALL)
    other_id["id"] = "other"
    assert not _conversation_continues(_tool_call_convo(2), [{"role": "assistant", "content": None, "tool_calls": [other_id]}])
    prefixed = copy.deepcopy(TOOL_CALL)
    prefixed["function"]["name"] = "function::getIncidents"
    convo = _tool_call_convo(2)
    convo["messages"][-1]["tool_calls"] = [prefixed]
    assert _conversation_continues(convo, calls)  # the prefix a model puts on a name is ignored
    assert not _conversation_continues({"messages": []}, mine)
    assert not _conversation_continues(None, mine)
    assert not _conversation_continues(_reply_convo(2, "x"), [{"role": "user", "content": "x"}])
    assert not _conversation_continues(_reply_convo(2, None), [{"role": "assistant", "content": ""}])  # nothing to compare


def test_per_run_storage_read_failure_falls_back_without_raising(mocker, run_store):
    client = _per_run_client()
    mocker.patch("GuardianCohere.get_integration_context", side_effect=RuntimeError("context down"))
    mocker.patch("GuardianCohere.get_integration_context_with_version", side_effect=RuntimeError("context down"))
    mock_http = _wire(mocker, client, _reply_convo(2))

    client.chat_completion({"messages": _start_messages()})  # start of run: new id, full body
    client.chat_completion({"messages": _later_messages()})  # later turn: no entry can be read

    first, second = _posts(mock_http)
    assert first["json_data"]["conversation"]["id"] != second["json_data"]["conversation"]["id"]
    assert [m["role"] for m in second["json_data"]["messages"]] == ["user", "assistant", "tool"]
    assert run_store["writes"] == 0


def test_per_run_storage_write_failure_falls_back_without_raising(mocker, run_store):
    client = _per_run_client()
    mocker.patch("GuardianCohere.set_integration_context", side_effect=RuntimeError("context read-only"))
    mock_http = _wire(mocker, client, _reply_convo(2))

    result = client.chat_completion({"messages": _start_messages()})
    assert result["choices"][0]["message"]["content"] == "done"
    client.chat_completion({"messages": _later_messages()})  # nothing was stored: a new conversation, full history
    first, second = _posts(mock_http)
    assert first["json_data"]["conversation"]["id"] != second["json_data"]["conversation"]["id"]
    assert len(second["json_data"]["messages"]) == 3


def test_per_run_a_context_that_is_not_a_dict_is_treated_as_empty(mocker, run_store):
    client = _per_run_client()
    mocker.patch("GuardianCohere.get_integration_context", return_value=None)
    mocker.patch("GuardianCohere.get_integration_context_with_version", return_value=(None, 3))
    _wire(mocker, client, _reply_convo(2))
    assert client.chat_completion({"messages": _start_messages()})["choices"][0]["message"]["content"] == "done"


def test_store_run_repeats_the_write_when_another_call_wrote_first(run_store):
    now = time.time()

    def other_call_writes():
        run_store["context"] = {RUN_CONTEXT_KEY: {"other": {"conversation_id": "c-other", "created": now}}}
        run_store["version"] += 1

    run_store["before_write"] = other_call_writes
    assert _store_run("mine", "c-mine", now) is True
    assert set(run_store["context"][RUN_CONTEXT_KEY]) == {"other", "mine"}  # the other call's entry survived
    assert run_store["writes"] == 1


def test_store_run_gives_up_after_a_few_version_conflicts_without_raising(mocker, run_store):
    calls = []

    def always_stale(context, sync=True, version=-1):
        calls.append(version)
        raise ValueError("version conflict")

    mocker.patch("GuardianCohere.set_integration_context", side_effect=always_stale)
    assert _store_run("k", "c", time.time()) is False
    assert len(calls) == RUN_STORE_ATTEMPTS


def test_store_run_works_where_the_versioned_helpers_are_missing(mocker, run_store):
    mocker.patch("GuardianCohere.get_integration_context_with_version", side_effect=NameError("not defined"))
    assert _store_run("k", "c", time.time()) is True
    assert run_store["context"][RUN_CONTEXT_KEY]["k"]["conversation_id"] == "c"


def test_prune_runs_drops_old_and_malformed_entries():
    now = 1_000_000.0
    runs = {
        "fresh": {"conversation_id": "a", "created": now - 10},
        "edge": {"conversation_id": "b", "created": now - RUN_MAX_AGE_SECONDS},
        "old": {"conversation_id": "c", "created": now - RUN_MAX_AGE_SECONDS - 1},
        "no-id": {"created": now},
        "bad": "text",
    }
    assert set(_prune_runs(runs, now)) == {"fresh", "edge"}


def test_prune_runs_keeps_the_newest_entries_up_to_the_cap():
    now = 1_000_000.0
    runs = {f"k{i}": {"conversation_id": f"c{i}", "created": now - i} for i in range(RUN_MAX_ENTRIES + 25)}
    kept = _prune_runs(runs, now)
    assert len(kept) == RUN_MAX_ENTRIES
    assert "k0" in kept and f"k{RUN_MAX_ENTRIES + 24}" not in kept


def test_store_run_prunes_on_write_and_keeps_other_context_keys(run_store):
    now = time.time()
    runs = {f"k{i}": {"conversation_id": f"c{i}", "created": now - 10 - i} for i in range(RUN_MAX_ENTRIES)}
    runs["stale"] = {"conversation_id": "s", "created": now - RUN_MAX_AGE_SECONDS - 100}
    run_store["context"] = {RUN_CONTEXT_KEY: runs, "something_else": {"keep": True}}

    assert _store_run("new", "conv-new", now) is True

    stored = run_store["context"]
    assert stored["something_else"] == {"keep": True}
    assert len(stored[RUN_CONTEXT_KEY]) == RUN_MAX_ENTRIES
    assert "stale" not in stored[RUN_CONTEXT_KEY]
    assert stored[RUN_CONTEXT_KEY]["new"]["conversation_id"] == "conv-new"
    assert f"k{RUN_MAX_ENTRIES - 1}" not in stored[RUN_CONTEXT_KEY]  # the oldest live entry made room


def test_per_run_label_is_added_once_and_only_to_the_copy_sent(mocker, run_store):
    client = _per_run_client()
    mock_http = _wire(mocker, client, [_reply_convo(2), _tool_call_convo(2), _reply_convo(4)])
    start = _start_messages()
    later = _later_messages()
    start_before, later_before = copy.deepcopy(start), copy.deepcopy(later)

    client.chat_completion({"messages": start})
    client.chat_completion({"messages": later})

    first, second = _posts(mock_http)
    sent = first["json_data"]["messages"][0]["content"]
    assert LABEL_RE.match(sent)
    assert sent.endswith("\n\nInvestigate this incident")
    assert sent.count("Guardian run") == 1
    assert "Guardian run" not in json.dumps(second["json_data"]["messages"])  # a later turn is not labelled
    assert start == start_before and later == later_before  # the caller's messages are untouched


def test_per_run_label_goes_on_the_first_user_message_in_text_mode_too(run_store):
    client = _per_run_client()
    client.tool_result_format = "text"
    body = client.build_request_body({"messages": _later_messages()}, "c1", send_full=True, label="Guardian run - x")
    assert body["messages"][0]["content"].startswith("Guardian run - x\n\nInvestigate")
    assert sum("Guardian run - x" in str(m.get("content")) for m in body["messages"]) == 1


def test_per_run_without_an_investigation_leaves_out_the_incident_part(mocker, run_store):
    client = _per_run_client()
    mocker.patch("GuardianCohere.demisto.investigation", side_effect=RuntimeError("no investigation"))
    mock_http = _wire(mocker, client, _reply_convo(2))
    client.chat_completion({"messages": _start_messages()})
    sent = _posts(mock_http)[0]["json_data"]["messages"][0]["content"]
    assert re.match(r"^Guardian run - \d{4}-\d{2}-\d{2} \d{2}:\d{2}\n\nInvestigate", sent)


@pytest.mark.parametrize("value", [None, {}, {"id": None}, "text", {"id": " "}])
def test_investigation_id_is_empty_when_unavailable(mocker, value):
    mocker.patch("GuardianCohere.demisto.investigation", return_value=value)
    assert _investigation_id() == ""


def test_investigation_id_reads_the_id(mocker):
    mocker.patch("GuardianCohere.demisto.investigation", return_value={"id": 77})
    assert _investigation_id() == "77"


def test_compaction_mark_recognises_a_checkpoint_and_the_free_path_note():
    plain = _later_messages()
    assert _compaction_mark(plain) == ""
    checkpoint = {"role": "system", "content": "CONVERSATION CHECKPOINT -- earlier turns summarized\nsummary one", "guardian_checkpoint": True}
    other = dict(checkpoint, content="CONVERSATION CHECKPOINT -- earlier turns summarized\nsummary two")
    first, second = _compaction_mark(plain[:2] + [checkpoint] + plain[2:]), _compaction_mark(plain[:2] + [other] + plain[2:])
    assert first.startswith("checkpoint:") and first != second
    note = {"role": "user", "content": "[Guardian-compaction] 3 earlier transcript turn(s) were dropped"}
    note_2 = {"role": "user", "content": "[Guardian-compaction] 9 earlier transcript turn(s) were dropped"}
    with_note, with_note_2 = _compaction_mark(plain[:2] + [note] + plain[2:]), _compaction_mark(plain[:2] + [note_2] + plain[2:])
    assert with_note.startswith("dropped:") and "checkpoint" not in with_note
    assert with_note != with_note_2  # the note is rewritten with a higher total on every further drop
    assert with_note == _compaction_mark(plain[:2] + [dict(note)] + plain[2:])  # an unchanged note keeps its mark
    both = _compaction_mark(plain[:2] + [checkpoint, note] + plain[2:])
    assert re.fullmatch(r"checkpoint:[0-9a-f]{16}\|dropped:[0-9a-f]{16}", both)
    assert both != _compaction_mark(plain[:2] + [checkpoint, note_2] + plain[2:])  # only the note changed
    assert both != _compaction_mark(plain[:2] + [other, note] + plain[2:])  # only the checkpoint changed
    # a user message that merely mentions it later in the text is not a note
    assert _compaction_mark(plain + [{"role": "user", "content": "see [Guardian-compaction] x"}]) == ""


def test_per_run_a_compacted_transcript_starts_a_new_conversation_once_per_summary(mocker, run_store):
    client = _per_run_client()
    mock_http = _wire_conversations(mocker, client, {})
    client.chat_completion({"messages": _start_messages()})
    first_id = _posts(mock_http)[0]["json_data"]["conversation"]["id"]
    # the same run, after Guardian summarized the early turns: a checkpoint right after the system prompt and task
    checkpoint = {"role": "system", "content": "CONVERSATION CHECKPOINT -- earlier turns summarized\nfound X", "guardian_checkpoint": True}
    compacted = _start_messages() + [checkpoint, {"role": "assistant", "content": "kept reply"}, {"role": "user", "content": "go on"}]

    client.chat_completion({"messages": compacted})

    post = _posts(mock_http)[1]["json_data"]
    second_id = post["conversation"]["id"]
    assert second_id != first_id
    assert LABEL_RE.match(post["messages"][0]["content"])
    assert "found X" in post["system"]  # the summary travels with the system text
    assert [m["role"] for m in post["messages"]] == ["user", "assistant", "user"]
    assert _entry_for(run_store, compacted)["compaction"].startswith("checkpoint:")

    # the next turn of the same compacted run continues the new conversation (its last reply was "fresh reply")
    mock_http = _wire(mocker, client, [_reply_convo(2, "fresh reply"), _reply_convo(4, "next")])
    later = compacted + [{"role": "assistant", "content": "fresh reply"}, {"role": "user", "content": "and then"}]
    client.chat_completion({"messages": later})
    post = _posts(mock_http)[0]["json_data"]
    assert post["conversation"] == {"id": second_id}
    assert post["messages"] == [{"role": "user", "content": "and then"}]


def test_per_run_the_free_path_note_restarts_the_conversation_whenever_its_text_changes(mocker, run_store):
    client = _per_run_client()
    mock_http = _wire_conversations(mocker, client, {})
    client.chat_completion({"messages": _start_messages()})
    note = {"role": "user", "content": "[Guardian-compaction] 4 earlier transcript turn(s) were dropped"}
    compacted = _start_messages() + [note, {"role": "assistant", "content": "kept"}, {"role": "user", "content": "next"}]
    client.chat_completion({"messages": compacted})
    first_id = _posts(mock_http)[0]["json_data"]["conversation"]["id"]
    restarted_id = _posts(mock_http)[1]["json_data"]["conversation"]["id"]
    assert restarted_id != first_id  # the first note starts a new conversation

    # the same note on the next turn: the run goes on in the conversation that was started above
    same_note = _start_messages() + [dict(note), {"role": "assistant", "content": "fresh reply"}, {"role": "user", "content": "again"}]
    mock_http = _wire(mocker, client, [_reply_convo(2, "fresh reply"), _reply_convo(4, "next")])
    client.chat_completion({"messages": same_note})
    post = _posts(mock_http)[0]["json_data"]
    assert post["conversation"] == {"id": restarted_id}
    assert post["messages"] == [{"role": "user", "content": "again"}]

    # more turns were dropped, so the note carries a higher total: the conversation is started again, or North would keep every turn
    more_dropped = dict(note, content="[Guardian-compaction] 9 earlier transcript turn(s) were dropped")
    more = _start_messages() + [more_dropped, {"role": "assistant", "content": "fresh reply"}, {"role": "user", "content": "and again"}]
    mock_http = _wire_conversations(mocker, client, {restarted_id: _reply_convo(2, "fresh reply")})
    client.chat_completion({"messages": more})
    post = _posts(mock_http)[0]["json_data"]
    assert post["conversation"]["id"] not in (first_id, restarted_id)
    assert LABEL_RE.match(post["messages"][0]["content"])
    assert _entry_for(run_store, more)["compaction"] == _compaction_mark(more)


def test_per_run_with_a_checkpoint_a_changed_note_alone_restarts_the_conversation(mocker, run_store):
    client = _per_run_client()
    checkpoint = {"role": "system", "content": "CONVERSATION CHECKPOINT -- earlier turns summarized\nfound X", "guardian_checkpoint": True}
    note = {"role": "user", "content": "[Guardian-compaction] 4 earlier transcript turn(s) were dropped"}
    tail = [{"role": "assistant", "content": "kept"}, {"role": "user", "content": "next"}]
    first = _start_messages() + [checkpoint, note] + tail
    mock_http = _wire_conversations(mocker, client, {})
    client.chat_completion({"messages": first})
    first_id = _posts(mock_http)[0]["json_data"]["conversation"]["id"]

    changed = _start_messages() + [checkpoint, dict(note, content="[Guardian-compaction] 9 earlier transcript turn(s) were dropped")] + tail
    mock_http = _wire_conversations(mocker, client, {first_id: _reply_convo(2, "kept")})
    client.chat_completion({"messages": changed})

    post = _posts(mock_http)[0]["json_data"]
    assert post["conversation"]["id"] != first_id
    assert LABEL_RE.match(post["messages"][0]["content"])
    assert _entry_for(run_store, changed)["compaction"] == _compaction_mark(changed)


def test_per_run_does_not_require_a_session_id():
    params = {"endpoint_url": "https://h", "agent_id": "a", "bearer_token": "t", "conversation_mode": "per_run"}
    assert build_client(params, verify=True, proxy=False).conversation_mode == "per_run"


def test_per_run_test_module_is_a_stateless_round_trip_that_stores_nothing(mocker, run_store):
    client = _per_run_client()
    mock_http = _wire(mocker, client, _reply_convo(2))
    assert run_test_module_command(client) == "ok"
    assert [c.kwargs["method"] for c in mock_http.call_args_list] == ["POST", "GET"]
    assert "Guardian run" not in json.dumps(_posts(mock_http)[0]["json_data"]["messages"])
    assert run_store["writes"] == 0 and run_store["context"] == {}


def test_stateless_and_reuse_never_touch_the_run_store_or_add_a_label(mocker, run_store):
    stateless = _client(conversation_mode=CONVERSATION_MODE_STATELESS)
    mock_http = _wire(mocker, stateless, _reply_convo(2))
    stateless.chat_completion({"messages": _start_messages()})
    sent = _posts(mock_http)[0]["json_data"]
    assert sent["messages"] == [{"role": "user", "content": "Investigate this incident"}]

    reuse = _client(conversation_mode=CONVERSATION_MODE_REUSE, session_id="sess-123")
    mock_http = _wire(mocker, reuse, [_reply_convo(2), _reply_convo(4)])
    reuse.chat_completion({"messages": _later_messages()})
    calls = mock_http.call_args_list
    assert [c.kwargs["method"] for c in calls] == ["GET", "POST", "GET"]  # reuse trusts its fixed id: no validation
    sent = _posts(mock_http)[0]["json_data"]
    assert sent["conversation"] == {"id": "sess-123"}
    assert sent["messages"] == [{"role": "tool", "tool_call_id": "c1", "content": "result"}]
    assert run_store["writes"] == 0 and run_store["context"] == {}
