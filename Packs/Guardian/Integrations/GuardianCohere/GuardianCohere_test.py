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

import json

import pytest
from CommonServerPython import DemistoException

from GuardianCohere import (
    CONVERSATION_MODE_REUSE,
    CONVERSATION_MODE_STATELESS,
    CohereNorthClient,
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
    assert body["tool_choice"] == "auto"
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
    not after the 90s poll window."""
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
