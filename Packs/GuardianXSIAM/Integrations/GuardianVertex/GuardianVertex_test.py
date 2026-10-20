"""GuardianVertex unit tests.

No live LLM endpoint/key is available in this environment, so every HTTP boundary is mocked at
``Client._http_request`` (and, for the vertex adapter, the token mint is mocked too — see the
"Vertex" section below). These tests exercise the four original scenarios:
  1. an OpenAI-compatible success (test_openai_compatible_success)
  2. an Azure success              (test_azure_success)
  3. a 429-retry                   (test_chat_completion_wires_up_429_retry_to_http_request +
                                     test_429_retries_exhausted_raises_clear_rate_limit_error)
  4. an Azure content-filter, both HTTP 400 on input and finish_reason=content_filter on output
     (test_azure_content_filter_on_input_http_400 / test_azure_content_filter_on_output_finish_reason)
plus additional coverage for adapter URL/header construction, provider selection, argument
parsing, test_module, and (added for the vertex adapter) Gemini request/response translation,
tool-schema cleaning, and the vertex content-filter path.

``test_module`` (the real integration command, imported below for direct-call test cases) is
aliased on import to ``run_test_module_command`` — importing it under its own name into this
module's namespace makes pytest's default ``test_*`` collection pick up the *imported function
object itself* as a bogus test item (it has no ``client`` fixture to satisfy), which surfaced as
a collection error the first time these tests were actually run locally.
"""

import json

import pytest
from CommonServerPython import DemistoException

from GuardianVertex import (
    CONTENT_FILTER_FINISH_REASON,
    AzureChatAdapter,
    BaseChatAdapter,
    Client,
    VertexChatAdapter,
    build_adapter,
    guardian_llm_chat_command,
    test_module as run_test_module_command,
)


class _FakeResponse:
    """Minimal stand-in for a requests.Response — just enough of the surface that
    DemistoException.res is inspected for (.status_code / .json() / .text)."""

    def __init__(self, status_code, json_body=None, text=None):
        self.status_code = status_code
        self._json_body = json_body
        self.text = text if text is not None else json.dumps(json_body or {})

    def json(self):
        if self._json_body is None:
            raise ValueError("no JSON body")
        return self._json_body


def _openai_success_body(finish_reason="stop", tool_calls=None, cached_tokens=5, content="hi there"):
    message = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
        message["content"] = None
    return {
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "gpt-4o-mini",
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": finish_reason,
            }
        ],
        "usage": {
            "prompt_tokens": 20,
            "completion_tokens": 4,
            "total_tokens": 24,
            "prompt_tokens_details": {"cached_tokens": cached_tokens},
        },
    }


def _openai_compatible_client(mocker, http_request_return=None, http_request_side_effect=None):
    adapter = BaseChatAdapter(
        base_url="https://api.openai.com",
        model="gpt-4o-mini",
        api_key="sk-test",
        auth_style="bearer",
    )
    client = Client(adapter=adapter, verify=False, proxy=False)
    mock_http = mocker.patch.object(
        client, "_http_request", return_value=http_request_return, side_effect=http_request_side_effect
    )
    return client, mock_http


def _azure_client(mocker, http_request_return=None, http_request_side_effect=None, auth_style="api-key"):
    adapter = AzureChatAdapter(
        base_url="https://my-resource.openai.azure.com",
        model="gpt-4o-deployment",
        api_key="azure-key",
        auth_style=auth_style,
        api_version="2024-10-21",
    )
    client = Client(adapter=adapter, verify=False, proxy=False)
    mock_http = mocker.patch.object(
        client, "_http_request", return_value=http_request_return, side_effect=http_request_side_effect
    )
    return client, mock_http


""" ------------------------- adapter URL / header construction ------------------------- """


def test_base_adapter_build_url_appends_v1_when_missing():
    adapter = BaseChatAdapter(base_url="https://api.openai.com", model="gpt-4o-mini", api_key="k")
    assert adapter.build_url() == "https://api.openai.com/v1/chat/completions"


def test_base_adapter_build_url_does_not_double_append_v1():
    adapter = BaseChatAdapter(base_url="http://localhost:8000/v1", model="local-model", api_key="")
    assert adapter.build_url() == "http://localhost:8000/v1/chat/completions"


def test_base_adapter_build_headers_bearer():
    adapter = BaseChatAdapter(
        base_url="https://api.openai.com", model="gpt-4o-mini", api_key="sk-test", auth_style="bearer"
    )
    assert adapter.build_headers() == {"Content-Type": "application/json", "Authorization": "Bearer sk-test"}


def test_base_adapter_build_headers_api_key_style():
    adapter = BaseChatAdapter(base_url="https://host", model="m", api_key="k", auth_style="api-key")
    assert adapter.build_headers() == {"Content-Type": "application/json", "api-key": "k"}


def test_base_adapter_build_params_is_none():
    adapter = BaseChatAdapter(base_url="https://host", model="m", api_key="k")
    assert adapter.build_params() is None


def test_azure_adapter_build_url_and_params():
    adapter = AzureChatAdapter(
        base_url="https://my-resource.openai.azure.com",
        model="gpt-4o-deployment",
        api_key="k",
        api_version="2024-10-21",
    )
    assert adapter.build_url() == (
        "https://my-resource.openai.azure.com/openai/deployments/gpt-4o-deployment/chat/completions"
    )
    assert adapter.build_params() == {"api-version": "2024-10-21"}


def test_azure_adapter_defaults_api_version_when_not_given():
    adapter = AzureChatAdapter(base_url="https://host", model="m", api_key="k")
    assert adapter.api_version == "2024-10-21"


def test_azure_adapter_build_headers_entra_token():
    adapter = AzureChatAdapter(base_url="https://host", model="m", api_key="aad-token", auth_style="entra-token")
    assert adapter.build_headers() == {"Content-Type": "application/json", "Authorization": "Bearer aad-token"}


def test_azure_adapter_build_headers_api_key_default():
    adapter = AzureChatAdapter(base_url="https://host", model="m", api_key="azure-key", auth_style="api-key")
    assert adapter.build_headers() == {"Content-Type": "application/json", "api-key": "azure-key"}


def test_azure_adapter_build_request_body_drops_model():
    adapter = AzureChatAdapter(base_url="https://host", model="deployment-x", api_key="k")
    body = adapter.build_request_body({"messages": [{"role": "user", "content": "hi"}]})
    assert "model" not in body
    assert body["messages"] == [{"role": "user", "content": "hi"}]


def test_base_adapter_build_request_body_sets_default_model():
    adapter = BaseChatAdapter(base_url="https://host", model="gpt-4o-mini", api_key="k")
    body = adapter.build_request_body({"messages": [{"role": "user", "content": "hi"}], "temperature": None})
    assert body["model"] == "gpt-4o-mini"
    assert "temperature" not in body  # None values are dropped, not sent as null


""" ------------------------- provider selection (build_adapter) ------------------------- """


def test_build_adapter_selects_openai_compatible_by_default():
    adapter = build_adapter({"base_url": "https://api.openai.com", "model": "gpt-4o-mini", "api_key": "k"})
    assert isinstance(adapter, BaseChatAdapter)
    assert not isinstance(adapter, AzureChatAdapter)


def test_build_adapter_selects_azure():
    adapter = build_adapter(
        {
            "provider": "azure",
            "base_url": "https://host",
            "model": "deployment-x",
            "api_key": "k",
            "api_version": "2023-05-15",
        }
    )
    assert isinstance(adapter, AzureChatAdapter)
    assert adapter.api_version == "2023-05-15"


def test_build_adapter_rejects_unknown_provider():
    with pytest.raises(DemistoException):
        build_adapter({"provider": "not-a-real-provider", "base_url": "https://host", "model": "m"})


def test_build_adapter_requires_base_url():
    with pytest.raises(DemistoException):
        build_adapter({"provider": "openai-compatible", "model": "m"})


def test_build_adapter_requires_model():
    with pytest.raises(DemistoException):
        build_adapter({"provider": "openai-compatible", "base_url": "https://host"})


""" ------------------------- Scenario 1: OpenAI-compatible success ------------------------- """


def test_openai_compatible_success(mocker):
    client, mock_http = _openai_compatible_client(mocker, http_request_return=_openai_success_body())
    args = {"messages": json.dumps([{"role": "user", "content": "say hi"}])}

    result = guardian_llm_chat_command(client, args)

    assert result.outputs["content_filter"] is False
    assert result.outputs["finish_reason"] == "stop"
    assert result.outputs["choices"][0]["message"]["content"] == "hi there"
    assert result.outputs["usage"]["cached_tokens"] == 5
    assert result.outputs["usage"]["total_tokens"] == 24
    assert result.outputs_prefix == "Guardian.LLM.Completion"

    mock_http.assert_called_once()
    call_kwargs = mock_http.call_args.kwargs
    assert call_kwargs["full_url"] == "https://api.openai.com/v1/chat/completions"
    assert call_kwargs["headers"]["Authorization"] == "Bearer sk-test"
    assert call_kwargs["method"] == "POST"
    assert call_kwargs["status_list_to_retry"] == [429]


def test_openai_compatible_success_with_tool_calls(mocker):
    tool_calls = [
        {
            "id": "call_1",
            "type": "function",
            "function": {"name": "ip_reputation", "arguments": '{"ip":"8.8.8.8"}'},
        }
    ]
    client, _ = _openai_compatible_client(
        mocker, http_request_return=_openai_success_body(finish_reason="tool_calls", tool_calls=tool_calls)
    )
    args = {
        "messages": json.dumps([{"role": "user", "content": "look up 8.8.8.8"}]),
        "tools": json.dumps(
            [{"type": "function", "function": {"name": "ip_reputation", "parameters": {"type": "object"}}}]
        ),
        "tool_choice": "auto",
    }

    result = guardian_llm_chat_command(client, args)

    assert result.outputs["finish_reason"] == "tool_calls"
    assert result.outputs["choices"][0]["message"]["tool_calls"] == tool_calls
    assert result.outputs["content_filter"] is False


""" ------------------------- Scenario 2: Azure success ------------------------- """


def test_azure_success(mocker):
    client, mock_http = _azure_client(mocker, http_request_return=_openai_success_body(finish_reason="stop"))
    args = {"messages": json.dumps([{"role": "user", "content": "say hi"}])}

    result = guardian_llm_chat_command(client, args)

    assert result.outputs["content_filter"] is False
    assert result.outputs["finish_reason"] == "stop"

    call_kwargs = mock_http.call_args.kwargs
    assert call_kwargs["full_url"] == (
        "https://my-resource.openai.azure.com/openai/deployments/gpt-4o-deployment/chat/completions"
    )
    assert call_kwargs["params"] == {"api-version": "2024-10-21"}
    assert call_kwargs["headers"]["api-key"] == "azure-key"
    assert "model" not in call_kwargs["json_data"]


def test_azure_success_entra_token_auth(mocker):
    client, mock_http = _azure_client(mocker, http_request_return=_openai_success_body(), auth_style="entra-token")
    args = {"messages": json.dumps([{"role": "user", "content": "hi"}])}

    guardian_llm_chat_command(client, args)

    call_kwargs = mock_http.call_args.kwargs
    assert call_kwargs["headers"]["Authorization"] == "Bearer azure-key"
    assert "api-key" not in call_kwargs["headers"]


""" ------------------------- Scenario 3: 429 retry ------------------------- """


def test_chat_completion_wires_up_429_retry_to_http_request(mocker):
    """Retrying on 429 itself happens inside the real _http_request/urllib3 Retry adapter
    (mocked out here, so it can't be re-exercised at this layer) — what unit tests at this
    boundary CAN and must verify is that Client.chat_completion asks the framework to retry
    on 429 with the documented policy (status_list_to_retry/retries/backoff_factor)."""
    client, mock_http = _openai_compatible_client(mocker, http_request_return=_openai_success_body())

    client.chat_completion({"messages": [{"role": "user", "content": "hi"}]})

    call_kwargs = mock_http.call_args.kwargs
    assert call_kwargs["status_list_to_retry"] == [429]
    assert call_kwargs["retries"] == 3
    assert call_kwargs["backoff_factor"] == 5


def test_429_retries_exhausted_raises_clear_rate_limit_error(mocker):
    """Once _http_request's own retries are exhausted it raises a DemistoException carrying
    the 429 response; Client.chat_completion re-raises with a clearer, rate-limit-specific
    message instead of letting the framework's generic one surface unexplained."""
    res = _FakeResponse(429, json_body={"error": {"message": "Rate limit reached"}})
    err = DemistoException("Error in API call [429] - Too Many Requests", res=res)
    client, _ = _openai_compatible_client(mocker, http_request_side_effect=err)

    with pytest.raises(DemistoException) as exc_info:
        client.chat_completion({"messages": [{"role": "user", "content": "hi"}]})

    message = str(exc_info.value).lower()
    assert "rate-limited" in message or "429" in message


""" ------------------------- Scenario 4: Azure content-filter (input 400 + output finish_reason) ------------------------- """


def test_azure_content_filter_on_input_http_400(mocker):
    """Azure blocks the *prompt* itself pre-generation: HTTP 400 with an Azure content-filter
    error body. This must come back as a structured, non-silent content_filter result — not a
    raised exception, and not a silently empty completion."""
    error_body = {
        "error": {
            "code": "content_filter",
            "message": (
                "The response was filtered due to the prompt triggering Azure OpenAI's "
                "content management policy."
            ),
            "innererror": {
                "code": "ResponsibleAIPolicyViolation",
                "content_filter_result": {"violence": {"filtered": True, "severity": "high"}},
            },
        }
    }
    res = _FakeResponse(400, json_body=error_body)
    err = DemistoException("Error in API call [400] - Bad Request", res=res)
    client, _ = _azure_client(mocker, http_request_side_effect=err)

    result = client.chat_completion({"messages": [{"role": "user", "content": "something blocked"}]})

    assert result["content_filter"] is True
    assert result["finish_reason"] == "content_filter"
    assert result["choices"] == []
    assert "content management policy" in result["content_filter_detail"]["message"]
    assert result["content_filter_detail"]["raw_error"] == error_body


def test_azure_content_filter_on_output_finish_reason(mocker):
    """Azure can also block a *completion* after generation: a normal 200 response where a
    choice's finish_reason == "content_filter". Must be detected with no HTTP-level error."""
    body = _openai_success_body(finish_reason="content_filter", content=None)
    client, _ = _azure_client(mocker, http_request_return=body)

    result = client.chat_completion({"messages": [{"role": "user", "content": "hi"}]})

    assert result["content_filter"] is True
    assert result["finish_reason"] == "content_filter"


def test_openai_compatible_adapter_skips_content_filter_detection_on_400(mocker):
    """Providers without a content-filtering concept (plain OpenAI-compatible, e.g.
    self-hosted vLLM/TGI/Ollama) have no special-case for HTTP 400 — a generic bad-request
    error must propagate as a normal exception, not be swallowed into a false content_filter
    result."""
    res = _FakeResponse(400, json_body={"error": {"code": "invalid_request_error", "message": "bad request"}})
    err = DemistoException("Error in API call [400] - Bad Request", res=res)
    client, _ = _openai_compatible_client(mocker, http_request_side_effect=err)

    with pytest.raises(DemistoException):
        client.chat_completion({"messages": [{"role": "user", "content": "hi"}]})


def test_azure_adapter_ignores_non_content_filter_400(mocker):
    """An Azure 400 that ISN'T a content-filter rejection (e.g. a malformed request) must
    still propagate as a normal error rather than being mistaken for a content-filter block."""
    res = _FakeResponse(400, json_body={"error": {"code": "invalid_request_error", "message": "bad request"}})
    err = DemistoException("Error in API call [400] - Bad Request", res=res)
    client, _ = _azure_client(mocker, http_request_side_effect=err)

    with pytest.raises(DemistoException):
        client.chat_completion({"messages": [{"role": "user", "content": "hi"}]})


""" ------------------------- guardian_llm_chat_command argument handling ------------------------- """


def test_guardian_llm_chat_command_builds_full_request_body(mocker):
    client, mock_http = _openai_compatible_client(mocker, http_request_return=_openai_success_body())
    args = {
        "messages": json.dumps([{"role": "user", "content": "hi"}]),
        "tools": json.dumps([{"type": "function", "function": {"name": "f"}}]),
        "tool_choice": json.dumps({"type": "function", "function": {"name": "f"}}),
        "response_format": json.dumps({"type": "json_object"}),
        "temperature": "0.3",
        "reasoning_effort": "high",
        "parallel_tool_calls": "false",
    }

    guardian_llm_chat_command(client, args)

    body = mock_http.call_args.kwargs["json_data"]
    assert body["tools"] == [{"type": "function", "function": {"name": "f"}}]
    assert body["tool_choice"] == {"type": "function", "function": {"name": "f"}}
    assert body["response_format"] == {"type": "json_object"}
    assert body["temperature"] == 0.3
    assert body["reasoning_effort"] == "high"
    assert body["parallel_tool_calls"] is False


def test_guardian_llm_chat_command_tool_choice_plain_string(mocker):
    client, mock_http = _openai_compatible_client(mocker, http_request_return=_openai_success_body())
    args = {"messages": json.dumps([{"role": "user", "content": "hi"}]), "tool_choice": "auto"}

    guardian_llm_chat_command(client, args)

    assert mock_http.call_args.kwargs["json_data"]["tool_choice"] == "auto"


def test_guardian_llm_chat_command_requires_messages():
    with pytest.raises(DemistoException):
        guardian_llm_chat_command(client=None, args={})


def test_guardian_llm_chat_command_rejects_invalid_json_messages():
    with pytest.raises(DemistoException):
        guardian_llm_chat_command(client=None, args={"messages": "not json"})


def test_guardian_llm_chat_command_rejects_non_list_messages():
    with pytest.raises(DemistoException):
        guardian_llm_chat_command(client=None, args={"messages": json.dumps({"role": "user"})})


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
# surrounding contract. Identical to GuardianCohere_test.py's coverage of the same (byte-identical)
# function, since each integration carries its own copy.


def test_guardian_llm_chat_command_accepts_raw_list_messages(mocker):
    # The real production shape: GuardianReasoningTick passes messages as an actual Python list
    # object (never a JSON string) straight through demisto.executeCommand -- no existing test
    # exercised guardian_llm_chat_command at this exact boundary.
    client, mock_http = _openai_compatible_client(mocker, http_request_return=_openai_success_body())
    guardian_llm_chat_command(client, {"messages": [{"role": "user", "content": "say hi"}]})
    assert mock_http.call_args.kwargs["json_data"]["messages"] == [{"role": "user", "content": "say hi"}]


def test_guardian_llm_chat_command_user_message_only_convenience_shape(mocker):
    client, mock_http = _openai_compatible_client(mocker, http_request_return=_openai_success_body())
    guardian_llm_chat_command(client, {"user_message": "look up 8.8.8.8"})
    assert mock_http.call_args.kwargs["json_data"]["messages"] == [
        {"role": "user", "content": "look up 8.8.8.8"}
    ]


def test_resolve_messages_user_message_only():
    from GuardianVertex import _resolve_messages

    assert _resolve_messages({"user_message": "look up 8.8.8.8"}) == [
        {"role": "user", "content": "look up 8.8.8.8"}
    ]


def test_resolve_messages_system_and_user_message_order():
    from GuardianVertex import _resolve_messages

    assert _resolve_messages({"system_message": "sys", "user_message": "hi"}) == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
    ]


def test_resolve_messages_system_message_alone_raises():
    from GuardianVertex import _resolve_messages

    with pytest.raises(DemistoException):
        _resolve_messages({"system_message": "sys only"})


def test_resolve_messages_messages_and_user_message_raises():
    from GuardianVertex import _resolve_messages

    with pytest.raises(DemistoException):
        _resolve_messages({"messages": [{"role": "user", "content": "hi"}], "user_message": "hi again"})


def test_resolve_messages_empty_args_raises_with_exact_message():
    from GuardianVertex import _resolve_messages

    with pytest.raises(DemistoException, match='Provide "messages"'):
        _resolve_messages({})


def test_resolve_messages_blank_messages_string_falls_back_to_user_message():
    # Cortex platform commonly sends "" for an unset optional text arg rather than omitting the key --
    # this pins _parse_json_arg's `raw in (None, "")` short-circuit feeding correctly into the
    # convenience-shape fallback, rather than a confusing "must be valid JSON" error.
    from GuardianVertex import _resolve_messages

    assert _resolve_messages({"messages": "", "user_message": "look up 8.8.8.8"}) == [
        {"role": "user", "content": "look up 8.8.8.8"}
    ]


def test_resolve_messages_rejects_empty_list_messages_with_user_message():
    # Regression test for the truthiness bug: an explicitly-empty array must be treated as
    # "messages was supplied" for the mutual-exclusion check, not silently as "absent".
    from GuardianVertex import _resolve_messages

    with pytest.raises(DemistoException, match="not both"):
        _resolve_messages({"messages": "[]", "user_message": "ping"})
    with pytest.raises(DemistoException, match="not both"):
        _resolve_messages({"messages": [], "system_message": "sys", "user_message": "ping"})


def test_resolve_messages_nonempty_messages_plus_user_message_still_rejected():
    from GuardianVertex import _resolve_messages

    with pytest.raises(DemistoException, match="not both"):
        _resolve_messages({"messages": [{"role": "user", "content": "hi"}], "user_message": "ping"})


def test_guardian_llm_chat_command_content_filter_result_does_not_raise(mocker):
    """A blocked request must surface as a normal, readable CommandResults — not an error entry."""
    error_body = {"error": {"code": "content_filter", "message": "blocked"}}
    res = _FakeResponse(400, json_body=error_body)
    err = DemistoException("Error in API call [400] - Bad Request", res=res)
    client, _ = _azure_client(mocker, http_request_side_effect=err)
    args = {"messages": json.dumps([{"role": "user", "content": "something blocked"}])}

    result = guardian_llm_chat_command(client, args)

    assert result.outputs["content_filter"] is True
    assert "BLOCKED BY CONTENT FILTER" in result.readable_output


""" ------------------------- test_module ------------------------- """


def test_test_module_success(mocker):
    client, mock_http = _openai_compatible_client(mocker, http_request_return=_openai_success_body())
    assert run_test_module_command(client) == "ok"
    call_kwargs = mock_http.call_args.kwargs
    assert call_kwargs["json_data"]["messages"] == [{"role": "user", "content": "ping"}]


def test_test_module_raises_on_content_filter(mocker):
    body = _openai_success_body(finish_reason="content_filter", content=None)
    client, _ = _azure_client(mocker, http_request_return=body)

    with pytest.raises(DemistoException):
        run_test_module_command(client)


""" ==================== Vertex (Gemini) adapter ==================== """
"""
No live GCP project/service-account with Vertex/Gemini access is available in this dispatch
(the project used for development lacks aiplatform access) — every test below mocks the token mint
(``google.oauth2.service_account.Credentials.from_service_account_info`` + ``creds.refresh``)
and ``Client._http_request``. A live vertex test-module / guardian-llm-chat run against a real
GCP project is deferred until the operator supplies project_id/region/model/service_account_json.
"""


def _mock_vertex_credentials(mocker, token="fake-token"):
    """Patch the google-auth token mint so VertexChatAdapter.build_headers() (and therefore
    every code path that calls it) never makes a real network call."""
    fake_creds = mocker.Mock()
    fake_creds.token = token
    fake_creds.refresh = mocker.Mock()
    mocker.patch(
        "google.oauth2.service_account.Credentials.from_service_account_info",
        return_value=fake_creds,
    )
    return fake_creds


def _vertex_client(mocker, http_request_return=None, http_request_side_effect=None, region="us-central1", token="fake-token"):
    _mock_vertex_credentials(mocker, token=token)
    adapter = VertexChatAdapter(
        project_id="my-project",
        region=region,
        model="gemini-2.5-flash",
        service_account_json=json.dumps({"type": "service_account", "project_id": "my-project"}),
    )
    client = Client(adapter=adapter, verify=False, proxy=False)
    mock_http = mocker.patch.object(
        client, "_http_request", return_value=http_request_return, side_effect=http_request_side_effect
    )
    return client, mock_http


def _gemini_success_body(finish_reason="STOP", function_call=None, text="hi there", cached_tokens=3):
    parts = []
    if text:
        parts.append({"text": text})
    if function_call:
        parts.append({"functionCall": function_call})
    return {
        "candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": finish_reason, "index": 0}],
        "usageMetadata": {
            "promptTokenCount": 12,
            "candidatesTokenCount": 4,
            "totalTokenCount": 16,
            "cachedContentTokenCount": cached_tokens,
        },
        "modelVersion": "gemini-2.5-flash-001",
        "responseId": "resp-123",
    }


""" ------------------------- provider selection (build_adapter) ------------------------- """


def test_build_adapter_selects_vertex():
    adapter = build_adapter(
        {
            "provider": "vertex",
            "model": "gemini-2.5-flash",
            "project_id": "my-project",
            "region": "europe-west4",
            "service_account_json": json.dumps({"type": "service_account"}),
        }
    )
    assert isinstance(adapter, VertexChatAdapter)
    assert adapter.project_id == "my-project"
    assert adapter.region == "europe-west4"


def test_build_adapter_vertex_defaults_region():
    adapter = build_adapter(
        {"provider": "vertex", "model": "gemini-2.5-flash", "project_id": "p", "service_account_json": "{}"}
    )
    assert adapter.region == "us-central1"


def test_build_adapter_vertex_does_not_require_base_url():
    """base_url is optional/ignored for provider=vertex — confirms build_adapter doesn't
    force-fit vertex through the base_url-required path used by the other two providers."""
    adapter = build_adapter(
        {"provider": "vertex", "model": "gemini-2.5-flash", "project_id": "p", "service_account_json": "{}"}
    )
    assert isinstance(adapter, VertexChatAdapter)


def test_build_adapter_vertex_requires_project_id():
    with pytest.raises(DemistoException):
        build_adapter({"provider": "vertex", "model": "m", "service_account_json": "{}"})


def test_build_adapter_vertex_requires_service_account_json():
    with pytest.raises(DemistoException):
        build_adapter({"provider": "vertex", "model": "m", "project_id": "p"})


""" ------------------------- adapter URL / header / auth construction ------------------------- """


def test_vertex_adapter_build_url_regional():
    adapter = VertexChatAdapter(project_id="proj", region="us-central1", model="gemini-2.5-flash", service_account_json="{}")
    assert adapter.build_url() == (
        "https://us-central1-aiplatform.googleapis.com/v1/projects/proj/locations/us-central1"
        "/publishers/google/models/gemini-2.5-flash:generateContent"
    )


def test_vertex_adapter_build_url_global_region_drops_region_host_prefix():
    """region == "global" uses the host with no region prefix, but the path still says
    /locations/global/ (the spec's one documented URL-shape special case)."""
    adapter = VertexChatAdapter(project_id="proj", region="global", model="gemini-2.5-pro", service_account_json="{}")
    assert adapter.build_url() == (
        "https://aiplatform.googleapis.com/v1/projects/proj/locations/global"
        "/publishers/google/models/gemini-2.5-pro:generateContent"
    )


def test_vertex_adapter_build_params_is_none():
    adapter = VertexChatAdapter(project_id="proj", region="us-central1", model="m", service_account_json="{}")
    assert adapter.build_params() is None


def test_vertex_adapter_build_headers_mints_token(mocker):
    fake_creds = _mock_vertex_credentials(mocker, token="minted-token-abc")
    adapter = VertexChatAdapter(
        project_id="proj", region="us-central1", model="m", service_account_json=json.dumps({"type": "service_account"})
    )

    headers = adapter.build_headers()

    assert headers == {"Content-Type": "application/json", "Authorization": "Bearer minted-token-abc"}
    fake_creds.refresh.assert_called_once()


def test_vertex_adapter_build_headers_raises_clear_error_on_invalid_service_account_json():
    adapter = VertexChatAdapter(project_id="proj", region="us-central1", model="m", service_account_json="not json")
    with pytest.raises(DemistoException) as exc_info:
        adapter.build_headers()
    assert "not valid JSON" in str(exc_info.value)


def test_vertex_adapter_build_headers_wraps_refresh_failure(mocker):
    fake_creds = mocker.Mock()
    fake_creds.refresh.side_effect = Exception("invalid_grant: account not found")
    mocker.patch("google.oauth2.service_account.Credentials.from_service_account_info", return_value=fake_creds)
    adapter = VertexChatAdapter(
        project_id="proj", region="us-central1", model="m", service_account_json=json.dumps({"type": "service_account"})
    )

    with pytest.raises(DemistoException) as exc_info:
        adapter.build_headers()
    assert "Failed to mint a Vertex AI access token" in str(exc_info.value)


""" ------------------------- request translation: OpenAI -> Gemini ------------------------- """


def test_vertex_build_request_body_translates_system_and_user_messages():
    adapter = VertexChatAdapter(project_id="p", region="us-central1", model="m", service_account_json="{}")
    body = adapter.build_request_body(
        {
            "messages": [
                {"role": "system", "content": "You are a SOC analyst."},
                {"role": "user", "content": "hi"},
            ]
        }
    )
    assert body["systemInstruction"] == {"parts": [{"text": "You are a SOC analyst."}]}
    assert body["contents"] == [{"role": "user", "parts": [{"text": "hi"}]}]
    assert "tools" not in body
    assert "generationConfig" not in body


def test_vertex_build_request_body_translates_assistant_tool_calls():
    adapter = VertexChatAdapter(project_id="p", region="us-central1", model="m", service_account_json="{}")
    body = adapter.build_request_body(
        {
            "messages": [
                {"role": "user", "content": "look up 8.8.8.8"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "ip_reputation", "arguments": '{"ip":"8.8.8.8"}'},
                        }
                    ],
                },
            ]
        }
    )
    assert body["contents"][1] == {
        "role": "model",
        "parts": [{"functionCall": {"name": "ip_reputation", "args": {"ip": "8.8.8.8"}}}],
    }


def test_vertex_build_request_body_translates_tool_result_message():
    adapter = VertexChatAdapter(project_id="p", region="us-central1", model="m", service_account_json="{}")
    body = adapter.build_request_body(
        {
            "messages": [
                {"role": "tool", "name": "ip_reputation", "tool_call_id": "call_1", "content": '{"reputation":"malicious"}'}
            ]
        }
    )
    assert body["contents"] == [
        {
            "role": "user",
            "parts": [{"functionResponse": {"name": "ip_reputation", "response": {"reputation": "malicious"}}}],
        }
    ]


def test_vertex_build_request_body_wraps_non_dict_tool_result():
    adapter = VertexChatAdapter(project_id="p", region="us-central1", model="m", service_account_json="{}")
    body = adapter.build_request_body(
        {"messages": [{"role": "tool", "name": "f", "tool_call_id": "call_1", "content": "plain text result"}]}
    )
    part = body["contents"][0]["parts"][0]["functionResponse"]
    assert part == {"name": "f", "response": {"result": "plain text result"}}


def test_vertex_build_request_body_groups_parallel_tool_results_into_one_content():
    """A model turn with N parallel functionCalls must be answered by ONE user content carrying
    N functionResponse parts. Emitting one content per tool result makes Gemini reject the turn
    with 400 'number of function response parts is equal to the number of function call parts'
    (observed live). Regression guard for the parallel-tool-call fix."""
    adapter = VertexChatAdapter(project_id="p", region="us-central1", model="m", service_account_json="{}")
    body = adapter.build_request_body(
        {
            "messages": [
                {"role": "user", "content": "enrich these"},
                {
                    "role": "assistant",
                    "tool_calls": [
                        {"id": "c1", "function": {"name": "ip", "arguments": "{}"}},
                        {"id": "c2", "function": {"name": "domain", "arguments": "{}"}},
                    ],
                },
                {"role": "tool", "name": "ip", "tool_call_id": "c1", "content": '{"geo":"SE"}'},
                {"role": "tool", "name": "domain", "tool_call_id": "c2", "content": '{"rep":"unknown"}'},
            ]
        }
    )
    model_turn, tool_turn = body["contents"][-2], body["contents"][-1]
    assert model_turn["role"] == "model"
    assert [p["functionCall"]["name"] for p in model_turn["parts"]] == ["ip", "domain"]
    # The two tool results MUST be grouped into a single user content, one functionResponse each.
    assert tool_turn["role"] == "user"
    assert [p["functionResponse"]["name"] for p in tool_turn["parts"]] == ["ip", "domain"]


def test_vertex_build_request_body_strips_additional_properties_from_tools():
    adapter = VertexChatAdapter(project_id="p", region="us-central1", model="m", service_account_json="{}")
    body = adapter.build_request_body(
        {
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "ip_reputation",
                        "description": "Look up IP reputation",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "ip": {"type": "string"},
                                "meta": {
                                    "type": "object",
                                    "properties": {"tag": {"type": "string"}},
                                    "additionalProperties": False,
                                },
                            },
                            "required": ["ip"],
                            "additionalProperties": False,
                        },
                    },
                }
            ],
            "tool_choice": "auto",
        }
    )
    declarations = body["tools"][0]["functionDeclarations"]
    assert len(declarations) == 1
    params = declarations[0]["parameters"]
    assert "additionalProperties" not in params
    assert "additionalProperties" not in params["properties"]["meta"]
    assert params["properties"]["meta"]["properties"] == {"tag": {"type": "string"}}
    assert body["toolConfig"] == {"functionCallingConfig": {"mode": "AUTO"}}


def test_vertex_build_request_body_tool_choice_required_and_none():
    adapter = VertexChatAdapter(project_id="p", region="us-central1", model="m", service_account_json="{}")
    tools = [{"type": "function", "function": {"name": "f", "parameters": {"type": "object"}}}]

    required_body = adapter.build_request_body(
        {"messages": [{"role": "user", "content": "hi"}], "tools": tools, "tool_choice": "required"}
    )
    assert required_body["toolConfig"] == {"functionCallingConfig": {"mode": "ANY"}}

    none_body = adapter.build_request_body(
        {"messages": [{"role": "user", "content": "hi"}], "tools": tools, "tool_choice": "none"}
    )
    assert none_body["toolConfig"] == {"functionCallingConfig": {"mode": "NONE"}}


def test_vertex_build_request_body_generation_config():
    adapter = VertexChatAdapter(project_id="p", region="us-central1", model="m", service_account_json="{}")
    body = adapter.build_request_body(
        {"messages": [{"role": "user", "content": "hi"}], "temperature": 0.2, "max_tokens": 128, "top_p": 0.9}
    )
    assert body["generationConfig"] == {"temperature": 0.2, "maxOutputTokens": 128, "topP": 0.9}


def test_vertex_build_request_body_response_format_json_schema_without_tools():
    adapter = VertexChatAdapter(project_id="p", region="us-central1", model="m", service_account_json="{}")
    body = adapter.build_request_body(
        {
            "messages": [{"role": "user", "content": "hi"}],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "schema": {
                        "type": "object",
                        "properties": {"verdict": {"type": "string"}},
                        "additionalProperties": False,
                    }
                },
            },
        }
    )
    config = body["generationConfig"]
    assert config["responseMimeType"] == "application/json"
    assert "additionalProperties" not in config["responseSchema"]


def test_vertex_build_request_body_prefers_tools_over_response_format(mocker):
    """Guard from the spec: tools + response_format together is a documented Gemini conflict —
    tools wins and response_format is dropped (non-silently: a demisto.debug note is logged)."""
    adapter = VertexChatAdapter(project_id="p", region="us-central1", model="m", service_account_json="{}")
    debug_spy = mocker.patch("GuardianVertex.demisto.debug")

    body = adapter.build_request_body(
        {
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"type": "function", "function": {"name": "f", "parameters": {"type": "object"}}}],
            "response_format": {"type": "json_object"},
        }
    )

    assert "tools" in body
    assert "responseMimeType" not in body.get("generationConfig", {})
    debug_spy.assert_called_once()


""" ------------------------- response translation: Gemini -> OpenAI (normalized) ------------------------- """


def test_vertex_normalize_response_text_and_usage():
    adapter = VertexChatAdapter(project_id="p", region="us-central1", model="gemini-2.5-flash", service_account_json="{}")
    result = adapter.normalize_response(_gemini_success_body(text="hi there", cached_tokens=3))

    assert result["content_filter"] is False
    assert result["finish_reason"] == "stop"
    assert result["choices"][0]["message"]["content"] == "hi there"
    assert result["choices"][0]["message"]["tool_calls"] is None
    assert result["usage"] == {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16, "cached_tokens": 3}
    assert result["model"] == "gemini-2.5-flash-001"
    assert result["id"] == "resp-123"


def test_vertex_normalize_response_function_call_maps_to_tool_calls():
    adapter = VertexChatAdapter(project_id="p", region="us-central1", model="m", service_account_json="{}")
    raw = _gemini_success_body(text=None, function_call={"name": "ip_reputation", "args": {"ip": "8.8.8.8"}})

    result = adapter.normalize_response(raw)

    tool_calls = result["choices"][0]["message"]["tool_calls"]
    assert tool_calls == [
        {
            "id": "call_0",
            "type": "function",
            "function": {"name": "ip_reputation", "arguments": json.dumps({"ip": "8.8.8.8"})},
        }
    ]
    assert result["finish_reason"] == "tool_calls"
    assert result["choices"][0]["message"]["content"] is None


@pytest.mark.parametrize(
    "gemini_reason,expected",
    [("STOP", "stop"), ("MAX_TOKENS", "length"), ("SAFETY", "content_filter"), ("PROHIBITED_CONTENT", "content_filter")],
)
def test_vertex_normalize_response_finish_reason_mapping(gemini_reason, expected):
    adapter = VertexChatAdapter(project_id="p", region="us-central1", model="m", service_account_json="{}")
    result = adapter.normalize_response(_gemini_success_body(finish_reason=gemini_reason))

    assert result["finish_reason"] == expected
    if expected == "content_filter":
        assert result["content_filter"] is True
        assert result["content_filter_detail"] is not None
    else:
        assert result["content_filter"] is False
        assert result["content_filter_detail"] is None


""" ------------------------- Vertex content-filter (blockReason / SAFETY finishReason) ------------------------- """


def test_vertex_normalize_response_prompt_blocked_by_prompt_feedback():
    """Input-side block: promptFeedback.blockReason with no candidates at all — must come back
    as a structured, non-silent content_filter result mirroring the Azure adapter's behavior."""
    adapter = VertexChatAdapter(project_id="p", region="us-central1", model="m", service_account_json="{}")
    result = adapter.normalize_response({"promptFeedback": {"blockReason": "SAFETY"}})

    assert result["content_filter"] is True
    assert result["finish_reason"] == CONTENT_FILTER_FINISH_REASON
    assert result["choices"] == []
    assert "blockReason=SAFETY" in result["content_filter_detail"]["message"]


def test_vertex_content_filter_block_reason_via_chat_completion(mocker):
    client, _ = _vertex_client(mocker, http_request_return={"promptFeedback": {"blockReason": "SAFETY"}})

    result = client.chat_completion({"messages": [{"role": "user", "content": "something blocked"}]})

    assert result["content_filter"] is True
    assert result["choices"] == []


def test_vertex_content_filter_safety_finish_reason_via_chat_completion(mocker):
    client, _ = _vertex_client(mocker, http_request_return=_gemini_success_body(finish_reason="SAFETY", text=None))

    result = client.chat_completion({"messages": [{"role": "user", "content": "hi"}]})

    assert result["content_filter"] is True
    assert result["finish_reason"] == "content_filter"


""" ------------------------- end-to-end: guardian_llm_chat_command / test_module ------------------------- """


def test_vertex_success_end_to_end(mocker):
    client, mock_http = _vertex_client(mocker, http_request_return=_gemini_success_body())
    args = {"messages": json.dumps([{"role": "user", "content": "say hi"}])}

    result = guardian_llm_chat_command(client, args)

    assert result.outputs["content_filter"] is False
    assert result.outputs["finish_reason"] == "stop"
    assert result.outputs["choices"][0]["message"]["content"] == "hi there"

    call_kwargs = mock_http.call_args.kwargs
    assert call_kwargs["full_url"] == (
        "https://us-central1-aiplatform.googleapis.com/v1/projects/my-project/locations/us-central1"
        "/publishers/google/models/gemini-2.5-flash:generateContent"
    )
    assert call_kwargs["headers"]["Authorization"] == "Bearer fake-token"
    assert call_kwargs["json_data"]["contents"] == [{"role": "user", "parts": [{"text": "say hi"}]}]


def test_test_module_vertex_success(mocker):
    client, mock_http = _vertex_client(mocker, http_request_return=_gemini_success_body())

    assert run_test_module_command(client) == "ok"
    assert mock_http.call_args.kwargs["headers"]["Authorization"] == "Bearer fake-token"


def test_test_module_vertex_raises_clear_error_on_bad_service_account_json(mocker):
    adapter = VertexChatAdapter(
        project_id="my-project", region="us-central1", model="gemini-2.5-flash", service_account_json="not-json"
    )
    client = Client(adapter=adapter, verify=False, proxy=False)
    mocker.patch.object(client, "_http_request")  # must never be reached — auth fails first

    with pytest.raises(DemistoException) as exc_info:
        run_test_module_command(client)
    assert "not valid JSON" in str(exc_info.value)


# --- per-call timeout ---------------------------------------------------------------------------


def test_per_call_timeout_is_one_attempt_capped_by_the_instance_timeout(mocker):
    """The contract's per-call `timeout` is a hard bound: capped by the instance timeout, and no
    transparent retry (read timeouts are retried by the HTTP layer otherwise)."""
    client, mock_http = _openai_compatible_client(mocker, http_request_return=_openai_success_body())
    client.chat_completion({"messages": [{"role": "user", "content": "hi"}]}, call_timeout=30)
    kwargs = mock_http.call_args.kwargs
    assert kwargs["timeout"] == min(client.timeout, 30)
    assert kwargs["retries"] == 0

    client.chat_completion({"messages": [{"role": "user", "content": "hi"}]}, call_timeout=10 ** 6)
    assert mock_http.call_args.kwargs["timeout"] == client.timeout


def test_chat_command_forwards_timeout_and_keeps_it_out_of_the_body(mocker):
    client, mock_http = _openai_compatible_client(mocker, http_request_return=_openai_success_body())
    guardian_llm_chat_command(client, {"messages": json.dumps([{"role": "user", "content": "hi"}]), "timeout": "30"})
    kwargs = mock_http.call_args.kwargs
    assert kwargs["timeout"] == min(client.timeout, 30.0)
    assert "timeout" not in kwargs["json_data"]  # a transport bound, never sent to the provider


def test_chat_command_without_timeout_keeps_default_retries(mocker):
    client, mock_http = _openai_compatible_client(mocker, http_request_return=_openai_success_body())
    guardian_llm_chat_command(client, {"messages": json.dumps([{"role": "user", "content": "hi"}])})
    assert mock_http.call_args.kwargs["retries"] == 3
    assert mock_http.call_args.kwargs["timeout"] == client.timeout


def test_chat_command_rejects_a_non_positive_timeout(mocker):
    client, _ = _openai_compatible_client(mocker, http_request_return=_openai_success_body())
    for bad in ("0", "-1", "later"):
        with pytest.raises(DemistoException):
            guardian_llm_chat_command(client, {"messages": json.dumps([{"role": "user", "content": "hi"}]), "timeout": bad})
