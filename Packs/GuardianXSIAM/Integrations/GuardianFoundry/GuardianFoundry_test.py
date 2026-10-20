"""GuardianFoundry unit tests.

No Foundry resource or key is available in the unit-test environment, so every HTTP boundary is mocked at
``Client._http_request``. The wire format asserted here (``POST {resource}/openai/v1/chat/completions``, the
deployment in the body's ``model`` field, an ``api-key`` header) is the Foundry v1 API as documented by Microsoft;
a live run against a real resource is a separate step (see the integration README).
"""

import json
import sys

import pytest
from CommonServerPython import DemistoException

import GuardianFoundry as gf
from GuardianFoundry import (
    CONTENT_FILTER_FINISH_REASON,
    Client,
    FoundryAdapter,
    build_adapter,
    guardian_llm_chat_command,
    normalize_endpoint,
    test_module as run_test_module_command,
)

RESOURCE = "https://my-res.services.ai.azure.com"


class _FakeResponse:
    def __init__(self, status_code, json_body=None):
        self.status_code = status_code
        self._json_body = json_body
        self.text = json.dumps(json_body or {})

    def json(self):
        if self._json_body is None:
            raise ValueError("no JSON body")
        return self._json_body


def _http_error(status_code, body=None, message="boom"):
    exc = DemistoException(message)
    exc.res = _FakeResponse(status_code, body)
    return exc


def _success_body(finish_reason="stop", tool_calls=None, content="hi there", cached_tokens=5):
    message = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
        message["content"] = None
    return {
        "id": "chatcmpl-1",
        "created": 1700000000,
        "model": "gpt-4o-2024-11-20",
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": {
            "prompt_tokens": 20,
            "completion_tokens": 4,
            "total_tokens": 24,
            "prompt_tokens_details": {"cached_tokens": cached_tokens},
        },
    }


def _client(mocker, model="gpt-4o", return_value=None, side_effect=None, **adapter_kwargs):
    adapter_kwargs.setdefault("api_key", "k")
    adapter = FoundryAdapter(endpoint=RESOURCE, model=model, **adapter_kwargs)
    client = Client(adapter=adapter, verify=False, proxy=False)
    mock_http = mocker.patch.object(client, "_http_request", return_value=return_value, side_effect=side_effect)
    return client, mock_http


""" ------------------------- endpoint normalisation ------------------------- """


@pytest.mark.parametrize(
    "raw, expected",
    [
        (RESOURCE, f"{RESOURCE}/openai/v1/chat/completions"),
        (f"{RESOURCE}/", f"{RESOURCE}/openai/v1/chat/completions"),
        ("https://my-res.openai.azure.com", "https://my-res.openai.azure.com/openai/v1/chat/completions"),
        (f"{RESOURCE}/openai", f"{RESOURCE}/openai/v1/chat/completions"),
        (f"{RESOURCE}/openai/v1", f"{RESOURCE}/openai/v1/chat/completions"),
        (f"{RESOURCE}/openai/v1/", f"{RESOURCE}/openai/v1/chat/completions"),
        # the project endpoint an operator copies from the portal: the project path is dropped
        (f"{RESOURCE}/api/projects/my-proj", f"{RESOURCE}/openai/v1/chat/completions"),
        # a full URL is the escape hatch and is used verbatim
        (f"{RESOURCE}/models/chat/completions", f"{RESOURCE}/models/chat/completions"),
    ],
)
def test_normalize_endpoint(raw, expected):
    assert normalize_endpoint(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "my-res.services.ai.azure.com"])
def test_normalize_endpoint_rejects_bad_input(raw):
    with pytest.raises(DemistoException):
        normalize_endpoint(raw)


""" ------------------------- headers / auth ------------------------- """


def test_headers_api_key_default():
    adapter = FoundryAdapter(RESOURCE, "gpt-4o", api_key="secret")
    assert adapter.build_headers() == {"Content-Type": "application/json", "api-key": "secret"}


def test_headers_bearer_key():
    adapter = FoundryAdapter(RESOURCE, "gpt-4o", auth_type=gf.AUTH_BEARER_KEY, api_key="secret")
    assert adapter.build_headers()["Authorization"] == "Bearer secret"
    assert "api-key" not in adapter.build_headers()


def test_headers_entra_uses_the_token_not_the_key():
    adapter = FoundryAdapter(RESOURCE, "gpt-4o", auth_type=gf.AUTH_ENTRA)
    assert adapter.build_headers("tok")["Authorization"] == "Bearer tok"


def test_api_version_param_only_when_set():
    assert FoundryAdapter(RESOURCE, "m", api_key="k").build_params() is None
    assert FoundryAdapter(RESOURCE, "m", api_key="k", api_version="2024-05-01-preview").build_params() == {
        "api-version": "2024-05-01-preview"
    }


""" ------------------------- request body: per-model parameter handling ------------------------- """


def _request(**over):
    base = {
        "messages": [{"role": "user", "content": "x"}],
        "tools": None,
        "tool_choice": None,
        "response_format": None,
        "temperature": None,
        "reasoning_effort": None,
        "parallel_tool_calls": None,
    }
    base.update(over)
    return base


def test_body_standard_model_keeps_temperature_and_drops_reasoning_effort():
    adapter = FoundryAdapter(RESOURCE, "gpt-4o", api_key="k")
    body = adapter.build_request_body(_request(temperature=0.2, reasoning_effort="high"))
    assert body["model"] == "gpt-4o"
    assert body["temperature"] == 0.2
    assert "reasoning_effort" not in body


@pytest.mark.parametrize("name", ["gpt-5", "gpt-5-mini", "o3", "o4-mini", "O1"])
def test_reasoning_models_detected_by_name(name):
    assert FoundryAdapter(RESOURCE, name, api_key="k").is_reasoning


@pytest.mark.parametrize("name", ["gpt-4o", "gpt-4.1", "DeepSeek-V3", "Llama-3.3-70B-Instruct", "my-deploy"])
def test_standard_models_detected_by_name(name):
    assert not FoundryAdapter(RESOURCE, name, api_key="k").is_reasoning


def test_model_family_overrides_name_detection():
    assert FoundryAdapter(RESOURCE, "my-deploy", api_key="k", model_family=gf.FAMILY_REASONING).is_reasoning
    assert not FoundryAdapter(RESOURCE, "gpt-5", api_key="k", model_family=gf.FAMILY_STANDARD).is_reasoning


def test_body_reasoning_model_drops_temperature_keeps_effort_and_renames_max_tokens():
    adapter = FoundryAdapter(RESOURCE, "gpt-5-mini", api_key="k", max_output_tokens=500)
    body = adapter.build_request_body(_request(temperature=0.2, reasoning_effort="low"))
    assert "temperature" not in body
    assert body["reasoning_effort"] == "low"
    assert body["max_completion_tokens"] == 500
    assert "max_tokens" not in body


def test_body_max_tokens_for_standard_model():
    adapter = FoundryAdapter(RESOURCE, "gpt-4o", api_key="k", max_output_tokens=500)
    assert adapter.build_request_body(_request())["max_tokens"] == 500


def test_body_translates_internal_max_tokens_for_reasoning_models():
    adapter = FoundryAdapter(RESOURCE, "o3", api_key="k")
    body = adapter.build_request_body(_request(max_tokens=16))
    assert body["max_completion_tokens"] == 16
    assert "max_tokens" not in body


def test_body_drops_tool_options_when_no_tools():
    adapter = FoundryAdapter(RESOURCE, "gpt-4o", api_key="k")
    body = adapter.build_request_body(_request(tool_choice="auto", parallel_tool_calls=False))
    assert "tool_choice" not in body and "parallel_tool_calls" not in body and "tools" not in body


def test_body_keeps_tool_options_with_tools():
    adapter = FoundryAdapter(RESOURCE, "gpt-4o", api_key="k")
    tools = [{"type": "function", "function": {"name": "t", "parameters": {"type": "object"}}}]
    body = adapter.build_request_body(_request(tools=tools, tool_choice="auto", parallel_tool_calls=False))
    assert body["tools"] == tools and body["tool_choice"] == "auto" and body["parallel_tool_calls"] is False


def test_body_omit_params():
    adapter = FoundryAdapter(RESOURCE, "Llama-3.3", api_key="k", omit_params=["response_format", "parallel_tool_calls"])
    tools = [{"type": "function", "function": {"name": "t"}}]
    body = adapter.build_request_body(
        _request(tools=tools, response_format={"type": "json_object"}, parallel_tool_calls=True)
    )
    assert "response_format" not in body and "parallel_tool_calls" not in body and "tools" in body


""" ------------------------- chat completion round trip ------------------------- """


def test_chat_completion_success_and_wire_shape(mocker):
    client, mock_http = _client(mocker, return_value=_success_body())
    result = client.chat_completion(_request(temperature=0.1))

    kwargs = mock_http.call_args.kwargs
    assert kwargs["method"] == "POST"
    assert kwargs["full_url"] == f"{RESOURCE}/openai/v1/chat/completions"
    assert kwargs["headers"]["api-key"] == "k"
    assert kwargs["params"] is None
    assert kwargs["json_data"]["model"] == "gpt-4o"
    assert kwargs["retries"] == gf.DEFAULT_RETRIES
    assert kwargs["status_list_to_retry"] == [429]

    assert result["choices"][0]["message"]["content"] == "hi there"
    assert result["finish_reason"] == "stop"
    assert result["content_filter"] is False
    assert result["usage"] == {"prompt_tokens": 20, "completion_tokens": 4, "total_tokens": 24, "cached_tokens": 5}


def test_call_timeout_is_a_hard_bound_with_no_retries(mocker):
    client, mock_http = _client(mocker, return_value=_success_body())
    client.chat_completion(_request(), call_timeout=7)
    kwargs = mock_http.call_args.kwargs
    assert kwargs["retries"] == 0
    assert kwargs["timeout"] == 7


def test_tool_calls_pass_through_and_object_arguments_become_json_strings(mocker):
    calls = [
        {"id": "c1", "type": "function", "function": {"name": "a", "arguments": '{"x": 1}'}},
        {"id": "c2", "type": "function", "function": {"name": "b", "arguments": {"y": 2}}},
    ]
    client, _ = _client(mocker, return_value=_success_body(finish_reason="tool_calls", tool_calls=calls))
    result = client.chat_completion(_request())
    out = result["choices"][0]["message"]["tool_calls"]
    assert out[0]["function"]["arguments"] == '{"x": 1}'
    assert json.loads(out[1]["function"]["arguments"]) == {"y": 2}
    assert result["finish_reason"] == "tool_calls"


def test_content_parts_are_flattened_to_text(mocker):
    body = _success_body()
    body["choices"][0]["message"]["content"] = [{"type": "text", "text": "he"}, {"type": "text", "text": "llo"}]
    client, _ = _client(mocker, return_value=body)
    assert client.chat_completion(_request())["choices"][0]["message"]["content"] == "hello"


def test_output_content_filter_finish_reason(mocker):
    body = _success_body(finish_reason=CONTENT_FILTER_FINISH_REASON, content=None)
    body["choices"][0]["content_filter_results"] = {"hate": {"filtered": True, "severity": "high"}}
    client, _ = _client(mocker, return_value=body)
    result = client.chat_completion(_request())
    assert result["content_filter"] is True
    assert result["finish_reason"] == CONTENT_FILTER_FINISH_REASON
    assert result["content_filter_detail"]["content_filter_results"]["hate"]["filtered"] is True


def test_input_content_filter_http_400_is_returned_not_raised(mocker):
    err = {"error": {"code": "content_filter", "message": "prompt blocked", "innererror": {"code": "ResponsibleAIPolicyViolation"}}}
    client, _ = _client(mocker, side_effect=_http_error(400, err))
    result = client.chat_completion(_request())
    assert result["content_filter"] is True
    assert result["choices"] == []
    assert result["content_filter_detail"]["message"] == "prompt blocked"
    assert result["content_filter_detail"]["raw_error"] == err


def test_prompt_filter_results_on_a_200_without_choices(mocker):
    body = {"id": None, "choices": [], "prompt_filter_results": [{"content_filter_results": {"jailbreak": {"filtered": True}}}]}
    client, _ = _client(mocker, return_value=body)
    result = client.chat_completion(_request())
    assert result["content_filter"] is True and result["choices"] == []


def test_other_400_is_raised(mocker):
    err = {"error": {"code": "unsupported_parameter", "message": "Unsupported parameter: 'temperature'", "param": "temperature"}}
    client, _ = _client(mocker, side_effect=_http_error(400, err, message="400 Bad Request"))
    with pytest.raises(DemistoException, match="400"):
        client.chat_completion(_request())


@pytest.mark.parametrize("status, needle", [(401, "API key"), (403, "Access denied"), (404, "deployment name")])
def test_auth_and_not_found_errors_carry_a_hint(mocker, status, needle):
    client, _ = _client(mocker, side_effect=_http_error(status, {"error": {"message": "x"}}, message="orig-error"))
    with pytest.raises(DemistoException) as exc_info:
        client.chat_completion(_request())
    assert needle in str(exc_info.value)
    assert "orig-error" in str(exc_info.value)


def test_429_after_retries_gets_a_rate_limit_message(mocker):
    client, _ = _client(mocker, side_effect=_http_error(429, {"error": {"message": "slow down"}}))
    with pytest.raises(DemistoException, match="rate-limited"):
        client.chat_completion(_request())


""" ------------------------- Entra ID ------------------------- """


def _entra_client(mocker, token_response, chat_response=None):
    adapter = FoundryAdapter(
        RESOURCE,
        "gpt-4o",
        auth_type=gf.AUTH_ENTRA,
        entra_tenant_id="tenant-1",
        entra_client_id="client-1",
        entra_client_secret="shh",
    )
    client = Client(adapter=adapter, verify=False, proxy=False)
    responses = [token_response, chat_response or _success_body()]
    mock_http = mocker.patch.object(
        client, "_http_request", side_effect=lambda **kw: responses.pop(0) if not isinstance(responses[0], Exception) else (_ for _ in ()).throw(responses.pop(0))
    )
    return client, mock_http


@pytest.fixture()
def integration_context(mocker):
    store = {}
    mocker.patch.object(gf.demisto, "getIntegrationContext", side_effect=lambda: dict(store))
    mocker.patch.object(gf.demisto, "setIntegrationContext", side_effect=lambda ctx: store.update(ctx))
    return store


def test_entra_token_is_minted_sent_and_cached(mocker, integration_context):
    client, mock_http = _entra_client(mocker, {"access_token": "AT", "expires_in": 3600})
    client.chat_completion(_request())

    token_call, chat_call = mock_http.call_args_list
    assert token_call.kwargs["full_url"] == "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token"
    assert token_call.kwargs["data"] == {
        "grant_type": "client_credentials",
        "client_id": "client-1",
        "client_secret": "shh",
        "scope": "https://ai.azure.com/.default",
    }
    assert chat_call.kwargs["headers"]["Authorization"] == "Bearer AT"
    assert integration_context["entra_token"]["access_token"] == "AT"


def test_entra_cached_token_is_reused(mocker, integration_context):
    import time

    integration_context["entra_token"] = {"access_token": "CACHED", "expires_at": time.time() + 3600}
    adapter = FoundryAdapter(RESOURCE, "gpt-4o", auth_type=gf.AUTH_ENTRA, entra_tenant_id="t", entra_client_id="c", entra_client_secret="s")
    client = Client(adapter=adapter, verify=False, proxy=False)
    mock_http = mocker.patch.object(client, "_http_request", return_value=_success_body())
    client.chat_completion(_request())
    assert mock_http.call_count == 1
    assert mock_http.call_args.kwargs["headers"]["Authorization"] == "Bearer CACHED"


def test_entra_expired_token_is_refreshed(mocker, integration_context):
    import time

    integration_context["entra_token"] = {"access_token": "OLD", "expires_at": time.time() + 10}
    client, mock_http = _entra_client(mocker, {"access_token": "NEW", "expires_in": 3600})
    client.chat_completion(_request())
    assert mock_http.call_args_list[1].kwargs["headers"]["Authorization"] == "Bearer NEW"


def test_entra_token_failure_surfaces_the_aad_description(mocker, integration_context):
    err = _http_error(401, {"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret"})
    client, _ = _entra_client(mocker, err)
    with pytest.raises(DemistoException, match="AADSTS7000215"):
        client.chat_completion(_request())


def test_entra_requires_all_three_fields(mocker, integration_context):
    adapter = FoundryAdapter(RESOURCE, "gpt-4o", auth_type=gf.AUTH_ENTRA, entra_tenant_id="t")
    client = Client(adapter=adapter, verify=False, proxy=False)
    mocker.patch.object(client, "_http_request")
    with pytest.raises(DemistoException, match="Tenant ID, Client ID and Client secret"):
        client.chat_completion(_request())


""" ------------------------- build_adapter / commands ------------------------- """


def test_build_adapter_from_params():
    adapter = build_adapter(
        {
            "endpoint": RESOURCE,
            "model": " gpt-5-mini ",
            "auth_type": "bearer-key",
            "api_key": "k",
            "omit_params": "response_format, parallel_tool_calls",
            "max_output_tokens": "800",
            "api_version": "",
        }
    )
    assert adapter.model == "gpt-5-mini" and adapter.is_reasoning
    assert adapter.omit_params == {"response_format", "parallel_tool_calls"}
    assert adapter.max_output_tokens == 800
    assert adapter.api_version is None


@pytest.mark.parametrize(
    "params, needle",
    [
        ({"endpoint": RESOURCE, "model": "", "api_key": "k"}, "deployment name"),
        ({"endpoint": "", "model": "m", "api_key": "k"}, "Endpoint"),
        ({"endpoint": RESOURCE, "model": "m"}, "API key"),
        ({"endpoint": RESOURCE, "model": "m", "api_key": "k", "max_output_tokens": "abc"}, "whole number"),
        ({"endpoint": RESOURCE, "model": "m", "api_key": "k", "max_output_tokens": "0"}, "positive"),
    ],
)
def test_build_adapter_validation(params, needle):
    with pytest.raises(DemistoException, match=needle):
        build_adapter(params)


def test_test_module_ok_and_sends_a_tiny_request(mocker):
    client, mock_http = _client(mocker, return_value=_success_body())
    assert run_test_module_command(client) == "ok"
    body = mock_http.call_args.kwargs["json_data"]
    assert body["max_tokens"] == gf.TEST_MODULE_MAX_TOKENS
    assert body["messages"] == [{"role": "user", "content": "ping"}]


def test_test_module_reasoning_model_uses_max_completion_tokens(mocker):
    client, mock_http = _client(mocker, model="gpt-5", return_value=_success_body())
    run_test_module_command(client)
    body = mock_http.call_args.kwargs["json_data"]
    assert body["max_completion_tokens"] == gf.TEST_MODULE_MAX_TOKENS and "max_tokens" not in body


def test_test_module_reports_a_content_filter_block(mocker):
    err = {"error": {"code": "content_filter", "message": "blocked"}}
    client, _ = _client(mocker, side_effect=_http_error(400, err))
    with pytest.raises(DemistoException, match="content filter"):
        run_test_module_command(client)


def test_command_with_messages_tools_and_options(mocker):
    client, mock_http = _client(mocker, return_value=_success_body())
    tools = [{"type": "function", "function": {"name": "t", "parameters": {"type": "object"}}}]
    result = guardian_llm_chat_command(
        client,
        {
            "messages": json.dumps([{"role": "user", "content": "hi"}]),
            "tools": json.dumps(tools),
            "tool_choice": "auto",
            "temperature": "0.3",
            "parallel_tool_calls": "false",
            "timeout": "30",
        },
    )
    body = mock_http.call_args.kwargs["json_data"]
    assert body["tools"] == tools and body["tool_choice"] == "auto"
    assert body["temperature"] == 0.3 and body["parallel_tool_calls"] is False
    assert result.outputs_prefix == "Guardian.LLM.Completion"
    assert result.outputs["choices"][0]["message"]["content"] == "hi there"


def test_command_user_message_shortcut(mocker):
    client, mock_http = _client(mocker, return_value=_success_body())
    guardian_llm_chat_command(client, {"system_message": "be brief", "user_message": "hi"})
    assert mock_http.call_args.kwargs["json_data"]["messages"] == [
        {"role": "system", "content": "be brief"},
        {"role": "user", "content": "hi"},
    ]


def test_command_rejects_both_message_shapes(mocker):
    client, _ = _client(mocker, return_value=_success_body())
    with pytest.raises(DemistoException, match="not both"):
        guardian_llm_chat_command(client, {"messages": "[]", "user_message": "hi"})


def test_command_requires_some_messages(mocker):
    client, _ = _client(mocker, return_value=_success_body())
    with pytest.raises(DemistoException, match="Provide"):
        guardian_llm_chat_command(client, {})


def test_command_content_filter_readable_output(mocker):
    err = {"error": {"code": "content_filter", "message": "blocked prompt"}}
    client, _ = _client(mocker, side_effect=_http_error(400, err))
    result = guardian_llm_chat_command(client, {"user_message": "x"})
    assert "BLOCKED BY CONTENT FILTER" in result.readable_output
    assert result.outputs["content_filter"] is True


""" ------------------------- XSIAM: b64 command arguments ------------------------- """


def test_b64_arguments_are_decoded(mocker):
    import base64

    def enc(value):
        return "b64:" + base64.b64encode(json.dumps(value).encode()).decode()

    client, mock_http = _client(mocker, return_value=_success_body())
    tools = [{"type": "function", "function": {"name": "t", "parameters": {"type": "object"}}}]
    messages = [{"role": "user", "content": 'a "quoted" \\ back\\slash\nline'}]
    guardian_llm_chat_command(
        client, {"messages": enc(messages), "tools": enc(tools), "response_format": enc({"type": "json_object"})}
    )
    body = mock_http.call_args.kwargs["json_data"]
    assert body["messages"] == messages and body["tools"] == tools
    assert body["response_format"] == {"type": "json_object"}


def test_invalid_b64_argument_is_a_clear_error(mocker):
    client, _ = _client(mocker, return_value=_success_body())
    with pytest.raises(DemistoException, match="b64"):
        guardian_llm_chat_command(client, {"messages": "b64:!!!not-base64!!!"})


def test_model_dropdown_overrides_the_deployment_name_and_custom_falls_back_to_it():
    base = {"endpoint": "https://r.services.ai.azure.com", "api_key": "k", "model": "my-deployment"}
    assert gf.build_adapter(dict(base, model_choice="cohere-command-a")).model == "cohere-command-a"
    assert gf.build_adapter(dict(base, model_choice=gf.MODEL_CHOICE_CUSTOM)).model == "my-deployment"
    assert gf.build_adapter(dict(base)).model == "my-deployment"  # an instance saved before the dropdown


def test_model_dropdown_alone_is_enough_and_nothing_at_all_is_an_error():
    ok = gf.build_adapter({"endpoint": "https://r.services.ai.azure.com", "api_key": "k", "model_choice": "gpt-oss-120b"})
    assert ok.model == "gpt-oss-120b"
    with pytest.raises(Exception, match="Model"):
        gf.build_adapter({"endpoint": "https://r.services.ai.azure.com", "api_key": "k"})


def test_recover_harmony_tool_call_turns_leaked_text_into_a_tool_call():
    text = '<|start|>assistant<|channel|>commentary to=functions.ip <|constrain|>json<|message|>{"value": "176.47.64.141"}<|call|>'
    content, calls = gf.recover_harmony_tool_call(text)
    assert content == "" and len(calls) == 1
    assert calls[0]["function"]["name"] == "ip"
    assert json.loads(calls[0]["function"]["arguments"]) == {"value": "176.47.64.141"}
    assert gf.recover_harmony_tool_call("a plain answer") == ("a plain answer", [])
    assert gf.recover_harmony_tool_call("to=functions.ip <|message|>{not json}<|call|>")[1] == []
    assert gf.recover_harmony_tool_call(None) == (None, [])


def test_normalize_response_recovers_a_leaked_call_but_keeps_real_tool_calls():
    adapter = FoundryAdapter(RESOURCE, "gpt-oss-120b", api_key="k")
    leaked = {"choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant",
        "content": '<|start|>assistant<|channel|>commentary to=functions.domain <|constrain|>json<|message|>{"domain": "a.example"}<|call|>'}}]}
    message = adapter.normalize_response(leaked)["choices"][0]["message"]
    assert message["content"] == "" and message["tool_calls"][0]["function"]["name"] == "domain"
    real = {"choices": [{"index": 0, "finish_reason": "tool_calls", "message": {"role": "assistant", "content": None,
        "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "ip", "arguments": "{}"}}]}}]}
    assert adapter.normalize_response(real)["choices"][0]["message"]["tool_calls"][0]["id"] == "c1"


""" ------------------------- Entra ID certificate authentication ------------------------- """

CERT_PASSPHRASE = "correct horse"


@pytest.fixture(scope="module")
def cert_material():
    """One RSA key and self-signed certificate for the whole module, in every PEM shape the tests need."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    def self_signed(key):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "guardian-test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256())
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = self_signed(key)
    pkcs8 = serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(*pkcs8, serialization.NoEncryption()).decode()
    der = cert.public_bytes(serialization.Encoding.DER)
    import hashlib

    return {
        "public_key": key.public_key(),
        "cert_pem": cert_pem,
        "key_pem": key_pem,
        "both": cert_pem + key_pem,
        "encrypted_both": cert_pem
        + key.private_bytes(*pkcs8, serialization.BestAvailableEncryption(CERT_PASSPHRASE.encode())).decode(),
        "rsa_traditional": cert_pem
        + key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        ).decode(),
        "ec_key_pem": ec.generate_private_key(ec.SECP256R1()).private_bytes(*pkcs8, serialization.NoEncryption()).decode(),
        "other_cert_pem": self_signed(other_key).public_bytes(serialization.Encoding.PEM).decode(),
        "sha1": hashlib.sha1(der).digest(),
        "sha256": hashlib.sha256(der).digest(),
    }


def _b64url_bytes(value):
    import base64

    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _json_of(raw):
    return json.loads(raw.decode("utf-8"))


def _decode_jwt(jwt):
    head, body, sig = jwt.split(".")
    return _json_of(_b64url_bytes(head)), _json_of(_b64url_bytes(body)), f"{head}.{body}".encode(), _b64url_bytes(sig)


def _cert_adapter(pem, passphrase="", thumbprint=""):
    return FoundryAdapter(
        RESOURCE,
        "gpt-4o",
        auth_type=gf.AUTH_ENTRA_CERT,
        entra_tenant_id="tenant-1",
        entra_client_id="client-1",
        entra_certificate_pem=pem,
        entra_certificate_passphrase=passphrase,
        entra_certificate_thumbprint=thumbprint,
    )


def _cert_client(mocker, pem, passphrase="", thumbprint="", token_response=None, chat_response=None):
    client = Client(adapter=_cert_adapter(pem, passphrase, thumbprint), verify=False, proxy=False)
    responses = [token_response or {"access_token": "CERT-AT", "expires_in": 3600}, chat_response or _success_body()]
    mock_http = mocker.patch.object(
        client,
        "_http_request",
        side_effect=lambda **kw: responses.pop(0) if not isinstance(responses[0], Exception) else (_ for _ in ()).throw(responses.pop(0)),
    )
    return client, mock_http


def _verify_signature(cert_material, signing_input, signature):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    cert_material["public_key"].verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())  # raises if invalid


def test_cert_token_request_carries_a_signed_client_assertion(mocker, integration_context, cert_material):
    import time

    before = int(time.time())
    client, mock_http = _cert_client(mocker, cert_material["both"])
    client.chat_completion(_request())

    token_call, chat_call = mock_http.call_args_list
    assert token_call.kwargs["full_url"] == "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token"
    form = token_call.kwargs["data"]
    assert set(form) == {"grant_type", "client_id", "client_assertion_type", "client_assertion", "scope"}
    assert form["grant_type"] == "client_credentials"
    assert form["client_id"] == "client-1"
    assert form["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    assert form["scope"] == "https://ai.azure.com/.default"
    assert "client_secret" not in form

    header, claims, signing_input, signature = _decode_jwt(form["client_assertion"])
    assert header["alg"] == "RS256" and header["typ"] == "JWT"
    assert _b64url_bytes(header["x5t"]) == cert_material["sha1"]
    assert _b64url_bytes(header["x5t#S256"]) == cert_material["sha256"]
    assert "=" not in header["x5t"] and "=" not in header["x5t#S256"]
    assert claims["aud"] == "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token"
    assert claims["iss"] == claims["sub"] == "client-1"
    assert claims["nbf"] == claims["iat"] and before <= claims["iat"] <= int(time.time())
    assert claims["exp"] == claims["nbf"] + 600
    assert claims["jti"]
    _verify_signature(cert_material, signing_input, signature)

    assert chat_call.kwargs["headers"]["Authorization"] == "Bearer CERT-AT"
    cached = integration_context["entra_token"]
    assert cached["access_token"] == "CERT-AT"


def test_cert_assertion_has_a_fresh_jti_each_time(cert_material):
    first = gf.build_client_assertion("t", "c", cert_material["both"])
    second = gf.build_client_assertion("t", "c", cert_material["both"])
    assert _decode_jwt(first)[1]["jti"] != _decode_jwt(second)[1]["jti"]


def test_cert_token_is_cached_and_reused(mocker, integration_context, cert_material):
    client, mock_http = _cert_client(mocker, cert_material["both"])
    client.chat_completion(_request())
    mock_http.side_effect = None
    mock_http.return_value = _success_body()
    client.chat_completion(_request())
    assert mock_http.call_count == 3  # token + chat, then chat only
    assert mock_http.call_args.kwargs["headers"]["Authorization"] == "Bearer CERT-AT"


def test_cached_token_of_another_auth_type_is_not_reused(mocker, integration_context, cert_material):
    import time

    integration_context["entra_token"] = {
        "access_token": "SECRET-AUTH-TOKEN",
        "expires_at": time.time() + 3600,
        "identity": "entra-client-credentials|tenant-1|client-1",
    }
    client, mock_http = _cert_client(mocker, cert_material["both"])
    client.chat_completion(_request())
    assert mock_http.call_args_list[1].kwargs["headers"]["Authorization"] == "Bearer CERT-AT"


def test_thumbprint_override_wins_over_the_certificate(cert_material):
    override = "AB:CD:EF:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01"
    header = _decode_jwt(gf.build_client_assertion("t", "c", cert_material["both"], thumbprint=override))[0]
    assert _b64url_bytes(header["x5t"]) == bytes.fromhex(override.replace(":", ""))
    assert _b64url_bytes(header["x5t#S256"]) == cert_material["sha256"]  # still taken from the certificate


def test_private_key_only_with_a_thumbprint(cert_material):
    thumbprint = cert_material["sha1"].hex().upper()
    jwt = gf.build_client_assertion("t", "c", cert_material["key_pem"], thumbprint=thumbprint)
    header, _claims, signing_input, signature = _decode_jwt(jwt)
    assert _b64url_bytes(header["x5t"]) == cert_material["sha1"]
    assert "x5t#S256" not in header  # no certificate, so no SHA-256 thumbprint
    _verify_signature(cert_material, signing_input, signature)


def test_private_key_only_without_a_thumbprint_is_an_error(cert_material):
    with pytest.raises(DemistoException, match="thumbprint"):
        gf.build_client_assertion("t", "c", cert_material["key_pem"])


def test_missing_private_key_is_an_error(cert_material):
    with pytest.raises(DemistoException, match="No private key"):
        gf.build_client_assertion("t", "c", cert_material["cert_pem"])


def test_missing_pem_is_an_error_before_any_request(mocker, integration_context):
    client, mock_http = _cert_client(mocker, "  ")
    with pytest.raises(DemistoException, match="certificate and private key"):
        client.chat_completion(_request())
    mock_http.assert_not_called()


def test_missing_tenant_or_client_id_is_an_error(mocker, integration_context, cert_material):
    adapter = _cert_adapter(cert_material["both"])
    adapter.entra_tenant_id = ""
    client = Client(adapter=adapter, verify=False, proxy=False)
    mocker.patch.object(client, "_http_request")
    with pytest.raises(DemistoException, match="Tenant ID and Client ID"):
        client.chat_completion(_request())


def test_encrypted_private_key_with_its_passphrase(cert_material):
    jwt = gf.build_client_assertion("t", "c", cert_material["encrypted_both"], passphrase=CERT_PASSPHRASE)
    _header, _claims, signing_input, signature = _decode_jwt(jwt)
    _verify_signature(cert_material, signing_input, signature)


def test_encrypted_private_key_without_its_passphrase(cert_material):
    with pytest.raises(DemistoException, match="passphrase"):
        gf.build_client_assertion("t", "c", cert_material["encrypted_both"])


def test_encrypted_private_key_with_the_wrong_passphrase(cert_material):
    with pytest.raises(DemistoException, match="could not be read") as exc_info:
        gf.build_client_assertion("t", "c", cert_material["encrypted_both"], passphrase="wrong")
    assert "wrong" not in str(exc_info.value)


def test_a_passphrase_for_an_unencrypted_key_is_ignored(cert_material):
    assert gf.build_client_assertion("t", "c", cert_material["both"], passphrase="unneeded")


def test_traditional_rsa_private_key_header_is_accepted(cert_material):
    assert "BEGIN RSA PRIVATE KEY" in cert_material["rsa_traditional"]
    assert gf.build_client_assertion("t", "c", cert_material["rsa_traditional"])


def test_pem_pasted_with_collapsed_or_escaped_newlines(cert_material):
    collapsed = cert_material["both"].replace("\n", " ")
    escaped = cert_material["both"].replace("\n", "\\n")
    crlf = cert_material["both"].replace("\n", "\r\n")
    for pem in (collapsed, escaped, crlf):
        header = _decode_jwt(gf.build_client_assertion("t", "c", pem))[0]
        assert _b64url_bytes(header["x5t"]) == cert_material["sha1"]


def test_certificate_must_belong_to_the_private_key(cert_material):
    with pytest.raises(DemistoException, match="does not belong"):
        gf.build_client_assertion("t", "c", cert_material["other_cert_pem"] + cert_material["key_pem"])


def test_a_certificate_chain_uses_the_leaf_that_matches_the_key(cert_material):
    pem = cert_material["other_cert_pem"] + cert_material["both"]
    header = _decode_jwt(gf.build_client_assertion("t", "c", pem))[0]
    assert _b64url_bytes(header["x5t"]) == cert_material["sha1"]


def test_only_rsa_keys_are_supported(cert_material):
    with pytest.raises(DemistoException, match="RSA"):
        gf.build_client_assertion("t", "c", cert_material["ec_key_pem"], thumbprint="ab" * 20)


@pytest.mark.parametrize("bad", ["abc", "zz" * 20, "ab" * 21])
def test_a_malformed_thumbprint_is_an_error(cert_material, bad):
    with pytest.raises(DemistoException, match="40 hexadecimal"):
        gf.build_client_assertion("t", "c", cert_material["both"], thumbprint=bad)


@pytest.mark.parametrize(
    "code, needle",
    [
        ("700027", "PUBLIC certificate is uploaded"),
        ("700024", "clock"),
        ("7000215", "client secret"),
    ],
)
def test_common_entra_errors_get_a_plain_explanation(mocker, integration_context, code, needle):
    err = _http_error(401, {"error": "invalid_client", "error_description": f"AADSTS{code}: raw text\r\nTrace ID: abc"})
    client, _ = _entra_client(mocker, err)
    with pytest.raises(DemistoException) as exc_info:
        client.chat_completion(_request())
    message = str(exc_info.value)
    assert f"AADSTS{code}" in message and needle in message
    assert "Trace ID" not in message


def test_cert_auth_surfaces_a_mapped_entra_error(mocker, integration_context, cert_material):
    err = _http_error(401, {"error": "invalid_client", "error_description": "AADSTS700027: Client assertion contains an invalid signature."})
    client, _ = _cert_client(mocker, cert_material["both"], token_response=err)
    with pytest.raises(DemistoException, match="thumbprint matches that certificate"):
        client.chat_completion(_request())


def test_an_unmapped_entra_error_keeps_the_original_description(mocker, integration_context):
    err = _http_error(400, {"error": "invalid_request", "error_description": "AADSTS90002: Tenant not found."})
    client, _ = _entra_client(mocker, err)
    with pytest.raises(DemistoException, match="AADSTS90002: Tenant not found"):
        client.chat_completion(_request())


def test_other_auth_types_never_import_cryptography(mocker, integration_context, monkeypatch):
    monkeypatch.setitem(sys.modules, "cryptography", None)  # any `import cryptography` now raises ImportError

    adapter = FoundryAdapter(RESOURCE, "gpt-4o", api_key="k")
    client = Client(adapter=adapter, verify=False, proxy=False)
    mocker.patch.object(client, "_http_request", return_value=_success_body())
    assert client.chat_completion(_request())["choices"]

    secret_client, _ = _entra_client(mocker, {"access_token": "AT", "expires_in": 3600})
    assert secret_client.chat_completion(_request())["choices"]


def test_cert_auth_without_cryptography_names_the_docker_image(mocker, integration_context, monkeypatch, cert_material):
    monkeypatch.setitem(sys.modules, "cryptography", None)
    client, mock_http = _cert_client(mocker, cert_material["both"])
    with pytest.raises(DemistoException, match="demisto/crypto"):
        client.chat_completion(_request())
    mock_http.assert_not_called()


def test_build_adapter_reads_the_certificate_params(cert_material):
    adapter = build_adapter(
        {
            "endpoint": RESOURCE,
            "model": "gpt-4o",
            "auth_type": "entra-client-certificate",
            "entra_tenant_id": " t ",
            "entra_client_id": " c ",
            "entra_certificate_pem": cert_material["both"],
            "entra_certificate_passphrase": {"identifier": "", "password": "pp"},
            "entra_certificate_thumbprint": " AB:CD ",
        }
    )
    assert adapter.auth_type == gf.AUTH_ENTRA_CERT
    assert adapter.entra_certificate_pem == cert_material["both"]
    assert adapter.entra_certificate_passphrase == "pp"
    assert adapter.entra_certificate_thumbprint == "AB:CD"
    assert adapter.entra_tenant_id == "t" and adapter.entra_client_id == "c"
    assert adapter.build_headers("tok")["Authorization"] == "Bearer tok"


# --- the optional `model` argument ------------------------------------------------------------------------------------

def test_model_arg_is_sent_as_the_requests_model_and_reported_back(mocker):
    client, mock_http = _client(mocker, model="gpt-4o", return_value=dict(_success_body(), model="gpt-5-mini-2025"))
    result = guardian_llm_chat_command(client, {"user_message": "hi", "model": "gpt-5-mini"})
    assert mock_http.call_args.kwargs["json_data"]["model"] == "gpt-5-mini"
    assert result.outputs["model"] == "gpt-5-mini-2025"
    assert client.adapter.model == "gpt-4o"  # the instance itself is not changed


def test_an_empty_or_equal_model_arg_is_todays_behaviour(mocker):
    for args in ({"user_message": "hi"}, {"user_message": "hi", "model": ""}, {"user_message": "hi", "model": "  "},
                 {"user_message": "hi", "model": "gpt-4o"}):
        client, mock_http = _client(mocker, model="gpt-4o", return_value=_success_body())
        guardian_llm_chat_command(client, args)
        assert mock_http.call_args.kwargs["json_data"]["model"] == "gpt-4o"


def test_model_family_auto_decides_from_the_routed_name(mocker):
    # the configured deployment is a standard model; the routed one is a reasoning model, so its parameters follow
    client, mock_http = _client(mocker, model="gpt-4o", return_value=_success_body())
    client.chat_completion({"messages": [{"role": "user", "content": "x"}], "temperature": 0.2, "max_tokens": 50}, model="o3-mini")
    body = mock_http.call_args.kwargs["json_data"]
    assert body["model"] == "o3-mini" and "temperature" not in body and body["max_completion_tokens"] == 50 and "max_tokens" not in body
    client, mock_http = _client(mocker, model="o3-mini", return_value=_success_body())
    client.chat_completion({"messages": [{"role": "user", "content": "x"}], "temperature": 0.2}, model="gpt-4o")
    assert mock_http.call_args.kwargs["json_data"]["temperature"] == 0.2


@pytest.mark.parametrize("status, body", [
    (404, {"error": {"code": "DeploymentNotFound", "message": "The API deployment for this resource does not exist."}}),
    (404, None),
    (400, {"error": {"code": "unknown_model", "message": "Unknown model: nope"}}),
    (400, {"error": {"message": "The model `nope` does not exist or you do not have access to it."}}),
])
def test_an_unknown_routed_deployment_is_a_model_not_available_error(mocker, status, body):
    client, _ = _client(mocker, side_effect=_http_error(status, body))
    with pytest.raises(DemistoException) as err:
        guardian_llm_chat_command(client, {"user_message": "hi", "model": "nope"})
    text = str(err.value)
    assert text.startswith("MODEL_NOT_AVAILABLE: model 'nope' is not deployed in this Foundry resource")
    assert "check the deployment name in the Foundry portal" in text


def test_other_failures_of_a_routed_call_keep_their_usual_messages(mocker):
    client, _ = _client(mocker, side_effect=_http_error(401, {"error": {"message": "bad key"}}))
    with pytest.raises(DemistoException) as err:
        guardian_llm_chat_command(client, {"user_message": "hi", "model": "gpt-5-mini"})
    assert not str(err.value).startswith("MODEL_") and "API key" in str(err.value)
    client, _ = _client(mocker, side_effect=_http_error(400, {"error": {"message": "max_tokens is too large"}}))
    with pytest.raises(DemistoException) as err:
        guardian_llm_chat_command(client, {"user_message": "hi", "model": "gpt-5-mini"})
    assert not str(err.value).startswith("MODEL_")


def test_a_404_for_the_configured_model_is_not_rewritten(mocker):
    client, _ = _client(mocker, side_effect=_http_error(404, {"error": {"code": "DeploymentNotFound"}}))
    with pytest.raises(DemistoException) as err:
        guardian_llm_chat_command(client, {"user_message": "hi"})
    assert not str(err.value).startswith("MODEL_") and "deployment name" in str(err.value)


def test_main_reports_a_model_error_with_its_prefix_first(mocker, monkeypatch):
    errors = []
    monkeypatch.setattr(gf, "return_error", errors.append)
    monkeypatch.setattr(gf.demisto, "params", lambda: {"endpoint": RESOURCE, "model": "gpt-4o", "api_key": "k"})
    monkeypatch.setattr(gf.demisto, "args", lambda: {"user_message": "hi", "model": "nope"})
    monkeypatch.setattr(gf.demisto, "command", lambda: "guardian-llm-chat")
    monkeypatch.setattr(gf.Client, "chat_completion", lambda self, *a, **k: (_ for _ in ()).throw(
        DemistoException("MODEL_NOT_AVAILABLE: model 'nope' is not deployed in this Foundry resource; check it.")))
    gf.main()
    assert errors and errors[0].startswith("MODEL_NOT_AVAILABLE:")


def test_the_yml_declares_the_model_argument():
    import pathlib
    import yaml
    doc = yaml.safe_load((pathlib.Path(__file__).parent / "GuardianFoundry.yml").read_text())
    args = {a["name"]: a for a in doc["script"]["commands"][0]["arguments"]}
    assert args["model"]["required"] is False and "MODEL_NOT_AVAILABLE:" in args["model"]["description"]
