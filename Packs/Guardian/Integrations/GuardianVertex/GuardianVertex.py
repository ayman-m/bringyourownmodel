"""GuardianVertex — provider-generic BYOI model-plane integration for Cortex XSOAR 6.

This is the model plane for the whole Guardian agent: every reasoning tick calls the
``guardian-llm-chat`` command. The OpenAI Chat-Completions wire format is treated as the
canonical shape — every provider adapter translates its own request/response format
to/from that shape, so ``guardian-llm-chat`` always returns the same, provider-independent
context under ``Guardian.LLM.Completion``.

Adding a new provider
----------------------
1. Subclass ``BaseChatAdapter`` (see ``AzureChatAdapter`` below for a worked example of a
   provider that still speaks the OpenAI wire shape but needs its own URL/header/content-filter
   logic, or ``VertexChatAdapter`` for a worked example of a provider — Google Vertex AI's
   Gemini — with an entirely different request/response wire format and its own auth minting).
2. Override whichever of the following need to differ from the OpenAI-compatible default:
   - ``build_url()``      — request URL.
   - ``build_params()``   — query-string params (e.g. Azure's ``api-version``).
   - ``build_headers()``  — auth header shape.
   - ``build_request_body()`` — translate the canonical request dict to the wire body.
   - ``normalize_response()`` — translate the wire response back to the canonical shape
     (only needed if the provider's response body deviates from the OpenAI shape).
   - ``handle_input_content_filter()`` — inspect a failed (non-2xx) call and return a
     structured content-filter result instead of raising, if this provider signals
     blocked *input* that way. Return ``None`` to fall back to a generic raised error
     (the default, correct behavior for providers with no content-filtering concept).
3. Register the adapter in ``ADAPTERS_BY_PROVIDER`` and add the provider name to the
   ``provider`` configuration dropdown in ``GuardianVertex.yml``. If the provider's configuration
   shape diverges from base_url/api_key (as Vertex's project_id/region/service_account_json
   does), add a branch in ``build_adapter()`` too.

All HTTP goes through ``BaseClient._http_request`` (proxy/verify/retry/backoff handled
uniformly for every provider); adapters only ever supply URL/headers/body translation.
"""

import copy
import json
import re
from typing import Any, Dict, List, Optional, Tuple, Type

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DEFAULT_PROVIDER = "openai-compatible"
DEFAULT_AUTH_STYLE = "bearer"
DEFAULT_API_VERSION = "2024-10-21"
DEFAULT_TIMEOUT = 120
DEFAULT_RETRIES = 3
RETRY_BACKOFF_FACTOR = 5
RETRYABLE_STATUS_CODES = [429]
CONTENT_FILTER_FINISH_REASON = "content_filter"

# Vertex AI (Gemini) adapter constants.
DEFAULT_VERTEX_REGION = "us-central1"
VERTEX_AUTH_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
GEMINI_CONTENT_FILTER_FINISH_REASONS = {"SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST"}
GEMINI_FINISH_REASON_MAP = {
    "STOP": "stop",
    "MAX_TOKENS": "length",
    "SAFETY": "content_filter",
    "PROHIBITED_CONTENT": "content_filter",
    "BLOCKLIST": "content_filter",
}
# JSON-Schema keywords Gemini's functionDeclarations.parameters / generationConfig.responseSchema
# parser rejects outright (Vertex only accepts a constrained OpenAPI-3.0-like subset).
# additionalProperties is the one Gemini has been observed to hard-reject with a 400; the rest
# are stripped defensively since they carry no meaning for Gemini's schema parser either.
GEMINI_UNSUPPORTED_SCHEMA_KEYS = {"additionalProperties", "$schema", "$id", "title", "default", "examples", "const"}
TOOL_CHOICE_STRING_TO_GEMINI_MODE = {"auto": "AUTO", "required": "ANY", "none": "NONE"}

""" PROVIDER ADAPTERS """


class BaseChatAdapter:
    """Base OpenAI-Chat-Completions-compatible provider adapter.

    Targets any server that speaks the plain OpenAI Chat Completions wire format:
    OpenAI itself, self-hosted vLLM/TGI, Ollama's OpenAI-compat endpoint, LiteLLM, etc.
    Since the canonical request/response shape *is* the OpenAI wire shape, this adapter's
    translation methods are close to pass-through; subclasses only need to override the
    pieces that actually differ (see module docstring).
    """

    provider_name = "openai-compatible"

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str,
        auth_style: str = DEFAULT_AUTH_STYLE,
        api_version: Optional[str] = None,
    ) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.model = model
        self.api_key = api_key or ""
        self.auth_style = auth_style or DEFAULT_AUTH_STYLE
        self.api_version = api_version

    def with_model(self, model: Optional[str]) -> "BaseChatAdapter":
        """This adapter for another model (the Gemini model id, the Azure deployment name or the server's model name);
        the URL and the request body are built from it. Everything else is unchanged."""
        model = (model or "").strip()
        if not model or model == self.model:
            return self
        clone = copy.copy(self)
        clone.model = model
        return clone

    def build_url(self) -> str:
        """Chat-completions endpoint. Avoids double-appending /v1 if the configured
        base_url already includes it (either shape is accepted from users)."""
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        if self.base_url.endswith("/v1"):
            return f"{self.base_url}/chat/completions"
        return f"{self.base_url}/v1/chat/completions"

    def build_params(self) -> Optional[Dict[str, str]]:
        """Query-string parameters. None for plain OpenAI-compatible servers."""
        return None

    def build_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.auth_style == "api-key":
            headers["api-key"] = self.api_key
        else:
            # "bearer" and "entra-token" both send a bearer Authorization header;
            # for entra-token the configured api_key holds a pre-acquired AAD token.
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def build_request_body(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """The canonical request dict already matches the OpenAI wire shape for this
        adapter, so this is close to a pass-through: drop unset (None) keys and make
        sure "model" is populated."""
        body = {k: v for k, v in request.items() if v is not None}
        body.setdefault("model", self.model)
        return body

    def normalize_response(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Translate a raw OpenAI-Chat-Completions-shaped response into the canonical
        Guardian.LLM.Completion shape."""
        choices: List[Dict[str, Any]] = []
        content_filter_flag = False
        top_finish_reason: Optional[str] = None

        for choice in raw.get("choices") or []:
            message = choice.get("message") or {}
            finish_reason = choice.get("finish_reason")
            if finish_reason == CONTENT_FILTER_FINISH_REASON:
                content_filter_flag = True
            normalized_choice = {
                "index": choice.get("index"),
                "message": {
                    "role": message.get("role"),
                    "content": message.get("content"),
                    "tool_calls": message.get("tool_calls"),
                },
                "finish_reason": finish_reason,
            }
            choices.append(normalized_choice)
            if top_finish_reason is None:
                top_finish_reason = finish_reason

        usage_raw = raw.get("usage") or {}
        cached_tokens = None
        prompt_details = usage_raw.get("prompt_tokens_details")
        if isinstance(prompt_details, dict):
            cached_tokens = prompt_details.get("cached_tokens")

        return {
            "id": raw.get("id"),
            "model": raw.get("model") or self.model,
            "created": raw.get("created"),
            "choices": choices,
            "finish_reason": top_finish_reason,
            "content_filter": content_filter_flag,
            "content_filter_detail": None,
            "usage": {
                "prompt_tokens": usage_raw.get("prompt_tokens"),
                "completion_tokens": usage_raw.get("completion_tokens"),
                "total_tokens": usage_raw.get("total_tokens"),
                "cached_tokens": cached_tokens,
            },
        }

    def handle_input_content_filter(self, exc: "DemistoException") -> Optional[Dict[str, Any]]:
        """Given the DemistoException raised by a failed (non-2xx) _http_request call,
        return a structured Guardian.LLM.Completion-shaped content-filter result if this
        looks like an input-side content-filter rejection, else None (caller re-raises
        the original error). Providers with no content-filtering concept (self-hosted
        vLLM/TGI/Ollama, etc.) always return None here — there is nothing to detect."""
        return None

    def empty_content_filter_result(self, message: str, raw_error: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Shared builder for the Guardian.LLM.Completion shape returned when the
        provider blocks a request before any completion is generated (no choices,
        no usage — only the content-filter flag and a human-readable detail)."""
        return {
            "id": None,
            "model": self.model,
            "created": None,
            "choices": [],
            "finish_reason": CONTENT_FILTER_FINISH_REASON,
            "content_filter": True,
            "content_filter_detail": {"message": message, "raw_error": raw_error},
            "usage": {
                "prompt_tokens": None,
                "completion_tokens": None,
                "total_tokens": None,
                "cached_tokens": None,
            },
        }


class AzureChatAdapter(BaseChatAdapter):
    """Azure OpenAI adapter.

    URL shape: {base_url}/openai/deployments/{model}/chat/completions?api-version={api_version}.
    Auth: "api-key" header (Azure's native key style) or "entra-token" (Authorization: Bearer
    <AAD token>).

    Content-filter handling is adapter-scoped here because Azure is the provider that actually
    signals it, on two channels:
      - Output-side: a normal 200 response where a choice's finish_reason == "content_filter"
        (already handled generically by the inherited normalize_response()).
      - Input-side: the prompt itself is rejected pre-generation as an HTTP 400 whose JSON body
        carries error.code / error.innererror.code of "content_filter" (or Azure's
        "ResponsibleAIPolicyViolation"). This is the case a plain OpenAI-compatible adapter has
        no equivalent for, so it is detected only here.
    """

    provider_name = "azure"

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str,
        auth_style: str = "api-key",
        api_version: Optional[str] = None,
    ) -> None:
        super().__init__(base_url, model, api_key, auth_style=auth_style, api_version=api_version)
        self.api_version = api_version or DEFAULT_API_VERSION

    def build_url(self) -> str:
        return f"{self.base_url}/openai/deployments/{self.model}/chat/completions"

    def build_params(self) -> Optional[Dict[str, str]]:
        return {"api-version": self.api_version}

    def build_headers(self) -> Dict[str, str]:
        if self.auth_style == "entra-token":
            return {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"}
        # Azure's native style, and the sane default for this adapter regardless of what
        # auth_style was left at (bearer would be wrong against Azure's own API surface).
        return {"Content-Type": "application/json", "api-key": self.api_key}

    def build_request_body(self, request: Dict[str, Any]) -> Dict[str, Any]:
        body = super().build_request_body(request)
        # The deployment (== model) is already encoded in the URL path; Azure API versions
        # vary on whether an extra "model" field in the body is tolerated, so drop it.
        body.pop("model", None)
        return body

    def handle_input_content_filter(self, exc: "DemistoException") -> Optional[Dict[str, Any]]:
        status_code = _status_code_of(exc)
        if status_code != 400:
            return None

        body = _extract_error_body(exc)
        if not isinstance(body, dict):
            return None

        error = body.get("error") or {}
        inner = error.get("innererror") or {}
        code = str(error.get("code") or "").lower()
        inner_code = str(inner.get("code") or "").lower()

        is_content_filter = (
            "content_filter" in code
            or "content_filter" in inner_code
            or "responsibleaipolicyviolation" in inner_code
            or "responsibleaipolicyviolation" in code
        )
        if not is_content_filter:
            return None

        message = error.get("message") or "Request blocked by the Azure OpenAI content filter."
        return self.empty_content_filter_result(message, raw_error=body)


""" VERTEX (GEMINI) TRANSLATION HELPERS """


def _strip_unsupported_json_schema_keys(schema: Any) -> Any:
    """Recursively drop JSON-Schema keywords Gemini's function-declaration / responseSchema
    parser rejects outright (see ``GEMINI_UNSUPPORTED_SCHEMA_KEYS``). ``additionalProperties``
    in particular is hard-rejected with an HTTP 400 if present *anywhere* in the schema
    (including nested inside ``properties`` / ``items``), which is why this recurses through
    the whole structure instead of only stripping it at the top level."""
    if isinstance(schema, dict):
        return {
            key: _strip_unsupported_json_schema_keys(value)
            for key, value in schema.items()
            if key not in GEMINI_UNSUPPORTED_SCHEMA_KEYS
        }
    if isinstance(schema, list):
        return [_strip_unsupported_json_schema_keys(item) for item in schema]
    return schema


def _gemini_content_parts(content: Any) -> List[Dict[str, Any]]:
    """Translate an OpenAI message's ``content`` field (a plain string, a list of content
    parts, or None) into Gemini ``parts`` entries. Only text is translated — Guardian's
    messages are text-only today; non-text content parts (e.g. image_url) are dropped rather
    than silently mis-translated into a text part."""
    if content is None:
        return []
    if isinstance(content, str):
        return [{"text": content}] if content else []
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append({"text": item})
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append({"text": item["text"]})
        return parts
    return [{"text": str(content)}]


def _gemini_tool_call_parts(tool_calls: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Translate an assistant message's OpenAI ``tool_calls`` into Gemini ``functionCall``
    parts. ``function.arguments`` is a JSON-encoded string on the OpenAI side; Gemini wants the
    parsed object directly."""
    parts = []
    for tool_call in tool_calls or []:
        function = tool_call.get("function") or {}
        raw_arguments = function.get("arguments")
        if isinstance(raw_arguments, dict):
            args = raw_arguments
        else:
            try:
                args = json.loads(raw_arguments) if raw_arguments else {}
            except (TypeError, ValueError):
                args = {}
        parts.append({"functionCall": {"name": function.get("name"), "args": args}})
    return parts


def _gemini_tool_response_part(name: Optional[str], content: Any) -> Dict[str, Any]:
    """Build ONE Gemini ``functionResponse`` part from an OpenAI ``tool`` (function-result)
    message. Gemini's ``functionResponse.response`` must be a JSON object: a plain
    string/number/list result is wrapped as ``{"result": ...}``."""
    if isinstance(content, dict):
        response = content
    elif isinstance(content, str):
        try:
            parsed = json.loads(content)
        except (TypeError, ValueError):
            parsed = content
        response = parsed if isinstance(parsed, dict) else {"result": parsed}
    elif content is None:
        response = {}
    else:
        response = {"result": content}
    return {"functionResponse": {"name": name, "response": response}}


def _gemini_tool_response_content(name: Optional[str], content: Any) -> Dict[str, Any]:
    """Translate a SINGLE OpenAI ``tool`` message into a Gemini ``user`` content carrying one
    ``functionResponse`` part. Kept for single-result callers/tests; the message translator
    groups consecutive tool results itself (see ``_messages_to_gemini_contents``)."""
    return {"role": "user", "parts": [_gemini_tool_response_part(name, content)]}


def _messages_to_gemini_contents(
    messages: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Translate the canonical (OpenAI-shaped) ``messages`` list into Gemini's ``contents``
    array plus a top-level ``systemInstruction`` (Gemini keeps the system prompt out of
    ``contents`` entirely, unlike OpenAI's system-role message)."""
    contents: List[Dict[str, Any]] = []
    system_parts: List[Dict[str, Any]] = []
    pending_tool_parts: List[Dict[str, Any]] = []  # consecutive tool results -> ONE user content

    def _flush_tool_parts() -> None:
        # Gemini requires the N functionResponse parts answering a model turn's N functionCall
        # parts to live in a SINGLE user content -- emitting one content per tool result makes
        # Gemini reject the turn ("number of function response parts is equal to the number of
        # function call parts"). So we buffer a run of tool results and flush them together.
        if pending_tool_parts:
            contents.append({"role": "user", "parts": list(pending_tool_parts)})
            pending_tool_parts.clear()

    for message in messages:
        role = message.get("role")

        if role == "system":
            system_parts.extend(_gemini_content_parts(message.get("content")))
            continue

        if role == "tool":
            # OpenAI tool-result messages are matched back to their call via tool_call_id;
            # Gemini's functionResponse matches by *name* instead, so the message must carry
            # "name" (Guardian's tool-execution layer is expected to include it alongside
            # tool_call_id when provider=vertex — there is no other reliable way to recover
            # the function name at this layer). Falls back to tool_call_id if name is absent
            # rather than dropping the turn outright.
            name = message.get("name") or message.get("tool_call_id")
            pending_tool_parts.append(_gemini_tool_response_part(name, message.get("content")))
            continue

        # Any non-tool message ends a run of tool results -- flush them as one user content first.
        _flush_tool_parts()

        if role == "assistant":
            parts = _gemini_content_parts(message.get("content"))
            parts.extend(_gemini_tool_call_parts(message.get("tool_calls")))
            if not parts:
                continue  # nothing translatable on this assistant turn
            contents.append({"role": "model", "parts": parts})
            continue

        # "user" and any other/unknown role default to Gemini's "user" role.
        parts = _gemini_content_parts(message.get("content"))
        if parts:
            contents.append({"role": "user", "parts": parts})

    _flush_tool_parts()  # trailing tool results (transcript ends on a tool turn)
    system_instruction = {"parts": system_parts} if system_parts else None
    return contents, system_instruction


def _gemini_function_declarations(tools: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Translate OpenAI ``tools`` (``{type:function, function:{name,description,parameters}}``)
    into Gemini ``functionDeclarations``, stripping unsupported JSON-Schema keywords from each
    tool's parameters schema (see ``_strip_unsupported_json_schema_keys``)."""
    declarations = []
    for tool in tools or []:
        if tool.get("type") != "function":
            continue
        function = tool.get("function") or {}
        name = function.get("name")
        if not name:
            continue
        declaration: Dict[str, Any] = {"name": name}
        if function.get("description"):
            declaration["description"] = function["description"]
        parameters = function.get("parameters")
        if parameters:
            declaration["parameters"] = _strip_unsupported_json_schema_keys(parameters)
        declarations.append(declaration)
    return declarations


def _gemini_tool_config(tool_choice: Any) -> Optional[Dict[str, Any]]:
    """Translate OpenAI ``tool_choice`` into Gemini's ``toolConfig.functionCallingConfig``.
    "auto"/"required"/"none" map to Gemini's AUTO/ANY/NONE modes; an OpenAI named-tool-selection
    object (``{"type":"function","function":{"name":"x"}}``) maps to mode ANY restricted to that
    one function via ``allowedFunctionNames`` (an extension beyond the plain string cases, but a
    faithful translation of the same intent)."""
    if tool_choice in (None, ""):
        return None
    if isinstance(tool_choice, str):
        mode = TOOL_CHOICE_STRING_TO_GEMINI_MODE.get(tool_choice.lower())
        return {"functionCallingConfig": {"mode": mode}} if mode else None
    if isinstance(tool_choice, dict):
        function = tool_choice.get("function") or {}
        name = function.get("name")
        if name:
            return {"functionCallingConfig": {"mode": "ANY", "allowedFunctionNames": [name]}}
    return None


def _gemini_generation_config(
    request: Dict[str, Any], response_format: Optional[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """Build Gemini's ``generationConfig`` from the canonical request's sampling params plus
    (when not overridden by tools — see ``VertexChatAdapter.build_request_body``)
    ``response_format`` structured-output settings."""
    config: Dict[str, Any] = {}

    temperature = request.get("temperature")
    if temperature is not None:
        config["temperature"] = temperature
    max_tokens = request.get("max_tokens")
    if max_tokens is not None:
        config["maxOutputTokens"] = max_tokens
    top_p = request.get("top_p")
    if top_p is not None:
        config["topP"] = top_p

    if response_format:
        response_type = response_format.get("type")
        if response_type in ("json_object", "json_schema"):
            config["responseMimeType"] = "application/json"
        schema = (response_format.get("json_schema") or {}).get("schema")
        if schema:
            config["responseSchema"] = _strip_unsupported_json_schema_keys(schema)

    return config or None


def _gemini_response_choice(candidate: Dict[str, Any], index: int) -> Tuple[Dict[str, Any], bool]:
    """Translate one Gemini ``candidates[]`` entry into an OpenAI-shaped choice dict. Returns
    the choice plus whether this candidate was blocked by Gemini's safety/content filtering."""
    content = candidate.get("content") or {}
    parts = content.get("parts") or []

    text_chunks: List[str] = []
    tool_calls: List[Dict[str, Any]] = []
    for part in parts:
        if isinstance(part.get("text"), str):
            text_chunks.append(part["text"])
        function_call = part.get("functionCall")
        if function_call:
            tool_calls.append(
                {
                    "id": f"call_{len(tool_calls)}",
                    "type": "function",
                    "function": {
                        "name": function_call.get("name"),
                        "arguments": json.dumps(function_call.get("args") or {}),
                    },
                }
            )

    gemini_finish_reason = candidate.get("finishReason")
    is_content_filter = gemini_finish_reason in GEMINI_CONTENT_FILTER_FINISH_REASONS

    if tool_calls:
        # Gemini reports a plain STOP even when the turn is actually a function call; the
        # canonical shape needs "tool_calls" here so callers can branch on it like they would
        # for any other provider.
        finish_reason: Optional[str] = "tool_calls"
    elif gemini_finish_reason in GEMINI_FINISH_REASON_MAP:
        finish_reason = GEMINI_FINISH_REASON_MAP[gemini_finish_reason]
    elif gemini_finish_reason:
        finish_reason = gemini_finish_reason.lower()
    else:
        finish_reason = None

    choice = {
        "index": candidate.get("index", index),
        "message": {
            "role": "assistant",
            "content": "".join(text_chunks) if text_chunks else None,
            "tool_calls": tool_calls or None,
        },
        "finish_reason": finish_reason,
    }
    return choice, is_content_filter


class VertexChatAdapter(BaseChatAdapter):
    """Google Vertex AI (Gemini) adapter.

    Unlike the OpenAI-compatible and Azure adapters (which both speak the OpenAI Chat
    Completions wire format directly), Vertex's ``generateContent`` API has its own distinct
    request/response shape entirely, so every translation hook is overridden here:

    - Auth is not a static key: a short-lived OAuth2 bearer token is minted per call from a
      service-account JSON key, scoped to ``https://www.googleapis.com/auth/cloud-platform``
      (the service account needs ``roles/aiplatform.user``). Minting happens in
      ``build_headers()``; the token is not cached across calls or instance lifetime (each
      mint costs one extra round trip to Google's token endpoint; tokens are valid ~1h).
      Caching it on the integration context would be a possible optimization for high call
      volumes.
    - The request body is the canonical OpenAI messages/tools/tool_choice/temperature/
      max_tokens translated to Gemini's contents/systemInstruction/tools/toolConfig/
      generationConfig shape (see the module-level ``_messages_to_gemini_contents`` /
      ``_gemini_*`` helpers above).
    - Gemini's function-declaration and responseSchema JSON-Schema subset rejects
      ``additionalProperties`` (and a few other JSON-Schema-only keywords) outright, so tool
      parameter schemas are recursively cleaned via ``_strip_unsupported_json_schema_keys``.
    - Content-filtering is signalled inside a normal 200 response, not as a distinct HTTP
      error like Azure's: either ``promptFeedback.blockReason`` (input blocked pre-generation)
      or a candidate ``finishReason`` of SAFETY/PROHIBITED_CONTENT/BLOCKLIST (output blocked).
      Both are detected in ``normalize_response()`` — there is no
      ``handle_input_content_filter()`` override because Vertex never signals this via a
      non-2xx HTTP error the way Azure does.
    """

    provider_name = "vertex"

    def __init__(self, project_id: str, region: str, model: str, service_account_json: str) -> None:
        self.project_id = project_id
        self.region = region or DEFAULT_VERTEX_REGION
        self.model = model
        self.service_account_json = service_account_json or ""
        self.base_url = self._api_host()
        # BaseChatAdapter fields unused by this adapter (no static key / api-version / auth
        # style — auth is minted per call in build_headers()) but kept set for anything that
        # introspects an adapter generically.
        self.api_key = ""
        self.auth_style = "bearer"
        self.api_version = None

    def _api_host(self) -> str:
        if self.region == "global":
            return "https://aiplatform.googleapis.com/v1"
        return f"https://{self.region}-aiplatform.googleapis.com/v1"

    def build_url(self) -> str:
        return (
            f"{self._api_host()}/projects/{self.project_id}/locations/{self.region}"
            f"/publishers/google/models/{self.model}:generateContent"
        )

    def build_params(self) -> Optional[Dict[str, str]]:
        return None

    def build_headers(self) -> Dict[str, str]:
        return {"Content-Type": "application/json", "Authorization": f"Bearer {self._mint_access_token()}"}

    def _mint_access_token(self) -> str:
        """Mint a short-lived OAuth2 access token from the configured service-account JSON,
        scoped to Vertex AI. Raises a clear DemistoException (rather than a raw traceback) if
        google-auth is missing from the Docker image or the service-account JSON is invalid —
        this is exactly the failure test-module is expected to surface for a bad SA key."""
        try:
            from google.oauth2 import service_account
            import google.auth.transport.requests
        except ImportError as exc:
            raise DemistoException(
                "The 'google-auth' package is required for provider=vertex but could not be "
                f"imported. Ensure the integration's Docker image bundles google-auth. Error: {exc}"
            )

        try:
            service_account_info = json.loads(self.service_account_json)
        except (TypeError, ValueError) as exc:
            raise DemistoException(f"'Service Account JSON' is not valid JSON: {exc}")

        try:
            credentials = service_account.Credentials.from_service_account_info(
                service_account_info, scopes=VERTEX_AUTH_SCOPES
            )
            credentials.refresh(google.auth.transport.requests.Request())
        except DemistoException:
            raise
        except Exception as exc:
            raise DemistoException(
                f"Failed to mint a Vertex AI access token from the configured service account: {exc}"
            )

        return credentials.token

    def build_request_body(self, request: Dict[str, Any]) -> Dict[str, Any]:
        contents, system_instruction = _messages_to_gemini_contents(request.get("messages") or [])
        body: Dict[str, Any] = {"contents": contents}
        if system_instruction:
            body["systemInstruction"] = system_instruction

        function_declarations = _gemini_function_declarations(request.get("tools"))
        response_format = request.get("response_format")

        if function_declarations:
            body["tools"] = [{"functionDeclarations": function_declarations}]
            tool_config = _gemini_tool_config(request.get("tool_choice"))
            if tool_config:
                body["toolConfig"] = tool_config
            if response_format:
                # Gemini does not reliably support functionDeclarations + responseSchema
                # together; prefer tools and drop response_format rather
                # than risk the provider rejecting (or silently ignoring) one of the two.
                demisto.debug(
                    "VertexChatAdapter: both 'tools' and 'response_format' were supplied; "
                    "ignoring 'response_format' in favor of 'tools' for this request."
                )
                response_format = None

        generation_config = _gemini_generation_config(request, response_format)
        if generation_config:
            body["generationConfig"] = generation_config

        return body

    def normalize_response(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        prompt_feedback = raw.get("promptFeedback") or {}
        block_reason = prompt_feedback.get("blockReason")
        if block_reason:
            return self.empty_content_filter_result(
                f"Vertex AI blocked the prompt before generation (blockReason={block_reason}).",
                raw_error=raw,
            )

        choices: List[Dict[str, Any]] = []
        content_filter_flag = False
        top_finish_reason: Optional[str] = None

        for index, candidate in enumerate(raw.get("candidates") or []):
            choice, is_content_filter = _gemini_response_choice(candidate, index)
            if is_content_filter:
                content_filter_flag = True
            choices.append(choice)
            if top_finish_reason is None:
                top_finish_reason = choice["finish_reason"]

        usage_raw = raw.get("usageMetadata") or {}

        return {
            "id": raw.get("responseId"),
            "model": raw.get("modelVersion") or self.model,
            "created": None,
            "choices": choices,
            "finish_reason": top_finish_reason,
            "content_filter": content_filter_flag,
            "content_filter_detail": (
                {
                    "message": "A candidate response was blocked by Gemini's safety/content filtering.",
                    "raw_error": raw,
                }
                if content_filter_flag
                else None
            ),
            "usage": {
                "prompt_tokens": usage_raw.get("promptTokenCount"),
                "completion_tokens": usage_raw.get("candidatesTokenCount"),
                "total_tokens": usage_raw.get("totalTokenCount"),
                "cached_tokens": usage_raw.get("cachedContentTokenCount"),
            },
        }


ADAPTERS_BY_PROVIDER: Dict[str, Type[BaseChatAdapter]] = {
    "openai-compatible": BaseChatAdapter,
    "azure": AzureChatAdapter,
    "vertex": VertexChatAdapter,
}


#: The start of the error text for a model the caller asked for (the `model` argument) that the provider does not have.
MODEL_NOT_AVAILABLE_PREFIX = "MODEL_NOT_AVAILABLE:"
MODEL_ERROR_PREFIXES = (MODEL_NOT_AVAILABLE_PREFIX, "MODEL_SELECTION_UNSUPPORTED:")

_MODEL_MISSING_RE = re.compile(
    r"DeploymentNotFound|model_not_found|NOT_FOUND|unknown[ _]model|invalid[ _]model"
    r"|(deployment|model)\b[^.]{0,80}(does not exist|not found|not exist|not supported|not available|not deployed)",
    re.IGNORECASE,
)

_MODEL_MISSING_WHERE = {
    "vertex": "is not available in this Vertex project and region; check the Gemini model id.",
    "azure": "is not deployed in this Azure OpenAI resource; check the deployment name.",
}


def get_adapter_class(provider: str) -> Type[BaseChatAdapter]:
    try:
        return ADAPTERS_BY_PROVIDER[provider]
    except KeyError:
        raise DemistoException(
            f"Unsupported provider '{provider}'. Supported providers: "
            f"{', '.join(ADAPTERS_BY_PROVIDER)}."
        )


""" HELPER FUNCTIONS """


def _status_code_of(exc: "DemistoException") -> Optional[int]:
    res = getattr(exc, "res", None)
    return getattr(res, "status_code", None) if res is not None else None


def _extract_error_body(exc: "DemistoException") -> Optional[Dict[str, Any]]:
    """Best-effort extraction of a parsed JSON error body from a DemistoException raised
    by _http_request. Returns None if no structured JSON body is available."""
    res = getattr(exc, "res", None)
    if res is None:
        return None
    try:
        return res.json()
    except Exception:
        return None


def _parse_json_arg(
    args: Dict[str, Any],
    name: str,
    expected_types: Tuple[type, ...],
    required: bool = False,
) -> Any:
    raw = args.get(name)
    if raw in (None, ""):
        if required:
            raise DemistoException(f'"{name}" is required.')
        return None
    if isinstance(raw, expected_types):
        return raw
    if not isinstance(raw, str):
        raise DemistoException(
            f'"{name}" must be a JSON {"/".join(t.__name__ for t in expected_types)} (as a string).'
        )
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise DemistoException(f'"{name}" must be valid JSON. Error: {exc}')
    if not isinstance(parsed, expected_types):
        raise DemistoException(
            f'"{name}" must be a JSON {"/".join(t.__name__ for t in expected_types)}, '
            f"got {type(parsed).__name__}."
        )
    return parsed


def _parse_tool_choice(raw: Optional[Any]) -> Optional[Any]:
    if raw in (None, ""):
        return None
    if isinstance(raw, (dict, list)):
        return raw
    stripped = str(raw).strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return json.loads(stripped)
        except (TypeError, ValueError) as exc:
            raise DemistoException(f'"tool_choice" looked like JSON but failed to parse: {exc}')
    return stripped  # plain string: "auto" | "none" | "required"


def _arg_to_float(args: Dict[str, Any], name: str) -> Optional[float]:
    raw = args.get(name)
    if raw in (None, ""):
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        raise DemistoException(f'"{name}" must be a number, got: {raw!r}')


def _arg_to_optional_bool(args: Dict[str, Any], name: str) -> Optional[bool]:
    raw = args.get(name)
    if raw in (None, ""):
        return None
    return argToBoolean(raw)


def _model_missing(exc: "DemistoException") -> bool:
    """Whether the provider answered that the model or deployment it was asked for does not exist: HTTP 404, or HTTP 400
    whose error body names the model or deployment."""
    status_code = _status_code_of(exc)
    if status_code == 404:
        return True
    if status_code != 400:
        return False
    body = _extract_error_body(exc)
    text = json.dumps(body) if body is not None else str(getattr(exc, "message", "") or "")
    return bool(_MODEL_MISSING_RE.search(text))


def _arg_to_call_timeout(args: Dict[str, Any]) -> Optional[float]:
    """The contract's optional per-call ``timeout`` (seconds): a hard wall-clock bound for this one
    call, capped by the instance's own request timeout. ``None`` when unset."""
    value = _arg_to_float(args, "timeout")
    if value is not None and value <= 0:
        raise DemistoException(f'"timeout" must be a positive number of seconds, got: {value!r}')
    return value


""" CLIENT CLASS """


class Client(BaseClient):
    """Thin BaseClient wrapper around a provider adapter.

    All HTTP happens through ``_http_request`` (inherited from BaseClient), so proxy /
    certificate-verification / retry / backoff behavior is uniform across every provider;
    the adapter only ever supplies the URL, headers, params, and request/response
    translation.
    """

    def __init__(self, adapter: BaseChatAdapter, verify: bool, proxy: bool, timeout: int = DEFAULT_TIMEOUT):
        # timeout is passed through to BaseClient, which layers in the standard
        # REQUESTS_TIMEOUT(.<integration>) env-var override on top of this default.
        super().__init__(base_url=adapter.base_url, verify=verify, proxy=proxy, timeout=timeout)
        self.adapter = adapter

    def chat_completion(
        self, request: Dict[str, Any], call_timeout: Optional[float] = None, model: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute one chat-completion round-trip through the configured provider
        adapter and return the canonical, normalized Guardian.LLM.Completion dict.

        ``model`` (the contract's optional argument) runs this call on another model than the configured one; a model
        the provider does not know is an error that starts with ``MODEL_NOT_AVAILABLE:``.

        ``call_timeout`` (the contract's per-call ``timeout``) makes this a hard wall-clock bound:
        one attempt, no transparent retries, never longer than the instance's own timeout.

        429s are retried transparently inside _http_request (status_list_to_retry +
        backoff_factor); if retries are exhausted the resulting error is re-raised with
        a clearer, rate-limit-specific message. A content-filter rejection recognized by
        the active adapter is returned as a structured result rather than raised.
        """
        adapter = self.adapter.with_model(model)
        routed = adapter is not self.adapter
        url = adapter.build_url()
        params = adapter.build_params()
        headers = adapter.build_headers()
        body = adapter.build_request_body(request)

        try:
            raw_response = self._http_request(
                method="POST",
                full_url=url,
                params=params,
                headers=headers,
                json_data=body,
                timeout=min(self.timeout, call_timeout) if call_timeout else self.timeout,
                ok_codes=(200,),
                retries=0 if call_timeout else DEFAULT_RETRIES,
                status_list_to_retry=RETRYABLE_STATUS_CODES,
                backoff_factor=RETRY_BACKOFF_FACTOR,
            )
        except DemistoException as exc:
            content_filter_result = adapter.handle_input_content_filter(exc)
            if content_filter_result is not None:
                return content_filter_result
            if routed and _model_missing(exc):
                where = _MODEL_MISSING_WHERE.get(adapter.provider_name, "is not known to this server; check the model name.")
                raise DemistoException(
                    f"{MODEL_NOT_AVAILABLE_PREFIX} model '{adapter.model}' {where} Original error: {exc.message}",
                    exception=exc,
                )
            if _status_code_of(exc) == 429:
                raise DemistoException(
                    "Guardian LLM provider rate-limited the request (HTTP 429) and the "
                    f"configured retries were exhausted. Original error: {exc.message}",
                    exception=exc,
                )
            raise

        return adapter.normalize_response(raw_response)


def build_adapter(params: Dict[str, Any]) -> BaseChatAdapter:
    provider = params.get("provider") or DEFAULT_PROVIDER
    adapter_cls = get_adapter_class(provider)

    model = (params.get("model") or "").strip()
    if not model:
        raise DemistoException("Model / deployment name is required.")

    if provider == "vertex":
        # Vertex's configuration shape (project_id/region/service_account_json) diverges
        # entirely from the base_url/api_key shape shared by the OpenAI-compatible and Azure
        # adapters, so it gets its own branch here rather than trying to force-fit it into the
        # generic base_url-required path below. base_url/auth_style/api_version are optional/
        # ignored for this provider, per the configuration's own additionalinfo text.
        project_id = (params.get("project_id") or "").strip()
        if not project_id:
            raise DemistoException("Project ID is required for provider=vertex.")
        region = (params.get("region") or DEFAULT_VERTEX_REGION).strip() or DEFAULT_VERTEX_REGION
        service_account_json = (params.get("service_account_json") or "").strip()
        if not service_account_json:
            raise DemistoException("Service Account JSON is required for provider=vertex.")
        return VertexChatAdapter(
            project_id=project_id,
            region=region,
            model=model,
            service_account_json=service_account_json,
        )

    base_url = (params.get("base_url") or "").strip()
    if not base_url:
        raise DemistoException("Base URL is required.")

    auth_style = params.get("auth_style") or DEFAULT_AUTH_STYLE
    api_key = params.get("api_key") or ""
    api_version = params.get("api_version") or None

    return adapter_cls(
        base_url=base_url,
        model=model,
        api_key=api_key,
        auth_style=auth_style,
        api_version=api_version,
    )


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Minimal 1-token completion used as the integration's connectivity/auth test."""
    request = {
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 1,
        "temperature": 0,
    }
    result = client.chat_completion(request)
    if result.get("content_filter"):
        detail = (result.get("content_filter_detail") or {}).get("message")
        raise DemistoException(
            "test-module completion was blocked by the provider's content filter "
            f"({detail}). Check the configured model/provider."
        )
    return "ok"


def _resolve_messages(args: Dict[str, Any]) -> list:
    """Resolve the effective messages array for one guardian-llm-chat call.

    Two mutually exclusive input shapes:
      * ``messages`` -- the full OpenAI-shaped array. Every production caller
        (GuardianReasoningTick, GuardianCompact, GuardianCompactCommand,
        GuardianPlanCommand, GuardianSubagentDispatch, GuardianProbeModel)
        uses this and is untouched by the branch below.
      * ``system_message`` (optional) + ``user_message`` (required) -- a
        single-turn convenience shape so an operator testing from the
        Playground never has to hand-format a JSON messages array just to
        try one prompt.
    Providing both shapes is rejected rather than silently preferring one --
    an operator who supplies both by mistake should see why, not get a
    transcript built from whichever branch happened to win.
    """
    messages = _parse_json_arg(args, "messages", expected_types=(list,), required=False)
    system_message = args.get("system_message") or None
    user_message = args.get("user_message") or None

    if messages is not None and (system_message or user_message):
        raise DemistoException(
            'Provide either "messages", or "system_message"/"user_message" -- not both.'
        )
    if messages is not None:
        return messages
    if not user_message:
        raise DemistoException(
            'Provide "messages" (a JSON array), or "user_message" '
            '(optionally with "system_message").'
        )
    built: list = []
    if system_message:
        built.append({"role": "system", "content": system_message})
    built.append({"role": "user", "content": user_message})
    return built


def guardian_llm_chat_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    messages = _resolve_messages(args)
    tools = _parse_json_arg(args, "tools", expected_types=(list,))
    response_format = _parse_json_arg(args, "response_format", expected_types=(dict,))
    tool_choice = _parse_tool_choice(args.get("tool_choice"))
    temperature = _arg_to_float(args, "temperature")
    reasoning_effort = args.get("reasoning_effort") or None
    parallel_tool_calls = _arg_to_optional_bool(args, "parallel_tool_calls")
    call_timeout = _arg_to_call_timeout(args)

    request = {
        "messages": messages,
        "tools": tools,
        "tool_choice": tool_choice,
        "response_format": response_format,
        "temperature": temperature,
        "reasoning_effort": reasoning_effort,
        "parallel_tool_calls": parallel_tool_calls,
    }

    result = client.chat_completion(request, call_timeout=call_timeout, model=(args.get("model") or "").strip() or None)

    if result.get("content_filter"):
        detail = (result.get("content_filter_detail") or {}).get("message")
        readable_output = tableToMarkdown(
            "Guardian LLM Completion — BLOCKED BY CONTENT FILTER",
            {
                "Model": result.get("model"),
                "Finish Reason": result.get("finish_reason"),
                "Detail": detail,
            },
        )
    else:
        usage = result.get("usage") or {}
        first_message = ((result.get("choices") or [{}])[0]).get("message", {}) or {}
        readable_output = tableToMarkdown(
            "Guardian LLM Completion",
            {
                "Model": result.get("model"),
                "Finish Reason": result.get("finish_reason"),
                "Content": first_message.get("content"),
                "Tool Calls": len(first_message.get("tool_calls") or []),
                "Prompt Tokens": usage.get("prompt_tokens"),
                "Completion Tokens": usage.get("completion_tokens"),
                "Cached Tokens": usage.get("cached_tokens"),
                "Total Tokens": usage.get("total_tokens"),
            },
        )

    return CommandResults(
        outputs_prefix="Guardian.LLM.Completion",
        outputs=result,
        readable_output=readable_output,
        raw_response=result,
    )


def main() -> None:
    """main function, parses params and runs command functions"""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    handle_proxy()

    demisto.debug(f"Command being called is {command}")

    try:
        adapter = build_adapter(params)
        client = Client(adapter=adapter, verify=verify_certificate, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))
        elif command == "guardian-llm-chat":
            return_results(guardian_llm_chat_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        if str(e).startswith(MODEL_ERROR_PREFIXES):
            return_error(str(e))  # the caller matches on the start of the text
        else:
            return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
