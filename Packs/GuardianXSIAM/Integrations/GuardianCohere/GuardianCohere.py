"""GuardianCohere — Cohere North provider integration for the Guardian model plane (Cortex platform).

This is one interchangeable *provider* behind Guardian's model plane. Like ``Guardian Vertex`` it
implements the **``guardian-llm-chat``** command and returns the canonical, provider-independent
``Guardian.LLM.Completion`` context (see ``docs/GUARDIAN_LLM_CHAT_CONTRACT.md``). Everything else in
the Guardian pack (the reasoning tick, prompt/tool-catalogue builders, compaction, cost ledger,
slash commands, sub-agents) only ever calls ``guardian-llm-chat`` and reads that normalized shape —
it never references a provider by name — so swapping Gemini for a private Cohere North deployment is
purely an operator choice: enable exactly one Guardian provider integration at a time.

Cohere North wire protocol
---------------------------
Unlike an OpenAI-compatible endpoint (single request/response), North is a *stateful conversation*
service reached in two hops:

  1. ``POST   {endpoint}/api/v1/chat``                  — submit a turn (Bearer auth). The request
     carries ``agent:{id}`` + ``conversation:{id}`` and ``stream:true``; the streamed body is drained
     and discarded (the model's reply is read back from the conversation object).
  2. ``GET    {endpoint}/api/v1/conversations/{id}``    — read the assembled conversation; the last
     message (role CHATBOT/assistant) is the model's reply. ``content`` is a list of text blocks.

Conversation identity is the operator-configured **Session ID** (a pre-created North conversation id):

  * ``reuse`` (default): the configured Session ID *is* ``conversation.id`` on every call, and only the
    turn's *new* messages (everything after the last assistant message) are sent — the server holds the
    running history (a fixed, pre-created conversation id).
  * ``stateless``: a fresh conversation id is minted per call and the full transcript is sent, for North
    deployments that accept client-supplied conversation UUIDs and want per-investigation isolation.

The messages/tools translation uses the OpenAI-compatible shape (``{"role":"user","content":"…"}``),
with a ``cohere`` tool-format fallback for North builds that expect Cohere-native
``parameter_definitions`` instead of OpenAI function tools.

All HTTP goes through ``BaseClient._http_request`` (proxy / TLS-verify / retry / backoff handled
uniformly); the client only supplies URL/headers/body translation and the conversation poll.
"""

import json
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import quote  # imported explicitly rather than via the wildcard import

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DEFAULT_MODEL_LABEL = "cohere-north"
MODEL_SELECTION_UNSUPPORTED_PREFIX = "MODEL_SELECTION_UNSUPPORTED:"
MODEL_ERROR_PREFIXES = (MODEL_SELECTION_UNSUPPORTED_PREFIX, "MODEL_NOT_AVAILABLE:")
# Default when the "Model size" instance param is absent/blank/unrecognized: "auto", meaning "no size
# declared here" -- the size a run uses comes from the model catalogue (or guardian_settings.model_tier for a
# model that is not in it). The value is informational; it never changes which size a run uses. It is its own
# constant here because GuardianCommon's tier logic is copied into scripts, never integrations.
DEFAULT_MODEL_TIER = "auto"
MODEL_TIER_CHOICES = ("auto", "small", "medium", "large")
# Per-HTTP-call timeout. Kept comfortably under Cortex platform's ~3-minute scheduled-entry ceiling so
# a single guardian-llm-chat can never blow the reasoning tick's budget.
DEFAULT_TIMEOUT = 120
DEFAULT_RETRIES = 2
RETRY_BACKOFF_FACTOR = 5
# Only 429 is safe to retry at the urllib3 layer: the chat POST is non-idempotent (it appends the
# turn and triggers a generation on a stateful conversation), so retrying a 5xx that the origin may
# have already processed would double-submit the turn (duplicate history / double billing). 429 is a
# pre-processing rate-limit reject, so re-POSTing it is safe. (Same rule as the Guardian Vertex provider.)
RETRYABLE_STATUS_CODES = [429]

CHAT_PATH = "/api/v1/chat"
CONVERSATIONS_PATH = "/api/v1/conversations/"

CONVERSATION_MODE_REUSE = "reuse"
CONVERSATION_MODE_STATELESS = "stateless"
DEFAULT_CONVERSATION_MODE = CONVERSATION_MODE_REUSE

TOOL_FORMAT_OPENAI = "openai"
TOOL_FORMAT_COHERE = "cohere"
DEFAULT_TOOL_FORMAT = TOOL_FORMAT_OPENAI

# Conversation poll: the POST normally blocks until North finishes generating (its streamed body is
# fully drained), so the reply is usually present on the first GET. The poll covers a
# not-yet-committed write, or a North build that returns 202 (accepted) and generates
# asynchronously. It requires a genuinely new terminal assistant message (message count grown past a
# pre-submit baseline) so it can never return the prior turn's reply on a stateful/reused conversation.
POLL_DEADLINE_SECONDS = 90
POLL_INTERVAL_CAP_SECONDS = 2.0
# Per-GET timeout cap for the (cheap) conversation reads: bounds a single hung GET well under the
# overall poll deadline so total poll wall-clock stays near POLL_DEADLINE_SECONDS.
POLL_GET_TIMEOUT_CAP = 30

ASSISTANT_ROLES = {"CHATBOT", "ASSISTANT"}

# Cohere-native parameter_definitions type mapping (used only when tool_format == "cohere").
COHERE_PARAM_TYPE_MAP = {
    "integer": "int",
    "number": "float",
    "boolean": "bool",
    "array": "list",
    "object": "dict",
    "string": "str",
}


""" TRANSLATION HELPERS """


def _content_to_text(content: Any) -> Optional[str]:
    """Flatten an OpenAI message ``content`` (string | list of parts | None) to plain text.

    North's chat messages carry a plain-string ``content``, so a list-of-parts content (OpenAI's
    multi-part shape) is reduced to its concatenated text; non-text parts (e.g. image_url) are
    dropped rather than mis-serialized. Returns None when there is no text (e.g. an assistant turn
    that is only tool_calls)."""
    if content is None:
        return None
    if isinstance(content, str):
        return content or None
    if isinstance(content, list):
        chunks: List[str] = []
        for item in content:
            if isinstance(item, str):
                chunks.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                chunks.append(item["text"])
        return "".join(chunks) or None
    return str(content)


def _extract_system_text(messages: List[Dict[str, Any]]) -> str:
    """Concatenate every system-role message's text. North takes the system prompt as a top-level
    ``system`` field (kept out of the ``messages`` array), so it is extracted from the *full*
    transcript and re-asserted on every call — independent of the reuse/stateless turn slicing."""
    parts: List[str] = []
    for message in messages:
        if message.get("role") == "system":
            text = _content_to_text(message.get("content"))
            if text:
                parts.append(text)
    return "\n".join(parts).strip()


def _messages_after_last_assistant(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The turn's *new* messages: everything after the last assistant message, minus any system
    messages (those go in the top-level ``system`` field). In ``reuse`` mode North already holds the
    prior history under the configured conversation id, so only these new messages are submitted."""
    last_assistant_idx = -1
    for i, message in enumerate(messages):
        if message.get("role") == "assistant":
            last_assistant_idx = i
    turn = messages[last_assistant_idx + 1:]
    return [m for m in turn if m.get("role") != "system"]


def _to_north_messages(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Translate canonical (OpenAI-shaped) messages into North chat messages.

    ``{"role":"user","content":"…"}`` (OpenAI-compatible). The
    assistant/tool round-trip fields (``tool_calls`` / ``tool_call_id`` / ``name``) are forwarded in
    their OpenAI shape for North builds that accept them; a build that ignores them still gets a
    well-formed text turn. System messages are excluded here (see ``_extract_system_text``)."""
    out: List[Dict[str, Any]] = []
    for message in messages:
        role = message.get("role") or "user"
        if role == "system":
            continue
        entry: Dict[str, Any] = {"role": role}
        text = _content_to_text(message.get("content"))
        if text is not None:
            entry["content"] = text
        if message.get("tool_calls"):
            entry["tool_calls"] = message["tool_calls"]
        if message.get("tool_call_id"):
            entry["tool_call_id"] = message["tool_call_id"]
        if message.get("name"):
            entry["name"] = message["name"]
        # An assistant turn that was purely tool_calls has no content; keep the entry (its tool_calls
        # carry the meaning) but ensure "content" exists as an empty string for strict parsers.
        if "content" not in entry and role != "assistant":
            entry["content"] = ""
        out.append(entry)
    return out


def _json_schema_to_cohere_param_defs(schema: Any) -> Dict[str, Dict[str, Any]]:
    """Translate a JSON-Schema ``parameters`` object into Cohere-native ``parameter_definitions``
    (used only when tool_format == "cohere")."""
    schema = schema if isinstance(schema, dict) else {}
    required = set(schema.get("required") or [])
    props = schema.get("properties") or {}
    out: Dict[str, Dict[str, Any]] = {}
    for name, prop in props.items():
        prop = prop if isinstance(prop, dict) else {}
        json_type = str(prop.get("type") or "string").lower()
        out[name] = {
            "description": prop.get("description") or "",
            "type": COHERE_PARAM_TYPE_MAP.get(json_type, "str"),
            "required": name in required,
        }
    return out


def _to_north_tools(tools: Optional[List[Dict[str, Any]]], tool_format: str) -> Optional[List[Dict[str, Any]]]:
    """Translate OpenAI ``tools`` into the North wire shape.

    ``openai`` (default): forwarded as-is (the North endpoint's messages layer is OpenAI-compatible, so
    OpenAI function tools are the most likely accepted shape). ``cohere``: converted to Cohere-native
    ``[{name, description, parameter_definitions}]`` for North builds that require it."""
    if not tools:
        return None
    if tool_format == TOOL_FORMAT_COHERE:
        converted: List[Dict[str, Any]] = []
        for tool in tools:
            if not isinstance(tool, dict) or tool.get("type") != "function":
                continue
            function = tool.get("function") or {}
            name = function.get("name")
            if not name:
                continue
            converted.append(
                {
                    "name": name,
                    "description": function.get("description") or "",
                    "parameter_definitions": _json_schema_to_cohere_param_defs(function.get("parameters")),
                }
            )
        return converted or None
    # openai (default): pass through the OpenAI tool defs unchanged.
    return tools


def _last_role_is_assistant(convo: Optional[Dict[str, Any]]) -> bool:
    """True when the conversation's last message is a CHATBOT/assistant reply — the poll-completion
    signal (we always append a user/tool message before reading, so the terminal state is assistant)."""
    messages = (convo or {}).get("messages") or []
    if not messages:
        return False
    last = messages[-1]
    role = str((last or {}).get("role") or "").upper()
    return role in ASSISTANT_ROLES


def _extract_reply_text(message: Dict[str, Any]) -> Optional[str]:
    """Pull the assistant reply text out of a North conversation message. ``content`` is normally a
    list of blocks (``[{text}, …]``) — the *last* text block is the answer (a leading block, when
    present, is a plan/citation preamble). Falls back to a plain-string
    ``content`` / ``message`` / ``text`` field."""
    content = message.get("content")
    if isinstance(content, str):
        return content or None
    if isinstance(content, list):
        texts = [b["text"] for b in content if isinstance(b, dict) and isinstance(b.get("text"), str) and b["text"]]
        if texts:
            return texts[-1]
        return None
    if isinstance(message.get("message"), str):
        return message["message"] or None
    if isinstance(message.get("text"), str):
        return message["text"] or None
    return None


def _extract_reply_tool_calls(message: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """Normalize a North reply's tool calls into the canonical OpenAI ``tool_calls`` shape. Accepts
    both an already-OpenAI-shaped call (``{id,type,function:{name,arguments}}``) and a Cohere-native
    call (``{name, parameters}``)."""
    raw = message.get("tool_calls")
    if not raw or not isinstance(raw, list):
        return None
    out: List[Dict[str, Any]] = []
    for i, call in enumerate(raw):
        if not isinstance(call, dict):
            continue
        if isinstance(call.get("function"), dict):
            # Already OpenAI-shaped; ensure a stable id/type are present.
            function = call["function"]
            arguments = function.get("arguments")
            if not isinstance(arguments, str):
                arguments = json.dumps(arguments or {})
            out.append(
                {
                    "id": call.get("id") or f"call_{i}",
                    "type": "function",
                    "function": {"name": function.get("name"), "arguments": arguments},
                }
            )
        elif call.get("name") is not None:
            out.append(
                {
                    "id": call.get("id") or f"call_{i}",
                    "type": "function",
                    "function": {
                        "name": call.get("name"),
                        "arguments": json.dumps(call.get("parameters") if call.get("parameters") is not None else {}),
                    },
                }
            )
    return out or None


def _usage_from_conversation(convo: Dict[str, Any]) -> Dict[str, Any]:
    """Map North's ``meta.tokens`` usage to the canonical ``usage`` shape. North reports
    ``input_tokens`` / ``output_tokens``; ``total_tokens`` is summed when both are present."""
    meta = convo.get("meta") or {}
    tokens = meta.get("tokens") or {}
    prompt_tokens = tokens.get("input_tokens")
    completion_tokens = tokens.get("output_tokens")
    total_tokens = None
    if isinstance(prompt_tokens, (int, float)) and isinstance(completion_tokens, (int, float)):
        total_tokens = prompt_tokens + completion_tokens
    return {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "cached_tokens": None,
    }


def _usage_from_stream(raw: Any) -> Optional[Dict[str, Any]]:
    """Token usage from the chat response's event stream, or ``None``. North ends the stream with an event that carries
    ``usage`` (``tokens`` with ``input_tokens``/``output_tokens``, else ``billed_units``); the conversation read
    does not always include it. The last ``usage`` found wins. Never raises."""
    if not isinstance(raw, str) or "usage" not in raw:
        return None

    def find(node: Any) -> Optional[Dict[str, Any]]:
        if isinstance(node, dict):
            usage = node.get("usage")
            if isinstance(usage, dict) and (usage.get("tokens") or usage.get("billed_units")):
                return usage
            for value in node.values():
                hit = find(value)
                if hit:
                    return hit
        elif isinstance(node, list):
            for value in node:
                hit = find(value)
                if hit:
                    return hit
        return None

    found = None
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        try:
            hit = find(json.loads(line[5:].strip()))
        except (TypeError, ValueError):
            continue
        if hit:
            found = hit
    if not found:
        return None
    counts = found.get("tokens") if isinstance(found.get("tokens"), dict) else {}
    billed = found.get("billed_units") if isinstance(found.get("billed_units"), dict) else {}
    prompt = counts.get("input_tokens", billed.get("input_tokens"))
    completion = counts.get("output_tokens", billed.get("output_tokens"))
    if not isinstance(prompt, (int, float)) and not isinstance(completion, (int, float)):
        return None
    total = prompt + completion if isinstance(prompt, (int, float)) and isinstance(completion, (int, float)) else None
    cached = found.get("cached_tokens")
    return {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": total,
        "cached_tokens": cached if isinstance(cached, (int, float)) else None,
    }


def _error_from_stream(raw: Any) -> Optional[str]:
    """The error North reported in the chat stream's last event (``error`` with ``error_code`` and ``message``,
    or a finish reason of ERROR_LIMIT / TIMEOUT), as one line, or ``None``. Without this a failed turn only shows up as
    a conversation that never gets a new reply. Never raises."""
    if not isinstance(raw, str) or ("error" not in raw and "finish_reason" not in raw):
        return None

    def walk(node: Any, out: Dict[str, Any]) -> None:
        if isinstance(node, dict):
            err = node.get("error")
            if isinstance(err, dict) and err.get("error_code"):
                out["error"] = err
            reason = node.get("finish_reason")
            if isinstance(reason, str):
                out["finish_reason"] = reason
            for value in node.values():
                walk(value, out)
        elif isinstance(node, list):
            for value in node:
                walk(value, out)

    found: Dict[str, Any] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        try:
            walk(json.loads(line[5:].strip()), found)
        except (TypeError, ValueError):
            continue
    err = found.get("error")
    reason = found.get("finish_reason")
    if isinstance(err, dict):
        text = f"{err.get('error_code')}: {err.get('message') or 'no message'}"
        if err.get("context"):
            text += f" (context: {json.dumps(err.get('context'), default=str)[:300]})"
        return f"{text} [finish reason {reason}]" if reason else text
    if reason in ("ERROR", "ERROR_LIMIT", "TIMEOUT"):
        return f"finish reason {reason} with no detail"
    return None


""" HELPER FUNCTIONS (argument parsing — shared shape with the other Guardian providers) """


def _decode_json_text(raw: str) -> Any:
    """Parse JSON text, or a ``b64:`` argument (base64 of the JSON text). XSIAM damages JSON arguments that carry deeply
    nested backslash escapes, so Guardian's own callers send ``messages``/``tools``/``response_format`` base64-encoded
    (see GuardianCommon.guardian_arg_encode); plain JSON is still accepted."""
    if raw.startswith("b64:"):
        import base64

        try:
            return json.loads(base64.b64decode(raw[4:]).decode("utf-8"))
        except Exception as exc:  # binascii.Error, UnicodeDecodeError and JSON errors alike
            raise ValueError(f"invalid b64 argument: {exc}")
    return json.loads(raw)



def _parse_json_arg(
    args: Dict[str, Any],
    name: str,
    expected_types: tuple,
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
        parsed = _decode_json_text(raw)
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


def _to_north_tool_choice(raw: Optional[Any]) -> Optional[str]:
    """Translate an OpenAI-style ``tool_choice`` into what North accepts: exactly ``REQUIRED`` or ``NONE``.

    ``auto`` (and an empty value) is North's default, so the key is left out. ``required``/``any`` and a call that
    names one function become ``REQUIRED`` (North cannot name the function); ``none`` becomes ``NONE``.
    Anything else is left out rather than sent and rejected with a 422."""
    if isinstance(raw, dict):
        return "REQUIRED"
    value = str(raw or "").strip().lower()
    if value in ("required", "any"):
        return "REQUIRED"
    if value == "none":
        return "NONE"
    return None


def _arg_to_float(args: Dict[str, Any], name: str) -> Optional[float]:
    raw = args.get(name)
    if raw in (None, ""):
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        raise DemistoException(f'"{name}" must be a number, got: {raw!r}')


def _arg_to_call_timeout(args: Dict[str, Any]) -> Optional[float]:
    """The contract's optional per-call ``timeout`` (seconds): one wall-clock deadline for this whole
    call, capped by the instance's own request timeout. ``None`` when unset."""
    value = _arg_to_float(args, "timeout")
    if value is not None and value <= 0:
        raise DemistoException(f'"timeout" must be a positive number of seconds, got: {value!r}')
    return value


def _arg_to_optional_bool(args: Dict[str, Any], name: str) -> Optional[bool]:
    raw = args.get(name)
    if raw in (None, ""):
        return None
    return argToBoolean(raw)


""" CLIENT CLASS """


class CohereNorthClient(BaseClient):
    """Guardian ↔ Cohere North transport.

    All HTTP goes through ``BaseClient._http_request`` (proxy / TLS-verify / retry / backoff uniform);
    this class owns only the two-hop chat protocol (POST a turn, poll the conversation) and the
    request/response translation to/from the canonical ``Guardian.LLM.Completion`` shape.
    """

    def __init__(
        self,
        endpoint: str,
        agent_id: str,
        session_id: str,
        bearer_token: str,
        model_label: str,
        model_tier: str,
        conversation_mode: str,
        tool_format: str,
        verify: bool,
        proxy: bool,
        timeout: int = DEFAULT_TIMEOUT,
        model_id: str = "",
    ) -> None:
        self.endpoint = (endpoint or "").rstrip("/")
        super().__init__(base_url=self.endpoint, verify=verify, proxy=proxy, timeout=timeout)
        self.agent_id = agent_id
        self.session_id = session_id
        self.bearer_token = bearer_token or ""
        self.model_label = model_label or DEFAULT_MODEL_LABEL
        self.model_tier = model_tier or DEFAULT_MODEL_TIER
        self.model_id = (model_id or "").strip()
        self.conversation_mode = conversation_mode or DEFAULT_CONVERSATION_MODE
        self.tool_format = tool_format or DEFAULT_TOOL_FORMAT
        self.request_timeout = timeout
        # Set only for the duration of a chat_completion() that was given a per-call timeout: one
        # wall-clock deadline shared by the baseline read, the submit and the poll (see _budget).
        self._call_deadline: Optional[float] = None

    def _budget(self, cap: float) -> float:
        """``cap``, shortened to the time left before this call's deadline when one is set."""
        if self._call_deadline is None:
            return cap
        return max(1.0, min(cap, self._call_deadline - time.time()))

    def _auth_headers(self) -> Dict[str, str]:
        # NOTE: must not be named `_headers`: CommonServerPython's BaseClient.__init__ sets an
        # instance attribute `self._headers` (default None), which would shadow a method of that name
        # and make `self._auth_headers()` raise "'NoneType' object is not callable".
        return {
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _conversation_id_for_call(self) -> str:
        if self.conversation_mode == CONVERSATION_MODE_STATELESS:
            return str(uuid.uuid4())
        return self.session_id

    def build_request_body(self, request: Dict[str, Any], conversation_id: str) -> Dict[str, Any]:
        messages = request.get("messages") or []
        if self.conversation_mode == CONVERSATION_MODE_STATELESS:
            turn_messages = [m for m in messages if m.get("role") != "system"]
        else:
            turn_messages = _messages_after_last_assistant(messages)

        body: Dict[str, Any] = {
            "stream": True,
            "messages": _to_north_messages(turn_messages),
            "agent": {"id": self.agent_id},
            "conversation": {"id": conversation_id},
        }

        if self.model_id:
            body["model"] = self.model_id  # only when the operator set a Model ID: otherwise North picks the model

        system_text = _extract_system_text(messages)
        if system_text:
            body["system"] = system_text

        tools = _to_north_tools(request.get("tools"), self.tool_format)
        if tools:
            body["tools"] = tools

        tool_choice = _to_north_tool_choice(request.get("tool_choice"))
        if tool_choice:
            body["tool_choice"] = tool_choice  # North accepts only "REQUIRED" or "NONE"; "auto" is its default

        temperature = request.get("temperature")
        if temperature is not None:
            body["temperature"] = temperature

        return body

    def _get_conversation(self, conversation_id: str, timeout: float) -> Optional[Dict[str, Any]]:
        """GET /api/v1/conversations/{id}. Returns the parsed conversation dict, or None if the read
        fails or the conversation does not exist yet (never raises)."""
        url = f"{self.endpoint}{CONVERSATIONS_PATH}{quote(conversation_id, safe='')}"
        try:
            fetched = self._http_request(
                method="GET",
                full_url=url,
                headers=self._auth_headers(),
                timeout=timeout,
                ok_codes=(200,),
                resp_type="json",
            )
            return fetched if isinstance(fetched, dict) else None
        except DemistoException as exc:
            demisto.debug(f"GuardianCohere: conversation read failed for {conversation_id}: {exc}")
            return None

    def baseline_message_count(self, conversation_id: str) -> int:
        """Read the conversation's current message count BEFORE submitting a turn, so the poll can
        require a genuinely NEW terminal assistant message (not the prior turn's assistant tail on a
        stateful/reused conversation). A missing/unreadable conversation counts as 0 (first use)."""
        convo = self._get_conversation(conversation_id, self._budget(min(self.request_timeout, POLL_GET_TIMEOUT_CAP)))
        if convo is None:
            return 0
        return len(convo.get("messages") or [])

    def probe_conversation(self, conversation_id: str) -> None:
        """Read-only connectivity/auth probe: a single GET that proves the endpoint is reachable, the
        bearer token is accepted, and the conversation id resolves — WITHOUT appending any turn. Raises
        on a real transport/auth error (401/403/404/…)."""
        url = f"{self.endpoint}{CONVERSATIONS_PATH}{quote(conversation_id, safe='')}"
        self._http_request(
            method="GET",
            full_url=url,
            headers=self._auth_headers(),
            timeout=min(self.request_timeout, POLL_GET_TIMEOUT_CAP),
            ok_codes=(200,),
            resp_type="json",
        )

    def submit_turn(self, body: Dict[str, Any]) -> str:
        """POST one turn to /api/v1/chat. The streamed body is drained and discarded — the reply is
        read back from the conversation object, except the token usage, which is read from the stream's last event
        and returned as text. Only 429 is retried (the POST is non-idempotent)."""
        streamed = self._http_request(
            method="POST",
            full_url=f"{self.endpoint}{CHAT_PATH}",
            headers=self._auth_headers(),
            json_data=body,
            timeout=self._budget(self.request_timeout),
            ok_codes=(200, 202),
            resp_type="text",  # the response is an SSE stream we don't consume; never parse it as JSON
            # A per-call deadline is a hard bound: no transparent retry may extend it.
            retries=0 if self._call_deadline is not None else DEFAULT_RETRIES,
            status_list_to_retry=RETRYABLE_STATUS_CODES,
            backoff_factor=RETRY_BACKOFF_FACTOR,
        )
        return streamed if isinstance(streamed, str) else ""

    def poll_conversation(self, conversation_id: str, baseline_count: int = 0) -> Dict[str, Any]:
        """GET /api/v1/conversations/{id} until it ends in a NEW assistant reply — i.e. the last
        message's role is CHATBOT/assistant AND the message count has grown past ``baseline_count``
        (the count captured before this turn was submitted). This is what makes the poll robust on a
        reused, stateful conversation: it can never fire on the PRIOR turn's assistant tail, only on a
        genuinely new reply. On deadline exhaustion it RAISES (it never fabricates a completion from a
        non-assistant terminal message such as the just-submitted user turn)."""
        deadline = time.time() + min(self.request_timeout, POLL_DEADLINE_SECONDS)
        if self._call_deadline is not None:
            deadline = min(deadline, self._call_deadline)
        attempt = 0
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            attempt += 1
            get_timeout = min(self.request_timeout, POLL_GET_TIMEOUT_CAP, max(1.0, remaining))
            convo = self._get_conversation(conversation_id, get_timeout)
            if convo is not None:
                messages = convo.get("messages") or []
                if len(messages) > baseline_count and _last_role_is_assistant(convo):
                    return convo
            time.sleep(min(POLL_INTERVAL_CAP_SECONDS, 0.5 + attempt * 0.1))

        if self._call_deadline is not None:
            raise DemistoException(
                f"Cohere North conversation {conversation_id} did not return a new assistant reply before "
                "this call's per-call timeout. The turn may still be generating server-side."
            )
        raise DemistoException(
            f"Cohere North conversation {conversation_id} did not return a new assistant reply within "
            f"the poll window (~{min(self.request_timeout, POLL_DEADLINE_SECONDS)}s). The turn may still "
            "be generating server-side; retry, or raise the Request timeout."
        )

    def normalize_response(self, convo: Dict[str, Any], conversation_id: str) -> Dict[str, Any]:
        """Translate a North conversation object into the canonical Guardian.LLM.Completion shape."""
        messages = (convo or {}).get("messages") or []
        last = messages[-1] if messages else {}
        if not isinstance(last, dict):
            last = {}

        text = _extract_reply_text(last)
        tool_calls = _extract_reply_tool_calls(last)
        finish_reason = "tool_calls" if tool_calls else "stop"

        # `self.model_label` is operator-declared free text on the integration instance
        # ("Model label", purely cosmetic), and nothing verifies it against what actually served
        # the request, so swapping the backing model without also editing this param would
        # misattribute every subsequent turn's cost/telemetry to the stale label. If North's own
        # response carries an observed model identifier (`meta.model`), prefer it. Otherwise fall
        # back to the declared label, so this is a no-op against any backend that does not echo
        # one.
        observed_model = ((convo or {}).get("meta") or {}).get("model")
        model_label = observed_model if isinstance(observed_model, str) and observed_model.strip() else self.model_label

        return {
            "id": last.get("id") or conversation_id,
            "model": model_label,
            "model_tier": self.model_tier,
            "created": None,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": text,
                        "tool_calls": tool_calls,
                    },
                    "finish_reason": finish_reason,
                }
            ],
            "finish_reason": finish_reason,
            "content_filter": False,
            "content_filter_detail": None,
            "usage": _usage_from_conversation(convo or {}),
        }

    def chat_completion(self, request: Dict[str, Any], call_timeout: Optional[float] = None) -> Dict[str, Any]:
        """One full Guardian chat turn against North: (reuse mode) read the baseline message count,
        submit the turn, poll for a genuinely NEW assistant reply, normalize.

        In ``stateless`` mode the conversation id is a fresh empty UUID, so the baseline is 0 and no
        pre-read is needed. Only genuine transport/auth/deadline failures propagate (which the caller
        reads off the executeCommand error entry, per the contract).

        ``call_timeout`` (the contract's per-call ``timeout``) bounds the WHOLE turn -- all three
        steps share one deadline -- instead of each step getting the full request timeout."""
        self._call_deadline = time.time() + min(self.request_timeout, call_timeout) if call_timeout else None
        try:
            conversation_id = self._conversation_id_for_call()
            baseline_count = 0
            if self.conversation_mode == CONVERSATION_MODE_REUSE:
                baseline_count = self.baseline_message_count(conversation_id)
            body = self.build_request_body(request, conversation_id)
            streamed = self.submit_turn(body)
            stream_error = _error_from_stream(streamed)
            if stream_error:
                raise DemistoException(f"Cohere North ended the turn with an error: {stream_error}")
            convo = self.poll_conversation(conversation_id, baseline_count)
            result = self.normalize_response(convo, conversation_id)
            if result["usage"].get("prompt_tokens") is None:
                result["usage"] = _usage_from_stream(streamed) or result["usage"]
            return result
        finally:
            self._call_deadline = None


def build_client(params: Dict[str, Any], verify: bool, proxy: bool) -> CohereNorthClient:
    endpoint = (params.get("endpoint_url") or "").strip()
    if not endpoint:
        raise DemistoException("Endpoint URL is required.")

    agent_id = (params.get("agent_id") or "").strip()
    if not agent_id:
        raise DemistoException("Agent ID is required.")

    conversation_mode = (params.get("conversation_mode") or DEFAULT_CONVERSATION_MODE).strip() or DEFAULT_CONVERSATION_MODE
    session_id = (params.get("session_id") or "").strip()
    if conversation_mode == CONVERSATION_MODE_REUSE and not session_id:
        raise DemistoException("Session ID is required when Conversation mode is 'reuse'.")

    # Bearer token: type-9 credentials param (preferred) or a plain type-4 encrypted field.
    bearer_token = _resolve_bearer_token(params)
    if not bearer_token:
        raise DemistoException("Bearer token is required.")

    model_label = (params.get("model") or DEFAULT_MODEL_LABEL).strip() or DEFAULT_MODEL_LABEL
    # An unrecognized value is normalized to "auto" (no size declared) rather than passed through verbatim.
    # This is a type-15 dropdown, so the platform itself should never deliver anything outside `options`,
    # but this client makes no assumption that it holds (e.g. a value set via raw REST/CI rather
    # than the UI).
    model_tier_raw = (params.get("model_tier") or DEFAULT_MODEL_TIER).strip().lower()
    model_tier = model_tier_raw if model_tier_raw in MODEL_TIER_CHOICES else DEFAULT_MODEL_TIER
    tool_format = (params.get("tool_format") or DEFAULT_TOOL_FORMAT).strip() or DEFAULT_TOOL_FORMAT

    timeout = arg_to_number(params.get("request_timeout")) or DEFAULT_TIMEOUT

    return CohereNorthClient(
        endpoint=endpoint,
        agent_id=agent_id,
        session_id=session_id,
        bearer_token=bearer_token,
        model_label=model_label,
        model_tier=model_tier,
        model_id=(params.get("model_id") or "").strip(),
        conversation_mode=conversation_mode,
        tool_format=tool_format,
        verify=verify,
        proxy=proxy,
        timeout=timeout,
    )


def _resolve_bearer_token(params: Dict[str, Any]) -> str:
    """Read the Bearer token from either the type-9 ``credentials`` object (password field) or the
    plain type-4 ``bearer_token`` field, whichever the operator populated."""
    credentials = params.get("credentials") or {}
    if isinstance(credentials, dict):
        password = credentials.get("password")
        if password:
            return str(password).strip()
    return (params.get("bearer_token") or "").strip()


""" COMMAND FUNCTIONS """


def test_module(client: CohereNorthClient) -> str:
    """Connectivity/auth test.

    reuse mode: a NON-INVASIVE read-only GET on the configured Session ID conversation — proves the
    endpoint is reachable, the bearer token is accepted, and the session id resolves, WITHOUT writing
    a ping turn into the operator's shared, pre-created production conversation.

    stateless mode: a throwaway one-turn round-trip on a fresh, isolated conversation id — also proves
    the model actually generates."""
    if client.conversation_mode == CONVERSATION_MODE_REUSE:
        if not client.session_id:
            raise DemistoException("Session ID is required to test in reuse mode.")
        client.probe_conversation(client.session_id)
        return "ok"

    result = client.chat_completion({"messages": [{"role": "user", "content": "ping"}]})
    if result.get("content_filter"):
        detail = (result.get("content_filter_detail") or {}).get("message")
        raise DemistoException(
            f"test-module completion was blocked by the provider's content filter ({detail})."
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


def guardian_llm_chat_command(client: CohereNorthClient, args: Dict[str, Any]) -> CommandResults:
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

    requested_model = (args.get("model") or "").strip()
    if requested_model and requested_model != client.model_label:
        raise DemistoException(
            f"{MODEL_SELECTION_UNSUPPORTED_PREFIX} this provider runs a fixed Cohere North agent; choose the model in "
            f"Cohere, not per call (asked for '{requested_model}', this instance reports '{client.model_label}')."
        )

    result = client.chat_completion(request, call_timeout=call_timeout)

    if result.get("content_filter"):
        detail = (result.get("content_filter_detail") or {}).get("message")
        readable_output = tableToMarkdown(
            "Guardian LLM Completion — BLOCKED BY CONTENT FILTER",
            {
                "Model": result.get("model"),
                "Model Size": result.get("model_tier"),
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
                "Model Size": result.get("model_tier"),
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


MODELS_PATHS = ("/api/v2/models", "/api/v1/models")
MODELS_PAGE_SIZE = 100
MODELS_MAX_PAGES = 5


def _model_entries(payload: Any) -> List[Any]:
    """The list of model entries in a models response, whichever wrapper the server uses."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("data", "models", "items", "results"):
            if isinstance(payload.get(key), list):
                return payload[key]
    return []


def _model_row(entry: Any) -> Optional[Dict[str, Any]]:
    """One normalized row from a models-list entry, or None when it names nothing.

    North's v2 entries carry ``id``, ``name``, ``display_name``, ``provider`` (``name`` and ``instance``),
    ``context_length``, ``max_tokens`` and ``supported_parameters``; v1 entries carry at least ``id``."""
    if isinstance(entry, str):
        entry = entry.strip()
        return _model_row({"id": entry}) if entry else None
    if not isinstance(entry, dict):
        return None
    model_id = next((str(entry[k]) for k in ("id", "model_id", "name", "model") if entry.get(k)), "")
    if not model_id:
        return None
    provider = entry.get("provider")
    provider_name = provider.get("name") if isinstance(provider, dict) else provider
    instance = provider.get("instance") if isinstance(provider, dict) else None
    supported = entry.get("supported_parameters") or entry.get("capabilities") or []
    if not isinstance(supported, list):
        supported = [supported]
    return {
        "id": model_id,
        "name": str(entry.get("name") or model_id),
        "display_name": str(entry.get("display_name") or entry.get("name") or model_id),
        "provider": str(provider_name or ""),
        "instance": str(instance or ""),
        "context_length": entry.get("context_length"),
        "max_tokens": entry.get("max_tokens"),
        "supported_parameters": [str(c) for c in supported],
        "default": bool(entry.get("default") or entry.get("is_default")),
    }


def _fetch_models(client: CohereNorthClient, path: str) -> List[Any]:
    """Every model entry at one path, following North's ``next_token`` paging (bounded)."""
    entries: List[Any] = []
    next_token = ""
    for _ in range(MODELS_MAX_PAGES):
        params: Dict[str, Any] = {"limit": MODELS_PAGE_SIZE} if path.endswith("/v2/models") else {}
        if next_token:
            params["next_token"] = next_token
        payload = client._http_request(
            method="GET",
            full_url=f"{client.endpoint}{path}",
            headers=client._auth_headers(),
            params=params or None,
            timeout=min(client.request_timeout, POLL_GET_TIMEOUT_CAP),
            ok_codes=(200,),
            resp_type="json",
        )
        entries.extend(_model_entries(payload))
        next_token = str(payload.get("next_token") or "") if isinstance(payload, dict) else ""
        if not next_token:
            break
    return entries


def guardian_cohere_list_models_command(client: CohereNorthClient, args: Dict[str, Any]) -> CommandResults:
    """List the models this Cohere North deployment offers, so a model name can be checked before it is configured.

    Read-only. Calls North's ``GET /api/v2/models`` (paged), and ``GET /api/v1/models`` when v2 is not there.
    """
    tried: List[str] = []
    entries: List[Any] = []
    found_path = ""
    for path in MODELS_PATHS:
        try:
            entries = _fetch_models(client, path)
            found_path = path
            break
        except DemistoException as exc:
            tried.append(f"{path}: {str(exc).splitlines()[0][:160]}")
    if not found_path:
        raise DemistoException(
            "This North endpoint did not answer a models request. Tried " + "; ".join(tried) + ". Read the model name "
            "from the North model picker instead and enter it as the instance's Model ID."
        )
    rows = [row for row in (_model_row(e) for e in entries) if row]
    if not rows:
        raise DemistoException(f"{found_path} answered, but it lists no models this user may use.")
    return CommandResults(
        outputs_prefix="GuardianCohere.Model",
        outputs_key_field="id",
        outputs=rows,
        readable_output=tableToMarkdown(
            f"Models available on this North endpoint ({found_path})",
            [
                {
                    "Name": r["name"],
                    "Id": r["id"],
                    "Display name": r["display_name"],
                    "Provider": r["provider"],
                    "Context": r["context_length"],
                    "Max output": r["max_tokens"],
                    "Supports": ", ".join(r["supported_parameters"]),
                }
                for r in rows
            ],
            headers=["Name", "Id", "Display name", "Provider", "Context", "Max output", "Supports"],
        ),
        raw_response=entries,
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
        client = build_client(params, verify=verify_certificate, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))
        elif command == "guardian-llm-chat":
            return_results(guardian_llm_chat_command(client, args))
        elif command == "guardian-cohere-list-models":
            return_results(guardian_cohere_list_models_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        if str(e).startswith(MODEL_ERROR_PREFIXES):
            return_error(str(e))  # the caller matches on the start of the text
        else:
            return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
