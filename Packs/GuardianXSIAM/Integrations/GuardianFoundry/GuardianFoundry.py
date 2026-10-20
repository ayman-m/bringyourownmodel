"""GuardianFoundry — Microsoft Foundry (Azure AI Foundry) model-plane integration.

Implements the single ``guardian-llm-chat`` command of the Guardian model plane (see
``docs/GUARDIAN_LLM_CHAT_CONTRACT.md``) against a Microsoft Foundry resource, and returns the
canonical ``Guardian.LLM.Completion`` shape, so nothing else in the pack changes when this provider is
the enabled one.

Wire format: the Foundry / Azure OpenAI **v1** API, ``POST {resource}/openai/v1/chat/completions``. The
deployment name goes in the body's ``model`` field and no ``api-version`` is needed. One endpoint serves
OpenAI models (gpt-4.x, gpt-5.x, o-series) and the other chat-completions models deployed in the same
Foundry resource (DeepSeek, Grok, Llama, Mistral, ...), which is why the Foundry resource is the unit of
configuration here, not a model family.

Auth: a resource key (``api-key`` header, or ``Authorization: Bearer <key>``), or a Microsoft Entra ID
service principal (client-credentials grant; the access token is cached in the integration context). The
service principal authenticates with a client secret, or with a certificate: a JWT client assertion signed
(RS256) with the certificate's private key. ``cryptography`` is imported only on the certificate path.

Per-model parameter handling (what differs between deployments, and what Foundry rejects with HTTP 400):
  * reasoning models (o-series, gpt-5*) accept only the default ``temperature`` and take
    ``max_completion_tokens`` instead of ``max_tokens``; non-reasoning models reject ``reasoning_effort``;
  * ``tool_choice`` / ``parallel_tool_calls`` are rejected when no ``tools`` are sent;
  * any other parameter a given deployment refuses can be listed in the instance's "Parameters to omit".

All HTTP goes through ``BaseClient._http_request`` (proxy / verify / retry / backoff handled uniformly).
"""

import base64
import hashlib
import json
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DEFAULT_TIMEOUT = 120
DEFAULT_RETRIES = 3
RETRY_BACKOFF_FACTOR = 5
RETRYABLE_STATUS_CODES = [429]
CONTENT_FILTER_FINISH_REASON = "content_filter"

AUTH_API_KEY = "api-key"
AUTH_BEARER_KEY = "bearer-key"
AUTH_ENTRA = "entra-client-credentials"
AUTH_ENTRA_CERT = "entra-client-certificate"
ENTRA_AUTH_TYPES = (AUTH_ENTRA, AUTH_ENTRA_CERT)
DEFAULT_AUTH_TYPE = AUTH_API_KEY

FAMILY_AUTO = "auto"
FAMILY_STANDARD = "standard"
FAMILY_REASONING = "reasoning"
# Deployment names that look like OpenAI reasoning models: o1 / o3 / o4-mini ..., gpt-5, gpt-5-mini ...
REASONING_MODEL_RE = re.compile(r"^(o\d|gpt-5)", re.IGNORECASE)

ENTRA_AUTHORITY = "https://login.microsoftonline.com"
DEFAULT_ENTRA_SCOPE = "https://ai.azure.com/.default"
TOKEN_CACHE_KEY = "entra_token"
TOKEN_REFRESH_MARGIN_SECONDS = 300
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
CLIENT_ASSERTION_LIFETIME_SECONDS = 600

# test-module sends a tiny completion. A reasoning model can spend a very small budget entirely on
# reasoning (finish_reason "length", empty content) -- that is still a successful round trip.
TEST_MODULE_MAX_TOKENS = 16

""" ENDPOINT / ERROR HELPERS """


def normalize_endpoint(raw: str) -> str:
    """Turn what an operator pastes into the full chat-completions URL.

    Accepted: the resource endpoint (``https://<r>.services.ai.azure.com`` or ``https://<r>.openai.azure.com``),
    the Foundry *project* endpoint (``https://<r>.services.ai.azure.com/api/projects/<p>`` -- the project path
    is dropped, inference is served at the resource), an ``.../openai/v1`` base, or a full
    ``.../chat/completions`` URL (used as given, the escape hatch for endpoints with a different path).
    """
    url = (raw or "").strip().rstrip("/")
    if not url:
        raise DemistoException("Endpoint is required.")
    if not re.match(r"^https?://", url, re.IGNORECASE):
        raise DemistoException(f"Endpoint must start with https:// (got: {url!r}).")
    if url.lower().endswith("/chat/completions"):
        return url
    project_at = url.lower().find("/api/projects")
    if project_at != -1:
        url = url[:project_at]
    if url.lower().endswith("/openai/v1"):
        return f"{url}/chat/completions"
    if url.lower().endswith("/openai"):
        return f"{url}/v1/chat/completions"
    return f"{url}/openai/v1/chat/completions"


def _status_code_of(exc: "DemistoException") -> Optional[int]:
    res = getattr(exc, "res", None)
    return getattr(res, "status_code", None) if res is not None else None


def _extract_error_body(exc: "DemistoException") -> Optional[Dict[str, Any]]:
    """Best-effort parsed JSON error body of a DemistoException raised by _http_request, else None."""
    res = getattr(exc, "res", None)
    if res is None:
        return None
    try:
        body = res.json()
    except Exception:
        return None
    return body if isinstance(body, dict) else None


def _error_hint(status_code: Optional[int]) -> Optional[str]:
    if status_code == 401:
        return (
            "Authentication failed (HTTP 401): check the API key, or the Entra tenant / client id and "
            "client secret or certificate."
        )
    if status_code == 403:
        return (
            "Access denied (HTTP 403): the key or service principal lacks access to this resource "
            "(Entra ID needs the 'Cognitive Services OpenAI User' or 'Foundry User' role), or a network "
            "rule on the resource blocks this caller."
        )
    if status_code == 404:
        return (
            "Not found (HTTP 404): check the endpoint and the deployment name. The deployment name is the one "
            "shown under Models + endpoints in the Foundry portal, not necessarily the model name."
        )
    return None


_AADSTS_RE = re.compile(r"AADSTS(\d+)")

#: Entra ID token-endpoint failures that have one usual cause, keyed by the AADSTS code.
ENTRA_ERROR_HELP = {
    "700027": (
        "Entra ID did not accept the certificate assertion. Check that the PUBLIC certificate is uploaded to the app "
        "registration (Certificates & secrets), that the thumbprint matches that certificate (enter it in the "
        "thumbprint field if you gave only a private key), and that the Tenant ID and Client ID are those of the "
        "app registration."
    ),
    "700024": (
        "The signed assertion was outside its valid time range, or the certificate has expired. Check that the clock "
        "of the Cortex server or engine is in sync (NTP), and that the certificate has not expired."
    ),
    "7000215": (
        "Entra ID rejected the client secret. Use the secret's Value (not its Secret ID), check that it has not "
        "expired, and that it belongs to this app registration."
    ),
}


def _entra_failure_message(exc: "DemistoException") -> str:
    """Readable text for a failed Entra ID token request; the common AADSTS codes get a plain explanation."""
    body = _extract_error_body(exc) or {}
    detail = str(body.get("error_description") or body.get("error") or exc.message)
    match = _AADSTS_RE.search(detail)
    help_text = ENTRA_ERROR_HELP.get(match.group(1)) if match else None
    if help_text:
        first_line = (detail.strip().splitlines() or [""])[0]
        return f"Entra ID token request failed (AADSTS{match.group(1)}): {help_text} Entra ID said: {first_line}"
    return f"Entra ID token request failed: {detail}"


""" ENTRA ID CERTIFICATE AUTHENTICATION (signed client assertion) """

_PEM_BLOCK_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _pem_blocks(text: str) -> List[Tuple[str, str]]:
    """``(label, pem)`` for every PEM block in ``text``. Tolerates what a pasted secret often turns into: literal ``\\n``
    sequences, or line breaks collapsed to spaces (the block is re-wrapped at 64 characters)."""
    text = (text or "").replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r", "")
    blocks = []
    for label, body in _PEM_BLOCK_RE.findall(text):
        if ":" in body:  # a legacy encrypted PEM has header lines (Proc-Type, DEK-Info); keep them as they are
            lines = body.strip("\n")
        else:
            data = re.sub(r"\s+", "", body)
            lines = "\n".join(data[i : i + 64] for i in range(0, len(data), 64))
        blocks.append((label, f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n"))
    return blocks


def _parse_thumbprint(raw: Optional[str]) -> Optional[bytes]:
    """The SHA-1 thumbprint as the Azure portal shows it (40 hex digits; colons and spaces are ignored) as 20 bytes."""
    cleaned = re.sub(r"[\s:\-]", "", raw or "")
    if not cleaned:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]{40}", cleaned):
        raise DemistoException(
            "The certificate thumbprint must be 40 hexadecimal characters (the SHA-1 thumbprint shown for the "
            "certificate in the Azure portal)."
        )
    return bytes.fromhex(cleaned)


def _import_cryptography():
    """``cryptography`` is imported only for certificate authentication, so no other auth type depends on it."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError:
        raise DemistoException(
            "Certificate authentication needs the 'cryptography' library, which the demisto/crypto docker image "
            "provides. Check that this integration runs in that image (its Docker image setting) and that the server "
            "has pulled it."
        )
    return x509, hashes, serialization, padding, rsa


def _load_signing_material(pem_text: str, passphrase: str, thumbprint: str):
    """``(private_key, sha1_thumbprint, sha256_thumbprint_or_None)`` from the PEM (certificate and/or private key).

    The thumbprint is computed from the certificate when the PEM has one; an explicit thumbprint overrides it, and is
    required when the PEM holds only the private key."""
    x509, hashes, serialization, _padding, rsa = _import_cryptography()
    blocks = _pem_blocks(pem_text)
    key_pems = [pem for label, pem in blocks if label.endswith("PRIVATE KEY")]
    if not key_pems:
        raise DemistoException(
            "No private key found in the certificate PEM. Paste the certificate and its private key, both as PEM "
            "(-----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----)."
        )

    def load_key(password: Optional[bytes]):
        try:
            return serialization.load_pem_private_key(key_pems[0].encode("ascii"), password)
        except TypeError:
            if password is None:
                raise DemistoException("The private key is encrypted: enter its passphrase.")
            return load_key(None)  # a passphrase was given for a key that is not encrypted: ignore it
        except Exception:
            raise DemistoException(
                "The private key could not be read. Check the passphrase, and that the PEM is complete."
            )

    key = load_key(passphrase.encode("utf-8") if passphrase else None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise DemistoException("Certificate authentication signs with RS256 and needs an RSA private key.")

    def public_der(public_key) -> bytes:
        return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    certificates = []
    for label, pem in blocks:
        if label == "CERTIFICATE":
            try:
                certificates.append(x509.load_pem_x509_certificate(pem.encode("ascii")))
            except Exception:
                raise DemistoException("The certificate in the PEM could not be read.")
    certificate_der = None
    if certificates:
        key_der = public_der(key.public_key())
        matching = [c for c in certificates if public_der(c.public_key()) == key_der]
        if not matching:
            raise DemistoException("The certificate in the PEM does not belong to the private key.")
        certificate_der = matching[0].public_bytes(serialization.Encoding.DER)

    sha1 = _parse_thumbprint(thumbprint)
    if sha1 is None:
        if certificate_der is None:
            raise DemistoException(
                "The PEM has no certificate, so the thumbprint cannot be computed. Enter the certificate thumbprint "
                "(SHA-1, as the Azure portal shows it)."
            )
        sha1 = hashlib.sha1(certificate_der, usedforsecurity=False).digest()  # nosec: an identifier, not a security hash
    sha256 = hashlib.sha256(certificate_der).digest() if certificate_der is not None else None
    return key, sha1, sha256


def build_client_assertion(
    tenant_id: str, client_id: str, pem_text: str, passphrase: str = "", thumbprint: str = ""
) -> str:
    """A signed (RS256) JWT client assertion for the Entra ID client-credentials grant with a certificate.

    Header ``x5t`` is the base64url of the certificate's SHA-1 (``x5t#S256`` is added when the PEM has the
    certificate); claims ``aud`` (the token endpoint), ``iss``/``sub`` (the client id), a fresh ``jti`` and
    ``nbf``/``iat``/``exp`` (valid for 10 minutes)."""
    _x509, hashes, _serialization, padding, _rsa = _import_cryptography()
    key, sha1, sha256 = _load_signing_material(pem_text, passphrase, thumbprint)
    now = int(time.time())
    header: Dict[str, Any] = {"alg": "RS256", "typ": "JWT", "x5t": _b64url(sha1)}
    if sha256 is not None:
        header["x5t#S256"] = _b64url(sha256)
    claims = {
        "aud": f"{ENTRA_AUTHORITY}/{tenant_id}/oauth2/v2.0/token",
        "iss": client_id,
        "sub": client_id,
        "jti": str(uuid.uuid4()),
        "nbf": now,
        "iat": now,
        "exp": now + CLIENT_ASSERTION_LIFETIME_SECONDS,
    }
    signing_input = ".".join(_b64url(json.dumps(part, separators=(",", ":")).encode("utf-8")) for part in (header, claims))
    signature = key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{_b64url(signature)}"


""" ARGUMENT HELPERS (identical contract handling to the other Guardian provider integrations) """


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


def _arg_to_call_timeout(args: Dict[str, Any]) -> Optional[float]:
    """The contract's optional per-call ``timeout`` (seconds): a hard wall-clock bound for this one
    call, capped by the instance's own request timeout. ``None`` when unset."""
    value = _arg_to_float(args, "timeout")
    if value is not None and value <= 0:
        raise DemistoException(f'"timeout" must be a positive number of seconds, got: {value!r}')
    return value


""" ADAPTER """



#: gpt-oss models can answer with their native "harmony" tool-call text instead of a tool_calls entry, for example
#: ``<|start|>assistant<|channel|>commentary to=functions.ip <|constrain|>json<|message|>{"value": "1.2.3.4"}<|call|>``.
#: Without a recovery the loop sees an empty turn and ends with no verdict.
_HARMONY_CALL_RE = re.compile(
    r"to=functions\.([A-Za-z0-9_.\-]+)[^{<]*(?:<\|constrain\|>[a-z]+)?<\|message\|>(\{.*?\})\s*<\|call\|>", re.DOTALL
)


def recover_harmony_tool_call(content: Any) -> Tuple[Any, List[Dict[str, Any]]]:
    """Return ``(content, tool_calls)``: a harmony-format call found in text becomes one tool call, and the text is cleared."""
    if not isinstance(content, str) or "<|call|>" not in content:
        return content, []
    match = _HARMONY_CALL_RE.search(content)
    if not match:
        return content, []
    try:
        arguments = json.loads(match.group(2))
    except ValueError:
        return content, []
    call = {
        "id": "call_harmony_%d" % (abs(hash(match.group(0))) % 10**10),
        "type": "function",
        "function": {"name": match.group(1), "arguments": json.dumps(arguments)},
    }
    return "", [call]

class FoundryAdapter:
    """URL, auth, request-body and response translation for one Foundry deployment."""

    def __init__(
        self,
        endpoint: str,
        model: str,
        auth_type: str = DEFAULT_AUTH_TYPE,
        api_key: str = "",
        entra_tenant_id: str = "",
        entra_client_id: str = "",
        entra_client_secret: str = "",
        entra_scope: str = DEFAULT_ENTRA_SCOPE,
        entra_certificate_pem: str = "",
        entra_certificate_passphrase: str = "",
        entra_certificate_thumbprint: str = "",
        model_family: str = FAMILY_AUTO,
        omit_params: Optional[List[str]] = None,
        max_output_tokens: Optional[int] = None,
        api_version: Optional[str] = None,
    ) -> None:
        self.url = normalize_endpoint(endpoint)
        self.model = model
        self.auth_type = auth_type or DEFAULT_AUTH_TYPE
        self.api_key = api_key or ""
        self.entra_tenant_id = entra_tenant_id
        self.entra_client_id = entra_client_id
        self.entra_client_secret = entra_client_secret
        self.entra_scope = entra_scope or DEFAULT_ENTRA_SCOPE
        self.entra_certificate_pem = entra_certificate_pem or ""
        self.entra_certificate_passphrase = entra_certificate_passphrase or ""
        self.entra_certificate_thumbprint = entra_certificate_thumbprint or ""
        self.model_family = model_family or FAMILY_AUTO
        self.omit_params = {p for p in (omit_params or []) if p}
        self.max_output_tokens = max_output_tokens
        self.api_version = api_version or None

    @property
    def is_reasoning(self) -> bool:
        if self.model_family == FAMILY_REASONING:
            return True
        if self.model_family == FAMILY_STANDARD:
            return False
        return bool(REASONING_MODEL_RE.match(self.model or ""))

    def build_params(self) -> Optional[Dict[str, str]]:
        return {"api-version": self.api_version} if self.api_version else None

    def build_headers(self, token: Optional[str] = None) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.auth_type in ENTRA_AUTH_TYPES:
            headers["Authorization"] = f"Bearer {token or ''}"
        elif self.auth_type == AUTH_BEARER_KEY:
            headers["Authorization"] = f"Bearer {self.api_key}"
        else:
            headers["api-key"] = self.api_key
        return headers

    def build_request_body(self, request: Dict[str, Any]) -> Dict[str, Any]:
        body = {k: v for k, v in request.items() if v is not None}
        body["model"] = self.model
        reasoning = self.is_reasoning

        if reasoning:
            body.pop("temperature", None)  # only the default is accepted
        else:
            body.pop("reasoning_effort", None)  # rejected by non-reasoning deployments
        if not body.get("tools"):
            body.pop("tools", None)
            body.pop("tool_choice", None)
            body.pop("parallel_tool_calls", None)

        if self.max_output_tokens and "max_tokens" not in body and "max_completion_tokens" not in body:
            body["max_tokens"] = self.max_output_tokens
        if reasoning and "max_tokens" in body:
            body["max_completion_tokens"] = body.pop("max_tokens")

        for name in self.omit_params:
            body.pop(name, None)
        return body

    def handle_input_content_filter(self, exc: "DemistoException") -> Optional[Dict[str, Any]]:
        """A prompt rejected pre-generation is an HTTP 400 whose error.code / error.innererror.code is
        ``content_filter`` or ``ResponsibleAIPolicyViolation``; return it as a structured result, not an error."""
        if _status_code_of(exc) != 400:
            return None
        body = _extract_error_body(exc)
        if body is None:
            return None
        error = body.get("error") or {}
        if not isinstance(error, dict):
            return None
        inner = error.get("innererror") or {}
        codes = [str(error.get("code") or "").lower(), str((inner or {}).get("code") or "").lower()]
        if not any("content_filter" in c or "responsibleaipolicyviolation" in c for c in codes):
            return None
        message = error.get("message") or "Request blocked by the Foundry content filter."
        return self.empty_content_filter_result(message, raw_error=body)

    def empty_content_filter_result(self, message: str, raw_error: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "id": None,
            "model": self.model,
            "created": None,
            "choices": [],
            "finish_reason": CONTENT_FILTER_FINISH_REASON,
            "content_filter": True,
            "content_filter_detail": {"message": message, "raw_error": raw_error},
            "usage": {"prompt_tokens": None, "completion_tokens": None, "total_tokens": None, "cached_tokens": None},
        }

    @staticmethod
    def _content_text(content: Any) -> Any:
        """Some deployments return ``content`` as a list of parts; the contract carries plain text."""
        if isinstance(content, list):
            return "".join(
                part.get("text", "") if isinstance(part, dict) else str(part) for part in content
            )
        return content

    @staticmethod
    def _tool_calls(tool_calls: Any) -> Any:
        """Tool-call ``arguments`` must be a JSON string in the contract; a few deployments return an object."""
        if not isinstance(tool_calls, list):
            return tool_calls
        fixed = []
        for call in tool_calls:
            if isinstance(call, dict) and isinstance(call.get("function"), dict):
                function = dict(call["function"])
                if not isinstance(function.get("arguments"), str):
                    function["arguments"] = json.dumps(function.get("arguments") or {})
                call = {**call, "function": function}
            fixed.append(call)
        return fixed

    def normalize_response(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        choices: List[Dict[str, Any]] = []
        content_filter_flag = False
        content_filter_detail: Optional[Dict[str, Any]] = None
        top_finish_reason: Optional[str] = None

        for choice in raw.get("choices") or []:
            message = choice.get("message") or {}
            finish_reason = choice.get("finish_reason")
            if finish_reason == CONTENT_FILTER_FINISH_REASON:
                content_filter_flag = True
                if content_filter_detail is None and choice.get("content_filter_results"):
                    content_filter_detail = {
                        "message": "The completion was cut by the Foundry content filter.",
                        "content_filter_results": choice.get("content_filter_results"),
                    }
            text = self._content_text(message.get("content"))
            calls = self._tool_calls(message.get("tool_calls"))
            if not calls:
                text, recovered = recover_harmony_tool_call(text)
                calls = recovered or calls
            choices.append(
                {
                    "index": choice.get("index"),
                    "message": {
                        "role": message.get("role"),
                        "content": text,
                        "tool_calls": calls,
                    },
                    "finish_reason": finish_reason,
                }
            )
            if top_finish_reason is None:
                top_finish_reason = finish_reason

        if not choices:
            # A prompt blocked by an asynchronous filter can come back as 200 with no choices.
            for result in raw.get("prompt_filter_results") or []:
                filters = (result or {}).get("content_filter_results") or {}
                if any(isinstance(v, dict) and v.get("filtered") for v in filters.values()):
                    return self.empty_content_filter_result(
                        "The prompt was blocked by the Foundry content filter.",
                        raw_error={"prompt_filter_results": raw.get("prompt_filter_results")},
                    )

        usage_raw = raw.get("usage") or {}
        prompt_details = usage_raw.get("prompt_tokens_details")
        cached_tokens = prompt_details.get("cached_tokens") if isinstance(prompt_details, dict) else None

        return {
            "id": raw.get("id"),
            "model": raw.get("model") or self.model,
            "created": raw.get("created"),
            "choices": choices,
            "finish_reason": top_finish_reason,
            "content_filter": content_filter_flag,
            "content_filter_detail": content_filter_detail,
            "usage": {
                "prompt_tokens": usage_raw.get("prompt_tokens"),
                "completion_tokens": usage_raw.get("completion_tokens"),
                "total_tokens": usage_raw.get("total_tokens"),
                "cached_tokens": cached_tokens,
            },
        }


""" CLIENT CLASS """


class Client(BaseClient):
    """Thin BaseClient wrapper around the adapter; all HTTP goes through ``_http_request``."""

    def __init__(self, adapter: FoundryAdapter, verify: bool, proxy: bool, timeout: int = DEFAULT_TIMEOUT):
        super().__init__(base_url=adapter.url, verify=verify, proxy=proxy, timeout=timeout)
        self.adapter = adapter

    def _entra_token(self, call_timeout: Optional[float] = None) -> str:
        """Client-credentials access token, cached in the integration context until shortly before expiry.

        The service principal proves itself with its client secret, or (``entra-client-certificate``) with a JWT
        assertion signed by its certificate's private key. A cached token made for a different auth type, tenant or
        client id is not reused (an entry saved before this marker existed is)."""
        adapter = self.adapter
        identity = f"{adapter.auth_type}|{adapter.entra_tenant_id}|{adapter.entra_client_id}"
        cached = (demisto.getIntegrationContext() or {}).get(TOKEN_CACHE_KEY) or {}
        if (
            cached.get("access_token")
            and cached.get("identity", identity) == identity
            and float(cached.get("expires_at") or 0) - TOKEN_REFRESH_MARGIN_SECONDS > time.time()
        ):
            return cached["access_token"]

        if adapter.auth_type == AUTH_ENTRA_CERT:
            if not (adapter.entra_tenant_id and adapter.entra_client_id):
                raise DemistoException("Tenant ID and Client ID are required for Entra ID certificate authentication.")
            if not adapter.entra_certificate_pem.strip():
                raise DemistoException("The certificate and private key (PEM) are required for Entra ID certificate authentication.")
            credential_fields = {
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": build_client_assertion(
                    adapter.entra_tenant_id,
                    adapter.entra_client_id,
                    adapter.entra_certificate_pem,
                    adapter.entra_certificate_passphrase,
                    adapter.entra_certificate_thumbprint,
                ),
            }
        else:
            if not (adapter.entra_tenant_id and adapter.entra_client_id and adapter.entra_client_secret):
                raise DemistoException("Tenant ID, Client ID and Client secret are required for Entra ID authentication.")
            credential_fields = {"client_secret": adapter.entra_client_secret}
        try:
            response = self._http_request(
                method="POST",
                full_url=f"{ENTRA_AUTHORITY}/{adapter.entra_tenant_id}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": adapter.entra_client_id,
                    **credential_fields,
                    "scope": adapter.entra_scope,
                },
                timeout=min(self.timeout, call_timeout) if call_timeout else self.timeout,
                ok_codes=(200,),
                retries=0,
            )
        except DemistoException as exc:
            raise DemistoException(_entra_failure_message(exc), exception=exc)

        token = response.get("access_token")
        if not token:
            raise DemistoException("Entra ID token response had no access_token.")
        expires_at = time.time() + float(response.get("expires_in") or 3600)
        demisto.setIntegrationContext({TOKEN_CACHE_KEY: {"access_token": token, "expires_at": expires_at, "identity": identity}})
        return token

    def chat_completion(self, request: Dict[str, Any], call_timeout: Optional[float] = None) -> Dict[str, Any]:
        """One chat-completion round trip, returned as the canonical Guardian.LLM.Completion dict.

        ``call_timeout`` (the contract's per-call ``timeout``) makes this a hard wall-clock bound: one attempt,
        no transparent retries. 429s are otherwise retried with backoff; a content-filter rejection is returned
        as a structured result, not raised.
        """
        adapter = self.adapter
        token = self._entra_token(call_timeout) if adapter.auth_type in ENTRA_AUTH_TYPES else None
        body = adapter.build_request_body(request)
        try:
            raw_response = self._http_request(
                method="POST",
                full_url=adapter.url,
                params=adapter.build_params(),
                headers=adapter.build_headers(token),
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
            status_code = _status_code_of(exc)
            if status_code == 429:
                raise DemistoException(
                    "Guardian LLM provider rate-limited the request (HTTP 429) and the configured retries were "
                    f"exhausted. Check the deployment's tokens-per-minute quota. Original error: {exc.message}",
                    exception=exc,
                )
            hint = _error_hint(status_code)
            if hint:
                raise DemistoException(f"{hint} Original error: {exc.message}", exception=exc)
            raise

        return adapter.normalize_response(raw_response)


#: The "Model" dropdown's first option: use the free-text deployment name instead of a named model.
MODEL_CHOICE_CUSTOM = "Custom (use the deployment name below)"


def resolve_model(params: Dict[str, Any]) -> str:
    """The deployment name to send: the "Model" dropdown choice, or (for "Custom", and for instances saved before
    the dropdown existed) the free-text deployment name."""
    choice = (params.get("model_choice") or "").strip()
    if choice and choice != MODEL_CHOICE_CUSTOM:
        return choice
    return (params.get("model") or "").strip()


def build_adapter(params: Dict[str, Any]) -> FoundryAdapter:
    model = resolve_model(params)
    if not model:
        raise DemistoException('Pick a model in the "Model" dropdown, or choose Custom and enter a deployment name.')

    credentials = params.get("api_key") or ""
    if isinstance(credentials, dict):  # a type-9 credentials param; type 4 arrives as a plain string
        credentials = credentials.get("password") or ""
    secret = params.get("entra_client_secret") or ""
    if isinstance(secret, dict):
        secret = secret.get("password") or ""
    certificate_pem = params.get("entra_certificate_pem") or ""  # type 14 (encrypted text area) arrives as a string
    if isinstance(certificate_pem, dict):
        certificate_pem = certificate_pem.get("password") or ""
    certificate_passphrase = params.get("entra_certificate_passphrase") or ""
    if isinstance(certificate_passphrase, dict):
        certificate_passphrase = certificate_passphrase.get("password") or ""

    auth_type = params.get("auth_type") or DEFAULT_AUTH_TYPE
    if auth_type in (AUTH_API_KEY, AUTH_BEARER_KEY) and not credentials:
        raise DemistoException("API key is required for this authentication type.")

    max_output_tokens = None
    if params.get("max_output_tokens") not in (None, ""):
        try:
            max_output_tokens = int(params["max_output_tokens"])
        except (TypeError, ValueError):
            raise DemistoException(f'"Max output tokens" must be a whole number, got: {params["max_output_tokens"]!r}')
        if max_output_tokens <= 0:
            raise DemistoException('"Max output tokens" must be positive.')

    return FoundryAdapter(
        endpoint=params.get("endpoint") or "",
        model=model,
        auth_type=auth_type,
        api_key=credentials,
        entra_tenant_id=(params.get("entra_tenant_id") or "").strip(),
        entra_client_id=(params.get("entra_client_id") or "").strip(),
        entra_client_secret=secret,
        entra_scope=(params.get("entra_scope") or DEFAULT_ENTRA_SCOPE).strip(),
        entra_certificate_pem=certificate_pem,
        entra_certificate_passphrase=certificate_passphrase,
        entra_certificate_thumbprint=(params.get("entra_certificate_thumbprint") or "").strip(),
        model_family=params.get("model_family") or FAMILY_AUTO,
        omit_params=argToList(params.get("omit_params")),
        max_output_tokens=max_output_tokens,
        api_version=(params.get("api_version") or "").strip() or None,
    )


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Minimal completion proving the endpoint, deployment name and credentials work."""
    result = client.chat_completion(
        {
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": TEST_MODULE_MAX_TOKENS,
        }
    )
    if result.get("content_filter"):
        detail = (result.get("content_filter_detail") or {}).get("message")
        raise DemistoException(
            f"test-module completion was blocked by the Foundry content filter ({detail}). "
            "Check the configured deployment."
        )
    return "ok"


def _resolve_messages(args: Dict[str, Any]) -> list:
    """The effective messages array: ``messages`` (every production caller), or ``user_message`` with an optional
    ``system_message`` (a one-turn convenience for the Playground). Giving both shapes is rejected."""
    messages = _parse_json_arg(args, "messages", expected_types=(list,), required=False)
    system_message = args.get("system_message") or None
    user_message = args.get("user_message") or None

    if messages is not None and (system_message or user_message):
        raise DemistoException('Provide either "messages", or "system_message"/"user_message" -- not both.')
    if messages is not None:
        return messages
    if not user_message:
        raise DemistoException(
            'Provide "messages" (a JSON array), or "user_message" (optionally with "system_message").'
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

    result = client.chat_completion(request, call_timeout=call_timeout)

    if result.get("content_filter"):
        detail = (result.get("content_filter_detail") or {}).get("message")
        readable_output = tableToMarkdown(
            "Guardian LLM Completion — BLOCKED BY CONTENT FILTER",
            {"Model": result.get("model"), "Finish Reason": result.get("finish_reason"), "Detail": detail},
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
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
