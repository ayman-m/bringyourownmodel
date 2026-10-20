Microsoft Foundry (Azure AI Foundry) provider integration for the Guardian model plane. Implements the same `guardian-llm-chat` command as every other Guardian provider and returns the canonical `Guardian.LLM.Completion` shape. Talks to a Foundry resource through its OpenAI-compatible v1 chat-completions API (`POST {resource}/openai/v1/chat/completions`), which serves OpenAI models and the other chat models deployed in the same resource. Authenticates with a resource key or a Microsoft Entra ID service principal (client secret or certificate).

## Configure Guardian Foundry in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Endpoint | The Foundry resource endpoint, e.g. https://&lt;resource&gt;.services.ai.azure.com. The project endpoint is also accepted. | True |
| Deployment name | The deployment name from Models + endpoints in the Foundry portal, sent as `model`. | True |
| Authentication | `api-key` (default), `bearer-key`, `entra-client-credentials` (client secret) or `entra-client-certificate` (certificate). | True |
| API key | The Foundry resource key. Required for api-key and bearer-key. | False |
| Tenant ID / Client ID / Client secret (Entra ID only) | Service principal for `entra-client-credentials` (the Tenant ID and Client ID are also used by `entra-client-certificate`). | False |
| Certificate and private key, PEM (Entra ID certificate only) | For `entra-client-certificate`: the certificate and its private key as PEM text, in one block. Stored encrypted. | False |
| Private key passphrase (Entra ID certificate only) | The private key's passphrase, when it is encrypted. Stored encrypted. | False |
| Certificate thumbprint (Entra ID certificate only) | SHA-1 thumbprint as the Azure portal shows it. Computed from the certificate when the PEM has one (a value here overrides it); required when the PEM holds only the private key. | False |
| Token scope (Entra ID only) | OAuth scope; default `https://ai.azure.com/.default`. | False |
| Model family | `auto` (default), `standard` or `reasoning`. Reasoning models take only the default temperature and use `max_completion_tokens`. | False |
| Parameters to omit | Comma-separated request parameters the deployment rejects. | False |
| Max output tokens | Optional cap on tokens generated per call. | False |
| API version (optional) | Sent as `api-version` when set. The v1 API needs none. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Entra ID certificate authentication

Use `entra-client-certificate` when the Entra ID app registration (enterprise application) signs in with a certificate instead of a secret.

1. Upload the **public** certificate to the app registration (**Certificates & secrets > Certificates**).
2. Give the app's service principal the **Cognitive Services OpenAI User** role (or the Foundry user role) on the Foundry resource.
3. In the instance, set Authentication to `entra-client-certificate`, fill in Tenant ID and Client ID, and paste the certificate and its private key as PEM into the **Certificate and private key** field (certificate first, then `-----BEGIN PRIVATE KEY-----`). Add the passphrase if the key is encrypted. Only the private key is needed if you also fill in the **Certificate thumbprint**.

Guardian signs a short-lived (10 minute) client assertion with the private key (RS256, header `x5t` set to the certificate's SHA-1 thumbprint) and exchanges it for an access token, which is cached until shortly before it expires. An RSA key is required. This integration runs in the `demisto/crypto` docker image, which provides the `cryptography` library used for the signature; a server without internet access must have that image available.

If the token request fails, **Test** shows what Entra ID answered. `AADSTS700027` means the certificate or assertion was not accepted (upload the public certificate, and check that the thumbprint matches it); `AADSTS700024` means the assertion was outside its valid time (check the clock of the server or engine, and the certificate's expiry); `AADSTS7000215` means a wrong client secret (secret authentication).

## Commands

### guardian-llm-chat

Identical to the other Guardian provider integrations; see `docs/GUARDIAN_LLM_CHAT_CONTRACT.md`.

## Status

The wire format follows Microsoft's published Foundry v1 API. The unit tests mock the HTTP layer; verify a new resource with **Test** and a short `!guardian-llm-chat user_message="hi"` before enabling it.
