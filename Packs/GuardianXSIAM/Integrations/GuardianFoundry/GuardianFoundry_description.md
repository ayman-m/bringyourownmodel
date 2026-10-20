## Guardian Foundry Help

Guardian Foundry is a **model-plane provider** for the Guardian agent, backed by a **Microsoft Foundry**
(Azure AI Foundry) resource. Like every Guardian provider it implements the single `guardian-llm-chat`
command and returns the canonical `Guardian.LLM.Completion` shape, so the rest of the Guardian pack does not
change when you switch to it. Enable **exactly one** Guardian provider integration at a time.

### Get the values you need (Foundry portal, ai.azure.com)

1. Create a Foundry project (or open an existing one) and deploy a chat model under **Discover > Models >
   Deploy**. Note the **deployment name** you chose.
2. **Endpoint**: the resource endpoint `https://<resource>.services.ai.azure.com`. The project endpoint shown
   on the project's welcome page (`.../api/projects/<project>`) also works.
3. **API key**: in the Azure portal, open the Foundry resource and go to **Resource Management > Keys and
   Endpoint**, then copy KEY 1. (If the portal shows key access as disabled, use Entra ID below.)

### Instance settings

- **Endpoint** and **Deployment name**: as above. The deployment name is sent as the request's `model`.
- **Authentication**: `api-key` (default), `bearer-key`, `entra-client-credentials` or `entra-client-certificate`.
  For Entra ID, register an app, give its service principal the **Cognitive Services OpenAI User** (or **Foundry
  User**) role on the resource, and fill in Tenant ID, Client ID and Client secret. The token is requested and
  cached for you.
- **Entra ID with a certificate** (`entra-client-certificate`): upload the **public** certificate to the app
  registration (**Certificates & secrets**), then paste the certificate and its private key as PEM into
  **Certificate and private key**. Add the **passphrase** if the key is encrypted. The thumbprint is computed from
  the certificate; fill in **Certificate thumbprint** (SHA-1, as the Azure portal shows it) to override it, or when
  you give only the private key. The integration signs a short-lived assertion with the key (RS256) and exchanges
  it for a token. It runs in the `demisto/crypto` docker image, which a server without internet access must have.
- **Model family**: leave on `auto`. Reasoning models (o-series, gpt-5) only accept the default temperature and
  use `max_completion_tokens`; `auto` recognises them by deployment name, so set it explicitly if your
  deployment is named something else.
- **Parameters to omit**: if a deployment answers HTTP 400 naming a parameter it does not support (for example
  `response_format` or `parallel_tool_calls` on some open models), list it here.

Click **Test** to run a 1-token completion. A 401 means the key or Entra credentials are wrong, a 403 means no
access to the resource, a 404 means the endpoint or deployment name is wrong.

The same endpoint serves OpenAI models and the other chat models deployed in the resource (DeepSeek, Grok, Llama,
Mistral and others), so switching models is a change of **Deployment name** only. After switching, run
`!guardian-probe-model`. The model size is taken from the model catalogue; set it in `guardian_settings` only for a model that is not in it (see the operator runbook).
