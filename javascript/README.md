# External Phone Provider — Azure Function (delivery endpoint)

An Azure Function (Node.js) that receives an OTP dispatch request and forwards it to a telephony
provider (**Infobip**, **Telesign**, **Sinch**, or **Soprano**).

## What it does

- `POST /api/SendOtp` — dispatches the OTP to the selected provider and returns an accepted/failed result.
- Provider secrets from **Azure Key Vault** (managed identity).
- **Correlation id** propagated to the provider and echoed back.
- **Shutter mode** — process the full path but do not send.
- **Optional token validation** — off by default; enable with `REQUIRE_AUTH=true`.

> Token validation exists but is **off by default** — enable it in any real deployment (`REQUIRE_AUTH=true`).

## Deploy

1. **Create the Key Vault** and add what the Function reads:
   - the provider **API key/token** as a **secret** (default name `infobip-api-key` — see [Configuration](#configuration)).
2. **Grant the Function's managed identity** on that vault: **Key Vault Secrets User**.
3. **Set the app settings** — copy [`../docs/local.settings.sample.json`](../docs/local.settings.sample.json) into `src/local.settings.json` locally; in Azure set them under **Function App → Settings → Environment variables**. At minimum set `KEY_VAULT_URL` and `DEFAULT_PROVIDER`; see [Configuration](#configuration) for the full list.
4. **Publish:**

```bash
cd src
npm install
func azure functionapp publish <your-function-app-name>
```

## Configuration

The endpoint is **plug-and-play by provider**. The **shared infrastructure** — token validation, dispatch,
response normalization, message templating, and
logging — is identical for every provider and needs no per-provider code. You **choose one provider**;
the only provider-specific parts are its **adapter** (the outbound API call) and the **few settings** below.

> A new provider is onboarded by dropping in a single file `providers/<id>.js` that exports its
> `manifest` (built-in defaults: endpoints, channels, auth, responseMapping) plus `buildRequest` /
> `parseResponse` — no change to the shared pipeline.

> **Provisioning model.** The provider's authoritative parameters live in its **Security Store package
> manifest**. At provisioning time, UX reads that manifest and sets the operational values as **app
> settings (env properties)** on the Function — endpoint URLs (`<ID>_ENDPOINT`, `EUDB`), sender/source
> IDs, `ENDPOINT_TIMEOUT_MS`, and the Key Vault secret references. The values baked
> into `providers/<id>.js` are just **local-dev defaults**; the app settings win. Only the **adapter
> code** (`buildRequest`/`parseResponse`) is provider-specific code — everything else is data.

Provider secrets are read from **Key Vault** by name via the Function's managed identity. Set
`KEY_VAULT_URL` to the vault URI. Each provider's secret name is fixed in its manifest
(`infobip-api-key` / `telesign-api-key` / `sinch-api-token` / `soprano-api-key`); the value lives in
Key Vault and can be rotated there without a redeploy.

### Shared settings (always)

| Key | Purpose |
|-----|---------|
| `DEFAULT_PROVIDER` | your chosen provider: `infobip` \| `telesign` \| `sinch` \| `soprano` |
| `KEY_VAULT_URL` | Key Vault URI (required) |
| `EUDB` | `true` for an EU Data Boundary deployment — uses each provider's EU endpoint URL (optional) |
| `ENDPOINT_TIMEOUT_MS` | outbound provider-call timeout in ms (default `1500`) |
| `REQUIRE_AUTH` | `true` to enforce token validation — enable in any real deployment |
| `EXPECTED_AUDIENCE` | token `aud` (this endpoint's app registration appId) — required when `REQUIRE_AUTH=true` |
| `ISSUER_TENANT_ID` | customer tenant id for issuer/JWKS — required when `REQUIRE_AUTH=true` |

### Per-provider settings (set only for the provider you chose)

Set `DEFAULT_PROVIDER` to your provider, then provision **only that block** — its **Key Vault secret**
(the API key/token — the *only* secret) plus its **non-secret app settings**: the endpoint
(`<PROVIDER>_ENDPOINT` / `_EUDB`), sender/source id, etc. Endpoints, sender ids, `KEY_VAULT_URL`, and the
Key Vault secret **names** are all non-secret configuration; only the key/token **value** lives in Key Vault.

**Infobip**
| Setting | Purpose |
|---------|---------|
| Key Vault secret `infobip-api-key` | API key |
| `INFOBIP_SENDER_ID` | registered sender, app setting (default `Verify`) |
| `INFOBIP_VOICE_FROM` | voice caller id, app setting (optional; falls back to `INFOBIP_SENDER_ID`) |

**Telesign**
| Setting | Purpose |
|---------|---------|
| Key Vault secret `telesign-api-key` | API key |
| Key Vault secret `telesign-customer-id` | customer id (the Basic-auth username) |
| `TELESIGN_SENDER_ID` | sender id, app setting (optional) |
| `TELESIGN_VOICE` | voice language/voice code for voice OTP, app setting (optional; default `f-en-US`) |

**Sinch**
| Setting | Purpose |
|---------|---------|
| Key Vault secret `sinch-api-token` | API token |
| `SINCH_SERVICE_PLAN_ID` | XMS service plan id, app setting |
| `SINCH_SENDER_ID` | sender, app setting (default `Verify`) |
| `SINCH_VOICE_ENDPOINT` | Sinch Voice API host, app setting (optional; default `https://calling.api.sinch.com`) |

**Soprano**
| Setting | Purpose |
|---------|---------|
| Key Vault secret `soprano-api-key` | API key (sent as the `X-MEMS-API-Key` header) |
| Key Vault secret `soprano-api-id` | API ID (sent as the `X-MEMS-API-ID` header) |
| `SOPRANO_ENDPOINT` | **required** — your MEMS API base `https://<your-mems-domain>/cgpapi` (per-customer; no default) |
| `SOPRANO_SOURCE_ID` | provisioned source/sender endpoint id, app setting — Soprano requires a provisioned sender, sent as `endpoints:[{type,id}]` |
| `SOPRANO_SOURCE_TYPE` | provisioned source endpoint type, app setting (optional; default `1`) |
| `SOPRANO_SENDER_ID` | optional free-text sender, used only as a fallback when `SOPRANO_SOURCE_ID` is unset |

> Optional per-provider `<PROVIDER>_ENDPOINT` overrides the manifest URL (e.g. a sandbox host); rarely needed.

### Identity & permissions (managed identity — no static credentials)

The Function authenticates to Key Vault (and any other Azure resource) with its **managed identity** (user-assigned when `AZURE_CLIENT_ID` is set, else system-assigned) — there are **no secrets, keys, or connection strings in code or config**. Grant it **least-privilege** access on the customer's vault:

| Scope | Role | Why |
|-------|------|-----|
| The provider **secret** (or the vault) | **Key Vault Secrets User** | `get` the provider API key/token |

Also use an **identity-based** `AzureWebJobsStorage` connection (managed identity) instead of a storage connection string, so the runtime holds no static secret either. All resource **names** (`KEY_VAULT_URL`, `EXPECTED_AUDIENCE`, `ISSUER_TENANT_ID`) come from app settings — nothing is hard-coded.

### Add your own provider

Onboarding a provider is **one file** — `src/functions/providers/<id>.js` — with no change to the shared pipeline. Copy an existing provider (e.g. [infobip.js](src/functions/providers/infobip.js)) and export three things:

```js
// 1) manifest — the provider's protocol facts the engine reads
const manifest = {
  id: 'acme',                                    // provider id (used as the `Provider` value); the URL
                                                 // app setting is `<ID>_ENDPOINT`, e.g. ACME_ENDPOINT
  auth: { mode: 'apiKey', keyVaultSecretName: 'acme-api-key' },
  responseMapping: { SENT: 'Continue', FAILED: 'Fail', default: 'Fail' }, // provider status → outcome
};

// 2) buildRequest — shape the outbound HTTP call
function buildRequest({ channel, endpoint, dispatch, credential, env }) {
  return {
    url: `${endpoint}/messages`,
    method: 'POST',
    headers: { Authorization: `Bearer ${credential.secret}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ to: dispatch.destination, text: dispatch.message }),
  };
}

// 3) parseResponse — normalize the provider reply
function parseResponse({ httpStatus, ok, json }) {
  return {
    success: ok,
    providerHttpStatus: httpStatus,
    providerMessageId: (json && json.id) || null,
    providerStatusName: (json && json.status) || (ok ? 'SENT' : null),
    providerStatusDescription: (json && json.description) || null,
  };
}

module.exports = { manifest, buildRequest, parseResponse };
```

The engine handles the rest — provider resolution, Key Vault credential fetch (via managed identity), message templating, timeout, `responseMapping` → HTTP status, and fail-closed behavior. Drop the file in, add the Key Vault secret, set `DEFAULT_PROVIDER=acme`, and it works.

## Request contract

`POST /api/SendOtp` — the SAS → External Phone Provider delivery endpoint. The cleartext body is a routing envelope; the
PII (phone + rendered message, which contains the passcode) is encrypted in a JWE. See
[../docs/CONTRACT.md](../docs/CONTRACT.md) for the full contract.

| Field | Required | Notes |
|-------|----------|-------|
| `type` | yes | envelope version, e.g. `microsoft.mfa.otpDeliver.v1` |
| `channel` | yes | `1`=Sms, `2`=Voice |
| `mode` | yes | `1`=Live, `2`=Evaluation (rehearsal — not delivered) |
| `encryptedDeliveryContext` | yes | JWE (RSA-OAEP-256 + A256GCM); decrypts to `{ nonce, phoneNumber, message, locale?, riskContext? }` |
| `tenantId`, `correlationId`, `ttlSeconds` | no | routing / tracing / passcode validity |

The active provider is deployment config (`DEFAULT_PROVIDER`), not a request field. The response is the
`CyotEndpointResponse`: `{ "nonce": "<echo>", "correlationId": "<echo>", "providerStatus": "accepted" }`.
A `2xx` with a matching nonce means handled; non-2xx / nonce mismatch / timeout → SAS falls back to CAPP.

## Try it

The private RSA key that decrypts `encryptedDeliveryContext` is resolved from Key Vault by the JOSE `kid`
(or `CYOT_JWE_PRIVATE_KEY_PEM` for local dev). Build the envelope with the matching public key:

```bash
curl -X POST https://<your-function-app>.azurewebsites.net/api/SendOtp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <Entra token>" \
  -H "x-ms-correlation-id: test-001" \
  -d '{
    "type": "microsoft.mfa.otpDeliver.v1",
    "tenantId": "<tenant-guid>",
    "correlationId": "test-001",
    "channel": 1,
    "mode": 1,
    "ttlSeconds": 60,
    "encryptedDeliveryContext": "<JWE compact serialization>"
  }'
# -> 202 { "nonce": "<echo>", "correlationId": "test-001", "providerStatus": "accepted" }
```

Evaluation mode (`"mode": 2`) runs everything except the actual send and still echoes the nonce.
