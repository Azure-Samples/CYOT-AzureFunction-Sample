# Customer Onboarding

A high-level guide to setting up, securing, and deploying the CYOT OTP Function. The steps are the same
for every language (`javascript/`, `dotnet/`, `python/`); only the build/run commands differ (see each
language's README). All config keys, Key Vault secret names, and behaviors are defined once in
[CONTRACT.md](CONTRACT.md).

## 1. Pick a language and a provider

Choose an implementation folder and the SMS/voice provider you have an account with (Infobip,
Telesign, Soprano, Sinch). One provider is active per deployment.

## 2. Store the provider secret in Key Vault

Provider API keys never live in code or app settings — put them in **Key Vault** under the names the
adapter expects (see [CONTRACT.md §3](CONTRACT.md)). The Function reads them at runtime via its
**managed identity**, which needs the *Key Vault Secrets User* role on the vault.

## 3. Configure

Set the app settings from [`local.settings.sample.json`](local.settings.sample.json) — locally in a
`local.settings.json` file, in Azure as environment variables. The keys are identical across languages;
the full catalog is in [CONTRACT.md §4](CONTRACT.md).

## 4. Run and send a test

Build/run per the language README, then `POST /api/SendOtp` with the cleartext envelope (the PII lives
in the encrypted JWE — see [CONTRACT.md](CONTRACT.md)). A **`202`** with the echoed `nonce`
(`{ "nonce": "<echo>", "correlationId": "<echo>", "providerStatus": "accepted" }`) means the provider
**queued** it — delivery is asynchronous, so confirm via the provider's delivery report.

## 5. Secure it — `REQUIRE_AUTH`

Keep `REQUIRE_AUTH=false` for local development. For any real deployment, set **`REQUIRE_AUTH=true`**
(plus `EXPECTED_AUDIENCE` and `ISSUER_TENANT_ID`). The Function then validates the caller's **Entra
JWT** and returns **401** without a valid token. To test it, obtain a token for the expected audience
and confirm: no token → 401, valid token → 202.

## 6. Deploy

Publish the chosen language folder to a Function App (see its README). Ensure the app's managed
identity has Key Vault access and the same environment variables are set.

## 7. Add another provider

One adapter file — `manifest` + `buildRequest` + `parseResponse` — then store its secret in Key Vault
and set its endpoint app setting. No engine changes. See [CONTRACT.md §3](CONTRACT.md).
