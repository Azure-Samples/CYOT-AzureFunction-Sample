# External Phone Provider — Azure Function Sample

A provider-agnostic **OTP-delivery Azure Function** sample, implemented across multiple languages.
Each language folder is a self-contained implementation of the **same design and the same
[contract](docs/CONTRACT.md)** — one engine, drop-in provider adapters, env-provisioned config, and
secrets in Key Vault.

## Implementations

| Language | Status | Folder |
|----------|--------|--------|
| JavaScript (Node.js) | ✅ Available | [`javascript/`](javascript/) |
| C# (.NET isolated worker) | ✅ Available | [`dotnet/`](dotnet/) |
| Python (v2 model) | ✅ Available | [`python/`](python/) |

All implementations conform to the **language-agnostic contract** in
[`docs/CONTRACT.md`](docs/CONTRACT.md) — identical HTTP API, provider-adapter shape, config/env var
names, Key Vault secret names, and behaviors (fail-closed, managed identity, privacy). Pick any folder
and follow its README.

New here? Start with **[docs/ONBOARDING.md](docs/ONBOARDING.md)** — setup, config, running, securing,
and deploying, step by step.

## The design in one line

`POST /api/SendOtp` → validate token → resolve provider → fetch secret from Key Vault (managed
identity) → provider adapter builds the request → send with a timeout → map the provider status to an
outcome and an HTTP status. **Fail-closed:** only a `Continue` outcome returns `202 accepted`.

See [`docs/CONTRACT.md`](docs/CONTRACT.md) for the full specification every implementation follows.

## Security

Set **`REQUIRE_AUTH=true`** in any real deployment. The Function then validates the caller's **Entra
JWT** (audience = `EXPECTED_AUDIENCE`, issuer tenant = `ISSUER_TENANT_ID`, signature via JWKS) and
returns **401** without a valid token. Provider secrets are read from **Key Vault** via **managed
identity** — no keys or connection strings in code or config. Locally, keep `REQUIRE_AUTH=false`. See
[docs/ONBOARDING.md §6](docs/ONBOARDING.md) for how to test it with a token.

## Docs

- **[docs/ONBOARDING.md](docs/ONBOARDING.md)** — customer setup / run / secure / deploy guide.
- **[docs/CONTRACT.md](docs/CONTRACT.md)** — the language-agnostic contract every implementation follows.

## Contributing a language or provider

- **New provider** (in any language): add one adapter file exposing `manifest` + `buildRequest` +
  `parseResponse` — no engine changes. See the language folder's README.
- **New language**: mirror the folder structure, implement the contract, add the same test scenarios,
  and wire it into [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
