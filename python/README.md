# CYOT Function — Python (v2 model)

A Python implementation of the CYOT OTP-delivery Function, conforming to the shared
[contract](../docs/CONTRACT.md). Same design as the [`javascript/`](../javascript/) and
[`dotnet/`](../dotnet/) versions: one dispatch engine + drop-in provider adapters, env-provisioned
config, secrets in Key Vault.

## Layout

```
python/
├─ function_app.py            # HTTP trigger: POST /api/SendOtp (v2 model)
├─ requirements.txt
├─ src/
│  ├─ cyot.py                 # envelope parse/validate + JWE decrypt + context → dispatch
│  ├─ dispatch.py             # resolve provider → credential → endpoint → send → outcome
│  ├─ registry.py             # adapter registry + DEFAULT_PROVIDER resolution
│  ├─ providers/*.py          # infobip, telesign, soprano, sinch (manifest + build/parse)
│  ├─ secrets.py              # Key Vault via managed identity (cached)
│  ├─ outcome.py              # status → outcome → HTTP status
│  ├─ models.py               # DispatchRequest + outcome constants
│  └─ security.py             # Entra JWT validation when REQUIRE_AUTH=true
└─ tests/                     # pytest conformance tests
```

## Build, test, run

```bash
cd python
python -m venv .venv && .venv\Scripts\activate      # (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt pytest
python -m pytest tests                               # run conformance tests
func start                                           # run locally (copy ../docs/local.settings.sample.json)
```

## Deploy

```bash
func azure functionapp publish <your-function-app>   # Linux Python Function App
```

The app's **managed identity** needs the **Key Vault Secrets User** role on the vault. Configuration
(env var names, Key Vault secret names, behaviors) is identical to the contract — see
[`../docs/CONTRACT.md`](../docs/CONTRACT.md).

Target: Azure Functions Python **v2** programming model (Python 3.11), Functions v4.
