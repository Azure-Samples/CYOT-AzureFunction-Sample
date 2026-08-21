"""Core engine: resolve provider -> credential (Key Vault) -> endpoint -> adapter
builds the request -> send with a timeout -> map status to outcome + HTTP status. Fail-closed."""
import os

import requests

from .models import CONTINUE
from .outcome import DEFAULT_CHANNELS, resolve_outcome, to_http_status

DEFAULT_TIMEOUT_MS = 1500


class DispatchEngine:
    def __init__(self, registry, secrets, env=None):
        self.registry = registry
        self.secrets = secrets
        self.env = env if env is not None else os.environ

    def dispatch(self, dispatch, request_provider, shutter, request_id, log):
        adapter = self.registry.resolve(request_provider)
        if adapter is None:
            log.warning("[DISPATCH_ERROR] requestId=%s unknown provider=%s", request_id, request_provider or "n/a")
            return 400, {"status": "error", "reason": "unknown provider", "requestId": request_id}

        manifest = adapter.manifest
        provider_id = manifest["id"]
        channel = (dispatch.channel or "sms").lower()

        if channel not in DEFAULT_CHANNELS:
            return 400, {"status": "error", "provider": provider_id, "reason": f"channel '{channel}' not supported", "requestId": request_id}

        # Credential (fail closed 502 if missing) — this is our credential, not the caller's token.
        credential = None
        try:
            credential = self._resolve_credential(manifest["auth"])
        except Exception as error:
            log.error("[DISPATCH_ERROR] requestId=%s provider=%s credential error=%s", request_id, provider_id, error)

        auth = manifest["auth"]
        identity_required = (
            credential is not None
            and credential["mode"] == "apiKey"
            and bool(auth.get("identity_key_vault_secret_name"))
        )
        credential_unavailable = (
            credential is None
            or (credential["mode"] == "oauth2" and not credential.get("token"))
            or (credential["mode"] == "apiKey" and not credential.get("secret"))
            or (identity_required and not credential.get("identity"))
        )
        if credential_unavailable:
            return 502, self._fail_body(provider_id, channel, "provider credential unavailable", dispatch, request_id)

        endpoint = self._resolve_endpoint(manifest)
        if not endpoint:
            return 502, self._fail_body(provider_id, channel, "provider endpoint not configured", dispatch, request_id)

        provider_request = adapter.build_request(channel, endpoint, dispatch, credential, self.env)
        log.info("[DISPATCH] requestId=%s provider=%s channel=%s shutter=%s", request_id, provider_id, channel, bool(shutter))

        if shutter:
            return 200, {"status": "accepted", "shutterProcessed": True, "provider": provider_id, "channel": channel, "correlationId": dispatch.correlation_id, "messageId": dispatch.message_id, "requestId": request_id}

        try:
            timeout_ms = int(self.env.get("EPP_PROVIDER_TIMEOUT_MS") or DEFAULT_TIMEOUT_MS)
        except (TypeError, ValueError):
            timeout_ms = DEFAULT_TIMEOUT_MS
        try:
            response = requests.request(
                provider_request["method"],
                provider_request["url"],
                headers=provider_request["headers"],
                data=provider_request["body"],
                timeout=timeout_ms / 1000,
            )
        except requests.exceptions.Timeout:
            log.warning("[DISPATCH_TIMEOUT] requestId=%s provider=%s", request_id, provider_id)
            return 504, self._fail_body(provider_id, channel, f"endpoint timeout after {timeout_ms}ms", dispatch, request_id)
        except requests.exceptions.RequestException as error:
            log.error("[DISPATCH_ERROR] requestId=%s provider=%s reason=%s", request_id, provider_id, error)
            return 502, self._fail_body(provider_id, channel, str(error), dispatch, request_id)

        try:
            body_json = response.json()
        except ValueError:
            body_json = {}

        ok = 200 <= response.status_code < 300
        parsed = adapter.parse_response(response.status_code, ok, body_json)
        outcome = resolve_outcome(manifest, parsed)
        http_status = to_http_status(outcome, parsed.get("provider_http_status") or response.status_code)

        log.info("[DISPATCH_RESULT] requestId=%s provider=%s channel=%s outcome=%s httpStatus=%s", request_id, provider_id, channel, outcome, http_status)

        return http_status, {
            "status": "accepted" if outcome == CONTINUE else "failed",
            "outcome": outcome,
            "provider": provider_id,
            "channel": channel,
            "messageId": dispatch.message_id,
            "correlationId": dispatch.correlation_id,
            "providerMessageId": parsed.get("provider_message_id"),
            "providerStatus": parsed.get("provider_status_name") or parsed.get("provider_status_code"),
            "providerStatusDescription": parsed.get("provider_status_description"),
            "requestId": request_id,
        }

    def _resolve_credential(self, auth):
        if auth.get("mode") == "oauth2":
            return {"mode": "oauth2", "token": None}  # not wired -> fails closed
        secret = self.secrets.resolve(auth.get("key_vault_secret_name"))
        identity = self.secrets.resolve(auth.get("identity_key_vault_secret_name")) if auth.get("identity_key_vault_secret_name") else ""
        return {"mode": "apiKey", "secret": secret, "identity": identity}

    def _resolve_endpoint(self, manifest):
        # One provider is active per deployment, so the endpoint is a single EPP_PROVIDER_ENDPOINT.
        return self.env.get("EPP_PROVIDER_ENDPOINT")

    def _fail_body(self, provider, channel, reason, dispatch, request_id):
        return {"status": "failed", "outcome": "Fail", "provider": provider, "channel": channel, "reason": reason, "correlationId": dispatch.correlation_id, "messageId": dispatch.message_id, "requestId": request_id}
