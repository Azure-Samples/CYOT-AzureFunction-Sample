"""CYOT OTP Function — Python v2 model. HTTP trigger: POST /api/SendOtp — the SAS → CYOT delivery
endpoint. Validates the token, parses the cleartext routing envelope, decrypts the JWE delivery context
(PII lives there), dispatches, and echoes the nonce to prove decryption.
Privacy: phone and OTP code are never logged or returned in the body."""
import json
import logging
import os
import uuid

import azure.functions as func

from src.cyot import (
    MODE_EVALUATION,
    context_to_dispatch,
    decrypt_delivery_context,
    make_key_provider,
    parse_envelope,
)
from src.dispatch import DispatchEngine
from src.providers.infobip import InfobipProvider
from src.providers.sinch import SinchProvider
from src.providers.soprano import SopranoProvider
from src.providers.telesign import TelesignProvider
from src.registry import ProviderRegistry
from src.secrets import SecretResolver
from src.security import validate_token

app = func.FunctionApp()

_registry = ProviderRegistry([InfobipProvider(), TelesignProvider(), SopranoProvider(), SinchProvider()])
_secrets = SecretResolver()
_engine = DispatchEngine(_registry, _secrets)
_key_provider = make_key_provider(os.environ, _secrets)


def _json(status_code, body):
    return func.HttpResponse(json.dumps(body), status_code=status_code, mimetype="application/json")


@app.route(route="SendOtp", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def send_otp(req: func.HttpRequest) -> func.HttpResponse:
    request_id = uuid.uuid4().hex
    client_request_id = req.headers.get("x-ms-client-request-id") or request_id
    header_correlation_id = req.headers.get("x-ms-correlation-id")

    auth_ok, reason, caller_object_id = validate_token(req.headers.get("Authorization"))
    if not auth_ok:
        logging.warning("[AUTH_ERROR] requestId=%s reason=%s", request_id, reason)
        return _json(401, {"error": "unauthorized", "reason": reason, "requestId": request_id})

    try:
        payload = req.get_json()
    except ValueError:
        logging.warning("[ERROR] requestId=%s invalid JSON body", request_id)
        return _json(400, {"error": "bad_request", "reason": "invalid JSON body", "requestId": request_id})

    envelope, error = parse_envelope(payload)
    if error:
        logging.warning("[VALIDATION_ERROR] requestId=%s %s", request_id, error)
        return _json(400, {"error": "bad_request", "reason": error, "requestId": request_id})

    correlation_id = envelope["correlation_id"] or header_correlation_id or request_id

    try:
        delivery = decrypt_delivery_context(envelope["encrypted_delivery_context"], _key_provider)
    except Exception as err:
        logging.warning("[DECRYPT_ERROR] requestId=%s correlationId=%s reason=%s", request_id, correlation_id, err)
        return _json(400, {"error": "decryption_failed", "correlationId": correlation_id, "requestId": request_id})

    if not delivery or not delivery.get("nonce") or not delivery.get("phoneNumber") or not delivery.get("message"):
        logging.warning("[VALIDATION_ERROR] requestId=%s correlationId=%s incomplete delivery context", request_id, correlation_id)
        return _json(400, {"error": "bad_request", "reason": "incomplete delivery context", "correlationId": correlation_id, "requestId": request_id})

    nonce = delivery["nonce"]
    evaluation = envelope["mode"] == MODE_EVALUATION

    # Respect ttlSeconds: don't start a live delivery for an already-expired passcode (contract §7).
    ttl_seconds = envelope["ttl_seconds"]
    if not evaluation and isinstance(ttl_seconds, (int, float)) and not isinstance(ttl_seconds, bool) and ttl_seconds <= 0:
        logging.warning("[EXPIRED] requestId=%s correlationId=%s ttl=%s", request_id, correlation_id, ttl_seconds)
        return _json(400, {"error": "request_expired", "correlationId": correlation_id, "requestId": request_id})

    logging.info(
        "[SENDOTP] requestId=%s caller=%s type=%s tenant=%s correlationId=%s channel=%s mode=%s phone=present message=present risk=%s",
        request_id, caller_object_id or "n/a", envelope["type"] or "n/a", envelope["tenant_id"] or "n/a",
        correlation_id, envelope["channel"], envelope["mode"], "present" if delivery.get("riskContext") else "absent",
    )

    dispatch = context_to_dispatch(delivery, envelope, client_request_id)

    try:
        status_code, _ = _engine.dispatch(dispatch, None, evaluation, request_id, logging)
        # Contract: acceptance is 202 Accepted (async delivery); the engine signals acceptance as 200.
        accepted = status_code == 200
        return _json(
            202 if accepted else status_code,
            {"nonce": nonce, "correlationId": correlation_id, "providerStatus": "accepted" if accepted else "failed"},
        )
    except Exception as error:
        logging.error("[EXCEPTION] requestId=%s error=%s", request_id, error)
        return _json(500, {"nonce": nonce, "correlationId": correlation_id, "providerStatus": "failed"})
