"""SAS → CYOT envelope handling. SAS sends a cleartext routing envelope (SendCyotOtpRequest) whose PII
(phone + rendered message, which contains the passcode) is encrypted in a JWE. This module parses the
envelope, decrypts the JWE delivery context (RSA-OAEP-256 + A256GCM, key selected by the JOSE `kid`),
and maps the CyotDeliveryContext onto the dispatch engine's request shape."""
import base64
import json

from jwcrypto import jwe as jwe_module
from jwcrypto import jwk

from .models import DispatchRequest

# CyotChannel: 1=Sms, 2=Voice (0=Undefined). CyotDeliveryMode: 1=Live, 2=Evaluation (do NOT deliver).
CHANNEL_BY_CODE = {1: "sms", 2: "voice"}
CHANNEL_BY_NAME = {"sms": 1, "voice": 2}
MODE_LIVE = 1
MODE_EVALUATION = 2
MODE_BY_NAME = {"live": MODE_LIVE, "evaluation": MODE_EVALUATION}


def _normalize_channel(channel):
    """channel accepts the int enum (1/2) or the string form ('sms'/'voice')."""
    if isinstance(channel, bool):
        return None
    if channel in CHANNEL_BY_CODE:
        return channel
    if isinstance(channel, str):
        return CHANNEL_BY_NAME.get(channel.lower())
    return None


def _normalize_mode(mode):
    """mode accepts the int enum (1/2) or the string form ('live'/'evaluation')."""
    if isinstance(mode, bool):
        return None
    if mode in (MODE_LIVE, MODE_EVALUATION):
        return mode
    if isinstance(mode, str):
        return MODE_BY_NAME.get(mode.lower())
    return None


def parse_envelope(payload):
    """Validates + normalizes the cleartext envelope. Returns (envelope, None) or (None, error)."""
    if not isinstance(payload, dict):
        return None, "invalid envelope"
    encrypted = payload.get("encryptedDeliveryContext")
    if not isinstance(encrypted, str) or not encrypted:
        return None, "encryptedDeliveryContext is required"
    channel = _normalize_channel(payload.get("channel"))
    if channel is None:
        return None, f"unsupported channel '{payload.get('channel')}'"
    mode = _normalize_mode(payload.get("mode"))
    if mode is None:
        return None, f"unsupported mode '{payload.get('mode')}'"
    return {
        "type": payload.get("type"),
        "tenant_id": payload.get("tenantId"),
        "correlation_id": payload.get("correlationId"),
        "channel": channel,
        "mode": mode,
        "ttl_seconds": payload.get("ttlSeconds"),
        "encrypted_delivery_context": encrypted,
    }, None


def read_kid(compact_jwe):
    """Reads the `kid` from the JWE protected (first) segment without decrypting."""
    header_segment = compact_jwe.split(".")[0]
    header_segment += "=" * (-len(header_segment) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_segment))
    return header.get("kid")


def make_key_provider(env, secrets):
    """Returns a key_provider(kid) -> PEM. Uses an inline PEM (CYOT_JWE_PRIVATE_KEY_PEM, local/dev) or a
    Key Vault secret (name = JWE_PRIVATE_KEY_SECRET, else the `kid`)."""
    def key_provider(kid):
        pem = env.get("CYOT_JWE_PRIVATE_KEY_PEM")
        if pem:
            return pem
        secret_name = env.get("JWE_PRIVATE_KEY_SECRET") or kid
        if not secret_name:
            return ""
        return secrets.resolve(secret_name)

    return key_provider


# Reject oversized or structurally invalid JWEs before base64-decoding or allocating buffers.
MAX_JWE_LENGTH = 16384


def _assert_well_formed_jwe(compact_jwe):
    """Contract: exactly five non-empty compact segments; alg/enc/IV/tag are enforced by the decrypt."""
    if not isinstance(compact_jwe, str) or not compact_jwe:
        raise ValueError("malformed JWE")
    if len(compact_jwe) > MAX_JWE_LENGTH:
        raise ValueError("delivery context exceeds size limit")
    segments = compact_jwe.split(".")
    if len(segments) != 5 or not all(segments):
        raise ValueError("malformed JWE: expected five non-empty segments")


def decrypt_delivery_context(compact_jwe, key_provider):
    """key_provider(kid) -> PEM string. Returns the decrypted CyotDeliveryContext dict."""
    _assert_well_formed_jwe(compact_jwe)
    kid = read_kid(compact_jwe)
    pem = key_provider(kid)
    if not pem:
        raise ValueError("private key unavailable")
    key = jwk.JWK.from_pem(pem.encode("utf-8") if isinstance(pem, str) else pem)
    # Pin alg/enc so a tampered header can't downgrade the crypto (contract: RSA-OAEP-256 + A256GCM).
    token = jwe_module.JWE(algs=["RSA-OAEP-256", "A256GCM"])
    token.deserialize(compact_jwe, key=key)
    return json.loads(token.payload.decode("utf-8"))


def context_to_dispatch(context, envelope, message_id):
    """Maps the decrypted context + envelope onto the engine's dispatch shape. The message is
    pre-rendered (already contains the passcode), so the fields mirror CyotDeliveryContext."""
    return DispatchRequest(
        destination=context.get("phoneNumber"),
        message=context.get("message"),
        channel=CHANNEL_BY_CODE[envelope["channel"]],
        message_id=message_id,
        correlation_id=envelope["correlation_id"],
        locale=context.get("locale"),
    )
