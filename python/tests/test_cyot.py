"""Envelope validation + JWE decryption round-trip (see docs/CONTRACT.md §1, §6)."""
import json

from jwcrypto import jwe, jwk

from src.cyot import (
    context_to_dispatch,
    decrypt_delivery_context,
    parse_envelope,
    read_kid,
)

# Throwaway RSA key: encrypt here, decrypt via the module using the private PEM.
_KEY = jwk.JWK.generate(kty="RSA", size=2048, kid="test-key")
_PRIVATE_PEM = _KEY.export_to_pem(private_key=True, password=None).decode("utf-8")


def _encrypt(context, kid="test-key"):
    protected = {"alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": kid}
    token = jwe.JWE(json.dumps(context).encode("utf-8"), protected=json.dumps(protected))
    token.add_recipient(_KEY)
    return token.serialize(compact=True)


def _key_provider(_kid):
    return _PRIVATE_PEM


def _sample_context():
    return {"nonce": "nonce-1", "phoneNumber": "+14255551234", "message": "Your code is 123456", "locale": "en-US"}


def test_missing_encrypted_context_is_error():
    envelope, error = parse_envelope({"channel": 1, "mode": 1})
    assert envelope is None
    assert "encryptedDeliveryContext" in error


def test_unsupported_channel_is_error():
    envelope, error = parse_envelope({"channel": 9, "mode": 1, "encryptedDeliveryContext": "x"})
    assert envelope is None
    assert "channel" in error


def test_unsupported_mode_is_error():
    envelope, error = parse_envelope({"channel": 1, "mode": 5, "encryptedDeliveryContext": "x"})
    assert envelope is None
    assert "mode" in error


def test_valid_envelope_parses():
    envelope, error = parse_envelope({
        "type": "microsoft.mfa.otpDeliver.v1", "tenantId": "t", "correlationId": "c",
        "channel": 2, "mode": 1, "ttlSeconds": 60, "encryptedDeliveryContext": "x",
    })
    assert error is None
    assert envelope["channel"] == 2
    assert envelope["mode"] == 1


def test_jwe_round_trips_to_delivery_context():
    compact = _encrypt(_sample_context())
    assert read_kid(compact) == "test-key"
    context = decrypt_delivery_context(compact, _key_provider)
    assert context["nonce"] == "nonce-1"
    assert context["phoneNumber"] == "+14255551234"
    assert context["message"] == "Your code is 123456"


def test_context_to_dispatch_maps_fields():
    envelope, _ = parse_envelope({
        "correlationId": "corr-1", "channel": 2, "mode": 1, "encryptedDeliveryContext": "x",
    })
    dispatch = context_to_dispatch(_sample_context(), envelope, "msg-1")
    assert dispatch.destination == "+14255551234"
    assert dispatch.channel == "voice"
    assert dispatch.message_id == "msg-1"
    assert dispatch.correlation_id == "corr-1"
