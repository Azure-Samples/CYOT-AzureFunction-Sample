"""Validates the Entra JWT when REQUIRE_AUTH=true (aud/issuer/JWKS, RS256).
No-op pass-through otherwise."""
import os

import jwt
from jwt import PyJWKClient


def validate_token(authorization_header):
    """Returns (ok, reason, caller_object_id)."""
    if (os.environ.get("REQUIRE_AUTH") or "").lower() != "true":
        return True, None, None

    audience = os.environ.get("EXPECTED_AUDIENCE")
    tenant_id = os.environ.get("ISSUER_TENANT_ID")
    if not audience or not tenant_id:
        return False, "auth misconfigured", None

    if not authorization_header or not authorization_header.lower().startswith("bearer "):
        return False, "missing bearer token", None

    token = authorization_header[len("bearer "):].strip()
    try:
        jwks_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        signing_key = PyJWKClient(jwks_url).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=audience,
            options={"verify_iss": False},
        )
        allowed_issuers = (
            f"https://login.microsoftonline.com/{tenant_id}/v2.0",
            f"https://sts.windows.net/{tenant_id}/",
        )
        if claims.get("iss") not in allowed_issuers:
            return False, "token validation failed", None
        return True, None, claims.get("oid")
    except Exception:
        return False, "token validation failed", None
