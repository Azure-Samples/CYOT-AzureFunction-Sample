"""Maps a provider status to an outcome, then to an HTTP status. Fail-closed."""
from .models import CONTINUE, FAIL, BLOCK, STEP_UP

DEFAULT_CHANNELS = ["sms", "voice"]


def resolve_outcome(manifest, parsed):
    mapping = manifest["response_mapping"]
    key = parsed.get("provider_status_name") or parsed.get("provider_status_code")
    if key:
        return mapping.get(key) or mapping.get("default", FAIL)
    return CONTINUE if parsed.get("success") else mapping.get("default", FAIL)


def to_http_status(outcome, provider_http_status):
    """Continue 200, Block 403, StepUp 409; a Fail surfaces the provider's failure class."""
    if outcome == CONTINUE:
        return 200
    if outcome == BLOCK:
        return 403
    if outcome == STEP_UP:
        return 409
    if outcome == FAIL:
        if provider_http_status == 429:
            return 429
        if provider_http_status in (401, 403):
            return 401
        if 400 <= provider_http_status < 500:
            return 400
    return 502
