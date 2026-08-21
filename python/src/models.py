"""Shared contract types for the EPP OTP engine (see /docs/CONTRACT.md)."""
from dataclasses import dataclass

# Outcomes (mirrors the other languages).
CONTINUE = "Continue"
FAIL = "Fail"
BLOCK = "Block"
STEP_UP = "StepUp"


@dataclass
class DispatchRequest:
    destination: str
    message: str | None
    channel: str
    message_id: str
    correlation_id: str | None
    locale: str | None
