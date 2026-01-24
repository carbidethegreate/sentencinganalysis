import re
from typing import Any, Dict

_SENSITIVE_FIELD_PATTERN = re.compile(
    r'(?i)("?(?:nextgencso|x-next-gen-cso|password|otpcode|clientcode|loginid|username)"?\s*[:=]\s*")([^"]+)(")'
)
_SENSITIVE_PARAM_PATTERN = re.compile(
    r"(?i)(nextgencso|x-next-gen-cso|password|otpcode|clientcode|loginid|username)\s*[:=]\s*([^\s,;&]+)"
)


def redact_tokens(message: str) -> str:
    if not message:
        return message
    redacted = _SENSITIVE_FIELD_PATTERN.sub(r"\1<redacted>\3", message)
    redacted = _SENSITIVE_PARAM_PATTERN.sub(r"\1=<redacted>", redacted)
    return redacted


def redact_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    redacted = dict(payload)
    for key in list(redacted.keys()):
        if key.lower() in {
            "nextgencso",
            "x-next-gen-cso",
            "password",
            "otpcode",
            "clientcode",
            "loginid",
            "username",
        }:
            redacted[key] = "<redacted>"
    return redacted


def scrub_log_message(message: str) -> str:
    return redact_tokens(message)
