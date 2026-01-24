import re
from typing import Any, Dict

_TOKEN_FIELD_PATTERN = re.compile(
    r'(?i)("?(?:nextgencso|x-next-gen-cso)"?\s*[:=]\s*")([^"]+)(")'
)
_TOKEN_HEADER_PATTERN = re.compile(
    r"(?i)(nextgencso|x-next-gen-cso)\s*[:=]\s*([^\s,;]+)"
)


def redact_tokens(message: str) -> str:
    if not message:
        return message
    redacted = _TOKEN_FIELD_PATTERN.sub(r"\1<redacted>\3", message)
    redacted = _TOKEN_HEADER_PATTERN.sub(r"\1=<redacted>", redacted)
    return redacted


def redact_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    redacted = dict(payload)
    for key in list(redacted.keys()):
        if key.lower() in {"nextgencso", "x-next-gen-cso"}:
            redacted[key] = "<redacted>"
    return redacted
