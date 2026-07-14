from __future__ import annotations

from stackscan.types import Headers, SecurityHeaders

SECURITY_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
)


def analyze_security_headers(headers: Headers) -> SecurityHeaders:
    present: dict[str, str] = {}
    missing: list[str] = []
    for name in SECURITY_HEADERS:
        value = headers.get(name)
        if value is not None:
            present[name] = value
        else:
            missing.append(name)
    return SecurityHeaders(present=present, missing=tuple(missing))
