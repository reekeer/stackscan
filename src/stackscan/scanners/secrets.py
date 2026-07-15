from __future__ import annotations

import re
from dataclasses import dataclass

from stackscan.types import SecretFinding


@dataclass(frozen=True)
class _SecretPattern:
    name: str
    regex: re.Pattern[str]
    severity: str = "HIGH"


_SECRET_PATTERNS: tuple[_SecretPattern, ...] = (
    _SecretPattern(
        name="AWS Access Key ID",
        regex=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    ),
    _SecretPattern(
        name="Google API key",
        regex=re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
    ),
    _SecretPattern(
        name="GitHub personal access token",
        regex=re.compile(r"\b(ghp_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59}|gho_[A-Za-z0-9_]{36}|ghu_[A-Za-z0-9_]{36}|ghs_[A-Za-z0-9_]{36}|ghr_[A-Za-z0-9_]{36})\b"),
    ),
    _SecretPattern(
        name="Slack token",
        regex=re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}(-[a-zA-Z0-9]{24})?)\b"),
    ),
    _SecretPattern(
        name="Slack webhook",
        regex=re.compile(r"(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{10,}/[a-zA-Z0-9_]{24,})"),
    ),
    _SecretPattern(
        name="Private key",
        regex=re.compile(r"(-----BEGIN (RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----[\s\S]{60,200}-----END (RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----)"),
        severity="CRITICAL",
    ),
    _SecretPattern(
        name="JWT",
        regex=re.compile(r"\b(eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)\b"),
    ),
    _SecretPattern(
        name="S3 bucket URL",
        regex=re.compile(r"\b(s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\b", re.IGNORECASE),
    ),
    _SecretPattern(
        name="Database URL",
        regex=re.compile(r"\b((?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^\s\"'<>]{8,})\b", re.IGNORECASE),
        severity="CRITICAL",
    ),
    _SecretPattern(
        name="Generic API key",
        regex=re.compile(
            r"(?i)(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]?([a-z0-9_\-]{16,})['\"]?"
        ),
    ),
    _SecretPattern(
        name="Password in JS/config",
        regex=re.compile(
            r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\s]{4,})['\"]"
        ),
        severity="MEDIUM",
    ),
)


def _redact(value: str, keep: int = 6) -> str:
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{value[-keep:]}"


def scan_secrets(body: str, location: str = "") -> list[SecretFinding]:
    """Return probable secret leaks found in the response body."""
    seen: set[tuple[str, str]] = set()
    findings: list[SecretFinding] = []
    for pattern in _SECRET_PATTERNS:
        for match in pattern.regex.finditer(body):
            value = match.group(1) if pattern.regex.groups else match.group(0)
            value = value.strip()
            if len(value) < 4:
                continue
            key = (pattern.name, value)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                SecretFinding(
                    name=pattern.name,
                    value=_redact(value),
                    source=f"body:{pattern.name}",
                    location=location,
                    severity=pattern.severity,
                )
            )
    return findings
