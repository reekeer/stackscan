"""Output payload types for a full stack analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TypeAlias, cast

# Legacy alias kept for callers that only want category -> tech-name lists.
DetectedTech: TypeAlias = dict[str, list[str]]


@dataclass(frozen=True)
class Technology:
    """A single detected technology and where the evidence came from."""

    name: str
    categories: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "categories": list(self.categories),
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class NetworkInfo:
    host: str
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    cname: tuple[str, ...] = ()
    reverse_dns: dict[str, str] = field(default_factory=dict)
    geo: dict[str, dict[str, str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "ipv4": list(self.ipv4),
            "ipv6": list(self.ipv6),
            "cname": list(self.cname),
            "reverse_dns": self.reverse_dns,
            "geo": self.geo,
        }


@dataclass(frozen=True)
class TlsInfo:
    subject: str | None = None
    issuer: str | None = None
    subject_alt_names: tuple[str, ...] = ()
    not_before: str | None = None
    not_after: str | None = None
    protocol: str | None = None
    cipher: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "subject_alt_names": list(self.subject_alt_names),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "protocol": self.protocol,
            "cipher": self.cipher,
        }


@dataclass(frozen=True)
class InfraInfo:
    """What sits in front of / runs the origin (CDN, WAF, proxy, server)."""

    cdn: tuple[str, ...] = ()
    waf: tuple[str, ...] = ()
    proxy: tuple[str, ...] = ()
    server: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "cdn": list(self.cdn),
            "waf": list(self.waf),
            "proxy": list(self.proxy),
            "server": list(self.server),
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class SecurityHeaders:
    present: dict[str, str] = field(default_factory=dict)
    missing: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"present": self.present, "missing": list(self.missing)}


@dataclass(frozen=True)
class ExposureInfo:
    """Passively observed, publicly reachable resources."""

    robots_txt: bool = False
    sitemap: bool = False
    security_txt: bool = False
    git_exposed: bool = False
    findings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "robots_txt": self.robots_txt,
            "sitemap": self.sitemap,
            "security_txt": self.security_txt,
            "git_exposed": self.git_exposed,
            "findings": list(self.findings),
        }


@dataclass
class ScanReport:
    """The full result of analyzing a single target."""

    url: str
    final_url: str | None = None
    status: int | None = None
    error: str | None = None
    technologies: list[Technology] = field(default_factory=list)
    infra: InfraInfo = field(default_factory=InfraInfo)
    security: SecurityHeaders = field(default_factory=SecurityHeaders)
    network: NetworkInfo | None = None
    tls: TlsInfo | None = None
    exposure: ExposureInfo | None = None

    def by_category(self) -> DetectedTech:
        grouped: dict[str, list[str]] = {}
        for tech in self.technologies:
            cats = tech.categories or ("uncategorized",)
            for cat in cats:
                grouped.setdefault(cat, [])
                if tech.name not in grouped[cat]:
                    grouped[cat].append(tech.name)
        return {cat: sorted(names) for cat, names in grouped.items()}

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "error": self.error,
            "technologies": [tech.to_dict() for tech in self.technologies],
            "infra": self.infra.to_dict(),
            "security": self.security.to_dict(),
            "network": self.network.to_dict() if self.network else None,
            "tls": self.tls.to_dict() if self.tls else None,
            "exposure": self.exposure.to_dict() if self.exposure else None,
        }


@dataclass(frozen=True)
class ScanTargetResult:
    """Backwards-compatible slim result (url/status/detected/error)."""

    url: str
    status: int | None
    detected: DetectedTech = field(default_factory=lambda: cast(DetectedTech, {}))
    error: str | None = None
