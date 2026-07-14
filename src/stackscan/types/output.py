from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TypeAlias

DetectedTech: TypeAlias = dict[str, list[str]]


@dataclass(frozen=True)
class Technology:
    name: str
    categories: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    location: str = ""
    confidence: int = 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "categories": list(self.categories),
            "evidence": list(self.evidence),
            "location": self.location,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class NetworkInfo:
    host: str
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    cname: tuple[str, ...] = ()
    mx: tuple[str, ...] = ()
    ns: tuple[str, ...] = ()
    txt: tuple[str, ...] = ()
    soa: tuple[str, ...] = ()
    caa: tuple[str, ...] = ()
    reverse_dns: dict[str, str] = field(default_factory=dict[str, str])
    geo: dict[str, dict[str, str]] = field(default_factory=dict[str, dict[str, str]])
    domains: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "ipv4": list(self.ipv4),
            "ipv6": list(self.ipv6),
            "cname": list(self.cname),
            "mx": list(self.mx),
            "ns": list(self.ns),
            "txt": list(self.txt),
            "soa": list(self.soa),
            "caa": list(self.caa),
            "reverse_dns": self.reverse_dns,
            "geo": self.geo,
            "domains": list(self.domains),
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
    alpn: str | None = None
    trusted: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "subject_alt_names": list(self.subject_alt_names),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "protocol": self.protocol,
            "cipher": self.cipher,
            "alpn": self.alpn,
            "trusted": self.trusted,
        }


@dataclass(frozen=True)
class InfraInfo:
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
    present: dict[str, str] = field(default_factory=dict[str, str])
    missing: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"present": self.present, "missing": list(self.missing)}


@dataclass(frozen=True)
class ExposureInfo:
    robots_txt: bool = False
    sitemap: bool = False
    security_txt: bool = False
    git_exposed: bool = False
    findings: tuple[str, ...] = ()
    urls: dict[str, str] = field(default_factory=dict[str, str])

    def to_dict(self) -> dict[str, Any]:
        return {
            "robots_txt": self.robots_txt,
            "sitemap": self.sitemap,
            "security_txt": self.security_txt,
            "git_exposed": self.git_exposed,
            "findings": list(self.findings),
            "urls": self.urls,
        }


@dataclass(frozen=True)
class Software:
    name: str
    version: str | None = None
    source: str = ""
    location: str = ""
    os: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "location": self.location,
            "os": self.os,
        }


@dataclass(frozen=True)
class CveMatch:
    id: str
    product: str
    version: str | None
    severity: str
    cvss: float | None
    confidence: int
    summary: str
    url: str | None = None
    locations: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    unconfirmed: bool = False
    caveat: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "product": self.product,
            "version": self.version,
            "severity": self.severity,
            "cvss": self.cvss,
            "confidence": self.confidence,
            "summary": self.summary,
            "url": self.url,
            "locations": list(self.locations),
            "sources": list(self.sources),
            "unconfirmed": self.unconfirmed,
            "caveat": self.caveat,
        }


@dataclass(frozen=True)
class Port:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    host: str | None = None
    os: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "host": self.host,
            "os": self.os,
        }


@dataclass(frozen=True)
class PortScan:
    scanner: str
    ports: tuple[Port, ...] = ()
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "ports": [port.to_dict() for port in self.ports],
            "note": self.note,
        }


@dataclass(frozen=True)
class Subdomain:
    name: str
    addresses: tuple[str, ...] = ()
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "addresses": list(self.addresses), "source": self.source}


@dataclass(frozen=True)
class IpInfo:
    ip: str
    country: str | None = None
    city: str | None = None
    org: str | None = None
    isp: str | None = None
    asn: str | None = None
    is_cdn: bool = False
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "country": self.country,
            "city": self.city,
            "org": self.org,
            "isp": self.isp,
            "asn": self.asn,
            "is_cdn": self.is_cdn,
            "source": self.source,
        }


@dataclass(frozen=True)
class CredFinding:
    target: str
    service: str
    kind: str
    detail: str = ""
    username: str | None = None
    password: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "service": self.service,
            "kind": self.kind,
            "detail": self.detail,
            "username": self.username,
            "password": self.password,
        }


@dataclass(frozen=True)
class SiteFinding:
    url: str
    final_url: str | None = None
    status: int | None = None
    error: str | None = None
    technologies: list[Technology] = field(default_factory=list[Technology])
    software: list[Software] = field(default_factory=list[Software])
    infra: InfraInfo = field(default_factory=InfraInfo)
    security: SecurityHeaders = field(default_factory=SecurityHeaders)
    exposure: ExposureInfo | None = None
    protocols: list[str] = field(default_factory=list[str])

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "error": self.error,
            "technologies": [tech.to_dict() for tech in self.technologies],
            "software": [sw.to_dict() for sw in self.software],
            "infra": self.infra.to_dict(),
            "security": self.security.to_dict(),
            "exposure": self.exposure.to_dict() if self.exposure else None,
            "protocols": list(self.protocols),
        }


@dataclass(frozen=True)
class ServiceFinding:
    name: str
    kind: str
    evidence: str
    severity: str = "INFO"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "evidence": self.evidence,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class SocialLink:
    platform: str
    url: str
    handle: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"platform": self.platform, "url": self.url, "handle": self.handle}


@dataclass(frozen=True)
class BruteTarget:
    host: str
    port: int
    tls: bool = False
    service: str = ""
    is_camera: bool = False

    @property
    def target(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def url(self) -> str:
        scheme = "https" if self.tls else "http"
        return f"{scheme}://{self.host}:{self.port}/"


@dataclass
class ScanReport:
    url: str
    final_url: str | None = None
    status: int | None = None
    error: str | None = None
    elapsed: float | None = None
    technologies: list[Technology] = field(default_factory=list[Technology])
    infra: InfraInfo = field(default_factory=InfraInfo)
    security: SecurityHeaders = field(default_factory=SecurityHeaders)
    network: NetworkInfo | None = None
    tls: TlsInfo | None = None
    exposure: ExposureInfo | None = None
    software: list[Software] = field(default_factory=list[Software])
    cves: list[CveMatch] = field(default_factory=list[CveMatch])
    ports: PortScan | None = None
    subdomains: list[Subdomain] = field(default_factory=list[Subdomain])
    ip_info: list[IpInfo] = field(default_factory=list[IpInfo])
    creds: list[CredFinding] = field(default_factory=list[CredFinding])
    protocols: list[str] = field(default_factory=list[str])
    site_findings: list[SiteFinding] = field(default_factory=list[SiteFinding])
    services: list[ServiceFinding] = field(default_factory=list[ServiceFinding])
    social: list[SocialLink] = field(default_factory=list[SocialLink])
    brute_targets: list[BruteTarget] = field(default_factory=list[BruteTarget])

    def by_category(self) -> DetectedTech:
        grouped: dict[str, list[str]] = {}
        for tech in self.technologies:
            cats = tech.categories or ("uncategorized",)
            for cat in cats:
                grouped.setdefault(cat, [])
                if tech.name not in grouped[cat]:
                    grouped[cat].append(tech.name)
        return {cat: sorted(names) for cat, names in grouped.items()}

    def all_technologies(self) -> list[Technology]:
        techs: list[Technology] = list(self.technologies)
        for site in self.site_findings:
            techs.extend(site.technologies)
        return techs

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "error": self.error,
            "elapsed": self.elapsed,
            "technologies": [tech.to_dict() for tech in self.technologies],
            "infra": self.infra.to_dict(),
            "security": self.security.to_dict(),
            "network": self.network.to_dict() if self.network else None,
            "tls": self.tls.to_dict() if self.tls else None,
            "exposure": self.exposure.to_dict() if self.exposure else None,
            "software": [item.to_dict() for item in self.software],
            "cves": [cve.to_dict() for cve in self.cves],
            "ports": self.ports.to_dict() if self.ports else None,
            "subdomains": [sub.to_dict() for sub in self.subdomains],
            "ip_info": [info.to_dict() for info in self.ip_info],
            "creds": [finding.to_dict() for finding in self.creds],
            "protocols": list(self.protocols),
            "site_findings": [site.to_dict() for site in self.site_findings],
            "services": [service.to_dict() for service in self.services],
            "social": [link.to_dict() for link in self.social],
        }
