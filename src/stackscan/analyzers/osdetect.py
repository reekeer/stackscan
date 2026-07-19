from __future__ import annotations

from collections import Counter

from stackscan.types import OsFinding, ScanReport

_WINDOWS_SERVICES: frozenset[str] = frozenset(
    {
        "microsoft-iis",
        "ms-sql",
        "msrpc",
        "netbios",
        "ms-wbt",
        "ms-wbt-server",
        "wsman",
    }
)


def _is_windows_service(service: str | None) -> bool:
    if not service:
        return False
    lower = service.lower()
    return lower in _WINDOWS_SERVICES or lower.startswith("ms-")


def _normalize_os(name: str) -> str:
    lower = name.lower()
    if "win64" in lower or "win32" in lower or "windows" in lower:
        return "Windows"
    if "ubuntu" in lower:
        return "Ubuntu"
    if "debian" in lower:
        return "Debian"
    if "centos" in lower:
        return "CentOS"
    if "rhel/centos" in lower:
        return "RHEL/CentOS"
    if "rhel" in lower or "red hat" in lower:
        return "Red Hat"
    if "fedora" in lower:
        return "Fedora"
    if "amazon" in lower or "amzn" in lower:
        return "Amazon Linux"
    if "alpine" in lower:
        return "Alpine"
    if "rocky" in lower:
        return "Rocky Linux"
    if "alma" in lower:
        return "AlmaLinux"
    if "unix" in lower:
        return "Unix"
    return name.strip().title() if name else ""


def _collect_votes(report: ScanReport) -> dict[str, list[tuple[str, str]]]:
    votes: dict[str, list[tuple[str, str]]] = {}

    def add(host: str, os: str, source: str) -> None:
        if not host or not os:
            return
        normalized = _normalize_os(os)
        if not normalized:
            return
        votes.setdefault(host, []).append((normalized, source))

    primary_host = report.network.host if report.network else ""

    for software in report.software:
        if software.os:
            add(primary_host, software.os, software.source)

    if report.ports is not None:
        for port in report.ports.ports:
            if not port.host:
                continue
            if port.os:
                add(port.host, port.os, f"port {port.port}")
            if _is_windows_service(port.service):
                add(port.host, "Windows", f"port {port.port}")

    for site in report.site_findings:
        from stackscan.utils import host_of

        host = host_of(site.url)
        for software in site.software:
            if software.os:
                add(host, software.os, software.source)

    return votes


def detect_os(report: ScanReport) -> list[OsFinding]:
    votes = _collect_votes(report)
    findings: list[OsFinding] = []
    for host, pairs in votes.items():
        if not pairs:
            continue
        counter = Counter(os for os, _ in pairs)
        total = sum(counter.values())
        if not total:
            continue
        winner, winner_count = counter.most_common(1)[0]
        sources = ", ".join(sorted(set(src for os, src in pairs if os == winner)))
        by_source: dict[str, list[str]] = {}
        for os, src in pairs:
            by_source.setdefault(src, []).append(os)
        dominant_source = max(by_source, key=lambda s: len(by_source[s]))
        if dominant_source == "port-banner" or dominant_source.startswith(
            ("header:", "meta:", "script")
        ):
            category = "banner"
        elif dominant_source.startswith("port "):
            category = "network"
        else:
            category = "banner"
        service = dominant_source
        findings.append(
            OsFinding(
                host=host,
                os=winner,
                category=category,
                service=service,
                source=sources,
                confidence=winner_count / total,
            )
        )
    findings.sort(key=lambda f: (f.host, -f.confidence))
    return findings
