from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import urljoin

from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from stackscan import __version__, theme
from stackscan.analyzers import port_category
from stackscan.types import CveMatch, IpInfo, ScanReport
from stackscan.utils import host_of

_SectionBuilder = Callable[[ScanReport], "RenderableType | None"]
_LABEL = f"bold {theme.ACCENT}"
_HEADER = f"bold {theme.ACCENT_2}"
BANNER = "\n ____  ____  __    ___  __ _  ____   ___   __   __ _\n/ ___)(_  _)/ _\\  / __)(  / )/ ___) / __) / _\\ (  ( \\\n\\___ \\  )( /    \\( (__  )  ( \\___ \\( (__ /    \\/    /\n(____/ (__)\\_/\\_/ \\___)(__\\_)(____/ \\___)\\_/\\_/\\_)__)"


def render_banner(console: Console) -> None:
    console.print(Text(BANNER, style=f"bold {theme.ACCENT}"), highlight=False)
    console.print(
        Text(
            f"Created by reekeer · https://github.com/reekeer/stackscan · {__version__}",
            style=f"dim {theme.ACCENT}",
        ),
        highlight=False,
    )


def _severity_text(cve: CveMatch) -> Text:
    color = theme.SEVERITY.get(cve.severity.upper(), theme.MUTED)
    label = cve.severity.upper()
    if cve.cvss is not None:
        label = f"{label} {cve.cvss:.1f}"
    if cve.severity.upper() == "CRITICAL" and not cve.unconfirmed:
        return Text(f" {label} ", style=f"bold white on {theme.DANGER}")
    return Text(f" {label} ", style=f"bold {color}")


def _fmt_elapsed(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.2f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}m {secs}s ({seconds:.0f}s)"


def _version_key(version: str) -> tuple[tuple[int, str], ...]:

    parts: list[tuple[int, str]] = []
    for chunk in re.split(r"[.\-_]", version.strip()):
        match = re.match(r"(\d*)(.*)", chunk)
        number = int(match.group(1)) if match and match.group(1) else 0
        suffix = (match.group(2) if match else "").lower()
        parts.append((number, suffix))
    return tuple(parts)


def _ip_sort_key(ip: str) -> tuple[int, ...]:
    try:
        import ipaddress

        return (0, int(ipaddress.ip_address(ip.split("%", 1)[0])))
    except ValueError:
        return (1, 0)


def _sorted_ips(ips: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(ips, key=_ip_sort_key))


def _confidence_bar(pct: int) -> Text:
    filled = round(pct / 10)
    bar = "█" * filled + "░" * (10 - filled)
    if pct >= 80:
        color = theme.SUCCESS
    elif pct >= 50:
        color = theme.WARN
    else:
        color = theme.DANGER
    return Text(f"{bar} {pct}%", style=color)


def _network_section(report: ScanReport) -> RenderableType | None:
    net = report.network
    if net is None:
        return None
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="bold cyan", no_wrap=True, justify="right")
    grid.add_column(overflow="fold")

    def row(label: str, values: tuple[str, ...]) -> None:
        if values:
            grid.add_row(label, ", ".join(values))

    row("IPv4", _sorted_ips(net.ipv4))
    row("IPv6", _sorted_ips(net.ipv6))
    row("CNAME", net.cname)
    if net.reverse_dns:
        grid.add_row("PTR", ", ".join((f"{ip} -> {name}" for ip, name in net.reverse_dns.items())))
    row("MX", net.mx)
    row("NS", net.ns)
    row("TXT", net.txt)
    row("SOA", net.soa)
    row("CAA", net.caa)
    if net.domains:
        grid.add_row("Domains", ", ".join(sorted(set(net.domains))))
    if net.geo:
        parts = [f"{ip}: {', '.join(v for v in data.values())}" for ip, data in net.geo.items()]
        grid.add_row("Geo", "; ".join(parts))
    if not grid.row_count:
        return None
    return grid


def _infra_section(report: ScanReport) -> RenderableType | None:
    infra = report.infra
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="bold cyan", no_wrap=True, justify="right")
    grid.add_column(overflow="fold")
    if infra.cdn:
        grid.add_row("CDN", ", ".join(infra.cdn))
    if infra.waf:
        grid.add_row("WAF", Text(", ".join(infra.waf), style="green"))
    if infra.server:
        grid.add_row("Server", ", ".join(infra.server))
    if infra.proxy:
        grid.add_row("Proxy", ", ".join(infra.proxy))
    for note in infra.notes:
        grid.add_row("Note", Text(note, style="dim"))
    if not grid.row_count:
        return None
    return grid


_ACME_CAS: tuple[str, ...] = (
    "let's encrypt",
    "lets encrypt",
    "zerossl",
    "buypass",
    "google trust services",
    "actalis free",
)
_COMMERCIAL_CAS: tuple[str, ...] = (
    "digicert",
    "globalsign",
    "sectigo",
    "comodo",
    "godaddy",
    "entrust",
    "thawte",
    "geotrust",
    "rapidssl",
    "certum",
    "starfield",
    "network solutions",
)


def _issuer_org(issuer: str) -> str:

    fields = dict(part.split("=", 1) for part in issuer.split(", ") if "=" in part)
    return (
        fields.get("organizationName")
        or fields.get("O")
        or fields.get("commonName")
        or fields.get("CN")
        or issuer
    ).strip()


def _ca_kind(issuer: str) -> str | None:
    blob = issuer.lower()
    if any(ca in blob for ca in _ACME_CAS):
        return "ACME (free / auto-renewed)"
    if "amazon" in blob:
        return "Amazon ACM (free, AWS)"
    if any(ca in blob for ca in _COMMERCIAL_CAS):
        return "commercial (purchased)"
    return None


def _cert_expiry(not_after: str | None) -> Text | None:
    if not not_after:
        return None
    import ssl
    import time

    try:
        remaining = ssl.cert_time_to_seconds(not_after) - time.time()
    except (ValueError, OverflowError):
        return Text(not_after)
    days = int(remaining // 86400)
    if days < 0:
        return Text(f"{not_after}  ({-days}d EXPIRED)", style=f"bold {theme.DANGER}")
    if days <= 21:
        return Text(f"{not_after}  (expires in {days}d)", style=theme.WARN)
    return Text(f"{not_after}  (in {days}d)")


def _tls_section(report: ScanReport) -> RenderableType | None:
    tls = report.tls
    if tls is None:
        return None
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="bold cyan", no_wrap=True, justify="right")
    grid.add_column(overflow="fold")
    if not tls.trusted:
        grid.add_row(
            "Trust",
            Text("⚠ self-signed / untrusted certificate", style=f"bold {theme.WARN}"),
        )
    if tls.issuer:
        ca_kind = _ca_kind(tls.issuer)
        issued_by = _issuer_org(tls.issuer)
        if ca_kind:
            issued_by += f"  ·  {ca_kind}"
        grid.add_row("Issued by", issued_by)
    expiry = _cert_expiry(tls.not_after)
    if expiry is not None:
        grid.add_row("Expires", expiry)
    if tls.not_before:
        grid.add_row("Issued", Text(tls.not_before, style=theme.MUTED))
    proto = " ".join(filter(None, (tls.protocol, tls.cipher)))
    if proto:
        grid.add_row("Cipher", proto)
    if tls.alpn:
        grid.add_row("ALPN", tls.alpn)
    if tls.subject_alt_names:
        sans = ", ".join(tls.subject_alt_names[:8])
        if len(tls.subject_alt_names) > 8:
            sans += f" (+{len(tls.subject_alt_names) - 8} more)"
        grid.add_row("SANs", sans)
    if report.protocols:
        grid.add_row("HTTP", "  ·  ".join(report.protocols))
    if not grid.row_count:
        return None
    return grid


def _tech_section(report: ScanReport) -> RenderableType | None:

    grouped = report.by_category()

    ordered = sorted(
        report.software, key=lambda sw: (sw.name.lower(), _version_key(sw.version or ""))
    )
    software = [f"{sw.name} {sw.version}" if sw.version else sw.name for sw in ordered]
    software = list(dict.fromkeys(software))
    if not grouped and not software:
        return None
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="bold magenta", no_wrap=True, justify="right")
    grid.add_column(overflow="fold")
    for category in sorted(grouped):
        labels: list[str] = []
        for tech in report.technologies:
            if category in (tech.categories or ("uncategorized",)):
                label = tech.name
                if tech.version:
                    label += f" v{tech.version}"
                if tech.location and tech.location != host_of(report.url):
                    label += f" @{tech.location}"
                label += f" [{theme.MUTED}]({tech.confidence}%)[/]"
                labels.append(label)
        grid.add_row(category, ", ".join(sorted(set(labels))))
    if software:
        grid.add_row("versions", ", ".join(software))
    return grid


def _sev_text(severity: str) -> Text:
    color = theme.SEVERITY.get(severity.upper(), theme.MUTED)
    return Text(f" {severity.upper()} ", style=f"bold {color}")


def _service_cell(product: str, service: str | None) -> str:

    name = (service or "").strip()
    if product and name:
        return f"{product} ({name})"
    return product or name or "-"


def _services_section(report: ScanReport) -> RenderableType | None:

    ports = report.ports.ports if report.ports else ()
    tech_services = [s for s in report.services if not s.evidence.startswith("port ")]
    if not ports and not tech_services:
        if report.ports is not None:
            return Text(f"no services found ({report.ports.scanner})", style="dim")
        return None

    table = Table(box=None, pad_edge=False)
    table.add_column("Port", style="bold cyan", justify="right", no_wrap=True)
    table.add_column("IP / Host", overflow="fold")
    table.add_column("Service", overflow="fold")
    table.add_column("Risk", no_wrap=True)

    ordered_ports = sorted(ports, key=lambda p: (p.port, _ip_sort_key(p.host or "")))
    for port in ordered_ports:
        _category, severity = port_category(port.port, port.service, port.state)
        product = " ".join(filter(None, (port.product, port.version)))
        table.add_row(
            f"{port.port}/{port.protocol}",
            port.host or "-",
            _service_cell(product, port.service),
            _sev_text(severity),
        )
    for svc in tech_services:
        table.add_row("-", "-", _service_cell(svc.name, svc.kind), _sev_text(svc.severity))

    if report.ports is not None:
        return Group(table, Text(f"via {report.ports.scanner}", style="dim"))
    return table


def _fmt_locations(locations: tuple[str, ...]) -> str:
    if not locations:
        return "-"
    shown = ", ".join(locations[:2])
    if len(locations) > 2:
        shown += f" +{len(locations) - 2}"
    return shown


def _cve_section(report: ScanReport) -> RenderableType | None:
    if not report.cves:
        return None
    table = Table(box=None, expand=True, pad_edge=False)
    table.add_column("Severity", no_wrap=True)
    table.add_column("CVE", style="bold", no_wrap=True)
    table.add_column("Affects", no_wrap=True)
    table.add_column("Where", overflow="fold")
    table.add_column("Source", overflow="fold")
    table.add_column("Confidence", no_wrap=True)
    table.add_column("Summary", overflow="fold")
    for cve in report.cves:
        affects = f"{cve.product} {cve.version}" if cve.version else cve.product
        if cve.unconfirmed:
            affects += "  ·  unconfirmed · version-only"
        summary = cve.summary if len(cve.summary) <= 80 else cve.summary[:77] + "..."
        if cve.caveat:
            summary = f"{cve.caveat} — {summary}"
        table.add_row(
            _severity_text(cve),
            cve.id,
            affects,
            _fmt_locations(cve.locations),
            _fmt_locations(cve.sources),
            _confidence_bar(cve.confidence),
            summary,
        )
    return table


def _ipinfo_section(report: ScanReport) -> RenderableType | None:
    if not report.ip_info:
        return None

    unique: dict[str, IpInfo] = {}
    for info in report.ip_info:
        unique.setdefault(info.ip, info)
    ordered = sorted(unique.values(), key=lambda i: _ip_sort_key(i.ip))

    table = Table(box=None, pad_edge=False)
    table.add_column("IP", style="bold cyan", no_wrap=True)
    table.add_column("Location", overflow="fold")
    table.add_column("Org / ISP", overflow="fold")
    table.add_column("ASN", no_wrap=True)
    table.add_column("Source", overflow="fold")
    for info in ordered:
        location = ", ".join(v for v in (info.city, info.country) if v) or "-"
        org = info.org or info.isp or "-"
        if info.is_cdn:
            org = f"{org} [dim](CDN/proxy)[/dim]"
        table.add_row(info.ip, location, org, info.asn or "-", info.source or "-")
    return table


def _creds_section(report: ScanReport) -> RenderableType | None:
    if not report.creds:
        return None
    table = Table(box=None, pad_edge=False, expand=True)
    table.add_column("Target", style="bold cyan", no_wrap=True)
    table.add_column("Finding", no_wrap=True)
    table.add_column("Detail", overflow="fold")
    for finding in report.creds:
        if finding.kind == "default-creds":
            label = Text(
                f" DEFAULT CREDS {finding.username}:{finding.password} ", style="bold white on red"
            )
        elif finding.kind == "open-no-auth":
            label = Text(" OPEN / NO AUTH ", style="bold white on red")
        else:
            label = Text("auth required", style="dim")
        table.add_row(finding.target, label, f"{finding.service} — {finding.detail}")
    return table


def _subdomains_section(report: ScanReport) -> RenderableType | None:
    if not report.subdomains:
        return None
    table = Table(box=None, pad_edge=False)
    table.add_column("Subdomain", style="bold cyan", overflow="fold")
    table.add_column("Addresses", overflow="fold")
    table.add_column("Source", style="dim", no_wrap=True)
    for sub in report.subdomains:
        addrs = ", ".join(sub.addresses) if sub.addresses else "(no A record)"
        table.add_row(sub.name, addrs, sub.source)
    return table


def _os_section(report: ScanReport) -> RenderableType | None:
    if not report.os_findings:
        return None
    table = Table(box=None, pad_edge=False)
    table.add_column("Host", style="bold cyan", overflow="fold")
    table.add_column("OS", overflow="fold")
    table.add_column("Service", overflow="fold")
    table.add_column("Category", overflow="fold")
    table.add_column("Source", overflow="fold")
    for finding in report.os_findings:
        table.add_row(
            finding.host,
            finding.os,
            finding.service,
            finding.category,
            f"{finding.source}  ({int(finding.confidence * 100)}%)",
        )
    return table


def _social_section(report: ScanReport) -> RenderableType | None:
    if not report.social:
        return None
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="bold cyan", no_wrap=True, justify="right")
    grid.add_column(overflow="fold")
    by_platform: dict[str, list[str]] = {}
    for link in report.social:
        by_platform.setdefault(link.platform, []).append(link.handle or link.url)
    for platform in sorted(by_platform):
        grid.add_row(platform, ", ".join(dict.fromkeys(by_platform[platform])))
    return grid


def _security_section(report: ScanReport) -> RenderableType | None:
    sec = report.security
    if not sec.present and (not sec.missing):
        return None
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="bold cyan", no_wrap=True, justify="right")
    grid.add_column(overflow="fold")
    if sec.present:
        grid.add_row("Present", Text(", ".join(sorted(sec.present)), style="green"))
    if sec.missing:
        grid.add_row("Missing", Text(", ".join(sec.missing), style="red"))
    return grid


def _exposure_section(report: ScanReport) -> RenderableType | None:
    exp = report.exposure
    if exp is None:
        return None
    base = report.final_url or report.url

    def url_for(resource: str, path: str) -> str:
        return exp.urls.get(resource) or urljoin(base, path)

    rows: list[tuple[str, str, str]] = []
    if exp.git_exposed:
        rows.append((".git EXPOSED", url_for(".git/HEAD", "/.git/HEAD"), "danger"))
    if exp.robots_txt:
        rows.append(("robots.txt", url_for("robots.txt", "/robots.txt"), "ok"))
    if exp.sitemap:
        rows.append(("sitemap.xml", url_for("sitemap.xml", "/sitemap.xml"), "ok"))
    if exp.security_txt:
        rows.append(("security.txt", url_for("security.txt", "/.well-known/security.txt"), "ok"))
    if not rows:
        return None

    grid = Table.grid(padding=(0, 2))
    grid.add_column(no_wrap=True)
    grid.add_column(overflow="fold")
    for label, url, kind in rows:
        style = "bold white on red" if kind == "danger" else "bold cyan"
        grid.add_row(Text(label, style=style), Text(url, style="dim"))
    return grid


_SECTIONS: tuple[tuple[str, _SectionBuilder], ...] = (
    ("Network / DNS", _network_section),
    ("IP intelligence", _ipinfo_section),
    ("Infrastructure", _infra_section),
    ("TLS / Protocol", _tls_section),
    ("Technologies & Software", _tech_section),
    ("Vulnerabilities (CVE)", _cve_section),
    ("Services & open ports", _services_section),
    ("Hosts & OS", _os_section),
    ("Default creds / open devices", _creds_section),
    ("Subdomains", _subdomains_section),
    ("Security headers", _security_section),
    ("Exposure", _exposure_section),
    ("Social & contacts", _social_section),
)


def _report_panel(report: ScanReport) -> Panel:
    status = f"[green]{report.status}[/green]" if report.status else "[red]—[/red]"
    header = Table.grid(expand=True)
    header.add_column(overflow="fold")
    header.add_column(justify="right", no_wrap=True)
    right = f"status {status}"
    if report.elapsed is not None:
        right += f"  ·  [cyan]{_fmt_elapsed(report.elapsed)}[/cyan]"
    ips: list[str] = []
    if report.network is not None:
        ips.extend(report.network.ipv4)
        ips.extend(report.network.ipv6)
    left = f"[bold]{report.final_url or report.url}[/bold]"
    if ips:
        left += f"\n[dim]{', '.join(ips)}[/dim]"
    header.add_row(left, right)
    blocks: list[RenderableType] = [header]
    if report.error:
        blocks.append(Text(f"error: {report.error}", style="red"))
    worst = _worst_severity(report)
    for title, builder in _SECTIONS:
        rendered = builder(report)
        if rendered is None:
            continue
        blocks.append(Text())
        blocks.append(Text(f"▸ {title}", style="bold"))
        blocks.append(rendered)
    danger = worst in ("CRITICAL", "HIGH") or any(
        f.kind in ("default-creds", "open-no-auth") for f in report.creds
    )
    border = theme.DANGER if danger else theme.ACCENT
    return Panel(Group(*blocks), border_style=border, padding=(1, 2))


def _is_unreachable(report: ScanReport) -> bool:
    return bool(report.error) and report.status is None and (not _has_findings(report))


def _unreachable_line(report: ScanReport) -> Text:
    line = Text()
    line.append(" [x] ", style=f"bold {theme.DANGER}")
    line.append(report.url, style="bold")
    line.append("  —  site unavailable", style=theme.MUTED)
    return line


def _worst_severity(report: ScanReport) -> str | None:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    present = {cve.severity.upper() for cve in report.cves if not cve.unconfirmed}
    for level in order:
        if level in present:
            return level
    return None


def _has_findings(report: ScanReport) -> bool:
    return bool(
        report.technologies
        or report.infra.server
        or report.infra.cdn
        or report.cves
        or (report.ports and report.ports.ports)
        or report.subdomains
        or report.ip_info
        or report.creds
        or (report.network and (report.network.ipv4 or report.network.ipv6))
    )


def render_reports(reports: list[ScanReport], console: Console, *, show_empty: bool) -> None:
    for report in reports:
        if _is_unreachable(report):
            console.print(_unreachable_line(report))
            continue
        if not show_empty and (not _has_findings(report)) and (not report.error):
            continue
        console.print(_report_panel(report))
