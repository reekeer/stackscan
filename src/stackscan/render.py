from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import urljoin

from rich.console import Console, Group, RenderableType
from rich.markup import escape
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


@lru_cache(maxsize=1)
def _glyphs() -> theme.Glyphs:
    return theme.glyphs(Console())


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


def _network_section(report: ScanReport) -> RenderableType | None:
    net = report.network
    rows: list[tuple[str, str, str]] = []
    host = net.host if net else host_of(report.url) or ""
    dns_ttl: dict[str, int] = net.dns_ttl if net else {}
    proxied_ips = {info.ip for info in report.ip_info if info.is_cdn}

    def add(rrtype: str, target: str, values: tuple[str, ...]) -> None:
        for value in values:
            rows.append((rrtype, target, value))

    def add_addr(rrtype: str, target: str, values: tuple[str, ...]) -> None:
        for value in values:
            if proxied_ips and value in proxied_ips:
                continue
            rows.append((rrtype, target, value))

    if net is not None:
        add_addr("A", host, _sorted_ips(net.ipv4))
        add_addr("AAAA", host, _sorted_ips(net.ipv6))
        add("CNAME", host, net.cname)
        add("MX", host, net.mx)
        add("NS", host, net.ns)
        add("TXT", host, net.txt)
        add("SOA", host, net.soa)
        add("CAA", host, net.caa)
        for rrtype in sorted(net.extras):
            add(rrtype, host, net.extras[rrtype])
        for ip, name in sorted(net.reverse_dns.items(), key=lambda x: _ip_sort_key(x[0])):
            rows.append(("PTR", ip, name))
        if net.geo:
            for ip, data in sorted(net.geo.items(), key=lambda x: _ip_sort_key(x[0])):
                rows.append(("Geo", ip, ", ".join(v for v in data.values() if v)))

    def _ip_rrtype(ip: str) -> str:
        try:
            parsed = ipaddress.ip_address(ip.split("%", 1)[0])
        except ValueError:
            return "A"
        return "AAAA" if isinstance(parsed, ipaddress.IPv6Address) else "A"

    for sub in sorted(report.subdomains, key=lambda s: s.name):
        if not sub.addresses:
            continue
        for ip in _sorted_ips(sub.addresses):
            if proxied_ips and ip in proxied_ips:
                continue
            rows.append((_ip_rrtype(ip), sub.name, ip))

    if not rows:
        return None

    table = Table(box=None, pad_edge=False)
    table.add_column("Type", style="bold cyan", no_wrap=True)
    table.add_column("Host", overflow="fold")
    table.add_column("Content", overflow="fold")
    table.add_column("TTL", justify="right", no_wrap=True)
    for rrtype, target, value in rows:
        ttl = ""
        if rrtype in dns_ttl:
            ttl = str(dns_ttl[rrtype])
        table.add_row(rrtype, escape(target), escape(value), ttl)
    return table


def _whois_section(report: ScanReport) -> RenderableType | None:
    whois = report.whois
    if whois is None:
        return None
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="bold cyan", no_wrap=True, justify="right")
    grid.add_column(overflow="fold")
    registrar = whois.registrar or ""
    if registrar and whois.registrar_url:
        registrar += f"  ·  {whois.registrar_url}"
    if registrar:
        grid.add_row("Registrar", escape(registrar))
    if whois.registrant_public and whois.registrant:
        grid.add_row("Registrant", Text(whois.registrant, style=theme.WARN))
    elif whois.privacy:
        grid.add_row("Registrant", Text(whois.privacy, style="dim"))
    dates: list[str] = []
    if whois.created:
        dates.append(f"registered {whois.created[:10]}")
    if whois.updated:
        dates.append(f"updated {whois.updated[:10]}")
    if whois.expires:
        dates.append(f"expires {whois.expires[:10]}")
    if dates:
        grid.add_row("Dates", escape("  ·  ".join(dates)))
    if whois.nameservers:
        grid.add_row("Nameservers", escape(", ".join(whois.nameservers)))
    if whois.dnssec:
        style = theme.SUCCESS if whois.dnssec == "signed" else theme.MUTED
        grid.add_row("DNSSEC", Text(whois.dnssec, style=style))
    if whois.statuses:
        shown = ", ".join(whois.statuses[:4])
        if len(whois.statuses) > 4:
            shown += f"  (+{len(whois.statuses) - 4})"
        grid.add_row("Status", Text(shown, style="dim"))
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
        grid.add_row("Issued by", escape(issued_by))
    expiry = _cert_expiry(tls.not_after)
    if expiry is not None:
        grid.add_row("Expires", expiry)
    if tls.not_before:
        grid.add_row("Issued", Text(tls.not_before, style=theme.MUTED))
    proto = " ".join(filter(None, (tls.protocol, tls.cipher)))
    if proto:
        grid.add_row("Cipher", escape(proto))
    if tls.alpn:
        grid.add_row("ALPN", escape(tls.alpn))
    if tls.subject_alt_names:
        sans = ", ".join(tls.subject_alt_names[:8])
        if len(tls.subject_alt_names) > 8:
            sans += f" (+{len(tls.subject_alt_names) - 8} more)"
        grid.add_row("SANs", escape(sans))
    if report.protocols:
        grid.add_row("HTTP", "  ·  ".join(report.protocols))
    if not grid.row_count:
        return None
    return grid


_GLOBAL_CATEGORIES: frozenset[str] = frozenset({"edge", "cdn", "waf", "proxy", "protocol"})


def _tech_section(report: ScanReport) -> RenderableType | None:
    all_techs = report.all_technologies()
    primary = host_of(report.url)
    # One group per (name, version, category): the same stack found on twenty subdomains is one
    # finding, not twenty rows — the hosts collapse into a list in its cell.
    groups: dict[tuple[str, str | None, str], _TechGroup] = {}
    order: list[tuple[str, str | None, str]] = []
    seen: set[tuple[str, str | None, str, str]] = set()

    def _add_row(name: str, version: str | None, category: str, host: str, confidence: int) -> None:
        global_cat = any(cat in _GLOBAL_CATEGORIES for cat in category.split(", "))
        host_cell = host or primary or "-"
        # Edge/CDN/protocol findings are a property of the site, not of one host, so they collapse to
        # a single entry keyed on the primary host regardless of where each header was seen.
        if global_cat:
            host_cell = primary or host_cell
        dedup = (name.lower(), version, category, host_cell)
        if dedup in seen:
            return
        seen.add(dedup)
        key = (name.lower(), version, category)
        group = groups.get(key)
        if group is None:
            group = _TechGroup(name=name, version=version, category=category)
            groups[key] = group
            order.append(key)
        group.add(host_cell, confidence)

    for tech in all_techs:
        category = ", ".join(tech.categories) if tech.categories else "uncategorized"
        _add_row(tech.name, tech.version, category, tech.location, tech.confidence)

    all_software = list(report.software)
    for site in report.site_findings:
        all_software.extend(site.software)
    for sw in all_software:
        _add_row(sw.name, sw.version, "software", sw.location, 100)

    if not groups:
        return None

    order.sort(key=lambda k: (k[2].lower(), k[0].lower(), _version_key(k[1] or "")))

    table = Table(box=None, pad_edge=False)
    table.add_column("Name", style="bold cyan", overflow="fold")
    table.add_column("Version", overflow="fold")
    table.add_column("Category", style="bold magenta", no_wrap=True)
    table.add_column("Host", overflow="fold")
    table.add_column("Conf", justify="right", no_wrap=True)
    for key in order:
        group = groups[key]
        table.add_row(
            escape(group.name),
            escape(group.version or "-"),
            escape(group.category),
            escape(group.hosts_cell(primary)),
            group.conf_cell(),
        )
    return table


@dataclass
class _TechGroup:
    name: str
    version: str | None
    category: str
    _hosts: list[str] = field(default_factory=list[str])
    _seen: set[str] = field(default_factory=set[str])
    _min_conf: int = 100
    _max_conf: int = 0

    def add(self, host: str, confidence: int) -> None:
        if host not in self._seen:
            self._seen.add(host)
            self._hosts.append(host)
        self._min_conf = min(self._min_conf, confidence)
        self._max_conf = max(self._max_conf, confidence)

    def hosts_cell(self, primary: str) -> str:
        # Primary host first, then the rest alphabetically, one per line.
        rest = sorted(h for h in self._hosts if h != primary)
        ordered = ([primary] if primary in self._hosts else []) + rest
        return "\n".join(ordered) if ordered else "-"

    def conf_cell(self) -> str:
        if self._min_conf == self._max_conf:
            return f"{self._max_conf}%"
        return f"{self._min_conf}-{self._max_conf}%"


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
    # Only show meaningful service findings (admin panels, databases, etc.).
    # Generic "service" kinds derived from technologies already live in the
    # Technologies & Software table.
    tech_services = [
        s for s in report.services if not s.evidence.startswith("port ") and s.kind != "service"
    ]
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
            escape(port.host or "-"),
            escape(_service_cell(product, port.service)),
            _sev_text(severity),
        )
    for svc in tech_services:
        table.add_row("-", "-", escape(_service_cell(svc.name, svc.kind)), _sev_text(svc.severity))

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
    table.add_column("Summary", overflow="fold")
    for cve in report.cves:
        affects = f"{cve.product} {cve.version}" if cve.version else cve.product
        if cve.unconfirmed:
            affects += " · unconfirmed"
        where = _fmt_locations(cve.locations) or _fmt_locations(cve.sources)
        summary = cve.summary if len(cve.summary) <= 160 else cve.summary[:157] + "..."
        if cve.caveat:
            summary = f"{cve.caveat} — {summary}"
        table.add_row(
            _severity_text(cve),
            escape(cve.id),
            escape(affects),
            escape(where),
            escape(summary),
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
        org = escape(info.org or info.isp or "-")
        if info.is_cdn:
            org = f"{org} [dim](CDN/proxy)[/dim]"
        table.add_row(
            escape(info.ip),
            escape(location),
            org,
            escape(info.asn or "-"),
            escape(info.source or "-"),
        )
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
        table.add_row(
            escape(finding.target), label, escape(f"{finding.service} — {finding.detail}")
        )
    return table


def _secrets_section(report: ScanReport) -> RenderableType | None:
    if not report.secrets:
        return None
    table = Table(box=None, pad_edge=False, expand=True)
    table.add_column("Type", style="bold cyan", no_wrap=True)
    table.add_column("Value", overflow="fold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Location", overflow="fold")
    for secret in sorted(report.secrets, key=lambda s: s.severity):
        color = theme.SEVERITY.get(secret.severity.upper(), theme.MUTED)
        table.add_row(
            escape(secret.name),
            escape(secret.value),
            Text(f" {secret.severity.upper()} ", style=f"bold {color}"),
            escape(secret.location or "-"),
        )
    return table


def _takeovers_section(report: ScanReport) -> RenderableType | None:
    if not report.takeovers:
        return None
    table = Table(box=None, pad_edge=False, expand=True)
    table.add_column("Subdomain", style="bold cyan", overflow="fold")
    table.add_column("Service", overflow="fold")
    table.add_column("CNAME", overflow="fold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Evidence", overflow="fold")
    for takeover in sorted(report.takeovers, key=lambda t: (t.verified, t.severity), reverse=True):
        color = theme.SEVERITY.get(takeover.severity.upper(), theme.MUTED)
        verified = "verified" if takeover.verified else "potential"
        table.add_row(
            escape(takeover.subdomain),
            escape(takeover.service),
            escape(takeover.cname),
            Text(f" {takeover.severity.upper()} ", style=f"bold {color}"),
            escape(f"{takeover.evidence} ({verified})"),
        )
    return table


def _subdomains_section(report: ScanReport) -> RenderableType | None:
    if not report.subdomains:
        return None
    table = Table(box=None, pad_edge=False)
    table.add_column("Subdomain", style="bold cyan", overflow="fold")
    table.add_column("Addresses", overflow="fold")
    table.add_column("Source", style="dim", no_wrap=True)
    show_real = bool(report.real_ips)
    if show_real:
        table.add_column("Real IP", style="bold green", no_wrap=True)
    for sub in report.subdomains:
        if report.hide_unresolved and not sub.addresses:
            continue
        addrs = ", ".join(sub.addresses) if sub.addresses else "(no A record)"
        real = [ip for ip in sub.addresses if ip in report.real_ips]
        real_cell = ", ".join(real) if real else "-"
        if show_real:
            table.add_row(escape(sub.name), escape(addrs), escape(sub.source), escape(real_cell))
        else:
            table.add_row(escape(sub.name), escape(addrs), escape(sub.source))
    return table if table.row_count else None


def _social_section(report: ScanReport) -> RenderableType | None:
    if not report.social:
        return None
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="bold cyan", no_wrap=True, justify="right")
    grid.add_column(overflow="fold")
    by_platform: dict[str, list[str]] = {}
    for link in report.social:
        by_platform.setdefault(link.platform, []).append(link.url)
    for platform in sorted(by_platform):
        links = ", ".join(dict.fromkeys(by_platform[platform]))
        grid.add_row(platform, Text(links, style=theme.ACCENT))
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
    ("Registration (WHOIS)", _whois_section),
    ("IP intelligence", _ipinfo_section),
    ("TLS / Protocol", _tls_section),
    ("Technologies & Software", _tech_section),
    ("Vulnerabilities (CVE)", _cve_section),
    ("Services & open ports", _services_section),
    ("Default creds / open devices", _creds_section),
    ("Secrets & leaks", _secrets_section),
    ("Subdomain takeovers", _takeovers_section),
    ("Subdomains", _subdomains_section),
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
    left = f"[bold]{escape(report.final_url or report.url)}[/bold]"
    if ips:
        left += f"\n[dim]{escape(', '.join(ips))}[/dim]"
    header.add_row(left, right)
    blocks: list[RenderableType] = [header]
    if report.error:
        blocks.append(Text(f"error: {report.error}", style="red"))
    worst = _worst_severity(report)
    section = _glyphs().section
    for title, builder in _SECTIONS:
        rendered = builder(report)
        if rendered is None:
            continue
        blocks.append(Text())
        blocks.append(Text(f"{section} {title}", style="bold"))
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
