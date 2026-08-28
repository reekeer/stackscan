"""How stackscan presents itself when reekeer is the host.

Standalone, stackscan owns the terminal: banner, window title, its own rich panels. Inside the reekeer
shell it is one command among many, and forty tools each drawing their own boxes stop looking like one
program. So there the scan is handed back as **data** and reekeer renders it in the shell's own style —
same palette, same glyphs, same column widths as every other command in it.

`cli.py` picks between the two on `reekeer.is_reekeer`; nothing in this module runs standalone.

The shape is reekeer's document schema: a title, a status line, a list of sections each carrying one
body (`fields`, `rows` with `columns`, or `lines`), and notes with a severity level.

Two directions, both of them declared here. `document` is what comes *back* from a scan. `form` is what
goes *in*: which of stackscan's flags a reekeer window should draw as controls, since the manifest
declares no arguments and argparse below keeps ownership of all of them.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypeVar

from stackscan import __version__
from stackscan.types import CveMatch, ScanReport
from stackscan.utils import host_of

_F = TypeVar("_F", bound=Callable[..., Any])

# `reekeer.gui` is put on `sys.path` by the shell at runtime and is deliberately not a dependency —
# stackscan is a tool that happens to mount inside reekeer, not a plugin that needs it to be built or
# tested. So the types are declared here and the import is done for real below: a bare `try/import`
# leaves the decorator untyped, and an untyped decorator makes a strict checker discard the signature
# of everything under it.
if TYPE_CHECKING:

    def fields(function: _F) -> _F: ...

    Arg: Any = None
else:
    try:
        from reekeer.gui import Arg, fields
    except ImportError:  # pragma: no cover - depends entirely on who started the process

        def fields(function):
            """Standalone, there is no window to describe a form to."""
            return function

        Arg = None

Section = dict[str, Any]
Note = dict[str, str]

#: CVE summaries and evidence strings run long; a table cell has to stay a cell.
_CELL = 72


@fields
def form() -> list[Any]:
    """Which flags a reekeer window draws as controls.

    Not all of them, on purpose. stackscan has thirty-odd options and about a dozen that anybody
    reaches for; drawing every one produces a column you scroll rather than a form you fill, with the
    target of the scan somewhere in the middle of it looking exactly like ``--no-bell``. What is left
    out is not unreachable — reekeer keeps an argument line under the form, and everything below still
    parses there the way it always has.

    The order is the order a scan is decided in: what to look at, then how deep to go, then the
    bounds. reekeer groups them by kind on its own, so switches gather without being listed together
    here.

    No defaults are declared even where argparse has one. A prefilled control is a value that gets
    sent explicitly, so a form nobody touched would compose a command line carrying eight flags that
    all mean "as it was" — the numbers live in the help text instead, where they read as information
    rather than as a decision.
    """
    if Arg is None:  # pragma: no cover - only when the SDK is missing, and then nobody asks
        return []
    return [
        Arg(
            "targets",
            positional=True,
            multiple=True,
            help="URLs, hostnames or CIDR ranges to scan.",
        ),
        Arg(
            "file",
            flag="-f",
            kind="path",
            help="Read targets from a file instead, one per line.",
        ),
        # The four that decide what a scan actually *does*. `--full` is the one most runs want and
        # turns the other three on, which is worth saying here rather than leaving to be discovered.
        Arg(
            "full",
            flag=True,
            help="Deep scan: ports, subdomains, offline CVEs, IP info and default-cred checks.",
        ),
        Arg("ports", flag=True, help="Active port and service scan (nmap when it is installed)."),
        Arg("subdomains", flag=True, help="Enumerate subdomains: AXFR, DNS wordlist, TLS SANs."),
        Arg(
            "default-creds",
            flag=True,
            help="Bounded default-credential check. Authorized targets only.",
        ),
        # Standalone this is a mid-scan y/n prompt; there is no terminal to answer it in the window,
        # so the answer is given here, before the run. On is "brute every discovered device"; off
        # leaves them found but untried.
        Arg(
            "full-auto",
            flag=True,
            help="Brute-force discovered devices without asking. Authorized targets only.",
        ),
        Arg("cve-online", flag=True, help="Query NVD live as well as the offline database."),
        Arg("insecure", flag=True, help="Do not verify TLS certificates."),
        Arg("compact", flag=True, help="One row per target instead of a section each."),
        # The bounds. Every one of these has a sane default; they are here because a scan that is
        # taking too long or hitting a rate limit is fixed by changing exactly these.
        Arg("timeout", kind="float", help="Per-request timeout in seconds. Default 12."),
        Arg("concurrency", kind="int", help="Targets scanned at once. Default 10."),
        Arg("workers", kind="int", help="Workers for ports, subdomains and creds. Default 350."),
        Arg(
            "subdomain-limit",
            kind="int",
            help="Wordlist labels to resolve. Default 5000; 0 is the full ~870k list.",
        ),
        # Both of these are a comma list argparse reads as one value, so they are checklists: a box
        # per option, sent as `--disable dns,tls`. `choices` names what may be ticked, `multiple` is
        # what makes it pick-several rather than a one-of dropdown.
        Arg(
            "disable",
            choices=["dns", "tls", "geo", "probe", "cve", "ip-info", "nmap"],
            multiple=True,
            help="Passes to skip.",
        ),
        Arg(
            "export",
            choices=["html", "xml", "json-f", "json-t"],
            multiple=True,
            help="Report formats to write.",
        ),
        Arg("output", kind="path", help="Base name or path for exported files."),
    ]


def document(reports: list[ScanReport], elapsed: float, *, compact: bool = False) -> dict[str, Any]:
    """The whole scan as one reekeer document.

    `compact` keeps the per-target overview and the notes but drops the long tables, which is what the
    flag means everywhere else in stackscan.
    """
    labelled = len(reports) > 1
    sections: list[Section] = []
    notes: list[Note] = []
    for report in reports:
        found = _sections(report, labelled)
        sections.extend(found[:1] if compact else found)
        notes.extend(_notes(report, labelled))

    failed = sum(1 for report in reports if report.error)
    return {
        "title": _title(reports),
        "status": {
            "level": "error" if failed == len(reports) else "warn" if failed else "ok",
            "message": _summary(reports, elapsed),
        },
        "sections": sections,
        "notes": notes,
    }


def _title(reports: list[ScanReport]) -> str:
    if len(reports) == 1:
        return f"stackscan {__version__} · {host_of(reports[0].url)}"
    return f"stackscan {__version__} · {len(reports)} targets"


def _summary(reports: list[ScanReport], elapsed: float) -> str:
    techs = len({tech.name for report in reports for tech in report.all_technologies()})
    cves = sum(len(report.cves) for report in reports)
    ports = sum(len(report.ports.ports) if report.ports else 0 for report in reports)
    parts = [
        _count(techs, "technology", "technologies"),
        _count(ports, "open port", "open ports"),
        _count(cves, "CVE", "CVEs"),
    ]
    return f"{', '.join(parts)} in {_elapsed(elapsed)}"


def _count(total: int, one: str, many: str) -> str:
    return f"{total} {one if total == 1 else many}"


def _elapsed(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.2f}s"
    return f"{int(seconds // 60)}m {int(seconds % 60)}s"


def _sections(report: ScanReport, labelled: bool) -> list[Section]:
    host = host_of(report.url) or report.url

    def heading(name: str) -> str:
        return f"{host} · {name}" if labelled else name

    sections: list[Section] = [{"heading": heading("host"), "fields": _overview(report)}]

    # Who owns the addresses, as a table of its own.
    #
    # These used to go in the overview above, one field per address — `46.224.155.79` on the left and
    # `Hetzner Online GmbH, AS24940, Germany` on the right — so a host with ten resolved addresses had
    # ten rows whose labels were IP addresses, wedged between `waf` and `tls`. A field list says what
    # a thing *is*; these are a set of like records with three columns, which is a table, and reading
    # them as properties of the host is why the section stopped being readable at all.
    if report.ip_info:
        rows = [
            [info.ip, info.org or info.isp or "", info.asn or "", info.country or ""]
            for info in report.ip_info
        ]
        if any(any(cell for cell in row[1:]) for row in rows):
            sections.append(
                {
                    "heading": heading("addresses"),
                    "columns": ["address", "organisation", "asn", "country"],
                    "rows": rows,
                }
            )

    technologies = report.all_technologies()
    if technologies:
        sections.append(
            {
                "heading": heading("technologies"),
                "columns": ["name", "version", "category"],
                "rows": [
                    [tech.name, tech.version or "", ", ".join(tech.categories)]
                    for tech in sorted(technologies, key=lambda tech: tech.name.lower())
                ],
            }
        )

    if report.ports and report.ports.ports:
        sections.append(
            {
                "heading": heading("ports"),
                "columns": ["port", "state", "service", "product"],
                "rows": [
                    [
                        f"{port.port}/{port.protocol}",
                        port.state,
                        port.service or "",
                        " ".join(part for part in (port.product, port.version) if part),
                    ]
                    for port in report.ports.ports
                ],
            }
        )

    if report.cves:
        sections.append(
            {
                "heading": heading("CVEs"),
                "columns": ["id", "severity", "component", "summary"],
                "rows": [_cve_row(cve) for cve in report.cves],
            }
        )

    if report.subdomains:
        sections.append(
            {
                "heading": heading("subdomains"),
                "columns": ["name", "addresses", "source"],
                "rows": [
                    [sub.name, ", ".join(sub.addresses), sub.source] for sub in report.subdomains
                ],
            }
        )

    if report.services:
        sections.append(
            {
                "heading": heading("services"),
                "columns": ["name", "kind", "severity", "evidence"],
                "rows": [
                    [service.name, service.kind, service.severity, _clip(service.evidence)]
                    for service in report.services
                ],
            }
        )

    return sections


def _overview(report: ScanReport) -> dict[str, str]:
    fields: dict[str, str] = {"url": report.final_url or report.url}
    if report.status is not None:
        fields["status"] = str(report.status)
    if report.error:
        fields["error"] = report.error
    if report.real_ips:
        fields["addresses"] = ", ".join(sorted(report.real_ips))
    for label, values in (
        ("server", report.infra.server),
        ("cdn", report.infra.cdn),
        ("waf", report.infra.waf),
        ("proxy", report.infra.proxy),
    ):
        if values:
            fields[label] = ", ".join(values)
    if report.tls:
        certificate = [part for part in (report.tls.issuer, report.tls.protocol) if part]
        if report.tls.not_after:
            certificate.append(f"expires {report.tls.not_after}")
        if certificate:
            fields["tls"] = ", ".join(certificate)
        if not report.tls.trusted:
            fields["tls trust"] = "not trusted"
    if report.whois and report.whois.registrar:
        fields["registrar"] = report.whois.registrar
    if report.protocols:
        fields["protocols"] = ", ".join(report.protocols)
    # No `elapsed` here: the summary line above the sections already ends `… in 1m 40s`, and reekeer's
    # own status bar carries a live clock — a third copy in the host table was the same number a third
    # time. The total is the headline; per-target timing, when several were scanned, is the overview's
    # own concern and not this per-host block.
    return fields


def _cve_row(cve: CveMatch) -> list[str]:
    severity = cve.severity.upper()
    if cve.cvss is not None:
        severity = f"{severity} {cve.cvss:.1f}"
    if cve.unconfirmed:
        severity = f"{severity}?"
    component = " ".join(part for part in (cve.product, cve.version) if part)
    return [cve.id, severity, component, _clip(cve.summary)]


def _notes(report: ScanReport, labelled: bool) -> list[Note]:
    """Anything the user should be told rather than left to spot in a table."""
    host = host_of(report.url) or report.url

    def message(text: str) -> str:
        return f"{host}: {text}" if labelled else text

    notes: list[Note] = []
    if report.error:
        notes.append({"level": "error", "message": message(report.error)})
    for finding in report.creds:
        detail = finding.detail or f"{finding.username or ''}:{finding.password or ''}".strip(":")
        notes.append(
            {
                "level": "error",
                "message": message(f"default credentials on {finding.service} — {detail}"),
            }
        )
    for secret in report.secrets:
        notes.append(
            {
                "level": "error" if secret.severity.upper() in {"CRITICAL", "HIGH"} else "warn",
                "message": message(f"exposed {secret.name} in {secret.source or secret.location}"),
            }
        )
    for takeover in report.takeovers:
        state = "confirmed" if takeover.verified else "possible"
        notes.append(
            {
                "level": "error" if takeover.verified else "warn",
                "message": message(
                    f"{state} subdomain takeover: {takeover.subdomain} -> {takeover.service}"
                ),
            }
        )
    if report.exposure:
        if report.exposure.git_exposed:
            notes.append({"level": "error", "message": message("/.git is reachable")})
        for finding in report.exposure.findings:
            notes.append({"level": "warn", "message": message(_clip(finding))})
    for note in report.infra.notes:
        notes.append({"level": "info", "message": message(_clip(note))})
    return notes


def _clip(text: str) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= _CELL:
        return collapsed
    return collapsed[: _CELL - 1] + "…"
