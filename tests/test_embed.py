from __future__ import annotations

from typing import Any, cast

import pytest

from stackscan.embed import Arg, document
from stackscan.types import CveMatch, InfraInfo, Port, PortScan, ScanReport, Technology


def _report() -> ScanReport:
    return ScanReport(
        url="https://example.com",
        status=200,
        elapsed=1.25,
        technologies=[Technology(name="nginx", categories=("server",), version="1.25.3")],
        infra=InfraInfo(server=("nginx",)),
        ports=PortScan(scanner="nmap", ports=(Port(port=443, service="https"),)),
        cves=[
            CveMatch(
                id="CVE-2024-0001",
                product="nginx",
                version="1.25.3",
                severity="high",
                cvss=7.5,
                confidence=90,
                summary="a  very   spaced summary",
            )
        ],
    )


def _sections(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return cast("list[dict[str, Any]]", doc["sections"])


def test_document_carries_a_title_and_a_status() -> None:
    doc = document([_report()], 2.0)
    assert doc["title"].endswith("example.com")
    status = cast("dict[str, str]", doc["status"])
    assert status["level"] == "ok"
    assert "1 technology, 1 open port, 1 CVE in 2.00s" == status["message"]


def test_each_finding_kind_gets_its_own_section() -> None:
    headings = [section["heading"] for section in _sections(document([_report()], 1.0))]
    assert headings == ["host", "technologies", "ports", "CVEs"]


def test_sections_are_labelled_by_host_only_when_there_is_more_than_one() -> None:
    doc = document([_report(), _report()], 1.0)
    assert _sections(doc)[0]["heading"] == "example.com · host"


def test_compact_keeps_the_overview_and_drops_the_tables() -> None:
    headings = [
        section["heading"] for section in _sections(document([_report()], 1.0, compact=True))
    ]
    assert headings == ["host"]


def test_the_host_block_does_not_repeat_the_elapsed_time() -> None:
    # The summary line already ends `… in Ns`, and reekeer's status bar carries a live clock — an
    # `elapsed` row in the host table was the same number a third time.
    host = _sections(document([_report()], 2.0))[0]
    assert "elapsed" not in dict(host["fields"])
    assert "in 2.00s" in cast("dict[str, str]", document([_report()], 2.0)["status"])["message"]


def test_rows_are_plain_strings_reekeer_can_lay_out() -> None:
    ports = _sections(document([_report()], 1.0))[2]
    assert ports["columns"] == ["port", "state", "service", "product"]
    assert ports["rows"] == [["443/tcp", "open", "https", ""]]


def test_a_cve_row_folds_severity_and_score_together() -> None:
    cves = _sections(document([_report()], 1.0))[3]
    assert cves["rows"] == [["CVE-2024-0001", "HIGH 7.5", "nginx 1.25.3", "a very spaced summary"]]


def test_a_failed_target_is_reported_as_an_error_rather_than_a_silence() -> None:
    doc = document([ScanReport(url="https://nope.invalid", error="dns failure")], 0.5)
    assert cast("dict[str, str]", doc["status"])["level"] == "error"
    assert doc["notes"] == [{"level": "error", "message": "dns failure"}]


#: The form is only built when reekeer's SDK is importable, which it is not in stackscan's own CI —
#: it is a standalone tool that happens to mount inside a shell, not a plugin that needs one to test.
#: Skipping rather than asserting an empty list keeps these checks meaningful where they can run.
_no_sdk = pytest.mark.skipif(
    Arg is None, reason="reekeer's SDK is not on sys.path; there is no form to check"
)


@_no_sdk
def test_the_declared_form_names_only_flags_stackscan_actually_takes() -> None:
    """A control that sends a flag argparse will reject is worse than no control at all.

    The form is a second statement of what the parser below already knows, which is the one thing
    about it that can rot: a flag renamed in `cli.py` leaves a control here that composes a line the
    tool refuses. Checked against the parser itself rather than against a copy of its option list.
    """
    from stackscan.cli import _build_scan_parser
    from stackscan.embed import form

    parser = _build_scan_parser()
    accepted = {option for action in parser._actions for option in action.option_strings}
    positional = {action.dest for action in parser._actions if not action.option_strings}

    declared = form()
    assert declared, "the SDK is importable, so there should be a form"

    for arg in declared:
        if arg.positional:
            assert arg.name in positional, f"{arg.name} is not a positional stackscan takes"
        else:
            spelling = f"-{arg.name}" if len(arg.name) == 1 else f"--{arg.name}"
            assert spelling in accepted, f"{spelling} is not an option stackscan takes"


@_no_sdk
def test_a_line_composed_from_the_form_parses() -> None:
    """What a filled form composes has to survive stackscan's own argparse, values and all."""
    from stackscan.cli import _build_scan_parser

    args = _build_scan_parser().parse_args(
        [
            "example.com",
            "acme.io",
            "--full",
            "--ports",
            "--timeout",
            "20",
            "--workers",
            "64",
            "--subdomain-limit",
            "2000",
            "--disable",
            "nmap,geo",
            "--export",
            "html,json-f",
            "--output",
            "/tmp/report",
        ]
    )
    assert args.targets == ["example.com", "acme.io"]
    assert args.full and args.ports
    assert args.timeout == 20.0
    assert args.workers == 64
    assert args.subdomain_limit == 2000
    assert args.disable == "nmap,geo"
    assert args.export == "html,json-f"
    assert args.output == "/tmp/report"


@_no_sdk
def test_the_form_declares_no_defaults_so_an_untouched_one_composes_nothing() -> None:
    """A prefilled control is a flag that gets sent, and a form nobody touched should send none."""
    from stackscan.embed import form

    for arg in form():
        assert arg.default is None, f"{arg.name} would arrive prefilled"
