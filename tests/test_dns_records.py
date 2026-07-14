from __future__ import annotations

from types import SimpleNamespace

from stackscan.net.dns import _format_rdata


def test_format_mx() -> None:
    rdata = SimpleNamespace(preference=10, exchange="mail.example.com.")
    assert _format_rdata("MX", rdata) == "10 mail.example.com"


def test_format_txt_from_strings() -> None:
    rdata = SimpleNamespace(strings=[b"v=spf1 ", b"include:_spf.example.com ~all"])
    assert _format_rdata("TXT", rdata) == "v=spf1 include:_spf.example.com ~all"


def test_format_soa() -> None:
    rdata = SimpleNamespace(mname="ns1.example.com.", rname="hostmaster.example.com.", serial=42)
    assert _format_rdata("SOA", rdata) == "ns1.example.com hostmaster.example.com 42"


def test_format_ns_strips_trailing_dot() -> None:
    rdata = SimpleNamespace(target="ns1.example.com.")
    assert _format_rdata("NS", rdata) == "ns1.example.com"
