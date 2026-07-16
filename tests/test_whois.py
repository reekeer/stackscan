from __future__ import annotations

from typing import Any

from stackscan.net.tld import registrable_domain
from stackscan.net.whois import _parse_rdap


def test_registrable_domain_basic() -> None:
    assert registrable_domain("www.example.com") == "example.com"
    assert registrable_domain("curseforge.leavepulse.com") == "leavepulse.com"
    assert registrable_domain("example.com") == "example.com"
    assert registrable_domain("https://a.b.example.dev/x") == "example.dev"


def test_registrable_domain_two_level_suffix() -> None:
    assert registrable_domain("shop.example.co.uk") == "example.co.uk"
    assert registrable_domain("example.com.br") == "example.com.br"


def _rdap(entities: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "entities": entities,
        "events": [
            {"eventAction": "registration", "eventDate": "2025-08-27T06:31:21Z"},
            {"eventAction": "expiration", "eventDate": "2026-08-27T06:31:21Z"},
        ],
        "status": ["client transfer prohibited"],
    }


def _entity(roles: list[str], **vcard: str) -> dict[str, Any]:
    items: list[Any] = [["version", {}, "text", "4.0"]]
    for key, value in vcard.items():
        items.append([key, {}, "text", value])
    return {"roles": roles, "vcardArray": ["vcard", items]}


def test_parse_registrar_only_marks_registrant_withheld() -> None:
    info = _parse_rdap("leavepulse.com", _rdap([_entity(["registrar"], fn="NameCheap, Inc.")]))
    assert info.registrar == "NameCheap, Inc."
    assert info.registrant_public is False
    assert "not published" in info.privacy
    assert info.created == "2025-08-27T06:31:21Z"
    assert info.expires == "2026-08-27T06:31:21Z"
    assert info.statuses == ("client transfer prohibited",)


def test_parse_public_registrant_is_exposed() -> None:
    info = _parse_rdap(
        "example.com",
        _rdap(
            [
                _entity(["registrar"], fn="Gandi"),
                _entity(["registrant"], org="Acme Corp", fn="Jane Doe"),
            ]
        ),
    )
    assert info.registrant_public is True
    assert info.registrant == "Acme Corp"
    assert info.privacy == "public"


def test_parse_privacy_service_registrant_is_hidden() -> None:
    info = _parse_rdap(
        "example.com",
        _rdap(
            [
                _entity(["registrar"], fn="NameCheap, Inc."),
                _entity(["registrant"], org="WhoisGuard Privacy Protection"),
            ]
        ),
    )
    assert info.registrant_public is False
    assert "privacy service" in info.privacy


def test_parse_registrar_provided_privacy() -> None:
    info = _parse_rdap(
        "example.com",
        _rdap(
            [
                _entity(["registrar"], fn="Cloudflare, Inc."),
                _entity(["registrant"], org="Cloudflare, Inc."),
            ]
        ),
    )
    assert info.registrant_public is False
    assert "registrar-provided privacy" in info.privacy
