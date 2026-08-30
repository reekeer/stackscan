from __future__ import annotations

import xml.dom.minidom as minidom

from stackscan.export import build_graph, to_html, to_json, to_xml

_PAYLOAD = {
    "scanner": "stackscan",
    "version": "9.9.9",
    "generated_at": "2026-07-13T00:00:00Z",
    "elapsed_seconds": 1.23,
    "results": [
        {
            "url": "https://a.test",
            "final_url": "https://a.test",
            "status": 200,
            "error": None,
            "network": {"ipv4": ["1.2.3.4"], "ipv6": [], "mx": [], "ns": []},
            "technologies": [{"name": "nginx", "categories": ["proxy"]}],
            "services": [
                {
                    "name": "MySQL",
                    "kind": "database",
                    "evidence": "port 3306/tcp",
                    "severity": "CRITICAL",
                }
            ],
            "cves": [
                {
                    "id": "CVE-2021-23017",
                    "product": "nginx",
                    "version": "1.18.0",
                    "severity": "HIGH",
                    "cvss": 7.7,
                    "confidence": 90,
                    "summary": "resolver off-by-one",
                }
            ],
            "creds": [],
            "protocols": ["HTTP/1.1", "HTTP/2 (ALPN)"],
        },
        {
            "url": "https://b.test",
            "final_url": "https://b.test",
            "status": None,
            "error": "boom",
            "network": {"ipv4": ["1.2.3.4"]},
        },
    ],
}


def test_to_json_roundtrips() -> None:
    import json

    data = json.loads(to_json(_PAYLOAD))
    assert data["results"][0]["url"] == "https://a.test"


def test_to_xml_is_well_formed() -> None:
    xml = to_xml(_PAYLOAD)
    doc = minidom.parseString(xml)
    assert doc.documentElement.tagName == "stackscan"


def test_to_html_is_self_contained_and_themed() -> None:
    out = to_html(_PAYLOAD)
    assert "<!doctype html>" in out.lower()
    assert "#050713" in out
    assert "CVE-2021-23017" in out
    assert "sev-high" in out
    assert "http://" not in out.replace("http://www.w3.org", "")
    assert "Network graph" in out
    assert "<svg" in out
    assert "force-directed" in out or "netgraph" in out
    assert "Services" in out
    assert "MySQL" in out


def test_to_html_includes_network_extras() -> None:
    payload = {
        "results": [
            {
                "url": "https://a.test",
                "final_url": "https://a.test",
                "status": 200,
                "network": {
                    "ipv4": ["1.2.3.4"],
                    "extras": {"HTTPS": ['1 . alpn="h3,h2"'], "DS": ["2371 13 2 abcd"]},
                },
            }
        ]
    }
    out = to_html(payload)
    assert "HTTPS" in out
    assert "alpn=" in out
    assert "h3,h2" in out
    assert "DS" in out


def test_to_html_includes_whois_fields() -> None:
    payload = {
        "results": [
            {
                "url": "https://a.test",
                "final_url": "https://a.test",
                "status": 200,
                "whois": {
                    "domain": "a.test",
                    "registrar": "Example Registrar",
                    "registrar_url": "https://example.com",
                    "nameservers": ["ns1.example.com"],
                    "dnssec": "signed",
                    "created": "2025-01-01T00:00:00Z",
                    "updated": "2026-01-01T00:00:00Z",
                    "expires": "2027-01-01T00:00:00Z",
                    "statuses": ["client transfer prohibited"],
                },
            }
        ]
    }
    out = to_html(payload)
    assert "Example Registrar" in out
    assert "https://example.com" in out
    assert "ns1.example.com" in out
    assert "signed" in out


def test_html_graph_json_escapes_script_terminator() -> None:
    payload = {
        "scanner": "stackscan",
        "version": "9.9.9",
        "generated_at": "2026-07-13T00:00:00Z",
        "elapsed_seconds": 0.1,
        "results": [
            {
                "url": "https://a.test",
                "final_url": "https://a.test",
                "status": 200,
                "ports": {
                    "scanner": "nmap",
                    "ports": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "host": "1.2.3.4",
                            "service": "ssh",
                            "product": "</script><img src=x onerror=alert(1)>",
                        }
                    ],
                },
                "subdomains": [{"name": "a.a.test", "addresses": ["1.2.3.4"]}],
            }
        ],
    }
    payload["graph"] = build_graph(payload["results"])
    out = to_html(payload)
    assert "</script><img" not in out
    assert "\\u003c/script\\u003e" in out
    assert "innerHTML" not in out
