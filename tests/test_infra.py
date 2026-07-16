from __future__ import annotations

from stackscan.analyzers import analyze_infra, summarize_edge
from stackscan.types import InfraInfo


def test_detects_cloudflare_and_nginx() -> None:
    headers = {"server": "cloudflare", "cf-ray": "abc123-FRA"}
    infra = analyze_infra(headers, (), "example.com")
    assert "Cloudflare" in infra.cdn
    assert "Cloudflare" in infra.waf


def test_detects_nginx_server() -> None:
    infra = analyze_infra({"server": "nginx/1.25.1"}, (), "example.com")
    assert "nginx" in infra.server


def test_openresty_flagged_as_proxy_note() -> None:
    infra = analyze_infra({"server": "openresty"}, (), "example.com")
    assert "OpenResty" in infra.server
    assert "OpenResty" in infra.proxy
    assert any("Nginx Proxy Manager" in note for note in infra.notes)


def test_host_reflection_note() -> None:
    headers = {"server": "nginx", "x-backend": "app.example.com"}
    infra = analyze_infra(headers, (), "example.com")
    assert any("reflects requested host" in note for note in infra.notes)


def test_bigip_cookie_promotes_waf() -> None:
    infra = analyze_infra({"server": "nginx"}, ("BIGipServerpool=123.45.67",), "example.com")
    assert "F5 BIG-IP" in infra.waf
    assert "F5 BIG-IP" in infra.proxy


def test_summarize_edge_groups_provider_roles() -> None:
    infra = InfraInfo(cdn=("Cloudflare",), waf=("Cloudflare",), proxy=("Cloudflare",))
    assert summarize_edge(infra) == "Cloudflare (CDN, WAF, reverse proxy)"


def test_summarize_edge_chains_layers_front_to_back() -> None:
    infra = InfraInfo(cdn=("Cloudflare", "Amazon CloudFront"), waf=("Cloudflare",))
    assert summarize_edge(infra) == "Cloudflare (CDN, WAF) → Amazon CloudFront (CDN)"


def test_summarize_edge_adds_ip_only_cdn_orgs() -> None:
    infra = InfraInfo(cdn=("Cloudflare",), waf=("Cloudflare",))
    edge = summarize_edge(infra, ["Fastly, Inc.", "Cloudflare, Inc."])
    assert "Cloudflare (CDN, WAF)" in edge
    assert "Fastly (CDN)" in edge
    assert edge.count("Cloudflare") == 1


def test_summarize_edge_empty_when_no_edge() -> None:
    assert summarize_edge(InfraInfo(server=("nginx",))) == ""
