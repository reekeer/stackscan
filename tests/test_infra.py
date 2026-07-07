"""Tests for edge-infrastructure heuristics."""

from __future__ import annotations

from stackscan.analyzers import analyze_infra


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
