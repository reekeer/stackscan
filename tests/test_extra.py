from __future__ import annotations

import argparse

from rich.console import Console

from stackscan.analyzers import TechAnalyzer
from stackscan.cli import _apply_disable
from stackscan.core.core import _charset
from stackscan.types import FetchResult


def _args(disable: str) -> argparse.Namespace:
    ns = argparse.Namespace(disable=disable)
    for attr in ("no_dns", "no_tls", "no_geo", "no_probe", "no_cve", "no_ip_info", "no_nmap"):
        setattr(ns, attr, False)
    return ns


def test_apply_disable_sets_flags() -> None:
    args = _args("dns, tls ,ip-info")
    _apply_disable(args, Console(quiet=True))
    assert args.no_dns is True
    assert args.no_tls is True
    assert args.no_ip_info is True
    assert args.no_geo is False


def test_curated_detects_header_and_cookie_tech() -> None:
    analyzer = TechAnalyzer([])
    result = FetchResult(
        url="https://x.test",
        status=200,
        headers={"x-powered-by": "PHP/8.1", "x-drupal-cache": "HIT"},
        body="",
        cookies=("laravel_session=abc; path=/", "csrftoken=xyz"),
    )
    names = {t.name for t in analyzer.detect(result)}
    assert {"PHP", "Drupal", "Laravel", "Django"} <= names


def test_charset_falls_back_on_unknown_encoding() -> None:
    assert _charset("utf-8") == "utf-8"
    assert _charset(None) == "utf-8"
    assert _charset("") == "utf-8"
    assert _charset("nonsense-charset") == "utf-8"
