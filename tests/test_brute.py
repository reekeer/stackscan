from __future__ import annotations

import argparse
from typing import Any

import pytest
from rich.console import Console

from stackscan import cli
from stackscan.analyzers.creds import _is_camera
from stackscan.types import BruteTarget, CredFinding, ScanReport


def _args(**overrides: Any) -> argparse.Namespace:
    ns = argparse.Namespace(
        full_auto=False,
        json_output=True,
        timeout=6.0,
        workers=40,
        cred_limit=50,
        concurrency=10,
    )
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


def test_is_camera_matches_camera_signatures() -> None:
    assert _is_camera('Basic realm="IPCamera"', "") is True
    assert _is_camera("", "Hikvision-Webs") is True
    assert _is_camera('Basic realm="Router"', "nginx") is False


def test_brute_target_url_and_target() -> None:
    target = BruteTarget(host="cam.test", port=8443, tls=True)
    assert target.target == "cam.test:8443"
    assert target.url == "https://cam.test:8443/"


def test_brute_subject_wording() -> None:
    assert cli._brute_subject(1, 0) == "1 open camera"
    assert cli._brute_subject(0, 2) == "2 devices"
    assert cli._brute_subject(2, 1) == "2 open cameras and 1 device"


def test_brute_phase_skips_in_json_without_full_auto() -> None:
    report = ScanReport(url="https://cam.test")
    report.brute_targets = [
        BruteTarget(host="cam.test", port=80, service="http (cam)", is_camera=True)
    ]
    cli._run_brute_phase([report], _args(), Console())
    assert any(
        f.kind == "auth-required" and f.detail == "brute-force skipped" for f in report.creds
    )


def test_brute_phase_declined_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    report = ScanReport(url="https://cam.test")
    report.brute_targets = [BruteTarget(host="cam.test", port=80, is_camera=True)]
    cli._run_brute_phase([report], _args(json_output=False), Console())
    assert all(f.kind != "default-creds" for f in report.creds)
    assert any(f.detail == "brute-force skipped" for f in report.creds)


def test_brute_phase_full_auto_runs_brute(monkeypatch: pytest.MonkeyPatch) -> None:
    report = ScanReport(url="https://cam.test")
    target = BruteTarget(host="cam.test", port=80, service="http (cam)", is_camera=True)
    report.brute_targets = [target]

    async def fake_brute(targets: list[BruteTarget], **_: Any) -> list[CredFinding]:
        return [
            CredFinding(
                target=t.target,
                service=t.service,
                kind="default-creds",
                detail="default credentials accepted via HTTP Basic auth",
                username="admin",
                password="admin",
            )
            for t in targets
        ]

    monkeypatch.setattr(cli, "brute_devices", fake_brute)
    cli._run_brute_phase([report], _args(full_auto=True, json_output=False), Console())
    assert any(f.kind == "default-creds" and f.username == "admin" for f in report.creds)
