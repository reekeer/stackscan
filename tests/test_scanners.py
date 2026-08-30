from __future__ import annotations

from stackscan.scanners.isp_blocked import detect_isp_block
from stackscan.scanners.secrets import scan_secrets
from stackscan.scanners.takeover import _service_for_cname
from stackscan.types import FetchResult


def test_detect_isp_block_by_body_marker() -> None:
    fetched = FetchResult(
        url="https://blocked.example/",
        status=200,
        headers={},
        body="<html>Доступ к сайту запрещен по решению суда</html>",
        cookies=(),
    )
    assert detect_isp_block("https://example.com", fetched) is not None
    assert "blocked" in detect_isp_block("https://example.com", fetched).lower()


def test_detect_isp_block_by_redirect_host() -> None:
    fetched = FetchResult(
        url="https://block.kmtn.ru/",
        status=301,
        headers={"location": "https://block.kmtn.ru/"},
        body="",
        cookies=(),
    )
    assert detect_isp_block("https://example.com", fetched) is not None


def test_detect_isp_block_no_block() -> None:
    fetched = FetchResult(
        url="https://example.com/",
        status=200,
        headers={},
        body="<html>Hello world</html>",
        cookies=(),
    )
    assert detect_isp_block("https://example.com", fetched) is None


def test_detect_isp_block_by_title() -> None:
    fetched = FetchResult(
        url="https://example.com/",
        status=200,
        headers={},
        body="<html><title>Доступ ограничен</title></html>",
        cookies=(),
    )
    assert detect_isp_block("https://example.com", fetched) is not None


def test_detect_isp_block_by_location_header() -> None:
    fetched = FetchResult(
        url="https://block.some-isp.example/notice",
        status=302,
        headers={"location": "https://block.some-isp.example/notice"},
        body="",
        cookies=(),
    )
    assert detect_isp_block("https://example.com", fetched) is not None


def test_scan_secrets_finds_aws_key_and_jwt() -> None:
    body = (
        'apiKey = "AKIAZ4XORKN2QVWD7PLR"\n'
        'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"\n'
    )
    findings = scan_secrets(body, location="https://x.test")
    names = {f.name for f in findings}
    assert "AWS Access Key ID" in names
    assert "JWT" in names
    assert all("..." in f.value for f in findings)


def test_scan_secrets_redacts_value() -> None:
    body = 'apiKey = "AKIAZ4XORKN2QVWD7PLR"'
    finding = scan_secrets(body)[0]
    assert finding.value != "AKIAZ4XORKN2QVWD7PLR"
    assert "..." in finding.value


def test_scan_secrets_ignores_documentation_placeholders() -> None:
    body = (
        'aws = "AKIAIOSFODNN7EXAMPLE"\n'
        "url = postgres://user:password@localhost:5432/example_db\n"
        'api_key = "YOUR_API_KEY_HERE_1234567"\n'
    )
    assert scan_secrets(body) == []


def test_takeover_service_for_github_pages_cname() -> None:
    target = _service_for_cname("foo.github.io")
    assert target is not None
    assert target.service == "GitHub Pages"


def test_takeover_service_for_aws_s3_cname() -> None:
    target = _service_for_cname("foo.s3-website-us-east-1.amazonaws.com")
    assert target is not None
    assert target.service == "AWS S3"


def test_takeover_service_returns_none_for_regular_cname() -> None:
    assert _service_for_cname("cdn.example.com") is None
