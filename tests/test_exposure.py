from __future__ import annotations

import asyncio
from dataclasses import dataclass

from stackscan.analyzers.exposure import ExposureProbe, analyze_exposure


@dataclass
class _Resp:
    status: int
    body: str


class _FakeSession:
    def __init__(self, routes: dict[str, _Resp], default: _Resp) -> None:
        self._routes = routes
        self._default = default

    async def fetch(self, url: str, **_kw: object) -> _Resp:
        for path, resp in self._routes.items():
            if url.endswith(path):
                return resp
        return self._default


_PROBE = ExposureProbe(timeout=2.0, user_agent="stackscan", insecure=True)


def _run(session: _FakeSession) -> object:
    return asyncio.run(analyze_exposure(session, "http://x/", _PROBE))


def test_exposure_detects_real_files() -> None:
    session = _FakeSession(
        {
            "/robots.txt": _Resp(200, "User-agent: *\nDisallow: /admin\n"),
            "/sitemap.xml": _Resp(200, '<?xml version="1.0"?><urlset></urlset>'),
            "/.well-known/security.txt": _Resp(200, "Contact: mailto:a@b.c\nExpires: 2030-01-01\n"),
            "/.git/HEAD": _Resp(200, "ref: refs/heads/main\n"),
        },
        _Resp(404, "not found"),
    )
    exposure = _run(session)
    assert exposure.robots_txt
    assert exposure.sitemap
    assert exposure.security_txt
    assert exposure.git_exposed


def test_exposure_ignores_soft_404() -> None:
    session = _FakeSession({}, _Resp(200, "<html><body>catch-all 200</body></html>"))
    exposure = _run(session)
    assert not exposure.robots_txt
    assert not exposure.sitemap
    assert not exposure.security_txt
    assert not exposure.git_exposed
