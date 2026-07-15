from __future__ import annotations

import re

from stackscan.types import Software, Technology

_SERVER_NAMES: frozenset[str] = frozenset({
    "nginx",
    "apache",
    "httpd",
    "lighttpd",
    "litespeed",
    "caddy",
    "openresty",
    "iis",
    "microsoft-iis",
    "cherokee",
    "h2o",
    "boa",
    "thttpd",
    "mini_httpd",
    "rejetto",
    "cowboy",
    "tornado",
    "gunicorn",
    "uwsgi",
    "jetty",
    "tomcat",
    "apache tomcat",
    "websphere",
    "glassfish",
    "play",
    "spray",
    "kestrel",
    "cassini",
    "kangle",
    "resin",
    "weblogic",
    "zope",
    "aolserver",
    "yaws",
})

# Product names we never want to emit as a generic technology/software hit.
_NOISE_NAMES: frozenset[str] = frozenset({
    "http",
    "https",
    "www",
    "html",
    "css",
    "json",
    "xml",
    "js",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "ico",
    "woff",
    "woff2",
    "ttf",
    "eot",
    "php",
    "asp",
    "aspx",
    "jsp",
    "cgi",
})

_CORE_COMMIT_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9\s_-]{1,40})\s+Core\s+\(([a-f0-9]{4,})\)", re.IGNORECASE
)

_POWERED_BY_VERSION_RE = re.compile(
    r"(?:powered\s+by|running\s+on|built\s+with|made\s+with)\s+"
    r"([A-Za-z][A-Za-z0-9_-]*(?:\s+[A-Za-z][A-Za-z0-9_-]*){0,4})"
    r"\s+(?:v\.?|version\s*)?(\d+\.\d+(?:\.\d+)?)",
    re.IGNORECASE,
)

_POWERED_BY_PLAIN_RE = re.compile(
    r"(?:powered\s+by|running\s+on|built\s+with|made\s+with)\s+"
    r"([A-Za-z][A-Za-z0-9_-]*(?:\s+[A-Za-z][A-Za-z0-9_-]*){0,4})"
    r"(?!\s+(?:v\.?|version\s*)?\d)",
    re.IGNORECASE,
)

_SERVER_VERSION_RE = re.compile(
    r"\b("
    + "|".join(re.escape(name) for name in sorted(_SERVER_NAMES, key=len, reverse=True))
    + r")[/ ]v?(\d+\.\d+(?:\.\d+)?)",
    re.IGNORECASE,
)

_COMMIT_AFTER_NAME_RE = re.compile(
    r"\b([A-Za-z][A-Za-z0-9\s_-]{1,40})\s+\(?([a-f0-9]{7,40})\)?", re.IGNORECASE
)


def _normalize_name(name: str) -> str:
    return " ".join(name.split()).strip()


def _software_name(name: str) -> str:
    return _normalize_name(name).lower().replace(" ", "")


def _category(name: str) -> str:
    if _software_name(name) in {n.replace(" ", "") for n in _SERVER_NAMES}:
        return "infrastructure"
    return "service"


def _is_noise(name: str) -> bool:
    return _software_name(name) in _NOISE_NAMES


def is_commit_hash(value: str) -> bool:
    """Return True when value looks like a Git commit hash rather than a version."""
    if len(value) < 7:
        return False
    if value.startswith("v"):
        return False
    return bool(re.fullmatch(r"[a-f0-9]{7,40}", value))


def extract_generic_tech(body: str) -> list[Technology]:
    """Return generic service/infrastructure technologies found in the body.

    This is meant to catch products and commit hashes that do not have a
    dedicated signature in the bundled database, e.g. a 404 page footer that
    says ``nginx/1.24.0`` or ``CurseForge Core (a26fded)``.
    """
    hits: list[tuple[str, str, str, str | None]] = []
    seen: set[tuple[str, str | None]] = set()

    def remember(name: str, evidence: str, version: str | None) -> None:
        name = _normalize_name(name)
        if len(name) < 2 or _is_noise(name):
            return
        key = (name.lower(), version)
        if key in seen:
            return
        seen.add(key)
        hits.append((name, evidence, _category(name), version))

    for match in _SERVER_VERSION_RE.finditer(body):
        name = _normalize_name(match.group(1))
        version = match.group(2)
        remember(name, f"body:{name}/{version}", version)

    for match in _POWERED_BY_VERSION_RE.finditer(body):
        name = _normalize_name(match.group(1))
        version = match.group(2)
        if name and not _is_noise(name):
            remember(name, f"body:powered-by {name} {version}", version)

    for match in _POWERED_BY_PLAIN_RE.finditer(body):
        name = _normalize_name(match.group(1))
        if name and not _is_noise(name):
            remember(name, f"body:powered-by {name}", None)

    core_spans: set[tuple[int, int]] = set()
    for match in _CORE_COMMIT_RE.finditer(body):
        name = _normalize_name(match.group(1))
        commit = match.group(2).lower()
        if name and not _is_noise(name):
            remember(name, f"body:{name} Core ({commit})", commit)
        core_spans.add(match.span())

    def _overlaps_core(span: tuple[int, int]) -> bool:
        start, end = span
        for c_start, c_end in core_spans:
            if start < c_end and end > c_start:
                return True
        return False

    # Product name directly followed by a short hex commit (no "Core" keyword).
    for match in _COMMIT_AFTER_NAME_RE.finditer(body):
        if _overlaps_core(match.span()):
            continue
        name = _normalize_name(match.group(1))
        commit = match.group(2).lower()
        if name and not _is_noise(name) and is_commit_hash(commit):
            # Prefer the Core match if we already have one for the same product.
            if (name.lower(), commit) not in seen:
                remember(name, f"body:{name} ({commit})", commit)

    return [
        Technology(
            name=name,
            categories=(category,),
            evidence=(evidence,),
            confidence=70,
            version=version,
        )
        for name, evidence, category, version in hits
    ]


def extract_generic_software(body: str, location: str = "") -> list[Software]:
    """Return Software records for generic product/version/commit patterns."""
    out: list[Software] = []
    seen: set[tuple[str, str | None]] = set()

    def add(name: str, version: str | None, evidence: str) -> None:
        name = _normalize_name(name)
        if len(name) < 2:
            return
        sname = _software_name(name)
        if sname in _NOISE_NAMES:
            return
        key = (sname, version)
        if key in seen:
            return
        seen.add(key)
        out.append(
            Software(
                name=sname,
                version=version,
                source=evidence,
                location=location,
            )
        )

    for match in _SERVER_VERSION_RE.finditer(body):
        name = _normalize_name(match.group(1))
        version = match.group(2)
        add(name, version, f"body:{name}/{version}")

    for match in _POWERED_BY_VERSION_RE.finditer(body):
        name = _normalize_name(match.group(1))
        version = match.group(2)
        if name:
            add(name, version, f"body:powered-by {name} {version}")

    for match in _POWERED_BY_PLAIN_RE.finditer(body):
        name = _normalize_name(match.group(1))
        if name:
            add(name, None, f"body:powered-by {name}")

    core_spans: set[tuple[int, int]] = set()
    for match in _CORE_COMMIT_RE.finditer(body):
        name = _normalize_name(match.group(1))
        commit = match.group(2).lower()
        if name:
            add(name, commit, f"body:core-commit {name} ({commit})")
        core_spans.add(match.span())

    def _overlaps_core(span: tuple[int, int]) -> bool:
        start, end = span
        for c_start, c_end in core_spans:
            if start < c_end and end > c_start:
                return True
        return False

    for match in _COMMIT_AFTER_NAME_RE.finditer(body):
        if _overlaps_core(match.span()):
            continue
        name = _normalize_name(match.group(1))
        commit = match.group(2).lower()
        if name and is_commit_hash(commit):
            add(name, commit, f"body:commit {name} ({commit})")

    return out
