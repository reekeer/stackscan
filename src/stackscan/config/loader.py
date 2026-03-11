"""Load framework detection rules."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlparse

from aiohttp import ClientSession, ClientTimeout
from pydantic import ValidationError

from stackscan.types import FrameworksDocument, FrameworksSource, Rule, RulesByCategory

DEFAULT_FRAMEWORKS_URL = "https://github.com/reekeer/stackscan/blob/frameworks/frameworks.json"


def _config_path() -> Path:
    return Path(__file__).with_name("frameworks.json")


def _normalize_github_blob(url: str) -> str:
    parsed = urlparse(url)
    if parsed.netloc.lower() != "github.com":
        return url
    parts = parsed.path.strip("/").split("/")
    if len(parts) >= 5 and parts[2] == "blob":
        owner, repo, _, branch, *rest = parts
        path = "/".join(rest)
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    return url


def _resolve_path(source: str) -> Path | None:
    candidate = Path(source)
    if candidate.is_file():
        return candidate
    fallback = Path(__file__).with_name(source)
    if fallback.is_file():
        return fallback
    return None


def _parse_document(raw: str) -> FrameworksDocument:
    return FrameworksDocument.model_validate_json(raw)


async def _read_text_from_url(url: str) -> str:
    async with ClientSession(timeout=ClientTimeout(total=20)) as session:
        async with session.get(
            url,
            headers={"User-Agent": "stackscan/1.0 (+https://example.invalid)"},
        ) as response:
            response.raise_for_status()
            charset = response.charset or "utf-8"
            raw = await response.read()
            return raw.decode(charset, errors="replace")


async def _read_text_from_file(path: Path) -> str:
    return await asyncio.to_thread(path.read_text, encoding="utf-8")


def _iter_frameworks(document: FrameworksDocument) -> Iterable[tuple[str, str, Rule]]:
    for item in document.frameworks:
        name = item.name.strip()
        category = item.category.strip() or "Other"
        if not name:
            continue

        yield category, name, Rule(
            html=tuple(item.html),
            headers=tuple(item.headers),
            cookies=tuple(item.cookies),
        )


async def load_framework_rules(source: FrameworksSource | None = None) -> RulesByCategory:
    if not source:
        source = str(_config_path())

    if source.startswith(("http://", "https://")):
        normalized = _normalize_github_blob(source)
        raw = await _read_text_from_url(normalized)
    else:
        path = _resolve_path(source)
        if path is None:
            raise FileNotFoundError(f"Frameworks file not found: {source}")
        raw = await _read_text_from_file(path)

    try:
        document = _parse_document(raw)
    except (json.JSONDecodeError, ValidationError) as exc:
        raise ValueError(f"Invalid frameworks JSON: {exc}") from exc

    rules: RulesByCategory = {}
    for category, name, rule in _iter_frameworks(document):
        rules.setdefault(category, {})[name] = rule

    return rules
