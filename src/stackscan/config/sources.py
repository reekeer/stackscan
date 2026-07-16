from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
import urllib.request
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, cast
from urllib.parse import urljoin

SIGDB_MAGIC = b"SIGT"
_RULES_FILENAMES = ("sigdb.json", "rules.json", "signatures.json")
_DOWNLOAD_UA = "stackscan-source-manager/1.0"
_DOWNLOAD_TIMEOUT = 30
_MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
_DOWNLOAD_CHUNK_SIZE = 8192


class SourceError(RuntimeError):
    pass


@dataclass(frozen=True)
class Source:
    id: str
    url: str
    kind: str
    path: str
    added: int
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _base_dir(env: str, default: Path) -> Path:
    override = os.environ.get("STACKSCAN_HOME")
    if override:
        return Path(override)
    raw = os.environ.get(env)
    return Path(raw) if raw else default


def config_home() -> Path:
    return _base_dir("XDG_CONFIG_HOME", Path.home() / ".config") / "stackscan"


def cache_home() -> Path:
    return _base_dir("XDG_CACHE_HOME", Path.home() / ".cache") / "stackscan"


def registry_path() -> Path:
    return config_home() / "sources.json"


def sources_cache_dir() -> Path:
    return cache_home() / "sources"


def _source_id(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]


def _looks_like_git(url: str) -> bool:
    return url.endswith(".git") or url.startswith(("git@", "git+", "ssh://"))


def _normalize_git_url(url: str) -> str:
    return url[4:] if url.startswith("git+") else url


def _detect_kind(url: str) -> str:
    if _looks_like_git(url):
        return "git"
    if url.startswith(("http://", "https://")):
        return "web"
    if Path(url).expanduser().is_file():
        return "path"
    return "web"


class SourceStore:
    def __init__(self) -> None:
        self._registry = registry_path()
        self._cache = sources_cache_dir()

    def _load_raw(self) -> list[dict[str, Any]]:
        if not self._registry.is_file():
            return []
        try:
            data = json.loads(self._registry.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(data, list):
            return []
        rows = cast("list[object]", data)
        return [cast("dict[str, Any]", row) for row in rows if isinstance(row, dict)]

    def list(self) -> list[Source]:
        sources: list[Source] = []
        for row in self._load_raw():
            try:
                kind = str(row["kind"])
                sources.append(
                    Source(
                        id=str(row["id"]),
                        url=str(row["url"]),
                        kind="web" if kind == "http" else kind,
                        path=str(row["path"]),
                        added=int(row["added"]),
                        enabled=bool(row.get("enabled", True)),
                    )
                )
            except (KeyError, ValueError, TypeError):
                continue
        return sources

    def _persist(self, sources: list[Source]) -> None:
        self._registry.parent.mkdir(parents=True, exist_ok=True)
        payload = [source.to_dict() for source in sources]
        self._registry.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def add(self, url: str, kind: str | None = None) -> Source:
        url = url.strip()
        if not url:
            raise SourceError("empty source url")
        kind = kind or _detect_kind(url)
        source_id = _source_id(url)
        dest = self._cache / source_id
        dest.mkdir(parents=True, exist_ok=True)
        compiled = dest / "signatures.sigdb"
        if kind == "git":
            _materialize_git(url, dest, compiled)
            path = compiled
        elif kind == "path":
            path = _materialize_path(url, compiled)
        else:
            _materialize_http(url, compiled)
            path = compiled
        previous = next((s for s in self.list() if s.id == source_id), None)
        source = Source(
            id=source_id,
            url=url,
            kind=kind,
            path=str(path),
            added=int(time.time()),
            enabled=previous.enabled if previous else True,
        )
        sources = [s for s in self.list() if s.id != source_id]
        sources.append(source)
        self._persist(sources)
        return source

    def remove(self, key: str) -> bool:
        sources = self.list()
        kept = [s for s in sources if s.id != key and s.url != key]
        if len(kept) == len(sources):
            return False
        self._persist(kept)
        removed = [s for s in sources if s not in kept]
        for source in removed:
            _remove_tree(self._cache / source.id)
        return True

    def set_enabled(self, key: str, enabled: bool) -> bool:
        sources = self.list()
        changed = False
        for index, source in enumerate(sources):
            if key in (source.id, source.url):
                sources[index] = replace(source, enabled=enabled)
                changed = True
        if changed:
            self._persist(sources)
        return changed

    def update(self, key: str | None = None) -> list[Source]:
        targets = [s for s in self.list() if key in (None, s.id, s.url)]
        refreshed: list[Source] = []
        for source in targets:
            refreshed.append(self.add(source.url, kind=source.kind))
        return refreshed

    def resolve_paths(self) -> list[Path]:
        paths: list[Path] = []
        for source in self.list():
            if not source.enabled:
                continue
            path = Path(source.path)
            if path.is_file():
                paths.append(path)
        return paths


def _http_get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": _DOWNLOAD_UA})
    try:
        with urllib.request.urlopen(request, timeout=_DOWNLOAD_TIMEOUT) as response:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(_DOWNLOAD_CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_DOWNLOAD_BYTES:
                    raise SourceError(
                        f"downloaded source from {url} exceeds {_MAX_DOWNLOAD_BYTES} bytes"
                    )
                chunks.append(chunk)
            return b"".join(chunks)
    except OSError as exc:
        raise SourceError(f"failed to fetch {url}: {exc}") from exc


def _compile_rules_bytes(raw: bytes, output: Path) -> None:
    from sigdb.core import build_sigdb

    try:
        rules = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SourceError("source is neither a .sigdb file nor valid rules JSON") from exc
    if not isinstance(rules, dict):
        raise SourceError("rules JSON must be an object of {name: definition}")
    output.parent.mkdir(parents=True, exist_ok=True)
    build_sigdb(rules=cast("dict[str, Any]", rules), output_path=output)


def _materialize_path(src: str, output: Path) -> Path:
    source_file = Path(src).expanduser()
    if not source_file.is_file():
        raise SourceError(f"file not found: {source_file}")
    raw = source_file.read_bytes()
    if raw[:4] == SIGDB_MAGIC:
        return source_file.resolve()
    _compile_rules_bytes(raw, output)
    return output


def _manifest_sigdb_url(manifest_url: str, data: dict[str, Any]) -> str | None:
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, dict):
        return None
    sigdb = cast("dict[str, Any]", artifacts).get("sigdb")
    if not isinstance(sigdb, dict):
        return None
    rel = cast("dict[str, Any]", sigdb).get("path")
    if not rel:
        return None
    return urljoin(manifest_url, str(rel))


def _materialize_http(url: str, output: Path) -> None:
    raw = _http_get(url)
    if raw[:4] == SIGDB_MAGIC:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(raw)
        return
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SourceError("source is neither a .sigdb file nor valid JSON") from exc
    if isinstance(data, dict):
        sigdb_url = _manifest_sigdb_url(url, cast("dict[str, Any]", data))
        if sigdb_url:
            sig_raw = _http_get(sigdb_url)
            if sig_raw[:4] != SIGDB_MAGIC:
                raise SourceError(f"{sigdb_url} is not a .sigdb file")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(sig_raw)
            return
    _compile_rules_bytes(raw, output)


def _materialize_git(url: str, dest: Path, output: Path) -> None:
    checkout = dest / "repo"
    _remove_tree(checkout)
    clone_url = _normalize_git_url(url)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", clone_url, str(checkout)],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SourceError("git is not installed") from exc
    except subprocess.CalledProcessError as exc:
        raise SourceError(f"git clone failed: {exc.stderr.strip()}") from exc
    prebuilt = sorted(checkout.rglob("*.sigdb"))
    if prebuilt:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(prebuilt[0].read_bytes())
        return
    for name in _RULES_FILENAMES:
        candidate = checkout / name
        if candidate.is_file():
            _compile_rules_bytes(candidate.read_bytes(), output)
            return
    raise SourceError("repository has no .sigdb or rules JSON (sigdb.json/rules.json)")


def _remove_tree(path: Path) -> None:
    if not path.exists():
        return
    import shutil

    shutil.rmtree(path, ignore_errors=True)
