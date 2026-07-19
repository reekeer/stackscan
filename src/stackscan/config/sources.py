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
DEFAULT_SOURCE_URL = "https://db.imalive.lol"
DEFAULT_SIGDB_URL = "https://db.imalive.lol/sigdb"
DEFAULT_STACKSCAN_URL = "https://db.imalive.lol/stackscan"
_RULES_FILENAMES = ("sigdb.json", "rules.json", "signatures.json")
_MANIFEST_REL = "sigdb/manifest.json"
_CVE_REL = "stackscan/cve.json.gz"
_SUBDOMAINS_REL = "stackscan/subdomains.txt"
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
    cve: str = ""
    subdomains: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class _Materialized:
    sigdb: str = ""
    cve: str = ""
    subdomains: str = ""


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
    if Path(url).expanduser().exists():
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
                        cve=str(row.get("cve", "")),
                        subdomains=str(row.get("subdomains", "")),
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
        if kind == "git":
            materialized = _materialize_git(url, dest)
        elif kind == "path":
            materialized = _materialize_path(url, dest)
        else:
            materialized = _materialize_http(url, dest)
        previous = next((s for s in self.list() if s.id == source_id), None)
        source = Source(
            id=source_id,
            url=url,
            kind=kind,
            path=materialized.sigdb,
            added=int(time.time()),
            enabled=previous.enabled if previous else True,
            cve=materialized.cve,
            subdomains=materialized.subdomains,
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
            if not source.enabled or not source.path:
                continue
            path = Path(source.path)
            if path.is_file():
                paths.append(path)
        return paths

    def _resolve_field(self, field: str) -> Path | None:
        for source in self.list():
            if not source.enabled:
                continue
            value = getattr(source, field, "")
            if not value:
                continue
            path = Path(value)
            if path.is_file():
                return path
        return None

    def resolve_cve(self) -> Path | None:
        return self._resolve_field("cve")

    def resolve_subdomains(self) -> Path | None:
        return self._resolve_field("subdomains")


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


def _materialize_path(src: str, dest: Path) -> _Materialized:
    source = Path(src).expanduser()
    if source.is_dir():
        sigdb, cve, subs = _scan_db_dir(source)
        if sigdb is None:
            raise SourceError(f"no sigdb under {source} (expected sigdb/stackscan.sigdb)")
        return _Materialized(
            sigdb=str(sigdb.resolve()),
            cve=str(cve.resolve()) if cve else "",
            subdomains=str(subs.resolve()) if subs else "",
        )
    if not source.is_file():
        raise SourceError(f"file not found: {source}")
    raw = source.read_bytes()
    if raw[:4] == SIGDB_MAGIC:
        return _Materialized(sigdb=str(source.resolve()))
    output = dest / "signatures.sigdb"
    _compile_rules_bytes(raw, output)
    return _Materialized(sigdb=str(output))


def _manifest_sigdb_url(manifest_url: str, data: dict[str, Any]) -> str | None:
    rel = data.get("path")
    if not rel:
        artifacts = data.get("artifacts")
        if isinstance(artifacts, dict):
            sigdb = cast("dict[str, Any]", artifacts).get("sigdb")
            if isinstance(sigdb, dict):
                rel = cast("dict[str, Any]", sigdb).get("path")
    if not rel:
        return None
    return urljoin(manifest_url, str(rel))


def _fetch_sigdb(url: str, output: Path) -> None:
    raw = _http_get(url)
    if raw[:4] != SIGDB_MAGIC:
        raise SourceError(f"{url} is not a .sigdb file")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(raw)


def _fetch_optional(url: str, output: Path) -> str:
    try:
        raw = _http_get(url)
    except SourceError:
        return ""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(raw)
    return str(output)


def _materialize_http(url: str, dest: Path) -> _Materialized:
    output = dest / "signatures.sigdb"
    lower = url.lower().rstrip("/")
    if lower.endswith(".sigdb"):
        _fetch_sigdb(url, output)
        return _Materialized(sigdb=str(output))
    if lower.endswith(".json"):
        raw = _http_get(url)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SourceError("source is neither a .sigdb file nor valid JSON") from exc
        if isinstance(data, dict):
            sigdb_url = _manifest_sigdb_url(url, cast("dict[str, Any]", data))
            if sigdb_url:
                _fetch_sigdb(sigdb_url, output)
                return _Materialized(sigdb=str(output))
        _compile_rules_bytes(raw, output)
        return _Materialized(sigdb=str(output))
    base = url if url.endswith("/") else url + "/"
    manifest_url = urljoin(base, _MANIFEST_REL)
    manifest_raw = _http_get(manifest_url)
    try:
        data = json.loads(manifest_raw)
    except json.JSONDecodeError as exc:
        raise SourceError(f"{manifest_url} is not valid JSON") from exc
    sigdb_url = _manifest_sigdb_url(manifest_url, cast("dict[str, Any]", data))
    if not sigdb_url:
        raise SourceError(f"{manifest_url} does not reference a sigdb path")
    _fetch_sigdb(sigdb_url, output)
    return _Materialized(
        sigdb=str(output),
        cve=_fetch_optional(urljoin(base, _CVE_REL), dest / "cve.json.gz"),
        subdomains=_fetch_optional(urljoin(base, _SUBDOMAINS_REL), dest / "subdomains.txt"),
    )


def _scan_db_dir(root: Path) -> tuple[Path | None, Path | None, Path | None]:
    sigdb: Path | None = None
    for candidate in (root / "sigdb" / "stackscan.sigdb", root / "stackscan.sigdb"):
        if candidate.is_file():
            sigdb = candidate
            break
    if sigdb is None:
        manifest = root / _MANIFEST_REL
        if manifest.is_file():
            try:
                data = json.loads(manifest.read_text("utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
            rel = cast("dict[str, Any]", data).get("path") if isinstance(data, dict) else None
            if rel:
                candidate = manifest.parent / str(rel)
                if candidate.is_file():
                    sigdb = candidate
    if sigdb is None:
        found = sorted(root.rglob("*.sigdb"))
        sigdb = found[0] if found else None
    cve = root / _CVE_REL
    subs = root / _SUBDOMAINS_REL
    return sigdb, (cve if cve.is_file() else None), (subs if subs.is_file() else None)


def _materialize_git(url: str, dest: Path) -> _Materialized:
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
    sigdb, cve, subs = _scan_db_dir(checkout)
    if sigdb is not None:
        return _Materialized(
            sigdb=str(sigdb.resolve()),
            cve=str(cve.resolve()) if cve else "",
            subdomains=str(subs.resolve()) if subs else "",
        )
    output = dest / "signatures.sigdb"
    for name in _RULES_FILENAMES:
        candidate = checkout / name
        if candidate.is_file():
            _compile_rules_bytes(candidate.read_bytes(), output)
            return _Materialized(sigdb=str(output))
    raise SourceError("repository has no .sigdb or rules JSON (sigdb.json/rules.json)")


def _remove_tree(path: Path) -> None:
    if not path.exists():
        return
    import shutil

    shutil.rmtree(path, ignore_errors=True)
