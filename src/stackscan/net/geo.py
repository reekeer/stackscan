from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast


class GeoProvider:
    def __init__(self, db_path: str | Path | None = None) -> None:
        env_path = os.environ.get("STACKSCAN_GEOIP_DB")
        resolved = db_path or env_path
        self._db_path = Path(resolved) if resolved else None
        self._reader: Any = None
        self._unavailable = False

    @property
    def enabled(self) -> bool:
        return self._db_path is not None and self._db_path.is_file()

    def _ensure_reader(self) -> Any:
        if self._reader is not None or self._unavailable:
            return self._reader
        if not self.enabled:
            self._unavailable = True
            return None
        try:
            from geoip2 import database as _geoip_db
        except ImportError:
            self._unavailable = True
            return None
        try:
            self._reader = cast("Any", _geoip_db).Reader(str(self._db_path))
        except Exception:
            self._unavailable = True
            return None
        return self._reader

    def lookup(self, ip: str) -> dict[str, str]:
        reader: Any = self._ensure_reader()
        if reader is None:
            return {}
        try:
            response: Any = reader.city(ip)
        except Exception:
            return {}
        out: dict[str, str] = {}
        country = getattr(getattr(response, "country", None), "iso_code", None)
        country_name = getattr(getattr(response, "country", None), "name", None)
        city = getattr(getattr(response, "city", None), "name", None)
        if isinstance(country, str):
            out["country_code"] = country
        if isinstance(country_name, str):
            out["country"] = country_name
        if isinstance(city, str):
            out["city"] = city
        return out


def lookup_geo(
    ips: tuple[str, ...], provider: GeoProvider | None = None
) -> dict[str, dict[str, str]]:
    provider = provider or GeoProvider()
    if not provider.enabled:
        return {}
    result: dict[str, dict[str, str]] = {}
    for ip in ips:
        data = provider.lookup(ip)
        if data:
            result[ip] = data
    return result
