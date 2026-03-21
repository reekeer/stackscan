"""Output payload types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeAlias, cast

DetectedTech: TypeAlias = dict[str, list[str]]


@dataclass(frozen=True)
class ScanTargetResult:
    url: str
    status: int | None
    detected: DetectedTech = field(default_factory=lambda: cast(DetectedTech, {}))
    error: str | None = None
