"""Output payload types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

from .aliases import DetectedTech


@dataclass(frozen=True)
class ScanTargetResult:
    url: str
    status: int | None
    detected: DetectedTech = field(default_factory=lambda: cast(DetectedTech, {}))
    error: str | None = None


@dataclass(frozen=True)
class ScanSummary:
    results: list[ScanTargetResult] = field(
        default_factory=lambda: cast(list[ScanTargetResult], [])
    )
