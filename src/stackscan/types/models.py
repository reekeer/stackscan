"""Core data models."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TypeAlias

Headers: TypeAlias = Mapping[str, str]
Cookies: TypeAlias = Sequence[str]


@dataclass(frozen=True)
class FetchResult:
    url: str
    status: int
    headers: Headers
    body: str
    cookies: Cookies


@dataclass(frozen=True)
class Rule:
    html: Sequence[str] = ()
    headers: Sequence[str] = ()
    cookies: Sequence[str] = ()
