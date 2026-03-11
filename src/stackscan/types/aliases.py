from __future__ import annotations

from collections.abc import Sequence
from typing import TypeAlias

from .models import Rule

Patterns: TypeAlias = Sequence[str]
RulesByCategory: TypeAlias = dict[str, dict[str, Rule]]
DetectedTech: TypeAlias = dict[str, list[str]]
FrameworksSource: TypeAlias = str
