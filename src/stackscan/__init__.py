"""Stackscan package."""

from .config import DEFAULT_FRAMEWORKS_URL, load_framework_rules
from .core import StackscanSession, detect_tech
from .utils import normalize_url

__all__ = [
    "__version__",
    "DEFAULT_FRAMEWORKS_URL",
    "StackscanSession",
    "detect_tech",
    "load_framework_rules",
    "normalize_url",
]

__version__ = "1.0.0"
