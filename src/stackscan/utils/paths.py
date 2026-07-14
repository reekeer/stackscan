from __future__ import annotations

import os
from pathlib import Path


def db_dir() -> Path:
    home = os.environ.get("STACKSCAN_HOME")
    base = Path(home) if home else Path.home() / ".local" / "stackscan"
    return base / "db"
