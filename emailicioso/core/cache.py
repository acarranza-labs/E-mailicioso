"""SQLite cache for reputation lookups, keyed by (provider, indicator)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from emailicioso.core.settings import DATA_DIR

CACHE_FILE = DATA_DIR / "reputation_cache.db"


class ReputationCache:
    def __init__(self, path: Path = CACHE_FILE, ttl_hours: int = 24) -> None:
        self.path = Path(path)
        self.ttl = timedelta(hours=ttl_hours)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS lookups (provider TEXT, indicator TEXT, result TEXT, "
                "ts TEXT, PRIMARY KEY (provider, indicator))"
            )

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.path), timeout=10)

    def get(self, provider: str, indicator: str) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT result, ts FROM lookups WHERE provider = ? AND indicator = ?",
                (provider, indicator.lower()),
            ).fetchone()
        if not row:
            return None
        try:
            if datetime.now() - datetime.fromisoformat(row[1]) > self.ttl:
                return None
            return json.loads(row[0])
        except (ValueError, TypeError):
            return None

    def set(self, provider: str, indicator: str, result: dict[str, Any]) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO lookups (provider, indicator, result, ts) VALUES (?, ?, ?, ?)",
                (provider, indicator.lower(), json.dumps(result), datetime.now().isoformat()),
            )

    def clear(self) -> int:
        with self._conn() as c:
            n = c.execute("SELECT COUNT(*) FROM lookups").fetchone()[0]
            c.execute("DELETE FROM lookups")
        return int(n)
