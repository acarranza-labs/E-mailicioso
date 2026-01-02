# -*- coding: utf-8 -*-
"""
Reputation Cache Module.
SQLite-based local cache for URL/domain reputation results.
"""
from __future__ import annotations

import sqlite3
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

CACHE_DIR = Path.home() / ".emailicioso"
CACHE_FILE = CACHE_DIR / "reputation_cache.db"
CACHE_TTL_HOURS = 24  # Results valid for 24 hours


def _ensure_db():
    """Ensure database and table exist."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(str(CACHE_FILE))
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reputation (
            domain TEXT PRIMARY KEY,
            source TEXT,
            result TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()


def get_cached_reputation(domain: str) -> Optional[Dict[str, Any]]:
    """
    Get cached reputation result for a domain.
    Returns None if not cached or expired.
    """
    _ensure_db()
    
    conn = sqlite3.connect(str(CACHE_FILE))
    cursor = conn.cursor()
    cursor.execute(
        "SELECT source, result, timestamp FROM reputation WHERE domain = ?",
        (domain.lower(),)
    )
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    source, result_json, timestamp_str = row
    
    # Check expiration
    try:
        cached_time = datetime.fromisoformat(timestamp_str)
        if datetime.now() - cached_time > timedelta(hours=CACHE_TTL_HOURS):
            return None  # Expired
    except Exception:
        return None
    
    try:
        result = json.loads(result_json)
    except Exception:
        result = {"raw": result_json}
    
    return {
        "domain": domain,
        "source": source,
        "result": result,
        "cached_at": timestamp_str,
    }


def set_cached_reputation(domain: str, source: str, result: Dict[str, Any]) -> None:
    """Cache a reputation result."""
    _ensure_db()
    
    conn = sqlite3.connect(str(CACHE_FILE))
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT OR REPLACE INTO reputation (domain, source, result, timestamp)
        VALUES (?, ?, ?, ?)
        """,
        (domain.lower(), source, json.dumps(result), datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def clear_cache() -> int:
    """Clear all cached entries. Returns number of entries deleted."""
    _ensure_db()
    
    conn = sqlite3.connect(str(CACHE_FILE))
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM reputation")
    count = cursor.fetchone()[0]
    cursor.execute("DELETE FROM reputation")
    conn.commit()
    conn.close()
    
    return count
