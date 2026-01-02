# -*- coding: utf-8 -*-
"""
Base común para scrapers (requests + bs4).
- Sesión con headers realistas
- Timeouts y control de errores
- Resultado homogéneo
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Dict
import time
import requests


@dataclass
class ReputationResult:
    engine: str                 # "talos" | "urlvoid" | "xforce"
    query: str                  # dominio o IP
    verdict: str                # "clean" | "suspicious" | "malicious" | "unknown" | "error"
    score: Optional[str] = None
    categories: Optional[str] = None
    details: Optional[str] = None
    url: Optional[str] = None
    error: Optional[str] = None


def build_session() -> requests.Session:
    """Crea una sesión requests con headers razonables."""
    s = requests.Session()
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/123.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
        "Connection": "keep-alive",
    })
    return s


def safe_get(session: requests.Session, url: str, timeout: int = 15) -> requests.Response:
    """GET con timeout y manejo de errores estándar."""
    r = session.get(url, timeout=timeout, allow_redirects=True)
    r.raise_for_status()
    return r


def polite_delay(seconds: float = 0.6) -> None:
    """Pequeño delay para no parecer un bot agresivo."""
    time.sleep(seconds)
