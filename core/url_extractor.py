# -*- coding: utf-8 -*-
"""
Extracción de URLs desde:
- texto plano
- HTML (href/src)
Incluye normalización básica.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Set

from bs4 import BeautifulSoup


# Regex razonable para URLs en texto (no perfecta, pero práctica)
URL_RE = re.compile(
    r"""(?ix)
    \b(
        https?://[^\s<>"']+
        |
        www\.[^\s<>"']+
    )
    """
)


@dataclass(frozen=True)
class ExtractedURL:
    url: str
    source: str  # "text" | "html"


def _normalize(u: str) -> str:
    u = u.strip().strip('",;:()[]<>')
    if u.lower().startswith("www."):
        u = "http://" + u
    return u


def extract_urls_from_text(text: str) -> List[str]:
    found = [_normalize(m.group(1)) for m in URL_RE.finditer(text or "")]
    return found


def extract_urls_from_html(html: str) -> List[str]:
    urls: List[str] = []
    if not html:
        return urls

    soup = BeautifulSoup(html, "html.parser")

    # href
    for a in soup.find_all("a", href=True):
        urls.append(_normalize(a["href"]))

    # src (img/script/iframe, etc.)
    for tag in soup.find_all(src=True):
        urls.append(_normalize(tag["src"]))

    return urls


def extract_all_urls(text: str, html: str) -> List[ExtractedURL]:
    """Devuelve URLs únicas con su origen."""
    out: List[ExtractedURL] = []
    seen: Set[str] = set()

    for u in extract_urls_from_text(text):
        if u and u not in seen:
            seen.add(u)
            out.append(ExtractedURL(url=u, source="text"))

    for u in extract_urls_from_html(html):
        if u and u not in seen:
            seen.add(u)
            out.append(ExtractedURL(url=u, source="html"))

    return out
