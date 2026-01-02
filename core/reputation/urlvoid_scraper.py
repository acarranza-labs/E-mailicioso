# -*- coding: utf-8 -*-
"""
URLVoid scraper (sin API) - parser robusto para "Report Summary".

Extrae:
- Detections Counts  -> "0/36"
- Domain Registration -> "2000-01-07 | 26 years ago"
- URL consultada
"""

from __future__ import annotations

from bs4 import BeautifulSoup

from .scrape_base import ReputationResult, build_session, safe_get, polite_delay


def _find_report_summary_table(soup: BeautifulSoup):
    """
    Encuentra la tabla del panel 'Report Summary'.
    Devuelve el <table> o None.
    """
    panels = soup.select("div.panel")
    for panel in panels:
        heading = panel.select_one(".panel-heading")
        if not heading:
            continue
        if heading.get_text(strip=True).lower() == "report summary":
            table = panel.select_one("table")
            return table
    return None


def _extract_kv_from_table(table) -> dict[str, str]:
    """
    Convierte la tabla de Report Summary en dict:
      { "Detections Counts": "0/36", "Domain Registration": "...", ... }
    """
    data: dict[str, str] = {}
    if not table:
        return data

    for tr in table.select("tr"):
        tds = tr.select("td")
        if len(tds) < 2:
            continue
        key = tds[0].get_text(" ", strip=True)
        val = tds[1].get_text(" ", strip=True)
        if key:
            data[key] = val

    return data


def _parse_detections_counts(value: str) -> tuple[int | None, int | None]:
    """
    Parse "0/36" -> (0, 36). Si no puede, (None, None).
    """
    if not value:
        return None, None
    if "/" not in value:
        return None, None
    left, right = value.split("/", 1)
    left = left.strip()
    right = right.strip()
    try:
        return int(left), int(right)
    except Exception:
        return None, None


def check_urlvoid(domain: str) -> ReputationResult:
    session = build_session()
    url = f"https://www.urlvoid.com/scan/{domain}/"

    try:
        r = safe_get(session, url, timeout=25)
        polite_delay()

        soup = BeautifulSoup(r.text or "", "lxml")

        # Detectar bloqueos típicos (Cloudflare / bot protection)
        page_text = soup.get_text(" ", strip=True).lower()
        if "cloudflare" in page_text or "checking your browser" in page_text or "access denied" in page_text:
            return ReputationResult(
                engine="urlvoid",
                query=domain,
                verdict="error",
                url=url,
                error="Bloqueado (Cloudflare/bot protection).",
            )

        table = _find_report_summary_table(soup)
        kv = _extract_kv_from_table(table)

        detections_raw = kv.get("Detections Counts", "")
        reg_raw = kv.get("Domain Registration", "")

        det, total = _parse_detections_counts(detections_raw)

        # Heurística de veredicto (simple y útil):
        # - detections > 0 => suspicious/malicious (no sabemos gravedad exacta)
        # - detections == 0 => clean
        verdict = "unknown"
        if det is not None:
            verdict = "clean" if det == 0 else "suspicious"

        details = []
        if detections_raw:
            details.append(f"Detections: {detections_raw}")
        if reg_raw:
            details.append(f"Domain registration: {reg_raw}")

        return ReputationResult(
            engine="urlvoid",
            query=domain,
            verdict=verdict,
            score=detections_raw or None,        # reutilizamos 'score' para 0/36
            categories=None,
            details=" | ".join(details) if details else "Parsed Report Summary.",
            url=url,
        )

    except Exception as e:
        return ReputationResult(
            engine="urlvoid",
            query=domain,
            verdict="error",
            url=url,
            error=f"{type(e).__name__}: {e}",
        )
