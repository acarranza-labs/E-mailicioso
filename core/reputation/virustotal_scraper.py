# -*- coding: utf-8 -*-
"""
VirusTotal (sin API) mediante Playwright.
Extrae el ratio de detecciones tipo "0/95" desde la UI web.

NOTAS:
- VT es SPA: hay que renderizar con navegador (Playwright).
- Puede aparecer captcha / bloqueo. En ese caso devolvemos error.
"""

from __future__ import annotations

import re
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

from .scrape_base import ReputationResult


RATIO_RE = re.compile(r"\b(\d{1,3})/(\d{1,3})\b")


def check_virustotal_domain(domain: str, timeout_ms: int = 25000) -> ReputationResult:
    """
    Consulta dominio en VirusTotal GUI y extrae ratio detecciones.
    URL típica: https://www.virustotal.com/gui/domain/<domain>
    """
    url = f"https://www.virustotal.com/gui/domain/{domain}"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.set_default_timeout(timeout_ms)

            page.goto(url, wait_until="domcontentloaded")

            # Heurísticas de bloqueo/captcha
            # (VT puede mostrar captcha/consent/login en algunos casos)
            page.wait_for_timeout(1200)
            body_text = (page.inner_text("body") or "").lower()

            if "captcha" in body_text or "unusual traffic" in body_text:
                browser.close()
                return ReputationResult(
                    engine="virustotal",
                    query=domain,
                    verdict="error",
                    url=url,
                    error="Bloqueado por captcha/antibot en VirusTotal GUI.",
                )

            # Intento 1: buscar un elemento típico de ratio (si existe en DOM)
            # En algunas versiones hay componentes vt-*; en otras solo texto.
            ratio = None

            # Espera a que la vista cargue algo más (SPA)
            page.wait_for_timeout(1500)

            # Intento 2: buscar ratio por regex en el texto visible
            body_text2 = page.inner_text("body") or ""
            m = RATIO_RE.search(body_text2)
            if m:
                ratio = m.group(0)

            browser.close()

            if not ratio:
                return ReputationResult(
                    engine="virustotal",
                    query=domain,
                    verdict="unknown",
                    url=url,
                    details="No se pudo localizar ratio en el DOM (posible cambio UI o bloqueo).",
                )

            # Veredicto simple a partir de ratio
            # Si left > 0 => suspicious (sin entrar en severidad)
            left, right = ratio.split("/", 1)
            try:
                det = int(left.strip())
                verdict = "clean" if det == 0 else "suspicious"
            except Exception:
                verdict = "unknown"

            return ReputationResult(
                engine="virustotal",
                query=domain,
                verdict=verdict,
                score=ratio,  # reutilizamos score para el ratio 0/95
                details=f"Detections: {ratio}",
                url=url,
            )

    except PWTimeout:
        return ReputationResult(
            engine="virustotal",
            query=domain,
            verdict="error",
            url=url,
            error="Timeout cargando VirusTotal GUI (posible bloqueo o conexión lenta).",
        )
    except Exception as e:
        return ReputationResult(
            engine="virustotal",
            query=domain,
            verdict="error",
            url=url,
            error=f"{type(e).__name__}: {e}",
        )
