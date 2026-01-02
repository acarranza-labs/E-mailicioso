# core/intel/talos_scraper.py
import asyncio
from typing import Optional, Dict
from playwright.async_api import async_playwright, TimeoutError as PWTimeoutError


TALOS_REPUTATION_URL = "https://talosintelligence.com/reputation"


async def talos_web_reputation(query: str, timeout_ms: int = 20000) -> Dict[str, Optional[str]]:
    """
    Extrae la 'Web Reputation' desde la UI de Talos.
    Ojo: Talos es dinámico; este método depende de que el valor se renderice en el DOM.

    :param query: Dominio/URL/IP a buscar (ej: "example.com" o "http://example.com")
    :param timeout_ms: Timeout máximo para esperar el renderizado.
    :return: dict con campos útiles (incluye web_reputation si se encuentra).
    """
    result = {
        "query": query,
        "web_reputation": None,
        "raw_text_block": None,
        "error": None,
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        )
        page = await context.new_page()

        try:
            # 1) Abrir Talos
            await page.goto(TALOS_REPUTATION_URL, wait_until="domcontentloaded", timeout=timeout_ms)

            # 2) Escribir en la caja y enviar (el input del HTML es #rep-lookup)
            await page.fill("#rep-lookup", query)
            await page.click("#intelligence-center-search-submit")

            # 3) Esperar a que la zona de resultados se rellene
            #    En tu HTML, #lookup-top-stats empieza vacío y luego se pinta.
            await page.wait_for_selector("#lookup-top-stats", timeout=timeout_ms)

            # 4) Capturar un bloque de texto de resultados (rápido para debug)
            top_stats_text = (await page.inner_text("#lookup-top-stats")).strip()
            result["raw_text_block"] = top_stats_text

            # 5) Buscar 'Web Reputation' en el texto (heurística)
            #    Dependiendo del markup, puede estar como "Web Reputation: Neutral" o similar.
            #    Ajusta el parseo cuando veas un ejemplo real del texto.
            lower = top_stats_text.lower()
            if "web reputation" in lower:
                # Parse muy simple: toma la línea donde aparece
                lines = [ln.strip() for ln in top_stats_text.splitlines() if ln.strip()]
                for ln in lines:
                    if "web reputation" in ln.lower():
                        # Ejemplos esperados: "Web Reputation: Neutral"
                        parts = ln.split(":", 1)
                        if len(parts) == 2:
                            result["web_reputation"] = parts[1].strip()
                        else:
                            # Si no hay ":", deja la línea completa
                            result["web_reputation"] = ln.strip()
                        break

        except PWTimeoutError:
            result["error"] = "Timeout esperando renderizado de resultados (posible bloqueo, cambios de UI o captcha)."
        except Exception as e:
            result["error"] = f"Error inesperado: {e}"
        finally:
            await context.close()
            await browser.close()

    return result


def lookup_talos_web_reputation(query: str) -> Dict[str, Optional[str]]:
    """Wrapper sync para usarlo fácil desde tu app PyGTK."""
    return asyncio.run(talos_web_reputation(query))


if __name__ == "__main__":
    # Prueba rápida en CLI
    data = lookup_talos_web_reputation("example.com")
    print(data)
