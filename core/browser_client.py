# core/browser_client.py
from __future__ import annotations

from playwright.sync_api import sync_playwright

class BrowserClient:
    """
    Renderiza páginas con JS para scraping “real”.
    Más lento y más detectable, pero a veces imprescindible.
    """
    def __init__(self, headless: bool = True, timeout_ms: int = 15000):
        self.headless = headless
        self.timeout_ms = timeout_ms

    def fetch_html(self, url: str) -> str:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)
            html = page.content()
            browser.close()
            return html
