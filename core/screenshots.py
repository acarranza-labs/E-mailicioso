# -*- coding: utf-8 -*-
from __future__ import annotations

from pathlib import Path
from playwright.sync_api import sync_playwright


def capture_screenshot(url: str, out_path: Path, timeout_ms: int = 20000) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_default_timeout(timeout_ms)

        page.goto(url, wait_until="domcontentloaded")
        page.wait_for_timeout(800)  # pequeño delay para render
        page.screenshot(path=str(out_path), full_page=True)

        browser.close()
