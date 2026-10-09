"""Evidence screenshots of URLs with a headless Chromium (Playwright).

This VISITS the URL. Use a proxy / isolated network when capturing live phishing pages.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

INSTALL_HINT = "Playwright is not installed. Run:\n  pip install playwright\n  python -m playwright install chromium"


class ScreenshotUnavailable(RuntimeError):
    pass


@dataclass
class Capture:
    url: str
    path: Path
    final_url: str = ""
    title: str = ""
    status: int | None = None
    redirects: list[str] = field(default_factory=list)


def safe_filename(url: str, max_len: int = 120) -> str:
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "unknown-host").lower()
        path = unquote(parts.path or "").strip("/")
    except ValueError:
        host, path = "invalid-url", ""
    base = host + ("_" + path.replace("/", "_") if path else "")
    base = re.sub(r'[\\/:*?"<>|\x00-\x1f\s]+', "_", base)
    base = re.sub(r"_+", "_", base).strip("._ ")[:max_len] or "capture"
    digest = hashlib.sha1(url.encode("utf-8", "ignore")).hexdigest()[:8]
    return f"{base}__{digest}.png"


def evidence_path(evidence_dir: str | Path, case: str, url: str) -> Path:
    case = re.sub(r'[\\/:*?"<>|\x00-\x1f]+', "_", case).strip() or "case"
    return Path(evidence_dir).expanduser() / case / "screenshots" / safe_filename(url)


def capture(url: str, out_path: Path, timeout_s: int = 20, proxy: str = "") -> Capture:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise ScreenshotUnavailable(INSTALL_HINT) from exc

    out_path.parent.mkdir(parents=True, exist_ok=True)
    result = Capture(url=url, path=out_path)
    launch_args: dict = {"headless": True}
    if proxy:
        launch_args["proxy"] = {"server": proxy}
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(**launch_args)
        except Exception as exc:
            if "Executable doesn't exist" in str(exc):
                raise ScreenshotUnavailable("Chromium for Playwright is missing. Run:\n"
                                            "  python -m playwright install chromium") from exc
            raise
        try:
            context = browser.new_context(
                viewport={"width": 1366, "height": 900},
                ignore_https_errors=True,
                accept_downloads=False,
                java_script_enabled=True,
            )
            page = context.new_page()
            page.set_default_timeout(timeout_s * 1000)
            chain: list[str] = []
            page.on("framenavigated", lambda fr: chain.append(fr.url) if fr == page.main_frame else None)
            response = page.goto(url, wait_until="domcontentloaded")
            try:
                page.wait_for_load_state("networkidle", timeout=4000)
            except Exception:
                pass
            result.status = response.status if response else None
            result.final_url = page.url
            result.title = page.title()
            result.redirects = list(dict.fromkeys(chain))
            page.screenshot(path=str(out_path), full_page=True)
        finally:
            browser.close()

    meta = {
        "url": url,
        "final_url": result.final_url,
        "title": result.title,
        "http_status": result.status,
        "redirects": result.redirects,
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "proxy": bool(proxy),
        "sha256": hashlib.sha256(out_path.read_bytes()).hexdigest() if out_path.exists() else "",
    }
    out_path.with_suffix(".json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return result
