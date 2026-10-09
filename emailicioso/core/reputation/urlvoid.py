"""URLVoid web scraper (no API key). Best effort: the site may block automated requests."""

from __future__ import annotations

from collections.abc import Callable

from bs4 import BeautifulSoup

from emailicioso.core.reputation.base import Provider, RepResult

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)


def _summary(soup: BeautifulSoup) -> dict[str, str]:
    for panel in soup.select("div.panel"):
        heading = panel.select_one(".panel-heading")
        if heading and heading.get_text(strip=True).lower() == "report summary":
            data = {}
            for tr in panel.select("table tr"):
                tds = tr.select("td")
                if len(tds) >= 2:
                    data[tds[0].get_text(" ", strip=True)] = tds[1].get_text(" ", strip=True)
            return data
    return {}


class UrlVoid(Provider):
    name = "URLVoid"
    kinds = ("domain",)
    needs_key = False

    def check(self, indicator: str, kind: str, should_stop: Callable[[], bool] = lambda: False) -> RepResult:
        link = f"https://www.urlvoid.com/scan/{indicator}/"
        try:
            resp = self._get(link, headers={"User-Agent": BROWSER_UA, "Accept-Language": "en"}, retries=0)
        except Exception as exc:
            return self.error(indicator, kind, f"{type(exc).__name__}: {exc}", link)
        text = resp.text or ""
        low = text.lower()
        if resp.status_code in (403, 429, 503) or "checking your browser" in low or "cf-chl" in low:
            return self.error(indicator, kind, "Blocked by bot protection (open the link manually)", link)
        if resp.status_code != 200:
            return self.error(indicator, kind, f"HTTP {resp.status_code}", link)
        data = _summary(BeautifulSoup(text, "html.parser"))
        detections = data.get("Detections Counts", "")
        det = None
        if "/" in detections:
            try:
                det = int(detections.split("/", 1)[0].strip())
            except ValueError:
                det = None
        verdict = "unknown" if det is None else ("clean" if det == 0 else "malicious" if det >= 3 else "suspicious")
        detail = []
        if data.get("Domain Registration"):
            detail.append(f"Registered: {data['Domain Registration']}")
        if data.get("IP Address"):
            detail.append(f"IP: {data['IP Address']}")
        return RepResult(self.name, indicator, kind, verdict, score=detections, detail=" | ".join(detail),
                         link=link)
