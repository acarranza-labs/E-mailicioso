"""urlscan.io search: has anyone scanned this domain/IP before? (search only, never submits)."""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import quote

from emailicioso.core.reputation.base import Provider, RepResult

API = "https://urlscan.io/api/v1/search/"


class UrlScan(Provider):
    name = "urlscan.io"
    kinds = ("domain", "ip")
    needs_key = False  # search works without a key, with lower rate limits

    def check(self, indicator: str, kind: str, should_stop: Callable[[], bool] = lambda: False) -> RepResult:
        field = "page.domain" if kind == "domain" else "page.ip"
        query = f'{field}:"{indicator}"'
        link = f"https://urlscan.io/search/#{quote(query)}"
        headers = {"API-Key": self.api_key} if self.api_key else {}
        try:
            resp = self._get(API, headers=headers, params={"q": query, "size": 20}, should_stop=should_stop,
                             retries=1, backoff=10)
        except Exception as exc:
            return self.error(indicator, kind, f"{type(exc).__name__}: {exc}", link)
        if resp.status_code == 429:
            return self.error(indicator, kind, "Rate limited", link)
        if resp.status_code != 200:
            return self.error(indicator, kind, f"HTTP {resp.status_code}", link)
        try:
            data = resp.json()
        except ValueError:
            return self.error(indicator, kind, "Unexpected response", link)
        results = data.get("results") or []
        total = data.get("total", len(results))
        if not results:
            return RepResult(self.name, indicator, kind, "unknown", detail="Never scanned on urlscan.io", link=link)
        malicious = sum(1 for r in results if (r.get("verdicts") or {}).get("overall", {}).get("malicious"))
        last = results[0].get("task", {}).get("time", "")[:10]
        titles = [r.get("page", {}).get("title", "") for r in results if r.get("page", {}).get("title")]
        detail = [f"{total} scans, last {last}"]
        if titles:
            detail.append(f"Title: {titles[0][:60]}")
        verdict = "malicious" if malicious else "unknown"
        return RepResult(self.name, indicator, kind, verdict, score=f"{malicious} flagged" if malicious else "",
                         detail=" | ".join(detail), link=link)
