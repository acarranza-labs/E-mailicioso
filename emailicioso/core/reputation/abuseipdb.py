"""AbuseIPDB API v2 (free key: 1000 checks/day)."""

from __future__ import annotations

from collections.abc import Callable

from emailicioso.core.reputation.base import Provider, RepResult

API = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDB(Provider):
    name = "AbuseIPDB"
    kinds = ("ip",)

    def check(self, indicator: str, kind: str, should_stop: Callable[[], bool] = lambda: False) -> RepResult:
        link = f"https://www.abuseipdb.com/check/{indicator}"
        try:
            resp = self._get(API, headers={"Key": self.api_key, "Accept": "application/json"},
                             params={"ipAddress": indicator, "maxAgeInDays": 90}, should_stop=should_stop,
                             retries=0)
        except Exception as exc:
            return self.error(indicator, kind, f"{type(exc).__name__}: {exc}", link)
        if resp.status_code in (401, 403):
            return self.error(indicator, kind, "Invalid API key", link)
        if resp.status_code == 429:
            return self.error(indicator, kind, "Daily quota exceeded", link)
        if resp.status_code != 200:
            return self.error(indicator, kind, f"HTTP {resp.status_code}", link)
        try:
            data = resp.json()["data"]
        except (ValueError, KeyError, TypeError):
            return self.error(indicator, kind, "Unexpected response", link)
        conf = int(data.get("abuseConfidenceScore") or 0)
        reports = int(data.get("totalReports") or 0)
        verdict = "malicious" if conf >= 75 else "suspicious" if conf >= 25 else "clean"
        detail = [f"{reports} reports (90 days)"]
        for key, label in (("isp", "ISP"), ("countryCode", "Country"), ("usageType", "Usage")):
            if data.get(key):
                detail.append(f"{label}: {data[key]}")
        if data.get("isTor"):
            detail.append("Tor exit node")
        return RepResult(self.name, indicator, kind, verdict, score=f"{conf}%", detail=" | ".join(detail),
                         link=link)
