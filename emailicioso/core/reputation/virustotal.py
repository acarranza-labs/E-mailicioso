"""VirusTotal API v3 (free or premium key). Lookups only: nothing is ever submitted."""

from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import datetime, timezone

from emailicioso.core.reputation.base import Provider, RepResult

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


class VirusTotal(Provider):
    name = "VirusTotal"
    kinds = ("domain", "ip", "url", "hash")

    def _endpoint(self, indicator: str, kind: str) -> tuple[str, str]:
        if kind == "domain":
            return f"{API}/domains/{indicator}", f"{GUI}/domain/{indicator}"
        if kind == "ip":
            return f"{API}/ip_addresses/{indicator}", f"{GUI}/ip-address/{indicator}"
        if kind == "url":
            uid = url_id(indicator)
            return f"{API}/urls/{uid}", f"{GUI}/url/{uid}"
        return f"{API}/files/{indicator}", f"{GUI}/file/{indicator}"

    def check(self, indicator: str, kind: str, should_stop: Callable[[], bool] = lambda: False) -> RepResult:
        api_url, link = self._endpoint(indicator, kind)
        try:
            resp = self._get(api_url, headers={"x-apikey": self.api_key}, should_stop=should_stop)
        except Exception as exc:
            return self.error(indicator, kind, f"{type(exc).__name__}: {exc}", link)
        if resp.status_code == 404:
            return RepResult(self.name, indicator, kind, "unknown", detail="Not seen by VirusTotal", link=link)
        if resp.status_code == 401:
            return self.error(indicator, kind, "Invalid API key", link)
        if resp.status_code == 429:
            return self.error(indicator, kind, "Rate limited (free API: 4 lookups/minute)", link)
        if resp.status_code != 200:
            return self.error(indicator, kind, f"HTTP {resp.status_code}", link)
        try:
            attrs = resp.json()["data"]["attributes"]
        except (ValueError, KeyError, TypeError):
            return self.error(indicator, kind, "Unexpected response", link)
        stats = attrs.get("last_analysis_stats") or {}
        mal = int(stats.get("malicious", 0))
        sus = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values() if isinstance(v, int))
        if mal >= 3:
            verdict = "malicious"
        elif mal or sus:
            verdict = "suspicious"
        elif total:
            verdict = "clean"
        else:
            verdict = "unknown"
        detail = []
        if kind == "domain":
            if attrs.get("creation_date"):
                created = datetime.fromtimestamp(int(attrs["creation_date"]), tz=timezone.utc)
                age = (datetime.now(timezone.utc) - created).days
                detail.append(f"Registered {created:%Y-%m-%d} ({age} days ago)")
            if attrs.get("registrar"):
                detail.append(f"Registrar: {attrs['registrar']}")
        if kind == "ip":
            for key, label in (("as_owner", "AS"), ("country", "Country")):
                if attrs.get(key):
                    detail.append(f"{label}: {attrs[key]}")
        if kind == "hash":
            if attrs.get("meaningful_name"):
                detail.append(attrs["meaningful_name"])
            label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
            if label:
                detail.append(f"Threat: {label}")
        cats = attrs.get("categories")
        if isinstance(cats, dict) and cats:
            detail.append("Categories: " + ", ".join(sorted(set(cats.values()))[:4]))
        return RepResult(self.name, indicator, kind, verdict, score=f"{mal + sus}/{total}" if total else "",
                         detail=" | ".join(detail), link=link)
