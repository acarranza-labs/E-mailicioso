"""Reputation lookups across providers, with a local cache.

Every lookup sends the indicator to a third party. The GUI only runs them when the
analyst asks (or enables automatic checks in Settings).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

from emailicioso.core.cache import ReputationCache
from emailicioso.core.models import IOCSet
from emailicioso.core.reputation.abuseipdb import AbuseIPDB
from emailicioso.core.reputation.base import Provider, RepResult
from emailicioso.core.reputation.urlscan import UrlScan
from emailicioso.core.reputation.urlvoid import UrlVoid
from emailicioso.core.reputation.virustotal import VirusTotal
from emailicioso.core.settings import Settings

__all__ = ["RepResult", "Provider", "build_providers", "indicators_from_iocs", "run_checks"]


def build_providers(settings: Settings) -> list[Provider]:
    providers: list[Provider] = []
    vt = settings.api_key("virustotal_api_key")
    if vt:
        providers.append(VirusTotal(vt))
    abuse = settings.api_key("abuseipdb_api_key")
    if abuse:
        providers.append(AbuseIPDB(abuse))
    providers.append(UrlScan(settings.api_key("urlscan_api_key")))
    if settings.use_urlvoid_scraper:
        providers.append(UrlVoid())
    return providers


def indicators_from_iocs(iocs: IOCSet, include_urls: bool = True) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = [(d, "domain") for d in iocs.domains]
    items += [(ip, "ip") for ip in iocs.ips]
    items += [(h["sha256"], "hash") for h in iocs.hashes]
    if include_urls:
        items += [(u, "url") for u in iocs.urls]
    return items


def run_checks(
    indicators: list[tuple[str, str]],
    providers: list[Provider],
    cache: ReputationCache | None = None,
    should_stop: Callable[[], bool] = lambda: False,
) -> Iterator[RepResult]:
    """Yield one result per (indicator, provider) pair, using the cache when possible."""
    for indicator, kind in indicators:
        for provider in providers:
            if should_stop():
                return
            if not provider.enabled or not provider.supports(kind):
                continue
            if cache is not None:
                hit = cache.get(provider.name, f"{kind}:{indicator}")
                if hit:
                    res = RepResult.from_dict(hit)
                    res.cached = True
                    yield res
                    continue
            res = provider.check(indicator, kind, should_stop)
            if cache is not None and res.verdict != "error":
                cache.set(provider.name, f"{kind}:{indicator}", res.to_dict())
            yield res
