"""Common pieces for reputation providers."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

import requests

from emailicioso import __version__

USER_AGENT = f"E-mailicioso/{__version__} (+https://github.com/acarranza-labs/E-mailicioso)"
TIMEOUT = 20

VERDICTS = ("malicious", "suspicious", "clean", "unknown", "error")


@dataclass
class RepResult:
    provider: str
    indicator: str
    kind: str  # domain | ip | url | hash
    verdict: str  # malicious | suspicious | clean | unknown | error
    score: str = ""
    detail: str = ""
    link: str = ""
    error: str = ""
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RepResult:
        return cls(**{k: d.get(k, "") for k in cls.__dataclass_fields__})  # type: ignore[arg-type]


class Provider:
    name = "provider"
    kinds: tuple[str, ...] = ()
    needs_key = True

    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT

    @property
    def enabled(self) -> bool:
        return bool(self.api_key) or not self.needs_key

    def supports(self, kind: str) -> bool:
        return kind in self.kinds

    def check(self, indicator: str, kind: str, should_stop: Callable[[], bool] = lambda: False) -> RepResult:
        raise NotImplementedError

    def _get(self, url: str, headers: dict[str, str] | None = None, params: dict[str, Any] | None = None,
             should_stop: Callable[[], bool] = lambda: False, retries: int = 2,
             backoff: float = 20.0) -> requests.Response:
        """GET with a polite retry on HTTP 429 (free API tiers are heavily rate limited)."""
        for attempt in range(retries + 1):
            resp = self.session.get(url, headers=headers, params=params, timeout=TIMEOUT)
            if resp.status_code != 429 or attempt == retries:
                return resp
            waited = 0.0
            while waited < backoff:
                if should_stop():
                    return resp
                time.sleep(0.5)
                waited += 0.5
        return resp  # pragma: no cover

    def error(self, indicator: str, kind: str, message: str, link: str = "") -> RepResult:
        return RepResult(self.name, indicator, kind, "error", error=message, link=link)
