from core.osint.base import OsintProvider
from core.models import ReputationResult
from core.http_client import HttpClient
from core.cache import Cache
from core.osint.scrape_utils import looks_blocked


class XForceProvider(OsintProvider):
    name = "xforce"

    def __init__(self, config: dict):
        self.http = HttpClient()
        self.cache = Cache()

    def check_url(self, url: str) -> ReputationResult:
        cached = self.cache.get(self.name, url)
        if cached:
            return cached

        try:
            lookup = f"https://exchange.xforce.ibmcloud.com/url/{url}"
            resp = self.http.get(lookup)

            if looks_blocked(resp.status_code, resp.text):
                result = ReputationResult(self.name, "unknown", error="Blocked")
            elif "malicious" in resp.text.lower():
                result = ReputationResult(self.name, "malicious")
            else:
                result = ReputationResult(self.name, "clean")

        except Exception as e:
            result = ReputationResult(self.name, "error", error=str(e))

        self.cache.set(self.name, url, result)
        return result
