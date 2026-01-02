from core.osint.base import OsintProvider
from core.models import ReputationResult
from core.http_client import HttpClient
from core.cache import Cache


class VirusTotalProvider(OsintProvider):
    name = "virustotal"

    def __init__(self, config: dict):
        self.http = HttpClient()
        self.cache = Cache()

    def check_url(self, url: str) -> ReputationResult:
        cached = self.cache.get(self.name, url)
        if cached:
            return cached

        try:
            lookup = f"https://www.virustotal.com/gui/search/{url}"
            resp = self.http.get(lookup)

            if "malicious" in resp.text.lower():
                result = ReputationResult(self.name, "malicious")
            elif "suspicious" in resp.text.lower():
                result = ReputationResult(self.name, "suspicious")
            else:
                result = ReputationResult(self.name, "unknown")

        except Exception as e:
            result = ReputationResult(self.name, "error", error=str(e))

        self.cache.set(self.name, url, result)
        return result
