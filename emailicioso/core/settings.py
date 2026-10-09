"""User settings stored in ~/.emailicioso/settings.json (API keys can come from env vars)."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

DATA_DIR = Path(os.environ.get("EMAILICIOSO_HOME", Path.home() / ".emailicioso"))
SETTINGS_FILE = DATA_DIR / "settings.json"

ENV_KEYS = {
    "virustotal_api_key": ("EMAILICIOSO_VT_API_KEY", "VT_API_KEY"),
    "abuseipdb_api_key": ("EMAILICIOSO_ABUSEIPDB_API_KEY", "ABUSEIPDB_API_KEY"),
    "urlscan_api_key": ("EMAILICIOSO_URLSCAN_API_KEY", "URLSCAN_API_KEY"),
}


@dataclass
class Settings:
    theme: str = "dark"  # dark | light
    defang: bool = True  # show/copy IOCs defanged by default
    summary_language: str = "en"  # en | es (ticket summary)
    hunting_lookback: str = "30d"
    # Reputation lookups send indicators to third parties: off until the analyst asks.
    auto_reputation: bool = False
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    urlscan_api_key: str = ""
    use_urlvoid_scraper: bool = False
    cache_ttl_hours: int = 24
    # Screenshots visit live (possibly malicious) URLs.
    evidence_dir: str = str(Path.home() / "E-mailicioso" / "evidence")
    screenshot_proxy: str = ""  # e.g. socks5://127.0.0.1:9050 or http://proxy:8080
    screenshot_timeout: int = 20
    recent_files: list[str] = field(default_factory=list)

    @classmethod
    def load(cls) -> Settings:
        data: dict = {}
        if SETTINGS_FILE.is_file():
            try:
                data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {}
        known = {f.name for f in fields(cls)}
        s = cls(**{k: v for k, v in data.items() if k in known})
        # Migrate the recent files list of v1.x
        legacy = DATA_DIR / "recent_files.json"
        if not s.recent_files and legacy.is_file():
            try:
                s.recent_files = [str(p) for p in json.loads(legacy.read_text())][:10]
            except (OSError, ValueError):
                pass
        return s

    def save(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        SETTINGS_FILE.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        try:
            os.chmod(SETTINGS_FILE, 0o600)  # contains API keys
        except OSError:
            pass

    def api_key(self, name: str) -> str:
        """API key from settings, falling back to environment variables."""
        value = getattr(self, name, "") or ""
        if value:
            return value
        for env in ENV_KEYS.get(name, ()):
            if os.environ.get(env):
                return os.environ[env]
        return ""

    def add_recent(self, path: str, limit: int = 10) -> None:
        path = str(path)
        if path in self.recent_files:
            self.recent_files.remove(path)
        self.recent_files.insert(0, path)
        del self.recent_files[limit:]
