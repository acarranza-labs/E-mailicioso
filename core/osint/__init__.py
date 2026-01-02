from core.osint.talos import TalosProvider
from core.osint.urlvoid import UrlVoidProvider
from core.osint.xforce import XForceProvider
from core.osint.virustotal import VirusTotalProvider


def build_providers(config: dict):
    return [
        TalosProvider(config),
        UrlVoidProvider(config),
        XForceProvider(config),
        VirusTotalProvider(config),
    ]
