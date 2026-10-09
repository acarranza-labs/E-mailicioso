"""Manual pivot links: open an indicator in the usual threat-intel sites (no API needed).

These links point to the lookup pages, never to the indicator itself.
"""

from __future__ import annotations

from urllib.parse import quote

from emailicioso.core.reputation.virustotal import url_id


def pivot_links(indicator: str, kind: str) -> list[tuple[str, str]]:
    q = quote(indicator, safe="")
    if kind == "domain":
        return [
            ("VirusTotal", f"https://www.virustotal.com/gui/domain/{indicator}"),
            ("urlscan.io", f"https://urlscan.io/search/#{quote(f'page.domain:{indicator}')}"),
            ("Cisco Talos", f"https://talosintelligence.com/reputation_center/lookup?search={q}"),
            ("URLVoid", f"https://www.urlvoid.com/scan/{indicator}/"),
            ("WHOIS (who.is)", f"https://who.is/whois/{indicator}"),
            ("crt.sh certificates", f"https://crt.sh/?q={q}"),
        ]
    if kind == "ip":
        return [
            ("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{indicator}"),
            ("AbuseIPDB", f"https://www.abuseipdb.com/check/{indicator}"),
            ("Cisco Talos", f"https://talosintelligence.com/reputation_center/lookup?search={q}"),
            ("Shodan", f"https://www.shodan.io/host/{indicator}"),
            ("GreyNoise", f"https://viz.greynoise.io/ip/{indicator}"),
        ]
    if kind == "url":
        return [
            ("VirusTotal", f"https://www.virustotal.com/gui/url/{url_id(indicator)}"),
            ("urlscan.io search", f"https://urlscan.io/search/#{quote(f'page.url:{chr(34)}{indicator}{chr(34)}')}"),
            ("URLhaus", f"https://urlhaus.abuse.ch/browse.php?search={q}"),
        ]
    if kind == "hash":
        return [
            ("VirusTotal", f"https://www.virustotal.com/gui/file/{indicator}"),
            ("MalwareBazaar", f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{indicator}"),
            ("Hybrid Analysis", f"https://www.hybrid-analysis.com/search?query={indicator}"),
        ]
    if kind == "email":
        return [("Have I Been Pwned", f"https://haveibeenpwned.com/account/{q}")]
    return []
