"""Domain, IP and lookalike helpers. Works fully offline."""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from urllib.parse import urlsplit

import tldextract

# Bundled Public Suffix List snapshot only: no network access, deterministic results.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.es", "live.com",
    "msn.com", "yahoo.com", "yahoo.es", "ymail.com", "aol.com", "icloud.com", "me.com",
    "mac.com", "gmx.com", "gmx.es", "gmx.net", "proton.me", "protonmail.com", "zoho.com",
    "yandex.com", "yandex.ru", "mail.com", "mail.ru", "tutanota.com", "tuta.io", "web.de",
}

URL_SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "lnkd.in", "s.id",
    "bl.ink", "short.io", "v.gd", "qrco.de", "urlz.fr", "shorturl.gg", "x.co", "trib.al",
    "surl.li", "tinu.be", "u.to", "clck.ru", "linktr.ee",
}

# Legitimate services frequently abused to host phishing kits or payloads.
ABUSED_HOSTING_SUFFIXES = (
    "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "ngrok.io", "ngrok-free.app",
    "ngrok.app", "github.io", "netlify.app", "vercel.app", "glitch.me", "weebly.com",
    "wixsite.com", "square.site", "r2.dev", "storage.googleapis.com", "blob.core.windows.net",
    "azurewebsites.net", "herokuapp.com", "onrender.com", "replit.app", "repl.co",
    "000webhostapp.com", "webflow.io", "framer.app", "godaddysites.com", "mystrikingly.com",
    "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "trycloudflare.com", "surge.sh",
    "sites.google.com", "forms.gle", "typeform.com", "jotform.com", "notion.site",
    "canva.site", "mailchi.mp", "translate.goog", "bubbleapps.io", "carrd.co",
)

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work",
    "support", "rest", "cam", "icu", "lol", "mom", "sbs", "cfd", "quest", "bond", "buzz",
    "monster", "cyou", "beauty", "hair", "skin", "makeup", "boats", "autos", "yachts",
    "today", "live", "fit", "loan", "win", "bid", "date", "racing", "review", "stream",
    "download", "men", "party", "trade", "webcam", "kim", "su", "ru.com",
}

# brand token -> registered domains legitimately owned by the brand
BRANDS: dict[str, tuple[str, ...]] = {
    "microsoft": ("microsoft.com", "microsoftonline.com", "office.com", "office365.com",
                  "live.com", "outlook.com", "sharepoint.com", "azure.com", "windows.net",
                  "msft.net", "microsoft365.com", "msn.com", "onmicrosoft.com", "bing.com",
                  "skype.com", "aka.ms", "microsoftstore.com", "cloud.microsoft",
                  "dynamics.com", "office.net", "msauth.net", "azureedge.net", "microsoftonline-p.com",
                  "microsoftstream.com", "microsoftedge.com", "microsoftazuread-sso.com"),
    "office365": ("office.com", "office365.com", "microsoft.com", "microsoftonline.com"),
    "outlook": ("outlook.com", "live.com", "microsoft.com", "office.com", "office365.com"),
    "sharepoint": ("sharepoint.com", "microsoft.com"),
    "onedrive": ("onedrive.com", "live.com", "microsoft.com", "sharepoint.com"),
    "paypal": ("paypal.com", "paypal.me", "paypalobjects.com", "paypal-communication.com",
               "paypal-community.com"),
    "apple": ("apple.com", "icloud.com", "me.com", "mzstatic.com", "apple.news"),
    "icloud": ("icloud.com", "apple.com"),
    "amazon": ("amazon.com", "amazon.es", "amazon.co.uk", "amazon.de", "amazon.fr",
               "amazon.it", "amazonaws.com", "amazonses.com", "a2z.com", "amazontrust.com",
               "amazonpay.com", "amazon.jobs"),
    "google": ("google.com", "google.es", "googleapis.com", "gmail.com", "googlemail.com",
               "youtube.com", "gstatic.com", "googleusercontent.com", "goo.gl", "g.co",
               "googleadservices.com", "googlesyndication.com", "doubleclick.net",
               "google-analytics.com", "googletagmanager.com", "withgoogle.com",
               "googleblog.com", "googlegroups.com"),
    "docusign": ("docusign.com", "docusign.net"),
    "dropbox": ("dropbox.com", "dropboxmail.com", "db.tt", "dropboxusercontent.com", "dropboxstatic.com"),
    "linkedin": ("linkedin.com", "lnkd.in", "licdn.com"),
    "netflix": ("netflix.com", "nflxext.com", "nflximg.net"),
    "fedex": ("fedex.com",),
    "adobe": ("adobe.com", "adobesign.com", "adobelogin.com", "acrobat.com", "echosign.com"),
    "wetransfer": ("wetransfer.com", "we.tl"),
    "facebook": ("facebook.com", "facebookmail.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com", "facebookmail.com"),
    "whatsapp": ("whatsapp.com", "whatsapp.net"),
    "binance": ("binance.com",),
    "coinbase": ("coinbase.com",),
    "santander": ("santander.com", "bancosantander.es", "santander.es", "santander.co.uk"),
    "caixabank": ("caixabank.es", "caixabank.com", "lacaixa.es"),
    "bankinter": ("bankinter.com", "bankinter.es"),
    "sabadell": ("bancsabadell.com", "sabadell.com"),
    "ingdirect": ("ing.es", "ingdirect.es", "ing.com"),
    "unicaja": ("unicajabanco.es", "unicaja.es"),
    "correos": ("correos.es", "correos.com"),
    "agenciatributaria": ("agenciatributaria.gob.es", "agenciatributaria.es"),
    "seguridadsocial": ("seg-social.es", "seg-social.gob.es"),
    "movistar": ("movistar.es", "movistar.com", "telefonica.com", "telefonica.es"),
    "vodafone": ("vodafone.es", "vodafone.com", "vodafone.co.uk"),
    "iberdrola": ("iberdrola.es", "iberdrola.com"),
    "endesa": ("endesa.com", "endesa.es", "endesaclientes.com"),
    "naturgy": ("naturgy.es", "naturgy.com"),
    "booking": ("booking.com", "bstatic.com"),
    "spotify": ("spotify.com",),
    "zoom": ("zoom.us", "zoom.com"),
}

# Characters attackers commonly swap to fool the eye, mapped to what they imitate.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})
_MULTI_HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("ii", "u"))


def split_domain(host: str) -> tuple[str, str, str]:
    """(subdomain, label, suffix) using the bundled Public Suffix List."""
    host = (host or "").strip().strip(".").lower()
    if not host or is_ip(host):
        return "", host, ""
    ext = _EXTRACT(host)
    return ext.subdomain, ext.domain, ext.suffix


@lru_cache(maxsize=4096)
def registered_domain(host: str) -> str:
    """example.co.uk for a.b.example.co.uk. Returns the host itself for IPs."""
    host = (host or "").strip().strip(".").lower()
    if not host:
        return ""
    if is_ip(host):
        return host
    _sub, label, suffix = split_domain(host)
    if label and suffix:
        return f"{label}.{suffix}"
    return host


def host_of(url: str) -> str:
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname or ""
    except ValueError:
        return ""
    return host.strip(".").lower()


def domain_of_email(address: str) -> str:
    if "@" not in (address or ""):
        return ""
    return address.rsplit("@", 1)[1].strip().strip(">").lower()


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)]


def is_public_ip(value: str) -> bool:
    """True for addresses outside internal/infrastructure ranges (RFC 1918, loopback, CGNAT...).

    Documentation ranges (TEST-NET) count as external on purpose: from a mail-routing
    point of view they are not part of the recipient's infrastructure.
    """
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not any(ip in net for net in _INTERNAL_NETS if net.version == ip.version)


def is_freemail(domain: str) -> bool:
    return registered_domain(domain) in FREEMAIL_DOMAINS or domain.lower() in FREEMAIL_DOMAINS


def is_shortener(host: str) -> bool:
    host = host.lower()
    return host in URL_SHORTENERS or registered_domain(host) in URL_SHORTENERS


def abused_hosting(host: str) -> str:
    host = host.lower()
    for suffix in ABUSED_HOSTING_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return suffix
    return ""


def suspicious_tld(host: str) -> str:
    _sub, _label, suffix = split_domain(host)
    last = suffix.rsplit(".", 1)[-1] if suffix else ""
    if suffix in SUSPICIOUS_TLDS:
        return suffix
    if last in SUSPICIOUS_TLDS:
        return last
    return ""


def is_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.lower().split("."))


def punycode_to_unicode(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


def _normalize_homoglyphs(label: str) -> str:
    out = label.lower().translate(_HOMOGLYPHS)
    for seq, repl in _MULTI_HOMOGLYPHS:
        out = out.replace(seq, repl)
    return re.sub(r"[^a-z]", "", out)


def _levenshtein(a: str, b: str, limit: int = 2) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > limit:
            return limit + 1
        prev = cur
    return prev[-1]


def is_brand_domain(host: str, brand: str) -> bool:
    reg = registered_domain(host)
    for legit in BRANDS.get(brand, ()):
        if reg == legit or host == legit or host.endswith("." + legit):
            return True
    return False


def _tokens(text: str) -> list[str]:
    return [_normalize_homoglyphs(t) for t in re.split(r"[-_.]+", text.lower()) if t]


def _token_has_brand(token: str, brand: str) -> bool:
    if token == brand or token.startswith(brand):
        return True
    return len(brand) >= 6 and token.endswith(brand)


def brand_impersonation(host: str) -> tuple[str, str] | None:
    """Detect domains that imitate well-known brands.

    Returns (brand, kind) or None. Kinds, from strongest to weakest:
      lookalike           paypa1.com, rnicrosoft.com, micosoft.com, xn--pypal-4ve.com
      brand-in-domain     microsoft-login-secure.com, paypalsupport.net
      brand-in-subdomain  login.microsoft.com.evil-site.net
      brand-other-tld     santander.xyz (brand label on a domain the brand doesn't use)
    """
    host = (host or "").lower().strip(".")
    if not host or is_ip(host):
        return None
    if any(is_brand_domain(host, b) for b in BRANDS):
        return None
    sub, label, _suffix = split_domain(host)
    if not label:
        return None

    raw_label = re.sub(r"[^a-z0-9]", "", label)
    uni_label = punycode_to_unicode(label) if label.startswith("xn--") else label
    norm_label = _normalize_homoglyphs(uni_label)
    candidates = [b for b in BRANDS if len(b) >= 5]

    for brand in candidates:
        if norm_label == brand and raw_label != brand:
            return brand, "lookalike"
        if len(brand) >= 6 and norm_label != brand and _levenshtein(norm_label, brand, 1) <= 1:
            return brand, "lookalike"
    for brand in candidates:
        if norm_label != brand and any(_token_has_brand(t, brand) for t in _tokens(uni_label)):
            return brand, "brand-in-domain"
    for brand in candidates:
        if any(_token_has_brand(t, brand) for t in _tokens(sub)):
            return brand, "brand-in-subdomain"
    for brand in candidates:
        if norm_label == brand:
            return brand, "brand-other-tld"
    return None


# --------------------------------------------------------------------------- defanging


def defang_url(url: str) -> str:
    out = re.sub(r"^http", "hxxp", url, flags=re.I)
    out = re.sub(r"^ftp", "fxp", out, flags=re.I)
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        host = ""
    if host:
        idx = out.lower().find(host)
        if idx != -1:
            out = out[:idx] + host.replace(".", "[.]") + out[idx + len(host):]
    return out


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def defang_ip(ip: str) -> str:
    if ":" in ip:
        return ip.replace(":", "[:]")
    return ip.replace(".", "[.]")


def defang_email(address: str) -> str:
    if "@" not in address:
        return address
    user, dom = address.rsplit("@", 1)
    return f"{user}[@]{defang_domain(dom)}"


def defang(value: str) -> str:
    """Defang any indicator (URL, email, IP or domain)."""
    v = value.strip()
    if re.match(r"^[a-z][a-z0-9+.-]*://", v, re.I):
        return defang_url(v)
    if "@" in v:
        return defang_email(v)
    if is_ip(v):
        return defang_ip(v)
    return defang_domain(v)


def refang(value: str) -> str:
    v = value.replace("[.]", ".").replace("(.)", ".").replace("[@]", "@").replace("[:]", ":")
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    v = re.sub(r"^fxp", "ftp", v, flags=re.I)
    return v
