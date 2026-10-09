"""URL extraction, unwrapping of security rewriters and redirectors, and per-URL risk flags."""

from __future__ import annotations

import base64
import binascii
import re
import string
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

from bs4 import BeautifulSoup

from emailicioso.core import domains as dom
from emailicioso.core.models import Finding, Severity, UrlInfo

URL_RE = re.compile(r"""(?i)\b((?:https?|ftp)://[^\s<>"'`{}|\\^\[\]]+|www\.[^\s<>"'`{}|\\^\[\]]+)""")
_TRAILING = ".,;:!?)]}>'\"»"
_SKIP_SCHEMES = ("mailto:", "tel:", "cid:", "sms:", "callto:", "#", "about:")
EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}(?![\w-])")

REDIRECT_PARAMS = (
    "url", "u", "q", "redirect", "redirect_url", "redirect_uri", "redirecturl", "target", "dest",
    "destination", "goto", "link", "r", "rurl", "returnurl", "return", "return_to", "next",
    "continue", "to", "out", "href", "location",
)
DANGEROUS_PATH_EXT = (
    ".exe", ".scr", ".msi", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta",
    ".ps1", ".lnk", ".iso", ".img", ".vhd", ".vhdx", ".zip", ".rar", ".7z", ".jar", ".apk",
    ".dll", ".cpl", ".msix", ".appx", ".one", ".docm", ".xlsm", ".pptm", ".svg",
)
CREDENTIAL_WORDS = ("login", "signin", "sign-in", "logon", "verify", "account", "secure", "update",
                    "password", "wallet", "auth", "webmail", "owa", "sso", "unlock", "validate")


@dataclass
class RawUrl:
    url: str
    source: str
    display_text: str = ""


# --------------------------------------------------------------------------- extraction


def _clean(u: str) -> str:
    u = u.strip().strip("\"'")
    while u and u[-1] in _TRAILING:
        # keep a closing paren that belongs to the URL: https://x/wiki/A_(b)
        if u[-1] == ")" and u.count("(") >= u.count(")"):
            break
        u = u[:-1]
    if u.lower().startswith("www."):
        u = "http://" + u
    return u


def extract_from_text(text: str, source: str = "text") -> list[RawUrl]:
    return [RawUrl(_clean(m.group(1)), source) for m in URL_RE.finditer(text or "")]


def _soup(html: str) -> BeautifulSoup:
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:
        return BeautifulSoup(html, "html.parser")


def extract_from_html(html: str, source_prefix: str = "html") -> list[RawUrl]:
    if not html:
        return []
    soup = _soup(html)
    out: list[RawUrl] = []
    for a in soup.find_all(["a", "area"], href=True):
        href = a["href"].strip()
        if not href or href.lower().startswith(_SKIP_SCHEMES):
            continue
        text = re.sub(r"\s+", " ", a.get_text(" ", strip=True))[:300] if a.name == "a" else ""
        if not text:
            img = a.find("img")
            if img is not None:
                text = f"[image] {img.get('alt', '')}".strip()
        out.append(RawUrl(_clean(href), source_prefix, text))
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        if action and not action.lower().startswith(_SKIP_SCHEMES):
            out.append(RawUrl(_clean(action), f"{source_prefix}-form"))
    for tag in soup.find_all(["img", "iframe", "script", "embed", "source", "link", "frame"]):
        src = (tag.get("src") or tag.get("href") or "").strip()
        if src and src.lower().startswith(("http://", "https://", "//")):
            if src.startswith("//"):
                src = "https:" + src
            out.append(RawUrl(_clean(src), f"{source_prefix}-resource"))
    for meta in soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
        m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", meta.get("content", ""), re.I)
        if m:
            out.append(RawUrl(_clean(m.group(1)), f"{source_prefix}-refresh"))
    # URLs written as plain text inside the HTML. Anchor texts are removed first: a URL
    # shown as link text is not where the link goes (that case is checked separately).
    for a in soup.find_all("a"):
        a.clear()
    for tag in soup.find_all(["script", "style"]):
        tag.decompose()
    out.extend(extract_from_text(soup.get_text(" "), f"{source_prefix}-text"))
    return out


def extract_emails(*texts: str) -> list[str]:
    seen: list[str] = []
    for t in texts:
        for m in EMAIL_RE.finditer(t or ""):
            e = m.group(0).lower().strip(".")
            if e not in seen:
                seen.append(e)
    return seen


# --------------------------------------------------------------------------- unwrapping

_V3_RUN_MAP = {c: i + 2 for i, c in enumerate(string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_")}


_V3_TOKEN_RE = re.compile(r"\*(\*.)?")


def _proofpoint_v3(url: str) -> str | None:
    m = re.search(r"/v3/__(?P<url>.+?)__;(?P<enc>.*?)!", url)
    if not m:
        return None
    try:
        dec = list(base64.urlsafe_b64decode(m.group("enc") + "==").decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        dec = []

    def replace(token: re.Match[str]) -> str:
        tok = token.group(0)
        if tok == "*":
            return dec.pop(0) if dec else ""
        run = _V3_RUN_MAP.get(tok[-1], 0)
        chunk = "".join(dec[:run])
        del dec[:run]
        return chunk

    return _V3_TOKEN_RE.sub(replace, unquote(m.group("url")))


def _proofpoint_v2(query: dict[str, list[str]]) -> str | None:
    u = query.get("u", [""])[0]
    if not u:
        return None
    return unquote(u.translate(str.maketrans("-_", "%/")))


def _try_decode_param(value: str) -> str | None:
    candidate = unquote(value).strip()
    for _ in range(3):
        if candidate.lower().startswith(("http://", "https://")):
            return candidate
        if candidate.lower().startswith("www."):
            return "http://" + candidate
        nxt = unquote(candidate)
        if nxt == candidate:
            break
        candidate = nxt
    cleaned = value.strip().replace("-", "+").replace("_", "/")
    if len(cleaned) >= 12 and re.fullmatch(r"[A-Za-z0-9+/=]+", cleaned):
        try:
            decoded = base64.b64decode(cleaned + "=" * (-len(cleaned) % 4)).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            decoded = ""
        if decoded.lower().startswith(("http://", "https://")):
            return decoded.strip()
    return None


def unwrap_once(url: str) -> tuple[str, str] | None:
    """Return (next_url, wrapper_name) if the URL is a known wrapper/redirector."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    query = parse_qs(parts.query, keep_blank_values=False)

    if host.endswith("safelinks.protection.outlook.com") or host.endswith("safelinks.protection.office365.us"):
        val = query.get("url", [None])[0]
        if val:
            return unquote(val), "Microsoft Safe Links"
    if host in ("urldefense.com", "urldefense.proofpoint.com", "urldefense.us"):
        if "/v3/" in parts.path:
            res = _proofpoint_v3(url)
            if res:
                return res, "Proofpoint URL Defense v3"
        if "/v2/" in parts.path:
            res = _proofpoint_v2(query)
            if res:
                return res, "Proofpoint URL Defense v2"
        if "/v1/" in parts.path and query.get("u"):
            return unquote(query["u"][0]), "Proofpoint URL Defense v1"
    if host.endswith("protect.mimecast.com") or host.endswith("protect-eu.mimecast.com"):
        return None  # Mimecast tokens can't be decoded offline
    if host.endswith("linkprotect.cudasvc.com"):
        val = query.get("a", [None])[0]
        if val:
            return unquote(val), "Barracuda Link Protect"
    if host.endswith(".trendmicro.com") and "url" in query:
        return unquote(query["url"][0]), "Trend Micro Click Time Protection"
    if host in ("www.google.com", "google.com") and parts.path in ("/url", "/amp/s"):
        val = query.get("q", query.get("url", [None]))[0]
        if val and _try_decode_param(val):
            return _try_decode_param(val), "Google redirect"  # type: ignore[return-value]
    if host in ("l.facebook.com", "lm.facebook.com", "l.instagram.com") and query.get("u"):
        return unquote(query["u"][0]), "Facebook link shim"
    if host == "t.co":
        return None
    for param in REDIRECT_PARAMS:
        for key, values in query.items():
            if key.lower() == param and values:
                decoded = _try_decode_param(values[0])
                if decoded and dom.host_of(decoded) and dom.host_of(decoded) != host:
                    return decoded, f"Redirect parameter '{key}'"
    return None


def unwrap(url: str, max_depth: int = 6) -> tuple[str, list[str]]:
    chain: list[str] = []
    current = url
    for _ in range(max_depth):
        step = unwrap_once(current)
        if not step:
            break
        nxt, name = step
        if not nxt or nxt == current:
            break
        chain.append(name)
        current = nxt
    return current, chain


# --------------------------------------------------------------------------- flags


def _looks_like_url_or_domain(text: str) -> str:
    """If the anchor text shows a URL/domain, return its host."""
    t = text.strip().strip("<>").lower()
    if not t or " " in t.strip():
        return ""
    if t.startswith(("http://", "https://")):
        return dom.host_of(t)
    if t.startswith("www."):
        return dom.host_of("http://" + t)
    if re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+(/\S*)?", t):
        host = t.split("/", 1)[0]
        _sub, label, suffix = dom.split_domain(host)
        if label and suffix:
            return host
    return ""


def assess(url: str, source: str, display_text: str = "") -> UrlInfo:
    final, chain = unwrap(url)
    info = UrlInfo(url=url, source=source, display_text=display_text, final_url=final if chain else "",
                   unwrapped_by=chain)
    target = info.target
    try:
        parts = urlsplit(target)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        parts, host, port = None, "", None
    info.domain = host
    info.registered_domain = dom.registered_domain(host) if host else ""
    flags: list[tuple[Severity, str]] = []

    scheme = (parts.scheme.lower() if parts else "")
    if scheme == "javascript":
        flags.append((Severity.HIGH, "javascript: link"))
    if scheme == "data":
        flags.append((Severity.HIGH, "data: URI (inline content)"))
    if host and dom.is_ip(host):
        flags.append((Severity.MEDIUM, "IP address instead of domain"))
    if host and dom.is_punycode(host):
        flags.append((Severity.MEDIUM, f"Punycode domain ({dom.punycode_to_unicode(host)})"))
    if parts and parts.username:
        flags.append((Severity.HIGH, "Userinfo '@' trick in URL"))
    if port and port not in (80, 443):
        flags.append((Severity.LOW, f"Non-standard port {port}"))
    if host and dom.is_shortener(host):
        flags.append((Severity.LOW, "URL shortener hides the destination"))
    hosting = dom.abused_hosting(host) if host else ""
    if hosting:
        flags.append((Severity.LOW, f"Hosted on frequently abused service ({hosting})"))
    tld = dom.suspicious_tld(host) if host else ""
    if tld:
        flags.append((Severity.LOW, f"High-abuse TLD .{tld}"))
    imp = dom.brand_impersonation(host) if host else None
    if imp:
        brand, kind = imp
        sev = Severity.HIGH if kind == "lookalike" else Severity.MEDIUM
        if kind == "brand-other-tld":
            sev = Severity.LOW
        flags.append((sev, f"Imitates {brand.capitalize()} ({kind.replace('-', ' ')})"))
    if host and host.count(".") >= 4 and not dom.is_ip(host):
        flags.append((Severity.LOW, "Many subdomain levels"))
    path = (parts.path.lower() if parts else "")
    if path.endswith(DANGEROUS_PATH_EXT):
        flags.append((Severity.MEDIUM, f"Direct download of {path.rsplit('.', 1)[-1]} file"))
    if scheme == "http" and source in ("html", "text", "html-text") and any(
        w in target.lower() for w in CREDENTIAL_WORDS
    ):
        flags.append((Severity.LOW, "Unencrypted HTTP link to a login-like page"))
    if chain:
        names = ", ".join(dict.fromkeys(chain))
        flags.append((Severity.INFO, f"Unwrapped: {names}"))
        if "Google redirect" in chain:
            flags.append((Severity.MEDIUM, "Goes through an open redirect (Google)"))
        elif any(n.startswith("Redirect parameter") for n in chain):
            flags.append((Severity.LOW, "Passes through a redirector"))
    if source.endswith("-form"):
        flags.append((Severity.HIGH, "HTML form posts data from inside the email"))
    if source.endswith("-refresh"):
        flags.append((Severity.MEDIUM, "Meta refresh redirect"))

    shown = _looks_like_url_or_domain(display_text)
    if shown and host:
        if dom.registered_domain(shown) != info.registered_domain:
            flags.append((Severity.HIGH, f"Link text shows {shown} but points to {host}"))

    info.flags = [f for _s, f in flags]
    info.flag_levels = [s for s, _f in flags]
    info.severity = max(info.flag_levels, default=Severity.INFO)
    return info


def collect(text: str, html: str) -> list[UrlInfo]:
    """Extract, de-duplicate and assess every URL from a message body."""
    raws = extract_from_text(text, "text") + extract_from_html(html, "html")
    by_url: dict[str, UrlInfo] = {}
    order: list[str] = []
    for r in raws:
        if not r.url or r.url.lower().startswith(_SKIP_SCHEMES):
            continue
        key = r.url
        existing = by_url.get(key)
        if existing is None:
            by_url[key] = assess(r.url, r.source, r.display_text)
            order.append(key)
        elif r.display_text and not existing.display_text:
            # Prefer the anchor version: it carries the visible text for mismatch checks.
            by_url[key] = assess(r.url, r.source, r.display_text)
        elif r.display_text and existing.display_text and r.display_text != existing.display_text:
            alt = assess(r.url, r.source, r.display_text)
            if alt.severity > existing.severity:
                by_url[key] = alt
    return [by_url[k] for k in order]


def url_findings(urls: list[UrlInfo]) -> list[Finding]:
    """Aggregate per-URL flags into message-level findings (one finding per flag type)."""
    groups: dict[str, tuple[Severity, list[str]]] = {}

    def add(key: str, sev: Severity, url: str) -> None:
        cur = groups.get(key)
        if cur is None:
            groups[key] = (sev, [url])
        else:
            groups[key] = (max(cur[0], sev), cur[1] + ([url] if url not in cur[1] else []))

    for u in urls:
        for flag, sev in zip(u.flags, u.flag_levels, strict=False):
            if flag.startswith(("Unwrapped:", "Delivered as a QR code")):
                continue
            key = re.sub(r" \(.*\)$", "", flag)
            key = re.sub(r"^Link text shows .*", "Link text does not match the real destination", key)
            key = re.sub(r"^Direct download of .*", "Links to a direct file download", key)
            key = re.sub(r"^Non-standard port .*", "Non-standard port in URL", key)
            key = re.sub(r"^High-abuse TLD .*", "Links to high-abuse TLDs", key)
            add(key, sev, u.target)

    findings = []
    for title, (sev, evidence) in groups.items():
        detail = _URL_DETAIL.get(title) or (_URL_DETAIL["Imitates a brand"] if title.startswith("Imitates") else "")
        findings.append(Finding(sev, "URL", title, detail, evidence[:20]))
    remote = [u for u in urls if u.source.endswith("-resource")]
    if remote:
        findings.append(Finding(Severity.INFO, "URL", "Remote images/resources (tracking possible)",
                                "Opening the message in a client that loads remote content tells the "
                                "sender it was read.", [u.url for u in remote][:10]))
    return findings


_URL_DETAIL = {
    "Link text does not match the real destination": "The visible text of a link shows one domain but the "
    "link goes to another. One of the most reliable phishing indicators.",
    "HTML form posts data from inside the email": "The email contains a form that submits data "
    "(typically credentials) directly to a remote server.",
    "Userinfo '@' trick in URL": "Everything before '@' in a URL is ignored by the browser, "
    "so http://bank.com@evil.net goes to evil.net.",
    "IP address instead of domain": "Legitimate services rarely link to bare IP addresses.",
    "Punycode domain": "Internationalized domain that may visually imitate another one.",
    "URL shortener hides the destination": "The real destination is only known after following the link.",
    "Hosted on frequently abused service": "Free hosting/forms/storage platforms are widely used for "
    "phishing kits because they inherit a good reputation.",
    "Goes through an open redirect": "A trusted domain (Google) is used to bounce the victim to another site.",
    "Passes through a redirector": "The link bounces through a redirect/tracking URL before the real "
    "destination. Common in newsletters, also used to hide phishing pages.",
    "Links to a direct file download": "The link downloads a file type commonly used to deliver malware.",
    "Imitates a brand": "The link domain uses the brand name or a lookalike of it, but is not owned by the brand.",
    "Links to high-abuse TLDs": "These top-level domains are cheap or loosely policed and host a "
    "disproportionate share of phishing.",
    "Many subdomain levels": "Long chains of subdomains are used to push the real domain out of view on phones.",
    "Non-standard port in URL": "Web services on unusual ports are rare in legitimate email links.",
    "Unencrypted HTTP link to a login-like page": "Credentials would travel in clear text.",
}
