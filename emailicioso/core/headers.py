"""Header analysis: authentication, routing (Received hops), sender consistency and
verdicts left by mail security gateways (Microsoft EOP/Defender, Proofpoint, SpamAssassin...).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import getaddresses, parsedate_to_datetime

from emailicioso.core import domains as dom
from emailicioso.core.models import (
    Address,
    AuthResult,
    Finding,
    GatewayVerdict,
    Hop,
    ParsedEmail,
    Severity,
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IP_BRACKET_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
_ZERO_WIDTH_RE = re.compile("[​‌‍⁠﻿­]")

AUTH_NAMES = {"spf": "SPF", "dkim": "DKIM", "dmarc": "DMARC", "arc": "ARC", "compauth": "CompAuth"}

MS_SFV = {
    "SPM": "Marked as spam by spam filtering",
    "SKS": "Marked as spam before spam filtering (mail flow rule)",
    "BLK": "Blocked: sender on the recipient's blocked senders list",
    "NSPM": "Not spam",
    "SKN": "Marked as not spam before filtering (mail flow rule)",
    "SKA": "Skipped filtering: allowed by admin policy",
    "SKB": "Marked as spam: matched a blocked sender/domain in policy",
    "SKI": "Intra-organization message, filtering skipped",
    "SKQ": "Released from quarantine",
    "SFE": "Skipped filtering: sender on the recipient's safe senders list",
}
MS_CAT = {
    "AMP": "Anti-malware",
    "BIMP": "Brand impersonation",
    "BULK": "Bulk",
    "DIMP": "Domain impersonation",
    "FTBP": "Anti-malware common attachments filter",
    "GIMP": "Mailbox intelligence impersonation",
    "HPHSH": "High confidence phishing",
    "HPHISH": "High confidence phishing",
    "HSPM": "High confidence spam",
    "INTOS": "Intra-organization phishing",
    "MALW": "Malware",
    "OSPM": "Outbound spam",
    "PHSH": "Phishing",
    "SAP": "Safe Attachments",
    "SPM": "Spam",
    "SPOOF": "Spoofing",
    "UIMP": "User impersonation",
    "NONE": "None",
}
MS_CAT_HIGH = {"HPHSH", "HPHISH", "PHSH", "MALW", "AMP", "FTBP", "SAP", "SPOOF", "BIMP", "DIMP", "UIMP", "GIMP", "INTOS"}


@dataclass
class HeaderReport:
    sender: Address | None = None
    reply_to: list[Address] = field(default_factory=list)
    return_path: str = ""
    recipients: list[Address] = field(default_factory=list)
    auth: list[AuthResult] = field(default_factory=list)
    gateway: list[GatewayVerdict] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)
    originating_ip: str = ""
    network_message_id: str = ""
    findings: list[Finding] = field(default_factory=list)


# --------------------------------------------------------------------------- addresses


def make_address(display: str, address: str) -> Address:
    address = (address or "").strip().strip("<>").lower()
    domain = dom.domain_of_email(address)
    return Address(
        display_name=(display or "").strip().strip('"'),
        address=address,
        domain=domain,
        registered_domain=dom.registered_domain(domain) if domain else "",
    )


def parse_addresses(value: str) -> list[Address]:
    if not value:
        return []
    out = []
    for display, addr in getaddresses([value]):
        if addr or display:
            out.append(make_address(display, addr))
    return out


# --------------------------------------------------------------------------- authentication


def _split_segments(value: str) -> list[str]:
    """Split an Authentication-Results value on ';' ignoring those inside (comments)."""
    segs, buf, depth = [], [], 0
    for ch in value:
        if ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        if ch == ";" and depth == 0:
            segs.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    segs.append("".join(buf))
    return [s.strip() for s in segs if s.strip()]


_METHOD_RE = re.compile(r"^([A-Za-z][\w.-]*)\s*=\s*([A-Za-z]+)", re.S)


def parse_auth_header(value: str, source: str) -> list[AuthResult]:
    results = []
    for seg in _split_segments(value):
        m = _METHOD_RE.match(seg)
        if not m:
            continue
        method = m.group(1).lower()
        if method not in AUTH_NAMES:
            continue
        results.append(
            AuthResult(
                mechanism=AUTH_NAMES[method],
                result=m.group(2).lower(),
                details=re.sub(r"\s+", " ", seg),
                source=source,
            )
        )
    return results


def parse_authentication(parsed: ParsedEmail) -> list[AuthResult]:
    results: list[AuthResult] = []
    ar_headers = parsed.headers_all("Authentication-Results")
    for i, value in enumerate(ar_headers):
        label = "Authentication-Results" if i == 0 else f"Authentication-Results #{i + 1}"
        results.extend(parse_auth_header(value, label))
    for value in parsed.headers_all("ARC-Authentication-Results"):
        results.extend(parse_auth_header(value, "ARC-Authentication-Results"))
    if not any(r.mechanism == "SPF" for r in results):
        rspf = parsed.header("Received-SPF")
        if rspf:
            word = rspf.split(None, 1)[0].lower().strip("();")
            results.append(AuthResult("SPF", word, rspf, "Received-SPF"))
    return results


def _auth_findings(auth: list[AuthResult]) -> list[Finding]:
    findings: list[Finding] = []
    if not auth:
        findings.append(
            Finding(
                Severity.INFO,
                "Authentication",
                "No authentication results in headers",
                "The message has no Authentication-Results header. It may have been exported "
                "before delivery, from the sender side, or headers were stripped.",
            )
        )
        return findings
    primary: dict[str, AuthResult] = {}
    for ar in auth:
        if ar.source.startswith("ARC"):
            continue
        primary.setdefault(ar.mechanism, ar)

    def add(mech: str, sev: Severity, title: str, detail: str) -> None:
        ar = primary.get(mech)
        findings.append(Finding(sev, "Authentication", title, detail, [ar.details] if ar else []))

    dmarc = primary.get("DMARC")
    if dmarc and dmarc.failed:
        add("DMARC", Severity.HIGH, "DMARC failed",
            "The From domain is not aligned with an authenticated SPF/DKIM domain. "
            "Classic sign of direct domain spoofing.")
    comp = primary.get("CompAuth")
    if comp and comp.failed:
        add("CompAuth", Severity.HIGH, "Microsoft composite authentication failed",
            "Exchange Online Protection could not authenticate the sender (compauth=fail).")
    spf = primary.get("SPF")
    if spf and spf.result in ("fail", "permerror"):
        add("SPF", Severity.MEDIUM, "SPF failed",
            "The sending server is not authorized to send for the envelope (MAIL FROM) domain.")
    elif spf and spf.result == "softfail":
        add("SPF", Severity.LOW, "SPF softfail",
            "The sending server is probably not authorized for the envelope domain (~all).")
    dkim = primary.get("DKIM")
    if dkim and dkim.result in ("fail", "permerror"):
        add("DKIM", Severity.MEDIUM, "DKIM signature failed",
            "The DKIM signature did not verify: the message may have been altered or forged.")
    if dmarc and dmarc.result == "none" and spf and not spf.passed and not (dkim and dkim.passed):
        add("DMARC", Severity.LOW, "Sender domain has no DMARC policy",
            "Without DMARC the From domain is trivially spoofable.")
    return findings


# --------------------------------------------------------------------------- routing


def _first_ip(text: str) -> str:
    # Postfix/Sendmail: "from HELO (rdns [IP])" and Exchange: "from host (IP)". The address
    # inside the parenthesized comment is the one the receiving server actually saw;
    # the HELO name before it is chosen by the sender and can be anything.
    for comment in re.findall(r"\(([^()]*)\)", text):
        for m in _IP_BRACKET_RE.finditer(comment):
            if dom.is_ip(m.group(1)):
                return m.group(1)
        for regex in (_IPV4_RE, _IPV6_RE):
            for m in regex.finditer(comment):
                if dom.is_ip(m.group(0)):
                    return m.group(0)
    for m in _IP_BRACKET_RE.finditer(text):
        if dom.is_ip(m.group(1)):
            return m.group(1)
    for regex in (_IPV4_RE, _IPV6_RE):
        for m in regex.finditer(text):
            if dom.is_ip(m.group(0)):
                return m.group(0)
    return ""


def _to_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_received(value: str) -> tuple[str, str, str, str, datetime | None]:
    text = re.sub(r"\s+", " ", value).strip()
    body, _, date_part = text.rpartition(";")
    if not body:
        body, date_part = text, ""
    from_clause = ""
    m = re.search(r"\bfrom\s+(.+?)(?=\s+by\s|\s+with\s|\s+id\s|\s+via\s|\s+for\s|$)", body, re.I)
    if m:
        from_clause = m.group(1)
    by = re.search(r"\bby\s+([^\s;()]+)", body, re.I)
    proto = re.search(r"\bwith\s+([^\s;()]+)", body, re.I)
    from_host = from_clause.split(" ", 1)[0].strip("()[]") if from_clause else ""
    from_ip = _first_ip(from_clause)
    if from_host == from_ip:
        from_host = ""
    ts = None
    if date_part.strip():
        try:
            ts = parsedate_to_datetime(date_part.strip())
        except (TypeError, ValueError, IndexError):
            ts = None
    return from_host, from_ip, by.group(1) if by else "", proto.group(1) if proto else "", ts


def parse_hops(parsed: ParsedEmail) -> list[Hop]:
    received = parsed.headers_all("Received")
    hops: list[Hop] = []
    prev_ts: datetime | None = None
    for i, raw in enumerate(reversed(received), 1):
        from_host, from_ip, by_host, proto, ts = parse_received(raw)
        ts_utc = _to_utc(ts)
        delay = (ts_utc - prev_ts).total_seconds() if ts_utc and prev_ts else None
        hops.append(Hop(i, from_host, from_ip, by_host, proto, ts, delay, raw))
        if ts_utc:
            prev_ts = ts_utc
    return hops


def originating_ip(parsed: ParsedEmail, hops: list[Hop]) -> str:
    for name in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP"):
        ip = parsed.header(name).strip().strip("[]")
        if ip and dom.is_public_ip(ip):
            return ip
    for hop in hops:
        if hop.from_ip and dom.is_public_ip(hop.from_ip):
            return hop.from_ip
    return ""


def _routing_findings(parsed: ParsedEmail, hops: list[Hop]) -> list[Finding]:
    findings: list[Finding] = []
    backwards = [h for h in hops if h.delay_seconds is not None and h.delay_seconds < -300]
    if backwards:
        findings.append(
            Finding(
                Severity.LOW,
                "Routing",
                "Received timestamps go backwards",
                "One or more hops are older than the previous one by more than 5 minutes. "
                "Can be clock skew, or Received headers forged by the sender.",
                [f"Hop {h.index}: {h.delay_seconds / 60:.0f} min" for h in backwards],
            )
        )
    first_ts = next((_to_utc(h.timestamp) for h in hops if h.timestamp), None)
    if first_ts and parsed.date:
        try:
            date_hdr = _to_utc(parsedate_to_datetime(parsed.date))
        except (TypeError, ValueError, IndexError):
            date_hdr = None
        if date_hdr and abs((first_ts - date_hdr).total_seconds()) > 86400:
            findings.append(
                Finding(
                    Severity.LOW,
                    "Routing",
                    "Date header far from first Received timestamp",
                    "The Date header differs from the first hop by more than 24 hours: "
                    "the message may be backdated or was held before sending.",
                    [f"Date: {parsed.date}", f"First hop: {first_ts.isoformat()}"],
                )
            )
    return findings


# --------------------------------------------------------------------------- sender


def _display_name_brand(display: str) -> str:
    tokens = [dom._normalize_homoglyphs(t) for t in re.split(r"[^A-Za-z0-9]+", display) if t]
    joined = "".join(tokens)
    for brand in dom.BRANDS:
        if len(brand) < 5:
            continue
        if brand in tokens or (len(brand) >= 7 and brand in joined):
            return brand
    return ""


def _sender_findings(parsed: ParsedEmail, rep: HeaderReport) -> list[Finding]:
    findings: list[Finding] = []
    froms = parse_addresses(parsed.from_)
    if not froms or not froms[0].address:
        findings.append(Finding(Severity.MEDIUM, "Sender", "Missing or unparseable From address",
                                "Legitimate mail almost always has a valid From address.", [parsed.from_]))
        return findings
    sender = froms[0]
    if len(froms) > 1:
        findings.append(Finding(Severity.LOW, "Sender", "Multiple From addresses",
                                "Unusual and sometimes used to confuse mail clients.", [parsed.from_]))

    # Display name spoofing: "ceo@company.com <attacker@gmail.com>"
    shown = _EMAIL_RE.findall(sender.display_name)
    if shown and any(s.lower() != sender.address for s in shown):
        findings.append(Finding(
            Severity.HIGH, "Sender", "Display name shows a different email address",
            "The display name contains an address that is not the real sender, "
            "so most clients will show the fake one.",
            [str(sender)]))

    brand = _display_name_brand(sender.display_name)
    if brand and not dom.is_brand_domain(sender.domain, brand):
        findings.append(Finding(
            Severity.MEDIUM, "Sender", f"Display name impersonates {brand.capitalize()}",
            f"The sender name mentions {brand.capitalize()} but the address belongs to "
            f"{sender.domain or 'an unknown domain'}.",
            [str(sender)]))

    imp = dom.brand_impersonation(sender.domain)
    if imp:
        brand_i, kind = imp
        sev = {"lookalike": Severity.HIGH, "brand-in-domain": Severity.MEDIUM,
               "brand-in-subdomain": Severity.MEDIUM}.get(kind, Severity.LOW)
        findings.append(Finding(
            sev, "Sender", f"Sender domain imitates {brand_i.capitalize()} ({kind.replace('-', ' ')})",
            f"{sender.domain} is not a domain owned by {brand_i.capitalize()}.", [sender.address]))
    if dom.is_punycode(sender.domain):
        findings.append(Finding(
            Severity.MEDIUM, "Sender", "Sender domain uses punycode (IDN)",
            f"{sender.domain} renders as {dom.punycode_to_unicode(sender.domain)}. "
            "Internationalized domains are often used for homograph attacks.", [sender.address]))
    if dom.is_freemail(sender.domain):
        findings.append(Finding(Severity.INFO, "Sender", "Sent from a free webmail provider",
                                f"{sender.domain} is a consumer email service.", [sender.address]))
    tld = dom.suspicious_tld(sender.domain)
    if tld:
        findings.append(Finding(Severity.LOW, "Sender", f"Sender domain uses a high-abuse TLD (.{tld})",
                                "This TLD is disproportionately used for malicious domains.", [sender.domain]))

    # Reply-To diversion (BEC pattern)
    diverted = [a for a in rep.reply_to if a.address and a.registered_domain != sender.registered_domain]
    if diverted:
        to_free = any(dom.is_freemail(a.domain) for a in diverted) and not dom.is_freemail(sender.domain)
        findings.append(Finding(
            Severity.HIGH if to_free else Severity.MEDIUM, "Sender",
            "Reply-To sends answers to a different domain",
            "Replies will go to a mailbox outside the sender's domain"
            + (" (a free webmail account)" if to_free else "")
            + ". Common in BEC and invoice fraud.",
            [f"From: {sender.address}"] + [f"Reply-To: {a.address}" for a in diverted]))

    rp = rep.return_path
    rp_dom = dom.registered_domain(dom.domain_of_email(rp)) if rp else ""
    if rp_dom and sender.registered_domain and rp_dom != sender.registered_domain:
        findings.append(Finding(
            Severity.LOW, "Sender", "Return-Path domain differs from From",
            "The envelope sender (bounce address) is in another domain. Normal for newsletters "
            "and ESPs, but also typical of spoofing.",
            [f"From: {sender.address}", f"Return-Path: {rp}"]))

    if not parsed.message_id and parsed.source_format == "eml":
        findings.append(Finding(Severity.LOW, "Sender", "Missing Message-ID",
                                "Mail servers add a Message-ID; its absence suggests a hand-crafted message."))

    subj = parsed.subject or ""
    # Only replies: forwards legitimately start new threads (and reported phish arrive as FW:).
    if re.match(r"^\s*(re|rv|res|aw|sv|antw)\s*:", subj, re.I) and not (
        parsed.header("In-Reply-To") or parsed.header("References") or parsed.header("Thread-Index")
    ):
        findings.append(Finding(
            Severity.LOW, "Content", "Fake reply subject",
            "The subject starts with RE: but the message is not part of any thread "
            "(no In-Reply-To, References or Thread-Index). A common trick to lower the guard.", [subj]))
    if _ZERO_WIDTH_RE.search(subj) or _ZERO_WIDTH_RE.search(sender.display_name):
        findings.append(Finding(Severity.LOW, "Content", "Invisible characters in subject or sender name",
                                "Zero-width characters are used to evade keyword filters.", [subj]))
    return findings


# --------------------------------------------------------------------------- gateways


def _kv_pairs(value: str, sep: str = ";", kv: str = ":") -> dict[str, str]:
    out: dict[str, str] = {}
    for part in value.split(sep):
        if kv in part:
            k, v = part.split(kv, 1)
            out[k.strip().upper()] = v.strip()
    return out


def parse_gateway(parsed: ParsedEmail) -> tuple[list[GatewayVerdict], list[Finding]]:
    verdicts: list[GatewayVerdict] = []
    findings: list[Finding] = []

    fopr = parsed.header("X-Forefront-Antispam-Report")
    if fopr:
        kv = _kv_pairs(fopr)
        scl = kv.get("SCL", "")
        sfv = kv.get("SFV", "")
        cat = kv.get("CAT", "")
        if scl:
            try:
                scl_i = int(scl)
            except ValueError:
                scl_i = -2
            verdicts.append(GatewayVerdict("Microsoft", "SCL", scl,
                                           "Spam confidence level (-1 bypass, 0-1 clean, 5-6 spam, 9 high confidence)",
                                           scl_i >= 5))
        if sfv:
            verdicts.append(GatewayVerdict("Microsoft", "SFV", sfv, MS_SFV.get(sfv, ""),
                                           sfv in ("SPM", "SKS", "BLK", "SKB")))
        if cat:
            verdicts.append(GatewayVerdict("Microsoft", "CAT", cat, MS_CAT.get(cat, ""),
                                           cat not in ("NONE", "")))
        for key, label in (("CTRY", "Source country"), ("CIP", "Connecting IP"), ("PTR", "Reverse DNS"),
                           ("IPV", "IP reputation (NLI = not listed, CAL = allowed)"), ("DIR", "Direction")):
            if kv.get(key):
                verdicts.append(GatewayVerdict("Microsoft", key, kv[key], label))
        if cat in MS_CAT_HIGH:
            findings.append(Finding(Severity.HIGH, "Gateway",
                                    f"Microsoft Defender classified it as {MS_CAT.get(cat, cat)}",
                                    "Exchange Online Protection / Defender for Office 365 flagged this message.",
                                    [f"CAT:{cat}", f"SFV:{sfv}", f"SCL:{scl}"]))
        elif cat in ("SPM", "HSPM") or sfv in ("SPM", "SKS") or (scl.isdigit() and int(scl) >= 5):
            findings.append(Finding(Severity.MEDIUM, "Gateway", "Microsoft filtering marked it as spam",
                                    "Exchange Online Protection scored this message as spam.",
                                    [f"CAT:{cat}", f"SFV:{sfv}", f"SCL:{scl}"]))
        elif cat == "BULK":
            findings.append(Finding(Severity.INFO, "Gateway", "Microsoft classified it as bulk mail", "",
                                    [f"CAT:{cat}"]))

    msas = parsed.header("X-Microsoft-Antispam")
    if msas:
        bcl = _kv_pairs(msas).get("BCL")
        if bcl:
            verdicts.append(GatewayVerdict("Microsoft", "BCL", bcl, "Bulk complaint level (0-9)",
                                           bcl.isdigit() and int(bcl) >= 7))
    auth_as = parsed.header("X-MS-Exchange-Organization-AuthAs")
    if auth_as:
        verdicts.append(GatewayVerdict("Microsoft", "AuthAs", auth_as,
                                       "Anonymous = external sender, Internal = authenticated in the tenant"))

    pp = parsed.header("X-Proofpoint-Spam-Details")
    if pp:
        kv = {k.lower(): v for k, v in _kv_pairs(pp, sep=" ", kv="=").items()}
        rule = kv.get("rule", "")
        if rule:
            verdicts.append(GatewayVerdict("Proofpoint", "rule", rule, "Matched rule",
                                           not rule.startswith("notspam") and rule not in ("safe",)))
        worst = 0
        for key in ("phishscore", "spamscore", "malwarescore", "suspectscore", "bulkscore", "impostorscore"):
            if key in kv:
                try:
                    val = int(kv[key])
                except ValueError:
                    continue
                verdicts.append(GatewayVerdict("Proofpoint", key, kv[key], "0-100", val >= 50))
                if key != "bulkscore":
                    worst = max(worst, val)
        if worst >= 80 or "phish" in rule or "malware" in rule:
            findings.append(Finding(Severity.HIGH, "Gateway", "Proofpoint scored it as malicious",
                                    "Proofpoint gave a high phish/malware/spam score.", [pp[:200]]))
        elif worst >= 50 or rule.startswith("spam"):
            findings.append(Finding(Severity.MEDIUM, "Gateway", "Proofpoint scored it as spam/suspicious",
                                    "", [pp[:200]]))

    flag = parsed.header("X-Spam-Flag")
    status = parsed.header("X-Spam-Status")
    if flag or status:
        verdicts.append(GatewayVerdict("SpamAssassin", "X-Spam-Status", status or flag))
        if flag.strip().upper() == "YES" or status.strip().lower().startswith("yes"):
            findings.append(Finding(Severity.MEDIUM, "Gateway", "SpamAssassin flagged it as spam", "",
                                    [status or flag]))
    for name, vendor in (("X-Mimecast-Spam-Score", "Mimecast"), ("X-Barracuda-Spam-Score", "Barracuda"),
                         ("X-Spam-Score", "Generic")):
        val = parsed.header(name)
        if val:
            verdicts.append(GatewayVerdict(vendor, name, val))
    return verdicts, findings


# --------------------------------------------------------------------------- entry point


def analyze_headers(parsed: ParsedEmail) -> HeaderReport:
    rep = HeaderReport()
    froms = parse_addresses(parsed.from_)
    rep.sender = froms[0] if froms else None
    rep.reply_to = parse_addresses(parsed.header("Reply-To"))
    rep.return_path = parsed.header("Return-Path").strip().strip("<>")
    rep.recipients = parse_addresses(parsed.to) + parse_addresses(parsed.cc)
    rep.auth = parse_authentication(parsed)
    rep.hops = parse_hops(parsed)
    rep.originating_ip = originating_ip(parsed, rep.hops)
    for name in (
        "X-MS-Exchange-Organization-Network-Message-Id",
        "X-MS-Exchange-CrossTenant-Network-Message-Id",
        "X-MS-Office365-Filtering-Correlation-Id",
    ):
        val = parsed.header(name).strip()
        if val:
            rep.network_message_id = val
            break
    rep.gateway, gw_findings = parse_gateway(parsed)

    rep.findings.extend(_sender_findings(parsed, rep))
    rep.findings.extend(_auth_findings(rep.auth))
    rep.findings.extend(_routing_findings(parsed, rep.hops))
    rep.findings.extend(gw_findings)
    return rep
