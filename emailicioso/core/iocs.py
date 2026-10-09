"""IOC collection and export (JSON / CSV / plain text, optionally defanged)."""

from __future__ import annotations

import csv
import io
import json

from emailicioso.core import domains as dom
from emailicioso.core.models import Address, AttachmentInfo, Hop, IOCSet, UrlInfo

# Shared platforms: keep the full URL as IOC but never the bare domain (blocking it would
# break legitimate use).
SHARED_PLATFORMS = ("api.telegram.org", "discord.com", "discordapp.com", "t.me")

WRAPPER_HOSTS = ("safelinks.protection.outlook.com", "urldefense.com", "urldefense.proofpoint.com",
                 "protect.mimecast.com", "linkprotect.cudasvc.com")


def _is_benign_infra(host: str) -> bool:
    host = host.lower()
    if any(host == w or host.endswith("." + w) for w in WRAPPER_HOSTS):
        return True
    return any(dom.is_brand_domain(host, b) for b in dom.BRANDS)


def _add(lst: list[str], value: str) -> None:
    value = (value or "").strip()
    if value and value not in lst:
        lst.append(value)


def collect_iocs(
    sender: Address | None,
    reply_to: list[Address],
    return_path: str,
    recipients: list[Address],
    hops: list[Hop],
    originating_ip: str,
    urls: list[UrlInfo],
    attachments: list[AttachmentInfo],
    body_emails: list[str],
) -> IOCSet:
    iocs = IOCSet()
    recipient_addrs = {a.address for a in recipients}

    if originating_ip:
        _add(iocs.ips, originating_ip)
    for hop in hops:
        if hop.from_ip and dom.is_public_ip(hop.from_ip):
            _add(iocs.ips, hop.from_ip)

    for addr in [sender, *reply_to]:
        if addr and addr.address:
            _add(iocs.emails, addr.address)
            if addr.domain and not dom.is_freemail(addr.domain) and not _is_benign_infra(addr.domain):
                _add(iocs.domains, addr.domain)
    if return_path and "@" in return_path:
        _add(iocs.emails, return_path.lower())
        rp_dom = dom.domain_of_email(return_path)
        if rp_dom and not dom.is_freemail(rp_dom) and not _is_benign_infra(rp_dom):
            _add(iocs.domains, rp_dom)
    for e in body_emails:
        if e not in recipient_addrs:
            _add(iocs.emails, e)

    for u in urls:
        if u.source.endswith("-resource") and u.severity.value < 2:
            continue
        host = u.domain
        if not host or _is_benign_infra(host):
            continue
        _add(iocs.urls, u.target)
        if dom.is_ip(host):
            if dom.is_public_ip(host):
                _add(iocs.ips, host)
        elif not dom.is_shortener(host) and host not in SHARED_PLATFORMS:
            _add(iocs.domains, host)

    for att in attachments:
        if not att.sha256:
            continue
        if att.is_inline and att.severity.value < 1:
            continue
        iocs.hashes.append({"filename": att.filename, "md5": att.md5, "sha1": att.sha1, "sha256": att.sha256})
    return iocs


def rows(iocs: IOCSet, defanged: bool = False) -> list[tuple[str, str, str]]:
    """(type, value, context) rows, in a stable order."""
    f = dom.defang if defanged else (lambda v: v)
    out: list[tuple[str, str, str]] = []
    out += [("ip", f(v), "") for v in iocs.ips]
    out += [("domain", f(v), "") for v in iocs.domains]
    out += [("url", f(v), "") for v in iocs.urls]
    out += [("email", f(v), "") for v in iocs.emails]
    for h in iocs.hashes:
        out.append(("sha256", h["sha256"], h["filename"]))
        out.append(("sha1", h["sha1"], h["filename"]))
        out.append(("md5", h["md5"], h["filename"]))
    return out


def to_csv(iocs: IOCSet, defanged: bool = False) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["type", "value", "context"])
    w.writerows(rows(iocs, defanged))
    return buf.getvalue()


def to_json(iocs: IOCSet, defanged: bool = False) -> str:
    if not defanged:
        return json.dumps(iocs.to_dict(), indent=2, ensure_ascii=False)
    data = iocs.to_dict()
    for key in ("ips", "domains", "urls", "emails"):
        data[key] = [dom.defang(v) for v in data[key]]
    return json.dumps(data, indent=2, ensure_ascii=False)


def to_text(iocs: IOCSet, defanged: bool = False) -> str:
    f = dom.defang if defanged else (lambda v: v)
    sections = []
    for title, values in (("IPs", iocs.ips), ("Domains", iocs.domains), ("URLs", iocs.urls),
                          ("Email addresses", iocs.emails)):
        if values:
            sections.append(f"# {title}\n" + "\n".join(f(v) for v in values))
    if iocs.hashes:
        sections.append("# File hashes (SHA256  filename)\n" + "\n".join(
            f"{h['sha256']}  {h['filename']}" for h in iocs.hashes))
    return "\n\n".join(sections) + ("\n" if sections else "")
