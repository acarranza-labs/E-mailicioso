"""Single entry point that runs every analysis step and returns an :class:`AnalysisResult`."""

from __future__ import annotations

import re
from pathlib import Path

from emailicioso.core import attachments as att_mod
from emailicioso.core import content, headers, hunting, iocs, qr, scoring, urls
from emailicioso.core.models import AnalysisResult, Finding, ParsedEmail, Severity, UrlInfo
from emailicioso.core.parser import parse_bytes, parse_file

_PDF_URI_RE = re.compile(rb"/URI\s*\(([^)]{4,2000})\)")
_BENIGN_DEFECTS = {"MissingHeaderBodySeparatorDefect", "InvalidHeaderDefect", "NonASCIILocalPartDefect"}


def _attachment_urls(parsed: ParsedEmail) -> list[UrlInfo]:
    found: list[UrlInfo] = []
    for att in parsed.attachments:
        if att.is_email or not att.payload:
            continue
        src = f"attachment:{att.filename}"
        raws: list[urls.RawUrl] = []
        if att.detected_type in ("HTML document", "SVG image"):
            html = att.payload.decode("utf-8", errors="replace")
            raws = urls.extract_from_html(html, src)
            raws += urls.extract_from_text(html, src)
        elif att.detected_type == "PDF document":
            for m in _PDF_URI_RE.finditer(att.payload):
                raws.append(urls.RawUrl(m.group(1).decode("latin-1", "replace").strip(), src))
        elif att.detected_type in ("Text", "iCalendar invite", "XML document"):
            raws = urls.extract_from_text(att.payload[:2_000_000].decode("utf-8", "replace"), src)
        seen = set()
        for r in raws:
            if r.url and r.url not in seen and r.url.lower().startswith(("http://", "https://")):
                seen.add(r.url)
                found.append(urls.assess(r.url, src if not r.source.endswith("-form") else src + "-form",
                                         r.display_text))
    return found


def _qr_urls(parsed: ParsedEmail) -> tuple[list[UrlInfo], list[Finding]]:
    out: list[UrlInfo] = []
    findings: list[Finding] = []
    by_name = {a.filename: a for a in parsed.attachments}
    for filename, payload in qr.scan_attachments(parsed.attachments):
        text = payload.strip()
        att = by_name.get(filename)
        if att is not None and "Contains a QR code" not in att.flags:
            att.flags.insert(0, "Contains a QR code")
            att.severity = max(att.severity, Severity.LOW)
        if re.match(r"^(https?://|www\.)", text, re.I):
            info = urls.assess(text if not text.lower().startswith("www.") else "http://" + text, f"qr:{filename}")
            info.flags.insert(0, "Delivered as a QR code (quishing)")
            info.flag_levels.insert(0, Severity.MEDIUM)
            info.severity = max(info.severity, Severity.MEDIUM)
            out.append(info)
        else:
            findings.append(Finding(Severity.INFO, "Attachment", f"QR code in {filename}",
                                    "The QR code does not contain a web link.", [text[:200]]))
    if out:
        findings.append(Finding(Severity.MEDIUM, "URL", "Link hidden in a QR code (quishing)",
                                "QR codes move the click to a phone, outside corporate protections "
                                "(Safe Links, proxy, EDR).", [u.url for u in out]))
    return out, findings


def analyze_parsed(parsed: ParsedEmail, lookback: str = "30d") -> AnalysisResult:
    hdr = headers.analyze_headers(parsed)
    for att in parsed.attachments:
        att_mod.analyze_attachment(att)

    url_list = urls.collect(parsed.text_body, parsed.html_body)
    known = {u.url for u in url_list}
    for extra in _attachment_urls(parsed):
        if extra.url not in known:
            known.add(extra.url)
            url_list.append(extra)
    qr_list, qr_findings = _qr_urls(parsed)
    url_list.extend(u for u in qr_list if u.url not in known)

    findings: list[Finding] = []
    findings += hdr.findings
    findings += urls.url_findings(url_list)
    findings += qr_findings
    findings += att_mod.attachment_findings(parsed.attachments)
    findings += content.analyze_content(parsed)
    odd = [d for d in parsed.defects if d not in _BENIGN_DEFECTS]
    if odd:
        findings.append(Finding(Severity.LOW if len(odd) > 1 else Severity.INFO, "Content",
                                "Malformed MIME structure",
                                "The message breaks the MIME standard. Broken structures are sometimes "
                                "used to make gateways and clients see different content.", odd))
    findings = scoring.sort_findings(findings)
    score, level = scoring.score_findings(findings)

    body_emails = urls.extract_emails(parsed.text_body, content.html_to_text(parsed.html_body))
    ioc_set = iocs.collect_iocs(hdr.sender, hdr.reply_to, hdr.return_path, hdr.recipients, hdr.hops,
                                hdr.originating_ip, url_list, parsed.attachments, body_emails)
    queries = hunting.build_queries(parsed, hdr.sender, ioc_set, hdr.network_message_id, lookback)

    return AnalysisResult(
        email=parsed,
        sender=hdr.sender,
        reply_to=hdr.reply_to,
        return_path=hdr.return_path,
        recipients=hdr.recipients,
        auth=hdr.auth,
        gateway=hdr.gateway,
        hops=hdr.hops,
        originating_ip=hdr.originating_ip,
        urls=url_list,
        attachments=parsed.attachments,
        iocs=ioc_set,
        findings=findings,
        score=score,
        level=level,
        hunting=queries,
        network_message_id=hdr.network_message_id,
    )


def analyze_bytes(raw: bytes, path: Path | None = None, lookback: str = "30d") -> AnalysisResult:
    return analyze_parsed(parse_bytes(raw, path), lookback)


def analyze_file(path: str | Path, lookback: str = "30d") -> AnalysisResult:
    return analyze_parsed(parse_file(path), lookback)
