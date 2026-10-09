"""Data model shared by the analyzer, the GUI, the CLI and the reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @property
    def weight(self) -> int:
        """Contribution of a finding of this severity to the risk score."""
        return {0: 0, 1: 5, 2: 12, 3: 25, 4: 40}[int(self)]


@dataclass
class Finding:
    severity: Severity
    category: str  # Sender, Authentication, Routing, URL, Attachment, Content, Gateway
    title: str
    detail: str = ""
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.label,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "evidence": list(self.evidence),
        }


@dataclass
class Address:
    display_name: str
    address: str
    domain: str
    registered_domain: str

    def __str__(self) -> str:
        if self.display_name:
            return f"{self.display_name} <{self.address}>"
        return self.address


@dataclass
class AuthResult:
    mechanism: str  # SPF, DKIM, DMARC, ARC, CompAuth
    result: str  # pass, fail, softfail, neutral, none, temperror, permerror, bestguesspass...
    details: str
    source: str  # header the result came from

    @property
    def passed(self) -> bool:
        return self.result in ("pass", "bestguesspass")

    @property
    def failed(self) -> bool:
        return self.result in ("fail", "softfail", "permerror", "hardfail")


@dataclass
class GatewayVerdict:
    """Verdicts left by mail security gateways (Microsoft EOP/Defender, Proofpoint...)."""

    vendor: str
    field: str
    value: str
    meaning: str = ""
    suspicious: bool = False


@dataclass
class Hop:
    index: int  # 1 = first hop (closest to the sender)
    from_host: str
    from_ip: str
    by_host: str
    protocol: str
    timestamp: datetime | None
    delay_seconds: float | None
    raw: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return d


@dataclass
class UrlInfo:
    url: str
    source: str  # text, html, html-form, html-resource, attachment:<name>, qr:<name>
    display_text: str = ""
    final_url: str = ""
    unwrapped_by: list[str] = field(default_factory=list)
    domain: str = ""
    registered_domain: str = ""
    flags: list[str] = field(default_factory=list)
    flag_levels: list[Severity] = field(default_factory=list)
    severity: Severity = Severity.INFO

    @property
    def target(self) -> str:
        """The URL the user would really end up at (after unwrapping known wrappers)."""
        return self.final_url or self.url

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["flag_levels"] = [s.label for s in self.flag_levels]
        return d


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    payload: bytes = field(repr=False, default=b"")
    content_id: str | None = None
    is_inline: bool = False
    detected_type: str = ""
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    flags: list[str] = field(default_factory=list)
    severity: Severity = Severity.INFO
    is_email: bool = False  # message/rfc822 or .msg that can be opened as a new analysis

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "detected_type": self.detected_type,
            "size": self.size,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "is_inline": self.is_inline,
            "is_email": self.is_email,
            "flags": list(self.flags),
            "severity": self.severity.label,
        }


@dataclass
class ParsedEmail:
    path: Path | None
    source_format: str  # eml, msg
    raw_headers: str
    header_items: list[tuple[str, str]]
    subject: str
    from_: str
    to: str
    cc: str
    date: str
    message_id: str
    text_body: str
    html_body: str
    attachments: list[AttachmentInfo]
    size: int = 0
    sha256: str = ""  # hash of the original file, for chain of custody
    defects: list[str] = field(default_factory=list)

    def header(self, name: str, default: str = "") -> str:
        """First (topmost) header with that name, case-insensitive."""
        lname = name.lower()
        for k, v in self.header_items:
            if k.lower() == lname:
                return v
        return default

    def headers_all(self, name: str) -> list[str]:
        lname = name.lower()
        return [v for k, v in self.header_items if k.lower() == lname]


@dataclass
class IOCSet:
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    hashes: list[dict[str, str]] = field(default_factory=list)  # filename, md5, sha1, sha256

    def is_empty(self) -> bool:
        return not (self.ips or self.domains or self.urls or self.emails or self.hashes)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HuntingQuery:
    title: str
    description: str
    query: str
    tables: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    email: ParsedEmail
    sender: Address | None
    reply_to: list[Address]
    return_path: str
    recipients: list[Address]
    auth: list[AuthResult]
    gateway: list[GatewayVerdict]
    hops: list[Hop]
    originating_ip: str
    urls: list[UrlInfo]
    attachments: list[AttachmentInfo]
    iocs: IOCSet
    findings: list[Finding]
    score: int
    level: Severity
    hunting: list[HuntingQuery]
    network_message_id: str = ""
    analyzed_at: datetime = field(default_factory=datetime.now)

    @property
    def verdict(self) -> str:
        return verdict_label(self.level)

    def auth_summary(self) -> dict[str, str]:
        """Best result per mechanism from the topmost Authentication-Results header."""
        out: dict[str, str] = {}
        for ar in self.auth:
            out.setdefault(ar.mechanism, ar.result)
        return out

    def to_dict(self) -> dict[str, Any]:
        from emailicioso import __version__

        e = self.email
        return {
            "tool": {"name": "E-mailicioso", "version": __version__},
            "analyzed_at": self.analyzed_at.isoformat(timespec="seconds"),
            "file": str(e.path) if e.path else None,
            "format": e.source_format,
            "verdict": {"level": self.level.label, "label": self.verdict, "score": self.score},
            "message": {
                "subject": e.subject,
                "from": e.from_,
                "to": e.to,
                "cc": e.cc,
                "date": e.date,
                "message_id": e.message_id,
                "network_message_id": self.network_message_id,
                "reply_to": [str(a) for a in self.reply_to],
                "return_path": self.return_path,
                "originating_ip": self.originating_ip,
                "size": e.size,
                "sha256": e.sha256,
            },
            "authentication": [asdict(a) for a in self.auth],
            "gateway_verdicts": [asdict(g) for g in self.gateway],
            "hops": [h.to_dict() for h in self.hops],
            "findings": [f.to_dict() for f in self.findings],
            "urls": [u.to_dict() for u in self.urls],
            "attachments": [a.to_dict() for a in self.attachments],
            "iocs": self.iocs.to_dict(),
            "hunting": [asdict(q) for q in self.hunting],
        }


def verdict_label(level: Severity) -> str:
    return {
        Severity.INFO: "No indicators",
        Severity.LOW: "Low risk",
        Severity.MEDIUM: "Suspicious",
        Severity.HIGH: "High risk",
        Severity.CRITICAL: "Malicious",
    }[level]
