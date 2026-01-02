from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional


@dataclass
class ReputationResult:
    provider: str
    verdict: str              # malicious | suspicious | clean | unknown | error
    score: Optional[float] = None
    raw: Dict[str, Any] = field(default_factory=dict)
    checked_at: datetime = field(default_factory=datetime.utcnow)
    error: Optional[str] = None


@dataclass
class UrlArtifact:
    original: str
    normalized: str
    domain: str
    reputations: List[ReputationResult] = field(default_factory=list)
    screenshot_path: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)


@dataclass
class EmailArtifact:
    path: str
    subject: str = ""
    from_addr: str = ""
    to_addr: str = ""
    date: str = ""
    message_id: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body_text: str = ""
    body_html: str = ""
    urls: List[UrlArtifact] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)
