"""Turn findings into a 0-100 risk score and a verdict level.

The score is explainable on purpose: it is the sum of the weights of the findings
(Critical 40, High 25, Medium 12, Low 5, Info 0), with Low findings capped so that
many weak signals cannot outweigh one strong one.
"""

from __future__ import annotations

from emailicioso.core.models import Finding, Severity

LOW_CAP = 20
THRESHOLDS = ((80, Severity.CRITICAL), (50, Severity.HIGH), (25, Severity.MEDIUM), (8, Severity.LOW))


def score_findings(findings: list[Finding]) -> tuple[int, Severity]:
    total = 0
    low_total = 0
    for f in findings:
        w = f.severity.weight
        if f.severity == Severity.LOW:
            add = min(w, max(0, LOW_CAP - low_total))
            low_total += add
            total += add
        else:
            total += w
    score = min(100, total)
    if any(f.severity == Severity.CRITICAL for f in findings):
        return max(score, 80), Severity.CRITICAL
    for threshold, level in THRESHOLDS:
        if score >= threshold:
            return score, level
    return score, Severity.INFO


def sort_findings(findings: list[Finding]) -> list[Finding]:
    order = {"Gateway": 0, "Attachment": 1, "URL": 2, "Sender": 3, "Authentication": 4, "Content": 5, "Routing": 6}
    return sorted(findings, key=lambda f: (-int(f.severity), order.get(f.category, 9), f.title))
