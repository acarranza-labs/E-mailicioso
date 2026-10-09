"""Body content heuristics (English and Spanish): social engineering, BEC, callback phishing."""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from emailicioso.core.models import Finding, ParsedEmail, Severity

CREDENTIAL = [
    r"verify (your )?(account|identity|email|mailbox)", r"confirm (your )?(password|credentials|account)",
    r"(account|mailbox) (has been |will be )?(suspended|locked|disabled|deactivated|closed|limited)",
    r"unusual (sign[- ]?in|login) activity", r"password (will )?expire", r"mailbox (is )?(full|over ?quota)",
    r"storage (is )?(full|limit)", r"update (your )?(payment|billing) (details|information)",
    r"re-?activate (your )?account", r"shared (a )?(document|file) with you", r"view (the )?document",
    r"verifique? (su|tu) (cuenta|identidad|correo)", r"confirme? (su|tu) (contrase[ñn]a|cuenta|identidad)",
    r"(su|tu) cuenta (ha sido|ser[aá]) (suspendida|bloqueada|desactivada|cancelada)",
    r"actividad (inusual|sospechosa)", r"(su|tu) contrase[ñn]a (caduca|expira|ha caducado)",
    r"buz[oó]n (lleno|completo)", r"actualice? (sus|tus) datos", r"ha compartido (un )?(documento|archivo)",
    r"inicie sesi[oó]n para", r"acceda a (su|tu) cuenta",
]
URGENCY = [
    r"\burgent(e|ly)?\b", r"\bimmediate(ly)?\b", r"within (24|48|72) hours", r"final (notice|warning|reminder)",
    r"action required", r"as soon as possible", r"failure to .{0,40}(will|may) result",
    r"\binmediata(mente)?\b", r"en (las pr[oó]ximas )?(24|48|72) horas", r"[uú]ltimo aviso",
    r"acci[oó]n requerida", r"lo antes posible", r"de lo contrario", r"plazo de",
]
FINANCIAL = [
    r"wire transfer", r"bank (details|account|information)", r"\biban\b", r"\bswift\b", r"remittance",
    r"(outstanding|overdue|unpaid) invoice", r"gift ?cards?", r"bitcoin|btc wallet|crypto",
    r"transferencia (bancaria)?", r"datos bancarios", r"cuenta bancaria", r"factura (pendiente|vencida|impagada)",
    r"tarjetas? regalo", r"\bpago\b",
]
BANK_CHANGE = [
    r"(new|updated|changed?|change of|different) (bank|banking) (details|account|information)",
    r"(our|the) bank (details|account) (has|have) changed",
    r"update (our|the) (bank|payment) (details|information)",
    r"(nueva|nuevo|cambio de|cambiado|actualizad[oa]s?) (de )?(cuenta bancaria|datos bancarios|n[uú]mero de cuenta|iban)",
    r"(hemos|ha) cambiado (de )?(banco|cuenta)",
    r"realice (los|el) pagos? (a|en) (la )?(nueva|siguiente) cuenta",
]
CALLBACK = [r"subscription", r"renew(al|ed)", r"auto[- ]?renew", r"cancel", r"refund", r"order (id|number)",
            r"suscripci[oó]n", r"renovaci[oó]n", r"cancelar", r"reembolso", r"pedido"]
PHONE_RE = re.compile(r"(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{3,4}")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")
BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|font-size\s*:\s*0(px|pt|em)?\s*[;\"']|visibility\s*:\s*hidden|max-height\s*:\s*0|opacity\s*:\s*0[;\"']",
    re.I,
)


def html_to_text(html: str) -> str:
    if not html:
        return ""
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "head"]):
        tag.decompose()
    return re.sub(r"[ \t\r\f\v]+", " ", soup.get_text("\n")).strip()


def _matches(patterns: list[str], text: str) -> list[str]:
    hits = []
    for p in patterns:
        m = re.search(p, text, re.I)
        if m:
            hits.append(m.group(0))
    return hits


def _valid_iban(candidate: str) -> bool:
    s = candidate.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    digits = "".join(str(int(c, 36)) for c in rearranged)
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False


def find_ibans(text: str) -> list[str]:
    out = []
    for m in IBAN_RE.finditer(text or ""):
        val = m.group(0)
        if _valid_iban(val) and val.replace(" ", "") not in [o.replace(" ", "") for o in out]:
            out.append(val)
    return out


def analyze_content(parsed: ParsedEmail) -> list[Finding]:
    text = "\n".join(filter(None, [parsed.subject, parsed.text_body, html_to_text(parsed.html_body)]))
    findings: list[Finding] = []

    cred = _matches(CREDENTIAL, text)
    urgent = _matches(URGENCY, text)
    money = _matches(FINANCIAL, text)
    bank_change = _matches(BANK_CHANGE, text)

    if cred and urgent:
        findings.append(Finding(Severity.MEDIUM, "Content", "Credential lure with urgency",
                                "The text asks to verify/log in and pressures the reader to act fast.",
                                (cred + urgent)[:6]))
    elif cred:
        findings.append(Finding(Severity.LOW, "Content", "Credential or account-verification lure", "", cred[:6]))
    elif urgent and money:
        findings.append(Finding(Severity.LOW, "Content", "Urgent payment request", "", (urgent + money)[:6]))
    elif urgent:
        findings.append(Finding(Severity.INFO, "Content", "Urgency language", "", urgent[:6]))

    if bank_change:
        findings.append(Finding(Severity.HIGH, "Content", "Asks to change bank/payment details",
                                "Requests to pay into a new bank account are the core of BEC / invoice "
                                "fraud. Verify by phone using a known number, never with the details in "
                                "the email.", bank_change[:4]))

    ibans = find_ibans(text)
    if ibans:
        findings.append(Finding(Severity.INFO if not bank_change else Severity.MEDIUM, "Content",
                                f"Contains {len(ibans)} bank account number(s) (IBAN)",
                                "Record them as IOCs if this is a payment fraud attempt.", ibans[:5]))
    wallets = BTC_RE.findall(text)
    if wallets:
        findings.append(Finding(Severity.MEDIUM, "Content", "Contains cryptocurrency wallet address",
                                "Typical of extortion/sextortion scams and fake invoices.", wallets[:3]))

    phones = [p for p in PHONE_RE.findall(text) if sum(c.isdigit() for c in p) >= 9]
    callback = _matches(CALLBACK, text)
    if phones and len(callback) >= 2 and len(re.findall(r"https?://", parsed.text_body + parsed.html_body)) <= 3:
        findings.append(Finding(Severity.MEDIUM, "Content", "Callback phishing pattern (TOAD)",
                                "Fake subscription/renewal notice that asks the victim to call a phone "
                                "number instead of clicking a link.", phones[:3] + callback[:3]))

    if parsed.html_body and HIDDEN_STYLE_RE.search(parsed.html_body):
        hidden_text = _hidden_text(parsed.html_body)
        if len(hidden_text) > 40:
            findings.append(Finding(Severity.LOW, "Content", "Hidden text in HTML body",
                                    "Invisible text is used to poison spam filters and AI classifiers.",
                                    [hidden_text[:200]]))

    visible = html_to_text(parsed.html_body) if parsed.html_body else parsed.text_body
    images = [a for a in parsed.attachments if a.content_type.startswith("image/")]
    if parsed.html_body and len(visible.strip()) < 40 and images:
        findings.append(Finding(Severity.LOW, "Content", "Body is almost only an image",
                                "Image-only emails evade text analysis; check the image for QR codes "
                                "or text instructions."))
    return findings


def _hidden_text(html: str) -> str:
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")
    chunks = []
    for tag in soup.find_all(style=HIDDEN_STYLE_RE):
        chunks.append(tag.get_text(" ", strip=True))
    return " ".join(c for c in chunks if c)
