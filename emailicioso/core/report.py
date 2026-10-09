"""Exports: standalone HTML report, JSON, and a plain-text summary for incident tickets."""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path

from emailicioso import __version__
from emailicioso.core import domains as dom
from emailicioso.core.models import AnalysisResult, Severity

SEV_COLORS = {
    Severity.CRITICAL: "#d92d20",
    Severity.HIGH: "#e8590c",
    Severity.MEDIUM: "#d4a106",
    Severity.LOW: "#2e7dd7",
    Severity.INFO: "#7a8494",
}

# --------------------------------------------------------------------------- ticket summary

_T = {
    "en": {
        "title": "Email analysis",
        "verdict": "Verdict",
        "score": "score",
        "subject": "Subject",
        "from": "From",
        "reply_to": "Reply-To",
        "return_path": "Return-Path",
        "to": "To",
        "date": "Date",
        "orig_ip": "Originating IP",
        "auth": "Authentication",
        "gateway": "Gateway verdict",
        "findings": "Key findings",
        "iocs": "IOCs (defanged)",
        "ips": "IPs",
        "domains": "Domains",
        "urls": "URLs",
        "emails": "Email addresses",
        "hashes": "Attachment SHA256",
        "actions": "Recommended actions",
        "none": "none",
        "file": "File SHA256",
        "act_block": "Block the sender address/domain and the listed URLs/domains in the mail gateway and proxy.",
        "act_purge": "Find and remove every copy of the message (Threat Explorer / 'This exact message in the tenant' query).",
        "act_clicks": "Check who clicked the links ('Who clicked the links' query) and reset credentials / revoke sessions for those users.",
        "act_files": "Check whether the attachments were opened or executed on any endpoint (hash query) and isolate affected devices.",
        "act_bec": "Do not pay or change bank details: confirm by phone with the supplier using a known number.",
        "act_user": "Tell the reporter the result and thank them for reporting.",
        "act_benign": "No malicious indicators found: close as benign after manual review of the content.",
    },
    "es": {
        "title": "Análisis de correo",
        "verdict": "Veredicto",
        "score": "puntuación",
        "subject": "Asunto",
        "from": "Remitente",
        "reply_to": "Responder a",
        "return_path": "Return-Path",
        "to": "Para",
        "date": "Fecha",
        "orig_ip": "IP de origen",
        "auth": "Autenticación",
        "gateway": "Veredicto del gateway",
        "findings": "Hallazgos principales",
        "iocs": "IOCs (defanged)",
        "ips": "IPs",
        "domains": "Dominios",
        "urls": "URLs",
        "emails": "Direcciones de correo",
        "hashes": "SHA256 de adjuntos",
        "actions": "Acciones recomendadas",
        "none": "ninguno",
        "file": "SHA256 del fichero",
        "act_block": "Bloquear la dirección/dominio remitente y las URLs/dominios listados en el gateway de correo y el proxy.",
        "act_purge": "Localizar y eliminar todas las copias del mensaje (Threat Explorer / consulta 'This exact message in the tenant').",
        "act_clicks": "Comprobar quién hizo clic en los enlaces (consulta 'Who clicked the links') y resetear credenciales / revocar sesiones de esos usuarios.",
        "act_files": "Comprobar si los adjuntos se abrieron o ejecutaron en algún equipo (consulta por hash) y aislar los afectados.",
        "act_bec": "No realizar pagos ni cambios de cuenta bancaria: confirmar por teléfono con el proveedor usando un número conocido.",
        "act_user": "Comunicar el resultado al usuario que lo reportó y agradecer el aviso.",
        "act_benign": "Sin indicadores maliciosos: cerrar como benigno tras revisar manualmente el contenido.",
    },
}

_VERDICT_ES = {
    Severity.INFO: "Sin indicadores",
    Severity.LOW: "Riesgo bajo",
    Severity.MEDIUM: "Sospechoso",
    Severity.HIGH: "Riesgo alto",
    Severity.CRITICAL: "Malicioso",
}


def summary_text(result: AnalysisResult, lang: str = "en") -> str:
    t = _T.get(lang, _T["en"])
    e = result.email
    verdict = _VERDICT_ES[result.level] if lang == "es" else result.verdict
    lines = [
        f"{t['title']} - E-mailicioso {__version__} - {result.analyzed_at:%Y-%m-%d %H:%M}",
        f"{t['verdict']}: {verdict.upper()} ({t['score']} {result.score}/100)",
        "",
        f"{t['subject']}: {e.subject}",
        f"{t['from']}: {e.from_}",
    ]
    if result.reply_to:
        lines.append(f"{t['reply_to']}: {', '.join(str(a) for a in result.reply_to)}")
    if result.return_path:
        lines.append(f"{t['return_path']}: {result.return_path}")
    lines += [f"{t['to']}: {e.to}", f"{t['date']}: {e.date}"]
    if result.originating_ip:
        lines.append(f"{t['orig_ip']}: {dom.defang_ip(result.originating_ip)}")
    auth = result.auth_summary()
    if auth:
        lines.append(f"{t['auth']}: " + ", ".join(f"{k} {v}" for k, v in auth.items()))
    gw = [f"{g.vendor} {g.field}:{g.value}" for g in result.gateway if g.suspicious]
    if gw:
        lines.append(f"{t['gateway']}: " + ", ".join(gw))
    if e.sha256:
        lines.append(f"{t['file']}: {e.sha256}")

    key = [f for f in result.findings if f.severity >= Severity.LOW][:12]
    if key:
        lines += ["", f"{t['findings']}:"]
        lines += [f"  - [{f.severity.label}] {f.title}" for f in key]

    i = result.iocs
    if not i.is_empty():
        lines += ["", f"{t['iocs']}:"]
        for label, values, fn in (
            (t["domains"], i.domains, dom.defang_domain),
            (t["urls"], i.urls, dom.defang_url),
            (t["ips"], i.ips, dom.defang_ip),
            (t["emails"], i.emails, dom.defang_email),
        ):
            if values:
                lines.append(f"  {label}:")
                lines += [f"    {fn(v)}" for v in values[:25]]
        if i.hashes:
            lines.append(f"  {t['hashes']}:")
            lines += [f"    {h['sha256']}  ({h['filename']})" for h in i.hashes]

    lines += ["", f"{t['actions']}:"]
    acts = []
    if result.level >= Severity.MEDIUM:
        acts += [t["act_block"], t["act_purge"]]
        if i.urls:
            acts.append(t["act_clicks"])
        if i.hashes and any(a.severity >= Severity.MEDIUM for a in result.attachments):
            acts.append(t["act_files"])
    if any(f.title.startswith("Asks to change bank") for f in result.findings):
        acts.append(t["act_bec"])
    if result.level <= Severity.LOW:
        acts.append(t["act_benign"])
    acts.append(t["act_user"])
    lines += [f"  {n}. {a}" for n, a in enumerate(acts, 1)]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- JSON


def to_json(result: AnalysisResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False, default=str)


# --------------------------------------------------------------------------- HTML


def _e(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _chip(sev: Severity) -> str:
    return f'<span class="chip" style="--c:{SEV_COLORS[sev]}">{_e(sev.label)}</span>'


def _table(headers: list[str], rows: list[list[str]], cls: str = "") -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<table class="{cls}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


def html_report(result: AnalysisResult, defang: bool = True) -> str:
    e = result.email
    f_url = dom.defang_url if defang else (lambda v: v)
    f_dom = dom.defang_domain if defang else (lambda v: v)
    f_ip = dom.defang_ip if defang else (lambda v: v)
    f_mail = dom.defang_email if defang else (lambda v: v)
    color = SEV_COLORS[result.level]

    meta_rows = [
        ["Subject", _e(e.subject)],
        ["From", _e(e.from_)],
        ["Reply-To", _e(", ".join(str(a) for a in result.reply_to)) or "&mdash;"],
        ["Return-Path", _e(result.return_path) or "&mdash;"],
        ["To", _e(e.to)],
        ["Cc", _e(e.cc) or "&mdash;"],
        ["Date", _e(e.date)],
        ["Message-ID", f"<code>{_e(e.message_id)}</code>" if e.message_id else "&mdash;"],
        ["Network Message ID", f"<code>{_e(result.network_message_id)}</code>" if result.network_message_id else "&mdash;"],
        ["Originating IP", f"<code>{_e(f_ip(result.originating_ip))}</code>" if result.originating_ip else "&mdash;"],
        ["Source file", _e(e.path.name if e.path else "(memory)") + f" &middot; {e.source_format.upper()} &middot; {e.size:,} bytes"],
        ["File SHA256", f"<code>{_e(e.sha256)}</code>"],
    ]
    meta = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in meta_rows)

    findings = _table(
        ["Severity", "Category", "Finding", "Evidence"],
        [[_chip(f.severity), _e(f.category), f"<b>{_e(f.title)}</b><div class='muted'>{_e(f.detail)}</div>",
          "<br>".join(f"<code>{_e(f_url(x) if x.startswith('http') else x)}</code>" for x in f.evidence[:6])]
         for f in result.findings],
        "findings",
    ) if result.findings else "<p class='muted'>No findings.</p>"

    auth_rows = [[_e(a.mechanism), f"<b class='{('ok' if a.passed else 'bad' if a.failed else '')}'>{_e(a.result)}</b>",
                  _e(a.source), f"<code>{_e(a.details)}</code>"] for a in result.auth]
    auth = _table(["Mechanism", "Result", "Header", "Details"], auth_rows) if auth_rows else \
        "<p class='muted'>No Authentication-Results header.</p>"
    gw = _table(["Vendor", "Field", "Value", "Meaning"],
                [[_e(g.vendor), _e(g.field), f"<b class='{'bad' if g.suspicious else ''}'>{_e(g.value)}</b>",
                  _e(g.meaning)] for g in result.gateway]) if result.gateway else ""

    hops = _table(
        ["#", "Timestamp", "Delay", "From", "IP", "By", "With"],
        [[str(h.index), _e(h.timestamp.strftime("%Y-%m-%d %H:%M:%S %z") if h.timestamp else ""),
          _e(fmt_delay(h.delay_seconds)), _e(h.from_host), f"<code>{_e(f_ip(h.from_ip))}</code>" if h.from_ip else "",
          _e(h.by_host), _e(h.protocol)] for h in result.hops],
    ) if result.hops else "<p class='muted'>No Received headers.</p>"

    url_rows = []
    for u in result.urls:
        target = f"<code>{_e(f_url(u.target))}</code>"
        if u.final_url:
            target += f"<div class='muted'>wrapped: <code>{_e(f_url(u.url))}</code></div>"
        url_rows.append([_chip(u.severity), target, _e(u.display_text), _e(u.source),
                         "<br>".join(_e(x) for x in u.flags)])
    urls_html = _table(["Risk", "Destination", "Link text", "Source", "Flags"], url_rows) if url_rows else \
        "<p class='muted'>No URLs.</p>"

    att_rows = [[_chip(a.severity), _e(a.filename), _e(a.detected_type), f"{a.size:,}",
                 f"<code>{_e(a.sha256)}</code>", "<br>".join(_e(x) for x in a.flags)] for a in result.attachments]
    atts = _table(["Risk", "Filename", "Real type", "Bytes", "SHA256", "Flags"], att_rows) if att_rows else \
        "<p class='muted'>No attachments.</p>"

    i = result.iocs
    ioc_blocks = []
    for title, values, fn in (("IPs", i.ips, f_ip), ("Domains", i.domains, f_dom), ("URLs", i.urls, f_url),
                              ("Email addresses", i.emails, f_mail)):
        if values:
            ioc_blocks.append(f"<h3>{title}</h3><pre class='ioc'>{_e(chr(10).join(fn(v) for v in values))}</pre>")
    if i.hashes:
        ioc_blocks.append("<h3>File hashes</h3><pre class='ioc'>" + _e("\n".join(
            f"{h['sha256']}  {h['filename']}" for h in i.hashes)) + "</pre>")
    iocs_html = "".join(ioc_blocks) or "<p class='muted'>No IOCs.</p>"

    hunting = "".join(
        f"<details><summary>{_e(q.title)} <span class='muted'>&middot; {_e(', '.join(q.tables))}</span></summary>"
        f"<p class='muted'>{_e(q.description)}</p><pre class='kql'>{_e(q.query)}</pre></details>"
        for q in result.hunting
    ) or "<p class='muted'>Not enough identifiers to build queries.</p>"

    counts = {s: sum(1 for f in result.findings if f.severity == s) for s in Severity}
    count_html = " ".join(
        f"<span class='chip' style='--c:{SEV_COLORS[s]}'>{n} {s.label}</span>"
        for s, n in sorted(counts.items(), reverse=True) if n and s > Severity.INFO
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>E-mailicioso report - {_e(e.subject)[:80]}</title>
<style>
:root {{ --bg:#f6f7f9; --card:#fff; --fg:#1c2330; --muted:#677284; --line:#e3e6eb; --code:#f0f2f5; }}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg:#0f1218; --card:#171b23; --fg:#e6e9ef; --muted:#8b95a7; --line:#262c38; --code:#1f2530; }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--fg); font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,sans-serif; }}
.wrap {{ max-width:1180px; margin:0 auto; padding:28px 20px 60px; }}
header {{ display:flex; justify-content:space-between; align-items:flex-end; gap:16px; flex-wrap:wrap; margin-bottom:18px; }}
h1 {{ font-size:22px; margin:0; }} h2 {{ font-size:16px; margin:0 0 12px; }} h3 {{ font-size:13px; margin:14px 0 6px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }}
.muted {{ color:var(--muted); font-size:12.5px; }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:18px 20px; margin-bottom:16px; overflow-x:auto; }}
.verdict {{ border-left:6px solid {color}; display:flex; gap:28px; align-items:center; flex-wrap:wrap; }}
.score {{ font-size:44px; font-weight:700; color:{color}; line-height:1; }}
.score small {{ font-size:16px; color:var(--muted); font-weight:500; }}
.label {{ font-size:22px; font-weight:700; color:{color}; }}
.bar {{ height:8px; width:220px; background:var(--line); border-radius:4px; overflow:hidden; margin-top:8px; }}
.bar i {{ display:block; height:100%; width:{result.score}%; background:{color}; }}
table {{ width:100%; border-collapse:collapse; }}
th, td {{ text-align:left; vertical-align:top; padding:7px 10px; border-bottom:1px solid var(--line); }}
thead th {{ font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.03em; }}
.meta th {{ width:180px; color:var(--muted); font-weight:600; }}
code, pre {{ font-family:"Cascadia Code",Consolas,"JetBrains Mono",monospace; font-size:12.5px; word-break:break-all; }}
code {{ background:var(--code); padding:1px 5px; border-radius:4px; }}
pre {{ background:var(--code); padding:12px; border-radius:8px; white-space:pre-wrap; margin:0; }}
.chip {{ display:inline-block; padding:1px 9px; border-radius:999px; font-size:12px; font-weight:600; color:var(--c);
        background:color-mix(in srgb, var(--c) 14%, transparent); border:1px solid color-mix(in srgb, var(--c) 40%, transparent); white-space:nowrap; }}
.ok {{ color:#1f9d55; }} .bad {{ color:#d92d20; }}
details {{ border:1px solid var(--line); border-radius:8px; padding:8px 12px; margin-bottom:8px; }}
summary {{ cursor:pointer; font-weight:600; }}
footer {{ text-align:center; color:var(--muted); font-size:12px; margin-top:30px; }}
@media print {{ body {{ background:#fff; }} .card {{ break-inside:avoid; }} details {{ display:block; }} }}
</style></head><body><div class="wrap">
<header><div><h1>Email forensic report</h1>
<div class="muted">Generated {datetime.now():%Y-%m-%d %H:%M:%S} by E-mailicioso {__version__}{' &middot; indicators defanged' if defang else ''}</div></div>
<div>{count_html}</div></header>

<section class="card verdict">
  <div><div class="score">{result.score}<small>/100</small></div><div class="bar"><i></i></div></div>
  <div><div class="muted">Verdict</div><div class="label">{_e(result.verdict)}</div>
  <div class="muted">{len(result.findings)} findings &middot; {len(result.urls)} URLs &middot; {len(result.attachments)} attachments</div></div>
</section>

<section class="card"><h2>Message</h2><table class="meta">{meta}</table></section>
<section class="card"><h2>Findings</h2>{findings}</section>
<section class="card"><h2>Authentication</h2>{auth}{('<h3>Gateway verdicts</h3>' + gw) if gw else ''}</section>
<section class="card"><h2>Delivery path</h2>{hops}</section>
<section class="card"><h2>URLs</h2>{urls_html}</section>
<section class="card"><h2>Attachments</h2>{atts}</section>
<section class="card"><h2>Indicators of compromise</h2>{iocs_html}</section>
<section class="card"><h2>Hunting queries (Microsoft Defender XDR / Sentinel)</h2>{hunting}</section>
<section class="card"><h2>Raw headers</h2><details><summary>Show {len(e.header_items)} headers</summary><pre>{_e(e.raw_headers)}</pre></details></section>
<footer>E-mailicioso &middot; static analysis only: no link was visited and no attachment was executed to build this report.</footer>
</div></body></html>
"""


def fmt_delay(seconds: float | None) -> str:
    if seconds is None:
        return ""
    sign = "-" if seconds < 0 else ""
    s = abs(int(seconds))
    if s < 60:
        return f"{sign}{s}s"
    if s < 3600:
        return f"{sign}{s // 60}m {s % 60}s"
    return f"{sign}{s // 3600}h {(s % 3600) // 60}m"


def save_html(result: AnalysisResult, path: str | Path, defang: bool = True) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(html_report(result, defang), encoding="utf-8")
    return p

