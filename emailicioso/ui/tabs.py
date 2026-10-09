"""The analysis tabs. Each tab exposes ``load(result)`` and talks back to the window via ``ctx``."""

from __future__ import annotations

import html
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QPoint, Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from emailicioso.core import domains as dom
from emailicioso.core import hunting
from emailicioso.core import iocs as ioc_mod
from emailicioso.core.models import AnalysisResult, AttachmentInfo, Finding, Severity, UrlInfo
from emailicioso.core.parser import html_with_inline_images
from emailicioso.core.report import fmt_delay, summary_text
from emailicioso.core.reputation.pivots import pivot_links
from emailicioso.ui import theme
from emailicioso.ui.widgets import (
    PAYLOAD_ROLE,
    Banner,
    Card,
    Chip,
    DataTable,
    ElidedLabel,
    button,
    copy_text,
    hbox,
    label,
    severity_cell,
    toggle,
)

if TYPE_CHECKING:
    from emailicioso.ui.main_window import MainWindow


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _page() -> tuple[QWidget, QVBoxLayout]:
    w = QWidget()
    w.setObjectName("Page")
    lay = QVBoxLayout(w)
    lay.setContentsMargins(18, 14, 18, 16)
    lay.setSpacing(12)
    return w, lay


def _mono_view(read_only: bool = True) -> QPlainTextEdit:
    v = QPlainTextEdit()
    v.setReadOnly(read_only)
    v.setFont(theme.mono_font(10))
    v.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
    return v


def add_pivot_menu(menu: QMenu, indicator: str, kind: str) -> None:
    links = pivot_links(indicator, kind)
    if not links:
        return
    sub = menu.addMenu("Look up in…")
    for name, url in links:
        sub.addAction(name, lambda u=url: QDesktopServices.openUrl(QUrl(u)))


# =========================================================================== Overview


class OverviewTab(QWidget):
    def __init__(self, ctx: MainWindow) -> None:
        super().__init__()
        self.ctx = ctx
        self.result: AnalysisResult | None = None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 14, 18, 16)
        outer.setSpacing(12)
        self.attached_banner = Banner("This message carries an <b>attached email</b>, usually the original phish "
                                      "a user reported. Analyze it to see the real sender, links and IOCs.")
        self.attached_banner.add_action(button("Analyze attached email", self._open_attached, primary=True))
        self.attached_banner.setVisible(False)
        outer.addWidget(self.attached_banner)
        root = QHBoxLayout()
        root.setSpacing(14)
        outer.addLayout(root, 1)

        left = QVBoxLayout()
        left.setSpacing(12)
        card = Card("Findings")
        self.table = DataTable(["Severity", "Category", "Finding"], "Filter findings…")
        self.table.set_column_widths({0: 104, 1: 120})
        self.table.selection_changed.connect(self._show_detail)
        card.body.addWidget(self.table, 1)
        left.addWidget(card, 3)

        self.detail_card = Card("Details")
        self.detail = QLabel()
        self.detail.setWordWrap(True)
        self.detail.setTextFormat(Qt.TextFormat.RichText)
        self.detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.detail.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.detail.setMinimumHeight(90)
        self.detail_card.body.addWidget(self.detail)
        left.addWidget(self.detail_card, 1)
        root.addLayout(left, 3)

        right_host = QWidget()
        right_host.setObjectName("Page")
        right = QVBoxLayout(right_host)
        right.setContentsMargins(0, 0, 4, 0)
        right.setSpacing(12)
        glance = Card("At a glance")
        self.grid = QGridLayout()
        self.grid.setHorizontalSpacing(14)
        self.grid.setVerticalSpacing(7)
        self.grid.setColumnStretch(1, 1)
        glance.body.addLayout(self.grid)
        right.addWidget(glance)

        auth = Card("Authentication")
        self.auth_row = QHBoxLayout()
        self.auth_row.setSpacing(6)
        auth.body.addLayout(self.auth_row)
        self.gw_label = label("", "Muted", wrap=True)
        auth.body.addWidget(self.gw_label)
        right.addWidget(auth)

        ticket = Card("Incident ticket")
        ticket.body.addWidget(label("Plain-text summary with verdict, findings, defanged IOCs and next steps, "
                                    "ready to paste into the ticket.", "Muted", wrap=True))
        ticket.body.addLayout(hbox(
            button("Copy summary (EN)", lambda: self._copy_summary("en"), primary=True),
            button("Copiar resumen (ES)", lambda: self._copy_summary("es")),
            None,
        ))
        ticket.body.addLayout(hbox(
            button("Export HTML report…", ctx.export_html),
            button("Export JSON…", ctx.export_json),
            None,
        ))
        right.addWidget(ticket)
        right.addStretch(1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(right_host)
        root.addWidget(scroll, 2)

    def _copy_summary(self, lang: str) -> None:
        if self.result:
            copy_text(summary_text(self.result, lang))
            self.ctx.notify("Ticket summary copied to the clipboard")

    def _open_attached(self) -> None:
        if self.result:
            emails = [a for a in self.result.attachments if a.is_email]
            if emails:
                self.ctx.open_attached_email(emails[0])

    def load(self, r: AnalysisResult) -> None:
        self.result = r
        self.attached_banner.setVisible(any(a.is_email for a in r.attachments))
        rows = []
        for f in r.findings:
            rows.append(([severity_cell(f.severity), f.category,
                          {"text": f.title, "tooltip": f.detail or f.title, "bold": f.severity >= Severity.HIGH}], f))
        self.table.set_rows(rows)
        self.table.view.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        if rows:
            self.table.view.selectRow(0)
        else:
            muted = theme.current()["muted"]
            self.detail.setText(f"<span style='color:{muted}'>No findings: nothing suspicious was detected by the "
                                "static checks. Review the content anyway.</span>")

        while self.grid.count():
            item = self.grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        e = r.email
        risky_urls = sum(1 for u in r.urls if u.severity >= Severity.MEDIUM)
        risky_atts = sum(1 for a in r.attachments if a.severity >= Severity.MEDIUM)
        facts = [
            ("From", str(r.sender) if r.sender else e.from_ or "—"),
            ("Reply-To", ", ".join(str(a) for a in r.reply_to) or "—"),
            ("Return-Path", r.return_path or "—"),
            ("To", e.to or "—"),
            ("Date", e.date or "—"),
            ("Originating IP", r.originating_ip or "—"),
            ("Message-ID", e.message_id or "—"),
            ("Network Msg ID", r.network_message_id or "—"),
            ("Content", f"{_plural(len(r.urls), 'URL')} ({risky_urls} risky) · "
                        f"{_plural(len(r.attachments), 'attachment')} ({risky_atts} risky) · "
                        f"{_plural(len(r.hops), 'hop')}"),
            ("File", f"{e.path.name if e.path else '(memory)'} · {e.source_format.upper()} · {e.size:,} bytes"),
            ("SHA256", e.sha256 or "—"),
        ]
        for row, (k, v) in enumerate(facts):
            kl = label(k, "Muted")
            vl = ElidedLabel(v)
            if k in ("SHA256", "Message-ID", "Network Msg ID", "Originating IP"):
                vl.setFont(theme.mono_font(9))
            if k == "Reply-To" and r.reply_to and r.sender and any(
                    a.registered_domain != r.sender.registered_domain for a in r.reply_to):
                vl.setStyleSheet(f"color:{theme.SEVERITY_COLORS[Severity.HIGH]}; font-weight:600;")
            self.grid.addWidget(kl, row, 0, Qt.AlignmentFlag.AlignTop)
            self.grid.addWidget(vl, row, 1)

        while self.auth_row.count():
            item = self.auth_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        summary = r.auth_summary()
        if summary:
            for mech, res in summary.items():
                self.auth_row.addWidget(Chip(f"{mech}  {res}", theme.AUTH_COLORS.get(res, "#8b95a7")))
        else:
            self.auth_row.addWidget(label("No Authentication-Results header", "Muted"))
        self.auth_row.addStretch(1)
        flagged = [f"{g.vendor} {g.field}={g.value}" + (f" ({g.meaning})" if g.meaning and g.field in
                                                         ("SFV", "CAT") else "")
                   for g in r.gateway if g.suspicious]
        self.gw_label.setText("Gateway: " + "; ".join(flagged) if flagged else
                              ("Gateway headers present, no negative verdict." if r.gateway else
                               "No security gateway verdict headers."))

    def _show_detail(self, f: Finding | None) -> None:
        if f is None:
            return
        t = theme.current()
        color = theme.SEVERITY_COLORS[f.severity]
        ev = "".join(f"<div style='font-family:Consolas,monospace; color:{t['muted']}'>• {html.escape(x)}</div>"
                     for x in f.evidence[:12])
        self.detail.setText(
            f"<div style='font-size:11pt; font-weight:700'>{html.escape(f.title)}</div>"
            f"<div style='color:{color}; font-weight:600; margin:2px 0 6px'>{f.severity.label} · {f.category}</div>"
            f"<div>{html.escape(f.detail)}</div><div style='margin-top:6px'>{ev}</div>"
        )


# =========================================================================== Headers


class HeadersTab(QWidget):
    def __init__(self, ctx: MainWindow) -> None:
        super().__init__()
        self.ctx = ctx
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 16)
        split = QSplitter(Qt.Orientation.Vertical)
        split.setChildrenCollapsible(False)

        hops = Card("Delivery path (oldest hop first)")
        self.hops = DataTable(["#", "Timestamp", "Delay", "From", "IP", "By", "With"], show_filter=False)
        self.hops.set_column_widths({0: 40, 1: 200, 2: 80, 3: 260, 4: 150, 5: 260})
        self.hops.activated.connect(lambda h: h and self._show_raw_hop(h))
        self.hops.context_menu.connect(self._hop_menu)
        hops.body.addWidget(self.hops)
        split.addWidget(hops)

        hdr = Card("Headers")
        self.sub = QTabWidget()
        self.sub.setObjectName("SubTabs")
        self.list = DataTable(["Name", "Value"], "Filter headers (name or value)…")
        self.list.set_column_widths({0: 260})
        self.list.context_menu.connect(self._header_menu)
        self.raw = _mono_view()
        self.sub.addTab(self.list, "Parsed")
        self.sub.addTab(self.raw, "Raw")
        hdr.body.addWidget(self.sub)
        split.addWidget(hdr)
        split.setSizes([260, 460])
        lay.addWidget(split)

    def load(self, r: AnalysisResult) -> None:
        rows = []
        for h in r.hops:
            ts = h.timestamp.strftime("%Y-%m-%d %H:%M:%S %z") if h.timestamp else ""
            delay = fmt_delay(h.delay_seconds)
            delay_cell: Any = delay
            if h.delay_seconds is not None and (h.delay_seconds < -300 or h.delay_seconds > 3600):
                delay_cell = {"text": delay, "fg": theme.SEVERITY_COLORS[Severity.MEDIUM], "bold": True,
                              "sort": h.delay_seconds}
            elif h.delay_seconds is not None:
                delay_cell = {"text": delay, "sort": h.delay_seconds}
            ip_cell = {"text": h.from_ip, "mono": True}
            if h.from_ip and h.from_ip == r.originating_ip:
                ip_cell.update({"fg": theme.current()["accent"], "bold": True, "tooltip": "Originating IP"})
            rows.append(([{"text": str(h.index), "sort": h.index}, ts, delay_cell,
                          {"text": h.from_host, "tooltip": h.raw}, ip_cell, h.by_host, h.protocol], h))
        self.hops.set_rows(rows)
        self.hops.view.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.list.set_rows([([{"text": k, "bold": True}, {"text": v, "tooltip": v[:2000]}], (k, v))
                            for k, v in r.email.header_items])
        self.raw.setPlainText(r.email.raw_headers)

    def _show_raw_hop(self, hop: Any) -> None:
        QMessageBox.information(self, f"Received header (hop {hop.index})", hop.raw)

    def _hop_menu(self, hops: list, pos: QPoint) -> None:
        menu = QMenu(self)
        hop = hops[0]
        menu.addAction("Copy raw Received header", lambda: copy_text(hop.raw))
        if hop.from_ip:
            menu.addAction("Copy IP", lambda: copy_text(hop.from_ip))
            add_pivot_menu(menu, hop.from_ip, "ip")
        menu.exec(pos)

    def _header_menu(self, items: list, pos: QPoint) -> None:
        menu = QMenu(self)
        menu.addAction("Copy value", lambda: copy_text("\n".join(v for _k, v in items)))
        menu.addAction("Copy as 'Name: value'", lambda: copy_text("\n".join(f"{k}: {v}" for k, v in items)))
        menu.exec(pos)


# =========================================================================== Authentication


class AuthTab(QWidget):
    def __init__(self, ctx: MainWindow) -> None:
        super().__init__()
        self.ctx = ctx
        w, lay = _page()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(w)
        self.banner = Banner("")
        lay.addWidget(self.banner)
        c1 = Card("Authentication results")
        self.auth = DataTable(["Mechanism", "Result", "Header", "Details"], show_filter=False)
        self.auth.set_column_widths({0: 110, 1: 120, 2: 210})
        c1.body.addWidget(self.auth)
        lay.addWidget(c1, 1)
        c2 = Card("Security gateway verdicts")
        self.gw = DataTable(["Vendor", "Field", "Value", "Meaning"], show_filter=False)
        self.gw.set_column_widths({0: 120, 1: 120, 2: 260})
        c2.body.addWidget(self.gw)
        lay.addWidget(c2, 1)

    def load(self, r: AnalysisResult) -> None:
        self.auth.set_rows([([{"text": a.mechanism, "bold": True},
                              {"text": a.result, "color": theme.AUTH_COLORS.get(a.result, "#8b95a7")},
                              a.source, {"text": a.details, "mono": True}], a) for a in r.auth])
        self.gw.set_rows([([g.vendor, {"text": g.field, "bold": True},
                            {"text": g.value, "color": theme.SEVERITY_COLORS[Severity.HIGH] if g.suspicious
                             else None, "mono": not g.suspicious}, g.meaning], g) for g in r.gateway])
        s = r.auth_summary()
        if not r.auth:
            self.banner.set_text("This message has no <b>Authentication-Results</b> header. That is normal for "
                                 "messages exported from the sender side or saved before delivery. Ask for the "
                                 "original as received (from the recipient's mailbox).")
        elif s.get("DMARC") in ("fail",) or s.get("CompAuth") == "fail":
            self.banner.set_text("<b>Authentication failed</b> for the From domain: the sender is very likely "
                                 "spoofed. Results come from the topmost header, added by your own mail server.")
        else:
            self.banner.set_text("Results are read from the topmost <b>Authentication-Results</b> header, added by "
                                 "the receiving server. A pass only proves the domain sent it, not that the domain "
                                 "is legitimate: check the Sender findings for lookalikes.")


# =========================================================================== Body


class SafeBrowser(QTextBrowser):
    """Renders HTML without fetching anything remote and without following links."""

    def __init__(self) -> None:
        super().__init__()
        self.setOpenLinks(False)
        self.setOpenExternalLinks(False)
        self.blocked = 0

    def loadResource(self, rtype: int, url: QUrl) -> Any:  # noqa: N802 (Qt API)
        if url.scheme().lower() in ("http", "https", "ftp", "file", ""):
            if url.scheme().lower() != "":
                self.blocked += 1
            return None
        return super().loadResource(rtype, url)


class BodyTab(QWidget):
    def __init__(self, ctx: MainWindow) -> None:
        super().__init__()
        self.ctx = ctx
        w, lay = _page()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(w)
        self.banner = Banner("Remote content is blocked and links are disabled. <b>Hover a link</b> to see where it "
                             "really goes (shown in the status bar).", "ok")
        lay.addWidget(self.banner)
        self.sub = QTabWidget()
        self.sub.setObjectName("SubTabs")
        self.rendered = SafeBrowser()
        self.rendered.setObjectName("Rendered")
        self.rendered.setFocusPolicy(Qt.FocusPolicy.ClickFocus)
        self.rendered.highlighted.connect(self._hover)
        self.rendered.anchorClicked.connect(self._clicked)
        self.text = _mono_view()
        self.source = _mono_view()
        self.sub.addTab(self.rendered, "Rendered")
        self.sub.addTab(self.text, "Plain text")
        self.sub.addTab(self.source, "HTML source")
        lay.addWidget(self.sub, 1)

    def _hover(self, url: QUrl) -> None:
        if url.isEmpty():
            self.ctx.notify("")
            return
        target = url.toString()
        from emailicioso.core.urls import unwrap

        final, chain = unwrap(target)
        msg = f"Link → {dom.defang_url(final)}"
        if chain:
            msg += f"   (unwrapped from {', '.join(chain)})"
        self.ctx.notify(msg, 0)

    def _clicked(self, url: QUrl) -> None:
        copy_text(url.toString())
        self.ctx.notify("Links are not opened from here. URL copied to the clipboard.")

    def load(self, r: AnalysisResult) -> None:
        e = r.email
        self.rendered.blocked = 0
        hidden = 0
        if e.html_body:
            doc_html, hidden = _strip_hidden(html_with_inline_images(e))
            self.rendered.setHtml(doc_html)
            self.sub.setTabEnabled(0, True)
            self.sub.setCurrentIndex(0)
        else:
            self.rendered.setHtml("<p style='color:#888'>(no HTML part)</p>")
            self.sub.setCurrentIndex(1)
        self.text.setPlainText(e.text_body or "(no plain-text part)")
        self.source.setPlainText(e.html_body or "(no HTML part)")
        blocked = self.rendered.blocked
        extra = []
        if blocked:
            extra.append(f"{blocked} remote resource(s) blocked")
        if hidden:
            extra.append(f"{hidden} hidden element(s) not shown, see HTML source")
        self.banner.set_text(
            "Remote content is blocked and links are disabled. <b>Hover a link</b> to see where it really goes "
            "(status bar)." + (" " + "; ".join(extra)[:1].upper() + "; ".join(extra)[1:] + "." if extra else ""))


def _strip_hidden(markup: str) -> tuple[str, int]:
    """Remove elements the recipient can't see (QTextBrowser ignores display:none)."""
    from bs4 import BeautifulSoup

    from emailicioso.core.content import HIDDEN_STYLE_RE

    try:
        soup = BeautifulSoup(markup, "lxml")
    except Exception:
        soup = BeautifulSoup(markup, "html.parser")
    hidden = [t for t in soup.find_all(style=HIDDEN_STYLE_RE) if t.name not in ("html", "body")]
    for t in hidden:
        t.decompose()
    for t in soup.find_all("script"):
        t.decompose()
    return str(soup), len(hidden)


# =========================================================================== URLs


class UrlsTab(QWidget):
    def __init__(self, ctx: MainWindow) -> None:
        super().__init__()
        self.ctx = ctx
        self.result: AnalysisResult | None = None
        w, lay = _page()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(w)
        self.table = DataTable(["Risk", "Destination", "Domain", "Link text", "Source", "Flags"],
                               "Filter URLs, domains, flags…")
        self.table.set_column_widths({0: 96, 1: 420, 2: 220, 3: 200, 4: 120})
        self.defang = toggle("Defang", ctx.settings.defang, lambda _: self.reload())
        self.only_risky = toggle("Only risky", False, lambda _: self.table.refilter())
        self.hide_res = toggle("Hide images/resources", True, lambda _: self.table.refilter())
        self.table.proxy.extra_filter = self._accept
        self.table.add_tool(self.defang)
        self.table.add_tool(self.only_risky)
        self.table.add_tool(self.hide_res)
        self.table.context_menu.connect(self._menu)
        self.table.activated.connect(lambda u: u and self._details(u))
        lay.addWidget(self.table, 1)
        lay.addLayout(hbox(
            button("Copy selected", self._copy_selected),
            button("Copy all (defanged)", lambda: self._copy_all(True)),
            button("Screenshot selected…", self._capture_selected),
            None,
            label("Double-click a row for details. Right-click to pivot to VirusTotal, urlscan…", "Muted"),
        ))

    def _accept(self, u: UrlInfo | None) -> bool:
        if u is None:
            return True
        if self.only_risky.isChecked() and u.severity < Severity.MEDIUM:
            return False
        if self.hide_res.isChecked() and u.source.endswith("-resource") and u.severity < Severity.MEDIUM:
            return False
        return True

    def _fmt(self, url: str) -> str:
        return dom.defang_url(url) if self.defang.isChecked() else url

    def load(self, r: AnalysisResult) -> None:
        self.result = r
        self.reload()

    def reload(self) -> None:
        if not self.result:
            return
        rows = []
        for u in self.result.urls:
            dest_tip = u.target + (f"\n\nWrapped URL:\n{u.url}\n\nUnwrapped by: {', '.join(u.unwrapped_by)}"
                                   if u.final_url else "")
            flags = [f for f in u.flags if not f.startswith("Unwrapped:")]
            rows.append(([severity_cell(u.severity),
                          {"text": self._fmt(u.target), "tooltip": dest_tip, "mono": True},
                          u.domain, u.display_text, u.source,
                          {"text": " · ".join(flags), "tooltip": "\n".join(u.flags)}], u))
        self.table.set_rows(rows)
        self.table.view.sortByColumn(0, Qt.SortOrder.DescendingOrder)

    def _copy_selected(self) -> None:
        sel = self.table.selected()
        if sel:
            copy_text("\n".join(self._fmt(u.target) for u in sel))
            self.ctx.notify(f"Copied {len(sel)} URL(s)")

    def _copy_all(self, defanged: bool) -> None:
        urls = self.table.all_payloads()
        copy_text("\n".join(dom.defang_url(u.target) if defanged else u.target for u in urls))
        self.ctx.notify(f"Copied {len(urls)} URL(s)")

    def _capture_selected(self) -> None:
        sel = self.table.selected()
        if not sel:
            self.ctx.notify("Select one or more URLs first")
            return
        self.ctx.capture_urls([u.target for u in sel])

    def _details(self, u: UrlInfo) -> None:
        lines = [f"Destination: {u.target}"]
        if u.final_url:
            lines += [f"Original (wrapped): {u.url}", f"Unwrapped by: {', '.join(u.unwrapped_by)}"]
        if u.display_text:
            lines.append(f"Link text: {u.display_text}")
        lines += [f"Source: {u.source}", f"Registered domain: {u.registered_domain}", "", "Flags:"]
        lines += [f"  [{lvl.label}] {f}" for f, lvl in zip(u.flags, u.flag_levels, strict=False)] or ["  none"]
        box = QMessageBox(self)
        box.setWindowTitle("URL details")
        box.setText("\n".join(lines))
        box.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        box.exec()

    def _menu(self, urls: list[UrlInfo], pos: QPoint) -> None:
        menu = QMenu(self)
        menu.addAction("Copy URL", lambda: copy_text("\n".join(u.target for u in urls)))
        menu.addAction("Copy defanged", lambda: copy_text("\n".join(dom.defang_url(u.target) for u in urls)))
        menu.addAction("Copy domain", lambda: copy_text("\n".join(dict.fromkeys(u.domain for u in urls))))
        if any(u.final_url for u in urls):
            menu.addAction("Copy original (wrapped) URL", lambda: copy_text("\n".join(u.url for u in urls)))
        menu.addSeparator()
        u = urls[0]
        add_pivot_menu(menu, u.target, "url")
        if u.domain:
            kind = "ip" if dom.is_ip(u.domain) else "domain"
            sub = menu.addMenu(f"Look up {kind} {u.domain}…")
            for name, link in pivot_links(u.domain, kind):
                sub.addAction(name, lambda x=link: QDesktopServices.openUrl(QUrl(x)))
        menu.addSeparator()
        menu.addAction("Take screenshot (visits the URL)…", lambda: self.ctx.capture_urls([x.target for x in urls]))
        menu.exec(pos)


# =========================================================================== Attachments


class AttachmentsTab(QWidget):
    def __init__(self, ctx: MainWindow) -> None:
        super().__init__()
        self.ctx = ctx
        w, lay = _page()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(w)
        lay.addWidget(Banner("Attachments are <b>never opened or executed</b>: the analysis is static (magic bytes, "
                             "structure, hashes). Saved files keep their original content, handle them in a sandbox."))
        self.table = DataTable(["Risk", "Filename", "Real type", "Declared type", "Size", "SHA256", "Flags"],
                               "Filter attachments…")
        self.table.set_column_widths({0: 96, 1: 260, 2: 190, 3: 170, 4: 80, 5: 200})
        self.table.context_menu.connect(self._menu)
        self.table.activated.connect(self._activated)
        lay.addWidget(self.table, 1)
        self.open_btn = button("Analyze attached email", self._open_email, primary=True)
        lay.addLayout(hbox(
            button("Save selected…", self._save_selected),
            button("Copy SHA256", lambda: self._copy("sha256")),
            self.open_btn,
            None,
            label("Double-click an attached email to analyze it.", "Muted"),
        ))

    def load(self, r: AnalysisResult) -> None:
        rows = []
        for a in r.attachments:
            name = a.filename + ("  (inline)" if a.is_inline else "")
            rows.append(([severity_cell(a.severity), {"text": name, "bold": a.severity >= Severity.MEDIUM},
                          a.detected_type, a.content_type, {"text": _size(a.size), "sort": a.size},
                          {"text": a.sha256, "mono": True}, {"text": " · ".join(a.flags),
                                                              "tooltip": "\n".join(a.flags)}], a))
        self.table.set_rows(rows)
        self.table.view.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        self.open_btn.setVisible(any(a.is_email for a in r.attachments))

    def _activated(self, a: AttachmentInfo | None) -> None:
        if a is not None and a.is_email:
            self.ctx.open_attached_email(a)

    def _open_email(self) -> None:
        sel = [a for a in self.table.selected() if a.is_email] or [
            a for a in self.table.all_payloads(False) if a.is_email]
        if sel:
            self.ctx.open_attached_email(sel[0])

    def _copy(self, field: str) -> None:
        sel = self.table.selected() or self.table.all_payloads()
        copy_text("\n".join(getattr(a, field) for a in sel if getattr(a, field)))
        self.ctx.notify(f"Copied {len(sel)} hash(es)")

    def _save_selected(self) -> None:
        sel = self.table.selected()
        if not sel:
            self.ctx.notify("Select one or more attachments first")
            return
        if len(sel) == 1:
            a = sel[0]
            path, _ = QFileDialog.getSaveFileName(self, "Save attachment", _safe_name(a.filename))
            if path:
                Path(path).write_bytes(a.payload)
                self.ctx.notify(f"Saved {Path(path).name}")
            return
        folder = QFileDialog.getExistingDirectory(self, "Save attachments to folder")
        if folder:
            for a in sel:
                (Path(folder) / _safe_name(a.filename)).write_bytes(a.payload)
            self.ctx.notify(f"Saved {len(sel)} attachments to {folder}")

    def _menu(self, atts: list[AttachmentInfo], pos: QPoint) -> None:
        menu = QMenu(self)
        a = atts[0]
        if a.is_email:
            menu.addAction("Analyze attached email", lambda: self.ctx.open_attached_email(a))
            menu.addSeparator()
        menu.addAction("Copy SHA256", lambda: copy_text("\n".join(x.sha256 for x in atts)))
        menu.addAction("Copy MD5", lambda: copy_text("\n".join(x.md5 for x in atts)))
        menu.addAction("Copy SHA1", lambda: copy_text("\n".join(x.sha1 for x in atts)))
        menu.addAction("Copy filename", lambda: copy_text("\n".join(x.filename for x in atts)))
        menu.addSeparator()
        if a.sha256:
            add_pivot_menu(menu, a.sha256, "hash")
        menu.addAction("Save…", self._save_selected)
        menu.exec(pos)


def _size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return str(n)


def _safe_name(name: str) -> str:
    cleaned = "".join(c for c in name.replace("‮", "") if c.isalnum() or c in "._- ()[]")
    return cleaned.strip(". ") or "attachment.bin"


# =========================================================================== IOCs


class IocsTab(QWidget):
    GROUPS = (("ips", "IP addresses", "ip"), ("domains", "Domains", "domain"), ("urls", "URLs", "url"),
              ("emails", "Email addresses", "email"))

    def __init__(self, ctx: MainWindow) -> None:
        super().__init__()
        self.ctx = ctx
        self.result: AnalysisResult | None = None
        w, lay = _page()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(w)
        self.defang = toggle("Defang", ctx.settings.defang, lambda _: self.reload())
        lay.addLayout(hbox(
            self.defang,
            None,
            button("Copy all", self._copy_all, primary=True),
            button("Export CSV…", lambda: self._export("csv")),
            button("Export JSON…", lambda: self._export("json")),
            button("Export TXT…", lambda: self._export("txt")),
        ))
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Indicator", "Context"])
        self.tree.setColumnWidth(0, 860)
        self.tree.setAlternatingRowColors(True)
        self.tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        self.tree.setFont(theme.mono_font(10))
        lay.addWidget(self.tree, 1)
        lay.addWidget(label("Well-known legitimate infrastructure (Microsoft, Google, link wrappers…), shorteners "
                            "and recipients are left out so the list can be blocked as-is.", "Muted", wrap=True))

    def load(self, r: AnalysisResult) -> None:
        self.result = r
        self.reload()

    def reload(self) -> None:
        self.tree.clear()
        if not self.result:
            return
        i = self.result.iocs
        f = dom.defang if self.defang.isChecked() else (lambda v: v)
        bold = self.tree.font()
        bold.setBold(True)
        for attr, title, kind in self.GROUPS:
            values = getattr(i, attr)
            if not values:
                continue
            top = QTreeWidgetItem([f"{title} ({len(values)})", ""])
            top.setFont(0, bold)
            for v in values:
                child = QTreeWidgetItem([f(v), ""])
                child.setData(0, Qt.ItemDataRole.UserRole, (v, kind))
                top.addChild(child)
            self.tree.addTopLevelItem(top)
            top.setExpanded(True)
        if i.hashes:
            top = QTreeWidgetItem([f"File hashes ({len(i.hashes)})", ""])
            top.setFont(0, bold)
            for h in i.hashes:
                for algo in ("sha256", "sha1", "md5"):
                    child = QTreeWidgetItem([h[algo], f"{algo.upper()} · {h['filename']}"])
                    child.setData(0, Qt.ItemDataRole.UserRole, (h[algo], "hash"))
                    top.addChild(child)
            self.tree.addTopLevelItem(top)
            top.setExpanded(True)
        if not self.tree.topLevelItemCount():
            self.tree.addTopLevelItem(QTreeWidgetItem(["No indicators extracted", ""]))

    def _copy_all(self) -> None:
        if self.result:
            copy_text(ioc_mod.to_text(self.result.iocs, self.defang.isChecked()))
            self.ctx.notify("All IOCs copied")

    def _export(self, fmt: str) -> None:
        if not self.result:
            return
        stem = self.ctx.case_name()
        path, _ = QFileDialog.getSaveFileName(self, "Export IOCs", f"{stem}.iocs.{fmt}",
                                              {"csv": "CSV (*.csv)", "json": "JSON (*.json)", "txt": "Text (*.txt)"}[fmt])
        if not path:
            return
        d = self.defang.isChecked()
        data = {"csv": ioc_mod.to_csv, "json": ioc_mod.to_json, "txt": ioc_mod.to_text}[fmt](self.result.iocs, d)
        Path(path).write_text(data, encoding="utf-8")
        self.ctx.notify(f"IOCs exported to {Path(path).name}")

    def _menu(self, pos: QPoint) -> None:
        items = [it.data(0, Qt.ItemDataRole.UserRole) for it in self.tree.selectedItems()]
        items = [x for x in items if x]
        if not items:
            return
        menu = QMenu(self)
        menu.addAction("Copy", lambda: copy_text("\n".join(v for v, _k in items)))
        menu.addAction("Copy defanged", lambda: copy_text("\n".join(dom.defang(v) for v, k in items)))
        value, kind = items[0]
        add_pivot_menu(menu, value, kind)
        menu.exec(self.tree.viewport().mapToGlobal(pos))


# =========================================================================== Hunting


class HuntingTab(QWidget):
    LOOKBACKS = ["1d", "7d", "14d", "30d", "90d", "180d"]

    def __init__(self, ctx: MainWindow) -> None:
        super().__init__()
        self.ctx = ctx
        self.result: AnalysisResult | None = None
        self.queries: list = []
        w, lay = _page()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(w)
        lay.addWidget(Banner("KQL for <b>Microsoft Defender XDR → Hunting → Advanced hunting</b> (also Microsoft "
                             "Sentinel with the Defender XDR connector). Built from this message's identifiers "
                             "and IOCs: scope the campaign, find clicks and purge copies."))
        self.lookback = QComboBox()
        self.lookback.addItems(self.LOOKBACKS)
        self.lookback.setCurrentText(ctx.settings.hunting_lookback)
        self.lookback.currentTextChanged.connect(lambda _t: self._rebuild())
        split = QSplitter(Qt.Orientation.Horizontal)
        self.list = QListWidget()
        self.list.setMinimumWidth(260)
        self.list.currentRowChanged.connect(self._show)
        split.addWidget(self.list)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(12, 0, 0, 0)
        rl.setSpacing(8)
        self.title = label("", "H2")
        self.desc = label("", "Muted", wrap=True)
        self.tables = QHBoxLayout()
        self.tables.setSpacing(6)
        self.editor = _mono_view(read_only=False)
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        rl.addWidget(self.title)
        rl.addWidget(self.desc)
        rl.addLayout(self.tables)
        rl.addWidget(self.editor, 1)
        rl.addLayout(hbox(label("Lookback", "Muted"), self.lookback, None,
                          button("Copy all queries", self._copy_all),
                          button("Copy query", self._copy, primary=True)))
        split.addWidget(right)
        split.setSizes([300, 800])
        lay.addWidget(split, 1)

    def load(self, r: AnalysisResult) -> None:
        self.result = r
        self._rebuild()

    def _rebuild(self) -> None:
        if not self.result:
            return
        r = self.result
        self.queries = hunting.build_queries(r.email, r.sender, r.iocs, r.network_message_id,
                                             self.lookback.currentText())
        self.list.clear()
        for q in self.queries:
            QListWidgetItem(q.title, self.list)
        if self.queries:
            self.list.setCurrentRow(0)
        else:
            self.title.setText("No queries")
            self.desc.setText("The message has no Message-ID, sender or IOCs to hunt for.")
            self.editor.clear()

    def _show(self, row: int) -> None:
        if row < 0 or row >= len(self.queries):
            return
        q = self.queries[row]
        self.title.setText(q.title)
        self.desc.setText(q.description)
        while self.tables.count():
            item = self.tables.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for t in q.tables:
            self.tables.addWidget(Chip(t, theme.current()["accent"]))
        self.tables.addStretch(1)
        self.editor.setPlainText(q.query)

    def _copy(self) -> None:
        copy_text(self.editor.toPlainText())
        self.ctx.notify("Query copied")

    def _copy_all(self) -> None:
        copy_text("\n\n".join(f"// {q.title}\n{q.query}" for q in self.queries))
        self.ctx.notify(f"{len(self.queries)} queries copied")


# =========================================================================== Reputation


class ReputationTab(QWidget):
    def __init__(self, ctx: MainWindow) -> None:
        super().__init__()
        self.ctx = ctx
        self.result: AnalysisResult | None = None
        self.job = None
        w, lay = _page()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(w)
        self.banner = Banner("", "warn")
        self.banner.add_action(button("Settings…", ctx.open_settings))
        lay.addWidget(self.banner)
        self.run_btn = button("Run lookups", self.start, primary=True)
        self.stop_btn = button("Stop", self.stop)
        self.stop_btn.setEnabled(False)
        self.include_urls = toggle("Include full URLs", False)
        self.status = label("", "Muted")
        lay.addLayout(hbox(self.run_btn, self.stop_btn, self.include_urls, 12, self.status, None))
        self.table = DataTable(["Verdict", "Indicator", "Type", "Provider", "Score", "Details"],
                               "Filter results…")
        self.table.set_column_widths({0: 110, 1: 360, 2: 80, 3: 110, 4: 90})
        self.table.activated.connect(lambda r: r and r.link and QDesktopServices.openUrl(QUrl(r.link)))
        self.table.context_menu.connect(self._menu)
        lay.addWidget(self.table, 1)
        lay.addWidget(label("Double-click a row to open the provider's page. Results are cached locally for "
                            f"{ctx.settings.cache_ttl_hours} h.", "Muted"))
        self.refresh_banner()

    def refresh_banner(self) -> None:
        from emailicioso.core.reputation import build_providers

        names = [p.name for p in build_providers(self.ctx.settings)]
        keys = []
        if not self.ctx.settings.api_key("virustotal_api_key"):
            keys.append("VirusTotal")
        if not self.ctx.settings.api_key("abuseipdb_api_key"):
            keys.append("AbuseIPDB")
        txt = ("<b>OPSEC:</b> lookups send the indicators to third-party services. They only run when you click "
               f"<b>Run lookups</b>{' (automatic mode is ON in Settings)' if self.ctx.settings.auto_reputation else ''}. "
               f"Active providers: {', '.join(names)}.")
        if keys:
            txt += f" Add free API keys for {' and '.join(keys)} in Settings for verdicts."
        self.banner.set_text(txt)

    def load(self, r: AnalysisResult) -> None:
        self.stop()
        self.result = r
        self.table.clear()
        self.status.setText("")
        self.refresh_banner()
        if self.ctx.settings.auto_reputation:
            self.start()

    def start(self) -> None:
        from emailicioso.core.cache import ReputationCache
        from emailicioso.core.reputation import build_providers, indicators_from_iocs, run_checks

        if not self.result or self.job is not None:
            return
        indicators = indicators_from_iocs(self.result.iocs, self.include_urls.isChecked())
        if not indicators:
            self.status.setText("No indicators to look up.")
            return
        providers = build_providers(self.ctx.settings)
        cache = ReputationCache(ttl_hours=self.ctx.settings.cache_ttl_hours)
        self.table.clear()
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status.setText(f"Checking {len(indicators)} indicators…")

        def work(job: Any) -> int:
            n = 0
            for res in run_checks(indicators, providers, cache, lambda: job.cancelled):
                job.emit_progress(res)
                n += 1
            return n

        self.job = self.ctx.jobs.start(work, self._done, self._failed, self._add)
        self.ctx.busy(True, "Reputation lookups running…")

    def stop(self) -> None:
        if self.job is not None:
            self.job.cancel()
            self.status.setText("Stopping…")

    def _add(self, res: Any) -> None:
        color = theme.VERDICT_COLORS.get(res.verdict, "#8b95a7")
        detail = res.error or res.detail
        self.table.add_row([
            {"text": res.verdict.capitalize(), "color": color,
             "sort": {"malicious": 4, "suspicious": 3, "unknown": 1, "clean": 0}.get(res.verdict, 2)},
            {"text": dom.defang(res.indicator) if self.ctx.settings.defang else res.indicator, "mono": True,
             "tooltip": res.indicator},
            res.kind, res.provider, res.score,
            {"text": detail + ("  (cached)" if res.cached else ""), "tooltip": detail},
        ], res)
        self.status.setText(f"{self.table.model.rowCount()} results…")

    def _done(self, n: int) -> None:
        self.job = None
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        bad = sum(1 for r in self.table.all_payloads(False) if r.verdict in ("malicious", "suspicious"))
        self.status.setText(f"Done: {n} results, {bad} flagged.")
        self.table.view.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        self.ctx.busy(False, f"Reputation lookups finished ({bad} flagged)")

    def _failed(self, err: str) -> None:
        self.job = None
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status.setText(f"Error: {err}")
        self.ctx.busy(False, "Reputation lookups failed")

    def _menu(self, results: list, pos: QPoint) -> None:
        menu = QMenu(self)
        r = results[0]
        if r.link:
            menu.addAction(f"Open in {r.provider}", lambda: QDesktopServices.openUrl(QUrl(r.link)))
        menu.addAction("Copy indicator", lambda: copy_text("\n".join(x.indicator for x in results)))
        add_pivot_menu(menu, r.indicator, r.kind)
        menu.exec(pos)


# =========================================================================== Screenshots


class ScreenshotsTab(QWidget):
    def __init__(self, ctx: MainWindow) -> None:
        super().__init__()
        self.ctx = ctx
        self.result: AnalysisResult | None = None
        self.job = None
        self.rows: dict[str, dict] = {}
        w, lay = _page()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(w)
        self.banner = Banner("", "warn")
        self.banner.add_action(button("Settings…", ctx.open_settings))
        lay.addWidget(self.banner)
        self.table = DataTable(["Status", "URL", "Final URL", "Page title", "Evidence file"], "Filter…")
        self.table.set_column_widths({0: 110, 1: 380, 2: 300, 3: 220})
        self.table.activated.connect(self._activated)
        lay.addWidget(self.table, 1)
        self.stop_btn = button("Stop", self._stop)
        self.stop_btn.setEnabled(False)
        lay.addLayout(hbox(
            button("Capture selected", self._capture_selected, primary=True),
            button("Capture all risky", self._capture_risky),
            self.stop_btn,
            None,
            button("Open evidence folder", self._open_folder),
        ))
        self.refresh_banner()

    def refresh_banner(self) -> None:
        s = self.ctx.settings
        proxy = f"through proxy <b>{html.escape(s.screenshot_proxy)}</b>" if s.screenshot_proxy else \
            "<b>directly from this machine</b> (no proxy configured)"
        self.banner.set_text("Capturing <b>visits the live URL</b> with a headless browser " + proxy +
                             ". The site will see your IP and may serve malware or alert the attacker. "
                             "Prefer an isolated network or a proxy/VPN.")

    def load(self, r: AnalysisResult) -> None:
        self.result = r
        self.rows.clear()
        self.refresh_banner()
        rows = []
        for u in r.urls:
            if u.source.endswith("-resource") or not u.target.lower().startswith(("http://", "https://")):
                continue
            if u.target in self.rows:
                continue
            self.rows[u.target] = {"status": "Not captured", "final": "", "title": "", "file": ""}
            rows.append((self._cells(u.target), u.target))
        self.table.set_rows(rows)

    def _cells(self, url: str) -> list:
        st = self.rows[url]
        colors = {"Captured": theme.current()["ok"], "Error": theme.SEVERITY_COLORS[Severity.CRITICAL],
                  "Capturing…": theme.current()["accent"], "Queued": theme.current()["muted"]}
        return [{"text": st["status"], "color": colors.get(st["status"])},
                {"text": dom.defang_url(url), "mono": True, "tooltip": url},
                {"text": dom.defang_url(st["final"]) if st["final"] else "", "tooltip": st["final"]},
                st["title"], {"text": Path(st["file"]).name if st["file"] else "", "tooltip": st.get("error") or st["file"]}]

    def _refresh_row(self, url: str) -> None:
        payloads = self.table.all_payloads(False)
        if url not in payloads:
            self.rows[url] = self.rows.get(url) or {"status": "Not captured", "final": "", "title": "", "file": ""}
            self.table.add_row(self._cells(url), url)
            return
        row = payloads.index(url)
        for col, cell in enumerate(self._cells(url)):
            item = self.table._make_item(cell)
            if col == 0:
                item.setData(url, PAYLOAD_ROLE)
            self.table.model.setItem(row, col, item)

    def capture(self, urls: list[str]) -> None:
        from emailicioso.core.screenshots import ScreenshotUnavailable, capture, evidence_path

        if self.job is not None:
            self.ctx.notify("A capture is already running")
            return
        urls = [u for u in urls if u.lower().startswith(("http://", "https://"))]
        if not urls:
            return
        s = self.ctx.settings
        msg = (f"Visit {len(urls)} URL(s) with a headless browser "
               f"{'through ' + s.screenshot_proxy if s.screenshot_proxy else 'directly from this machine'}?\n\n"
               + "\n".join(dom.defang_url(u) for u in urls[:8]) + ("\n…" if len(urls) > 8 else ""))
        if QMessageBox.question(self, "Capture screenshots", msg) != QMessageBox.StandardButton.Yes:
            return
        for u in urls:
            self.rows.setdefault(u, {"status": "", "final": "", "title": "", "file": ""})
            self.rows[u].update(status="Queued", error="")
            self._refresh_row(u)
        case = self.ctx.case_name()

        def work(job: Any) -> int:
            ok = 0
            for u in urls:
                if job.cancelled:
                    break
                job.emit_progress((u, "Capturing…", None, ""))
                try:
                    cap = capture(u, evidence_path(s.evidence_dir, case, u), s.screenshot_timeout, s.screenshot_proxy)
                    job.emit_progress((u, "Captured", cap, ""))
                    ok += 1
                except ScreenshotUnavailable as exc:
                    job.emit_progress((u, "Error", None, str(exc)))
                    break
                except Exception as exc:
                    job.emit_progress((u, "Error", None, f"{type(exc).__name__}: {exc}"))
            return ok

        self.stop_btn.setEnabled(True)
        self.job = self.ctx.jobs.start(work, self._done, self._failed, self._progress)
        self.ctx.busy(True, "Capturing screenshots…")

    def _progress(self, data: tuple) -> None:
        url, status, cap, err = data
        st = self.rows.setdefault(url, {"status": "", "final": "", "title": "", "file": ""})
        st["status"] = status
        if cap is not None:
            st.update(final=cap.final_url, title=cap.title, file=str(cap.path))
        if err:
            st["error"] = err
            if "Playwright" in err or "Chromium" in err:
                QMessageBox.warning(self, "Screenshots unavailable", err)
        self._refresh_row(url)

    def _done(self, ok: int) -> None:
        self.job = None
        self.stop_btn.setEnabled(False)
        self.ctx.busy(False, f"{ok} screenshot(s) captured")

    def _failed(self, err: str) -> None:
        self.job = None
        self.stop_btn.setEnabled(False)
        self.ctx.busy(False, f"Capture failed: {err}")

    def _stop(self) -> None:
        if self.job is not None:
            self.job.cancel()

    def _capture_selected(self) -> None:
        sel = self.table.selected()
        if not sel:
            self.ctx.notify("Select one or more URLs first")
            return
        self.capture(sel)

    def _capture_risky(self) -> None:
        if not self.result:
            return
        risky = [u.target for u in self.result.urls if u.severity >= Severity.MEDIUM and u.target in self.rows]
        if not risky:
            self.ctx.notify("No risky URLs to capture")
            return
        self.capture(risky)

    def _activated(self, url: str | None) -> None:
        if not url:
            return
        st = self.rows.get(url, {})
        if st.get("file") and Path(st["file"]).exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(st["file"]))
        elif st.get("error"):
            QMessageBox.information(self, "Capture error", st["error"])
        else:
            self.capture([url])

    def _open_folder(self) -> None:
        folder = Path(self.ctx.settings.evidence_dir).expanduser() / self.ctx.case_name()
        folder.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))


__all__ = [
    "OverviewTab", "HeadersTab", "AuthTab", "BodyTab", "UrlsTab", "AttachmentsTab", "IocsTab", "HuntingTab",
    "ReputationTab", "ScreenshotsTab",
]
