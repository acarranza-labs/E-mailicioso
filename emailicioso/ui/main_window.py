"""Main window: welcome screen, analysis view with tabs, menus and background jobs."""

from __future__ import annotations

import re
from pathlib import Path

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QAction, QDragEnterEvent, QDropEvent, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QStackedWidget,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from emailicioso import APP_NAME, __version__
from emailicioso.core import report
from emailicioso.core.models import AnalysisResult, AttachmentInfo, Severity
from emailicioso.core.settings import Settings
from emailicioso.ui import theme
from emailicioso.ui.settings_dialog import SettingsDialog
from emailicioso.ui.tabs import (
    AttachmentsTab,
    AuthTab,
    BodyTab,
    HeadersTab,
    HuntingTab,
    IocsTab,
    OverviewTab,
    ReputationTab,
    ScreenshotsTab,
    UrlsTab,
)
from emailicioso.ui.widgets import Chip, DropZone, VerdictGauge, app_icon, button, copy_text, label
from emailicioso.ui.workers import JobRunner, analysis_job

DEMO_SAMPLE = Path(__file__).resolve().parents[2] / "samples" / "demo-phishing.eml"
FILE_FILTER = "Email files (*.eml *.msg);;All files (*)"


class MainWindow(QMainWindow):
    def __init__(self, settings: Settings | None = None) -> None:
        super().__init__()
        self.settings = settings or Settings.load()
        self.jobs = JobRunner(self)
        self.result: AnalysisResult | None = None
        self.history: list[tuple[Path | None, bytes | None, str]] = []  # previous analyses (for Back)
        self._current_source: tuple[Path | None, bytes | None, str] | None = None
        self._loading = False

        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(app_icon())
        self.resize(1400, 900)
        self.setMinimumSize(QSize(1040, 680))
        self.setAcceptDrops(True)

        self._build_actions()
        self._build_ui()
        self._refresh_recent()
        self.stack.setCurrentIndex(0)
        self._update_actions()

    # ================================================================== construction
    def _build_actions(self) -> None:
        def act(text: str, slot, shortcut: str | QKeySequence | None = None) -> QAction:
            a = QAction(text, self)
            a.triggered.connect(slot)
            if shortcut:
                a.setShortcut(QKeySequence(shortcut))
            self.addAction(a)
            return a

        self.a_open = act("Open email…", self.open_dialog, QKeySequence.StandardKey.Open)
        self.a_reload = act("Re-analyze", self.reanalyze, "F5")
        self.a_close = act("Close email", self.close_email, QKeySequence.StandardKey.Close)
        self.a_back = act("Back to parent email", self.go_back, "Alt+Left")
        self.a_html = act("Export HTML report…", self.export_html, "Ctrl+E")
        self.a_json = act("Export JSON…", self.export_json, "Ctrl+Shift+E")
        self.a_sum_en = act("Copy ticket summary (EN)", lambda: self.copy_summary("en"), "Ctrl+Shift+C")
        self.a_sum_es = act("Copiar resumen del ticket (ES)", lambda: self.copy_summary("es"))
        self.a_iocs = act("Copy all IOCs", self.copy_iocs, "Ctrl+Shift+I")
        self.a_settings = act("Settings…", self.open_settings, "Ctrl+,")
        self.a_theme = act("Toggle dark/light theme", self.toggle_theme, "Ctrl+T")
        self.a_quit = act("Quit", self.close, QKeySequence.StandardKey.Quit)

        mb = self.menuBar()
        m = mb.addMenu("&File")
        m.addAction(self.a_open)
        self.recent_menu = m.addMenu("Open recent")
        m.addAction(self.a_reload)
        m.addAction(self.a_back)
        m.addAction(self.a_close)
        m.addSeparator()
        m.addAction(self.a_html)
        m.addAction(self.a_json)
        m.addSeparator()
        m.addAction(self.a_settings)
        m.addSeparator()
        m.addAction(self.a_quit)
        m = mb.addMenu("&Analysis")
        m.addAction(self.a_sum_en)
        m.addAction(self.a_sum_es)
        m.addAction(self.a_iocs)
        m = mb.addMenu("&View")
        m.addAction(self.a_theme)
        m = mb.addMenu("&Help")
        m.addAction("About E-mailicioso", self._about)

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("Page")
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Top bar --------------------------------------------------------------
        bar = QFrame()
        bar.setObjectName("TopBar")
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(16, 10, 16, 10)
        bl.setSpacing(8)
        logo = QLabel()
        logo.setPixmap(app_icon().pixmap(26, 26))
        bl.addWidget(logo)
        bl.addWidget(label(APP_NAME, "Brand"))
        bl.addSpacing(14)
        self.back_btn = button("‹ Back", self.go_back, flat=True, tooltip="Back to the parent email (Alt+Left)")
        bl.addWidget(self.back_btn)
        bl.addWidget(button("Open…", self.open_dialog, tooltip="Open an .eml or .msg file (Ctrl+O)"))
        self.export_btn = QToolButton()
        self.export_btn.setText("Export  ▾")
        self.export_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.export_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        em = QMenu(self.export_btn)
        em.addAction(self.a_html)
        em.addAction(self.a_json)
        em.addSeparator()
        em.addAction(self.a_iocs)
        self.export_btn.setMenu(em)
        bl.addWidget(self.export_btn)
        self.summary_btn = QToolButton()
        self.summary_btn.setText("Copy summary  ▾")
        self.summary_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.summary_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        sm = QMenu(self.summary_btn)
        sm.addAction(self.a_sum_en)
        sm.addAction(self.a_sum_es)
        self.summary_btn.setMenu(sm)
        bl.addWidget(self.summary_btn)
        bl.addStretch(1)
        self.theme_btn = button("", self.toggle_theme, flat=True, tooltip="Toggle theme (Ctrl+T)")
        bl.addWidget(self.theme_btn)
        bl.addWidget(button("Settings", self.open_settings, flat=True, tooltip="Settings (Ctrl+,)"))
        root.addWidget(bar)

        # Pages ------------------------------------------------------------------
        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_welcome())
        self.stack.addWidget(self._build_analysis())
        root.addWidget(self.stack, 1)
        self.setCentralWidget(central)

        # Status bar ---------------------------------------------------------------
        sb = self.statusBar()
        self.status_msg = QLabel("")
        self.status_msg.setStyleSheet("padding-left: 10px;")
        self.status_msg.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        sb.addWidget(self.status_msg, 1)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setFixedWidth(120)
        self.progress.setVisible(False)
        sb.addPermanentWidget(self.progress)
        sb.addPermanentWidget(label(f"v{__version__} · static analysis, offline by default  ", "Muted"))
        self._status_timer = QTimer(self)
        self._status_timer.setSingleShot(True)
        self._status_timer.timeout.connect(lambda: self.status_msg.setText(""))
        self._update_theme_button()

    def _build_welcome(self) -> QWidget:
        page = QWidget()
        page.setObjectName("Page")
        outer = QVBoxLayout(page)
        outer.setContentsMargins(40, 30, 40, 30)
        outer.addStretch(1)
        col = QVBoxLayout()
        col.setSpacing(14)

        title = label("Analyze a suspicious email", "H1")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub = label("Headers, authentication, links, attachments, IOCs and KQL hunting queries in seconds. "
                    "Everything runs locally: nothing is sent anywhere unless you ask for it.", "Muted", wrap=True)
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        col.addWidget(title)
        col.addWidget(sub)

        self.drop = DropZone()
        dl = QVBoxLayout(self.drop)
        dl.setContentsMargins(30, 30, 30, 30)
        dl.setSpacing(10)
        dl.addStretch(1)
        icon = QLabel()
        icon.setPixmap(app_icon().pixmap(56, 56))
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dl.addWidget(icon)
        t = label("Drop an .eml or .msg file here", "H2")
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dl.addWidget(t)
        hint = label("or", "Muted")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dl.addWidget(hint)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(button("Choose file…", self.open_dialog, primary=True))
        if DEMO_SAMPLE.exists():
            row.addWidget(button("Try the demo phishing sample", lambda: self.load_path(DEMO_SAMPLE)))
        row.addStretch(1)
        dl.addLayout(row)
        dl.addStretch(1)
        col.addWidget(self.drop)

        self.recent_title = label("RECENT", "SectionTitle")
        col.addWidget(self.recent_title)
        self.recent_list = QListWidget()
        self.recent_list.setMaximumHeight(190)
        self.recent_list.itemActivated.connect(lambda it: self.load_path(Path(it.data(Qt.ItemDataRole.UserRole))))
        self.recent_list.itemClicked.connect(lambda it: self.load_path(Path(it.data(Qt.ItemDataRole.UserRole))))
        col.addWidget(self.recent_list)

        wrap = QHBoxLayout()
        wrap.addStretch(1)
        holder = QWidget()
        holder.setLayout(col)
        holder.setMaximumWidth(760)
        holder.setMinimumWidth(560)
        wrap.addWidget(holder, 3)
        wrap.addStretch(1)
        outer.addLayout(wrap)
        outer.addStretch(2)
        return page

    def _build_analysis(self) -> QWidget:
        page = QWidget()
        page.setObjectName("Page")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(18, 14, 18, 0)
        lay.setSpacing(4)

        head = QFrame()
        head.setObjectName("Card")
        hl = QHBoxLayout(head)
        hl.setContentsMargins(18, 12, 12, 12)
        hl.setSpacing(16)
        info = QVBoxLayout()
        info.setSpacing(4)
        self.crumb = label("", "Muted")
        self.subject = label("", "H1")
        self.subject.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.meta = label("", "Muted")
        self.meta.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.chips = QHBoxLayout()
        self.chips.setSpacing(6)
        info.addWidget(self.crumb)
        info.addWidget(self.subject)
        info.addWidget(self.meta)
        info.addSpacing(2)
        info.addLayout(self.chips)
        hl.addLayout(info, 1)
        self.gauge = VerdictGauge()
        hl.addWidget(self.gauge, 0, Qt.AlignmentFlag.AlignVCenter)
        lay.addWidget(head)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.t_overview = OverviewTab(self)
        self.t_headers = HeadersTab(self)
        self.t_auth = AuthTab(self)
        self.t_body = BodyTab(self)
        self.t_urls = UrlsTab(self)
        self.t_atts = AttachmentsTab(self)
        self.t_iocs = IocsTab(self)
        self.t_hunting = HuntingTab(self)
        self.t_rep = ReputationTab(self)
        self.t_shots = ScreenshotsTab(self)
        for w, name in ((self.t_overview, "Overview"), (self.t_headers, "Headers"), (self.t_auth, "Authentication"),
                        (self.t_body, "Body"), (self.t_urls, "URLs"), (self.t_atts, "Attachments"),
                        (self.t_iocs, "IOCs"), (self.t_hunting, "Hunting (KQL)"), (self.t_rep, "Reputation"),
                        (self.t_shots, "Screenshots")):
            self.tabs.addTab(w, name)
        for i in range(min(9, self.tabs.count())):
            a = QAction(self)
            a.setShortcut(QKeySequence(f"Ctrl+{i + 1}"))
            a.triggered.connect(lambda _=False, idx=i: self.tabs.setCurrentIndex(idx))
            self.addAction(a)
        lay.addWidget(self.tabs, 1)
        return page

    # ================================================================== helpers for tabs
    def notify(self, msg: str, timeout: int = 5000) -> None:
        self.status_msg.setText(msg)
        self._status_timer.stop()
        if msg and timeout:
            self._status_timer.start(timeout)

    def busy(self, on: bool, msg: str = "") -> None:
        self.progress.setVisible(on)
        if msg:
            self.notify(msg, 0 if on else 6000)

    def case_name(self) -> str:
        if not self.result:
            return "case"
        e = self.result.email
        base = e.path.stem if e.path else "email"
        return re.sub(r"[^\w.\- ]+", "_", base)[:80] or "case"

    def capture_urls(self, urls: list[str]) -> None:
        self.tabs.setCurrentWidget(self.t_shots)
        self.t_shots.capture(urls)

    # ================================================================== loading
    def open_dialog(self) -> None:
        start = str(Path(self.settings.recent_files[0]).parent) if self.settings.recent_files else str(Path.home())
        path, _ = QFileDialog.getOpenFileName(self, "Open email", start, FILE_FILTER)
        if path:
            self.load_path(Path(path))

    def load_path(self, path: Path) -> None:
        if not path.is_file():
            QMessageBox.warning(self, "File not found", f"{path}\n\nThe file no longer exists.")
            if str(path) in self.settings.recent_files:
                self.settings.recent_files.remove(str(path))
                self.settings.save()
                self._refresh_recent()
            return
        self.history.clear()
        self._start((path, None, path.name))

    def open_attached_email(self, att: AttachmentInfo) -> None:
        if not att.payload:
            QMessageBox.warning(self, "Empty attachment", "The attached email has no content.")
            return
        if self._current_source:
            self.history.append(self._current_source)
        parent = self._current_source[2] if self._current_source else ""
        self._start((Path(att.filename), att.payload, f"{parent} › {att.filename}" if parent else att.filename))

    def go_back(self) -> None:
        if self.history:
            self._start(self.history.pop())

    def reanalyze(self) -> None:
        if self._current_source:
            self._start(self._current_source)

    def close_email(self) -> None:
        self.result = None
        self._current_source = None
        self.history.clear()
        self.stack.setCurrentIndex(0)
        self.setWindowTitle(APP_NAME)
        self._refresh_recent()
        self._update_actions()

    def _start(self, source: tuple[Path | None, bytes | None, str]) -> None:
        if self._loading:
            return
        path, raw, crumb = source
        self._loading = True
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        self.busy(True, f"Analyzing {crumb}…")

        def done(result: AnalysisResult) -> None:
            self._finish_loading()
            self._current_source = source
            if raw is None and path is not None:
                self.settings.add_recent(str(path))
                self.settings.save()
                self._refresh_recent()
            self._show(result, crumb)

        def failed(err: str) -> None:
            self._finish_loading()
            QMessageBox.critical(self, "Could not analyze the file", f"{crumb}\n\n{err}")
            if raw is not None and self.history:
                self.history.pop()

        self.jobs.start(analysis_job(path, raw, self.settings.hunting_lookback), done, failed)

    def _finish_loading(self) -> None:
        self._loading = False
        QApplication.restoreOverrideCursor()
        self.busy(False)

    def _show(self, r: AnalysisResult, crumb: str) -> None:
        self.result = r
        e = r.email
        self.setWindowTitle(f"{e.subject or '(no subject)'} — {APP_NAME}")
        self.crumb.setText(crumb if self.history else (str(e.path.parent) if e.path and e.path.parent != Path(".")
                                                       else crumb))
        subject = e.subject or "(no subject)"
        self.subject.setText(subject if len(subject) < 110 else subject[:107] + "…")
        self.subject.setToolTip(subject)
        sender = str(r.sender) if r.sender else e.from_
        self.meta.setText(f"{sender}   →   {e.to or '(no recipient)'}   ·   {e.date}")
        while self.chips.count():
            item = self.chips.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for mech, res in r.auth_summary().items():
            if mech in ("SPF", "DKIM", "DMARC", "CompAuth"):
                self.chips.addWidget(Chip(f"{mech} {res}", theme.AUTH_COLORS.get(res, "#8b95a7")))
        if r.originating_ip:
            self.chips.addWidget(Chip(f"Origin {r.originating_ip}", theme.current()["muted"]))
        risky = sum(1 for u in r.urls if u.severity >= Severity.MEDIUM)
        if r.urls:
            self.chips.addWidget(Chip(f"{len(r.urls)} URL{'s' if len(r.urls) != 1 else ''}"
                                      + (f" · {risky} risky" if risky else ""),
                                      theme.SEVERITY_COLORS[Severity.HIGH] if risky else theme.current()["muted"]))
        if r.attachments:
            bad = sum(1 for a in r.attachments if a.severity >= Severity.MEDIUM)
            self.chips.addWidget(Chip(f"{len(r.attachments)} attachment{'s' if len(r.attachments) != 1 else ''}"
                                      + (f" · {bad} risky" if bad else ""),
                                      theme.SEVERITY_COLORS[Severity.HIGH] if bad else theme.current()["muted"]))
        if e.source_format == "msg":
            self.chips.addWidget(Chip("Outlook .msg", theme.current()["accent"]))
        self.chips.addStretch(1)
        self.gauge.set_result(r.score, r.level, r.verdict)

        for tab in (self.t_overview, self.t_headers, self.t_auth, self.t_body, self.t_urls, self.t_atts,
                    self.t_iocs, self.t_hunting, self.t_rep, self.t_shots):
            tab.load(r)
        counts = {
            self.t_overview: len([f for f in r.findings if f.severity > Severity.INFO]),
            self.t_headers: len(r.hops),
            self.t_urls: len(r.urls),
            self.t_atts: len(r.attachments),
            self.t_iocs: len(r.iocs.ips) + len(r.iocs.domains) + len(r.iocs.urls) + len(r.iocs.emails)
            + len(r.iocs.hashes),
            self.t_hunting: len(r.hunting),
        }
        base = ["Overview", "Headers", "Authentication", "Body", "URLs", "Attachments", "IOCs", "Hunting (KQL)",
                "Reputation", "Screenshots"]
        for i, name in enumerate(base):
            w = self.tabs.widget(i)
            n = counts.get(w)
            self.tabs.setTabText(i, f"{name}  {n}" if n else name)
        self.tabs.setCurrentIndex(0)
        self.stack.setCurrentIndex(1)
        self._update_actions()
        self.notify(f"Analyzed {crumb}: {r.verdict} ({r.score}/100), {len(r.findings)} findings", 8000)

    # ================================================================== exports
    def export_html(self) -> None:
        if not self.result:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export HTML report", f"{self.case_name()}.report.html",
                                              "HTML (*.html)")
        if path:
            report.save_html(self.result, path, self.settings.defang)
            self.notify(f"Report saved: {path}")
            from PySide6.QtCore import QUrl
            from PySide6.QtGui import QDesktopServices

            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def export_json(self) -> None:
        if not self.result:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", f"{self.case_name()}.analysis.json",
                                              "JSON (*.json)")
        if path:
            Path(path).write_text(report.to_json(self.result), encoding="utf-8")
            self.notify(f"JSON saved: {path}")

    def copy_summary(self, lang: str) -> None:
        if self.result:
            copy_text(report.summary_text(self.result, lang))
            self.notify("Ticket summary copied to the clipboard")

    def copy_iocs(self) -> None:
        if self.result:
            from emailicioso.core import iocs

            copy_text(iocs.to_text(self.result.iocs, self.settings.defang))
            self.notify("IOCs copied to the clipboard")

    # ================================================================== settings & theme
    def open_settings(self) -> None:
        old_theme = self.settings.theme
        dlg = SettingsDialog(self.settings, self)
        if dlg.exec():
            if self.settings.theme != old_theme:
                self._apply_theme()
            self.t_rep.refresh_banner()
            self.t_shots.refresh_banner()
            self.notify("Settings saved")

    def toggle_theme(self) -> None:
        self.settings.theme = "light" if self.settings.theme == "dark" else "dark"
        self.settings.save()
        self._apply_theme()

    def _apply_theme(self) -> None:
        theme.apply(QApplication.instance(), self.settings.theme)  # type: ignore[arg-type]
        self._update_theme_button()
        if self.result:
            src = self._current_source
            self._show(self.result, src[2] if src else "")
        self.update()

    def _update_theme_button(self) -> None:
        self.theme_btn.setText("Light theme" if self.settings.theme == "dark" else "Dark theme")

    # ================================================================== misc
    def _refresh_recent(self) -> None:
        self.recent_menu.clear()
        self.recent_list.clear()
        files = [f for f in self.settings.recent_files if f]
        for f in files:
            p = Path(f)
            self.recent_menu.addAction(p.name, lambda path=p: self.load_path(path))
            item = QListWidgetItem(f"{p.name}\n{p.parent}")
            item.setData(Qt.ItemDataRole.UserRole, f)
            item.setToolTip(f)
            self.recent_list.addItem(item)
        self.recent_menu.setEnabled(bool(files))
        self.recent_list.setVisible(bool(files))
        self.recent_title.setVisible(bool(files))

    def _update_actions(self) -> None:
        has = self.result is not None
        for a in (self.a_reload, self.a_close, self.a_html, self.a_json, self.a_sum_en, self.a_sum_es, self.a_iocs):
            a.setEnabled(has)
        self.export_btn.setEnabled(has)
        self.summary_btn.setEnabled(has)
        self.a_back.setEnabled(bool(self.history))
        self.back_btn.setVisible(bool(self.history))

    def _about(self) -> None:
        QMessageBox.about(
            self, f"About {APP_NAME}",
            f"<h3>{APP_NAME} {__version__}</h3>"
            "<p>Portable email forensics for SOC analysts: header and authentication analysis, link and "
            "attachment triage, IOC extraction and KQL hunting queries.</p>"
            "<p>Static analysis only: links are not visited and attachments are not executed unless you "
            "explicitly request a screenshot or a reputation lookup.</p>"
            "<p><a href='https://github.com/acarranza-labs/E-mailicioso'>github.com/acarranza-labs/E-mailicioso</a>"
            " · MIT License</p>")

    # ================================================================== drag & drop
    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        urls = event.mimeData().urls()
        if urls and urls[0].isLocalFile():
            event.acceptProposedAction()
            self.drop.set_hover(True)
            return
        event.ignore()

    def dragLeaveEvent(self, event) -> None:  # noqa: N802
        self.drop.set_hover(False)

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        self.drop.set_hover(False)
        urls = [u for u in event.mimeData().urls() if u.isLocalFile()]
        if urls:
            self.load_path(Path(urls[0].toLocalFile()))

    def closeEvent(self, event) -> None:  # noqa: N802
        self.jobs.cancel_all()
        self.jobs.wait_all(2000)
        self.settings.save()
        super().closeEvent(event)
