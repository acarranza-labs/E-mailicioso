import sys
import json
import subprocess
import os
import platform
from pathlib import Path
import tldextract

from PySide6.QtCore import QThread, Slot, Qt, QMimeData
from PySide6.QtGui import QDragEnterEvent, QDropEvent, QPalette, QColor
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QTabWidget,
    QVBoxLayout,
    QPushButton,
    QFileDialog,
    QMessageBox,
    QPlainTextEdit,
    QTextBrowser,
    QTableWidget,
    QTableWidgetItem,
    QLabel,
    QHBoxLayout,
    QHeaderView,
    QMenu,
    QMenuBar,
    QApplication,
)

from core.eml_parser import parse_eml
from core.url_extractor import extract_all_urls
from core.security_analysis import parse_authentication_results, extract_iocs, iocs_to_json
from core.url_decoder import analyze_urls
from core.report_generator import generate_html_report
from ui.workers import ScreenshotWorker, ReputationWorker, SingleScreenshotWorker
from core.utils import url_to_safe_filename, get_domain_from_url

# Settings file for recent files
SETTINGS_DIR = Path.home() / ".emailicioso"
RECENT_FILES_PATH = SETTINGS_DIR / "recent_files.json"
MAX_RECENT = 10


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("E-mailicioso - Forensic Toolkit")
        self.resize(1200, 850)
        self.setAcceptDrops(True)  # Enable drag & drop

        self.current_eml: Path | None = None
        self.current_parsed = None  # Store parsed for report
        self.current_auth_results = None
        self.current_iocs = None
        self.current_url_analysis = None
        self.last_urls: list[str] = []
        self.is_dark_theme = True

        # Refs for workers
        self._rep_thread: QThread | None = None
        self._rep_worker: ReputationWorker | None = None
        self._active_captures = {}

        self._setup_menu()
        self._setup_ui()
        self._load_recent_files()

    def _setup_menu(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        file_menu.addAction("Open EML...", self.open_eml, "Ctrl+O")
        
        self.recent_menu = file_menu.addMenu("Recent Files")
        
        file_menu.addSeparator()
        file_menu.addAction("Export Report (HTML)", self.export_report)
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close, "Ctrl+Q")
        
        # View menu
        view_menu = menubar.addMenu("View")
        view_menu.addAction("Toggle Theme", self.toggle_theme)

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Top Bar
        top_bar = QHBoxLayout()
        
        self.btn_open = QPushButton("📂 Open EML")
        self.btn_open.setFixedHeight(40)
        self.btn_open.clicked.connect(self.open_eml)
        top_bar.addWidget(self.btn_open)
        
        self.btn_export = QPushButton("📄 Export Report")
        self.btn_export.setFixedHeight(40)
        self.btn_export.clicked.connect(self.export_report)
        top_bar.addWidget(self.btn_export)
        
        self.btn_theme = QPushButton("🌙 Theme")
        self.btn_theme.setFixedHeight(40)
        self.btn_theme.clicked.connect(self.toggle_theme)
        top_bar.addWidget(self.btn_theme)
        
        top_bar.addStretch()
        
        self.status_label = QLabel("Drag & Drop an .eml file or click Open")
        self.status_label.setStyleSheet("color: #888;")
        top_bar.addWidget(self.status_label)
        
        layout.addLayout(top_bar)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # 1. Headers Tab
        self.headers_view = QPlainTextEdit()
        self.headers_view.setReadOnly(True)
        self.headers_view.setPlaceholderText("Header information...")
        self.tabs.addTab(self._wrap(self.headers_view), "📨 Headers")

        # 2. Body Tab
        self.body_text_view = QPlainTextEdit()
        self.body_text_view.setReadOnly(True)
        self.body_html_view = QTextBrowser()
        self.body_html_view.setReadOnly(True)
        self.body_html_view.setOpenExternalLinks(False)

        body_container = QWidget()
        body_layout = QVBoxLayout(body_container)
        body_layout.setContentsMargins(12, 12, 12, 12)
        body_layout.addWidget(QLabel("Text / Plain"))
        body_layout.addWidget(self.body_text_view, 1)
        body_layout.addWidget(QLabel("HTML (Rendered)"))
        body_layout.addWidget(self.body_html_view, 2)
        self.tabs.addTab(body_container, "📝 Body")

        # 3. Security Tab (NEW)
        self.security_table = QTableWidget(0, 3)
        self.security_table.setHorizontalHeaderLabels(["Mechanism", "Result", "Details"])
        self.security_table.horizontalHeader().setStretchLastSection(True)
        self.security_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tabs.addTab(self._wrap(self.security_table), "🛡️ Security")

        # 4. IOCs Tab (NEW)
        self.iocs_view = QPlainTextEdit()
        self.iocs_view.setReadOnly(True)
        self.iocs_view.setPlaceholderText("IOCs will appear here...")
        
        ioc_container = QWidget()
        ioc_layout = QVBoxLayout(ioc_container)
        ioc_layout.setContentsMargins(12, 12, 12, 12)
        
        btn_export_iocs = QPushButton("📋 Copy IOCs (JSON)")
        btn_export_iocs.clicked.connect(self.copy_iocs)
        ioc_layout.addWidget(btn_export_iocs)
        ioc_layout.addWidget(self.iocs_view, 1)
        
        self.tabs.addTab(ioc_container, "🧲 IOCs")

        # 5. URLs Tab
        self.urls_table = QTableWidget(0, 3)
        self.urls_table.setHorizontalHeaderLabels(["Original URL", "Final Destination", "Obfuscated?"])
        self.urls_table.horizontalHeader().setStretchLastSection(True)
        self.urls_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.urls_table.setAlternatingRowColors(True)
        self.tabs.addTab(self._wrap(self.urls_table), "🔗 URLs")

        # 6. Reputation Tab
        self.rep_view = QPlainTextEdit()
        self.rep_view.setReadOnly(True)
        self.btn_cancel_rep = QPushButton("Stop Check")
        self.btn_cancel_rep.setEnabled(False)
        self.btn_cancel_rep.clicked.connect(self.cancel_reputation)

        rep_container = QWidget()
        rep_layout = QVBoxLayout(rep_container)
        rep_layout.setContentsMargins(12, 12, 12, 12)
        rep_layout.addWidget(self.btn_cancel_rep)
        rep_layout.addWidget(self.rep_view, 1)
        self.tabs.addTab(rep_container, "🌐 Reputation")

        # 7. Screenshots Tab
        self.ss_table = QTableWidget(0, 3)
        self.ss_table.setHorizontalHeaderLabels(["URL", "Status", "Action"])
        self.ss_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.ss_table.setEditTriggers(QTableWidget.NoEditTriggers)

        ss_container = QWidget()
        ss_layout = QVBoxLayout(ss_container)
        ss_layout.setContentsMargins(12, 12, 12, 12)
        ss_layout.addWidget(QLabel("Screenshot URLs:"))
        ss_layout.addWidget(self.ss_table)
        self.tabs.addTab(ss_container, "🖼️ Screenshots")

        # 8. Attachments Tab
        self.atts_table = QTableWidget(0, 4)
        self.atts_table.setHorizontalHeaderLabels(["Filename", "Type", "Size", "Action"])
        self.atts_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.atts_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        atts_container = QWidget()
        atts_layout = QVBoxLayout(atts_container)
        atts_layout.setContentsMargins(12, 12, 12, 12)
        atts_layout.addWidget(QLabel("Attachments:"))
        atts_layout.addWidget(self.atts_table)
        self.tabs.addTab(atts_container, "📎 Attachments")

    def _wrap(self, widget: QWidget) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(12, 12, 12, 12)
        l.addWidget(widget)
        return w

    # =========================================================
    # DRAG & DROP
    # =========================================================
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls and urls[0].toLocalFile().lower().endswith('.eml'):
                event.acceptProposedAction()
                self.status_label.setText("Drop to open EML file...")
                return
        event.ignore()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if path.lower().endswith('.eml'):
                self._load_eml(path)
        self.status_label.setText("")

    # =========================================================
    # RECENT FILES
    # =========================================================
    def _load_recent_files(self):
        self.recent_files = []
        if RECENT_FILES_PATH.exists():
            try:
                self.recent_files = json.loads(RECENT_FILES_PATH.read_text())[:MAX_RECENT]
            except:
                pass
        self._update_recent_menu()

    def _add_recent_file(self, path: str):
        if path in self.recent_files:
            self.recent_files.remove(path)
        self.recent_files.insert(0, path)
        self.recent_files = self.recent_files[:MAX_RECENT]
        
        SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
        RECENT_FILES_PATH.write_text(json.dumps(self.recent_files))
        self._update_recent_menu()

    def _update_recent_menu(self):
        self.recent_menu.clear()
        for f in self.recent_files:
            name = Path(f).name
            self.recent_menu.addAction(name, lambda p=f: self._load_eml(p))

    # =========================================================
    # THEME TOGGLE
    # =========================================================
    def toggle_theme(self):
        self.is_dark_theme = not self.is_dark_theme
        app = QApplication.instance()
        
        if self.is_dark_theme:
            from ui.styles import apply_dark_theme
            apply_dark_theme(app)
            self.btn_theme.setText("🌙 Dark")
        else:
            # Light theme
            app.setStyleSheet("")
            palette = QPalette()
            palette.setColor(QPalette.Window, QColor(245, 245, 245))
            palette.setColor(QPalette.WindowText, QColor(30, 30, 30))
            palette.setColor(QPalette.Base, QColor(255, 255, 255))
            palette.setColor(QPalette.Text, QColor(30, 30, 30))
            palette.setColor(QPalette.Button, QColor(230, 230, 230))
            palette.setColor(QPalette.ButtonText, QColor(30, 30, 30))
            app.setPalette(palette)
            self.btn_theme.setText("☀️ Light")

    # =========================================================
    # OPEN / LOAD EML
    # =========================================================
    def open_eml(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open .eml file", str(Path.home()),
            "EML files (*.eml);;All files (*.*)",
        )
        if file_path:
            self._load_eml(file_path)

    def _load_eml(self, file_path: str) -> None:
        try:
            self.current_eml = Path(file_path)
            self.status_label.setText(f"Loading: {self.current_eml.name}...")
            
            try:
                parsed = parse_eml(self.current_eml)
                self.current_parsed = parsed
            except Exception as e:
                QMessageBox.warning(self, "Parse Error", str(e))
                return

            self._add_recent_file(file_path)

            # Headers
            header_block = (
                f"Path: {parsed.path}\n"
                f"From: {parsed.from_}\n"
                f"To: {parsed.to}\n"
                f"Date: {parsed.date}\n"
                f"Subject: {parsed.subject}\n\n"
                "==== RAW HEADERS ====\n"
                f"{parsed.headers_raw}\n"
            )
            self.headers_view.setPlainText(header_block)

            # Body
            if not parsed.text_body.strip() and not parsed.html_body.strip():
                self.body_text_view.setPlainText("(No text body)")
                self.body_html_view.setHtml("<i>(No HTML body)</i>")
            else:
                self.body_text_view.setPlainText(parsed.text_body)
                self.body_html_view.setHtml(parsed.html_body or "<i>(No HTML)</i>")

            # Security Analysis
            auth_results = parse_authentication_results(parsed.headers)
            self.current_auth_results = auth_results
            self._fill_security_table(auth_results)

            # IOCs
            iocs = extract_iocs(parsed)
            self.current_iocs = iocs
            self.iocs_view.setPlainText(iocs_to_json(iocs))

            # URLs with analysis
            extracted = extract_all_urls(parsed.text_body, parsed.html_body)
            self.last_urls = [u.url for u in extracted]
            url_analysis = analyze_urls(self.last_urls)
            self.current_url_analysis = url_analysis
            self._fill_urls_table(url_analysis)

            # Screenshots
            self._fill_ss_table(self.last_urls)

            # Attachments
            self._fill_attachments_table(parsed.attachments)

            # Reputation
            self.rep_view.clear()
            domains = self._domains_from_urls(self.last_urls)
            if domains:
                self.start_reputation(domains)

            self.status_label.setText(f"Loaded: {self.current_eml.name}")
            QMessageBox.information(self, "Loaded", f"Successfully loaded:\n{self.current_eml.name}")

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # =========================================================
    # TABLE FILLERS
    # =========================================================
    def _fill_security_table(self, results):
        self.security_table.setRowCount(0)
        for ar in results:
            row = self.security_table.rowCount()
            self.security_table.insertRow(row)
            self.security_table.setItem(row, 0, QTableWidgetItem(ar.mechanism))
            
            result_item = QTableWidgetItem(ar.result.upper())
            if ar.result == "pass":
                result_item.setForeground(Qt.green)
            else:
                result_item.setForeground(Qt.red)
            self.security_table.setItem(row, 1, result_item)
            self.security_table.setItem(row, 2, QTableWidgetItem(ar.details))

    def _fill_urls_table(self, analysis):
        self.urls_table.setRowCount(0)
        for ua in analysis:
            row = self.urls_table.rowCount()
            self.urls_table.insertRow(row)
            self.urls_table.setItem(row, 0, QTableWidgetItem(ua['original']))
            self.urls_table.setItem(row, 1, QTableWidgetItem(ua['final']))
            obf = "⚠️ Yes" if ua['is_obfuscated'] else "No"
            self.urls_table.setItem(row, 2, QTableWidgetItem(obf))

    def _fill_ss_table(self, urls: list[str]) -> None:
        self.ss_table.setRowCount(0)
        unique = sorted(set(urls))
        for u in unique:
            row = self.ss_table.rowCount()
            self.ss_table.insertRow(row)
            self.ss_table.setItem(row, 0, QTableWidgetItem(u))
            self.ss_table.setItem(row, 1, QTableWidgetItem("Pending"))
            btn = QPushButton("Capture")
            btn.setStyleSheet("background-color: #2a82da; color: white;")
            btn.clicked.connect(lambda checked=False, r=row, url=u: self.capture_single(r, url))
            self.ss_table.setCellWidget(row, 2, btn)

    def _fill_attachments_table(self, attachments):
        self.atts_table.setRowCount(0)
        self.current_attachments = attachments
        for i, att in enumerate(attachments):
            row = self.atts_table.rowCount()
            self.atts_table.insertRow(row)
            self.atts_table.setItem(row, 0, QTableWidgetItem(att.filename))
            self.atts_table.setItem(row, 1, QTableWidgetItem(att.content_type))
            self.atts_table.setItem(row, 2, QTableWidgetItem(f"{att.size_bytes/1024:.1f} KB"))
            btn = QPushButton("Save")
            btn.setStyleSheet("background-color: #2a82da; color: white;")
            btn.clicked.connect(lambda checked=False, idx=i: self.save_attachment(idx))
            self.atts_table.setCellWidget(row, 3, btn)

    def _domains_from_urls(self, urls):
        out, seen = [], set()
        for u in urls:
            try:
                ext = tldextract.extract(u)
                if ext.domain and ext.suffix:
                    d = f"{ext.domain}.{ext.suffix}".lower()
                    if d not in seen:
                        seen.add(d)
                        out.append(d)
            except:
                pass
        return out

    # =========================================================
    # ACTIONS
    # =========================================================
    def copy_iocs(self):
        text = self.iocs_view.toPlainText()
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "Copied", "IOCs copied to clipboard!")

    def export_report(self):
        if not self.current_parsed:
            QMessageBox.warning(self, "No Data", "Open an EML file first.")
            return
        
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", "report.html", "HTML Files (*.html)"
        )
        if save_path:
            generate_html_report(
                self.current_parsed,
                self.current_auth_results,
                self.current_iocs,
                self.current_url_analysis,
                Path(save_path)
            )
            QMessageBox.information(self, "Saved", f"Report saved to:\n{save_path}")
            # Open in browser
            import webbrowser
            webbrowser.open(f"file://{save_path}")

    def save_attachment(self, idx: int):
        if idx >= len(self.current_attachments):
            return
        att = self.current_attachments[idx]
        fname = "".join(c for c in att.filename if c.isalnum() or c in "._- ")
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Attachment", fname, "All Files (*.*)")
        if save_path:
            try:
                Path(save_path).write_bytes(att.payload)
                QMessageBox.information(self, "Saved", f"Saved to:\n{save_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    # =========================================================
    # REPUTATION
    # =========================================================
    def start_reputation(self, domains):
        if self._rep_thread:
            self.rep_view.appendPlainText("[!] Already running.")
            return
        self.rep_view.setPlainText(f"Checking {len(domains)} domains...\n")
        self.btn_cancel_rep.setEnabled(True)
        self._rep_thread = QThread()
        self._rep_worker = ReputationWorker(domains)
        self._rep_worker.moveToThread(self._rep_thread)
        self._rep_thread.started.connect(self._rep_worker.run)
        self._rep_worker.finished.connect(self._on_rep_finished)
        self._rep_worker.failed.connect(self._on_rep_failed)
        self._rep_worker.finished.connect(self._rep_thread.quit)
        self._rep_worker.failed.connect(self._rep_thread.quit)
        self._rep_thread.finished.connect(self._cleanup_rep)
        self._rep_thread.start()

    @Slot(str)
    def _on_rep_finished(self, text):
        self.rep_view.setPlainText(text)

    @Slot(str)
    def _on_rep_failed(self, err):
        self.rep_view.appendPlainText(f"[FAIL] {err}")

    def cancel_reputation(self):
        if self._rep_worker:
            self._rep_worker.cancel()

    def _cleanup_rep(self):
        self.btn_cancel_rep.setEnabled(False)
        self._rep_thread = None
        self._rep_worker = None

    # =========================================================
    # SCREENSHOTS
    # =========================================================
    def capture_single(self, row, url):
        if row in self._active_captures or not self.current_eml:
            return
        btn = self.ss_table.cellWidget(row, 2)
        if btn:
            btn.setEnabled(False)
            btn.setText("Wait...")
        self.ss_table.item(row, 1).setText("Capturing...")
        domain = get_domain_from_url(url)
        fname = url_to_safe_filename(url)
        out_path = Path("evidence") / self.current_eml.stem / "screenshots" / domain / fname
        thread = QThread()
        worker = SingleScreenshotWorker(url, out_path)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(lambda s, m, p: self._on_ss_done(row, s, m, p))
        worker.finished.connect(thread.quit)
        thread.finished.connect(lambda: self._active_captures.pop(row, None))
        self._active_captures[row] = (thread, worker)
        thread.start()

    def _on_ss_done(self, row, success, msg, path):
        item = self.ss_table.item(row, 1)
        btn = self.ss_table.cellWidget(row, 2)
        if success:
            item.setText("Captured!")
            item.setForeground(Qt.green)
            if btn:
                btn.setText("Open")
                btn.setEnabled(True)
                try:
                    btn.clicked.disconnect()
                except:
                    pass
                btn.clicked.connect(lambda: self._open_file(path))
        else:
            item.setText("Error")
            item.setForeground(Qt.red)
            item.setToolTip(msg)
            if btn:
                btn.setText("Retry")
                btn.setEnabled(True)

    def _open_file(self, path_str):
        p = Path(path_str)
        if not p.exists():
            QMessageBox.warning(self, "Not Found", str(path_str))
            return
        if platform.system() == 'Darwin':
            subprocess.call(('open', path_str))
        elif platform.system() == 'Windows':
            os.startfile(path_str)
        else:
            subprocess.call(('xdg-open', path_str))
