"""Settings dialog: appearance, threat-intel API keys, screenshots/OPSEC."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QLineEdit,
    QMessageBox,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from emailicioso.core.settings import ENV_KEYS, Settings
from emailicioso.ui.widgets import button, hbox, label, toggle


def _form() -> tuple[QWidget, QFormLayout]:
    w = QWidget()
    w.setObjectName("Page")
    f = QFormLayout(w)
    f.setContentsMargins(16, 16, 16, 16)
    f.setHorizontalSpacing(16)
    f.setVerticalSpacing(12)
    f.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    return w, f


def _secret(value: str, placeholder: str) -> QLineEdit:
    e = QLineEdit(value)
    e.setEchoMode(QLineEdit.EchoMode.Password)
    e.setPlaceholderText(placeholder)
    e.setMinimumWidth(360)
    return e


class SettingsDialog(QDialog):
    def __init__(self, settings: Settings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("Settings")
        self.setMinimumWidth(700)
        tabs = QTabWidget()

        # General ------------------------------------------------------------------
        g, gf = _form()
        self.theme = QComboBox()
        self.theme.addItems(["dark", "light"])
        self.theme.setCurrentText(settings.theme)
        self.lang = QComboBox()
        self.lang.addItem("English", "en")
        self.lang.addItem("Español", "es")
        self.lang.setCurrentIndex(0 if settings.summary_language == "en" else 1)
        self.lookback = QComboBox()
        self.lookback.addItems(["1d", "7d", "14d", "30d", "90d", "180d"])
        self.lookback.setCurrentText(settings.hunting_lookback)
        self.defang = toggle("Defang indicators (hxxps://example[.]com)", settings.defang)
        gf.addRow("Theme", self.theme)
        gf.addRow("Ticket summary language", self.lang)
        gf.addRow("KQL lookback", self.lookback)
        gf.addRow("", self.defang)
        tabs.addTab(g, "General")

        # Threat intel -----------------------------------------------------------------
        t, tf = _form()
        self.vt = _secret(settings.virustotal_api_key, "Free key from virustotal.com → API key")
        self.abuse = _secret(settings.abuseipdb_api_key, "Free key from abuseipdb.com → Account → API")
        self.urlscan = _secret(settings.urlscan_api_key, "Optional: raises urlscan.io search limits")
        tf.addRow("VirusTotal API key", self.vt)
        tf.addRow("AbuseIPDB API key", self.abuse)
        tf.addRow("urlscan.io API key", self.urlscan)
        envs = ", ".join(v[0] for v in ENV_KEYS.values())
        tf.addRow("", label(f"Keys can also come from environment variables ({envs}). They are stored in "
                            "plain text in your profile folder.", "Muted", wrap=True))
        self.auto = toggle("Run lookups automatically when an email is opened", settings.auto_reputation)
        self.urlvoid = toggle("Also scrape URLVoid (no key, often blocked)", settings.use_urlvoid_scraper)
        tf.addRow("", self.auto)
        tf.addRow("", label("Off by default: lookups disclose the indicators (and that you are investigating "
                            "them) to third parties.", "Muted", wrap=True))
        tf.addRow("", self.urlvoid)
        self.ttl = QSpinBox()
        self.ttl.setRange(1, 24 * 30)
        self.ttl.setSuffix(" h")
        self.ttl.setValue(settings.cache_ttl_hours)
        tf.addRow("Cache results for", hbox(self.ttl, button("Clear cache", self._clear_cache), None))
        tabs.addTab(t, "Threat intel")

        # Screenshots ----------------------------------------------------------------------
        s, sf = _form()
        self.evidence = QLineEdit(settings.evidence_dir)
        sf.addRow("Evidence folder", hbox(self.evidence, button("Browse…", self._browse)))
        self.proxy = QLineEdit(settings.screenshot_proxy)
        self.proxy.setPlaceholderText("socks5://127.0.0.1:9050  or  http://proxy.example:8080")
        sf.addRow("Proxy for captures", self.proxy)
        self.timeout = QSpinBox()
        self.timeout.setRange(5, 120)
        self.timeout.setSuffix(" s")
        self.timeout.setValue(settings.screenshot_timeout)
        sf.addRow("Page timeout", self.timeout)
        sf.addRow("", label("Screenshots need Playwright: <code>pip install playwright</code> and "
                            "<code>python -m playwright install chromium</code>. Each capture saves a PNG plus a "
                            "JSON with final URL, redirects, HTTP status and the PNG's SHA256.", "Muted", wrap=True))
        tabs.addTab(s, "Screenshots")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.addWidget(tabs)
        lay.addWidget(buttons)

    def _browse(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Evidence folder", self.evidence.text())
        if folder:
            self.evidence.setText(folder)

    def _clear_cache(self) -> None:
        from emailicioso.core.cache import ReputationCache

        n = ReputationCache().clear()
        QMessageBox.information(self, "Cache cleared", f"Removed {n} cached lookups.")

    def _save(self) -> None:
        s = self.settings
        s.theme = self.theme.currentText()
        s.summary_language = self.lang.currentData()
        s.hunting_lookback = self.lookback.currentText()
        s.defang = self.defang.isChecked()
        s.virustotal_api_key = self.vt.text().strip()
        s.abuseipdb_api_key = self.abuse.text().strip()
        s.urlscan_api_key = self.urlscan.text().strip()
        s.auto_reputation = self.auto.isChecked()
        s.use_urlvoid_scraper = self.urlvoid.isChecked()
        s.cache_ttl_hours = self.ttl.value()
        s.evidence_dir = self.evidence.text().strip() or s.evidence_dir
        s.screenshot_proxy = self.proxy.text().strip()
        s.screenshot_timeout = self.timeout.value()
        s.save()
        self.accept()
