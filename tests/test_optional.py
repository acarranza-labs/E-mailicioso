"""Tests for optional features: QR decoding, reputation plumbing (offline), settings, GUI smoke test."""

import io
import os

import pytest

from conftest import DEMO, build_email
from emailicioso.core.analyzer import analyze_bytes


def test_qr_code_in_image_attachment():
    pytest.importorskip("cv2")
    qrcode = pytest.importorskip("qrcode")
    buf = io.BytesIO()
    qrcode.make("https://mfa-check.example-login.top/reset").save(buf, format="PNG")
    raw = build_email(text="Scan the code to keep your account",
                      attachments=[("scan.png", buf.getvalue(), "image/png")])
    r = analyze_bytes(raw)
    qr_urls = [u for u in r.urls if u.source.startswith("qr:")]
    assert qr_urls and qr_urls[0].url == "https://mfa-check.example-login.top/reset"
    assert "Link hidden in a QR code (quishing)" in {f.title for f in r.findings}


def test_reputation_runner_uses_cache(tmp_path):
    from emailicioso.core.cache import ReputationCache
    from emailicioso.core.reputation import run_checks
    from emailicioso.core.reputation.base import Provider, RepResult

    calls = []

    class Fake(Provider):
        name = "Fake"
        kinds = ("domain",)
        needs_key = False

        def check(self, indicator, kind, should_stop=lambda: False):
            calls.append(indicator)
            return RepResult(self.name, indicator, kind, "malicious", "5/90")

    cache = ReputationCache(tmp_path / "c.db")
    first = list(run_checks([("evil.example", "domain"), ("1.2.3.4", "ip")], [Fake()], cache))
    second = list(run_checks([("evil.example", "domain")], [Fake()], cache))
    assert [r.verdict for r in first] == ["malicious"]
    assert second[0].cached and calls == ["evil.example"]


def test_virustotal_url_id():
    from emailicioso.core.reputation.virustotal import url_id

    assert url_id("http://example.com/") == "aHR0cDovL2V4YW1wbGUuY29tLw"


def test_settings_roundtrip_and_env_key(monkeypatch):
    from emailicioso.core.settings import Settings

    s = Settings.load()
    s.theme = "light"
    s.add_recent("/tmp/a.eml")
    s.save()
    again = Settings.load()
    assert again.theme == "light" and again.recent_files[0] == "/tmp/a.eml"
    monkeypatch.setenv("VT_API_KEY", "abc")
    assert Settings().api_key("virustotal_api_key") == "abc"


def test_gui_smoke():
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QEventLoop, QTimer
    from PySide6.QtWidgets import QApplication

    from emailicioso.core.settings import Settings
    from emailicioso.ui import theme
    from emailicioso.ui.main_window import MainWindow

    app = QApplication.instance() or QApplication([])
    theme.apply(app, "dark")
    win = MainWindow(Settings())
    win.show()
    loop = QEventLoop()
    win.load_path(DEMO)
    deadline = QTimer()
    deadline.setSingleShot(True)
    deadline.timeout.connect(loop.quit)
    deadline.start(20000)
    poll = QTimer()
    poll.timeout.connect(lambda: loop.quit() if win.result is not None else None)
    poll.start(50)
    loop.exec()
    assert win.result is not None
    assert win.stack.currentIndex() == 1
    assert win.tabs.tabText(0).startswith("Overview")
    assert win.t_urls.table.model.rowCount() == len(win.result.urls)
    win.toggle_theme()
    assert theme.current_name() == "light"
    win.close()
