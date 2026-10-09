"""GUI bootstrap."""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from emailicioso import APP_NAME, __version__
from emailicioso.core.settings import Settings
from emailicioso.ui import theme
from emailicioso.ui.main_window import MainWindow
from emailicioso.ui.widgets import app_icon


def run(file: str | None = None) -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setOrganizationName("acarranza-labs")
    app.setWindowIcon(app_icon())
    settings = Settings.load()
    theme.apply(app, settings.theme)
    win = MainWindow(settings)
    win.show()
    if file:
        QTimer.singleShot(0, lambda: win.load_path(Path(file)))
    return app.exec()
