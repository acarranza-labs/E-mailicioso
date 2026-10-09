"""Design tokens and Qt stylesheet for the dark and light themes."""

from __future__ import annotations

from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication

from emailicioso.core.models import Severity

THEMES: dict[str, dict[str, str]] = {
    "dark": {
        "bg": "#0e1116",
        "surface": "#151a21",
        "surface2": "#1b212a",
        "surface3": "#232a35",
        "border": "#283040",
        "text": "#e6e9ef",
        "muted": "#8b95a7",
        "faint": "#5d6778",
        "accent": "#4c8dff",
        "accent_hover": "#6aa2ff",
        "accent_text": "#ffffff",
        "selection": "#24406e",
        "ok": "#3fb37f",
        "code_bg": "#11151b",
    },
    "light": {
        "bg": "#f3f5f8",
        "surface": "#ffffff",
        "surface2": "#f1f3f6",
        "surface3": "#e7ebf0",
        "border": "#dce1e8",
        "text": "#1b2230",
        "muted": "#5f6b7d",
        "faint": "#97a1b0",
        "accent": "#2563eb",
        "accent_hover": "#1d4ed8",
        "accent_text": "#ffffff",
        "selection": "#d8e5ff",
        "ok": "#16834f",
        "code_bg": "#f6f8fa",
    },
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "#e5484d",
    Severity.HIGH: "#f76b15",
    Severity.MEDIUM: "#e2a336",
    Severity.LOW: "#3e8ef7",
    Severity.INFO: "#8b95a7",
}

VERDICT_COLORS = {
    "malicious": SEVERITY_COLORS[Severity.CRITICAL],
    "suspicious": SEVERITY_COLORS[Severity.MEDIUM],
    "clean": "#3fb37f",
    "unknown": "#8b95a7",
    "error": "#8b95a7",
}

AUTH_COLORS = {"pass": "#3fb37f", "bestguesspass": "#3fb37f", "fail": "#e5484d", "permerror": "#e5484d",
               "softfail": "#e2a336", "neutral": "#8b95a7", "none": "#8b95a7", "temperror": "#8b95a7"}

MONO_FAMILIES = ["Cascadia Mono", "Cascadia Code", "JetBrains Mono", "Consolas", "SF Mono", "Menlo",
                 "DejaVu Sans Mono", "monospace"]
UI_FAMILIES = ["Segoe UI Variable Text", "Segoe UI", "Inter", "SF Pro Text", "Helvetica Neue", "Ubuntu",
               "Noto Sans", "DejaVu Sans", "sans-serif"]

_current = "dark"


def current() -> dict[str, str]:
    return THEMES[_current]


def current_name() -> str:
    return _current


def mono_font(size: int = 10) -> QFont:
    f = QFont()
    f.setFamilies(MONO_FAMILIES)
    f.setStyleHint(QFont.StyleHint.Monospace)
    f.setPointSize(size)
    return f


def severity_color(sev: Severity) -> QColor:
    return QColor(SEVERITY_COLORS[sev])


def _qss(t: dict[str, str]) -> str:
    return f"""
* {{ outline: 0; }}
QWidget {{ color: {t['text']}; font-size: 10pt; }}
QMainWindow, QDialog, QWidget#Page, QStackedWidget, QScrollArea, QScrollArea > QWidget > QWidget {{ background: {t['bg']}; }}
QToolTip {{ background: {t['surface3']}; color: {t['text']}; border: 1px solid {t['border']}; padding: 6px 8px; border-radius: 6px; }}

QFrame#Card {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 10px; }}
QFrame#Banner {{ background: {t['surface2']}; border: 1px solid {t['border']}; border-radius: 8px; }}
QFrame#DropZone {{ background: {t['surface']}; border: 2px dashed {t['border']}; border-radius: 16px; }}
QFrame#DropZone[hover="true"] {{ border-color: {t['accent']}; background: {t['surface2']}; }}
QFrame#TopBar {{ background: {t['surface']}; border-bottom: 1px solid {t['border']}; }}
QLabel {{ background: transparent; }}
QLabel#Muted, QLabel[muted="true"] {{ color: {t['muted']}; }}
QLabel#H1 {{ font-size: 17pt; font-weight: 700; }}
QLabel#H2 {{ font-size: 12pt; font-weight: 600; }}
QLabel#SectionTitle {{ color: {t['muted']}; font-size: 8.5pt; font-weight: 700; letter-spacing: 1px; }}
QLabel#Brand {{ font-size: 12.5pt; font-weight: 800; }}

QPushButton, QToolButton {{
    background: {t['surface2']}; border: 1px solid {t['border']}; border-radius: 7px;
    padding: 6px 13px; color: {t['text']};
}}
QPushButton:hover, QToolButton:hover {{ background: {t['surface3']}; }}
QPushButton:pressed, QToolButton:pressed {{ background: {t['border']}; }}
QPushButton:disabled, QToolButton:disabled {{ color: {t['faint']}; background: {t['surface']}; }}
QPushButton[primary="true"] {{ background: {t['accent']}; border-color: {t['accent']}; color: {t['accent_text']}; font-weight: 600; }}
QPushButton[primary="true"]:hover {{ background: {t['accent_hover']}; border-color: {t['accent_hover']}; }}
QPushButton[flat="true"], QToolButton[flat="true"] {{ background: transparent; border-color: transparent; }}
QPushButton[flat="true"]:hover, QToolButton[flat="true"]:hover {{ background: {t['surface2']}; border-color: {t['border']}; }}
QToolButton::menu-indicator {{ image: none; width: 0; }}
QPushButton::menu-indicator {{ subcontrol-position: right center; right: 6px; }}

QLineEdit, QComboBox, QSpinBox {{
    background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 7px; padding: 5px 9px;
    selection-background-color: {t['selection']};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-color: {t['accent']}; }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{ background: {t['surface']}; border: 1px solid {t['border']}; selection-background-color: {t['selection']}; }}
QCheckBox {{ spacing: 7px; background: transparent; }}
QCheckBox::indicator {{ width: 15px; height: 15px; border: 1px solid {t['border']}; border-radius: 4px; background: {t['surface']}; }}
QCheckBox::indicator:checked {{ background: {t['accent']}; border-color: {t['accent']}; }}

QTabWidget::pane {{ border: none; background: transparent; }}
QTabBar {{ background: transparent; qproperty-drawBase: 0; }}
QTabBar::tab {{
    background: transparent; color: {t['muted']}; padding: 9px 14px 8px; margin-right: 2px;
    border: none; border-bottom: 2px solid transparent; font-weight: 600;
}}
QTabBar::tab:hover {{ color: {t['text']}; }}
QTabBar::tab:selected {{ color: {t['text']}; border-bottom: 2px solid {t['accent']}; }}
QTabWidget#SubTabs QTabBar::tab {{ padding: 6px 12px; font-weight: 500; }}

QTableView, QTreeView, QListView, QListWidget, QTreeWidget {{
    background: {t['surface']}; alternate-background-color: {t['surface2']};
    border: 1px solid {t['border']}; border-radius: 8px; gridline-color: transparent;
    selection-background-color: {t['selection']}; selection-color: {t['text']};
}}
QTableView::item, QTreeView::item, QListView::item {{ padding: 4px 6px; border: none; }}
QListWidget::item {{ padding: 8px 10px; border-radius: 6px; }}
QListWidget::item:selected {{ background: {t['selection']}; }}
QHeaderView {{ background: transparent; }}
QHeaderView::section {{
    background: {t['surface']}; color: {t['muted']}; border: none; border-bottom: 1px solid {t['border']};
    padding: 7px 8px; font-weight: 700; font-size: 8.5pt;
}}
QTableCornerButton::section {{ background: {t['surface']}; border: none; }}

QPlainTextEdit, QTextEdit, QTextBrowser {{
    background: {t['code_bg']}; border: 1px solid {t['border']}; border-radius: 8px; padding: 6px;
    selection-background-color: {t['selection']};
}}
QTextBrowser#Rendered {{ background: #ffffff; color: #1b2230; }}

QScrollBar:vertical {{ background: transparent; width: 11px; margin: 2px; }}
QScrollBar:horizontal {{ background: transparent; height: 11px; margin: 2px; }}
QScrollBar::handle {{ background: {t['border']}; border-radius: 4px; min-height: 28px; min-width: 28px; }}
QScrollBar::handle:hover {{ background: {t['faint']}; }}
QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {{ background: none; border: none; width: 0; height: 0; }}

QMenuBar {{ background: {t['surface']}; border-bottom: 1px solid {t['border']}; }}
QMenuBar::item {{ padding: 5px 10px; background: transparent; }}
QMenuBar::item:selected {{ background: {t['surface2']}; border-radius: 5px; }}
QMenu {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 8px; padding: 5px; }}
QMenu::item {{ padding: 6px 22px 6px 12px; border-radius: 5px; }}
QMenu::item:selected {{ background: {t['selection']}; }}
QMenu::item:disabled {{ color: {t['faint']}; }}
QMenu::separator {{ height: 1px; background: {t['border']}; margin: 4px 6px; }}

QStatusBar {{ background: {t['surface']}; border-top: 1px solid {t['border']}; color: {t['muted']}; }}
QStatusBar::item {{ border: none; }}
QProgressBar {{ background: {t['surface2']}; border: none; border-radius: 3px; max-height: 6px; }}
QProgressBar::chunk {{ background: {t['accent']}; border-radius: 3px; }}
QSplitter::handle {{ background: transparent; }}
QSplitter::handle:hover {{ background: {t['border']}; }}
QGroupBox {{ border: 1px solid {t['border']}; border-radius: 8px; margin-top: 14px; padding: 12px 10px 10px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; color: {t['muted']}; font-weight: 700; }}
"""


def apply(app: QApplication, name: str = "dark") -> None:
    global _current
    _current = name if name in THEMES else "dark"
    t = THEMES[_current]
    app.setStyle("Fusion")
    font = QFont()
    font.setFamilies(UI_FAMILIES)
    font.setPointSize(10)
    app.setFont(font)

    pal = QPalette()
    roles = {
        QPalette.ColorRole.Window: t["bg"],
        QPalette.ColorRole.WindowText: t["text"],
        QPalette.ColorRole.Base: t["surface"],
        QPalette.ColorRole.AlternateBase: t["surface2"],
        QPalette.ColorRole.Text: t["text"],
        QPalette.ColorRole.Button: t["surface2"],
        QPalette.ColorRole.ButtonText: t["text"],
        QPalette.ColorRole.Highlight: t["selection"],
        QPalette.ColorRole.HighlightedText: t["text"],
        QPalette.ColorRole.ToolTipBase: t["surface3"],
        QPalette.ColorRole.ToolTipText: t["text"],
        QPalette.ColorRole.PlaceholderText: t["faint"],
        QPalette.ColorRole.Link: t["accent"],
    }
    for role, color in roles.items():
        pal.setColor(role, QColor(color))
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(t["faint"]))
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(t["faint"]))
    app.setPalette(pal)
    app.setStyleSheet(_qss(t))
