from PySide6.QtGui import QColor, QPalette

def apply_dark_theme(app):
    """Applies a modern dark theme to the Qt Application."""
    app.setStyle("Fusion")
    
    dark_palette = QPalette()
    
    # Colors
    white = QColor(255, 255, 255)
    black = QColor(0, 0, 0)
    red = QColor(255, 0, 0)
    
    dark_bg = QColor(30, 30, 30)         # Fondo principal
    darker_bg = QColor(25, 25, 25)       # Fondo inputs/listas
    light_text = QColor(220, 220, 220)   # Texto principal
    disabled_text = QColor(127, 127, 127)
    
    accent = QColor(42, 130, 218)        # Azul "premium"
    accent_light = QColor(60, 150, 240)
    
    # Palette setup
    dark_palette.setColor(QPalette.Window, dark_bg)
    dark_palette.setColor(QPalette.WindowText, light_text)
    dark_palette.setColor(QPalette.Base, darker_bg)
    dark_palette.setColor(QPalette.AlternateBase, dark_bg)
    dark_palette.setColor(QPalette.ToolTipBase, white)
    dark_palette.setColor(QPalette.ToolTipText, white)
    dark_palette.setColor(QPalette.Text, light_text)
    dark_palette.setColor(QPalette.Button, dark_bg)
    dark_palette.setColor(QPalette.ButtonText, light_text)
    dark_palette.setColor(QPalette.BrightText, red)
    dark_palette.setColor(QPalette.Link, accent_light)
    dark_palette.setColor(QPalette.Highlight, accent)
    dark_palette.setColor(QPalette.HighlightedText, white)
    dark_palette.setColor(QPalette.Disabled, QPalette.Text, disabled_text)
    dark_palette.setColor(QPalette.Disabled, QPalette.ButtonText, disabled_text)

    app.setPalette(dark_palette)

    # StyleSheet extra para controles específicos
    app.setStyleSheet("""
        QToolTip { 
            color: #ffffff; 
            background-color: #2a82da; 
            border: 1px solid white; 
        }
        QMainWindow {
            background-color: #1e1e1e;
        }
        QTabWidget::pane {
            border: 1px solid #3c3c3c;
            background: #1e1e1e;
        }
        QTabBar::tab {
            background: #2d2d2d;
            color: #aaaaaa;
            padding: 8px 20px;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background: #3c3c3c;
            color: #ffffff;
            border-bottom: 2px solid #2a82da;
        }
        QTabBar::tab:hover {
            background: #333333;
            color: #ffffff;
        }
        QPushButton {
            background-color: #2a82da;
            color: white;
            border-radius: 4px;
            padding: 6px 16px;
            font-weight: bold;
            border: none;
        }
        QPushButton:hover {
            background-color: #3c96f0;
        }
        QPushButton:pressed {
            background-color: #1e60a0;
        }
        QPushButton:disabled {
            background-color: #333333;
            color: #777777;
        }
        QPlainTextEdit, QTextBrowser, QTableWidget {
            background-color: #252525;
            border: 1px solid #3c3c3c;
            border-radius: 4px;
            color: #eeeeee;
        }
        QHeaderView::section {
            background-color: #2d2d2d;
            padding: 4px;
            border: 1px solid #3c3c3c;
            color: #dddddd;
        }
    """)
