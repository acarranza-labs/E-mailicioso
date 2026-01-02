import sys
from PySide6.QtWidgets import QApplication
from ui.main_window import MainWindow
from ui.styles import apply_dark_theme

def main() -> int:
    app = QApplication(sys.argv)
    
    # Apply dark/modern theme
    apply_dark_theme(app)
    
    win = MainWindow()
    win.show()
    
    return app.exec()

if __name__ == "__main__":
    raise SystemExit(main())
