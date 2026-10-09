"""Launcher kept for backwards compatibility: `python main.py [file.eml]` opens the GUI,
`python main.py analyze file.eml` runs headless. Same as `python -m emailicioso`."""

from emailicioso.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
