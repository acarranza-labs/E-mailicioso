from pathlib import Path
from PySide6.QtCore import QObject, Signal, Slot

from core.utils import get_domain_from_url, url_to_safe_filename
from core.reputation.urlvoid_scraper import check_urlvoid
from core.reputation.virustotal_scraper import check_virustotal_domain
from core.screenshots import capture_screenshot

# =========================================================
# Worker: screenshots en background
# =========================================================

class ScreenshotWorker(QObject):
    progress = Signal(str)
    finished = Signal(int, int, str)
    failed = Signal(str)

    def __init__(self, urls: list[str], out_dir_base: Path) -> None:
        super().__init__()
        self.urls = urls
        self.out_dir_base = out_dir_base
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    @Slot()
    def run(self) -> None:
        try:
            self.out_dir_base.mkdir(parents=True, exist_ok=True)
            total = len(self.urls)
            ok = 0

            self.progress.emit(f"Output base dir: {self.out_dir_base}")
            self.progress.emit(f"URLs: {total}\n")

            for url in self.urls:
                if self._cancel:
                    self.progress.emit("\n[!] Cancelado por el usuario.")
                    break

                u = (url or "").strip()
                if not u:
                    continue

                if u.lower().startswith(("mailto:", "tel:", "data:", "javascript:")):
                    self.progress.emit(f"[SKIP] {u} (esquema no navegable)")
                    continue

                domain = get_domain_from_url(u)
                domain_dir = self.out_dir_base / domain
                domain_dir.mkdir(parents=True, exist_ok=True)

                fname = url_to_safe_filename(u)
                out_path = domain_dir / fname

                try:
                    capture_screenshot(u, out_path)
                    ok += 1
                    self.progress.emit(f"[OK]  {u} -> {out_path}")
                except Exception as e:
                    self.progress.emit(f"[ERR] {u} -> {type(e).__name__}: {e}")

            self.finished.emit(ok, total, str(self.out_dir_base))
        except Exception as e:
            self.failed.emit(f"{type(e).__name__}: {e}")


# =========================================================
# Worker: reputation en background (evita congelar UI)
# =========================================================

class ReputationWorker(QObject):
    progress = Signal(str)
    finished = Signal(str)
    failed = Signal(str)

    def __init__(self, domains: list[str]) -> None:
        super().__init__()
        self.domains = domains
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    @Slot()
    def run(self) -> None:
        try:
            lines: list[str] = []
            if not self.domains:
                self.finished.emit("(No domains found)")
                return

            lines.append("Reputation engines: URLVoid + VirusTotal (GUI)\n")

            for d in self.domains:
                if self._cancel:
                    lines.append("\n[!] Cancelado por el usuario.")
                    break

                # URLVoid
                res_uv = check_urlvoid(d)
                lines.append(self._format_rep(res_uv))

                # VirusTotal (GUI)
                res_vt = check_virustotal_domain(d)
                lines.append(self._format_rep(res_vt))

                lines.append("-" * 60)

            self.finished.emit("\n".join(lines))

        except Exception as e:
            self.failed.emit(f"{type(e).__name__}: {e}")

    def _format_rep(self, res) -> str:
        if res.verdict == "error":
            return (
                f"[{res.engine.upper()}] {res.query} -> ERROR\n"
                f"  {res.error}\n"
                f"  {res.url}\n"
            )

        extra = []
        if res.score:
            extra.append(f"Score/Detections: {res.score}")
        if res.details:
            extra.append(res.details)

        extra_txt = ("\n  " + "\n  ".join(extra)) if extra else ""
        return (
            f"[{res.engine.upper()}] {res.query} -> {res.verdict.upper()}\n"
            f"  {res.url}{extra_txt}\n"
        )


class SingleScreenshotWorker(QObject):
    finished = Signal(bool, str, str) # success, message, out_path

    def __init__(self, url: str, out_path: Path) -> None:
        super().__init__()
        self.url = url
        self.out_path = out_path

    @Slot()
    def run(self) -> None:
        try:
            self.out_path.parent.mkdir(parents=True, exist_ok=True)
            capture_screenshot(self.url, self.out_path)
            self.finished.emit(True, "Captured", str(self.out_path))
        except Exception as e:
            self.finished.emit(False, str(e), "")
