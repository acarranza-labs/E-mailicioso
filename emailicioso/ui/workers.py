"""Background jobs so the window never freezes (parsing, reputation lookups, screenshots)."""

from __future__ import annotations

import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal, Slot


class Job(QObject):
    """Runs ``fn(job)`` in a worker thread. ``fn`` may call ``job.emit_progress(obj)``."""

    progress = Signal(object)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, fn: Callable[[Job], Any]) -> None:
        super().__init__()
        self._fn = fn
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def emit_progress(self, obj: Any) -> None:
        self.progress.emit(obj)

    @Slot()
    def run(self) -> None:
        try:
            result = self._fn(self)
        except Exception as exc:
            detail = "".join(traceback.format_exception_only(type(exc), exc)).strip()
            self.failed.emit(detail if str(exc) else f"{type(exc).__name__}\n{traceback.format_exc(limit=3)}")
            return
        self.finished.emit(result)


class _Relay(QObject):
    """Lives in the GUI thread so callbacks never run inside the worker thread.

    (Connecting a cross-thread signal to a plain Python function would call it in the
    emitting thread; connecting it to a slot of a GUI-thread QObject queues it instead.)
    """

    def __init__(self, on_done, on_error, on_progress, parent: QObject) -> None:
        super().__init__(parent)
        self._done, self._error, self._progress = on_done, on_error, on_progress
        self.on_cleanup: Callable[[], None] | None = None

    @Slot(object)
    def done(self, obj: Any) -> None:
        if self._done:
            self._done(obj)

    @Slot(str)
    def error(self, msg: str) -> None:
        if self._error:
            self._error(msg)

    @Slot(object)
    def progress(self, obj: Any) -> None:
        if self._progress:
            self._progress(obj)

    @Slot()
    def cleanup(self) -> None:
        if self.on_cleanup:
            self.on_cleanup()
        self.deleteLater()


class JobRunner(QObject):
    """Keeps references to running threads/jobs and cleans them up."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._running: set[tuple[QThread, Job]] = set()

    def start(
        self,
        fn: Callable[[Job], Any],
        on_done: Callable[[Any], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        on_progress: Callable[[Any], None] | None = None,
    ) -> Job:
        thread = QThread()
        job = Job(fn)
        job.moveToThread(thread)
        thread.started.connect(job.run)
        relay = _Relay(on_done, on_error, on_progress, self)
        job.finished.connect(relay.done)
        job.failed.connect(relay.error)
        job.progress.connect(relay.progress)
        job.finished.connect(thread.quit)
        job.failed.connect(thread.quit)
        entry = (thread, job)
        self._running.add(entry)
        relay.on_cleanup = lambda: self._running.discard(entry)
        thread.finished.connect(relay.cleanup)
        thread.finished.connect(thread.deleteLater)
        thread.start()
        return job

    def cancel_all(self) -> None:
        for _thread, job in list(self._running):
            job.cancel()

    def wait_all(self, ms: int = 3000) -> None:
        for thread, _job in list(self._running):
            thread.quit()
            thread.wait(ms)


def analysis_job(path: Path | None, raw: bytes | None, lookback: str) -> Callable[[Job], Any]:
    def run(_job: Job) -> Any:
        from emailicioso.core.analyzer import analyze_bytes, analyze_file

        if raw is not None:
            return analyze_bytes(raw, path, lookback)
        return analyze_file(path, lookback)  # type: ignore[arg-type]

    return run
