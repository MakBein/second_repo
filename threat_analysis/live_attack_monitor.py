"""Thread-safe dispatcher for Threat Intel live events."""

from __future__ import annotations

import logging
import queue
import threading
from typing import Any, Callable

from xss_security_gui.threat_analysis.threat_connector import LIVE_MONITOR_QUEUE

_logger = logging.getLogger(__name__)


class AttackStreamProcessor:
    """Forward connector events to the GUI callback without blocking Tk."""

    def __init__(
        self,
        ui,
        gui_callback: Callable[[dict[str, Any]], None],
        *,
        event_queue: queue.Queue | None = None,
        poll_interval: float = 0.25,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError("poll_interval must be greater than zero")
        self.ui = ui
        self.gui_callback = gui_callback
        self.event_queue = event_queue if event_queue is not None else LIVE_MONITOR_QUEUE
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="AttackStreamProcessor",
            daemon=True,
        )
        self._thread.start()

    @property
    def is_running(self) -> bool:
        return self._thread.is_alive() and not self._stop_event.is_set()

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                raw_event = self.event_queue.get(timeout=self.poll_interval)
            except queue.Empty:
                continue

            if not isinstance(raw_event, dict):
                _logger.warning(
                    "Ignoring invalid live event of type %s",
                    type(raw_event).__name__,
                )
                continue

            result = raw_event.get("data")
            if not isinstance(result, dict):
                result = {}
            event = {
                **raw_event,
                "data": result,
                "module": raw_event.get("module", "unknown"),
                "target": raw_event.get("target", "—"),
                "severity": raw_event.get("severity", result.get("severity", "info")),
                "category": raw_event.get("category", result.get("category", "")),
            }
            try:
                self.ui.post_ui(self.gui_callback, event)
            except Exception:
                if not self._stop_event.is_set():
                    _logger.exception("Could not dispatch live event to GUI")

    def stop(self, wait: bool = False, timeout: float | None = None) -> None:
        """Stop consuming events; optionally wait a bounded time for the worker."""
        self._stop_event.set()
        if wait and self._thread is not threading.current_thread():
            self._thread.join(timeout=timeout)
