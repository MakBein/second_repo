# xss_security_gui/utils/thread_worker.py
"""Global background worker used by GUI + testers."""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Optional

_logger = logging.getLogger(__name__)
_ROOT = None


def init_global_worker(root=None, name: str = "GlobalWorker") -> None:
    global _ROOT
    _ROOT = root
    _logger.debug("Global worker ready (%s)", name)


def run_in_thread(
    fn: Callable[..., Any],
    *args: Any,
    name: str = "Worker",
    on_start: Optional[Callable[[], None]] = None,
    on_progress: Optional[Callable[[Any], None]] = None,
    on_success: Optional[Callable[[Any], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
    on_finally: Optional[Callable[[], None]] = None,
    **kwargs: Any,
) -> threading.Thread:
    def _worker() -> None:
        try:
            if on_start:
                try:
                    on_start()
                except Exception:
                    _logger.debug("on_start failed", exc_info=True)
            result = fn(*args, **kwargs)
            if on_success:
                try:
                    on_success(result)
                except Exception:
                    _logger.debug("on_success failed", exc_info=True)
        except Exception as exc:
            if on_error:
                try:
                    on_error(exc)
                except Exception:
                    _logger.debug("on_error failed", exc_info=True)
            else:
                _logger.exception("Background thread %s failed", name)
        finally:
            if on_finally:
                try:
                    on_finally()
                except Exception:
                    _logger.debug("on_finally failed", exc_info=True)

    thread = threading.Thread(target=_worker, name=name, daemon=True)
    thread.start()
    return thread
