# xss_security_gui/utils/ui_queue_bridge.py
# ============================================================
# UIQueueBridge 10.1 — fast, battle-ready, deadlock-free
# ============================================================

import queue
import threading
from typing import Callable, Any


class UIQueueBridge:
    """
    UIQueueBridge 10.1 — міст між worker-потоками і Tk mainloop.

    Особливості:
    • deadlock-free stop() з None-сигналом
    • агресивний drain: до max_calls_per_cycle викликів за тик
    • м’який drop при переповненні черги
    • post_bg з callback у UI-потоці
    """

    def __init__(
        self,
        root,
        poll_ms: int = 25,
        max_queue: int = 10000,
        max_calls_per_cycle: int = 500,
    ):
        self._root = root
        self._poll_ms = max(5, int(poll_ms))
        self._max_queue = max_queue
        self._max_calls = max_calls_per_cycle

        self._q: "queue.Queue[tuple | None]" = queue.Queue()
        self._running = True

        self._root.after(self._poll_ms, self._drain)

    # ---------------------------------------------------------
    # Public API
    # ---------------------------------------------------------

    def stop(self) -> None:
        """Безпечне завершення bridge."""
        self._running = False
        try:
            self._q.put_nowait(None)
        except Exception:
            pass

    def post_ui(self, fn: Callable[..., Any], *args, **kwargs) -> None:
        """Поставити виклик у чергу з worker-потоку."""
        if not self._running:
            return

        try:
            if self._q.qsize() > self._max_queue:
                return  # м’який drop
        except Exception:
            pass

        self._q.put((fn, args, kwargs))

    def call_ui(self, fn: Callable[..., Any], *args, **kwargs) -> None:
        """Викликати fn прямо в UI, якщо ми в main_thread, інакше — через чергу."""
        if threading.current_thread() is threading.main_thread():
            try:
                fn(*args, **kwargs)
            except Exception:
                pass
        else:
            self.post_ui(fn, *args, **kwargs)

    def post_bg(
        self,
        fn: Callable[..., Any],
        callback: Callable[[Any], None] | None = None,
        *args,
        **kwargs,
    ) -> None:
        """Запустити fn у фоні, callback — у UI."""

        def worker():
            try:
                result = fn(*args, **kwargs)
            except Exception as e:
                result = e

            if callback:
                self.post_ui(callback, result)

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    # ---------------------------------------------------------
    # Internal drain
    # ---------------------------------------------------------

    def _drain(self) -> None:
        """Витягнути події з черги і виконати їх у UI-потоці."""
        if not self._running:
            return

        try:
            for _ in range(self._max_calls):
                try:
                    item = self._q.get_nowait()
                except queue.Empty:
                    break

                if item is None:
                    self._running = False
                    break

                fn, args, kwargs = item
                try:
                    fn(*args, **kwargs)
                except Exception:
                    pass
        finally:
            if self._running:
                self._root.after(self._poll_ms, self._drain)




