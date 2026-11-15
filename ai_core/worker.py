# ai_core/worker.py (SAFE MODE)

import threading
import queue
from typing import Callable, Dict, Any, Optional, Tuple

from xss_security_gui.settings import (
    AI_SAFE_MODE,
    AI_FALLBACK_ON_ERROR,
)

from xss_security_gui.ai_core.risk_engine import analyze_security_risk


class AIWorker:
    """
    Асинхронний воркер для AI Core 20.0.
    SAFE MODE гарантує, що:
    - GUI ніколи не фрізить
    - помилки AI не валять інтерфейс
    - callback завжди отримує валідний dict
    """

    def __init__(self):
        self._tasks: "queue.Queue[Tuple[str, str, dict]]" = queue.Queue()
        self._results: "queue.Queue[Tuple[str, Dict[str, Any]]]" = queue.Queue()
        self._callbacks: Dict[str, Callable[[Dict[str, Any]], None]] = {}
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._running = False
        self._seq = 0
        self._ui_root = None
        self._poll_ms = 100

    # ------------------------------------------------------------
    #  Запуск воркера
    # ------------------------------------------------------------
    def start(self) -> None:
        if not self._running:
            self._running = True
            self._thread.start()

    # ------------------------------------------------------------
    #  Зупинка воркера
    # ------------------------------------------------------------
    def stop(self) -> None:
        self._running = False
        self._tasks.put(("__STOP__", "STOP", {}))

    # ------------------------------------------------------------
    #  Додавання задачі
    # ------------------------------------------------------------
    def bind_to_tk(self, root, poll_ms: int = 100) -> None:
        """
        Прив'язує воркер до Tk root і запускає polling через root.after().
        """
        self._ui_root = root
        self._poll_ms = max(20, int(poll_ms))
        try:
            self._ui_root.after(self._poll_ms, self._drain_results_ui)
        except Exception:
            pass

    def submit(
        self,
        js_insights: Dict[str, Any],
        raw_js: str,
        callback: Callable[[Dict[str, Any]], None],
    ) -> str:
        """
        Додає задачу в чергу.
        callback — викликається ТІЛЬКИ в GUI-потоці (через after).
        """
        self._seq += 1
        task_id = f"AIW-{self._seq}"
        self._callbacks[task_id] = callback
        self._tasks.put(("ANALYZE", task_id, {"js_insights": js_insights, "raw_js": raw_js}))
        return task_id

    def pump(self, max_items: int = 50) -> int:
        """
        Забирає результати з черги і викликає callbacks.
        Може використовуватись у сторонньому UI-циклі.
        """
        processed = 0
        while processed < max_items:
            try:
                task_id, result = self._results.get_nowait()
            except queue.Empty:
                break
            cb = self._callbacks.pop(task_id, None)
            if cb:
                try:
                    cb(result)
                except Exception as e:
                    print(f"[AI Core] Worker callback failed: {e}")
            processed += 1
        return processed

    def _drain_results_ui(self) -> None:
        try:
            self.pump(100)
        finally:
            if self._running and self._ui_root is not None:
                try:
                    self._ui_root.after(self._poll_ms, self._drain_results_ui)
                except Exception:
                    pass

    # ------------------------------------------------------------
    #  Основний цикл воркера
    # ------------------------------------------------------------
    def _loop(self) -> None:
        while self._running:
            task_type, task_id, payload = self._tasks.get()

            if task_type == "__STOP__":
                break

            if task_type == "ANALYZE":
                try:
                    result = analyze_security_risk(payload["js_insights"], payload["raw_js"])

                except Exception as e:
                    print(f"[AI Core] Worker error: {e}")

                    if AI_SAFE_MODE or AI_FALLBACK_ON_ERROR:
                        result = {
                            "error": f"AI SAFE MODE: {e}",
                            "risk_score": 0.0,
                            "risk_level": "info",
                        }
                    else:
                        raise

                self._results.put((task_id, result))

