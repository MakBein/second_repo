# xss_security_gui/utils/thread_worker.py
"""
ThreadWorker 10.0 — боевое асинхронное ядро XSS Security Suite.
С интеграцией в SecurityDashboardPanel.
"""

from __future__ import annotations

import threading
import queue
import traceback
import time
from typing import Any, Callable, Optional, Dict


class ThreadStatus:
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    DONE = "DONE"
    ERROR = "ERROR"
    CANCELLED = "CANCELLED"


class ThreadWorker:
    def __init__(self, gui_root, dashboard=None, poll_ms: int = 50):
        self.gui_root = gui_root
        self.dashboard = dashboard   # 🔥 Интеграция с SecurityDashboardPanel
        self.poll_ms = poll_ms

        self._event_queue: "queue.Queue[tuple[str, str, Any]]" = queue.Queue()
        self._threads: Dict[str, Dict[str, Any]] = {}
        self._poll_id: Optional[str] = None

    # ------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------
    def run_async(
        self,
        work_fn: Callable[[Callable[[int], None], Callable[[], bool]], Any],
        *,
        name: str = "Worker",
        on_start: Optional[Callable[[], None]] = None,
        on_progress: Optional[Callable[[int], None]] = None,
        on_success: Optional[Callable[[Any], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        on_finally: Optional[Callable[[], None]] = None,
    ) -> threading.Thread:

        info = self._threads.get(name)
        if info and info["status"] == ThreadStatus.RUNNING:
            print(f"[⚠️ {name}] Поток уже выполняется — запуск отменён.")
            return info["thread"]

        self._threads[name] = {
            "thread": None,
            "status": ThreadStatus.RUNNING,
            "error": None,
            "log": [],
            "progress": 0,
            "start_time": time.time(),
            "cancel_flag": False,
            "pause_flag": False,
            "last_heartbeat": time.time(),
            "callbacks": {
                "on_start": on_start,
                "on_progress": on_progress,
                "on_success": on_success,
                "on_error": on_error,
                "on_finally": on_finally,
            },
        }

        # 🔥 Dashboard event: thread started
        self._dashboard_event(name, "started")

        if on_start:
            try:
                on_start()
            except Exception:
                traceback.print_exc()

        def progress_callback(value: int) -> None:
            self._event_queue.put((name, "progress", value))

        def is_cancelled() -> bool:
            return bool(self._threads.get(name, {}).get("cancel_flag"))

        def worker_thread() -> None:
            try:
                result = work_fn(progress_callback, is_cancelled)
                self._event_queue.put((name, "success", result))
            except Exception as exc:
                self._event_queue.put((name, "error", exc))
            finally:
                self._event_queue.put((name, "finally", None))

        thread = threading.Thread(target=worker_thread, name=name, daemon=True)
        self._threads[name]["thread"] = thread
        thread.start()

        self._start_polling()
        return thread

    # ------------------------------------------------------------
    # CONTROL API
    # ------------------------------------------------------------
    def pause(self, name: str) -> None:
        info = self._threads.get(name)
        if info:
            info["pause_flag"] = True
            info["status"] = ThreadStatus.PAUSED
            self._dashboard_event(name, "paused")

    def resume(self, name: str) -> None:
        info = self._threads.get(name)
        if info:
            info["pause_flag"] = False
            info["status"] = ThreadStatus.RUNNING
            self._dashboard_event(name, "resumed")

    def cancel(self, name: str) -> None:
        info = self._threads.get(name)
        if info:
            info["cancel_flag"] = True
            info["status"] = ThreadStatus.CANCELLED
            self._dashboard_event(name, "cancelled")

    # ------------------------------------------------------------
    # STATUS API
    # ------------------------------------------------------------
    def get_thread_status(self, name: str) -> Optional[str]:
        info = self._threads.get(name)
        return info["status"] if info else None

    def get_thread_log(self, name: str) -> Optional[list]:
        info = self._threads.get(name)
        return info["log"] if info else None

    def get_all_threads(self) -> Dict[str, Dict[str, Any]]:
        return self._threads

    # ------------------------------------------------------------
    # INTERNAL
    # ------------------------------------------------------------
    def _start_polling(self) -> None:
        if self._poll_id is not None:
            return

        def poll() -> None:
            try:
                if not self.gui_root.winfo_exists():
                    return

                while not self._event_queue.empty():
                    name, msg_type, msg_data = self._event_queue.get_nowait()
                    info = self._threads.get(name)
                    if not info:
                        continue

                    info["last_heartbeat"] = time.time()
                    cbs = info.get("callbacks", {})

                    if msg_type == "progress":
                        info["progress"] = msg_data
                        self._dashboard_event(name, "progress", msg_data)
                        cb = cbs.get("on_progress")
                        if cb:
                            cb(msg_data)

                    elif msg_type == "success":
                        info["status"] = ThreadStatus.DONE
                        self._dashboard_event(name, "success", msg_data)
                        cb = cbs.get("on_success")
                        if cb:
                            cb(msg_data)

                    elif msg_type == "error":
                        info["status"] = ThreadStatus.ERROR
                        info["error"] = msg_data
                        self._dashboard_event(name, "error", msg_data)
                        cb = cbs.get("on_error")
                        if cb:
                            cb(msg_data)

                    elif msg_type == "finally":
                        self._dashboard_event(name, "finally")
                        cb = cbs.get("on_finally")
                        if cb:
                            cb()

                self._check_watchdog()
                self._dashboard_metrics()
                self._poll_id = self.gui_root.after(self.poll_ms, poll)

            except Exception as e:
                print(f"[ThreadWorker 10.0] Error in polling: {e}")
                traceback.print_exc()

        poll()

    def _check_watchdog(self) -> None:
        now = time.time()
        for name, info in self._threads.items():
            if info["status"] == ThreadStatus.RUNNING:
                if now - info["last_heartbeat"] > 120:
                    info["status"] = ThreadStatus.ERROR
                    info["error"] = TimeoutError(f"Поток {name} завис (>120 сек)")
                    self._dashboard_event(name, "watchdog_error", info["error"])
                    print(f"[⚠️ WATCHDOG] Поток {name} завис и помечен как ERROR")

    # ------------------------------------------------------------
    # DASHBOARD INTEGRATION
    # ------------------------------------------------------------
    def _dashboard_event(self, name: str, event: str, data: Any = None) -> None:
        if not self.dashboard:
            return
        try:
            self.dashboard.update_thread_event(name, event, data)
        except Exception:
            pass

    def _dashboard_metrics(self) -> None:
        if not self.dashboard:
            return
        try:
            metrics = {
                "total": len(self._threads),
                "running": sum(1 for t in self._threads.values() if t["status"] == ThreadStatus.RUNNING),
                "errors": sum(1 for t in self._threads.values() if t["status"] == ThreadStatus.ERROR),
                "done": sum(1 for t in self._threads.values() if t["status"] == ThreadStatus.DONE),
                "cancelled": sum(1 for t in self._threads.values() if t["status"] == ThreadStatus.CANCELLED),
                "avg_runtime": self._compute_avg_runtime(),
            }
            self.dashboard.update_thread_metrics(metrics)
        except Exception:
            pass

    def _compute_avg_runtime(self) -> float:
        times = []
        now = time.time()
        for info in self._threads.values():
            start = info.get("start_time")
            if start:
                times.append(now - start)
        return sum(times) / len(times) if times else 0.0

    # ------------------------------------------------------------
    # GLOBAL STOP
    # ------------------------------------------------------------
    def stop_all(self) -> None:
        if self._poll_id:
            try:
                self.gui_root.after_cancel(self._poll_id)
            except Exception:
                pass
            self._poll_id = None
        self._threads.clear()


# ------------------------------------------------------------
# GLOBAL API
# ------------------------------------------------------------
_global_worker_instance: Optional[ThreadWorker] = None


def init_global_worker(gui_root, dashboard=None) -> ThreadWorker:
    global _global_worker_instance
    _global_worker_instance = ThreadWorker(gui_root, dashboard=dashboard)
    return _global_worker_instance


def get_global_worker() -> Optional[ThreadWorker]:
    return _global_worker_instance


def run_in_thread(
    work_fn: Callable[[Callable[[int], None], Callable[[], bool]], Any],
    *,
    name: str = "Worker",
    on_start: Optional[Callable[[], None]] = None,
    on_progress: Optional[Callable[[int], None]] = None,
    on_success: Optional[Callable[[Any], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
    on_finally: Optional[Callable[[], None]] = None,
) -> Optional[threading.Thread]:
    worker = get_global_worker()
    if not worker:
        print("[⚠️] Global ThreadWorker not initialized. Call init_global_worker() first.")
        return None

    return worker.run_async(
        work_fn,
        name=name,
        on_start=on_start,
        on_progress=on_progress,
        on_success=on_success,
        on_error=on_error,
        on_finally=on_finally,
    )





