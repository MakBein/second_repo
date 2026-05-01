# xss_security_gui/mutator_task_manager.py

from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Any, Callable, Dict, Optional
import uuid
import traceback
import time


class MutatorTaskManager:
    """
    MutatorTaskManager ULTRA (боевой уровень)

    • Уніфікована модель задачі
    • Підтримка модульних задач і мутаторних задач
    • Події lifecycle:
        - on_task_added
        - on_task_started
        - on_task_finished
        - on_task_error
        - on_task_cancelled
    • Метадані задачі:
        - type: "module" / "mutator"
        - payload
        - created_at
        - started_at
        - finished_at
        - duration
    • Потокобезпечний
    • Готовий до сортування, групування, ризик‑аналізу
    """

    def __init__(self, max_workers: int = 6):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.tasks: Dict[str, Future] = {}
        self.meta: Dict[str, Dict[str, Any]] = {}

        # GUI callbacks
        self.on_task_added: Optional[Callable[[str, Any], None]] = None
        self.on_task_started: Optional[Callable[[str, Any], None]] = None
        self.on_task_finished: Optional[Callable[[str, Any], None]] = None
        self.on_task_error: Optional[Callable[[str, Any], None]] = None
        self.on_task_cancelled: Optional[Callable[[str, Any], None]] = None

    # ----------------------------------------------------------------------
    # Submit task
    # ----------------------------------------------------------------------
    def submit(self, fn: Callable, *args, payload: Any = None, task_type: str = "module", **kwargs) -> str:
        """
        Запускає задачу у пулі потоків.

        payload — довільний об'єкт (назва модуля або dict мутатора)
        task_type — "module" або "mutator"
        """

        task_id = str(uuid.uuid4())
        created_at = time.time()

        # Зберігаємо метадані
        self.meta[task_id] = {
            "id": task_id,
            "type": task_type,
            "payload": payload,
            "created_at": created_at,
            "started_at": None,
            "finished_at": None,
            "duration": None,
        }

        future = self.executor.submit(self._run_task, task_id, fn, *args, **kwargs)
        self.tasks[task_id] = future

        # GUI callback: task added
        if self.on_task_added:
            try:
                self.on_task_added(task_id, payload)
            except Exception:
                pass

        return task_id

    # ----------------------------------------------------------------------
    # Internal runner
    # ----------------------------------------------------------------------
    def _run_task(self, task_id: str, fn: Callable, *args, **kwargs):
        """Внутрішній запуск задачі з lifecycle callback'ами."""

        meta = self.meta.get(task_id)
        if not meta:
            return {"error": "metadata missing"}

        # Mark as started
        meta["started_at"] = time.time()

        if self.on_task_started:
            try:
                self.on_task_started(task_id, meta["payload"])
            except Exception:
                pass

        try:
            result = fn(*args, **kwargs)

        except Exception as e:
            meta["finished_at"] = time.time()
            meta["duration"] = meta["finished_at"] - meta["started_at"]

            error_info = {
                "error": str(e),
                "traceback": traceback.format_exc(),
                "payload": meta["payload"],
                "task_type": meta["type"],
                "duration": meta["duration"],
            }

            if self.on_task_error:
                try:
                    self.on_task_error(task_id, error_info)
                except Exception:
                    pass

            return error_info

        # Normal finish
        meta["finished_at"] = time.time()
        meta["duration"] = meta["finished_at"] - meta["started_at"]

        if isinstance(result, dict):
            result["payload"] = meta["payload"]
            result["task_type"] = meta["type"]
            result["duration"] = meta["duration"]
        else:
            result = {
                "result": result,
                "payload": meta["payload"],
                "task_type": meta["type"],
                "duration": meta["duration"],
            }

        if self.on_task_finished:
            try:
                self.on_task_finished(task_id, result)
            except Exception:
                pass

        return result

    # ----------------------------------------------------------------------
    # Cancel
    # ----------------------------------------------------------------------
    def cancel(self, task_id: str) -> bool:
        future = self.tasks.get(task_id)
        if future and not future.done():
            cancelled = future.cancel()
            if cancelled and self.on_task_cancelled:
                try:
                    self.on_task_cancelled(task_id, self.meta.get(task_id))
                except Exception:
                    pass
            return cancelled
        return False

    # ----------------------------------------------------------------------
    # Status
    # ----------------------------------------------------------------------
    def status(self, task_id: str) -> Optional[str]:
        future = self.tasks.get(task_id)
        if not future:
            return None
        if future.cancelled():
            return "cancelled"
        if future.running():
            return "running"
        if future.done():
            return "finished"
        return "pending"

    # ----------------------------------------------------------------------
    # Metadata access
    # ----------------------------------------------------------------------
    def get_meta(self, task_id: str) -> Optional[Dict[str, Any]]:
        return self.meta.get(task_id)

    def list_tasks(self):
        return list(self.meta.values())