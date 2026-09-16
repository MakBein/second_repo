# xss_security_gui/mutator_task_manager.py

from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, Future
from queue import PriorityQueue
from typing import Any, Callable, Dict, Optional, Tuple, List
import itertools
import uuid
import traceback
import time
import json
from pathlib import Path

# ThreadWorker для async shutdown
from xss_security_gui.utils.thread_worker import run_in_thread


class MutatorTaskManager:
    """
    MutatorTaskManager ULTRA 11.0 — Combat Edition
    ----------------------------------------------
    • Пріоритетна черга MUTATION_ATTACK_QUEUE (risk-driven)
    • JSON‑експорт кожної задачі
    • Підтримка family + risk
    • Повна інтеграція з MutatorTasksPanel / DefenseEvasionLab / Combat Results / Threat Intel
    • Потокобезпечний lifecycle:
        - on_task_added
        - on_task_started
        - on_task_finished
        - on_task_error
        - on_task_cancelled
    • Combat‑safe shutdown() + graceful_shutdown() + cancel_all()
    • Повна fault‑tolerance, без падінь
    """

    def __init__(self, max_workers: int = 6):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.tasks: Dict[str, Future] = {}
        self.meta: Dict[str, Dict[str, Any]] = {}

        # Приватна черга планування задач менеджера.
        # ВАЖЛИВО: раніше тут використовувалась глобальна MUTATION_ATTACK_QUEUE,
        # у яку payload_mutator кладе 2-кортежі (priority, dict), а менеджер —
        # 5-кортежі. Спільна черга призводила до ValueError при розпакуванні та
        # TypeError при порівнянні пріоритетів. Власна черга повністю ізолює
        # планування менеджера від конвеєра мутант-пейлоадів.
        self._sched_queue: "PriorityQueue" = PriorityQueue()
        self._seq = itertools.count()  # монотонний tie-breaker для рівних пріоритетів

        # GUI callbacks
        self.on_task_added: Optional[Callable[[str, Any], None]] = None
        self.on_task_started: Optional[Callable[[str, Any], None]] = None
        self.on_task_finished: Optional[Callable[[str, Dict[str, Any]], None]] = None
        self.on_task_error: Optional[Callable[[str, Dict[str, Any]], None]] = None
        self.on_task_cancelled: Optional[Callable[[str, Dict[str, Any]], None]] = None

        # JSON export directory
        self.EXPORT_DIR = Path("logs/mutator_tasks")
        self.EXPORT_DIR.mkdir(parents=True, exist_ok=True)

        # Internal shutdown flag
        self._shutdown_flag = False

    # ----------------------------------------------------------------------
    # JSON EXPORT
    # ----------------------------------------------------------------------
    def _export_task_json(self, task: Dict[str, Any]) -> None:
        path = self.EXPORT_DIR / f"task_{task['id']}.json"
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(task, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    # ----------------------------------------------------------------------
    # Submit task (з пріоритетом по risk)
    # ----------------------------------------------------------------------
    def submit(
        self,
        fn: Callable,
        *args,
        payload: Any = None,
        task_type: str = "mutator",
        family: str = "defense_evasion",
        risk: str = "medium",
        **kwargs
    ) -> str:

        if self._shutdown_flag:
            return "shutdown"

        task_id = str(uuid.uuid4())
        created_at = time.time()

        self.meta[task_id] = {
            "id": task_id,
            "type": task_type,
            "payload": payload,
            "family": family,
            "risk": risk,
            "created_at": created_at,
            "started_at": None,
            "finished_at": None,
            "duration": None,
        }

        priority_map = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        priority = priority_map.get(risk, 3)

        # (priority, seq, ...) — seq гарантує, що об'єкти fn/args ніколи не
        # порівнюються при рівних пріоритетах.
        self._sched_queue.put((priority, next(self._seq), task_id, fn, args, kwargs))

        if self.on_task_added:
            try:
                self.on_task_added(task_id, payload)
            except Exception:
                pass

        self._schedule_next()
        return task_id

    # ----------------------------------------------------------------------
    # Worker scheduler
    # ----------------------------------------------------------------------
    def _schedule_next(self) -> None:
        if self._shutdown_flag or self._sched_queue.empty():
            return

        try:
            priority, seq, task_id, fn, args, kwargs = self._sched_queue.get_nowait()
        except Exception:
            return

        future = self.executor.submit(self._run_task, task_id, fn, *args, **kwargs)
        self.tasks[task_id] = future

    # ----------------------------------------------------------------------
    # Internal runner
    # ----------------------------------------------------------------------
    def _run_task(self, task_id: str, fn: Callable, *args, **kwargs) -> Dict[str, Any]:
        meta = self.meta.get(task_id)
        if not meta:
            return {"id": task_id, "error": "metadata missing"}

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
                "id": task_id,
                "error": str(e),
                "traceback": traceback.format_exc(),
                "payload": meta["payload"],
                "task_type": meta["type"],
                "family": meta["family"],
                "risk": meta["risk"],
                "duration": meta["duration"],
            }

            self._export_task_json(error_info)

            if self.on_task_error:
                try:
                    self.on_task_error(task_id, error_info)
                except Exception:
                    pass

            self._schedule_next()
            return error_info

        meta["finished_at"] = time.time()
        meta["duration"] = meta["finished_at"] - meta["started_at"]

        if isinstance(result, dict):
            result.update({
                "id": task_id,
                "payload": meta["payload"],
                "task_type": meta["type"],
                "family": meta["family"],
                "risk": meta["risk"],
                "duration": meta["duration"],
            })
        else:
            result = {
                "id": task_id,
                "result": result,
                "payload": meta["payload"],
                "task_type": meta["type"],
                "family": meta["family"],
                "risk": meta["risk"],
                "duration": meta["duration"],
            }

        self._export_task_json(result)

        if self.on_task_finished:
            try:
                self.on_task_finished(task_id, result)
            except Exception:
                pass

        self._schedule_next()
        return result

    # ----------------------------------------------------------------------
    # Cancel single task
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
    # Cancel ALL tasks
    # ----------------------------------------------------------------------
    def cancel_all(self) -> None:
        for task_id, future in list(self.tasks.items()):
            try:
                if not future.done():
                    future.cancel()
                    if self.on_task_cancelled:
                        try:
                            self.on_task_cancelled(task_id, self.meta.get(task_id))
                        except Exception:
                            pass
            except Exception:
                pass

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
    # Metadata / results
    # ----------------------------------------------------------------------
    def get_meta(self, task_id: str) -> Optional[Dict[str, Any]]:
        return self.meta.get(task_id)

    def get_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        future = self.tasks.get(task_id)
        if future and future.done():
            try:
                return future.result()
            except Exception:
                return None
        return None

    def list_tasks(self) -> List[Dict[str, Any]]:
        return list(self.meta.values())

    # ----------------------------------------------------------------------
    # Shutdown (combat-safe)
    # ----------------------------------------------------------------------
    def shutdown(self, wait: bool = False) -> None:
        """
        Combat‑safe shutdown:
        • Останавливает executor (cancel_futures=True)
        • Не блокує Tk‑потік
        • Чистить tasks/meta
        • Можна викликати багато разів (idempotent)
        """
        self._shutdown_flag = True

        try:
            self.executor.shutdown(wait=wait, cancel_futures=True)
        except Exception:
            pass

        try:
            self.tasks.clear()
            self.meta.clear()
        except Exception:
            pass

    # ----------------------------------------------------------------------
    # Graceful shutdown (м’яке завершення критичних задач)
    # ----------------------------------------------------------------------
    def graceful_shutdown(self, timeout: float = 3.0) -> None:
        """
        М’яке завершення:
        • Дає критичним задачам шанс завершитися
        • Не блокує GUI
        • Після timeout → звичайний shutdown()
        """
        self._shutdown_flag = True

        def _worker():
            start = time.time()
            while time.time() - start < timeout:
                running = any(future.running() for future in self.tasks.values())
                if not running:
                    break
                time.sleep(0.1)
            self.shutdown(wait=False)

        run_in_thread(_worker)

    # ----------------------------------------------------------------------
    # Async shutdown (через ThreadWorker)
    # ----------------------------------------------------------------------
    def shutdown_async(self) -> None:
        """Асинхронне завершення без блокування GUI."""
        run_in_thread(lambda: self.shutdown(wait=False))

    # ----------------------------------------------------------------------
    # Is running?
    # ----------------------------------------------------------------------
    def is_running(self) -> bool:
        """Повертає True, якщо є активні задачі."""
        return any(future.running() for future in self.tasks.values())


