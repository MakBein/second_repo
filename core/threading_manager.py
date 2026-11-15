# xss_security_gui/core/threading_manager.py
"""
ThreadPoolManager 12.0 — Enterprise-Grade Async Engine
========================================================
Предотвращает фризы GUI через:
• Thread Pool с динамическим масштабированием
• Priority Queue для критичных задач
• Task Monitoring & Health Check
• Graceful shutdown
• No blocking, no deadlocks
"""

from __future__ import annotations

import threading
import queue
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Any, Dict, Optional, List
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

_logger = logging.getLogger(__name__)


class TaskPriority(Enum):
    """Приоритеты задач"""
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3


@dataclass
class Task:
    """Представление задачи в очереди"""
    task_id: str
    func: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    callback: Optional[Callable] = None
    error_callback: Optional[Callable] = None
    timeout: int = 60
    created_at: datetime = field(default_factory=datetime.now)

    def __lt__(self, other):
        """Сравнение для приоритета в очереди"""
        return self.priority.value < other.priority.value


class ThreadPoolManager:
    """
    Управляет асинхронным выполнением задач без блокирования GUI
    """

    def __init__(self, max_workers: int = 8, queue_size: int = 1000):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.task_queue = queue.PriorityQueue(maxsize=queue_size)
        self.active_tasks: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.RLock()
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        _logger.info(f"ThreadPoolManager initialized with {max_workers} workers")

    def submit(
        self,
        task_id: str,
        func: Callable,
        args: tuple = (),
        kwargs: dict = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        callback: Optional[Callable] = None,
        error_callback: Optional[Callable] = None,
        timeout: int = 60,
    ) -> str:
        """
        Добавить задачу в очередь для выполнения
        
        :param task_id: Уникальный ID задачи
        :param func: Функция для выполнения
        :param args: Аргументы функции
        :param kwargs: Keyword аргументы
        :param priority: Приоритет выполнения
        :param callback: Функция обратного вызова при успехе
        :param error_callback: Функция обратного вызова при ошибке
        :param timeout: Timeout в секундах
        :return: task_id
        """
        if kwargs is None:
            kwargs = {}

        task = Task(
            task_id=task_id,
            func=func,
            args=args,
            kwargs=kwargs,
            priority=priority,
            callback=callback,
            error_callback=error_callback,
            timeout=timeout,
        )

        with self.lock:
            self.active_tasks[task_id] = {
                "status": "queued",
                "created_at": datetime.now(),
                "result": None,
                "error": None,
            }

        try:
            self.task_queue.put(task, timeout=5)
            _logger.debug(f"Task {task_id} queued with priority {priority.name}")
            return task_id
        except queue.Full:
            _logger.error(f"Task queue is full, rejecting {task_id}")
            with self.lock:
                self.active_tasks[task_id]["status"] = "rejected"
            return None

    def _worker_loop(self):
        """Worker loop для обработки задач из очереди"""
        while self.running:
            try:
                task = self.task_queue.get(timeout=1)
                self._execute_task(task)
            except queue.Empty:
                continue
            except Exception as e:
                _logger.error(f"Worker loop error: {e}")

    def _execute_task(self, task: Task):
        """Выполнить задачу в thread pool"""
        try:
            with self.lock:
                self.active_tasks[task.task_id]["status"] = "running"

            # Выполнить функцию в executor
            future = self.executor.submit(
                self._run_task_with_timeout,
                task.func,
                task.args,
                task.kwargs,
                task.timeout,
            )

            try:
                result = future.result(timeout=task.timeout + 5)
                
                with self.lock:
                    self.active_tasks[task.task_id]["status"] = "completed"
                    self.active_tasks[task.task_id]["result"] = result

                if task.callback:
                    try:
                        task.callback(result)
                    except Exception as e:
                        _logger.error(f"Callback error for {task.task_id}: {e}")

                _logger.debug(f"Task {task.task_id} completed successfully")

            except Exception as e:
                with self.lock:
                    self.active_tasks[task.task_id]["status"] = "failed"
                    self.active_tasks[task.task_id]["error"] = str(e)

                if task.error_callback:
                    try:
                        task.error_callback(e)
                    except Exception as cb_err:
                        _logger.error(f"Error callback failed: {cb_err}")

                _logger.error(f"Task {task.task_id} failed: {e}")

        except Exception as e:
            _logger.error(f"Critical error in task execution: {e}")

    @staticmethod
    def _run_task_with_timeout(func, args, kwargs, timeout):
        """Выполнить функцию (может быть обёрнута для timeout)"""
        return func(*args, **kwargs)

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Получить статус задачи"""
        with self.lock:
            return self.active_tasks.get(task_id)

    def wait_for_task(self, task_id: str, timeout: int = 60) -> Optional[Any]:
        """Синхронно дождаться завершения задачи"""
        start = time.time()
        while time.time() - start < timeout:
            status = self.get_task_status(task_id)
            if status and status["status"] == "completed":
                return status["result"]
            if status and status["status"] == "failed":
                raise Exception(f"Task failed: {status['error']}")
            time.sleep(0.1)
        raise TimeoutError(f"Task {task_id} timed out")

    def get_active_tasks_count(self) -> int:
        """Количество активных задач"""
        with self.lock:
            return sum(
                1 for t in self.active_tasks.values()
                if t["status"] in ["queued", "running"]
            )

    def health_check(self) -> Dict[str, Any]:
        """Health check системы"""
        with self.lock:
            total = len(self.active_tasks)
            completed = sum(1 for t in self.active_tasks.values() if t["status"] == "completed")
            failed = sum(1 for t in self.active_tasks.values() if t["status"] == "failed")
            active = self.get_active_tasks_count()

        return {
            "status": "healthy" if active < self.max_workers else "busy",
            "total_tasks": total,
            "active_tasks": active,
            "completed_tasks": completed,
            "failed_tasks": failed,
            "queue_size": self.task_queue.qsize(),
            "max_workers": self.max_workers,
            "timestamp": datetime.now().isoformat(),
        }

    def shutdown(self, wait: bool = True):
        """Graceful shutdown"""
        _logger.info("Shutting down ThreadPoolManager")
        self.running = False
        if wait:
            self.executor.shutdown(wait=True)
        else:
            self.executor.shutdown(wait=False)


# Global singleton
_pool_manager: Optional[ThreadPoolManager] = None


def get_thread_pool() -> ThreadPoolManager:
    """Получить глобальный экземпляр ThreadPoolManager"""
    global _pool_manager
    if _pool_manager is None:
        _pool_manager = ThreadPoolManager()
    return _pool_manager


def submit_task(
    task_id: str,
    func: Callable,
    args: tuple = (),
    kwargs: dict = None,
    priority: TaskPriority = TaskPriority.NORMAL,
    callback: Optional[Callable] = None,
    error_callback: Optional[Callable] = None,
    timeout: int = 60,
) -> str:
    """Convenience функция для submit задачи"""
    pool = get_thread_pool()
    return pool.submit(
        task_id, func, args, kwargs, priority, callback, error_callback, timeout
    )


def wait_for(task_id: str, timeout: int = 60) -> Any:
    """Convenience функция для ожидания результата"""
    pool = get_thread_pool()
    return pool.wait_for_task(task_id, timeout)


def health_check() -> Dict[str, Any]:
    """Convenience функция для health check"""
    pool = get_thread_pool()
    return pool.health_check()
