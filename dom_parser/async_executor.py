# xss_security_gui/dom_parser/async_executor.py
"""
ThreadPoolExecutor wrapper for non-blocking DOM parsing
DOMParser ULTRA 7.0 — Асинхронное выполнение
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from typing import Callable, Any, Dict, List, Optional
from functools import wraps
import time

from .errors import ParseTimeout, DOMParserException


class AsyncExecutor:
    """
    Wrapper around ThreadPoolExecutor для безопасного выполнения
    парсинга без блокировки основного потока GUI.
    """

    def __init__(self, max_workers: int = 6, thread_name_prefix: str = "DOMParser"):
        self.max_workers = max_workers
        self.thread_name_prefix = thread_name_prefix
        self.executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix=thread_name_prefix
        )
        self.log = logging.getLogger("AsyncExecutor")
        self._active_tasks: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def submit(
        self,
        func: Callable,
        *args,
        name: str = None,
        timeout: float = 5.0,
        **kwargs
    ) -> Any:
        """
        Submit task с таймаутом и опциональным именем для отслеживания.
        Возвращает будущий объект.
        """
        future = self.executor.submit(func, *args, **kwargs)
        if name:
            with self._lock:
                self._active_tasks[name] = future
        return future

    def submit_with_timeout(
        self,
        func: Callable,
        timeout: float = 5.0,
        *args,
        **kwargs
    ) -> Optional[Any]:
        """
        Submit task с автоматической обработкой таймаута.
        Возвращает результат или None в случае timeout.
        """
        future = self.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            self.log.warning(f"Task {func.__name__} exceeded timeout {timeout}s")
            return None
        except Exception as e:
            self.log.error(f"Task {func.__name__} failed: {e}", exc_info=True)
            return None

    def submit_all(
        self,
        tasks: List[tuple],
        timeout: float = 10.0
    ) -> Dict[str, Any]:
        """
        Submit батч задач: [(name, func, args, kwargs), ...].
        Возвращает dict имена → результаты, обработав таймауты.
        """
        futures = {}
        results = {}

        # Submit все задачи
        for task_info in tasks:
            if len(task_info) == 2:
                name, func = task_info
                args, kwargs = (), {}
            elif len(task_info) == 3:
                name, func, args = task_info
                kwargs = {}
            else:
                name, func, args, kwargs = task_info

            future = self.submit(func, *args, name=name, timeout=timeout, **kwargs)
            futures[name] = future

        # Собрать результаты с таймаутом
        start_time = time.time()
        for name, future in futures.items():
            remaining_time = max(0.1, timeout - (time.time() - start_time))
            try:
                results[name] = future.result(timeout=remaining_time)
            except TimeoutError:
                self.log.warning(f"Task {name} exceeded timeout {timeout}s")
                results[name] = None
            except Exception as e:
                self.log.error(f"Task {name} failed: {e}", exc_info=True)
                results[name] = None
            finally:
                with self._lock:
                    self._active_tasks.pop(name, None)

        return results

    def active_count(self) -> int:
        """Количество активных задач"""
        with self._lock:
            return len(self._active_tasks)

    def shutdown(self, wait: bool = True) -> None:
        """Корректное завершение executor"""
        self.log.info(f"Shutting down executor (wait={wait})...")
        try:
            self.executor.shutdown(wait=wait, cancel_futures=not wait)
        except Exception as e:
            self.log.error(f"Executor shutdown error: {e}")

    def __del__(self):
        """Cleanup при удалении объекта"""
        try:
            self.shutdown(wait=False)
        except Exception:
            pass


def timeout_handler(timeout: float = 5.0):
    """
    Декоратор для оборачивания функции в timeout.
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            executor = AsyncExecutor(max_workers=1)
            try:
                result = executor.submit_with_timeout(func, timeout, *args, **kwargs)
                return result if result is not None else {}
            finally:
                executor.shutdown()
        return wrapper
    return decorator


class BatchProcessor:
    """
    Процессор для обработки батчей результатов.
    Аккумулирует, батчит и отправляет результаты.
    """

    def __init__(
        self,
        batch_size: int = 50,
        flush_timeout: float = 5.0,
        callback: Callable = None
    ):
        self.batch_size = batch_size
        self.flush_timeout = flush_timeout
        self.callback = callback
        self.batch: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._last_flush = time.time()
        self.log = logging.getLogger("BatchProcessor")

    def add(self, item: Dict[str, Any]) -> None:
        """Добавить элемент в батч"""
        with self._lock:
            self.batch.append(item)
            if len(self.batch) >= self.batch_size:
                self._flush_locked()

    def add_batch(self, items: List[Dict[str, Any]]) -> None:
        """Добавить батч элементов"""
        with self._lock:
            self.batch.extend(items)
            while len(self.batch) >= self.batch_size:
                self._flush_locked()

    def _flush_locked(self) -> None:
        """Flushить батч (должен быть вызван с lock'ом)"""
        if not self.batch or not self.callback:
            return

        batch_to_send = self.batch[:self.batch_size]
        self.batch = self.batch[self.batch_size:]

        try:
            self._dispatch_callback(self.callback, batch_to_send)
            self._last_flush = time.time()
            self.log.debug(f"Flushed {len(batch_to_send)} items")
        except Exception as e:
            self.log.error(f"Batch flush failed: {e}")
            self.batch = batch_to_send + self.batch

    def flush(self) -> None:
        """Явный flush всего батча"""
        with self._lock:
            while self.batch:
                self._flush_locked()

    def should_flush(self) -> bool:
        """Проверить, нужно ли flush (по timeout)"""
        with self._lock:
            return (
                len(self.batch) > 0
                and time.time() - self._last_flush >= self.flush_timeout
            )

    def get_size(self) -> int:
        """Размер текущего батча"""
        with self._lock:
            return len(self.batch)

    def clear(self) -> None:
        """Очистить батч"""
        with self._lock:
            self.batch.clear()

    @staticmethod
    def _dispatch_callback(callback: Callable, payload: List[Dict[str, Any]]) -> None:
        owner = getattr(callback, "__self__", None)
        after = getattr(owner, "after", None)
        if callable(after):
            after(0, lambda p=payload: callback(p))
        else:
            callback(payload)

