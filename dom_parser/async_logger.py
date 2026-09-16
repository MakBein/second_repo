# xss_security_gui/dom_parser/async_logger.py
"""
Asynchronous logging for DOMParser ULTRA 7.0
Queue-based background thread logger
"""

import logging
import logging.handlers
import threading
import queue
from pathlib import Path
from typing import Optional


class AsyncLogger:
    """
    Асинхронный логгер с очередью.
    Используется Queue для неблокирующего логирования.
    """

    def __init__(
        self,
        log_file: Path,
        log_level: int = logging.INFO,
        queue_size: int = 1000,
        batch_size: int = 10,
    ):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.log_queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self.logger = logging.getLogger("DOMParser")
        self.logger.setLevel(log_level)
        
        # Queue handler
        self.queue_handler = logging.handlers.QueueHandler(self.log_queue)
        self.queue_handler.setLevel(log_level)
        
        # File handler (будет в background потоке)
        file_handler = logging.FileHandler(self.log_file, encoding="utf-8")
        file_handler.setLevel(log_level)
        
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)
        
        # Queue listener (background поток для записи в файл)
        self.queue_listener = logging.handlers.QueueListener(
            self.log_queue,
            file_handler,
            respect_handler_level=True
        )
        self.queue_listener.start()
        
        # Добавить queue handler к логгеру
        self.logger.addHandler(self.queue_handler)

    def get_logger(self) -> logging.Logger:
        """Получить логгер"""
        return self.logger

    def shutdown(self) -> None:
        """Корректное завершение"""
        try:
            self.queue_listener.stop()
        except Exception:
            pass

    def __del__(self):
        """Cleanup"""
        self.shutdown()


class BulkLogger:
    """
    Логгер для батчевой записи результатов.
    Аккумулирует логи и выписывает их батчами.
    """

    def __init__(self, log_file: Path, batch_size: int = 100):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.batch_size = batch_size
        self.buffer = []
        self._lock = threading.Lock()

    def log_entry(self, entry: str) -> None:
        """Добавить запись в буфер"""
        with self._lock:
            self.buffer.append(entry)
            if len(self.buffer) >= self.batch_size:
                self._flush()

    def log_batch(self, entries: list) -> None:
        """Добавить батч записей"""
        with self._lock:
            self.buffer.extend(entries)
            while len(self.buffer) >= self.batch_size:
                self._flush()

    def _flush(self) -> None:
        """Выписать батч в файл (должен вызваться с lock'ом)"""
        if not self.buffer:
            return

        try:
            # use io.open to avoid any accidental shadowing of built-in open
            import io

            with io.open(self.log_file, "a", encoding="utf-8") as f:
                for entry in self.buffer:
                    f.write(entry + "\n")
            self.buffer.clear()
        except Exception as e:
            # Logging may be unavailable during Python shutdown (sys.meta_path None).
            # Use a safe fallback that avoids calling logging.error when the runtime
            # teardown has already started.
            try:
                import sys as _sys

                if getattr(_sys, "meta_path", None) is None:
                    # Python is shutting down: avoid any logging or printing.
                    pass
                else:
                    logging.error(f"Failed to flush logs to {self.log_file}: {e}")
            except Exception:
                # Last-resort silent fallback
                # Silent fallback: nothing we can reliably do here during teardown
                pass

    def flush(self) -> None:
        """Явный flush"""
        with self._lock:
            self._flush()

    def __del__(self):
        """Cleanup при удалении"""
        self.flush()


# Глобальный инстанс (singleton)
_async_logger_instance: Optional[AsyncLogger] = None


def get_async_logger(log_file: Path) -> AsyncLogger:
    """Получить или создать глобальный AsyncLogger"""
    global _async_logger_instance
    
    if _async_logger_instance is None:
        _async_logger_instance = AsyncLogger(log_file)
    
    return _async_logger_instance


def shutdown_async_logger() -> None:
    """Завершить глобальный AsyncLogger"""
    global _async_logger_instance
    
    if _async_logger_instance:
        _async_logger_instance.shutdown()
        _async_logger_instance = None

