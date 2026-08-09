# xss_security_gui/auto_recon/core_logger.py
"""
Core Logger — центральное логирование для AutoRecon Enterprise.
Функции:
• Структурированное логирование (JSON/NDJSON)
• Трейсинг операций и user-agnostic логирование
• Ротация логов
• Thread-safe запись
• Интеграция с системой мониторинга
"""

import json
import logging
import threading
import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from enum import Enum
import hashlib
import os

from xss_security_gui.settings import LOG_DIR


class LogLevel(Enum):
    """Уровни логирования."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    SUCCESS = "SUCCESS"
    AUDIT = "AUDIT"


class EnterpriseLogger:
    """Enterprise-level логгер с структурированным выводом."""

    def __init__(self, module_name: str = "AutoRecon", log_dir: Optional[Path] = None):
        self.module_name = module_name
        self.log_dir = log_dir or LOG_DIR / "auto_recon"
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.ndjson_path = self.log_dir / f"{module_name.lower()}.ndjson"
        self.json_path = self.log_dir / f"{module_name.lower()}_events.json"
        self.audit_path = self.log_dir / f"{module_name.lower()}_audit.ndjson"

        self._lock = threading.Lock()
        self._python_logger = self._setup_python_logger()
        self._events: List[Dict[str, Any]] = []

    def _setup_python_logger(self) -> logging.Logger:
        """Настройка стандартного Python логгера."""
        logger = logging.getLogger(self.module_name)
        logger.setLevel(logging.DEBUG)

        # FileHandler
        fh = logging.FileHandler(
            self.log_dir / f"{self.module_name.lower()}.log",
            encoding="utf-8"
        )
        fh.setLevel(logging.DEBUG)

        # Formatter
        formatter = logging.Formatter(
            "%(asctime)s [%(name)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        return logger

    def _rotate_if_big(self, path: Path, max_mb: int = 50) -> None:
        """Ротирует лог-файл если он слишком большой."""
        try:
            if not path.exists():
                return

            size = path.stat().st_size
            if size <= max_mb * 1024 * 1024:
                return

            ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup = path.with_suffix(path.suffix + f".{ts}.bak")
            path.rename(backup)
            self._python_logger.info(f"Log rotated: {path} → {backup}")
        except Exception as e:
            self._python_logger.error(f"Log rotation error: {e}", exc_info=True)

    def log(
        self,
        level: LogLevel,
        message: str,
        tags: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Логирует событие в структурированном формате.

        Args:
            level: уровень логирования
            message: текст сообщения
            tags: дополнительные теги (dict)
            user_id: ID пользователя
            request_id: ID запроса (для трэйсинга)
            **kwargs: дополнительные поля
        """
        try:
            ts = datetime.datetime.utcnow().isoformat()
            entry = {
                "timestamp": ts,
                "module": self.module_name,
                "level": level.value,
                "message": message,
                "tags": tags or {},
                "user_id": user_id,
                "request_id": request_id,
                **kwargs
            }

            # Удаляем None значения
            entry = {k: v for k, v in entry.items() if v is not None}

            # Логирование в Python logger
            getattr(self._python_logger, level.value.lower())(message)

            # NDJSON запись
            with self._lock:
                self._rotate_if_big(self.ndjson_path)
                with self.ndjson_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")

                # Кэширование в памяти
                self._events.append(entry)
                if len(self._events) > 10000:
                    self._events = self._events[-5000:]  # Trim to prevent memory bloat

            return entry

        except Exception as e:
            self._python_logger.error(f"Logging error: {e}", exc_info=True)
            return {}

    def info(self, msg: str, **kwargs):
        """Логирование уровня INFO."""
        return self.log(LogLevel.INFO, msg, **kwargs)

    def warning(self, msg: str, **kwargs):
        """Логирование уровня WARNING."""
        return self.log(LogLevel.WARNING, msg, **kwargs)

    def error(self, msg: str, **kwargs):
        """Логирование уровня ERROR."""
        return self.log(LogLevel.ERROR, msg, **kwargs)

    def debug(self, msg: str, **kwargs):
        """Логирование уровня DEBUG."""
        return self.log(LogLevel.DEBUG, msg, **kwargs)

    def success(self, msg: str, **kwargs):
        """Логирование успешной операции."""
        return self.log(LogLevel.SUCCESS, msg, **kwargs)

    def audit(self, msg: str, user_id: str, action: str, **kwargs):
        """Логирование аудита (кто что сделал)."""
        audit_entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "user_id": user_id,
            "module": self.module_name,
            "action": action,
            "message": msg,
            **kwargs
        }

        with self._lock:
            with self.audit_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(audit_entry, ensure_ascii=False) + "\n")

        return audit_entry

    def save_events_snapshot(self, filename: Optional[str] = None) -> Path:
        """Сохраняет снимок всех событий в JSON."""
        filename = filename or f"events_snapshot_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        path = self.log_dir / filename

        with self._lock:
            with path.open("w", encoding="utf-8") as f:
                json.dump(self._events, f, indent=2, ensure_ascii=False)

        self._python_logger.info(f"Events snapshot saved: {path}")
        return path

    def get_events(self, limit: int = 100, level: Optional[LogLevel] = None) -> List[Dict[str, Any]]:
        """Возвращает недавние события."""
        events = self._events if level is None else [
            e for e in self._events if e.get("level") == level.value
        ]
        return events[-limit:]

    def load_ndjson(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Загружает события из NDJSON файла."""
        events: List[Dict[str, Any]] = []

        if not self.ndjson_path.exists():
            return events

        try:
            with self.ndjson_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

            return events[-limit:]
        except Exception as e:
            self._python_logger.error(f"NDJSON load error: {e}", exc_info=True)
            return []


# Глобальный экземпляр по умолчанию
_default_logger = EnterpriseLogger("AutoRecon")


def get_logger(module_name: str = "AutoRecon") -> EnterpriseLogger:
    """Возвращает логгер для модуля."""
    return EnterpriseLogger(module_name)


__all__ = [
    "EnterpriseLogger",
    "LogLevel",
    "get_logger",
]

