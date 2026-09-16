# xss_security_gui/auto_recon/core_logger.py
"""
Core Logger — Enterprise-grade логирование для AutoRecon Red Team Suite.
Особенности:
• Структурированное NDJSON/JSON логирование
• MITRE-aware события
• Threat-aware уровни
• Корреляция запросов, операторов, фаз и сессий
• Integrity hashing (SHA256)
• Аномалия-трейсинг
• Multi-channel вывод (ops / audit / anomaly / intel)
• Thread-safe запись
• Адаптивная ротация
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
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    SUCCESS = "SUCCESS"
    AUDIT = "AUDIT"
    ANOMALY = "ANOMALY"
    INTEL = "INTEL"


class EnterpriseLogger:
    """Enterprise-level логгер с расширенным Red Team функционалом."""

    def __init__(self, module_name: str = "AutoRecon", log_dir: Optional[Path] = None):
        self.module_name = module_name
        self.log_dir = log_dir or LOG_DIR / "enterprise_logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Основные каналы
        self.ndjson_path = self.log_dir / f"{module_name.lower()}.ndjson"
        self.audit_path = self.log_dir / f"{module_name.lower()}_audit.ndjson"
        self.anomaly_path = self.log_dir / f"{module_name.lower()}_anomaly.ndjson"
        self.intel_path = self.log_dir / f"{module_name.lower()}_intel.ndjson"

        self._lock = threading.Lock()
        self._python_logger = self._setup_python_logger()
        self._events: List[Dict[str, Any]] = []

    # ==========================
    #  Python logger
    # ==========================
    def _setup_python_logger(self) -> logging.Logger:
        logger = logging.getLogger(self.module_name)
        logger.setLevel(logging.DEBUG)

        fh = logging.FileHandler(self.log_dir / f"{self.module_name.lower()}.log", encoding="utf-8")
        fh.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            "%(asctime)s [%(name)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        return logger

    # ==========================
    #  Log rotation
    # ==========================
    def _rotate_if_big(self, path: Path, max_mb: int = 100) -> None:
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

    # ==========================
    #  Core logging
    # ==========================
    def log(
        self,
        level: LogLevel,
        message: str,
        tags: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        mitre: Optional[Dict[str, str]] = None,
        threat_level: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Структурированное логирование с MITRE, threat-level и integrity hashing.
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
                "session_id": session_id,
                "request_id": request_id,
                "mitre": mitre,
                "threat_level": threat_level,
                **kwargs
            }

            # Удаляем None
            entry = {k: v for k, v in entry.items() if v is not None}

            # Integrity hash
            entry_hash = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
            entry["integrity_hash"] = entry_hash

            # Python logger
            getattr(self._python_logger, level.value.lower())(message)

            # NDJSON запись
            with self._lock:
                self._rotate_if_big(self.ndjson_path)
                with self.ndjson_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")

                self._events.append(entry)
                if len(self._events) > 15000:
                    self._events = self._events[-8000:]

            return entry

        except Exception as e:
            self._python_logger.error(f"Logging error: {e}", exc_info=True)
            return {}

    # ==========================
    #  Convenience wrappers
    # ==========================
    def info(self, msg: str, **kwargs):
        return self.log(LogLevel.INFO, msg, **kwargs)

    def warning(self, msg: str, **kwargs):
        return self.log(LogLevel.WARNING, msg, **kwargs)

    def error(self, msg: str, **kwargs):
        return self.log(LogLevel.ERROR, msg, **kwargs)

    def debug(self, msg: str, **kwargs):
        return self.log(LogLevel.DEBUG, msg, **kwargs)

    def success(self, msg: str, **kwargs):
        return self.log(LogLevel.SUCCESS, msg, **kwargs)

    # ==========================
    #  Audit logging
    # ==========================
    def audit(self, msg: str, user_id: str, action: str, **kwargs):
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "user_id": user_id,
            "module": self.module_name,
            "action": action,
            "message": msg,
            **kwargs
        }

        with self._lock:
            with self.audit_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        return entry

    # ==========================
    #  Anomaly logging
    # ==========================
    def anomaly(self, msg: str, score: float, vector: Dict[str, Any], **kwargs):
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "module": self.module_name,
            "level": LogLevel.ANOMALY.value,
            "message": msg,
            "score": score,
            "vector": vector,
            **kwargs
        }

        with self._lock:
            with self.anomaly_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        return entry

    # ==========================
    #  Threat Intelligence logging
    # ==========================
    def intel(self, msg: str, intel_type: str, data: Dict[str, Any], **kwargs):
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "module": self.module_name,
            "level": LogLevel.INTEL.value,
            "intel_type": intel_type,
            "message": msg,
            "data": data,
            **kwargs
        }

        with self._lock:
            with self.intel_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        return entry

    # ==========================
    #  Snapshot
    # ==========================
    def save_events_snapshot(self, filename: Optional[str] = None) -> Path:
        filename = filename or f"events_snapshot_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        path = self.log_dir / filename

        with self._lock:
            with path.open("w", encoding="utf-8") as f:
                json.dump(self._events, f, indent=2, ensure_ascii=False)

        self._python_logger.info(f"Events snapshot saved: {path}")
        return path

    # ==========================
    #  Loaders
    # ==========================
    def get_events(self, limit: int = 200, level: Optional[LogLevel] = None) -> List[Dict[str, Any]]:
        events = self._events if level is None else [
            e for e in self._events if e.get("level") == level.value
        ]
        return events[-limit:]

    def load_ndjson(self, limit: int = 2000) -> List[Dict[str, Any]]:
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


# Глобальный экземпляр
_default_logger = EnterpriseLogger("AutoRecon")


def get_logger(module_name: str = "AutoRecon") -> EnterpriseLogger:
    return EnterpriseLogger(module_name)


__all__ = ["EnterpriseLogger", "LogLevel", "get_logger"]


