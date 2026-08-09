# xss_security_gui/auto_recon/user_tracker.py
"""
User Tracker — отслеживание пользователей и контекста операций.
Функции:
• Захват информации о пользователе (имя, IP, среда)
• Трэйсинг сессий
• История операций
• Контекст-специфичные логи
"""

import json
import socket
import getpass
import os
import uuid
import datetime
import platform
from pathlib import Path
from typing import Dict, Any, Optional, List
import threading

from xss_security_gui.settings import LOG_DIR


class UserContext:
    """Контекст пользователя и сессии."""

    def __init__(self):
        self.user_id = getpass.getuser()
        self.hostname = socket.gethostname()
        self.ip_address = self._get_ip_address()
        self.session_id = str(uuid.uuid4())[:8]
        self.session_start = datetime.datetime.utcnow()
        self.platform = platform.system()
        self.python_version = platform.python_version()
        self.pid = os.getpid()
        self.environment = os.environ.get("ENV", "dev")

    def _get_ip_address(self) -> str:
        """Определяет IP адрес машины."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def to_dict(self) -> Dict[str, Any]:
        """Преобразует контекст в словарь."""
        return {
            "user_id": self.user_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "session_id": self.session_id,
            "session_start": self.session_start.isoformat(),
            "platform": self.platform,
            "python_version": self.python_version,
            "pid": self.pid,
            "environment": self.environment,
        }

    def __repr__(self) -> str:
        return f"UserContext(user={self.user_id}, session={self.session_id}, ip={self.ip_address})"


class UserTracker:
    """Отслеживание пользовательских операций."""

    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = log_dir or LOG_DIR / "auto_recon" / "users"
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.context = UserContext()
        self.history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

        self.user_log = self.log_dir / f"{self.context.user_id}_operations.ndjson"
        self.sessions_log = self.log_dir / "sessions.json"

        # Логирование начала сессии
        self._log_session_start()

    def _log_session_start(self):
        """Логирует начало сессии."""
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "event": "session_start",
            **self.context.to_dict()
        }

        with self._lock:
            with self.user_log.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def track_operation(
        self,
        operation: str,
        details: Optional[Dict[str, Any]] = None,
        target: Optional[str] = None,
        status: str = "success",
    ) -> Dict[str, Any]:
        """
        Отслеживает операцию пользователя.

        Args:
            operation: тип операции (scan, analyze, exploit и т.д.)
            details: подробности операции
            target: целевой ресурс
            status: статус выполнения
        """
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "operation": operation,
            "target": target,
            "status": status,
            "details": details or {},
            "user_id": self.context.user_id,
            "session_id": self.context.session_id,
            "hostname": self.context.hostname,
            "ip_address": self.context.ip_address,
        }

        with self._lock:
            # NDJSON запись
            with self.user_log.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

            # Кэширование в памяти
            self.history.append(entry)
            if len(self.history) > 1000:
                self.history = self.history[-500:]

        return entry

    def track_vulnerability_found(
        self,
        vuln_type: str,
        url: str,
        severity: str,
        payload: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Отслеживает найденную уязвимость."""
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "event": "vulnerability_found",
            "vulnerability_type": vuln_type,
            "url": url,
            "severity": severity,
            "payload": payload,
            "details": details or {},
            "user_id": self.context.user_id,
            "session_id": self.context.session_id,
            "user_ip": self.context.ip_address,
        }

        with self._lock:
            with self.user_log.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        return entry

    def track_error(
        self,
        error_type: str,
        message: str,
        operation: Optional[str] = None,
        target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Отслеживает ошибки."""
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "event": "error",
            "error_type": error_type,
            "message": message,
            "operation": operation,
            "target": target,
            "user_id": self.context.user_id,
            "session_id": self.context.session_id,
            "user_ip": self.context.ip_address,
        }

        with self._lock:
            with self.user_log.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        return entry

    def get_user_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Возвращает историю операций пользователя."""
        return self.history[-limit:]

    def save_session_report(self) -> Path:
        """Сохраняет отчёт сессии."""
        session_report = {
            "user_context": self.context.to_dict(),
            "session_duration": (datetime.datetime.utcnow() - self.context.session_start).total_seconds(),
            "operations_count": len(self.history),
            "operations": self.get_user_history(limit=500),
            "saved_at": datetime.datetime.utcnow().isoformat(),
        }

        filename = f"session_{self.context.session_id}_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        path = self.log_dir / filename

        with path.open("w", encoding="utf-8") as f:
            json.dump(session_report, f, indent=2, ensure_ascii=False)

        return path

    def load_user_history(self, user_id: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        """Загружает историю пользователя из лог-файла."""
        user_id = user_id or self.context.user_id
        user_log = self.log_dir / f"{user_id}_operations.ndjson"

        events: List[Dict[str, Any]] = []

        if not user_log.exists():
            return events

        try:
            with user_log.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass

            return events[-limit:]
        except Exception:
            return []


# Глобальный экземпляр
_global_tracker = UserTracker()


def get_user_tracker() -> UserTracker:
    """Возвращает глобальный tracker."""
    return _global_tracker


def get_user_context() -> UserContext:
    """Возвращает контекст текущего пользователя."""
    return _global_tracker.context


__all__ = [
    "UserContext",
    "UserTracker",
    "get_user_tracker",
    "get_user_context",
]

