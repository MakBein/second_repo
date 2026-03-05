# xss_security_gui/__init__.py
# 🛡️ XSS Security GUI — Core Initialization (v6.5 ULTRA)

import os
import sys
import json
import shutil
import logging
import datetime
from logging.handlers import RotatingFileHandler
from typing import Optional

from .settings import (
    settings,
    Settings,
    BASE_DIR,
    LOG_DIR,
    CONFIG_DIR,
    EXPORT_DIR,
    PAYLOADS_DIR,
)
from .payloads import load_payloads
from .dom_parser import DOMParser
from .network_checker import NetworkChecker

VERSION = "6.5.0"

# ============================================================
# 📁 Директории проекта (единый источник — settings/BASE_DIR)
# ============================================================

DIRS = {
    "logs": str(LOG_DIR),
    "target": str(CONFIG_DIR),
    "exports": str(EXPORT_DIR),
    "payloads": str(PAYLOADS_DIR),
    "resources": os.path.join(BASE_DIR, "resources"),
    "assets": os.path.join(BASE_DIR, "assets"),
    "sessions": os.path.join(BASE_DIR, "sessions"),
}

for path in DIRS.values():
    os.makedirs(path, exist_ok=True)

LOGS_DIR = DIRS["logs"]
INIT_LOG = os.path.join(LOGS_DIR, "init.log")

# ============================================================
# 📝 Логирование (Rotating Logs + Console)
# ============================================================

def setup_logging() -> logging.Logger:
    logger = logging.getLogger("XSS_GUI")
    logger.setLevel(logging.INFO)

    file_handler = RotatingFileHandler(
        INIT_LOG,
        maxBytes=2 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s"
    ))

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s"
    ))

    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console)

    return logger


logger = setup_logging()

# ============================================================
# 🧪 Проверки окружения
# ============================================================

def check_python_version() -> None:
    if sys.version_info < (3, 8):
        logger.error("Требуется Python 3.8 или выше.")
        print("[❌] Требуется Python 3.8 или выше.")
        sys.exit(1)


def check_dependencies() -> None:
    """Проверка внешних CLI-зависимостей."""
    if not shutil.which("ngrok"):
        logger.warning("Ngrok не найден. Туннель будет недоступен.")
        print("[⚠️] Ngrok не найден. Туннель будет недоступен.")
    else:
        logger.info("Ngrok доступен.")
        print("[🔗] Ngrok доступен.")


def check_libraries() -> None:
    """Проверка обязательных Python-библиотек."""
    required = ["requests", "urllib3", "bs4", "pythonping"]
    for lib in required:
        try:
            __import__(lib)
        except ImportError:
            logger.error(f"Отсутствует библиотека: {lib}")
            print(f"[❌] Отсутствует библиотека: {lib}")
            sys.exit(1)

# ============================================================
# 🧩 AppContext — единый объект окружения
# ============================================================

class AppContext:
    def __init__(self):
        self.version = VERSION
        self.paths = DIRS
        self.logger = logger
        self.initialized_at = datetime.datetime.now().isoformat()
        self.settings = settings  # гибридные настройки ULTRA 6.5

    def summary(self) -> dict:
        return {
            "version": self.version,
            "initialized_at": self.initialized_at,
            "paths": self.paths,
            "profile": self.settings.profile,
        }

# ============================================================
# 🚀 Главная инициализация
# ============================================================

_initialized = False
_context: Optional[AppContext] = None


def init_environment() -> AppContext:
    global _initialized, _context

    if _initialized and _context is not None:
        return _context

    check_python_version()
    check_dependencies()
    check_libraries()

    # === Загрузка payload'ов ===
    load_payloads()

    # === ThreatConnector: экспорт статистики payload'ов ===
    try:
        from xss_security_gui.payloads import PAYLOADS
        PAYLOADS.export_stats_to_threat_intel()
    except Exception as e:
        logger.warning(f"Не удалось отправить статистику payload'ов: {e}")

    print(f"[🛡️ XSS GUI] Запуск: {datetime.datetime.now().isoformat()}")
    print(f"[📦 Версия GUI] {VERSION}")
    print("[✅] Инициализация завершена. Payload’ы загружены. Логи активны.")

    logger.info("Окружение успешно инициализировано.")

    _context = AppContext()
    _initialized = True
    return _context

# ============================================================
# 🔄 Автоинициализация
# ============================================================

AUTO_INIT = os.environ.get("XSS_GUI_AUTO_INIT", "1") == "1"
CONTEXT = init_environment() if AUTO_INIT else None

# ============================================================
# 📦 Экспортируемые объекты пакета
# ============================================================

__all__ = [
    "VERSION",
    "BASE_DIR",
    "DIRS",
    "LOGS_DIR",
    "INIT_LOG",
    "logger",
    "AppContext",
    "init_environment",
    "CONTEXT",
    "settings",
    "Settings",
    "DOMParser",
    "NetworkChecker",
]