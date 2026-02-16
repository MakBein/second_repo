# xss_security_gui/__init__.py
# 🛡️ XSS Security GUI — Core Initialization (v6.2 ULTRA)

import os
import sys
import json
import shutil
import logging
import datetime
from logging.handlers import RotatingFileHandler

from .payloads import load_payloads
from .dom_parser import DOMParser
from .network_checker import NetworkChecker
from .settings import settings, Settings

VERSION = "6.2.0"

# ============================================================
# 📁 Базовые директории проекта
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DIRS = {
    "logs": os.path.join(BASE_DIR, "logs"),
    "configs": os.path.join(BASE_DIR, "configs"),
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

def setup_logging():
    logger = logging.getLogger("XSS_GUI")
    logger.setLevel(logging.INFO)

    file_handler = RotatingFileHandler(
        INIT_LOG,
        maxBytes=2 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8"
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

def check_python_version():
    if sys.version_info < (3, 8):
        logger.error("Требуется Python 3.8 или выше.")
        print("[❌] Требуется Python 3.8 или выше.")
        sys.exit(1)

def check_dependencies():
    """Проверка внешних CLI-зависимостей."""
    if not shutil.which("ngrok"):
        logger.warning("Ngrok не найден. Туннель будет недоступен.")
        print("[⚠️] Ngrok не найден. Туннель будет недоступен.")
    else:
        logger.info("Ngrok доступен.")
        print("[🔗] Ngrok доступен.")

def check_libraries():
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
# ⚙️ Загрузка конфигурации
# ============================================================

def load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Ошибка загрузки {path}: {e}")
        return {}

def load_config():
    default_cfg = os.path.join(DIRS["configs"], "default_config.json")
    user_cfg = os.path.join(DIRS["configs"], "user_config.json")

    cfg = load_json(default_cfg)
    if cfg:
        logger.info(f"Загружена базовая конфигурация: {default_cfg}")
        print(f"[⚙️] Загружена базовая конфигурация: {default_cfg}")

    user = load_json(user_cfg)
    if user:
        cfg.update(user)
        logger.info(f"Загружена пользовательская конфигурация: {user_cfg}")
        print(f"[⚙️] Загружена пользовательская конфигурация: {user_cfg}")

    if not cfg:
        logger.warning("Конфигурация не найдена.")
        print("[⚠️] Конфигурация не найдена.")

    return cfg

# ============================================================
# 🧩 AppContext — единый объект окружения
# ============================================================

class AppContext:
    def __init__(self, config: dict):
        self.version = VERSION
        self.config = config
        self.paths = DIRS
        self.logger = logger
        self.initialized_at = datetime.datetime.now().isoformat()

    def summary(self):
        return {
            "version": self.version,
            "initialized_at": self.initialized_at,
            "paths": self.paths,
            "config_keys": list(self.config.keys()),
        }

# ============================================================
# 🚀 Главная инициализация
# ============================================================

_initialized = False
_context: AppContext | None = None

def init_environment() -> AppContext:
    global _initialized, _context

    if _initialized:
        return _context

    check_python_version()
    check_dependencies()
    check_libraries()

    # === Загрузка payload'ов ===
    load_payloads()

    # === Конфигурация ===
    cfg = load_config()

    # === ThreatConnector: экспорт статистики payload'ов ===
    try:
        from xss_security_gui.payloads import PAYLOADS
        PAYLOADS.export_stats_to_threat_intel()
    except Exception as e:
        logger.warning(f"Не удалось отправить статистику payload'ов: {e}")

    cfg.setdefault("threat_enabled", True)

    print(f"[🛡️ XSS GUI] Запуск: {datetime.datetime.now().isoformat()}")
    print(f"[📦 Версия GUI] {VERSION}")
    print("[✅] Инициализация завершена. Payload’ы загружены. Логи активны.")

    logger.info("Окружение успешно инициализировано.")

    _context = AppContext(cfg)
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
    "VERSION", "BASE_DIR", "DIRS", "LOGS_DIR", "INIT_LOG",
    "logger", "AppContext", "init_environment", "CONTEXT",
    "settings", "Settings",
    "DOMParser", "NetworkChecker",
]