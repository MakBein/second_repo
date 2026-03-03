# xss_security_gui/config_manager.py
"""
config_manager.py — единая система конфигурации XSS Security GUI (v3.3 ULTRA)
Автор: Aleksandr + Copilot
"""

import os
import json
from pathlib import Path
from dotenv import load_dotenv
import xss_security_gui
from xss_security_gui.settings import LOG_DIR


# ================================
# 📁 БАЗОВЫЕ ДИРЕКТОРИИ
# ================================

# Абсолютный путь к корню пакета (работает везде: GUI, PyCharm, REPL, exe)
BASE_DIR: Path = Path(xss_security_gui.__file__).parent.resolve()

LOGS_DIR: Path = BASE_DIR / "logs"
CONFIGS_DIR: Path = BASE_DIR / "target"
PAYLOADS_DIR: Path = BASE_DIR / "payloads"
EXPORTS_DIR: Path = BASE_DIR / "exports"

for d in (LOGS_DIR, CONFIGS_DIR, PAYLOADS_DIR, EXPORTS_DIR):
    d.mkdir(parents=True, exist_ok=True)

# ================================
# 📄 ПУТИ К ФАЙЛАМ
# ================================

SETTINGS_JSON_PATH = CONFIGS_DIR / "settings.json"
DEFAULT_CONFIG_PATH = CONFIGS_DIR / "default_config.json"
USER_CONFIG_PATH = CONFIGS_DIR / "user_config.json"

CRAWLER_RESULTS_PATH = LOG_DIR / "crawler_results.json"
DEEP_CRAWL_JSON_PATH = LOG_DIR / "deep_crawl.json"
CRAWLER_STRUCTURE_PATH = LOGS_DIR / "crawler_structure.log"
CRAWLER_GRAPH_DOT_PATH = LOGS_DIR / "crawl_graph.dot"
CRAWLER_GRAPH_SVG_PATH = LOGS_DIR / "crawl_graph"  # Graphviz добавит .svg

HONEYPOT_LOG_PATH = LOGS_DIR / "honeypot.log"
HONEYPOT_HITS_PATH = LOGS_DIR / "honeypot_hits.log"

FUZZ_LOG_PATH = LOGS_DIR / "param_fuzz_hits.log"

PAYLOAD_DB_PATH = PAYLOADS_DIR / "payload_db.json"

PDF_EXPORT_PATH = EXPORTS_DIR / "reports"
JSON_EXPORT_PATH = EXPORTS_DIR / "json"

PDF_EXPORT_PATH.mkdir(parents=True, exist_ok=True)
JSON_EXPORT_PATH.mkdir(parents=True, exist_ok=True)

# === Новые алиасы для OverviewTab и других модулей ===
THREAT_LOG_PATH = LOGS_DIR / "threat_intel.log"
LOG_HONEYPOT_HITS = LOGS_DIR / "honeypot_hits.log"
PARAM_FUZZ_LOG_PATH = LOGS_DIR / "form_fuzz_hits.log"


# ================================
# 📥 ЗАГРУЗКА .ENV
# ================================

ENV_PATH = BASE_DIR / ".env"
if ENV_PATH.exists():
    load_dotenv(ENV_PATH)


# ================================
# 🔧 ФУНКЦИИ ЗАГРУЗКИ КОНФИГУРАЦИИ
# ================================

def load_json(path: Path) -> dict:
    """Безопасная загрузка JSON."""
    if not path.exists():
        print(f"[⚠] Файл не найден: {path}")
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[⚠] Ошибка чтения {path}: {e}")
        return {}


def load_settings() -> dict:
    """Загружает settings.json, fallback на default_config.json."""
    cfg = load_json(SETTINGS_JSON_PATH)
    if not cfg:
        cfg = load_json(DEFAULT_CONFIG_PATH)
    return cfg


def load_default_config() -> dict:
    return load_json(DEFAULT_CONFIG_PATH)


def load_user_config() -> dict:
    return load_json(USER_CONFIG_PATH)


def merge_configs(*configs: dict) -> dict:
    """Объединяет конфиги, приоритет — последний."""
    final = {}
    for cfg in configs:
        final.update(cfg)
    return final


# ================================
# 🧪 ВАЛИДАЦИЯ КОНФИГУРАЦИИ
# ================================

def validate_config(cfg: dict) -> dict:
    """Проверяет корректность ключевых параметров."""
    validated = cfg.copy()

    validated.setdefault("honeypot", {})
    if validated["honeypot"].get("poll_interval", 0) < 1:
        validated["honeypot"]["poll_interval"] = 4

    validated.setdefault("gui", {})
    if validated["gui"].get("max_report_line_length", 0) < 50:
        validated["gui"]["max_report_line_length"] = 110

    return validated


# ================================
# 🧩 ГЛАВНАЯ ФУНКЦИЯ ИНИЦИАЛИЗАЦИИ
# ================================

def load_full_config() -> dict:
    """
    Загружает:
    - default_config.json
    - user_config.json
    - settings.json (с fallback)
    - .env
    Объединяет всё в один словарь.
    """
    cfg_default = load_default_config()
    cfg_user = load_user_config()
    cfg_settings = load_settings()

    merged = merge_configs(cfg_default, cfg_user, cfg_settings)

    # Добавляем переменные из .env
    merged["env"] = {
        "ENABLE_AUTO_TRAPS": os.getenv("ENABLE_AUTO_TRAPS"),
        "DEFAULT_TRAP_TYPE": os.getenv("DEFAULT_TRAP_TYPE"),
        "HONEYPOT_POLL_INTERVAL": os.getenv("HONEYPOT_POLL_INTERVAL"),
        "DEFAULT_GUI_THEME": os.getenv("DEFAULT_GUI_THEME"),
    }

    return validate_config(merged)


# ================================
# 📦 ГЛОБАЛЬНАЯ КОНФИГУРАЦИЯ
# ================================

CONFIG = load_full_config()