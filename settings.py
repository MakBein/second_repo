# xss_security_gui/settings.py
"""
Settings ULTRA Hybrid 6.1
Гибридная система конфигурации:
- .env
- settings.json
- переменные окружения
- CLI-аргументы
- профили dev/prod/sandbox/ci
- автоопределение окружения
- поддержка всех модулей XSS Security Suite
"""

from __future__ import annotations
import json, os, sys
from pathlib import Path
from dotenv import load_dotenv
from typing import Any, Dict

from xss_security_gui.sandbox_detector import detect_sandbox
from xss_security_gui.dom_parser import DOMParser

# 📁 Базовые директории
BASE_DIR: Path = Path(__file__).parent.resolve()
LOG_DIR: Path = BASE_DIR / "logs"
EXPORT_DIR: Path = BASE_DIR / "exports"
PDF_DIR: Path = EXPORT_DIR / "reports"
PAYLOADS_DIR: Path = BASE_DIR / "payloads"
CONFIG_DIR: Path = BASE_DIR / "configs"

for d in (LOG_DIR, EXPORT_DIR, PDF_DIR, PAYLOADS_DIR, CONFIG_DIR):
    d.mkdir(parents=True, exist_ok=True)

# 📥 Загрузка .env
ENV_PATH = BASE_DIR / ".env"
if ENV_PATH.exists():
    load_dotenv(ENV_PATH)

# 📄 Загрузка settings.json
SETTINGS_JSON_PATH = CONFIG_DIR / "settings.json"
SETTINGS_JSON: Dict[str, Any] = {}
if SETTINGS_JSON_PATH.exists():
    try:
        with open(SETTINGS_JSON_PATH, encoding="utf-8") as f:
            SETTINGS_JSON = json.load(f)
    except Exception as e:
        print(f"[Settings] Ошибка загрузки settings.json: {e}")
        SETTINGS_JSON = {}

# 🧠 Автоопределение окружения
_sandbox_info = detect_sandbox()
if _sandbox_info.get("sandboxed"):
    AUTO_PROFILE = "sandbox"
elif any(k in os.environ for k in ["CI", "GITHUB_ACTIONS", "GITLAB_CI"]):
    AUTO_PROFILE = "ci"
else:
    AUTO_PROFILE = os.getenv("APP_PROFILE", "dev")

# 🧩 Профили конфигурации
PROFILE_DEFAULTS = {
    "dev": {"logging.level": "DEBUG", "gui.theme": "dark", "mutator.max_workers": 8,
            "attack_engine.threads": 6, "crawl.depth_limit": 3},
    "prod": {"logging.level": "INFO", "gui.theme": "light", "mutator.max_workers": 12,
             "attack_engine.threads": 10, "crawl.depth_limit": 2},
    "sandbox": {"logging.level": "WARNING", "gui.theme": "dark", "mutator.max_workers": 2,
                "attack_engine.threads": 1, "crawl.depth_limit": 1},
    "ci": {"logging.level": "ERROR", "gui.theme": "minimal", "mutator.max_workers": 1,
           "attack_engine.threads": 1, "crawl.depth_limit": 1},
}

# 🧬 Гибридный загрузчик настроек
class Settings:
    def __init__(self):
        self.profile = AUTO_PROFILE
        self.data: Dict[str, Any] = {}
        self._load_defaults()
        self._load_json()
        self._load_env()
        self._load_cli()
        self._apply_profile_overrides()

    def _load_defaults(self):
        self.data.update({
            "honeypot.enable": True,
            "honeypot.poll_interval": 5,
            "honeypot.port": 8080,
            "honeypot.log_path": str(LOG_DIR / "honeypot.log"),
            "honeypot.signatures": ["<script", "alert(", "onerror", "onload",
                                    "javascript:", "iframe", "<svg", "document.cookie"],
            "mutator.max_workers": 6,
            "attack_engine.threads": 6,
            "gui.theme": "dark",
            "gui.sound_alerts": True,
            "crawl.depth_limit": 2,
            "crawl.delay": 1.0,
            "crawl.user_agent": "Mozilla/5.0",
            "crawl.max_workers": 20,
            "crawl.max_links": 500,
            "crawl.max_scripts": 200,
            "crawl.domains_whitelist": [],
            "crawl.error_log": str(LOG_DIR / "crawler_errors.log"),
            "api.max_tokens": 200,
            "api.max_endpoints": 200,
            "threat.log_path": str(LOG_DIR / "threat_intel.log"),
            "threat.max_size_mb": 20,
            "export.max_line_length": 110,
        })

    def _load_json(self):
        self.data.update(SETTINGS_JSON)

    def _load_env(self):
        for key, value in os.environ.items():
            if key.startswith("XSS_"):
                normalized = key[4:].lower().replace("__", ".").replace("_", ".")
                self.data[normalized] = self._convert(value)

    def _load_cli(self):
        for arg in sys.argv[1:]:
            if arg.startswith("--") and "=" in arg:
                key, value = arg[2:].split("=", 1)
                self.data[key] = self._convert(value)

    def _apply_profile_overrides(self):
        profile_data = PROFILE_DEFAULTS.get(self.profile, {})
        for k, v in profile_data.items():
            if k not in self.data:
                self.data[k] = v

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def _convert(self, value: str) -> Any:
        v = value.strip()
        if v.lower() in ("true", "false"):
            return v.lower() == "true"
        if v.isdigit():
            return int(v)
        try:
            return float(v)
        except ValueError:
            pass
        if "," in v:
            return [x.strip() for x in v.split(",")]
        return v


# 📦 Экспортируемый объект настроек
settings = Settings()

# 🔄 Backward compatibility for legacy modules
JSON_CRAWL_EXPORT_PATH = LOG_DIR / "crawler_results.json"
LOG_SUCCESS_PATH = LOG_DIR / "success.log"
ENABLE_AUTO_TRAPS = settings.get("honeypot.enable", True)

CRAWL_DEPTH_LIMIT = settings.get("crawl.depth_limit")
CRAWL_DOMAINS_WHITELIST = settings.get("crawl.domains_whitelist")
CRAWLER_ERROR_LOG = settings.get("crawl.error_log")

PARAM_FUZZ_LOG_PATH = LOG_DIR / "param_fuzz.log"
MAX_REPORT_LINE_LENGTH = settings.get("export.max_line_length", 110)

LOG_HONEYPOT_PATH = Path(settings.get("honeypot.log_path", LOG_DIR / "honeypot.log"))
LOG_HONEYPOT_HITS = LOG_DIR / "honeypot_hits.log"

PAYLOAD_DB_PATH = BASE_DIR / "payloads" / "payloads.db"

# ➕ Новые пути для полной интеграции
DEEP_CRAWL_JSON_PATH = LOG_DIR / "deep_crawl.json"
DEEP_ANALYSIS_EXPORT_PATH = LOG_DIR / "deep_analysis_export.txt"
ATTACK_PLAN_PATH = LOG_DIR / "attack_plan.json"
ATTACK_LOGS_PATH = LOG_DIR / "attack_logs.md"
HONEYPOT_EVENTS_JSONL = LOG_DIR / "honeypot_events.jsonl"
NETWORK_LOG_PATH = LOG_DIR / "network_checks.log"

# ============================================================
#  Публичный API пакета (ULTRA 6.x)
# ============================================================

__all__ = [
    # Основные объекты
    "settings", "Settings",
    "BASE_DIR", "LOG_DIR", "EXPORT_DIR", "PDF_DIR", "PAYLOADS_DIR",

    # Пути
    "JSON_CRAWL_EXPORT_PATH", "LOG_SUCCESS_PATH",
    "ENABLE_AUTO_TRAPS", "CRAWL_DEPTH_LIMIT",
    "CRAWL_DOMAINS_WHITELIST", "CRAWLER_ERROR_LOG",
    "PARAM_FUZZ_LOG_PATH", "MAX_REPORT_LINE_LENGTH",
    "LOG_HONEYPOT_PATH", "LOG_HONEYPOT_HITS",
    "PAYLOAD_DB_PATH",
    "DEEP_CRAWL_JSON_PATH", "DEEP_ANALYSIS_EXPORT_PATH",
    "ATTACK_PLAN_PATH", "ATTACK_LOGS_PATH",
    "HONEYPOT_EVENTS_JSONL", "NETWORK_LOG_PATH",

    # Парсер DOM
    "DOMParser",

    # ➕ Новые улучшенные модули ULTRA 6.x
    "form_fuzzer",
    "http_headers",
    "payload_mutator",
    "risk_classifier",
    "honeypot_monitor",
]