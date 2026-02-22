# xss_security_gui/settings.py
"""
Settings ULTRA Hybrid 6.5
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

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

from dotenv import load_dotenv

from xss_security_gui.sandbox_detector import detect_sandbox
from xss_security_gui.dom_parser import DOMParser


# ============================================================
#  Базовые директории
# ============================================================

BASE_DIR: Path = Path(__file__).parent.resolve()
LOG_DIR: Path = BASE_DIR / "logs"
EXPORT_DIR: Path = BASE_DIR / "exports"
PDF_DIR: Path = EXPORT_DIR / "reports"
PAYLOADS_DIR: Path = BASE_DIR / "payloads"
CONFIG_DIR: Path = BASE_DIR / "configs"


for d in (LOG_DIR, EXPORT_DIR, PDF_DIR, PAYLOADS_DIR, CONFIG_DIR):
    d.mkdir(parents=True, exist_ok=True)

# ============================================================
#  Загрузка .env
# ============================================================

ENV_PATH = BASE_DIR / ".env"
if ENV_PATH.exists():
    load_dotenv(ENV_PATH)

# ============================================================
#  Загрузка settings.json
# ============================================================

SETTINGS_JSON_PATH = CONFIG_DIR / "settings.json"
SETTINGS_JSON: Dict[str, Any] = {}
if SETTINGS_JSON_PATH.exists():
    try:
        with open(SETTINGS_JSON_PATH, encoding="utf-8") as f:
            SETTINGS_JSON = json.load(f)
    except Exception as e:
        print(f"[Settings] Ошибка загрузки settings.json: {e}")
        SETTINGS_JSON = {}

# ============================================================
#  Автоопределение окружения
# ============================================================

_sandbox_info = detect_sandbox()
if _sandbox_info.get("sandboxed"):
    AUTO_PROFILE = "sandbox"
elif any(k in os.environ for k in ["CI", "GITHUB_ACTIONS", "GITLAB_CI"]):
    AUTO_PROFILE = "ci"
else:
    AUTO_PROFILE = os.getenv("APP_PROFILE", "dev")

# ============================================================
#  Профили конфигурации
# ============================================================

PROFILE_DEFAULTS = {
    "dev": {
        "logging.level": "DEBUG",
        "gui.theme": "dark",
        "mutator.max_workers": 8,
        "attack_engine.threads": 6,
        "crawl.depth_limit": 3,
    },
    "prod": {
        "logging.level": "INFO",
        "gui.theme": "light",
        "mutator.max_workers": 12,
        "attack_engine.threads": 10,
        "crawl.depth_limit": 2,
    },
    "sandbox": {
        "logging.level": "WARNING",
        "gui.theme": "dark",
        "mutator.max_workers": 2,
        "attack_engine.threads": 1,
        "crawl.depth_limit": 1,
    },
    "ci": {
        "logging.level": "ERROR",
        "gui.theme": "minimal",
        "mutator.max_workers": 1,
        "attack_engine.threads": 1,
        "crawl.depth_limit": 1,
    },
}


# ============================================================
#  Класс гибридных настроек
# ============================================================

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
            # Honeypot
            "honeypot.enable": True,
            "honeypot.poll_interval": 5,
            "honeypot.port": 8080,
            "honeypot.log_path": str(LOG_DIR / "honeypot.log"),
            "honeypot.hits_log_path": str(LOG_DIR / "honeypot_hits.log"),
            "honeypot.signatures": [
                "<script", "alert(", "onerror", "onload",
                "javascript:", "iframe", "<svg", "document.cookie"
            ],

            # GUI / общие
            "mutator.max_workers": 6,
            "attack_engine.threads": 6,
            "gui.theme": "dark",
            "gui.sound_alerts": True,

            # Crawler
            "crawl.depth_limit": 2,
            "crawl.delay": 1.0,
            "crawl.user_agent": "Mozilla/5.0",
            "crawl.max_workers": 20,
            "crawl.max_links": 500,
            "crawl.max_scripts": 200,
            "crawl.domains_whitelist": [],
            "crawl.error_log": str(LOG_DIR / "crawler_errors.log"),

            # API
            "api.max_tokens": 200,
            "api.max_endpoints": 200,

            # Threat Intel / экспорт
            "threat.log_path": str(LOG_DIR / "threat_intel.log"),
            "threat.max_size_mb": 20,
            "export.max_line_length": 110,

            # HTTP / сетевые дефолты
            "http.request_timeout": 7,
            "http.default_user_agent": "XSS-Security-GUI/6.5",

            # IDOR
            "idor.delay": 0.5,

            # LFI
            "lfi.delay": 0.5,
            "lfi.payloads": [
                "../../etc/passwd",
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "..%2f..%2fetc%2fpasswd",
                "..\\..\\windows\\win.ini",
                "/etc/passwd",
                "..%252f..%252fetc%252fpasswd",
            ],
            "lfi.signatures": [
                "root:x",          # /etc/passwd
                "[extensions]",    # win.ini
                "[fonts]",
                "[drivers]",
            ],

            # SQLi
            "sqli.error_indicators": [
                "sql syntax", "mysql", "postgres", "sqlite", "odbc",
                "warning", "fatal error", "unclosed quotation mark",
                "unexpected end of input", "query failed",
                "native client", "syntax error", "invalid query",
                "unexpected token", "unterminated string", "invalid column",
            ],
            "sqli.waf_indicators": [
                "waf", "blocked", "forbidden", "security", "mod_security",
                "access denied", "firewall", "request rejected",
            ],

            # SSRF
            "ssrf.body_indicators": [
                "169.254.", "metadata", "ec2", "internal", "localhost", "127.0.0.1",
                "google.internal", "azure", "gcp", "aws", "openstack",
                "file://", "ftp://", "unix://",
            ],
            "ssrf.header_indicators": [
                "via", "x-forwarded-for", "x-aws-", "metadata", "x-real-ip",
            ],

            # Payload files
            "payloads.sqli_file": str(PAYLOADS_DIR / "sqli.json"),
            "payloads.xss_file": str(PAYLOADS_DIR / "xss.json"),
            "payloads.ssrf_file": str(PAYLOADS_DIR / "ssrf.json"),

            # Threat Intel artifacts
            "threat.artifact_path": str(LOG_DIR / "threat_intel_artifact.json"),
        })

    def _load_json(self):
        # settings.json может быть как плоским, так и вложенным — просто мержим
        self.data.update(SETTINGS_JSON)

    def _load_env(self):
        # Только XSS_* переменные маппятся в настройки
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

# ============================================================
#  Backward compatibility + удобные алиасы
# ============================================================

JSON_CRAWL_EXPORT_PATH = LOG_DIR / "crawler_results.json"
LOG_SUCCESS_PATH = LOG_DIR / "success.log"
ENABLE_AUTO_TRAPS = settings.get("honeypot.enable", True)

CRAWL_DEPTH_LIMIT = settings.get("crawl.depth_limit")
CRAWL_DOMAINS_WHITELIST = settings.get("crawl.domains_whitelist")
CRAWLER_ERROR_LOG = settings.get("crawl.error_log")

PARAM_FUZZ_LOG_PATH = LOG_DIR / "form_fuzz_hits.log"   # исправлено
MAX_REPORT_LINE_LENGTH = settings.get("export.max_line_length", 110)

LOG_HONEYPOT_PATH = Path(settings.get("honeypot.log_path", LOG_DIR / "honeypot.log"))
LOG_HONEYPOT_HITS = LOG_DIR / "honeypot_hits.log"

THREAT_LOG_PATH = LOG_DIR / "threat_intel.log"         # добавлено

PAYLOAD_DB_PATH = BASE_DIR / "payloads" / "payloads.db"

DEEP_CRAWL_JSON_PATH = LOG_DIR / "deep_crawl.json"
DEEP_ANALYSIS_EXPORT_PATH = LOG_DIR / "deep_analysis_export.txt"
ATTACK_PLAN_PATH = LOG_DIR / "attack_plan.json"
ATTACK_LOGS_PATH = LOG_DIR / "attack_logs.md"
HONEYPOT_EVENTS_JSONL = LOG_DIR / "honeypot_events.jsonl"
NETWORK_LOG_PATH = LOG_DIR / "network_checks.log"
GUI_STATE_PATH = LOG_DIR / "gui_state.json"

# ============================================================
#  Функции для универсальных путей
# ============================================================

def crawler_results_path() -> Path:
    """
    Возвращает универсальный путь к crawler_results.json.
    Используется в main.py, overview_tab.py и других модулях.
    """
    return LOG_DIR / "crawler_results.json"


# ============================================================
#  ULTRA 6.5 — Автоматический валидатор настроек
# ============================================================

class SettingsValidator:
    REQUIRED_STRUCTURE = {
        "gui": {
            # мы валидируем через export.max_line_length, но секцию оставим для будущего расширения
        },
        "honeypot": {
            "enable": bool,
            "poll_interval": int,
            "log_path": str,
            "hits_log_path": str,
        },
        "http": {
            "request_timeout": int,
            "default_user_agent": str,
        },
        "idor": {
            "delay": float,
        },
        "lfi": {
            "delay": float,
            "payloads": list,
            "signatures": list,
        },
        "sqli": {
            "error_indicators": list,
            "waf_indicators": list,
        },
        "ssrf": {
            "body_indicators": list,
            "header_indicators": list,
        },
        "payloads": {
            "sqli_file": str,
            "xss_file": str,
            "ssrf_file": str,
        },
        "threat": {
            "artifact_path": str,
            "log_path": str,
            "max_size_mb": int,
        },
        "export": {
            "max_line_length": int,
        },
    }

    @classmethod
    def validate(cls, data: dict) -> list[str]:
        errors: list[str] = []

        for section, fields in cls.REQUIRED_STRUCTURE.items():
            for key, expected_type in fields.items():
                full_key = f"{section}.{key}"
                if full_key not in data:
                    errors.append(f"Отсутствует ключ: {full_key}")
                    continue

                value = data[full_key]
                if not isinstance(value, expected_type):
                    errors.append(
                        f"Неверный тип: {full_key} "
                        f"(ожидалось {expected_type.__name__}, получено {type(value).__name__})"
                    )

        return errors


# === Запуск валидатора на итоговых settings.data ===
validator_errors = SettingsValidator.validate(settings.data)

if validator_errors:
    print("\n[⚠️ Settings Validator] Обнаружены проблемы в конфигурации:")
    for err in validator_errors:
        print(" -", err)
    print("[⚠️] Используются дефолтные значения там, где возможно.\n")

# ============================================================
#  Удобные алиасы для новых модулей
# ============================================================

REQUEST_TIMEOUT = settings.get("http.request_timeout", 7)
DEFAULT_USER_AGENT = settings.get("http.default_user_agent", "XSS-Security-GUI/6.5")

IDOR_DELAY = settings.get("idor.delay", 0.5)

LFI_DELAY = settings.get("lfi.delay", 0.5)
LFI_PAYLOADS = settings.get("lfi.payloads")
LFI_SIGNATURES = settings.get("lfi.signatures")

SQLI_ERROR_INDICATORS = settings.get("sqli.error_indicators")
SQLI_WAF_INDICATORS = settings.get("sqli.waf_indicators")

SSRF_BODY_INDICATORS = settings.get("ssrf.body_indicators")
SSRF_HEADER_INDICATORS = settings.get("ssrf.header_indicators")

SQLI_PAYLOAD_FILE = settings.get("payloads.sqli_file")
XSS_PAYLOAD_FILE = settings.get("payloads.xss_file")
SSRF_PAYLOAD_FILE = settings.get("payloads.ssrf_file")

THREAT_INTEL_ARTIFACT_PATH = Path(settings.get("threat.artifact_path"))

# ============================================================
#  Публичный API пакета (ULTRA 6.x)
# ============================================================

__all__ = [
    "settings", "Settings",
    "BASE_DIR", "LOG_DIR", "EXPORT_DIR", "PDF_DIR", "PAYLOADS_DIR",

    "JSON_CRAWL_EXPORT_PATH", "LOG_SUCCESS_PATH",
    "ENABLE_AUTO_TRAPS", "CRAWL_DEPTH_LIMIT",
    "CRAWL_DOMAINS_WHITELIST", "CRAWLER_ERROR_LOG",
    "PARAM_FUZZ_LOG_PATH", "MAX_REPORT_LINE_LENGTH",
    "LOG_HONEYPOT_PATH", "LOG_HONEYPOT_HITS",
    "PAYLOAD_DB_PATH",
    "DEEP_CRAWL_JSON_PATH", "DEEP_ANALYSIS_EXPORT_PATH",
    "ATTACK_PLAN_PATH", "ATTACK_LOGS_PATH",
    "HONEYPOT_EVENTS_JSONL", "NETWORK_LOG_PATH",

    "DOMParser",

    # Новые алиасы
    "REQUEST_TIMEOUT", "DEFAULT_USER_AGENT",
    "IDOR_DELAY",
    "LFI_DELAY", "LFI_PAYLOADS", "LFI_SIGNATURES",
    "SQLI_ERROR_INDICATORS", "SQLI_WAF_INDICATORS",
    "SSRF_BODY_INDICATORS", "SSRF_HEADER_INDICATORS",
    "SQLI_PAYLOAD_FILE", "XSS_PAYLOAD_FILE", "SSRF_PAYLOAD_FILE",
    "THREAT_INTEL_ARTIFACT_PATH", "crawler_results_path",

]