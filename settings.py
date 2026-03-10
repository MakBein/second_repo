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
from typing import Any, Dict, List

from dotenv import load_dotenv

from xss_security_gui.sandbox_detector import detect_sandbox

# По умолчанию — безопасный режим: реальные запросы запрещены
ALLOW_REAL_RUN = True

# Белый список доменов, на которые разрешено выполнять реальные запросы
ALLOWED_TARGETS = [
    "gazprombank.ru",
]


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

# === Honeypot / Trap Engine ===
TRAP_WEBHOOK_URL = os.getenv("TRAP_WEBHOOK_URL", "")


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
    """
    Гибридный конфиг:
    - дефолты
    - settings.json
    - .env (XSS_*)
    - CLI (--key=value)
    - профили dev/prod/sandbox/ci
    """

    # Ключи, которые по смыслу должны быть списками
    LIST_KEYS: set[str] = {
        "crawl.domains_whitelist",
        "lfi.payloads",
        "lfi.signatures",
        "sqli.error_indicators",
        "sqli.waf_indicators",
        "ssrf.body_indicators",
        "ssrf.header_indicators",
    }

    # Плоские ключи ↔ точечные
    _KEY_ALIASES = {
        "ENABLE_AUTO_TRAPS": "honeypot.enable",
        "HONEYPOT_POLL_INTERVAL": "honeypot.poll_interval",
        "DEFAULT_TRAP_TYPE": "gui.default_trap_type",
    }
    _KEY_ALIASES_REVERSE = {v: k for k, v in _KEY_ALIASES.items()}

    def __init__(self) -> None:
        self.profile = AUTO_PROFILE
        self.data: Dict[str, Any] = {}
        self._load_defaults()
        self._load_json()
        self._load_env()
        self._load_cli()
        self._apply_profile_overrides()

    def _load_defaults(self) -> None:
        self.data.update(
            {
                # Honeypot
                "honeypot.enable": True,
                "honeypot.poll_interval": 5,
                "honeypot.port": 8080,
                "honeypot.log_path": str(LOG_DIR / "honeypot.log"),
                "honeypot.hits_log_path": str(LOG_DIR / "honeypot_hits.log"),
                "honeypot.signatures": [
                    "<script",
                    "alert(",
                    "onerror",
                    "onload",
                    "javascript:",
                    "iframe",
                    "<svg",
                    "document.cookie",
                ],
                # GUI / общие
                "mutator.max_workers": 6,
                "attack_engine.threads": 6,
                "gui.theme": "dark",
                "gui.sound_alerts": True,
                "gui.default_trap_type": "js",
                # Crawler
                "crawl.depth_limit": 2,
                "crawl.delay": 1.0,
                "crawl.user_agent": "Mozilla/5.0",
                "crawl.max_workers": 20,
                "crawl.max_links": 500,
                "crawl.max_scripts": 200,
                "crawl.max_links_per_page": 500,
                "crawl.max_scripts_per_page": 200,
                "crawl.max_rps": 2.0,
                "crawl.max_matches_per_key": 200,
                "crawl.max_api_endpoints": 200,
                "crawl.domains_whitelist": [],
                "crawl.error_log": str(LOG_DIR / "crawler_errors.log"),
                # Crawler / JS detection
                "crawler.enable_graphql_detection": True,
                "js.enable_dynamic_detection": True,
                "js.enable_framework_detection": True,
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
                "http.aggressive_headers": True,
                "http.proxies": None,
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
                    "root:x",  # /etc/passwd
                    "[extensions]",  # win.ini
                    "[fonts]",
                    "[drivers]",
                ],
                # SQLi
                "sqli.error_indicators": [
                    "sql syntax",
                    "mysql",
                    "postgres",
                    "sqlite",
                    "odbc",
                    "warning",
                    "fatal error",
                    "unclosed quotation mark",
                    "unexpected end of input",
                    "query failed",
                    "native client",
                    "syntax error",
                    "invalid query",
                    "unexpected token",
                    "unterminated string",
                    "invalid column",
                ],
                "sqli.waf_indicators": [
                    "waf",
                    "blocked",
                    "forbidden",
                    "security",
                    "mod_security",
                    "access denied",
                    "firewall",
                    "request rejected",
                ],
                # SSRF
                "ssrf.body_indicators": [
                    "169.254.",
                    "metadata",
                    "ec2",
                    "internal",
                    "localhost",
                    "127.0.0.1",
                    "google.internal",
                    "azure",
                    "gcp",
                    "aws",
                    "openstack",
                    "file://",
                    "ftp://",
                    "unix://",
                ],
                "ssrf.header_indicators": [
                    "via",
                    "x-forwarded-for",
                    "x-aws-",
                    "metadata",
                    "x-real-ip",
                ],
                # Payload files
                "payloads.sqli_file": str(PAYLOADS_DIR / "sqli.json"),
                "payloads.xss_file": str(PAYLOADS_DIR / "xss.json"),
                "payloads.ssrf_file": str(PAYLOADS_DIR / "ssrf.json"),
                "payloads.csrf_file": str(PAYLOADS_DIR / "csrf.json"),
                # Threat Intel artifacts
                "threat.artifact_path": str(LOG_DIR / "threat_intel_artifact.json"),
            }
        )

    def _load_json(self) -> None:
        """settings.json может быть плоским или вложенным — просто мержим."""
        if SETTINGS_JSON:
            self.data.update(SETTINGS_JSON)

    def _load_env(self) -> None:
        """Только XSS_* переменные маппятся в настройки."""
        for key, value in os.environ.items():
            if not key.startswith("XSS_"):
                continue
            normalized = key[4:].lower().replace("__", ".").replace("_", ".")
            self.data[normalized] = self._convert(value, normalized)

    def _load_cli(self) -> None:
        """CLI аргументы вида --key=value."""
        for arg in sys.argv[1:]:
            if arg.startswith("--") and "=" in arg:
                key, value = arg[2:].split("=", 1)
                self.data[key] = self._convert(value, key)

    def _apply_profile_overrides(self) -> None:
        """Профиль dev/prod/sandbox/ci."""
        profile_data = PROFILE_DEFAULTS.get(self.profile, {})
        for k, v in profile_data.items():
            if k not in self.data:
                self.data[k] = v

    def _convert(self, value: str, key: str | None = None) -> Any:
        """
        Безопасное приведение типов:
        - bool
        - int
        - float
        - list (только для ключей из LIST_KEYS)
        - иначе str
        """
        v = value.strip()
        low = v.lower()

        # bool
        if low in ("true", "false"):
            return low == "true"

        # int
        if v.isdigit():
            try:
                return int(v)
            except ValueError:
                pass

        # float
        try:
            float_val = float(v)
        except ValueError:
            float_val = None
        else:
            # float только если это действительно float, а не "1"
            if "." in v or "e" in low:
                return float_val

        # list — только для известных ключей
        if key in self.LIST_KEYS and "," in v:
            return [x.strip() for x in v.split(",") if x.strip()]

        # fallback: str
        return v


    def get(self, key: str, default: Any = None) -> Any:
        """
        Универсальный getter:
        - поддерживает старые плоские ключи
        - поддерживает новые точечные ключи
        - безопасен и предсказуем
        """
        # Старый плоский → новый точечный
        flat = self._KEY_ALIASES_REVERSE.get(key)
        if flat is not None and flat in self.data:
            return self.data[flat]

        # Новый ключ
        if key in self.data:
            return self.data[key]

        # Новый → старый плоский
        alias = self._KEY_ALIASES.get(key)
        if alias is not None and alias in self.data:
            return self.data[alias]

        return default


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

LOG_CRAWL_STRUCTURE_PATH = LOG_DIR / "crawl_structure.log"
LOG_CRAWL_GRAPH_DOT = LOG_DIR / "crawl_graph.dot"
LOG_CRAWL_GRAPH_SVG = LOG_DIR / "crawl_graph.svg"

PARAM_FUZZ_LOG_PATH = LOG_DIR / "form_fuzz_hits.log"
MAX_REPORT_LINE_LENGTH = settings.get("export.max_line_length", 110)

LOG_HONEYPOT_PATH = Path(settings.get("honeypot.log_path", LOG_DIR / "honeypot.log"))
LOG_HONEYPOT_HITS = LOG_DIR / "honeypot_hits.log"

THREAT_LOG_PATH = LOG_DIR / "threat_intel.log"

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
    return JSON_CRAWL_EXPORT_PATH


# ============================================================
#  Backward compatibility: CONFIG alias
# ============================================================

# CONFIG — это просто ссылка на settings.data (словарь всех настроек)
CONFIG = settings.data

# ============================================================
#  ULTRA 6.5 — Автоматический валидатор настроек
# ============================================================

class SettingsValidator:
    REQUIRED_STRUCTURE = {
        "gui": {
            "theme": str,
            "sound_alerts": bool,
            "default_trap_type": str,
        },
        "honeypot": {
            "enable": bool,
            "poll_interval": int,
            "log_path": str,
            "hits_log_path": str,
        },
        "crawl": {
            "depth_limit": int,
            "error_log": str,
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
    def validate(cls, data: dict) -> List[str]:
        errors: List[str] = []

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

                if expected_type is int and isinstance(value, int) and value < 0:
                    errors.append(f"Недопустимое значение: {full_key} < 0")

                if expected_type is str and isinstance(value, str) and not value.strip():
                    errors.append(f"Пустая строка: {full_key}")

        return errors


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
CSRF_PAYLOAD_FILE = settings.get("payloads.csrf_file")
THREAT_INTEL_ARTIFACT_PATH = Path(settings.get("threat.artifact_path"))


# ============================================================
#  Обратная совместимость: атрибуты на объекте settings
# ============================================================


def _attach_settings_aliases() -> None:
    """
    Автоматически привязывает алиасы путей и констант к объекту settings
    для совместимости: settings.LOG_DIR, settings.REQUEST_TIMEOUT и т.д.
    """
    g = globals()
    for name, value in g.items():
        if not name.isupper():
            continue
        if name.startswith("_"):
            continue
        # CONFIG и подобные — не дублируем
        if name in {"CONFIG"}:
            continue
        setattr(settings, name, value)


_attach_settings_aliases()


# ============================================================
#  Публичный API пакета (ULTRA 6.x)
# ============================================================

_PUBLIC_EXPORTS = [
    "settings",
    "Settings",
    "CONFIG",
    "BASE_DIR",
    "LOG_DIR",
    "EXPORT_DIR",
    "PDF_DIR",
    "PAYLOADS_DIR",
    "CONFIG_DIR",
    "SETTINGS_JSON_PATH",
    "SETTINGS_JSON",
    "JSON_CRAWL_EXPORT_PATH",
    "LOG_SUCCESS_PATH",
    "ENABLE_AUTO_TRAPS",
    "CRAWL_DEPTH_LIMIT",
    "CRAWL_DOMAINS_WHITELIST",
    "CRAWLER_ERROR_LOG",
    "PARAM_FUZZ_LOG_PATH",
    "MAX_REPORT_LINE_LENGTH",
    "LOG_HONEYPOT_PATH",
    "LOG_HONEYPOT_HITS",
    "THREAT_LOG_PATH",
    "PAYLOAD_DB_PATH",
    "DEEP_CRAWL_JSON_PATH",
    "DEEP_ANALYSIS_EXPORT_PATH",
    "ATTACK_PLAN_PATH",
    "ATTACK_LOGS_PATH",
    "HONEYPOT_EVENTS_JSONL",
    "NETWORK_LOG_PATH",
    "GUI_STATE_PATH",
    "LOG_CRAWL_STRUCTURE_PATH",
    "LOG_CRAWL_GRAPH_DOT",
    "LOG_CRAWL_GRAPH_SVG",
    "REQUEST_TIMEOUT",
    "DEFAULT_USER_AGENT",
    "IDOR_DELAY",
    "LFI_DELAY",
    "LFI_PAYLOADS",
    "LFI_SIGNATURES",
    "SQLI_ERROR_INDICATORS",
    "SQLI_WAF_INDICATORS",
    "SSRF_BODY_INDICATORS",
    "SSRF_HEADER_INDICATORS",
    "SQLI_PAYLOAD_FILE",
    "XSS_PAYLOAD_FILE",
    "SSRF_PAYLOAD_FILE",
    "CSRF_PAYLOAD_FILE",
    "THREAT_INTEL_ARTIFACT_PATH",
    "crawler_results_path",
    "TRAP_WEBHOOK_URL",
]

__all__ = _PUBLIC_EXPORTS