# xss_security_gui/config.py
"""
Config ULTRA 6.5
Гибридный загрузчик настроек для XSS Security Suite:
- Ищет settings.json в target/, затем в корне пакета
- Безопасная обработка ошибок
- Единый API get_setting(section, key)
"""

import json
from pathlib import Path
from typing import Any, Dict

BASE_DIR = Path(__file__).resolve().parent
CONFIGS_DIR = BASE_DIR / "target"

SETTINGS_PATH = CONFIGS_DIR / "settings.json"

_settings: Dict[str, Any] = {}


def _safe_load_json(path: Path) -> Dict[str, Any]:
    """Безопасная загрузка JSON с обработкой ошибок."""
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)

    except FileNotFoundError:
        print(f"[⚠️ Config] settings.json не найден: {path}")

    except json.JSONDecodeError as e:
        print(f"[⚠️ Config] Ошибка JSON в {path}: {e}")

    except Exception as e:
        print(f"[⚠️ Config] Ошибка загрузки {path}: {e}")

    return {}


def _load_settings() -> Dict[str, Any]:
    """Загружает настройки ТОЛЬКО из target/settings.json."""
    if SETTINGS_PATH.exists():
        data = _safe_load_json(SETTINGS_PATH)
        if data:
            return data
        print(f"[⚠️ Config] settings.json найден, но пустой или поврежден: {SETTINGS_PATH}")
    else:
        print(f"[⚠️ Config] settings.json отсутствует: {SETTINGS_PATH}")

    return {}


def reload_settings() -> None:
    """Перезагружает настройки."""
    global _settings
    _settings = _load_settings()


def get_setting(section: str, key: str | None = None, *, default: Any = None) -> Any:
    """Универсальный доступ к настройкам."""
    global _settings

    if not _settings:
        _settings = _load_settings()

    section_data = _settings.get(section)

    if not isinstance(section_data, dict):
        return default

    if key is None:
        return section_data or default

    return section_data.get(key, default)