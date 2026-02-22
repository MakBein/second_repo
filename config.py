# xss_security_gui/config.py
"""
Config ULTRA 6.5
Гибридный загрузчик настроек для XSS Security Suite:
- Ищет settings.json в configs/, затем в корне пакета
- Безопасная обработка ошибок
- Единый API get_setting(section, key)
"""

import json
from pathlib import Path
from typing import Any, Dict

BASE_DIR = Path(__file__).parent
CONFIGS_DIR = BASE_DIR / "configs"

# Основные пути
PRIMARY_SETTINGS = CONFIGS_DIR / "settings.json"
FALLBACK_SETTINGS = BASE_DIR / "settings.json"


def _safe_load_json(path: Path) -> Dict[str, Any]:
    """Безопасная загрузка JSON с обработкой ошибок."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[⚠️ Config] settings.json не найден ({path})")
    except json.JSONDecodeError as e:
        print(f"[⚠️ Config] Ошибка JSON в {path}: {e}")
    except Exception as e:
        print(f"[⚠️ Config] Ошибка загрузки {path}: {e}")
    return {}


def _load_settings() -> Dict[str, Any]:
    """Загружает настройки из configs/settings.json или fallback."""
    # 1) configs/settings.json
    if PRIMARY_SETTINGS.exists():
        return _safe_load_json(PRIMARY_SETTINGS)

    # 2) fallback: settings.json в корне пакета
    if FALLBACK_SETTINGS.exists():
        return _safe_load_json(FALLBACK_SETTINGS)

    print("[⚠️ Config] settings.json не найден ни в configs/, ни в корне — используем пустые настройки")
    return {}


# Кэш настроек
_settings: Dict[str, Any] = _load_settings()


def reload_settings() -> None:
    """Перезагружает настройки из файла."""
    global _settings
    _settings = _load_settings()


def get_setting(section: str, key: str | None = None, *, default: Any = None) -> Any:
    """
    Получает настройку из settings.json.
    - Если указан только section → вернёт весь словарь секции.
    - Если указан section и key → вернёт конкретное значение.
    - Если значение отсутствует → вернёт default.
    """
    section_data = _settings.get(section)

    if not isinstance(section_data, dict):
        return default

    if key is None:
        return section_data or default

    return section_data.get(key, default)