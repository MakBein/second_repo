# xss_security_gui/config.py
"""
Config ULTRA 6.0
Гибридный загрузчик настроек для XSS Security Suite:
- settings.json внутри пакета
- безопасная обработка ошибок
- единый API get_setting(section, key)
"""

import json
import os
from pathlib import Path
from typing import Any, Dict

BASE_DIR = Path(__file__).parent
SETTINGS_PATH = BASE_DIR / "settings.json"


def _load_settings() -> Dict[str, Any]:
    """Загружает настройки из settings.json внутри пакета xss_security_gui."""
    if not SETTINGS_PATH.exists():
        print(f"[⚠️ Config] settings.json не найден ({SETTINGS_PATH}) — используем пустые настройки")
        return {}
    try:
        with open(SETTINGS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[⚠️ Config] Ошибка загрузки settings.json: {e}")
        return {}


# Кэш настроек
_settings: Dict[str, Any] = _load_settings()


def reload_settings() -> None:
    """Перезагружает настройки из файла (если он изменился)."""
    global _settings
    _settings = _load_settings()


def get_setting(section: str, key: str | None = None, *, default: Any = None) -> Any:
    """
    Получает настройку из settings.json.
    - Если указан только section → вернёт весь словарь секции.
    - Если указан section и key → вернёт конкретное значение.
    - Если значение отсутствует → вернёт default.
    """
    section_data = _settings.get(section, {})
    if key is None:
        return section_data or default
    return section_data.get(key, default)