# xss_security_gui/config_loader.py
"""
Config Loader ULTRA 7.0

Универсальный загрузчик конфигураций и результатов для XSS Security Suite:
- settings.json
- crawler_results.json
- безопасная загрузка любых JSON-файлов
- строгая типизация
- автоматическое создание директорий
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, TypeVar, Union

# Универсальные пути
from xss_security_gui.settings import SETTINGS_JSON_PATH, crawler_results_path


T = TypeVar("T")


# ============================================================
#  Internal helpers
# ============================================================

def _ensure_dir(path: Path) -> None:
    """Гарантирует, что директория существует."""
    if not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)


def _safe_load_json(path: Path, default: T) -> T:
    """
    Безопасно загружает JSON.
    Возвращает default при любой ошибке.
    """
    _ensure_dir(path)

    if not path.exists():
        print(f"⚠️ Файл не найден: {path}")
        return default

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, type(default)) else default
    except Exception as e:
        print(f"⚠️ Ошибка загрузки {path}: {e}")
        return default


def _safe_save_json(path: Path, data: Any) -> bool:
    """
    Безопасно сохраняет JSON.
    Возвращает True/False.
    """
    try:
        _ensure_dir(path)
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"⚠️ Ошибка сохранения {path}: {e}")
        return False


# ============================================================
#  Public API
# ============================================================

def load_settings() -> Dict[str, Any]:
    """Загружает настройки из settings.json."""
    return _safe_load_json(SETTINGS_JSON_PATH, default={})


def save_settings(data: Dict[str, Any]) -> bool:
    """Сохраняет настройки в settings.json."""
    return _safe_save_json(SETTINGS_JSON_PATH, data)


def load_crawler_results() -> List[Dict[str, Any]]:
    """Загружает результаты краулера из crawler_results.json."""
    return _safe_load_json(crawler_results_path(), default=[])


def save_crawler_results(results: List[Dict[str, Any]]) -> bool:
    """Сохраняет результаты краулера."""
    return _safe_save_json(crawler_results_path(), results)


# ============================================================
#  Generic loader for any module
# ============================================================

def load_json(path: Union[str, Path], default: T) -> T:
    """Универсальная безопасная загрузка JSON."""
    return _safe_load_json(Path(path), default)


def save_json(path: Union[str, Path], data: Any) -> bool:
    """Универсальное безопасное сохранение JSON."""
    return _safe_save_json(Path(path), data)