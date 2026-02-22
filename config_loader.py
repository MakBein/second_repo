# xss_security_gui/config_loader.py
"""
Config Loader ULTRA 6.0
Загрузчик конфигураций и результатов для XSS Security Suite:
- settings.json
- crawler_results.json
"""

import json
from pathlib import Path
from typing import Any, Dict, List

# Импортируем универсальные пути
from xss_security_gui.config_manager import SETTINGS_JSON_PATH, CRAWLER_RESULTS_PATH


def _safe_load_json(path: Path, default: Any) -> Any:
    """Безопасно загружает JSON, возвращает default при ошибке."""
    if not path.exists():
        print(f"⚠️ Файл не найден: {path}")
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ Ошибка загрузки {path}: {e}")
        return default


def load_settings() -> Dict[str, Any]:
    """Загружает настройки из settings.json."""
    return _safe_load_json(SETTINGS_JSON_PATH, default={})


def load_crawler_results() -> List[Dict[str, Any]]:
    """Загружает результаты краулера из crawler_results.json."""
    return _safe_load_json(CRAWLER_RESULTS_PATH, default=[])