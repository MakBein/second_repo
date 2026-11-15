# xss_security_gui/file_loader.py
"""
File Loader ULTRA 7.0

Универсальный загрузчик файлов для XSS Security Suite:
- безопасная загрузка текстовых файлов
- безопасная загрузка/сохранение JSON
- автоматическое создание logs/
- строгая типизация
- поддержка больших файлов
"""

from __future__ import annotations

import os
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, TypeVar


BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"

T = TypeVar("T")


# ============================================================
#  Internal helpers
# ============================================================

def ensure_logs_dir() -> None:
    """Гарантирует, что директория logs/ существует."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


def _safe_read_text(path: Path, default: str) -> str:
    """Безопасно читает текстовый файл."""
    if not path.exists():
        return default
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"[⚠️] Ошибка чтения {path.name}: {e}")
        return default


def _safe_load_json(path: Path, default: T) -> T:
    """Безопасно загружает JSON, возвращает default при ошибке."""
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, type(default)) else default
    except Exception as e:
        print(f"[⚠️] Ошибка загрузки JSON {path.name}: {e}")
        return default


def _safe_save_json(path: Path, data: Any) -> bool:
    """Безопасно сохраняет JSON."""
    try:
        ensure_logs_dir()
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"[⚠️] Ошибка сохранения JSON {path.name}: {e}")
        return False


# ============================================================
#  Public API
# ============================================================

def load_file(filename: str, default: str = "") -> str:
    """
    Загружает текстовый файл из logs/.
    Если файла нет — возвращает default.
    """
    ensure_logs_dir()
    path = LOGS_DIR / filename
    return _safe_read_text(path, default)


def load_json(filename: str, default: Optional[T] = None) -> T:
    """
    Загружает JSON из logs/.
    Если файла нет — возвращает default или {}.
    """
    ensure_logs_dir()
    path = LOGS_DIR / filename
    if default is None:
        default = {}  # type: ignore
    return _safe_load_json(path, default)


def save_json(filename: str, data: Any) -> bool:
    """
    Сохраняет JSON в logs/.
    Возвращает True/False.
    """
    ensure_logs_dir()
    path = LOGS_DIR / filename
    return _safe_save_json(path, data)


# ============================================================
#  Extra helpers (ULTRA)
# ============================================================

def list_logs() -> List[str]:
    """Возвращает список всех файлов в logs/."""
    ensure_logs_dir()
    return sorted([p.name for p in LOGS_DIR.iterdir() if p.is_file()])


def delete_log(filename: str) -> bool:
    """Удаляет файл из logs/."""
    try:
        path = LOGS_DIR / filename
        if path.exists():
            path.unlink()
        return True
    except Exception as e:
        print(f"[⚠️] Ошибка удаления {filename}: {e}")
        return False


def load_or_create_json(filename: str, default: T) -> T:
    """
    Загружает JSON или создаёт файл с default, если его нет.
    """
    ensure_logs_dir()
    path = LOGS_DIR / filename
    if not path.exists():
        _safe_save_json(path, default)
        return default
    return _safe_load_json(path, default)