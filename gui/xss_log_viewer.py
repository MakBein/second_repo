# xss_security_gui/gui/xss_log_viewer.py
"""
XSS Log Viewer ULTRA 6.0
------------------------
• Читает NDJSON лог отражённых XSS
• Даёт сводку по категориям
• Даёт детальный список
• Поддерживает фильтрацию и сортировку
• Готов для GUI-интеграции
"""

import json
import threading
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import Counter

from xss_security_gui.config_manager import LOGS_DIR

# Директория и файл логов
LOG_DIR: Path = LOGS_DIR / "xss"
LOG_FILE: Path = LOG_DIR / "reflected_responses.json"

LOG_DIR.mkdir(parents=True, exist_ok=True)
_write_lock = threading.Lock()


def rotate_if_big(path: Path, max_mb: int = 20) -> None:
    """Ротирует файл, если он превышает max_mb мегабайт."""
    try:
        if path.exists() and path.stat().st_size > max_mb * 1024 * 1024:
            ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup = path.with_suffix(path.suffix + f".{ts}.bak")
            path.rename(backup)
    except Exception as e:
        print(f"[XSSLogViewer] Ошибка ротации: {e}")


def load_ndjson(path: Path) -> List[Dict[str, Any]]:
    """Безопасная загрузка NDJSON."""
    items: List[Dict[str, Any]] = []
    if not path.exists():
        return items

    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[XSSLogViewer] Ошибка чтения NDJSON: {e}")

    return items


class XSSLogViewer:
    """
    Класс для работы с логами XSS:
    • загрузка
    • сводка
    • фильтрация
    • сортировка
    • интеграция с GUI
    """

    def __init__(self, gui_callback: Optional[callable] = None):
        self.gui_callback = gui_callback

    # ---------------------------------------------------------
    # Вспомогательный метод для безопасного вызова callback
    # ---------------------------------------------------------
    def _emit(self, key: str, payload: Any) -> None:
        if self.gui_callback:
            try:
                self.gui_callback({key: payload})
            except Exception as e:
                print(f"[XSSLogViewer] Ошибка gui_callback: {e}")

    # ---------------------------------------------------------
    # Загрузка логов
    # ---------------------------------------------------------
    def load(self, path: Path = LOG_FILE) -> List[Dict[str, Any]]:
        """Загружает логи XSS из NDJSON."""
        rotate_if_big(path)
        return load_ndjson(path)

    # ---------------------------------------------------------
    # Сводка по категориям
    # ---------------------------------------------------------
    def summarize(self, items: List[Dict[str, Any]]) -> Dict[str, int]:
        """Возвращает сводку по категориям."""
        severities = [r.get("category", "unknown") for r in items]
        return dict(Counter(severities))

    # ---------------------------------------------------------
    # Фильтрация
    # ---------------------------------------------------------
    def filter_by_category(self, items: List[Dict[str, Any]], category: str) -> List[Dict[str, Any]]:
        """Фильтрует артефакты по категории."""
        return [r for r in items if r.get("category") == category]

    def filter_by_url(self, items: List[Dict[str, Any]], url: str) -> List[Dict[str, Any]]:
        """Фильтрует артефакты по URL."""
        return [r for r in items if r.get("url") == url]

    # ---------------------------------------------------------
    # Сортировка
    # ---------------------------------------------------------
    def sort_by_timestamp(self, items: List[Dict[str, Any]], reverse: bool = True) -> List[Dict[str, Any]]:
        """Сортирует артефакты по времени."""
        def parse_ts(x: Dict[str, Any]) -> datetime.datetime:
            ts = x.get("_ts")
            try:
                return datetime.datetime.fromisoformat(ts)
            except Exception:
                return datetime.datetime.min

        return sorted(items, key=parse_ts, reverse=reverse)

    # ---------------------------------------------------------
    # GUI: сводка
    # ---------------------------------------------------------
    def render_summary(self) -> Dict[str, Any]:
        """Формирует сводку для GUI."""
        items = self.load()
        summary = self.summarize(items)

        data = {
            "total": len(items),
            "by_category": summary,
        }

        self._emit("xss_log_summary", data)
        return data

    # ---------------------------------------------------------
    # GUI: детальный список
    # ---------------------------------------------------------
    def render_details(self, limit: int = 50, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """Формирует детальный список артефактов для GUI."""
        items = self.load()
        items = self.sort_by_timestamp(items)

        if category:
            items = self.filter_by_category(items, category)

        sliced = items[:limit]
        self._emit("xss_log_details", sliced)
        return sliced

    # ---------------------------------------------------------
    # Поиск
    # ---------------------------------------------------------
    def search(self, keyword: str) -> List[Dict[str, Any]]:
        """Ищет артефакты по ключевому слову в URL или ответе."""
        items = self.load()
        keyword = keyword.lower()

        return [
            r for r in items
            if keyword in r.get("url", "").lower()
            or keyword in r.get("full_response", "").lower()
        ]