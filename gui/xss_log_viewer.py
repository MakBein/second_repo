# xss_security_gui/auto_recon/xss_log_viewer.py

import os
import json
import threading
import datetime
from typing import List, Dict, Any, Optional

# Универсальные пути пакета
from xss_security_gui import DIRS

# Директория и файл логов
LOG_DIR = os.path.join(DIRS["logs"], "xss")
LOG_FILE = os.path.join(LOG_DIR, "reflected_responses.json")

# Гарантируем существование директории
os.makedirs(LOG_DIR, exist_ok=True)

_write_lock = threading.Lock()


def rotate_if_big(path: str, max_mb: int = 20):
    """Ротация логов, если файл слишком большой."""
    if os.path.exists(path) and os.path.getsize(path) > max_mb * 1024 * 1024:
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup = f"{path}.{ts}.bak"
        os.rename(path, backup)


def load_ndjson(path: str) -> List[Dict[str, Any]]:
    """Безопасная загрузка NDJSON."""
    items = []
    if not os.path.exists(path):
        return items

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return items


class XSSLogViewer:
    """
    XSS Log Viewer 2.0
    -------------------
    • Читает NDJSON лог отражённых XSS
    • Даёт сводку по категориям
    • Даёт детальный список
    • Поддерживает фильтрацию и сортировку
    • Готов для GUI-интеграции
    """

    def __init__(self, gui_callback=None):
        self.gui_callback = gui_callback

    # -----------------------------
    # Загрузка логов
    # -----------------------------
    def load(self, path: str = LOG_FILE) -> List[Dict[str, Any]]:
        rotate_if_big(path)
        return load_ndjson(path)

    # -----------------------------
    # Сводка по категориям
    # -----------------------------
    def summarize(self, items: List[Dict[str, Any]]) -> Dict[str, int]:
        summary = {}
        for r in items:
            cat = r.get("category", "unknown")
            summary[cat] = summary.get(cat, 0) + 1
        return summary

    # -----------------------------
    # Фильтрация по категории
    # -----------------------------
    def filter_by_category(self, items: List[Dict[str, Any]], category: str) -> List[Dict[str, Any]]:
        return [r for r in items if r.get("category") == category]

    # -----------------------------
    # Фильтрация по URL
    # -----------------------------
    def filter_by_url(self, items: List[Dict[str, Any]], url: str) -> List[Dict[str, Any]]:
        return [r for r in items if r.get("url") == url]

    # -----------------------------
    # Сортировка по времени
    # -----------------------------
    def sort_by_timestamp(self, items: List[Dict[str, Any]], reverse: bool = True) -> List[Dict[str, Any]]:
        def parse_ts(x):
            ts = x.get("_ts")
            try:
                return datetime.datetime.fromisoformat(ts)
            except Exception:
                return datetime.datetime.min

        return sorted(items, key=parse_ts, reverse=reverse)

    # -----------------------------
    # GUI: сводка
    # -----------------------------
    def render_summary(self):
        items = self.load()
        summary = self.summarize(items)

        data = {
            "total": len(items),
            "by_category": summary,
        }

        if self.gui_callback:
            self.gui_callback({"xss_log_summary": data})

        return data

    # -----------------------------
    # GUI: детальный список
    # -----------------------------
    def render_details(self, limit: int = 50, category: Optional[str] = None):
        items = self.load()
        items = self.sort_by_timestamp(items)

        if category:
            items = self.filter_by_category(items, category)

        sliced = items[:limit]

        if self.gui_callback:
            self.gui_callback({"xss_log_details": sliced})

        return sliced

    # -----------------------------
    # Поиск по ключевому слову
    # -----------------------------
    def search(self, keyword: str) -> List[Dict[str, Any]]:
        items = self.load()
        keyword = keyword.lower()

        result = []
        for r in items:
            url = r.get("url", "").lower()
            resp = r.get("full_response", "").lower()
            if keyword in url or keyword in resp:
                result.append(r)

        return result