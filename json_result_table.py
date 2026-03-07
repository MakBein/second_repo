# xss_security_gui/json_result_table.py

from tkinter import ttk
import json
from pathlib import Path
from typing import Any, Dict, List

from xss_security_gui.settings import crawler_results_path


class JSONResultTable(ttk.Frame):
    """
    Универсальная таблица для отображения результатов краулера.
    - Автоматически определяет колонки по структуре JSON
    - Безопасно обрабатывает ошибки
    - Поддерживает обновление данных
    - Гибкая и расширяемая
    """

    DEFAULT_COLUMNS = ["url", "forms", "csp", "xss"]

    def __init__(self, parent, json_path: Path = None):
        super().__init__(parent)
        self.json_path = Path(json_path) if json_path else crawler_results_path()
        self.tree = None
        self.build_ui()

    # ============================================================
    #  UI
    # ============================================================

    def build_ui(self):
        self.tree = ttk.Treeview(self, show="headings", height=25)
        self.tree.pack(fill="both", expand=True)

        self.load_and_render()

    # ============================================================
    #  Загрузка JSON
    # ============================================================

    def load_json(self) -> List[Dict[str, Any]]:
        if not self.json_path.exists():
            return []

        try:
            with open(self.json_path, encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                return []
        except Exception as e:
            return [{"url": f"❌ Ошибка чтения JSON: {e}"}]

    # ============================================================
    #  Рендер таблицы
    # ============================================================

    def load_and_render(self):
        data = self.load_json()

        # Определяем колонки динамически
        columns = self.detect_columns(data)
        self.tree["columns"] = columns

        # Заголовки
        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=200 if col != "url" else 400, anchor="w")

        # Очищаем старые строки
        for row in self.tree.get_children():
            self.tree.delete(row)

        # Заполняем таблицу
        for entry in data:
            row = self.extract_row(entry, columns)
            self.tree.insert("", "end", values=row)

    # ============================================================
    #  Определение колонок
    # ============================================================

    def detect_columns(self, data: List[Dict[str, Any]]) -> List[str]:
        if not data:
            return self.DEFAULT_COLUMNS

        # Собираем все ключи, которые встречаются в JSON
        keys = set()
        for entry in data:
            if isinstance(entry, dict):
                keys.update(entry.keys())

        # Гарантируем наличие основных колонок
        keys.update(self.DEFAULT_COLUMNS)

        # Убираем слишком вложенные структуры
        filtered = []
        for k in keys:
            if isinstance(k, str) and "." not in k:
                filtered.append(k)

        return sorted(filtered)

    # ============================================================
    #  Формирование строки
    # ============================================================

    def extract_row(self, entry: Dict[str, Any], columns: List[str]) -> List[Any]:
        row = []
        for col in columns:
            if col == "forms":
                row.append(len(entry.get("forms", [])))
            elif col == "csp":
                row.append(entry.get("headers", {}).get("CSP", "—"))
            elif col == "xss":
                row.append(entry.get("headers", {}).get("X-XSS-Protection", "—"))
            else:
                value = entry.get(col, "—")
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, ensure_ascii=False)
                row.append(value)
        return row

    # ============================================================
    #  Публичный метод обновления
    # ============================================================

    def refresh(self):
        """Обновляет таблицу без перезапуска GUI."""
        self.load_and_render()