# xss_security_gui/threat_tab.py

from __future__ import annotations

import json
import threading
from typing import Any, Dict, List, Optional

import tkinter as tk
from tkinter import ttk, filedialog

from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


class ThreatAnalysisTab(ttk.Frame):
    """
    Threat Intel Viewer ULTRA 8.0

    - Потокобезопасное обновление (lock + after)
    - Кэширование summary
    - Универсальный рендерер дерева (dict / list / primitives)
    - Фильтры по модулю, поиск по всему JSON
    - Экспорт в JSON
    - Контекстное меню (копирование ключа/значения)
    - Кнопки Expand All / Collapse All
    - Защита от ошибок Tkinter при закрытии окна
    """

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent)

        self._last_summary: Optional[Dict[str, Any]] = None
        self._reload_lock = threading.Lock()

        # ============================================================
        # Верхняя панель
        # ============================================================
        top = ttk.Frame(self)
        top.pack(fill="x", pady=3)

        ttk.Button(top, text="🔄 Обновить", command=self.reload_summary).pack(side="left", padx=5)
        ttk.Button(top, text="🧹 Очистить", command=self.clear).pack(side="left")
        ttk.Button(top, text="💾 Экспорт JSON", command=self.export_json).pack(side="left", padx=5)

        ttk.Button(top, text="➕ Expand All", command=self.expand_all).pack(side="left", padx=5)
        ttk.Button(top, text="➖ Collapse All", command=self.collapse_all).pack(side="left")

        ttk.Label(top, text="Модуль:").pack(side="left", padx=5)
        self.filter_var = tk.StringVar()
        self.filter_box = ttk.Combobox(top, textvariable=self.filter_var, width=20, state="readonly")
        self.filter_box.pack(side="left")
        self.filter_box.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())

        ttk.Label(top, text="Поиск:").pack(side="left", padx=5)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(top, textvariable=self.search_var, width=25)
        search_entry.pack(side="left")
        search_entry.bind("<Return>", lambda e: self.apply_search())
        ttk.Button(top, text="🔍", command=self.apply_search).pack(side="left")

        # ============================================================
        # Summary (верхняя панель)
        # ============================================================
        self.text_widget = tk.Text(self, height=10, bg="#111", fg="#0f0")
        self.text_widget.pack(fill="x", padx=5, pady=5)

        # ============================================================
        # Дерево (нижняя панель)
        # ============================================================
        self.scrollbar = ttk.Scrollbar(self, orient="vertical")
        self.scrollbar.pack(side="right", fill="y")

        self.tree = ttk.Treeview(
            self,
            columns=("detail",),
            show="tree headings",
            yscrollcommand=self.scrollbar.set,
        )
        self.tree.heading("#0", text="Ключ")
        self.tree.heading("detail", text="Значение")

        self.tree.column("#0", width=350, anchor="w")
        self.tree.column("detail", width=550, anchor="w")

        self.tree.pack(fill="both", expand=True)
        self.scrollbar.config(command=self.tree.yview)

        # ============================================================
        # Контекстное меню
        # ============================================================
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Копировать ключ", command=self._copy_selected_key)
        self.menu.add_command(label="Копировать значение", command=self._copy_selected_value)
        self.tree.bind("<Button-3>", self._show_context_menu)

        # ============================================================
        # Статус
        # ============================================================
        self.status_var = tk.StringVar(value="Готово")
        status = ttk.Label(self, textvariable=self.status_var, anchor="w")
        status.pack(side="bottom", fill="x")

        # Автообновление при старте
        self.reload_summary()

    # ============================================================
    # Вспомогательные методы
    # ============================================================

    def _to_str(self, value: Any) -> str:
        """Безопасное преобразование значения в строку с ограничением длины."""
        try:
            text = str(value)
        except Exception:
            text = repr(value)
        return text if len(text) <= 2000 else text[:2000] + "…"

    def _show_context_menu(self, event: tk.Event) -> None:
        selected = self.tree.identify_row(event.y)
        if not selected:
            return
        self.tree.selection_set(selected)
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _copy_selected_key(self) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        key_text = self.tree.item(selected[0], "text")
        self.clipboard_clear()
        self.clipboard_append(key_text)
        self.status_var.set("Ключ скопирован")

    def _copy_selected_value(self) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        values = self.tree.item(selected[0], "values")
        value_text = values[0] if values else ""
        self.clipboard_clear()
        self.clipboard_append(value_text)
        self.status_var.set("Значение скопировано")

    # ============================================================
    # Интеграция с Threat Intel
    # ============================================================

    def get_all_threats(self) -> List[Dict[str, Any]]:
        """
        Возвращает полный список Threat Intel событий.
        Использует THREAT_CONNECTOR.summary() — безопасно и универсально.
        """
        try:
            summary = THREAT_CONNECTOR.summary()
        except Exception:
            return []

        entries = summary.get("entries", [])
        return list(entries) if isinstance(entries, list) else []

    def send_to_threat_intel(self, module: str, data: Any) -> None:
        """
        Локальный предпросмотр данных от модулей (crawler, autorecon и т.д.).
        НЕ отправляет данные в ThreatConnector, только рендерит в GUI.
        """
        try:
            payload = {
                "module": module,
                "entries": data if isinstance(data, list) else [data],
            }
            self.load_results(payload)
            self.status_var.set(f"Получены данные от модуля: {module}")
        except Exception as e:
            self._render_empty(f"Ошибка обработки данных: {e}")
            self.status_var.set("Ошибка Threat Intel")

    # ============================================================
    # Ошибки / пустые состояния
    # ============================================================

    def _show_error(self, error: Exception) -> None:
        if not self.winfo_exists():
            return
        self.text_widget.delete("1.0", "end")
        self.text_widget.insert("1.0", f"❌ Ошибка загрузки Threat Intel:\n{error}")
        self.status_var.set("Ошибка Threat Intel")

    def _render_empty(self, message: str) -> None:
        if not self.winfo_exists():
            return

        self.tree.delete(*self.tree.get_children())
        root = self.tree.insert("", "end", text="Пусто", open=True)
        self.tree.insert(root, "end", text="→", values=(message,))

        self.text_widget.delete("1.0", "end")
        self.text_widget.insert("1.0", message)

        self.status_var.set(message)

    # ============================================================
    # Основные методы
    # ============================================================

    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.text_widget.delete("1.0", "end")
        self.status_var.set("Очищено")
        self._last_summary = None

    def reload_summary(self) -> None:
        if self._reload_lock.locked():
            return
        if not hasattr(self.master, "after"):
            return

        self.status_var.set("Загрузка Threat Intel…")
        threading.Thread(target=self._reload_worker, daemon=True).start()

    def _reload_worker(self) -> None:
        with self._reload_lock:
            try:
                if hasattr(THREAT_CONNECTOR, "generate_report"):
                    summary = THREAT_CONNECTOR.generate_report()
                else:
                    summary = THREAT_CONNECTOR.summary()
            except Exception as e:
                try:
                    self.after(0, self._show_error, e)
                except RuntimeError:
                    return
                return

            self._last_summary = summary

            try:
                self.master.after(0, lambda: self._apply_summary(summary))
            except RuntimeError:
                return

    def _apply_summary(self, summary: Dict[str, Any]) -> None:
        if not self.winfo_exists():
            return

        self.text_widget.delete("1.0", "end")
        self.text_widget.insert("1.0", json.dumps(summary, indent=2, ensure_ascii=False))

        modules = list(summary.get("by_module", {}).keys()) if isinstance(summary, dict) else []
        self.filter_box["values"] = ["Все"] + modules if modules else []
        self.filter_box.set("Все" if modules else "")

        self.load_results(summary)
        self.status_var.set("Summary обновлён")

    # ============================================================
    # Экспорт
    # ============================================================

    def export_json(self) -> None:
        summary = self._last_summary
        if not summary:
            try:
                if hasattr(THREAT_CONNECTOR, "generate_report"):
                    summary = THREAT_CONNECTOR.generate_report()
                else:
                    summary = THREAT_CONNECTOR.summary()
            except Exception as e:
                self.status_var.set(f"Ошибка экспорта: {e}")
                return

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            self.status_var.set(f"Экспортировано: {path}")
        except Exception as e:
            self.status_var.set(f"Ошибка экспорта: {e}")

    # ============================================================
    # Фильтр и поиск
    # ============================================================

    def apply_filter(self) -> None:
        module = self.filter_var.get()
        summary = self._last_summary
        if not summary or not isinstance(summary, dict):
            return

        if module == "Все" or not module:
            self.load_results(summary)
            self.status_var.set("Фильтр: все модули")
            return

        by_module = summary.get("by_module", {})
        filtered = {
            "module": module,
            "count": by_module.get(module, 0),
        }
        self.load_results(filtered)
        self.status_var.set(f"Фильтр по модулю: {module}")

    def apply_search(self) -> None:
        query = self.search_var.get().lower().strip()
        if not query:
            return

        summary = self._last_summary
        if not summary:
            return

        self.tree.delete(*self.tree.get_children())
        root = self.tree.insert("", "end", text="Результаты поиска", open=True)

        text = json.dumps(summary, ensure_ascii=False)
        if query in text.lower():
            self.tree.insert(root, "end", text="Совпадение", values=("Есть совпадения",))
        else:
            self.tree.insert(root, "end", text="Нет совпадений", values=("—",))

        self.status_var.set(f"Поиск: {query}")

    # ============================================================
    # Рендеринг дерева
    # ============================================================

    def load_results(self, payload: Any) -> None:
        self.tree.delete(*self.tree.get_children())
        root = self.tree.insert("", "end", text="Threat Intel", open=True)

        def render(parent: str, obj: Any) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    node = self.tree.insert(parent, "end", text=self._to_str(k), open=False)
                    render(node, v)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    node = self.tree.insert(parent, "end", text=f"[{i}]", open=False)
                    render(node, item)
            else:
                self.tree.insert(parent, "end", text="→", values=(self._to_str(obj),))

        render(root, payload)

    # ============================================================
    # Управление деревом (Expand / Collapse)
    # ============================================================

    def expand_all(self) -> None:
        for item in self.tree.get_children():
            self._expand_recursive(item)
        self.status_var.set("Все узлы раскрыты")

    def collapse_all(self) -> None:
        for item in self.tree.get_children():
            self._collapse_recursive(item)
        self.status_var.set("Все узлы свернуты")

    def _expand_recursive(self, item: str) -> None:
        self.tree.item(item, open=True)
        for child in self.tree.get_children(item):
            self._expand_recursive(child)

    def _collapse_recursive(self, item: str) -> None:
        for child in self.tree.get_children(item):
            self._collapse_recursive(child)
        self.tree.item(item, open=False)