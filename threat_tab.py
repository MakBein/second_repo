# xss_security_gui/threat_tab.py
import threading
import json
import tkinter as tk
from tkinter import ttk, filedialog

from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


class ThreatAnalysisTab(ttk.Frame):
    """
    Threat Intel Viewer ULTRA 5.0

    - Двухпанельный интерфейс (summary + дерево)
    - Фильтры по модулям
    - Поиск по ключам и значениям
    - Экспорт JSON
    - Автообновление (потокобезопасно)
    - Цветовые теги для уровней угроз (готово к расширению)
    - Приём данных от других модулей (send_to_threat_intel)
    """

    def __init__(self, parent):
        super().__init__(parent)

        # ============================================================
        # Верхняя панель управления
        # ============================================================
        top = ttk.Frame(self)
        top.pack(fill="x", pady=3)

        ttk.Button(top, text="🔄 Обновить", command=self.reload_summary).pack(side="left", padx=5)
        ttk.Button(top, text="🧹 Очистить", command=self.clear).pack(side="left")
        ttk.Button(top, text="💾 Экспорт JSON", command=self.export_json).pack(side="left", padx=5)

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
        # Статусная строка
        # ============================================================
        self.status_var = tk.StringVar(value="Готово")
        status = ttk.Label(self, textvariable=self.status_var, anchor="w")
        status.pack(side="bottom", fill="x")

        # Автообновление при старте
        self.reload_summary()

    # ============================================================
    # Основные функции
    # ============================================================

    def clear(self):
        """Полная очистка дерева и summary."""
        try:
            self.tree.delete(*self.tree.get_children())
        except Exception:
            pass
        self.text_widget.delete("1.0", "end")
        self.status_var.set("Очищено")

    def reload_summary(self):
        """Запускает обновление Threat Intel в отдельном потоке, не блокируя GUI."""
        self.status_var.set("Загрузка Threat Intel…")
        threading.Thread(target=self._reload_worker, daemon=True).start()

    def _reload_worker(self):
        """Фоновая загрузка summary из ThreatConnector 6.0."""
        try:
            summary = THREAT_CONNECTOR.summary()
        except Exception as e:
            self.after(0, lambda: self._show_error(e))
            return
        self.after(0, lambda: self._apply_summary(summary))

    def _apply_summary(self, summary: dict):
        """Обновляет GUI после фоновой загрузки."""
        try:
            self.text_widget.delete("1.0", "end")
            self.text_widget.insert("1.0", json.dumps(summary, indent=2, ensure_ascii=False))

            modules = list(summary.get("by_module", {}).keys())
            self.filter_box["values"] = ["Все"] + modules
            if modules:
                self.filter_box.set("Все")
            else:
                self.filter_box.set("")

            self.load_results(summary)
            self.status_var.set("Summary обновлён")
        except Exception as e:
            self._show_error(e)

    def _show_error(self, e: Exception):
        """Показывает ошибку в текстовом поле и статусе."""
        self.text_widget.insert("end", f"\n[⚠️] Ошибка Threat Intel: {e}\n")
        self.status_var.set("Ошибка Threat Intel")

    def export_json(self):
        """Экспорт summary в JSON."""
        try:
            summary = THREAT_CONNECTOR.summary()
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")],
            )
            if not path:
                return
            with open(path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            self.status_var.set(f"Экспортировано: {path}")
        except Exception as e:
            self.status_var.set(f"Ошибка экспорта: {e}")

    def apply_filter(self):
        """Фильтр по модулю."""
        module = self.filter_var.get()
        try:
            summary = THREAT_CONNECTOR.summary()
        except Exception as e:
            self._show_error(e)
            return

        if module == "Все" or not module:
            self.load_results(summary)
            return

        filtered = {
            "module": module,
            "entries": [
                {"module": module, "count": summary.get("by_module", {}).get(module, 0)}
            ],
        }
        self.load_results(filtered)
        self.status_var.set(f"Фильтр по модулю: {module}")

    def apply_search(self):
        """Поиск по ключам и значениям в summary."""
        query = self.search_var.get().lower().strip()
        if not query:
            return

        try:
            summary = THREAT_CONNECTOR.summary()
        except Exception as e:
            self._show_error(e)
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

    def load_results(self, payload):
        """Универсальный рендерер дерева для summary и внешних payload'ов."""
        try:
            self.tree.delete(*self.tree.get_children())
        except Exception:
            pass

        root = self.tree.insert("", "end", text="Threat Intel", open=True)

        def render(parent, obj):
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

    def _render_empty(self, message: str):
        """Отображает сообщение о пустых данных или ошибке в дереве."""
        try:
            self.tree.delete(*self.tree.get_children())
        except Exception:
            pass

        self.tree.insert(
            "",
            "end",
            text="⚠️ Нет данных",
            values=(self._to_str(message),),
            open=True,
        )

    def _to_str(self, value) -> str:
        """Безопасное приведение к строке с ограничением длины."""
        try:
            text = str(value)
        except Exception:
            text = repr(value)
        return text[:2000] + "…" if len(text) > 2000 else text

    # ============================================================
    # Контекстное меню
    # ============================================================

    def _show_context_menu(self, event):
        selected = self.tree.identify_row(event.y)
        if selected:
            self.tree.selection_set(selected)
            self.menu.tk_popup(event.x_root, event.y_root)

    def _copy_selected_key(self):
        selected = self.tree.selection()
        if not selected:
            return
        key_text = self.tree.item(selected[0], "text")
        self.clipboard_clear()
        self.clipboard_append(key_text)
        self.status_var.set("Ключ скопирован")

    def _copy_selected_value(self):
        selected = self.tree.selection()
        if not selected:
            return
        values = self.tree.item(selected[0], "values")
        value_text = values[0] if values else ""
        self.clipboard_clear()
        self.clipboard_append(value_text)
        self.status_var.set("Значение скопировано")

    # ============================================================
    # Интеграция с другими модулями
    # ============================================================

    def send_to_threat_intel(self, module, data):
        """
        Получение данных от других модулей (crawler, js_inspector, autorecon и т.д.).
        Ожидает:
        - module: str
        - data: dict | list[dict] | произвольная структура
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