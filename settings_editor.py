# xss_security_gui/settings_editor.py
import tkinter as tk
from tkinter import ttk, messagebox
import json
import os

class SettingsEditor(ttk.Frame):
    def __init__(self, parent, json_path="settings.json"):
        super().__init__(parent)
        self.json_path = json_path
        self.entries = {}
        self.readonly_keys = {
            "logging.success_path",
            "honeypot.log_path"
        }
        self.search_var = tk.StringVar()
        self.build_ui()

    def build_ui(self):
        topbar = ttk.Frame(self)
        topbar.pack(fill="x", padx=10, pady=5)

        ttk.Label(topbar, text="🔎 Поиск:").pack(side="left")
        tk.Entry(topbar, textvariable=self.search_var, width=25).pack(side="left", padx=5)
        ttk.Button(topbar, text="Искать", command=self.search).pack(side="left", padx=5)
        ttk.Button(topbar, text="🔄 Обновить", command=self.load_settings).pack(side="right", padx=5)
        ttk.Button(topbar, text="💾 Сохранить", command=self.save_settings).pack(side="right", padx=5)

        self.tree = ttk.Treeview(self, columns=("key", "value"), show="headings", height=30)
        self.tree.heading("key", text="Параметр")
        self.tree.heading("value", text="Значение")
        self.tree.column("key", width=240, anchor="w")
        self.tree.column("value", width=320, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        self.tree.bind("<Double-1>", self.on_double_click)

        self.load_settings()

    def load_settings(self):
        self.tree.delete(*self.tree.get_children())
        if not os.path.exists(self.json_path):
            messagebox.showerror("❌ Ошибка", f"{self.json_path} не найден")
            return

        with open(self.json_path, encoding="utf-8") as f:
            self.current_data = json.load(f)

        for key, value in self._flatten(self.current_data):
            self.tree.insert("", "end", iid=key, values=(key, str(value)))

    def save_settings(self):
        for item in self.tree.get_children():
            key, value = self.tree.item(item)["values"]

            if key in self.readonly_keys:
                continue  # skip protected keys

            value = self._convert_value(value)
            self._set_nested_value(self.current_data, key.split("."), value)

        try:
            with open(self.json_path, "w", encoding="utf-8") as f:
                json.dump(self.current_data, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("✅ Готово", "Настройки сохранены")
        except Exception as e:
            messagebox.showerror("❌ Ошибка сохранения", str(e))

    def search(self):
        term = self.search_var.get().lower()
        for item in self.tree.get_children():
            values = self.tree.item(item)["values"]
            if any(term in str(v).lower() for v in values):
                self.tree.selection_set(item)
                self.tree.see(item)
                break

    def on_double_click(self, event):
        item_id = self.tree.identify_row(event.y)
        col = self.tree.identify_column(event.x)
        if col != "#2" or not item_id:
            return

        key = self.tree.item(item_id)["values"][0]
        if key in self.readonly_keys:
            messagebox.showwarning("🛑 Запрещено", f"{key} защищён от редактирования")
            return

        x, y, width, height = self.tree.bbox(item_id, column=col)
        old_val = self.tree.set(item_id, column=col)
        entry = tk.Entry(self.tree)
        entry.place(x=x, y=y, width=width, height=height)
        entry.insert(0, old_val)
        entry.focus()

        def on_enter(event=None):
            self.tree.set(item_id, column=col, value=entry.get())
            entry.destroy()

        entry.bind("<Return>", on_enter)
        entry.bind("<FocusOut>", lambda e: entry.destroy())

    def _convert_value(self, value):
        if isinstance(value, str):
            v = value.strip().lower()
            if v == "true":
                return True
            elif v == "false":
                return False
            try:
                return int(value) if "." not in value else float(value)
            except:
                return value
        return value

    def _set_nested_value(self, d, path, value):
        for key in path[:-1]:
            d = d.setdefault(key, {})
        d[path[-1]] = value

    def _flatten(self, d, prefix=""):
        items = []
        for k, v in d.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                items.extend(self._flatten(v, path))
            else:
                items.append((path, v))
        return items