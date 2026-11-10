# xss_security_gui/gui/environment_tab.py
# ============================================================
# EnvironmentTab 9.0 — пошук, фільтрація, підсвітка, copy, diff
# ============================================================

import os
import platform
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from dotenv import load_dotenv


class EnvironmentTab(ttk.Frame):
    """
    Environment Viewer — 9.0
    ------------------------
    • Пошук по ключам/значенням
    • Підсвітка чутливих змінних
    • Copy key / Copy value
    • Reload .env
    • Diff між .env та os.environ
    • Підтримка .env.dev / .env.prod
    """

    SENSITIVE_KEYS = {"API_KEY", "AUTH_TOKEN", "SECRET", "TOKEN", "PASSWORD"}

    def __init__(self, parent, env_path: Path):
        super().__init__(parent)
        self.env_path = env_path

        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        self._build_header()
        self._build_search()
        self._build_tree()
        self._build_buttons()

        self.refresh()

    # ============================================================
    # HEADER
    # ============================================================
    def _build_header(self):
        ttk.Label(
            self,
            text="Environment Variables (9.0)",
            font=("Segoe UI", 14, "bold"),
        ).grid(row=0, column=0, pady=10)

    # ============================================================
    # SEARCH BAR
    # ============================================================
    def _build_search(self):
        search_frame = ttk.Frame(self)
        search_frame.grid(row=1, column=0, sticky="ew", padx=10)

        ttk.Label(search_frame, text="🔍 Пошук:").pack(side="left")

        self.search_var = ttk.Entry(search_frame, width=40)
        self.search_var.pack(side="left", padx=5)

        ttk.Button(search_frame, text="Знайти", command=self.search).pack(side="left", padx=5)
        ttk.Button(search_frame, text="Скинути", command=self.refresh).pack(side="left", padx=5)

    # ============================================================
    # TREEVIEW
    # ============================================================
    def _build_tree(self):
        self.tree = ttk.Treeview(
            self,
            columns=("key", "value"),
            show="headings",
            height=20,
        )
        self.tree.heading("key", text="Variable")
        self.tree.heading("value", text="Value")
        self.tree.column("key", width=250)
        self.tree.column("value", width=500)

        self.tree.grid(row=2, column=0, sticky="nsew", padx=10)

        # Right-click menu
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Copy key", command=self.copy_key)
        self.menu.add_command(label="Copy value", command=self.copy_value)

        self.tree.bind("<Button-3>", self._show_menu)

    # ============================================================
    # BUTTONS
    # ============================================================
    def _build_buttons(self):
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=3, column=0, pady=10)

        ttk.Button(btn_frame, text="Reload .env", command=self.reload_env).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Open .env", command=self.open_env_file).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Export to .env", command=self.export_env).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Show Diff", command=self.show_diff).pack(side="left", padx=5)

    # ============================================================
    # REFRESH
    # ============================================================
    def refresh(self):
        """Перезавантажує таблицю."""
        for row in self.tree.get_children():
            self.tree.delete(row)

        for key, value in sorted(os.environ.items()):
            display_value = self._mask_if_sensitive(key, value)
            self.tree.insert("", "end", values=(key, display_value))

    # ============================================================
    # SEARCH
    # ============================================================
    def search(self):
        query = self.search_var.get().strip().lower()
        if not query:
            self.refresh()
            return

        for row in self.tree.get_children():
            self.tree.delete(row)

        for key, value in sorted(os.environ.items()):
            if query in key.lower() or query in str(value).lower():
                display_value = self._mask_if_sensitive(key, value)
                self.tree.insert("", "end", values=(key, display_value))

    # ============================================================
    # MASK SENSITIVE
    # ============================================================
    def _mask_if_sensitive(self, key: str, value: str) -> str:
        if any(s in key.upper() for s in self.SENSITIVE_KEYS):
            return "************" if value.strip() else "<empty>"
        return value

    # ============================================================
    # RELOAD .ENV
    # ============================================================
    def reload_env(self):
        try:
            load_dotenv(self.env_path, override=True)
            self.refresh()
        except Exception as e:
            messagebox.showerror("Error", f"Помилка при завантаженні .env: {e}")

    # ============================================================
    # OPEN .ENV
    # ============================================================
    def open_env_file(self):
        try:
            if platform.system() == "Windows":
                os.startfile(self.env_path)
            elif platform.system() == "Darwin":
                os.system(f"open {self.env_path}")
            else:
                os.system(f"xdg-open {self.env_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Помилка при відкритті .env: {e}")

    # ============================================================
    # EXPORT ENV
    # ============================================================
    def export_env(self):
        try:
            with open(self.env_path, "w", encoding="utf-8") as f:
                for key, value in sorted(os.environ.items()):
                    f.write(f"{key}={value}\n")
            messagebox.showinfo("Export", "Змінні середовища експортовано у .env")
        except Exception as e:
            messagebox.showerror("Error", f"Помилка експорту: {e}")

    # ============================================================
    # DIFF
    # ============================================================
    def show_diff(self):
        """Показує змінні, які відрізняються від .env."""
        try:
            env_file_vars = {}
            if self.env_path.exists():
                with open(self.env_path, "r", encoding="utf-8") as f:
                    for raw_line in f:
                        line = raw_line.strip()
                        # пропускаємо порожні рядки та коментарі
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")  # знімаємо лапки/пробіли
                        if k:
                            env_file_vars[k] = v

            diff_added = []
            diff_changed = []

            for key, value in os.environ.items():
                if key not in env_file_vars:
                    diff_added.append(key)
                elif env_file_vars[key] != value:
                    diff_changed.append(key)

            msg = (
                f"🟢 Нові змінні (не у .env):\n{diff_added}\n\n"
                f"🟡 Змінені змінні:\n{diff_changed}"
            )
            messagebox.showinfo("Environment Diff", msg)

        except Exception as e:
            messagebox.showerror("Error", f"Помилка diff: {e}")

    # ============================================================
    # COPY MENU
    # ============================================================
    def _show_menu(self, event):
        row_id = self.tree.identify_row(event.y)
        if row_id:
            self.tree.selection_set(row_id)
            self.menu.post(event.x_root, event.y_root)

    def copy_key(self):
        item = self.tree.selection()
        if not item:
            return
        key = self.tree.item(item[0], "values")[0]
        self.clipboard_clear()
        self.clipboard_append(key)

    def copy_value(self):
        item = self.tree.selection()
        if not item:
            return
        value = self.tree.item(item[0], "values")[1]
        self.clipboard_clear()
        self.clipboard_append(value)
