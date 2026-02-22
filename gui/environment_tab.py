# xss_security_gui/gui/environment_tab.py

import os
import platform
from tkinter import ttk
from dotenv import load_dotenv
from pathlib import Path


class EnvironmentTab(ttk.Frame):
    """
    Environment Viewer — ULTRA 6.5
    Просмотр переменных окружения + .env
    """

    SENSITIVE_KEYS = {"API_KEY", "AUTH_TOKEN", "SECRET", "TOKEN", "PASSWORD"}

    def __init__(self, parent, env_path: Path):
        super().__init__(parent)
        self.env_path = env_path

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        title = ttk.Label(
            self,
            text="Environment Variables (ULTRA 6.5)",
            font=("Segoe UI", 14, "bold"),
        )
        title.grid(row=0, column=0, pady=10)

        # Таблица
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
        self.tree.grid(row=1, column=0, sticky="nsew", padx=10)

        # Кнопки
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=2, column=0, pady=10)

        ttk.Button(btn_frame, text="Reload .env", command=self.reload_env).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Refresh View", command=self.refresh).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="Open .env", command=self.open_env_file).grid(row=0, column=2, padx=5)

        self.refresh()

    # ---------------------------------------------------------
    # Обновление таблицы
    # ---------------------------------------------------------
    def refresh(self):
        """Обновляет таблицу переменных окружения."""
        for row in self.tree.get_children():
            self.tree.delete(row)

        for key, value in sorted(os.environ.items()):
            display_value = self._mask_if_sensitive(key, value)
            self.tree.insert("", "end", values=(key, display_value))

    # ---------------------------------------------------------
    # Маскирование чувствительных значений
    # ---------------------------------------------------------
    def _mask_if_sensitive(self, key: str, value: str) -> str:
        """Маскирует значение, если ключ чувствительный."""
        if any(s in key.upper() for s in self.SENSITIVE_KEYS):
            return "************" if value.strip() else "<empty>"
        return value

    # ---------------------------------------------------------
    # Перезагрузка .env
    # ---------------------------------------------------------
    def reload_env(self):
        """Перезагружает .env файл и обновляет таблицу."""
        try:
            load_dotenv(self.env_path, override=True)
            self.refresh()
        except Exception as e:
            print(f"[EnvironmentTab] Ошибка при загрузке .env: {e}")

    # ---------------------------------------------------------
    # Открыть .env в редакторе
    # ---------------------------------------------------------
    def open_env_file(self):
        """Открывает .env файл в системном редакторе."""
        try:
            if platform.system() == "Windows":
                os.startfile(self.env_path)
            elif platform.system() == "Darwin":  # macOS
                os.system(f"open {self.env_path}")
            else:  # Linux/Unix
                os.system(f"xdg-open {self.env_path}")
        except Exception as e:
            print(f"[EnvironmentTab] Ошибка при открытии .env: {e}")