# xss_security_gui/settings_tab.py

from __future__ import annotations

import json
import os
from typing import Any, Dict

import tkinter as tk
from tkinter import ttk, messagebox

SETTINGS_FILE = "configs/settings.json"


# ============================================================
#  Low-level helpers
# ============================================================

def _ensure_settings_dir() -> None:
    directory = os.path.dirname(SETTINGS_FILE)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)


def load_settings() -> Dict[str, Any]:
    """Безопасная загрузка настроек с дефолтами."""
    _ensure_settings_dir()
    if not os.path.exists(SETTINGS_FILE):
        return {}
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_settings(data: Dict[str, Any]) -> bool:
    """Безопасное сохранение настроек на диск."""
    try:
        _ensure_settings_dir()
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[Settings GUI] Ошибка сохранения: {e}")
        return False


# ============================================================
#  SettingsTab ULTRA 3.0
# ============================================================

class SettingsTab(ttk.Frame):
    """
    SettingsTab ULTRA 3.0

    - Безопасная загрузка/сохранение JSON
    - Валидация числовых полей
    - Авто-создание configs/
    - Дефолтные значения при ошибках
    """

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent)

        self.settings: Dict[str, Any] = load_settings()

        # ============================================================
        # Авто-ловушки
        # ============================================================
        self.auto_traps_var = tk.BooleanVar(
            value=bool(self.settings.get("ENABLE_AUTO_TRAPS", True))
        )
        ttk.Checkbutton(
            self,
            text="Включить авто-ловушки honeypot",
            variable=self.auto_traps_var,
        ).pack(anchor="w", padx=10, pady=5)

        # ============================================================
        # Тип ловушки
        # ============================================================
        ttk.Label(self, text="Тип ловушки:").pack(anchor="w", padx=10)
        self.trap_type_var = tk.StringVar(
            value=str(self.settings.get("DEFAULT_TRAP_TYPE", "js"))
        )
        self.trap_type_box = ttk.Combobox(
            self,
            textvariable=self.trap_type_var,
            values=["js", "html"],
            width=15,
            state="readonly",
        )
        self.trap_type_box.pack(anchor="w", padx=10, pady=2)

        # ============================================================
        # Интервал honeypot
        # ============================================================
        ttk.Label(self, text="Интервал опроса Honeypot (сек):").pack(
            anchor="w", padx=10, pady=5
        )
        self.interval_entry = ttk.Entry(self, width=10)
        self.interval_entry.insert(
            0,
            str(self._safe_int(self.settings.get("HONEYPOT_POLL_INTERVAL", 4), default=4)),
        )
        self.interval_entry.pack(anchor="w", padx=10)

        # ============================================================
        # Кнопка сохранения
        # ============================================================
        ttk.Button(
            self,
            text="💾 Сохранить настройки",
            command=self.save,
        ).pack(pady=10)

    # ============================================================
    # Helpers
    # ============================================================

    def _safe_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except Exception:
            return default

    # ============================================================
    # Save
    # ============================================================

    def save(self) -> None:
        """Сохраняет настройки с валидацией."""
        # Валидация интервала
        interval_raw = self.interval_entry.get().strip()
        interval = self._safe_int(interval_raw, default=-1)
        if interval <= 0:
            messagebox.showerror(
                "Ошибка",
                "Интервал опроса должен быть положительным целым числом.",
            )
            return

        updated: Dict[str, Any] = {
            "ENABLE_AUTO_TRAPS": bool(self.auto_traps_var.get()),
            "DEFAULT_TRAP_TYPE": self.trap_type_var.get() or "js",
            "HONEYPOT_POLL_INTERVAL": interval,
        }

        current = load_settings()
        current.update(updated)

        if save_settings(current):
            messagebox.showinfo("Настройки", "Изменения сохранены!")
        else:
            messagebox.showerror("Ошибка", "Не удалось сохранить настройки.")