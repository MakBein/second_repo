import json
import tkinter as tk
from tkinter import ttk, messagebox

SETTINGS_FILE = "configs/settings.json"

def load_settings():
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_settings(data):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"[Settings GUI] Ошибка сохранения: {e}")
        return False

class SettingsTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.settings = load_settings()

        # Авто-ловушки
        self.auto_traps_var = tk.BooleanVar(value=self.settings.get("ENABLE_AUTO_TRAPS", True))
        ttk.Checkbutton(self, text="Включить авто-ловушки honeypot",
                        variable=self.auto_traps_var).pack(anchor="w", padx=10, pady=5)

        # Тип ловушки
        ttk.Label(self, text="Тип ловушки:").pack(anchor="w", padx=10)
        self.trap_type_var = tk.StringVar(value=self.settings.get("DEFAULT_TRAP_TYPE", "js"))
        ttk.Combobox(self, textvariable=self.trap_type_var,
                     values=["js", "html"], width=15).pack(anchor="w", padx=10)

        # Интервал honeypot
        ttk.Label(self, text="Интервал опроса Honeypot (сек):").pack(anchor="w", padx=10, pady=5)
        self.interval_entry = ttk.Entry(self, width=10)
        self.interval_entry.insert(0, str(self.settings.get("HONEYPOT_POLL_INTERVAL", 4)))
        self.interval_entry.pack(anchor="w", padx=10)

        # Сохранение
        ttk.Button(self, text="💾 Сохранить настройки", command=self.save).pack(pady=10)

    def save(self):
        updated = {
            "ENABLE_AUTO_TRAPS": self.auto_traps_var.get(),
            "DEFAULT_TRAP_TYPE": self.trap_type_var.get(),
            "HONEYPOT_POLL_INTERVAL": int(self.interval_entry.get())
        }
        current = load_settings()
        current.update(updated)
        if save_settings(current):
            messagebox.showinfo("Настройки", "Изменения сохранены!")
        else:
            messagebox.showerror("Ошибка", "Не удалось сохранить настройки.")