# xss_security_gui/tabs/xss_flooder_tab.py
from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Any, Iterable, Optional
import threading
from pathlib import Path

from xss_security_gui.auto_recon.xss_flooder import (
    clear_flood_log,
    start_flood,
    stop_flood,
)
from xss_security_gui.auto_recon.scope import is_target_authorized
from xss_security_gui.settings import BASE_DIR
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge


class XSSFlooderTab(ttk.Frame):
    """
    XSS Flooder — боевой таб для многопоточного флудера.
    Управляет:
    - Целевым URL
    - Параметром
    - Базовым значением
    - Категорией payload-ов (пока просто метка)
    - Макс. потоками
    - Режимами: разовый запуск / цикл
    - Детальным логом
    - Выбором payload-файла (targets.txt)
    """

    TITLE = "XSS Flooder"

    def __init__(self, parent, **kwargs: Any) -> None:
        super().__init__(parent, **kwargs)
        self._bridge = UIQueueBridge(self, poll_ms=50)

        # Состояние
        self._running = False
        self._flood_error: Optional[str] = None
        self._flood_thread: Optional[threading.Thread] = None
        self._targets_file: Path = BASE_DIR / "auto_recon" / "target" / "targets.txt"

        # ==============================
        # Верхняя панель: Цель, параметр
        # ==============================
        top_frame = ttk.LabelFrame(self, text="⚙️ Налаштування флудера", padding=8)
        top_frame.pack(fill="x", padx=10, pady=(10, 5))

        # Цільовий URL
        url_row = ttk.Frame(top_frame)
        url_row.pack(fill="x", pady=2)
        ttk.Label(url_row, text="Цільовий URL:").pack(side="left")
        self.target_var = tk.StringVar(value="")
        self.target_entry = ttk.Entry(url_row, textvariable=self.target_var)
        self.target_entry.pack(side="left", fill="x", expand=True, padx=5)

        ttk.Button(
            url_row,
            text="🔄 Оновити URL",
            command=self._refresh_target,
        ).pack(side="left", padx=5)

        # Параметр
        param_row = ttk.Frame(top_frame)
        param_row.pack(fill="x", pady=2)
        ttk.Label(param_row, text="Параметр:").pack(side="left")
        self.param_var = tk.StringVar(value="url")
        self.param_entry = ttk.Entry(param_row, textvariable=self.param_var, width=15)
        self.param_entry.pack(side="left", padx=5)

        # Базове значення
        base_row = ttk.Frame(top_frame)
        base_row.pack(fill="x", pady=2)
        ttk.Label(base_row, text="Базове значення:").pack(side="left")
        self.base_value_var = tk.StringVar(value="")
        self.base_entry = ttk.Entry(base_row, textvariable=self.base_value_var)
        self.base_entry.pack(side="left", fill="x", expand=True, padx=5)

        # Категорія payload-ів
        payload_row = ttk.Frame(top_frame)
        payload_row.pack(fill="x", pady=2)
        ttk.Label(payload_row, text="Категорія payload-ів:").pack(side="left")
        self.payload_category_var = tk.StringVar(value="Всі категорії")
        self.payload_category_combo = ttk.Combobox(
            payload_row,
            textvariable=self.payload_category_var,
            values=["Всі категорії", "Reflected XSS", "Stored XSS", "DOM XSS"],
            state="readonly",
            width=20,
        )
        self.payload_category_combo.pack(side="left", padx=5)

        # Макс. потоків
        threads_row = ttk.Frame(top_frame)
        threads_row.pack(fill="x", pady=2)
        ttk.Label(threads_row, text="Макс. потоків:").pack(side="left")
        self.max_workers_var = tk.IntVar(value=5)
        self.max_workers_spin = ttk.Spinbox(
            threads_row,
            from_=1,
            to=64,
            textvariable=self.max_workers_var,
            width=5,
        )
        self.max_workers_spin.pack(side="left", padx=5)

        # ==============================
        # Опції: лог, режим
        # ==============================
        options_frame = ttk.LabelFrame(self, text="Режим роботи", padding=8)
        options_frame.pack(fill="x", padx=10, pady=5)

        self.detailed_log_var = tk.BooleanVar(value=True)
        self.single_run_var = tk.BooleanVar(value=True)
        self.cycle_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(
            options_frame,
            text="Детальний лог",
            variable=self.detailed_log_var,
        ).pack(side="left", padx=5)

        ttk.Checkbutton(
            options_frame,
            text="Разовий запуск",
            variable=self.single_run_var,
        ).pack(side="left", padx=5)

        ttk.Checkbutton(
            options_frame,
            text="Цикл",
            variable=self.cycle_var,
        ).pack(side="left", padx=5)

        # ==============================
        # Кнопки дій
        # ==============================
        actions_frame = ttk.Frame(self)
        actions_frame.pack(fill="x", padx=10, pady=5)

        self.start_btn = ttk.Button(
            actions_frame,
            text="▶️ Запустити флудер",
            command=self._start_flood,
        )
        self.start_btn.pack(side="left", padx=3)

        self.stop_btn = ttk.Button(
            actions_frame,
            text="⏹️ Зупинити",
            command=self._stop_flood,
            state="disabled",
        )
        self.stop_btn.pack(side="left", padx=3)

        ttk.Button(
            actions_frame,
            text="🧹 Очистити вивід",
            command=self._clear_output,
        ).pack(side="left", padx=3)

        ttk.Button(
            actions_frame,
            text="📂 Вибрати payload-файл",
            command=self._choose_targets_file,
        ).pack(side="left", padx=3)

        ttk.Button(
            actions_frame,
            text="🧹 Очистити лог артефактів",
            command=self._clear_artifacts_log,
        ).pack(side="left", padx=3)

        # ==============================
        # Вивід / лог
        # ==============================
        output_frame = ttk.LabelFrame(self, text="Вивід флудера", padding=8)
        output_frame.pack(fill="both", expand=True, padx=10, pady=(5, 10))

        self.output_text = tk.Text(
            output_frame,
            height=15,
            bg="#111111",
            fg="#00ff00",
            insertbackground="#00ff00",
            wrap="word",
        )
        self.output_text.pack(fill="both", expand=True)

        self.status_var = tk.StringVar(value="Готово")
        ttk.Label(self, textvariable=self.status_var, anchor="w").pack(
            fill="x", padx=10, pady=(0, 5)
        )

        self.bind("<Destroy>", self._on_destroy, add=True)

    # ==============================
    # Внутрішня логіка
    # ==============================
    def _append_output(self, line: str) -> None:
        def update():
            self.output_text.insert("end", line + "\n")
            self.output_text.see("end")
        self._bridge.call_ui(update)

    def _refresh_target(self) -> None:
        # Тут можна додати логіку оновлення з іншого таба/настройок
        self._append_output(f"[INFO] Оновлено URL: {self.target_var.get()}")

    def _choose_targets_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Вибрати файл цілей (targets.txt)",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            self._targets_file = Path(path)
            self._append_output(f"[INFO] Обрано файл цілей: {self._targets_file}")

    def _clear_output(self) -> None:
        self.output_text.delete("1.0", "end")
        self._append_output("[INFO] Вивід очищено")

    def _clear_artifacts_log(self) -> None:
        try:
            clear_flood_log()
        except OSError as exc:
            messagebox.showerror("Ошибка", f"Не удалось очистить лог: {exc}", parent=self)
            self._append_output(f"[ERROR] Не удалось очистить лог: {exc}")
            return
        self._append_output("[INFO] Лог артефактов Flooder очищен")

    def _start_flood(self) -> None:
        if self._running:
            return

        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Помилка", "Вкажіть цільовий URL", parent=self)
            return

        if not is_target_authorized(target):
            messagebox.showerror(
                "Цель не разрешена",
                "Включите ALLOW_REAL_RUN и добавьте собственный target в ALLOWED_TARGETS.",
                parent=self,
            )
            return

        try:
            max_workers = int(self.max_workers_var.get())
        except ValueError:
            messagebox.showerror("Помилка", "Макс. потоків має бути числом", parent=self)
            return
        if not 1 <= max_workers <= 10:
            messagebox.showerror("Помилка", "Макс. потоків має быть от 1 до 10", parent=self)
            return

        detailed_log = self.detailed_log_var.get()
        single_run = self.single_run_var.get()
        cycle = self.cycle_var.get()

        self._running = True
        self._flood_error = None
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_var.set("Флудер запущено…")

        # Callback для GUI
        def gui_callback(url: str, status: str, snippet: str) -> None:
            if not detailed_log:
                line = f"[{status}] {url}"
            else:
                line = f"[{status}] {url} | {snippet[:120]}"
            self._append_output(line)

        # Запуск у фоні
        def run():
            try:
                # Тут ми використовуємо твій xss_flooder.start_flood
                start_flood(
                    target_urls=[target],
                    flood_interval=1.0,
                    flood_count=1 if single_run else 3,
                    max_workers=max_workers,
                    callback=gui_callback,
                    timeout=2,
                    repeat_each=10,
                    delay_each=0.0,
                    infinite=cycle,
                )

            except Exception as e:
                self._flood_error = f"{type(e).__name__}: {e}"
                self._append_output(f"[ERROR] {self._flood_error}")
            finally:
                self._bridge.post_ui(self._on_flood_finished)

        self._flood_thread = threading.Thread(target=run, daemon=True)
        self._flood_thread.start()

    def _on_flood_finished(self) -> None:
        self._running = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        if self._flood_error:
            self.status_var.set(f"Ошибка: {self._flood_error}")
            self._append_output("[ERROR] Flooder stopped after an error")
        else:
            self.status_var.set("Флудер завершив роботу")
            self._append_output("[INFO] Flood complete")

    def _stop_flood(self):
        stop_flood()
        self._append_output("[INFO] Цикл зупинено користувачем")
        self.status_var.set("Цикл зупинено…")

    def _on_destroy(self, event: tk.Event) -> None:
        if event.widget is self:
            try:
                self._bridge.stop()
            except Exception:
                pass
