# xss_security_gui/live_monitor.py

from __future__ import annotations

import queue
import json
import tkinter as tk
from tkinter import ttk

EventDict = dict


class LiveAttackMonitor(ttk.Frame):
    """
    Live Attack Monitor ULTRA 2.5

    - Потокобезопасный приём событий через queue.Queue
    - Авто‑scroll
    - Фильтр по severity/module
    - Пауза/продолжение
    - Очистка лога
    - Авто‑очистка при переполнении
    - Подсветка модулей
    - Счётчик событий
    """

    MAX_LINES = 5000  # авто‑очистка при превышении

    def __init__(self, parent: tk.Misc, event_queue: queue.Queue[EventDict]):
        super().__init__(parent)

        self.event_queue = event_queue
        self._running = True
        self._paused = False
        self._counter = 0

        # ===== Верхняя панель =====
        top = ttk.Frame(self)
        top.pack(fill="x", pady=3)

        ttk.Label(top, text="Severity:").pack(side="left", padx=5)
        self.sev_var = tk.StringVar(value="all")
        self.sev_box = ttk.Combobox(
            top,
            textvariable=self.sev_var,
            values=["all", "high", "medium", "low", "error"],
            width=10,
            state="readonly",
        )
        self.sev_box.pack(side="left")

        ttk.Label(top, text="Module:").pack(side="left", padx=5)
        self.mod_var = tk.StringVar(value="")
        self.mod_entry = ttk.Entry(top, textvariable=self.mod_var, width=15)
        self.mod_entry.pack(side="left")

        # Пауза
        self.pause_btn = ttk.Button(top, text="⏸ Пауза", command=self.toggle_pause)
        self.pause_btn.pack(side="left", padx=5)

        # Очистить
        ttk.Button(top, text="🧹 Очистить", command=self.clear).pack(side="left", padx=5)

        # Счётчик
        self.counter_var = tk.StringVar(value="0 событий")
        ttk.Label(top, textvariable=self.counter_var).pack(side="right", padx=10)

        # ===== Текстовое окно =====
        self.text = tk.Text(self, height=20, bg="#000", fg="#0f0")
        self.text.pack(fill="both", expand=True, padx=5, pady=5)

        # Цвета по severity
        self.text.tag_configure("high", foreground="#ff4444")
        self.text.tag_configure("medium", foreground="#ffaa00")
        self.text.tag_configure("low", foreground="#888888")
        self.text.tag_configure("error", foreground="#ff00ff")

        # Цвета по модулям
        self.text.tag_configure("dom", foreground="#00eaff")
        self.text.tag_configure("endpoint", foreground="#00ff88")
        self.text.tag_configure("api", foreground="#66ff66")
        self.text.tag_configure("token", foreground="#ff66ff")

        self.after(200, self._poll_events)

    # ============================================================
    # Управление
    # ============================================================

    def toggle_pause(self):
        self._paused = not self._paused
        self.pause_btn.config(text="▶ Продолжить" if self._paused else "⏸ Пауза")

    def clear(self):
        self.text.delete("1.0", "end")
        self._counter = 0
        self.counter_var.set("0 событий")

    # ============================================================
    # Получение событий
    # ============================================================

    def _poll_events(self):
        if not self._running:
            return

        if not self._paused:
            try:
                while True:
                    event = self.event_queue.get_nowait()
                    self._handle_event(event)
            except queue.Empty:
                pass

        self.after(200, self._poll_events)

    # ============================================================
    # Обработка события
    # ============================================================

    def _handle_event(self, event: EventDict):
        sev_filter = self.sev_var.get()
        mod_filter = self.mod_var.get().strip().lower()

        severity = str(event.get("severity", "info")).lower()
        module = str(event.get("module", "")).lower()

        # Фильтры
        if sev_filter != "all" and severity != sev_filter:
            return
        if mod_filter and mod_filter not in module:
            return

        # JSON строка
        line = json.dumps(event, ensure_ascii=False)

        # Теги
        tags = []
        if severity in ("high", "medium", "low", "error"):
            tags.append(severity)

        if "dom" in module:
            tags.append("dom")
        elif "endpoint" in module:
            tags.append("endpoint")
        elif "api" in module:
            tags.append("api")
        elif "token" in module:
            tags.append("token")

        # Вставка
        self.text.insert("end", line + "\n", tuple(tags))
        self.text.see("end")

        # Счётчик
        self._counter += 1
        self.counter_var.set(f"{self._counter} событий")

        # Авто‑очистка
        if float(self.text.index("end")) > self.MAX_LINES:
            self.text.delete("1.0", "2000.0")

    # ============================================================
    # Остановка
    # ============================================================

    def stop(self):
        self._running = False