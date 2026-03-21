# xss_security_gui/live_monitor.py

from __future__ import annotations
import queue
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from collections import Counter, deque
from typing import Dict, Any, List

EventDict = Dict[str, Any]


class LiveAttackMonitor(ttk.Frame):
    """
    Live Attack Monitor — Enterprise AI 5.0

    Функціонал:
    - Ручной запуск / остановка
    - Пауза / продолжение
    - Буферизация вставок (пачками)
    - Авто‑scroll только если пользователь внизу
    - Поиск по логу
    - Подсветка модулей и severity
    - Авто‑очистка по количеству строк
    - Счётчик событий
    - Панель статистики по severity и модулям
    - Экспорт видимых событий в JSON
    - Режим "summary" (короткие строки вместо полного JSON)
    - AI‑Insights:
        * rule‑based “умный” анализ потока событий
        * детекция всплесков HIGH‑событий
        * детекция массовых DOM/endpoint атак
        * подсказки по возможным сценариям атак
    """

    MAX_LINES = 8000
    INSERT_BATCH = 50

    def __init__(self, parent: tk.Misc, event_queue: queue.Queue[EventDict]):
        super().__init__(parent)

        self.event_queue = event_queue
        self._running = False
        self._paused = False
        self._counter = 0
        self._buffer: List[EventDict] = []
        self._visible_events: List[EventDict] = []
        self._severity_stats = Counter()
        self._module_stats = Counter()
        self._summary_mode = tk.BooleanVar(value=False)

        # Для "AI‑аналитики"
        self._recent_events = deque(maxlen=500)
        self._high_timestamps = deque(maxlen=200)
        self._dom_counter_window = deque(maxlen=200)
        self._endpoint_counter_window = deque(maxlen=200)
        self._last_ai_insight_ts = 0.0

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

        self.start_btn = ttk.Button(top, text="▶ Запустить", command=self.start_monitor)
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = ttk.Button(top, text="⏹ Стоп", command=self.stop_monitor, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        self.pause_btn = ttk.Button(top, text="⏸ Пауза", command=self.toggle_pause, state="disabled")
        self.pause_btn.pack(side="left", padx=5)

        ttk.Button(top, text="🧹 Очистить", command=self.clear).pack(side="left", padx=5)
        ttk.Button(top, text="🔍 Поиск", command=self.search_popup).pack(side="left", padx=5)
        ttk.Button(top, text="📤 Экспорт JSON", command=self.export_json).pack(side="left", padx=5)

        ttk.Checkbutton(
            top,
            text="Summary mode",
            variable=self._summary_mode,
            command=self._redraw_from_visible,
        ).pack(side="left", padx=5)

        self.counter_var = tk.StringVar(value="0 событий")
        ttk.Label(top, textvariable=self.counter_var).pack(side="right", padx=10)

        # ===== Панель статистики =====
        stats = ttk.Frame(self)
        stats.pack(fill="x", pady=3)

        self.sev_stats_var = tk.StringVar(value="Severity: H=0 M=0 L=0 E=0")
        self.mod_stats_var = tk.StringVar(value="Modules: dom=0 endpoint=0 api=0 token=0")

        ttk.Label(stats, textvariable=self.sev_stats_var).pack(side="left", padx=5)
        ttk.Label(stats, textvariable=self.mod_stats_var).pack(side="right", padx=5)

        # ===== Основной лог =====
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True)

        self.text = tk.Text(main_frame, height=18, bg="#000", fg="#0f0")
        self.text.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        self.text.tag_configure("high", foreground="#ff4444")
        self.text.tag_configure("medium", foreground="#ffaa00")
        self.text.tag_configure("low", foreground="#888888")
        self.text.tag_configure("error", foreground="#ff00ff")

        self.text.tag_configure("dom", foreground="#00eaff")
        self.text.tag_configure("endpoint", foreground="#00ff88")
        self.text.tag_configure("api", foreground="#66ff66")
        self.text.tag_configure("token", foreground="#ff66ff")

        # ===== AI‑Insights панель =====
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side="right", fill="y", padx=5, pady=5)

        ttk.Label(right_frame, text="🤖 AI Insights").pack(anchor="w")
        self.ai_text = tk.Text(right_frame, height=18, width=40, bg="#050505", fg="#00ffaa", wrap="word")
        self.ai_text.pack(fill="both", expand=True)

        self.ai_text.tag_configure("alert", foreground="#ff5555")
        self.ai_text.tag_configure("hint", foreground="#ffaa00")
        self.ai_text.tag_configure("info", foreground="#00ffaa")

    # ============================================================
    # Управление
    # ============================================================

    def start_monitor(self):
        if self._running:
            return
        self._running = True
        self._paused = False

        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.pause_btn.config(state="normal", text="⏸ Пауза")

        self._log_system("▶ Монитор запущен")

        self.after(200, self._poll_events)
        self.after(120, self._flush_buffer)

    def stop_monitor(self):
        self._running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.pause_btn.config(state="disabled")

        self._log_system("⏹ Монитор остановлен")

    def toggle_pause(self):
        if not self._running:
            return
        self._paused = not self._paused
        self.pause_btn.config(text="▶ Продолжить" if self._paused else "⏸ Пауза")
        self._log_system("⏸ Пауза" if self._paused else "▶ Продолжение")

    def clear(self):
        self.text.delete("1.0", "end")
        self.ai_text.delete("1.0", "end")
        self._counter = 0
        self._buffer.clear()
        self._visible_events.clear()
        self._severity_stats.clear()
        self._module_stats.clear()
        self._recent_events.clear()
        self._high_timestamps.clear()
        self._dom_counter_window.clear()
        self._endpoint_counter_window.clear()
        self._update_stats_labels()
        self.counter_var.set("0 событий")

    def _log_system(self, msg: str):
        try:
            self.text.insert("end", f"[SYSTEM] {msg}\n")
            self.text.see("end")
        except Exception:
            pass

    # ============================================================
    # Поиск
    # ============================================================

    def search_popup(self):
        popup = tk.Toplevel(self)
        popup.title("Поиск")
        tk.Label(popup, text="Введите строку:").pack(padx=10, pady=5)
        entry = tk.Entry(popup, width=40)
        entry.pack(padx=10, pady=5)
        entry.focus()

        def do_search():
            term = entry.get().strip()
            if term:
                self._search_in_text(term)
            popup.destroy()

        ttk.Button(popup, text="Искать", command=do_search).pack(pady=10)

    def _search_in_text(self, term: str):
        self.text.tag_remove("search", "1.0", "end")
        start = "1.0"
        while True:
            pos = self.text.search(term, start, stopindex="end", nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(term)}c"
            self.text.tag_add("search", pos, end)
            start = end
        self.text.tag_configure("search", background="#3333aa")

    # ============================================================
    # Экспорт
    # ============================================================

    def export_json(self):
        if not self._visible_events:
            messagebox.showinfo("Экспорт", "Нет видимых событий для экспорта.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            title="Сохранить события в JSON",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._visible_events, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Экспорт", f"Экспортировано {len(self._visible_events)} событий.")
        except Exception as e:
            messagebox.showerror("Ошибка экспорта", str(e))

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
                    self._buffer.append(event)
            except queue.Empty:
                pass

        self.after(200, self._poll_events)

    # ============================================================
    # Вставка пачками
    # ============================================================

    def _flush_buffer(self):
        if not self._running:
            return

        if self._paused or not self._buffer:
            self.after(120, self._flush_buffer)
            return

        batch = self._buffer[:self.INSERT_BATCH]
        del self._buffer[:self.INSERT_BATCH]

        for event in batch:
            self._insert_event_safe(event)

        self.after(120, self._flush_buffer)

    def _insert_event_safe(self, event: EventDict):
        try:
            self._insert_event(event)
        except Exception as e:
            self._log_system(f"Ошибка обработки события: {e}")

    # ============================================================
    # Обработка события + AI‑аналитика
    # ============================================================

    def _insert_event(self, event: EventDict):
        sev_filter = self.sev_var.get()
        mod_filter = self.mod_var.get().strip().lower()

        severity = str(event.get("severity", "info")).lower()
        module = str(event.get("module", "")).lower()

        if sev_filter != "all" and severity != sev_filter:
            return
        if mod_filter and mod_filter not in module:
            return

        # обновляем статистику
        self._severity_stats[severity] += 1
        if "dom" in module:
            self._module_stats["dom"] += 1
        elif "endpoint" in module:
            self._module_stats["endpoint"] += 1
        elif "api" in module:
            self._module_stats["api"] += 1
        elif "token" in module:
            self._module_stats["token"] += 1

        self._update_stats_labels()

        # сохраняем видимое событие
        self._visible_events.append(event)
        self._recent_events.append((time.time(), event))

        # AI‑аналитика
        self._ai_process_event(severity, module, event)

        # строка для вывода
        if self._summary_mode.get():
            line = self._format_summary_line(event, severity, module)
        else:
            line = json.dumps(event, ensure_ascii=False)

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

        at_bottom = self.text.yview()[1] > 0.95

        self.text.insert("end", line + "\n", tuple(tags))

        if at_bottom:
            self.text.see("end")

        self._counter += 1
        self.counter_var.set(f"{self._counter} событий")

        if float(self.text.index("end")) > self.MAX_LINES:
            self.text.delete("1.0", "2000.0")

    def _format_summary_line(self, event: EventDict, severity: str, module: str) -> str:
        target = event.get("target") or event.get("url") or ""
        category = event.get("category", "")
        msg = event.get("message") or event.get("detail") or ""
        base = f"[{severity.upper()}] [{module}]"
        if category:
            base += f" [{category}]"
        if target:
            base += f" → {target}"
        if msg:
            base += f" :: {msg}"
        return base

    def _update_stats_labels(self):
        h = self._severity_stats.get("high", 0)
        m = self._severity_stats.get("medium", 0)
        l = self._severity_stats.get("low", 0)
        e = self._severity_stats.get("error", 0)
        self.sev_stats_var.set(f"Severity: H={h} M={m} L={l} E={e}")

        d = self._module_stats.get("dom", 0)
        ep = self._module_stats.get("endpoint", 0)
        api = self._module_stats.get("api", 0)
        tok = self._module_stats.get("token", 0)
        self.mod_stats_var.set(f"Modules: dom={d} endpoint={ep} api={api} token={tok}")

    def _redraw_from_visible(self):
        self.text.delete("1.0", "end")
        for ev in self._visible_events:
            severity = str(ev.get("severity", "info")).lower()
            module = str(ev.get("module", "")).lower()
            if self._summary_mode.get():
                line = self._format_summary_line(ev, severity, module)
            else:
                line = json.dumps(ev, ensure_ascii=False)

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

            self.text.insert("end", line + "\n", tuple(tags))
        self.text.see("end")

    # ============================================================
    # AI‑логика (rule‑based)
    # ============================================================

    def _ai_process_event(self, severity: str, module: str, event: EventDict):
        now = time.time()

        # 1) Всплеск HIGH‑событий
        if severity == "high":
            self._high_timestamps.append(now)
            self._ai_check_high_burst(now)

        # 2) Массовые DOM‑события
        if "dom" in module:
            self._dom_counter_window.append(now)
            self._ai_check_dom_burst(now)

        # 3) Массовые endpoint‑события
        if "endpoint" in module:
            self._endpoint_counter_window.append(now)
            self._ai_check_endpoint_burst(now)

        # 4) Специфические паттерны по полям
        self._ai_check_token_pattern(event)
        self._ai_check_xss_pattern(event)

    def _ai_check_high_burst(self, now: float):
        # если за последние 30 секунд > N HIGH‑событий — сигнал
        window = 30.0
        threshold = 10
        while self._high_timestamps and now - self._high_timestamps[0] > window:
            self._high_timestamps.popleft()
        if len(self._high_timestamps) >= threshold:
            self._ai_log(
                "⚠️ Всплеск HIGH‑событий",
                "За последние 30 секунд зафиксировано много критичных событий. Возможна активная атака.",
                tag="alert",
            )

    def _ai_check_dom_burst(self, now: float):
        window = 20.0
        threshold = 15
        while self._dom_counter_window and now - self._dom_counter_window[0] > window:
            self._dom_counter_window.popleft()
        if len(self._dom_counter_window) >= threshold:
            self._ai_log(
                "🧨 Подозрительная активность DOM‑XSS",
                "Много DOM‑событий за короткий период. Проверьте обработку клиентских скриптов и CSP.",
                tag="alert",
            )

    def _ai_check_endpoint_burst(self, now: float):
        window = 20.0
        threshold = 15
        while self._endpoint_counter_window and now - self._endpoint_counter_window[0] > window:
            self._endpoint_counter_window.popleft()
        if len(self._endpoint_counter_window) >= threshold:
            self._ai_log(
                "🌐 Массовые запросы к endpoint‑ам",
                "Высокая активность по endpoint‑модулям. Возможен сканинг API или brute‑force.",
                tag="alert",
            )

    def _ai_check_token_pattern(self, event: EventDict):
        module = str(event.get("module", "")).lower()
        if "token" not in module:
            return
        status = event.get("status")
        token = event.get("token") or event.get("value") or ""
        if status in (401, 403):
            self._ai_log(
                "🔐 Подбор токенов",
                f"Обнаружены неуспешные проверки токенов (status={status}). Возможен перебор токенов: {token}",
                tag="hint",
            )
        elif status in (200, 201):
            self._ai_log(
                "🔓 Валидный токен",
                f"Найден валидный токен (status={status}). Проверьте политику доступа и ротацию токенов.",
                tag="alert",
            )

    def _ai_check_xss_pattern(self, event: EventDict):
        payload = str(event.get("payload") or "")
        if "<script" in payload.lower() or "onerror=" in payload.lower():
            self._ai_log(
                "🧬 XSS‑payload в трафике",
                "Обнаружен XSS‑payload в событиях. Проверьте отражение данных и фильтрацию ввода.",
                tag="hint",
            )

    def _ai_log(self, title: str, message: str, tag: str = "info"):
        now = time.time()
        # не спамим слишком часто одинаковыми подсказками
        if now - self._last_ai_insight_ts < 2.0 and tag != "alert":
            return
        self._last_ai_insight_ts = now
        try:
            self.ai_text.insert("end", f"{title}\n", (tag,))
            self.ai_text.insert("end", f"  {message}\n\n", (tag,))
            self.ai_text.see("end")
        except Exception:
            pass

    # ============================================================
    # Остановка
    # ============================================================

    def stop(self):
        self._running = False