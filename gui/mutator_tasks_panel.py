# xss_security_gui/gui/mutator_tasks_panel.py

import tkinter as tk
from tkinter import ttk
import json


class MutatorTasksPanel(tk.Frame):
    """
    MutatorTasksPanel ULTRA (GUI-only)
    ----------------------------------
    • Вкладки (Notebook)
    • Popup‑details
    • Heatmap ризиків
    • Фільтри за сімействами
    • Розширена статистика
    • Інформаційні секції (headers, cookies, CSP, tech, history, WAF)
    """

    def __init__(self, parent, task_manager):
        super().__init__(parent)
        self.task_manager = task_manager
        # === Мапа task_id → row_id ===
        self.rows = {}

        # -------------------------------
        # Notebook (вкладки)
        # -------------------------------
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)

        # Вкладки
        self.tab_tasks = ttk.Frame(self.notebook)
        self.tab_info = ttk.Frame(self.notebook)
        self.tab_headers = ttk.Frame(self.notebook)
        self.tab_cookies = ttk.Frame(self.notebook)
        self.tab_csp = ttk.Frame(self.notebook)
        self.tab_tech = ttk.Frame(self.notebook)
        self.tab_history = ttk.Frame(self.notebook)
        self.tab_waf = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_tasks, text="Задачи")
        self.notebook.add(self.tab_info, text="Информация о сайте")
        self.notebook.add(self.tab_headers, text="Заголовки")
        self.notebook.add(self.tab_cookies, text="Cookies")
        self.notebook.add(self.tab_csp, text="CSP")
        self.notebook.add(self.tab_tech, text="Технологии")
        self.notebook.add(self.tab_history, text="История")
        self.notebook.add(self.tab_waf, text="WAF")

        # -------------------------------
        # Вкладка "Задачи"
        # -------------------------------
        self._build_tasks_tab()

        # -------------------------------
        # Інформаційні вкладки
        # -------------------------------
        self.info_text = self._build_textbox(self.tab_info)
        self.headers_text = self._build_textbox(self.tab_headers)
        self.cookies_text = self._build_textbox(self.tab_cookies)
        self.csp_text = self._build_textbox(self.tab_csp)
        self.tech_text = self._build_textbox(self.tab_tech)
        self.history_text = self._build_textbox(self.tab_history)
        self.waf_text = self._build_textbox(self.tab_waf)

        # -------------------------------
        # Підключення callback’ів
        # -------------------------------
        task_manager.on_task_added = self.on_task_added
        task_manager.on_task_started = self.on_task_started
        task_manager.on_task_finished = self.on_task_finished
        task_manager.on_task_error = self.on_task_error

    # =========================================================
    # Вкладка "Задачи"
    # =========================================================
    def _build_tasks_tab(self):
        ttk.Label(
            self.tab_tasks,
            text="Активные задачи:",
            font=("Segoe UI", 11, "bold")
        ).pack(anchor="w", padx=5, pady=5)

        # Фільтри сімейств
        filter_frame = ttk.Frame(self.tab_tasks)
        filter_frame.pack(fill="x", padx=5)

        families = ["all", "recon", "auth", "xss", "headers", "secrets", "forms", "errors", "graphql", "js"]

        for fam in families:
            ttk.Button(
                filter_frame,
                text=fam,
                command=lambda f=fam: self.filter_family(f)
            ).pack(side="left", padx=2)

        # Таблиця
        frame = ttk.Frame(self.tab_tasks)
        frame.pack(fill="both", expand=True, padx=5, pady=5)

        x_scroll = ttk.Scrollbar(frame, orient="horizontal")
        y_scroll = ttk.Scrollbar(frame, orient="vertical")

        self.tree = ttk.Treeview(
            frame,
            columns=("task", "type", "status", "risk", "family", "duration"),
            show="headings",
            xscrollcommand=x_scroll.set,
            yscrollcommand=y_scroll.set
        )

        # Заголовки
        self.tree.heading("task", text="Задача")
        self.tree.heading("type", text="Тип")
        self.tree.heading("status", text="Статус")
        self.tree.heading("risk", text="Риск")
        self.tree.heading("family", text="Семейство")
        self.tree.heading("duration", text="Длительность")

        # Колонки
        self.tree.column("task", width=350, anchor="w")
        self.tree.column("type", width=80, anchor="center")
        self.tree.column("status", width=200, anchor="center")
        self.tree.column("risk", width=60, anchor="center")
        self.tree.column("family", width=120, anchor="center")
        self.tree.column("duration", width=100, anchor="center")

        # Теги
        self.tree.tag_configure("running", foreground="#d4a017")
        self.tree.tag_configure("done", foreground="#2ecc71")
        self.tree.tag_configure("error", foreground="#e74c3c")

        # Heatmap
        self.tree.tag_configure("risk_high", background="#ffcccc")
        self.tree.tag_configure("risk_medium", background="#fff0b3")
        self.tree.tag_configure("risk_low", background="#e6ffe6")

        # Розміщення
        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        x_scroll.config(command=self.tree.xview)
        y_scroll.config(command=self.tree.yview)

        # Popup‑details
        self.tree.bind("<Double-1>", self.on_row_double_click)

        # Статистика
        stats_frame = ttk.Frame(self.tab_tasks)
        stats_frame.pack(fill="x", padx=5, pady=(0, 5))

        self.stats_label = ttk.Label(
            stats_frame,
            text="Статистика: задач=0 | модулей=0 | мутаторов=0 | high‑risk=0 | ошибок=0 | средняя длительность=0.00s",
            font=("Segoe UI", 10)
        )
        self.stats_label.pack(anchor="w")

    # =========================================================
    # Текстові вкладки
    # =========================================================
    def _build_textbox(self, parent):
        text = tk.Text(parent, wrap="word")
        text.pack(fill="both", expand=True)
        return text

    # =========================================================
    # Callback’и задач
    # =========================================================
    def on_task_added(self, task_id: str, payload):
        meta = self.task_manager.get_meta(task_id)
        label = self._extract_label(payload)

        self.tree.insert(
            "",
            "end",
            iid=task_id,
            values=(label, meta["type"], "🟡 Ожидание", "-", "-", "-"),
            tags=("running",)
        )
        self.update_stats()

    def on_task_started(self, task_id: str, payload):
        if not self.tree.exists(task_id):
            return

        meta = self.task_manager.get_meta(task_id)
        label = self._extract_label(payload)

        self.tree.item(
            task_id,
            values=(label, meta["type"], "🟡 В процессе", "-", "-", "-"),
            tags=("running",)
        )
        self.update_stats()

    def on_task_finished(self, task_id: str, result: dict):
        if not self.tree.exists(task_id):
            return
        self.update_task(task_id, result)
        self.update_stats()

    def on_task_error(self, task_id: str, result: dict):
        if not self.tree.exists(task_id):
            return

        label = self._extract_label(result.get("payload"))
        duration = f"{result.get('duration', 0):.2f}s"

        self.tree.item(
            task_id,
            values=(label, result.get("task_type", "-"), f"🔴 Ошибка: {result['error']}", "-", "-", duration),
            tags=("error",)
        )
        self.update_stats()

    def add_task(self, task_id: str, label: str):
        """
        Добавляет задачу в Mutator Tasks Panel.
        task_id — уникальный ID задачи из MutatorTaskManager
        label — текстовое описание (payload или имя модуля)
        """
        try:
            row_id = self.tree.insert(
                "",
                "end",
                values=(task_id, label, "pending")
            )
            self.rows[task_id] = row_id
        except Exception as e:
            print(f"[MutatorTasksPanel] Ошибка add_task: {e}")

    # =========================================================
    # Оновлення задачі
    # =========================================================
    def update_task(self, task_id: str, result: dict):
        meta = self.task_manager.get_meta(task_id)
        label = self._extract_label(result.get("payload"))
        duration = f"{result.get('duration', 0):.2f}s"

        # Модуль
        risk = result.get("risk", "-")
        family = result.get("family", "-")
        count = result.get("count", 0)

        if count == 0:
            status_text = "🟢 Готово (ничего не найдено)"
        else:
            status_text = f"🟢 Найдено {count} элементов"

        # Heatmap
        tags = ["done"]
        if isinstance(risk, int):
            if risk >= 8:
                tags.append("risk_high")
            elif risk >= 5:
                tags.append("risk_medium")
            else:
                tags.append("risk_low")

        self.tree.item(
            task_id,
            values=(label, meta["type"], status_text, risk, family, duration),
            tags=tags
        )

        # Оновлення вкладок
        if result.get("site_info"):
            self._update_textbox(self.info_text, result["site_info"])

        if result.get("headers"):
            self._update_textbox(self.headers_text, result["headers"])

        if result.get("cookies"):
            self._update_textbox(self.cookies_text, result["cookies"])

        if result.get("csp"):
            self._update_textbox(self.csp_text, result["csp"])

        if result.get("tech"):
            self._update_textbox(self.tech_text, result["tech"])

        if result.get("history"):
            self._update_textbox(self.history_text, result["history"])

        if result.get("waf"):
            self._update_textbox(self.waf_text, result["waf"])

    # =========================================================
    # Popup‑details
    # =========================================================
    def on_row_double_click(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return

        result = self.task_manager.get_result(item)
        if not result:
            return

        win = tk.Toplevel(self)
        win.title("Детали задачи")
        win.geometry("700x500")

        text = tk.Text(win, wrap="word")
        text.pack(fill="both", expand=True)

        text.insert("1.0", json.dumps(result, indent=2, ensure_ascii=False))

    # =========================================================
    # Фільтр сімейств
    # =========================================================
    def filter_family(self, fam):
        for iid in self.tree.get_children():
            vals = self.tree.item(iid)["values"]
            family = vals[4]
            if fam == "all" or family == fam:
                self.tree.reattach(iid, "", "end")
            else:
                self.tree.detach(iid)

    # =========================================================
    # Допоміжні
    # =========================================================
    def _extract_label(self, payload):
        if isinstance(payload, dict) and "payload" in payload:
            return payload["payload"]
        return str(payload)

    def _update_textbox(self, widget, data):
        widget.delete("1.0", "end")
        widget.insert("1.0", json.dumps(data, indent=2, ensure_ascii=False))

    def update_stats(self):
        tasks = self.task_manager.list_tasks()

        total = len(tasks)
        modules = sum(1 for t in tasks if t["type"] == "module")
        mutators = sum(1 for t in tasks if t["type"] == "mutator")

        high_risk = 0
        errors = 0
        durations = []

        for t in tasks:
            tid = t["id"]

            if t.get("duration"):
                durations.append(t["duration"])

            if self.task_manager.status(tid) == "error":
                errors += 1

            risk = t.get("risk", 0)
            if isinstance(risk, int) and risk >= 8:
                high_risk += 1

        avg_duration = sum(durations) / len(durations) if durations else 0.0

        self.stats_label.config(
            text=(
                f"Статистика: "
                f"задач={total} | "
                f"модулей={modules} | "
                f"мутаторов={mutators} | "
                f"high‑risk={high_risk} | "
                f"ошибок={errors} | "
                f"средняя длительность={avg_duration:.2f}s"
            )
        )