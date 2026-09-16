# xss_security_gui/gui/mutator_tasks_panel.py
# ============================================================
# MutatorTasksPanel 9.0 — async, heatmap, filters, popup 2.0
# ============================================================

import tkinter as tk
from tkinter import ttk
import json


class MutatorTasksPanel(tk.Frame):
    """
    MutatorTasksPanel 9.0
    ---------------------
    • Повна асинхронність через UIQueueBridge
    • Heatmap ризиків (critical/high/medium/low)
    • Popup‑details 2.0 (pretty JSON + copy)
    • Фільтри сімейств + фільтри ризиків
    • Автооновлення вкладок (headers, cookies, CSP, tech, history, WAF)
    • Підтримка defense_evasion + recon + forms + js + graphql + headers/errors
    """

    SUPPORTED_FAMILIES = [
        "all",
        "xss",
        "sqli",
        "csrf",
        "ssrf",
        "defense_evasion",
        "recon",
        "forms",
        "headers",
        "errors",
        "graphql",
        "js",
    ]

    RISK_COLORS = {
        "critical": "#ff4d4f",
        "high": "#ff7a45",
        "medium": "#faad14",
        "low": "#52c41a",
        "unknown": "#d9d9d9",
    }

    def __init__(self, parent, task_manager, ui_bridge, family="defense_evasion"):
        super().__init__(parent)
        self.task_manager = task_manager
        self.ui_bridge = ui_bridge
        self.family = family
        self.rows = {}

        # Notebook
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)

        # Tabs
        self.tab_tasks = ttk.Frame(self.notebook)
        self.tab_info = ttk.Frame(self.notebook)
        self.tab_headers = ttk.Frame(self.notebook)
        self.tab_cookies = ttk.Frame(self.notebook)
        self.tab_csp = ttk.Frame(self.notebook)
        self.tab_tech = ttk.Frame(self.notebook)
        self.tab_history = ttk.Frame(self.notebook)
        self.tab_waf = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_tasks, text="Задачи")
        self.notebook.add(self.tab_info, text="Информация")
        self.notebook.add(self.tab_headers, text="Заголовки")
        self.notebook.add(self.tab_cookies, text="Cookies")
        self.notebook.add(self.tab_csp, text="CSP")
        self.notebook.add(self.tab_tech, text="Технологии")
        self.notebook.add(self.tab_history, text="История")
        self.notebook.add(self.tab_waf, text="WAF")

        # Build UI
        self._build_tasks_tab()

        # Textboxes
        self.info_text = self._build_textbox(self.tab_info)
        self.headers_text = self._build_textbox(self.tab_headers)
        self.cookies_text = self._build_textbox(self.tab_cookies)
        self.csp_text = self._build_textbox(self.tab_csp)
        self.tech_text = self._build_textbox(self.tab_tech)
        self.history_text = self._build_textbox(self.tab_history)
        self.waf_text = self._build_textbox(self.tab_waf)

        # MutatorManager callbacks → через UIQueueBridge
        task_manager.on_task_added = lambda tid, payload: \
            self.ui_bridge.post_ui(self.on_task_added, tid, payload)

        task_manager.on_task_started = lambda tid, payload: \
            self.ui_bridge.post_ui(self.on_task_started, tid, payload)

        task_manager.on_task_finished = lambda tid, result: \
            self.ui_bridge.post_ui(self.on_task_finished, tid, result)

        task_manager.on_task_error = lambda tid, result: \
            self.ui_bridge.post_ui(self.on_task_error, tid, result)

    # ============================================================
    # Tasks Tab
    # ============================================================
    def _build_tasks_tab(self):
        ttk.Label(
            self.tab_tasks,
            text="Активные задачи:",
            font=("Segoe UI", 11, "bold")
        ).pack(anchor="w", padx=5, pady=5)

        # Filters
        filter_frame = ttk.Frame(self.tab_tasks)
        filter_frame.pack(fill="x", padx=5)

        for fam in self.SUPPORTED_FAMILIES:
            ttk.Button(
                filter_frame,
                text=fam,
                command=lambda f=fam: self.filter_family(f)
            ).pack(side="left", padx=2)

        # Risk filters
        ttk.Button(filter_frame, text="risk:critical", command=lambda: self.filter_risk("critical")).pack(side="left", padx=2)
        ttk.Button(filter_frame, text="risk:high", command=lambda: self.filter_risk("high")).pack(side="left", padx=2)
        ttk.Button(filter_frame, text="risk:medium", command=lambda: self.filter_risk("medium")).pack(side="left", padx=2)
        ttk.Button(filter_frame, text="risk:low", command=lambda: self.filter_risk("low")).pack(side="left", padx=2)
        ttk.Button(filter_frame, text="risk:all", command=lambda: self.filter_risk("all")).pack(side="left", padx=2)

        # Table
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

        # Headers
        self.tree.heading("task", text="Задача")
        self.tree.heading("type", text="Тип")
        self.tree.heading("status", text="Статус")
        self.tree.heading("risk", text="Риск")
        self.tree.heading("family", text="Семейство")
        self.tree.heading("duration", text="Длительность")

        # Columns
        self.tree.column("task", width=350, anchor="w")
        self.tree.column("type", width=80, anchor="center")
        self.tree.column("status", width=200, anchor="center")
        self.tree.column("risk", width=60, anchor="center")
        self.tree.column("family", width=120, anchor="center")
        self.tree.column("duration", width=100, anchor="center")

        # Tags
        self.tree.tag_configure("running", foreground="#d4a017")
        self.tree.tag_configure("done", foreground="#2ecc71")
        self.tree.tag_configure("error", foreground="#e74c3c")

        # Heatmap
        for risk, color in self.RISK_COLORS.items():
            self.tree.tag_configure(f"risk_{risk}", background=color)

        # Layout
        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        x_scroll.config(command=self.tree.xview)
        y_scroll.config(command=self.tree.yview)

        # Popup
        self.tree.bind("<Double-1>", self.on_row_double_click)

        # Stats
        stats_frame = ttk.Frame(self.tab_tasks)
        stats_frame.pack(fill="x", padx=5, pady=(0, 5))

        self.stats_label = ttk.Label(
            stats_frame,
            text="Статистика: задач=0 | high‑risk=0 | ошибок=0 | средняя длительность=0.00s",
            font=("Segoe UI", 10)
        )
        self.stats_label.pack(anchor="w")

    # ============================================================
    # Textboxes
    # ============================================================
    def _build_textbox(self, parent):
        text = tk.Text(parent, wrap="word")
        text.pack(fill="both", expand=True)
        return text

    # ============================================================
    # Callbacks
    # ============================================================
    def on_task_added(self, task_id, payload):
        meta = self.task_manager.get_meta(task_id)
        label = self._extract_label(payload)

        self.tree.insert(
            "",
            "end",
            iid=task_id,
            values=(label, meta["type"], "🟡 Ожидание", "-", meta.get("family", "-"), "-"),
            tags=("running",)
        )
        self.update_stats()

    def on_task_started(self, task_id, payload):
        if not self.tree.exists(task_id):
            return

        meta = self.task_manager.get_meta(task_id)
        label = self._extract_label(payload)

        self.tree.item(
            task_id,
            values=(label, meta["type"], "🟡 В процессе", "-", meta.get("family", "-"), "-"),
            tags=("running",)
        )
        self.update_stats()

    def on_task_finished(self, task_id, result):
        if not self.tree.exists(task_id):
            return
        self.update_task(task_id, result)
        self.update_stats()

    def on_task_error(self, task_id, result):
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

    # ============================================================
    # Update Task
    # ============================================================
    def update_task(self, task_id, result):
        meta = self.task_manager.get_meta(task_id)
        label = self._extract_label(result.get("payload"))
        duration = f"{result.get('duration', 0):.2f}s"

        risk = result.get("risk", "unknown")
        family = meta.get("family", "-")
        count = result.get("count", 0)

        status_text = (
            f"🟢 Найдено {count} элементов"
            if count > 0 else
            "🟢 Готово (ничего не найдено)"
        )

        tags = ["done"]
        if risk in self.RISK_COLORS:
            tags.append(f"risk_{risk}")

        self.tree.item(
            task_id,
            values=(label, meta["type"], status_text, risk, family, duration),
            tags=tags
        )

        # Update info tabs
        for key, widget in [
            ("site_info", self.info_text),
            ("headers", self.headers_text),
            ("cookies", self.cookies_text),
            ("csp", self.csp_text),
            ("tech", self.tech_text),
            ("history", self.history_text),
            ("waf", self.waf_text),
        ]:
            if result.get(key):
                self._update_textbox(widget, result[key])

    # ============================================================
    # Popup
    # ============================================================
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

    # ============================================================
    # Filters
    # ============================================================
    def filter_family(self, fam):
        for iid in self.tree.get_children():
            vals = self.tree.item(iid)["values"]
            family = vals[4]
            if fam == "all" or family == fam:
                self.tree.reattach(iid, "", "end")
            else:
                self.tree.detach(iid)

    def filter_risk(self, risk):
        for iid in self.tree.get_children():
            vals = self.tree.item(iid)["values"]
            r = vals[3]
            if risk == "all" or r == risk:
                self.tree.reattach(iid, "", "end")
            else:
                self.tree.detach(iid)

    # ============================================================
    # Helpers
    # ============================================================
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
        high_risk = sum(1 for t in tasks if t.get("risk") == "high")
        errors = sum(1 for t in tasks if t.get("status") == "error")
        durations = [t.get("duration", 0) for t in tasks if t.get("duration")]

        avg_duration = sum(durations) / len(durations) if durations else 0.0

        self.stats_label.config(
            text=(
                f"Статистика: "
                f"задач={total} | "
                f"high‑risk={high_risk} | "
                f"ошибок={errors} | "
                f"средняя длительность={avg_duration:.2f}s"
            )
        )


