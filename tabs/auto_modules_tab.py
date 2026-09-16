# xss_security_gui/tabs/auto_modules_tab.py
"""
AutoModules ULTRA Tab — полноценная GUI-панель для запуска всех
автоматических модулей атак (уровень Burp Suite Enterprise).

Все сканирования выполняются в фоновом потоке — GUI не фризится.
"""

from __future__ import annotations

import json
import threading
import time
import datetime
from typing import Any, Dict, List, Optional

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import requests
import logging

logger = logging.getLogger(__name__)

# Все доступные модули для чекбоксов
ALL_MODULE_NAMES = [
    "Technology Fingerprint",
    "Security Headers Audit",
    "CORS Misconfiguration",
    "HTTP Method Tampering",
    "API Endpoints",
    "Parameters Discovery",
    "XSS Targets",
    "Path Traversal",
    "Open Redirect",
    "CRLF Injection",
    "Token Brute Force",
    "User IDs Enumeration",
    "Forms & Inputs",
]

_SEV_COLORS = {
    "critical": "#ff2222",
    "high": "#ff6600",
    "medium": "#ffaa00",
    "low": "#44bb44",
    "info": "#4488ff",
    "error": "#999999",
}


class AutoModulesTab(ttk.Frame):
    """
    GUI-таб для AutoModulesEngine — запуск всех модулей,
    отображение результатов, экспорт, heatmap.
    """

    def __init__(self, parent, threat_tab=None):
        super().__init__(parent)
        self.threat_tab = threat_tab
        self._engine = None
        self._session: Optional[requests.Session] = None
        self._running = False
        self._cancel = False
        self._results: Dict[str, Any] = {}
        self._module_vars: Dict[str, tk.BooleanVar] = {}
        self._build_ui()

    # ----------------------------------------------------------
    #  UI
    # ----------------------------------------------------------
    def _build_ui(self):
        # Top bar: URL + controls
        top = ttk.Frame(self)
        top.pack(fill="x", padx=8, pady=(8, 4))

        ttk.Label(top, text="Target URL:").pack(side="left")
        self._url_var = tk.StringVar(value="https://")
        url_entry = ttk.Entry(top, textvariable=self._url_var, width=60)
        url_entry.pack(side="left", padx=(4, 8))

        self._btn_start = ttk.Button(top, text="▶ Full Scan", command=self._start_scan)
        self._btn_start.pack(side="left", padx=2)

        self._btn_stop = ttk.Button(top, text="⏹ Stop", command=self._stop_scan, state="disabled")
        self._btn_stop.pack(side="left", padx=2)

        self._btn_export = ttk.Button(top, text="💾 Export", command=self._export_results, state="disabled")
        self._btn_export.pack(side="left", padx=2)

        self._btn_clear = ttk.Button(top, text="🗑 Clear", command=self._clear_results)
        self._btn_clear.pack(side="left", padx=2)

        # Paned: left = modules checkboxes, right = results
        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=8, pady=4)

        # Left panel: module selection
        left_frame = ttk.LabelFrame(paned, text="Модули атак")
        paned.add(left_frame, weight=1)

        modules_canvas = tk.Canvas(left_frame, width=220, highlightthickness=0)
        modules_scroll = ttk.Scrollbar(left_frame, orient="vertical", command=modules_canvas.yview)
        modules_canvas.configure(yscrollcommand=modules_scroll.set)
        modules_canvas.pack(side="left", fill="both", expand=True)
        modules_scroll.pack(side="right", fill="y")

        modules_inner = ttk.Frame(modules_canvas)
        modules_canvas.create_window((0, 0), window=modules_inner, anchor="nw")
        modules_inner.bind(
            "<Configure>",
            lambda e: modules_canvas.configure(scrollregion=modules_canvas.bbox("all")),
        )

        # Select All / Deselect All
        btn_row = ttk.Frame(modules_inner)
        btn_row.pack(fill="x", padx=4, pady=(4, 2))
        ttk.Button(btn_row, text="✅ Все", width=8, command=self._select_all).pack(side="left", padx=2)
        ttk.Button(btn_row, text="❌ Нет", width=8, command=self._deselect_all).pack(side="left", padx=2)

        for mod_name in ALL_MODULE_NAMES:
            var = tk.BooleanVar(value=True)
            self._module_vars[mod_name] = var
            cb = ttk.Checkbutton(modules_inner, text=mod_name, variable=var)
            cb.pack(anchor="w", padx=8, pady=1)

        # Extra inputs
        ttk.Separator(modules_inner, orient="horizontal").pack(fill="x", padx=4, pady=6)
        ttk.Label(modules_inner, text="Endpoints (по строке):").pack(anchor="w", padx=8)
        self._endpoints_text = tk.Text(modules_inner, height=4, width=28, font=("Consolas", 9))
        self._endpoints_text.pack(fill="x", padx=8, pady=2)

        ttk.Label(modules_inner, text="Parameters (по строке):").pack(anchor="w", padx=8)
        self._params_text = tk.Text(modules_inner, height=3, width=28, font=("Consolas", 9))
        self._params_text.pack(fill="x", padx=8, pady=2)

        ttk.Label(modules_inner, text="Tokens (по строке):").pack(anchor="w", padx=8)
        self._tokens_text = tk.Text(modules_inner, height=3, width=28, font=("Consolas", 9))
        self._tokens_text.pack(fill="x", padx=8, pady=2)

        ttk.Label(modules_inner, text="User IDs (через запятую):").pack(anchor="w", padx=8)
        self._uids_var = tk.StringVar(value="1,2,3,100,admin")
        ttk.Entry(modules_inner, textvariable=self._uids_var, width=28).pack(fill="x", padx=8, pady=2)

        # Right panel: results
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=3)

        # Progress
        prog_frame = ttk.Frame(right_frame)
        prog_frame.pack(fill="x", padx=4, pady=(4, 2))
        self._progress = ttk.Progressbar(prog_frame, orient="horizontal", mode="determinate")
        self._progress.pack(fill="x", side="left", expand=True, padx=(0, 4))
        self._status_label = ttk.Label(prog_frame, text="Готов", width=40)
        self._status_label.pack(side="right")

        # Stats bar
        stats_frame = ttk.Frame(right_frame)
        stats_frame.pack(fill="x", padx=4, pady=2)
        self._stats_label = ttk.Label(stats_frame, text="", font=("Consolas", 9))
        self._stats_label.pack(side="left")

        # Results tree
        tree_frame = ttk.Frame(right_frame)
        tree_frame.pack(fill="both", expand=True, padx=4, pady=4)

        columns = ("module", "severity", "status", "count", "details")
        self._tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        self._tree.heading("module", text="Модуль")
        self._tree.heading("severity", text="Severity")
        self._tree.heading("status", text="Status")
        self._tree.heading("count", text="Findings")
        self._tree.heading("details", text="Детали")

        self._tree.column("module", width=180, minwidth=120)
        self._tree.column("severity", width=80, minwidth=60)
        self._tree.column("status", width=70, minwidth=50)
        self._tree.column("count", width=70, minwidth=50)
        self._tree.column("details", width=400, minwidth=200)

        tree_scroll_y = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll_y.grid(row=0, column=1, sticky="ns")
        tree_scroll_x.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        # Detail panel
        detail_frame = ttk.LabelFrame(right_frame, text="Подробности")
        detail_frame.pack(fill="both", padx=4, pady=(2, 4), expand=False)

        self._detail_text = tk.Text(
            detail_frame, height=10, wrap="word",
            font=("Consolas", 9), state="disabled",
        )
        detail_scroll = ttk.Scrollbar(detail_frame, orient="vertical", command=self._detail_text.yview)
        self._detail_text.configure(yscrollcommand=detail_scroll.set)
        self._detail_text.pack(side="left", fill="both", expand=True)
        detail_scroll.pack(side="right", fill="y")

        # Log panel
        log_frame = ttk.LabelFrame(right_frame, text="Лог сканирования")
        log_frame.pack(fill="x", padx=4, pady=(0, 4))

        self._log_text = tk.Text(
            log_frame, height=6, wrap="word",
            font=("Consolas", 8), state="disabled",
        )
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=log_scroll.set)
        self._log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

    # ----------------------------------------------------------
    #  Module selection helpers
    # ----------------------------------------------------------
    def _select_all(self):
        for var in self._module_vars.values():
            var.set(True)

    def _deselect_all(self):
        for var in self._module_vars.values():
            var.set(False)

    def _get_selected_modules(self) -> List[str]:
        return [name for name, var in self._module_vars.items() if var.get()]

    # ----------------------------------------------------------
    #  Logging
    # ----------------------------------------------------------
    def _log(self, msg: str, level: str = "info"):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] [{level.upper()}] {msg}\n"

        def _ui():
            try:
                self._log_text.configure(state="normal")
                self._log_text.insert("end", line)
                self._log_text.see("end")
                self._log_text.configure(state="disabled")
            except Exception:
                pass

        try:
            self.after(0, _ui)
        except Exception:
            pass

    # ----------------------------------------------------------
    #  Scan control
    # ----------------------------------------------------------
    def _start_scan(self):
        url = self._url_var.get().strip()
        if not url or not url.startswith(("http://", "https://")):
            messagebox.showwarning("AutoModules", "Введите корректный URL (http:// или https://)")
            return

        selected = self._get_selected_modules()
        if not selected:
            messagebox.showwarning("AutoModules", "Выберите хотя бы один модуль")
            return

        self._running = True
        self._cancel = False
        self._btn_start.configure(state="disabled")
        self._btn_stop.configure(state="normal")
        self._btn_export.configure(state="disabled")
        self._progress["value"] = 0
        self._status_label.configure(text="Запуск сканирования...")

        # Collect inputs
        endpoints = [
            line.strip()
            for line in self._endpoints_text.get("1.0", "end").strip().splitlines()
            if line.strip()
        ]
        parameters = [
            line.strip()
            for line in self._params_text.get("1.0", "end").strip().splitlines()
            if line.strip()
        ]
        tokens = [
            line.strip()
            for line in self._tokens_text.get("1.0", "end").strip().splitlines()
            if line.strip()
        ]
        uids_raw = self._uids_var.get().strip()
        user_ids = [u.strip() for u in uids_raw.split(",") if u.strip()] if uids_raw else []

        t = threading.Thread(
            target=self._scan_worker,
            args=(url, selected, endpoints, parameters, tokens, user_ids),
            daemon=True,
        )
        t.start()

    def _stop_scan(self):
        self._cancel = True
        self._log("⏹ Остановка сканирования...", "warn")

    def _scan_worker(
        self,
        url: str,
        selected: List[str],
        endpoints: List[str],
        parameters: List[str],
        tokens: List[str],
        user_ids: List[Any],
    ):
        try:
            from xss_security_gui.auto_modules.auto_modules import AutoModulesEngine

            self._session = requests.Session()
            self._session.verify = False
            self._session.headers.update({
                "User-Agent": "XSS-Security-GUI-AutoModules/Ultra",
            })

            self._engine = AutoModulesEngine(
                on_event=self._on_engine_event,
                debug_telemetry=True,
            )

            def log_func(msg: str, level: str = "info"):
                self._log(msg, level)

            total = len(selected)

            result = self._engine.run_full_scan(
                session=self._session,
                base_url=url,
                endpoints=endpoints,
                parameters=parameters,
                tokens=tokens,
                user_ids=user_ids,
                xss_targets=[],
                forms_data=[],
                headers_list=[{}],
                log=log_func,
                selected_modules=selected,
                cancel_flag=lambda: self._cancel,
            )

            self._results = result

            # Update UI from main thread
            self.after(0, lambda: self._on_scan_complete(result))

        except Exception as e:
            logger.exception("[AutoModulesTab] scan error")
            self._log(f"❌ Ошибка: {e}", "error")
            self.after(0, self._on_scan_finished)

    def _on_engine_event(self, event_name: str, data: Dict[str, Any]):
        """Callback от AutoModulesEngine — обновляем прогресс."""
        if event_name == "auto_module_result_ultra":
            mod = data.get("module", "?")
            count = data.get("count", 0)
            self._log(f"✅ {mod}: {count} findings", "info")

            # Update tree from main thread
            self.after(0, lambda d=data: self._add_module_to_tree(d))

    def _on_scan_complete(self, result: Dict[str, Any]):
        """Вызывается в main thread после завершения скана."""
        modules_run = result.get("modules_run", 0)
        summary = result.get("summary", {})
        heatmap = summary.get("heatmap", {})

        total_findings = sum(heatmap.values())
        self._status_label.configure(text=f"Готово: {modules_run} модулей, {total_findings} findings")
        self._progress["value"] = 100

        # Stats
        results_data = result.get("results", {})
        crit = high = med = low = info_count = 0
        for mod_result in results_data.values():
            for item in (mod_result.get("items") or []):
                sev = (item.get("severity") or "info").lower()
                if sev == "critical":
                    crit += 1
                elif sev == "high":
                    high += 1
                elif sev == "medium":
                    med += 1
                elif sev == "low":
                    low += 1
                else:
                    info_count += 1

        self._stats_label.configure(
            text=f"🔴 Critical: {crit}  🟠 High: {high}  🟡 Medium: {med}  🟢 Low: {low}  🔵 Info: {info_count}"
        )

        self._on_scan_finished()

    def _on_scan_finished(self):
        self._running = False
        self._btn_start.configure(state="normal")
        self._btn_stop.configure(state="disabled")
        if self._results:
            self._btn_export.configure(state="normal")

    # ----------------------------------------------------------
    #  Tree management
    # ----------------------------------------------------------
    def _add_module_to_tree(self, data: Dict[str, Any]):
        """Добавляет результат модуля в дерево."""
        try:
            module = data.get("module", "?")
            items = data.get("items") or []
            count = len(items)
            status = data.get("status", "ok")

            # Determine worst severity
            worst = "info"
            sev_order = ["info", "low", "medium", "high", "critical"]
            for item in items:
                sev = (item.get("severity") or "info").lower()
                if sev in sev_order and sev_order.index(sev) > sev_order.index(worst):
                    worst = sev

            # Summary details
            details_parts = []
            if data.get("family"):
                details_parts.append(f"family={data['family']}")
            if data.get("entropy"):
                details_parts.append(f"entropy={data['entropy']}")
            if data.get("tags"):
                details_parts.append(f"tags={','.join(data['tags'][:4])}")
            details = " | ".join(details_parts)

            iid = self._tree.insert(
                "", "end",
                values=(module, worst.upper(), status, count, details),
            )

            # Store items for detail view
            self._tree.set(iid, "module", module)

            # Add child rows for individual findings
            for i, item in enumerate(items[:50]):
                sev = (item.get("severity") or "info").lower()
                item_detail = self._format_item_summary(item)
                self._tree.insert(
                    iid, "end",
                    values=(f"  └ #{i+1}", sev.upper(), item.get("status", "-"), "", item_detail),
                    tags=(sev,),
                )

            # Configure tag colors
            for sev_name, color in _SEV_COLORS.items():
                self._tree.tag_configure(sev_name, foreground=color)

        except Exception as e:
            logger.debug(f"[AutoModulesTab] tree update error: {e}")

    def _format_item_summary(self, item: Dict[str, Any]) -> str:
        """Форматирует краткое описание finding'а."""
        parts = []
        for key in ("url", "endpoint", "param", "parameter", "payload", "origin",
                     "technology", "header", "token_preview"):
            val = item.get(key)
            if val:
                s = str(val)
                if len(s) > 80:
                    s = s[:77] + "..."
                parts.append(f"{key}={s}")
                break

        flags = []
        if item.get("reflected"):
            flags.append("REFLECTED")
        if item.get("misconfigured"):
            flags.append("MISCONFIGURED")
        if item.get("open_redirect"):
            flags.append("OPEN_REDIRECT")
        if item.get("header_injected") or item.get("body_injected"):
            flags.append("INJECTED")
        if item.get("traversal_found"):
            flags.append("TRAVERSAL")
        if item.get("trace_enabled"):
            flags.append("TRACE_ON")
        if item.get("waf_or_block_page"):
            flags.append("WAF")
        if item.get("dom_suspicious"):
            flags.append("DOM_RISK")

        if flags:
            parts.append(" ".join(flags))

        return " | ".join(parts) if parts else "-"

    def _on_tree_select(self, event):
        """Показывает подробности выбранного элемента."""
        sel = self._tree.selection()
        if not sel:
            return

        iid = sel[0]
        values = self._tree.item(iid, "values")
        module_name = values[0].strip() if values else ""

        # Find full data
        detail_data = None
        results = self._results.get("results", {})
        if module_name.startswith("└"):
            # Child item — show parent module
            parent = self._tree.parent(iid)
            if parent:
                parent_vals = self._tree.item(parent, "values")
                module_name = parent_vals[0] if parent_vals else ""

        if module_name in results:
            detail_data = results[module_name]

        if detail_data:
            try:
                text = json.dumps(detail_data, indent=2, ensure_ascii=False, default=str)
            except Exception:
                text = str(detail_data)
        else:
            text = f"Модуль: {module_name}\nДанные не найдены"

        try:
            self._detail_text.configure(state="normal")
            self._detail_text.delete("1.0", "end")
            self._detail_text.insert("1.0", text[:50000])
            self._detail_text.configure(state="disabled")
        except Exception:
            pass

    # ----------------------------------------------------------
    #  Export
    # ----------------------------------------------------------
    def _export_results(self):
        if not self._results:
            messagebox.showinfo("AutoModules", "Нет результатов для экспорта")
            return

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile=f"auto_modules_scan_{ts}.json",
            filetypes=[("JSON", "*.json"), ("All", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._results, f, indent=2, ensure_ascii=False, default=str)
            self._log(f"💾 Экспорт: {path}", "info")
            messagebox.showinfo("AutoModules", f"Результаты сохранены:\n{path}")
        except Exception as e:
            messagebox.showerror("AutoModules", f"Ошибка экспорта: {e}")

    # ----------------------------------------------------------
    #  Clear
    # ----------------------------------------------------------
    def _clear_results(self):
        self._results = {}
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.configure(state="disabled")
        self._log_text.configure(state="normal")
        self._log_text.delete("1.0", "end")
        self._log_text.configure(state="disabled")
        self._stats_label.configure(text="")
        self._status_label.configure(text="Готов")
        self._progress["value"] = 0
        self._btn_export.configure(state="disabled")

    # ----------------------------------------------------------
    #  Cleanup
    # ----------------------------------------------------------
    def destroy(self):
        self._cancel = True
        if self._session:
            try:
                self._session.close()
            except Exception:
                pass
        super().destroy()
