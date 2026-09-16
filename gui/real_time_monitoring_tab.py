# xss_security_gui/gui/real_time_monitoring_tab.py
# ============================================================
# RealTimeMonitoringTab 8.0 — LIVE Threat Intel Dashboard
# Stealth Mode 11.0 Stats + Пагінація + async + threat‑query API
# Асинхронна вставка рядків у TreeView (batch insert)
# ============================================================

import os
import tkinter as tk
from tkinter import ttk
from typing import Any, Dict, List, Optional

from xss_security_gui.threat_tab_connector import ThreatIntelConnector


class RealTimeMonitoringTab(ttk.Frame):
    PAGE_SIZE = 100
    BATCH_SIZE = 50  # кількість рядків у одній порції вставки

    def __init__(self, parent, ui_bridge, tic: ThreatIntelConnector):
        super().__init__(parent)

        self.ui = ui_bridge
        self.tic = tic

        # Filters
        self._risk_var = tk.StringVar(value="all")
        self._module_var = tk.StringVar(value="all")
        self._category_var = tk.StringVar(value="all")
        self._search_var = tk.StringVar(value="")

        # Pagination
        self._page = 0
        self._total_rows = 0

        # Status
        self._status_var = tk.StringVar(value="Ready")

        # Trees
        self._tree: Optional[ttk.Treeview] = None
        self._file_tree: Optional[ttk.Treeview] = None
        self._artifact_text: Optional[tk.Text] = None

        self._build_layout()
        self._refresh_async()

    # ============================================================
    # Layout
    # ============================================================
    def _build_layout(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=8, pady=6)

        # Filters
        ttk.Label(top, text="Risk:").pack(side="left")
        ttk.Combobox(
            top,
            textvariable=self._risk_var,
            values=["all", "critical", "high", "medium", "low", "info"],
            width=10,
            state="readonly",
        ).pack(side="left", padx=4)

        ttk.Label(top, text="Module:").pack(side="left")
        self._module_cb = ttk.Combobox(top, textvariable=self._module_var, values=["all"], width=14)
        self._module_cb.pack(side="left", padx=4)

        ttk.Label(top, text="Category:").pack(side="left")
        self._category_cb = ttk.Combobox(top, textvariable=self._category_var, values=["all"], width=16)
        self._category_cb.pack(side="left", padx=4)

        ttk.Label(top, text="Search:").pack(side="left")
        search_entry = ttk.Entry(top, textvariable=self._search_var, width=24)
        search_entry.pack(side="left", padx=4)
        search_entry.bind("<Return>", lambda e: self._refresh_async())

        ttk.Button(top, text="🔄 Refresh", command=self._refresh_async).pack(side="left", padx=4)

        ttk.Label(top, textvariable=self._status_var).pack(side="right")

        # Pagination buttons
        pag = ttk.Frame(self)
        pag.pack(fill="x", padx=8, pady=4)

        ttk.Button(pag, text="⬅ Prev", command=self._prev_page).pack(side="left")
        ttk.Button(pag, text="Next ➡", command=self._next_page).pack(side="left")

        # Main split
        main = ttk.PanedWindow(self, orient="horizontal")
        main.pack(fill="both", expand=True)

        # Left: Tree
        left = ttk.Frame(main)
        main.add(left, weight=3)

        self._tree = ttk.Treeview(
            left,
            columns=("risk", "category", "module", "url", "extra"),
            show="headings",
            height=20,
        )
        self._tree.pack(fill="both", expand=True)

        for col, w in [
            ("risk", 80),
            ("category", 140),
            ("module", 120),
            ("url", 260),
            ("extra", 260),
        ]:
            self._tree.heading(col, text=col.capitalize())
            self._tree.column(col, width=w, anchor="w")

        self._tree.bind("<Double-1>", self._on_artifact_click)

        # Right: Inspector + Files
        right = ttk.Frame(main)
        main.add(right, weight=2)

        # Artifact Inspector
        insp = ttk.LabelFrame(right, text="Artifact Inspector")
        insp.pack(fill="both", expand=True, padx=4, pady=4)

        self._artifact_text = tk.Text(insp, wrap="word", height=12)
        self._artifact_text.pack(fill="both", expand=True)
        self._artifact_text.config(state="disabled")

        # Stealth Mode 11.0 Stats Panel
        stealth_frame = ttk.LabelFrame(right, text="🛡️ Stealth Mode 11.0 — Red Team Edition")
        stealth_frame.pack(fill="x", padx=4, pady=4)

        self._stealth_text = tk.Text(stealth_frame, wrap="word", height=6, state="disabled")
        self._stealth_text.pack(fill="both", expand=True)

        # File Explorer
        files = ttk.LabelFrame(right, text="File Explorer")
        files.pack(fill="both", expand=True, padx=4, pady=4)

        self._file_tree = ttk.Treeview(files, columns=("type", "path"), show="headings", height=8)
        self._file_tree.pack(side="left", fill="both", expand=True)

        self._file_tree.heading("type", text="Type")
        self._file_tree.heading("path", text="Path")
        self._file_tree.column("type", width=120)
        self._file_tree.column("path", width=320)

        self._file_tree.bind("<Double-1>", self._on_file_click)

        scroll = ttk.Scrollbar(files, orient="vertical", command=self._file_tree.yview)
        self._file_tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")

    # ============================================================
    # Pagination
    # ============================================================
    def _next_page(self):
        self._page += 1
        self._refresh_async()

    def _prev_page(self):
        if self._page > 0:
            self._page -= 1
        self._refresh_async()

    # ============================================================
    # Async refresh
    # ============================================================
    def _refresh_async(self):
        self._status_var.set("Loading…")

        if hasattr(self.ui, "post_bg"):
            self.ui.post_bg(self._refresh_bg, self._refresh_done)
        else:
            self._refresh_done(self._refresh_bg())

    def _refresh_bg(self) -> Dict[str, Any]:
        risk = self._risk_var.get()
        module = self._module_var.get()
        category = self._category_var.get()
        search = self._search_var.get().strip()

        risk = None if risk == "all" else risk
        module = None if module == "all" else module
        category = None if category == "all" else category
        search = None if not search else search

        total_count = self.tic.count(
            category=category,
            risk=risk,
            module=module,
            search=search,
        )

        rows = self.tic.query(
            category=category,
            risk=risk,
            module=module,
            search=search,
            limit=self.PAGE_SIZE,
            offset=self._page * self.PAGE_SIZE,
            order_by="timestamp",
            order_desc=True,
        )

        all_mods = set()
        all_cats = set()
        files = []

        for a in rows:
            res = a.get("result") or {}
            all_mods.add(a.get("module", "unknown"))
            all_cats.add(res.get("category", "unknown"))

            lp = res.get("local_path")
            if lp:
                files.append(("config", lp))
            screenshot = res.get("screenshot") or res.get("screenshot_path")
            if screenshot:
                files.append(("screenshot", screenshot))
            js_files = res.get("js_files") or []
            for j in js_files:
                files.append(("js", j))

        return {
            "rows": rows,
            "total_count": total_count,
            "modules": sorted(all_mods),
            "categories": sorted(all_cats),
            "files": files,
        }

    # ============================================================
    # Async UI update (batch insert)
    # ============================================================
    def async_fill_treeview(self, tree: ttk.Treeview, rows: List[tuple], batch_size: int = 50):
        tree.delete(*tree.get_children())

        total = len(rows)
        index = 0

        def insert_batch():
            nonlocal index

            end = min(index + batch_size, total)
            batch = rows[index:end]

            for row in batch:
                risk = row[0]
                tag = f"risk_{risk}"
                if not tree.tag_has(tag):
                    color = {
                        "critical": "#ff4d4f",
                        "high": "#ff7a45",
                        "medium": "#faad14",
                        "low": "#52c41a",
                        "info": "#1890ff",
                    }.get(risk, "#d9d9d9")
                    tree.tag_configure(tag, background=color)

                tree.insert("", "end", values=row, tags=(tag,))

            index = end

            if index < total:
                tree.after(1, insert_batch)
            else:
                self._status_var.set(f"Page {self._page + 1} — {total} rows (async)")

        insert_batch()

    def async_fill_file_tree(self, files: List[tuple], batch_size: int = 50):
        self._file_tree.delete(*self._file_tree.get_children())

        total = len(files)
        index = 0

        def insert_batch():
            nonlocal index

            end = min(index + batch_size, total)
            batch = files[index:end]

            for ftype, path in batch:
                self._file_tree.insert("", "end", values=(ftype, path))

            index = end

            if index < total:
                self._file_tree.after(1, insert_batch)

        insert_batch()

    # ============================================================
    # Refresh done
    # ============================================================
    def _refresh_done(self, data: Dict[str, Any]):
        try:
            rows = data.get("rows", [])
            total_count = data.get("total_count", len(rows))
            modules = data.get("modules", [])
            categories = data.get("categories", [])
            files = data.get("files", [])

            self._total_rows = total_count
            total_pages = max(1, (total_count + self.PAGE_SIZE - 1) // self.PAGE_SIZE)

            # Prepare rows for async insert
            prepared_rows = []
            for a in rows:
                res = a.get("result") or {}
                prepared_rows.append((
                    res.get("risk", "info"),
                    res.get("category", ""),
                    a.get("module", ""),
                    res.get("url", a.get("target", "")),
                    str(res),
                ))

            # Async insert
            self.async_fill_treeview(self._tree, prepared_rows, batch_size=self.BATCH_SIZE)
            self.async_fill_file_tree(files, batch_size=self.BATCH_SIZE)

            # Update filters
            self._module_cb["values"] = ["all"] + modules
            self._category_cb["values"] = ["all"] + categories

            self._status_var.set(
                f"Page {self._page + 1}/{total_pages} — {total_count} total artifacts"
            )

        except Exception as e:
            self._status_var.set(f"Error: {e}")

    # ============================================================
    # Artifact Inspector
    # ============================================================
    def _on_artifact_click(self, event):
        item = self._tree.selection()
        if not item:
            return

        values = self._tree.item(item[0], "values")
        if len(values) < 5:
            return

        extra = values[4]

        self._artifact_text.config(state="normal")
        self._artifact_text.delete("1.0", "end")
        self._artifact_text.insert("1.0", extra)
        self._artifact_text.config(state="disabled")

        self._status_var.set("Artifact opened")

    # ============================================================
    # File Explorer
    # ============================================================
    def update_stealth_stats(self, stats: dict):
        """Update Stealth Mode 11.0 stats panel."""
        try:
            self._stealth_text.config(state="normal")
            self._stealth_text.delete("1.0", "end")

            lines = []
            lines.append(f"Active: {'✅ YES' if stats.get('stealth_active') else '❌ NO'}")
            lines.append(f"Detected WAF: {stats.get('detected_waf', 'None')}")
            lines.append(f"Browser Profiles: {stats.get('browser_profiles_count', 0)}")

            tls = stats.get("tls", {})
            lines.append(f"TLS Profiles: {tls.get('total_profiles', 0)} | Blocked: {len(tls.get('blocked_profiles', []))}")

            delay = stats.get("delay", {})
            lines.append(f"Avg Delay: {delay.get('avg_delay', 0)}s | Blocks: {delay.get('consecutive_blocks', 0)}")

            evasion = stats.get("evasion", {})
            lines.append(f"Requests: {evasion.get('requests_sent', 0)} | Evaded: {evasion.get('blocks_evaded', 0)} | WAF Hits: {evasion.get('waf_detections', 0)}")

            self._stealth_text.insert("1.0", "\n".join(lines))
            self._stealth_text.config(state="disabled")
        except Exception:
            pass

    def _on_file_click(self, event):
        item = self._file_tree.selection()
        if not item:
            return

        values = self._file_tree.item(item[0], "values")
        if len(values) < 2:
            return

        path = values[1]
        if not os.path.exists(path):
            self._status_var.set(f"File not found: {path}")
            return

        os.startfile(path)
        self._status_var.set(f"Opened: {path}")










