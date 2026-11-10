# xss_security_gui/tabs/analyzer_source_tab.py
"""
Analyzer Source Tab 11.0 GOD‑MODE
Отображает артефакты из analyzer1.json в структурированном виде:
 - асинхронная загрузка (не блокирует UI)
 - фильтрация по категории и severity
 - summary по risk / category
 - детальный viewer артефакта
 - отправка артефактов в Threat Tab
 - экспорт в JSON
"""

import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional, List, Dict, Any

from xss_security_gui.threat_data_loader import ThreatDataLoader, ThreatRisk
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge


class AnalyzerSourceTab(ttk.Frame):
    """Tab for viewing threats from analyzer1.json source."""

    def __init__(self, parent: tk.Misc, threat_tab: Optional[object] = None):
        super().__init__(parent)
        self.threat_tab = threat_tab
        self.loader = ThreatDataLoader()
        self.threats_cache: List[Dict[str, Any]] = []
        self._bridge = UIQueueBridge(self, poll_ms=100)

        # ============================================================
        # Top controls
        # ============================================================
        top = ttk.Frame(self)
        top.pack(fill="x", pady=3)

        ttk.Button(top, text="🔄 Load analyzer1.json", command=self.load_analyzer).pack(side="left", padx=4)
        ttk.Button(top, text="📤 Send to Threat Tab", command=self.send_to_threat_tab).pack(side="left", padx=4)
        ttk.Button(top, text="💾 Export", command=self.export_data).pack(side="left", padx=4)
        ttk.Button(top, text="🧹 Clear", command=self.clear_data).pack(side="left", padx=4)

        ttk.Label(top, text="Category:").pack(side="left", padx=5)
        self.filter_var = tk.StringVar()
        self.filter_combo = ttk.Combobox(top, textvariable=self.filter_var, width=18, state="readonly")
        self.filter_combo.pack(side="left", padx=4)
        self.filter_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())

        ttk.Label(top, text="Severity:").pack(side="left", padx=5)
        self.severity_var = tk.StringVar()
        self.severity_combo = ttk.Combobox(
            top,
            textvariable=self.severity_var,
            width=12,
            state="readonly",
            values=["All", "critical", "high", "medium", "low", "info"],
        )
        self.severity_combo.pack(side="left", padx=4)
        self.severity_combo.set("All")
        self.severity_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())

        # ============================================================
        # Summary text
        # ============================================================
        summary_frame = ttk.LabelFrame(self, text="Summary", height=110)
        summary_frame.pack(fill="x", padx=5, pady=5)
        summary_frame.pack_propagate(False)

        self.summary_text = tk.Text(
            summary_frame,
            height=5,
            bg="#1a1a1a",
            fg="#00ff00",
            font=("Courier New", 9),
        )
        self.summary_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.summary_text.config(state="disabled")

        # ============================================================
        # Tree view
        # ============================================================
        tree_frame = ttk.LabelFrame(self, text="Analyzer Artifacts")
        tree_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("category", "risk", "count", "timestamp"),
            show="tree headings",
        )
        self.tree.column("#0", width=320, anchor="w")
        self.tree.column("category", width=150, anchor="w")
        self.tree.column("risk", width=90, anchor="center")
        self.tree.column("count", width=80, anchor="center")
        self.tree.column("timestamp", width=140, anchor="center")

        self.tree.heading("#0", text="Module / Details")
        self.tree.heading("category", text="Category")
        self.tree.heading("risk", text="Risk")
        self.tree.heading("count", text="Events")
        self.tree.heading("timestamp", text="Timestamp")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.tree.bind("<Double-1>", self.on_tree_double_click)

    # ============================================================
    # Loading
    # ============================================================

    def load_analyzer(self) -> None:
        """Асинхронная загрузка analyzer1.json через ThreatDataLoader."""

        def _worker():
            try:
                ok = self.loader.load()
                if not ok:
                    self._bridge.post_ui(
                        messagebox.showwarning,
                        "Load Failed",
                        "Could not load analyzer1.json",
                    )
                    return

                self.threats_cache = self.loader.artifacts or []

                categories = set(
                    (a.get("result") or {}).get("category", "unknown")
                    for a in self.threats_cache
                )
                categories.add("All")

                def _ui():
                    self.filter_combo["values"] = sorted(categories)
                    self.filter_combo.set("All")
                    self.apply_filter()
                    self.update_summary()

                self._bridge.post_ui(_ui)
            except Exception as e:
                self._bridge.post_ui(
                    messagebox.showerror,
                    "Error",
                    f"Load failed: {e}",
                )

        self._bridge.post_bg(_worker)

    # ============================================================
    # Filtering + rendering
    # ============================================================

    def apply_filter(self) -> None:
        """Фильтрация артефактов по категории и severity и отображение в дереве."""
        category_selected = self.filter_var.get()
        severity_selected = self.severity_var.get()

        filtered: List[Dict[str, Any]] = []

        for a in self.threats_cache:
            result = a.get("result", {}) or {}
            cat = result.get("category", "unknown")
            risk = ThreatRisk.normalize(result.get("risk", "info"))

            if category_selected and category_selected != "All" and cat != category_selected:
                continue

            if severity_selected and severity_selected != "All":
                if ThreatRisk.ORDER.get(risk, -1) < ThreatRisk.ORDER.get(
                    ThreatRisk.normalize(severity_selected),
                    -1,
                ):
                    continue

            filtered.append(a)

        self.tree.delete(*self.tree.get_children())

        if not filtered:
            self.tree.insert("", "end", text="No artifacts found")
            return

        root = self.tree.insert(
            "",
            "end",
            text=f"Analyzer Artifacts ({len(filtered)})",
            open=True,
        )

        for i, artifact in enumerate(filtered[:200], 1):
            result = artifact.get("result", {}) or {}
            category = result.get("category", "unknown")
            risk = result.get("risk", "medium")
            timestamp = artifact.get("timestamp", "?")
            module = artifact.get("module", "unknown")

            node = self.tree.insert(
                root,
                "end",
                text=f"[{i}] {module}",
                values=(category, risk, "1", timestamp),
                open=False,
            )

            # Preview of first fields
            for key, val in list(result.items())[:6]:
                val_str = str(val)
                if len(val_str) > 120:
                    val_str = val_str[:117] + "..."
                self.tree.insert(
                    node,
                    "end",
                    text=f"{key}: {val_str}",
                    values=("", "", "", ""),
                )

    # ============================================================
    # Details viewer
    # ============================================================

    def on_tree_double_click(self, event) -> None:
        """Открывает полные детали артефакта в отдельном окне."""
        item = self.tree.selection()
        if not item:
            return

        label = self.tree.item(item[0], "text")

        try:
            details_win = tk.Toplevel(self)
            details_win.title("Analyzer Artifact Details")
            details_win.geometry("900x650")

            text = tk.Text(
                details_win,
                bg="#1a1a1a",
                fg="#00ff00",
                font=("Courier New", 9),
                wrap="none",
            )
            text.pack(fill="both", expand=True, padx=5, pady=5)

            x_scroll = ttk.Scrollbar(details_win, orient="horizontal", command=text.xview)
            y_scroll = ttk.Scrollbar(details_win, orient="vertical", command=text.yview)
            text.configure(xscrollcommand=x_scroll.set, yscrollcommand=y_scroll.set)
            y_scroll.pack(side="right", fill="y")
            x_scroll.pack(side="bottom", fill="x")

            if label.startswith("["):
                idx = int(label.split("]")[0][1:]) - 1
                if 0 <= idx < len(self.threats_cache):
                    artifact = self.threats_cache[idx]
                    details = json.dumps(artifact, indent=2, ensure_ascii=False)
                    text.insert("1.0", details)

            text.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show details: {e}")

    # ============================================================
    # Summary
    # ============================================================

    def update_summary(self) -> None:
        """Обновляет summary по analyzer1.json."""
        try:
            summary = self.loader.get_summary()

            txt = (
                "Analyzer1.json Summary\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                f"Total Artifacts: {len(self.threats_cache)}\n"
                f"Total Events: {summary.get('total', 0)}\n\n"
                "By Severity:\n"
                f"{json.dumps(summary.get('by_severity', {}), indent=2)}\n\n"
                "By Category:\n"
                f"{json.dumps(summary.get('by_category', {}), indent=2)}"
            )

            self.summary_text.config(state="normal")
            self.summary_text.delete("1.0", "end")
            self.summary_text.insert("1.0", txt)
            self.summary_text.config(state="disabled")
        except Exception as e:
            self.summary_text.config(state="normal")
            self.summary_text.delete("1.0", "end")
            self.summary_text.insert("1.0", f"Error: {e}")
            self.summary_text.config(state="disabled")

    # ============================================================
    # Send to Threat Tab
    # ============================================================

    def send_to_threat_tab(self) -> None:
        """Отправляет все артефакты в Threat Tab."""
        if not self.threat_tab or not hasattr(self.threat_tab, "add_threat"):
            messagebox.showwarning("Warning", "Threat Tab not available")
            return

        count = 0
        for artifact in self.threats_cache:
            try:
                gui_artifact = self.loader.convert_artifact_for_gui(artifact)
                if gui_artifact:
                    self.threat_tab.add_threat(gui_artifact)
                    count += 1
            except Exception:
                continue

        messagebox.showinfo("Success", f"Sent {count} artifacts to Threat Tab")

    # ============================================================
    # Export / Clear
    # ============================================================

    def export_data(self) -> None:
        """Экспортирует текущие артефакты в JSON."""
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.threats_cache, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Success", f"Exported to {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")

    def clear_data(self) -> None:
        """Очищает артефакты и UI."""
        self.threats_cache = []
        self.tree.delete(*self.tree.get_children())
        self.summary_text.config(state="normal")
        self.summary_text.delete("1.0", "end")
        self.summary_text.config(state="disabled")
        self.filter_combo["values"] = []
        self.filter_var.set("")
        self.severity_combo.set("All")


