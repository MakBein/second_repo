# xss_security_gui/tabs/history_tab.py
"""
History Tab 11.0 — Threat‑aware, async, restore via ThreatConnector
"""
import json
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional
from pathlib import Path

from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


class HistoryTab(ttk.Frame):
    def __init__(self, parent: tk.Misc, threat_tab: Optional[object] = None):
        super().__init__(parent)
        self.threat_tab = threat_tab
        self.history_file = Path(__file__).parent.parent / "logs" / "threat_history.json"
        self.history_cache = []
        self._bridge = UIQueueBridge(self, poll_ms=100)

        top = ttk.Frame(self)
        top.pack(fill="x", pady=3)
        ttk.Button(top, text="🔄 Load", command=self.load_history).pack(side="left", padx=4)
        ttk.Button(top, text="📤 Restore", command=self.restore_selected).pack(side="left", padx=4)
        ttk.Button(top, text="🗑️ Clear", command=self.clear_history).pack(side="left", padx=4)

        self.summary_text = tk.Text(self, height=4, bg="#1a1a1a", fg="#00ff99")
        self.summary_text.pack(fill="x", padx=5, pady=5)
        self.summary_text.config(state="disabled")

        self.tree = ttk.Treeview(self, columns=("risk", "timestamp"), show="tree headings")
        self.tree.column("#0", width=300)
        self.tree.column("risk", width=100)
        self.tree.column("timestamp", width=200)
        self.tree.heading("#0", text="Event")
        self.tree.heading("risk", text="Risk")
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.pack(fill="both", expand=True, padx=5, pady=5)

    # ============================================================
    # Async load via UIQueueBridge
    # ============================================================
    def load_history(self):
        def _worker():
            try:
                if not self.history_file.exists():
                    self._bridge.post_ui(
                        self._set_summary_text,
                        "No history file found",
                    )
                    return

                with open(self.history_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                self.history_cache = data.get("events", [])

                def _ui():
                    self.tree.delete(*self.tree.get_children())
                    root = self.tree.insert(
                        "",
                        "end",
                        text=f"History ({len(self.history_cache)})",
                        open=True,
                    )
                    for ev in self.history_cache[-200:]:
                        self.tree.insert(
                            root,
                            "end",
                            text=ev.get("module", "event"),
                            values=(ev.get("risk", ""), ev.get("timestamp", "")),
                        )
                    self._set_summary_text(f"Loaded {len(self.history_cache)} events")

                self._bridge.post_ui(_ui)
            except Exception as e:
                # важливо: передаємо e як default‑arg, щоб не було NameError
                self._bridge.post_ui(
                    lambda err=e: messagebox.showerror("Error", str(err))
                )

        self._bridge.post_bg(_worker)

    def _set_summary_text(self, text: str):
        try:
            self.summary_text.config(state="normal")
            self.summary_text.delete("1.0", "end")
            self.summary_text.insert("1.0", text)
            self.summary_text.config(state="disabled")
        except Exception:
            pass

    # ============================================================
    # Restore via ThreatConnector
    # ============================================================
    def restore_selected(self):
        sel = self.tree.selection()
        if not sel:
            return

        item_id = sel[0]
        parent = self.tree.parent(item_id)
        index = self.tree.index(item_id)

        # root → history_cache[-200:], тому індекс співпадає з останніми 200
        if not self.history_cache:
            return

        try:
            # беремо відповідний евент з кінця
            base_index = max(0, len(self.history_cache) - 200)
            ev = self.history_cache[base_index + index]
        except Exception:
            messagebox.showerror("Error", "Cannot map selection to history event")
            return

        # реальна інтеграція з ThreatConnector: емісія артефакта назад у пайплайн
        try:
            THREAT_CONNECTOR.emit(
                module=ev.get("module", "HistoryRestore"),
                target=ev.get("url") or ev.get("target") or "",
                result={
                    "category": ev.get("category", "history_restore"),
                    "risk": ev.get("risk", "unknown"),
                    "timestamp": ev.get("timestamp", ""),
                    "type": ev.get("type", "history_event"),
                    "raw": ev,
                },
            )
            messagebox.showinfo(
                "Restore",
                "Event restored into ThreatConnector pipeline.",
            )
        except Exception as e:
            messagebox.showerror("Restore error", str(e))

    # ============================================================
    # Clear
    # ============================================================
    def clear_history(self):
        if not messagebox.askyesno("Confirm", "Clear history file?"):
            return
        try:
            self.history_cache = []
            self.tree.delete(*self.tree.get_children())
            self._set_summary_text("")
        except Exception as e:
            messagebox.showerror("Error", str(e))




