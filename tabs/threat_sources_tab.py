# xss_security_gui/tabs/threat_sources_tab.py
"""
Threat Sources Tab - shows threats loaded from multiple sources (analyzer, real breaches, history)
Provides Load All / Analyze / Export actions and a tree viewer.
"""
import json
import tkinter as tk
from tkinter import ttk, filedialog
from typing import Optional

from xss_security_gui.unified_threat_loader import UnifiedThreatLoader
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge


class ThreatSourcesTab(ttk.Frame):
    def __init__(self, parent: tk.Misc, threat_tab: Optional[object] = None):
        super().__init__(parent)
        self.threat_tab = threat_tab
        self.loader = UnifiedThreatLoader()
        self._bridge = UIQueueBridge(self, poll_ms=100)

        top = ttk.Frame(self)
        top.pack(fill="x", pady=3)

        ttk.Button(top, text="🔄 Load All", command=self.load_all).pack(side="left", padx=4)
        ttk.Button(top, text="🧠 Analyze (AI)", command=self.analyze).pack(side="left", padx=4)
        ttk.Button(top, text="💾 Export Combined", command=self.export_combined).pack(side="left", padx=4)
        ttk.Button(top, text="📤 Send to ThreatTab", command=self.send_to_threat_tab).pack(side="left", padx=4)

        self.summary_text = tk.Text(self, height=8, bg="#111", fg="#0f0")
        self.summary_text.pack(fill="x", padx=5, pady=5)

        self.tree = ttk.Treeview(self, columns=("detail",), show="tree headings")
        self.tree.heading("#0", text="Key")
        self.tree.heading("detail", text="Value")
        self.tree.column("#0", width=300, anchor="w")
        self.tree.column("detail", width=600, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=5, pady=5)

    def _render_summary(self, stats: dict):
        self.summary_text.delete("1.0", "end")
        txt = json.dumps(stats, indent=2, ensure_ascii=False)
        self.summary_text.insert("1.0", txt)

    def _render_threats(self, threats):
        self.tree.delete(*self.tree.get_children())
        root = self.tree.insert("", "end", text=f"Threats ({len(threats)})", open=True)
        for i, th in enumerate(threats[:200]):
            tnode = self.tree.insert(root, "end", text=f"[{i+1}] {th.get('module', th.get('category','unknown'))}")
            # show small preview
            preview = th.get("result") or th.get("ai_analysis") or th
            try:
                self.tree.insert(tnode, "end", text="preview", values=(str(preview)[:200],))
            except Exception:
                pass

    def load_all(self):
        def _worker():
            ok = self.loader.load_all_sources()
            stats = self.loader.get_statistics()
            threats = self.loader.threats

            def _ui():
                if not ok:
                    self.summary_text.delete("1.0", "end")
                    self.summary_text.insert("1.0", "No threats loaded")
                else:
                    self._render_summary(stats)
                    self._render_threats(threats)

            try:
                self.after(0, _ui)
            except Exception:
                pass

        self._bridge.post_bg(_worker)

    def analyze(self):
        def _worker():
            try:
                self.loader.analyze_with_ai()
                threats = self.loader.export_to_gui_format()

                def _ui():
                    self._render_threats(threats)
                    self._render_summary(self.loader.get_statistics())

                self.after(0, _ui)
            except Exception as e:
                try:
                    self.after(0, lambda: self.summary_text.insert("1.0", f"Error: {e}"))
                except Exception:
                    pass

        self._bridge.post_bg(_worker)

    def export_combined(self):
        try:
            path = self.loader.save_combined_analysis()
            self.summary_text.delete("1.0", "end")
            self.summary_text.insert("1.0", f"Saved: {path}")
        except Exception as e:
            self.summary_text.insert("1.0", f"Export error: {e}")

    def send_to_threat_tab(self):
        if not self.threat_tab:
            self.summary_text.insert("1.0", "No Threat Tab connected")
            return
        threats = self.loader.export_to_gui_format()
        try:
            # If threat_tab supports batch loading, call its loader
            if hasattr(self.threat_tab, "_load_threats_to_tree"):
                self.threat_tab._load_threats_to_tree(threats)
            elif hasattr(self.threat_tab, "load_results"):
                self.threat_tab.load_results({"entries": threats})
            self.summary_text.insert("1.0", f"Sent {len(threats)} threats to Threat Tab\n")
        except Exception as e:
            self.summary_text.insert("1.0", f"Send error: {e}\n")

