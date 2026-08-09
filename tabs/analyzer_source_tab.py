# xss_security_gui/tabs/analyzer_source_tab.py
"""
Analyzer Source Tab - displays threats from analyzer1.json (structured artifacts)
"""
import threading
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional
from pathlib import Path

from xss_security_gui.threat_data_loader import ThreatDataLoader


class AnalyzerSourceTab(ttk.Frame):
    """Tab for viewing threats from analyzer1.json source"""

    def __init__(self, parent: tk.Misc, threat_tab: Optional[object] = None):
        super().__init__(parent)
        self.threat_tab = threat_tab
        self.loader = ThreatDataLoader()
        self.threats_cache = []

        # ============================================================
        # Top controls
        # ============================================================
        top = ttk.Frame(self)
        top.pack(fill="x", pady=3)

        ttk.Button(top, text="🔄 Load Analyzer1.json", command=self.load_analyzer).pack(side="left", padx=4)
        ttk.Button(top, text="📤 Send to Threat Tab", command=self.send_to_threat_tab).pack(side="left", padx=4)
        ttk.Button(top, text="💾 Export", command=self.export_data).pack(side="left", padx=4)
        ttk.Button(top, text="🧹 Clear", command=self.clear_data).pack(side="left", padx=4)

        ttk.Label(top, text="Filter:").pack(side="left", padx=5)
        self.filter_var = tk.StringVar()
        self.filter_combo = ttk.Combobox(top, textvariable=self.filter_var, width=20, state="readonly")
        self.filter_combo.pack(side="left", padx=4)
        self.filter_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())

        # ============================================================
        # Summary text
        # ============================================================
        summary_frame = ttk.LabelFrame(self, text="Summary", height=100)
        summary_frame.pack(fill="x", padx=5, pady=5)
        summary_frame.pack_propagate(False)

        self.summary_text = tk.Text(summary_frame, height=4, bg="#1a1a1a", fg="#00ff00", font=("Courier", 9))
        self.summary_text.pack(fill="both", expand=True, padx=5, pady=5)

        # ============================================================
        # Tree view
        # ============================================================
        tree_frame = ttk.LabelFrame(self, text="Analyzer Artifacts")
        tree_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Create treeview with scrollbars
        self.tree = ttk.Treeview(tree_frame, columns=("category", "risk", "count"), show="tree headings")
        self.tree.column("#0", width=300, anchor="w")
        self.tree.column("category", width=150, anchor="w")
        self.tree.column("risk", width=100, anchor="center")
        self.tree.column("count", width=100, anchor="center")

        self.tree.heading("#0", text="Module / Details")
        self.tree.heading("category", text="Category")
        self.tree.heading("risk", text="Risk Level")
        self.tree.heading("count", text="Events")

        # Add scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Bind double-click for details
        self.tree.bind("<Double-1>", self.on_tree_double_click)

    def load_analyzer(self):
        """Load threats from analyzer1.json"""
        def _worker():
            try:
                ok = self.loader.load()
                if not ok:
                    self.after(0, lambda: messagebox.showwarning("Load Failed", "Could not load analyzer1.json"))
                    return

                self.threats_cache = self.loader.artifacts

                # Populate filter combo
                categories = set(a.get("result", {}).get("category", "unknown") for a in self.threats_cache)
                categories.add("All")

                def _ui():
                    self.filter_combo["values"] = sorted(categories)
                    self.filter_combo.set("All")
                    self.apply_filter()
                    self.update_summary()

                self.after(0, _ui)
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Error", f"Load failed: {e}"))

        threading.Thread(target=_worker, daemon=True).start()

    def apply_filter(self):
        """Filter and display artifacts"""
        selected = self.filter_var.get()

        # Filter artifacts
        if selected and selected != "All":
            filtered = [a for a in self.threats_cache if a.get("result", {}).get("category") == selected]
        else:
            filtered = self.threats_cache

        # Render tree
        self.tree.delete(*self.tree.get_children())

        if not filtered:
            self.tree.insert("", "end", text="No artifacts found")
            return

        root = self.tree.insert("", "end", text=f"Analyzer Artifacts ({len(filtered)})", open=True)

        for i, artifact in enumerate(filtered[:100], 1):
            result = artifact.get("result", {})
            category = result.get("category", "unknown")
            risk = result.get("risk", "medium")
            timestamp = artifact.get("timestamp", "?")

            node = self.tree.insert(root, "end", text=f"[{i}] {artifact.get('module', 'unknown')}",
                                     values=(category, risk, "1"), open=False)

            # Add result preview
            if isinstance(result, dict):
                for key, val in list(result.items())[:5]:
                    val_str = str(val)[:100]
                    self.tree.insert(node, "end", text=f"{key}: {val_str}", values=("", "", ""))

    def on_tree_double_click(self, event):
        """Show full details for selected artifact"""
        item = self.tree.selection()
        if not item:
            return

        # Try to find the artifact index from label
        label = self.tree.item(item[0], "text")
        try:
            # Create details window
            details_win = tk.Toplevel(self)
            details_win.title("Artifact Details")
            details_win.geometry("800x600")

            text = tk.Text(details_win, bg="#1a1a1a", fg="#00ff00", font=("Courier", 9))
            text.pack(fill="both", expand=True, padx=5, pady=5)

            # Find artifact details and display
            if label.startswith("["):
                idx = int(label.split("]")[0][1:]) - 1
                if 0 <= idx < len(self.threats_cache):
                    artifact = self.threats_cache[idx]
                    details = json.dumps(artifact, indent=2, ensure_ascii=False)
                    text.insert("1.0", details)

            text.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show details: {e}")

    def update_summary(self):
        """Update summary statistics"""
        try:
            summary = self.loader.get_summary()

            txt = f"""Analyzer1.json Summary
━━━━━━━━━━━━━━━━━━━━━━
Total Artifacts: {len(self.threats_cache)}
Total Events: {summary.get('total', 0)}

By Severity:
{json.dumps(summary.get('by_severity', {}), indent=2)}

By Category:
{json.dumps(summary.get('by_category', {}), indent=2)}"""

            self.summary_text.config(state="normal")
            self.summary_text.delete("1.0", "end")
            self.summary_text.insert("1.0", txt)
            self.summary_text.config(state="disabled")
        except Exception as e:
            self.summary_text.config(state="normal")
            self.summary_text.insert("1.0", f"Error: {e}")
            self.summary_text.config(state="disabled")

    def send_to_threat_tab(self):
        """Send selected threats to Threat Tab"""
        if not self.threat_tab:
            messagebox.showwarning("Warning", "Threat Tab not available")
            return

        count = 0
        for artifact in self.threats_cache:
            try:
                gui_artifact = self.loader.convert_artifact_for_gui(artifact)
                if hasattr(self.threat_tab, 'add_threat'):
                    self.threat_tab.add_threat(gui_artifact)
                    count += 1
            except Exception:
                pass

        messagebox.showinfo("Success", f"Sent {count} artifacts to Threat Tab")

    def export_data(self):
        """Export artifacts to JSON"""
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.threats_cache, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Success", f"Exported to {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")

    def clear_data(self):
        """Clear all data"""
        self.threats_cache = []
        self.tree.delete(*self.tree.get_children())
        self.summary_text.config(state="normal")
        self.summary_text.delete("1.0", "end")
        self.summary_text.config(state="disabled")

