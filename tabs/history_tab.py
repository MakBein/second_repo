# xss_security_gui/tabs/history_tab.py
"""
History Tab - view and manage threat history
"""
import threading
import json
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional
from pathlib import Path


class HistoryTab(ttk.Frame):
    def __init__(self, parent: tk.Misc, threat_tab: Optional[object] = None):
        super().__init__(parent)
        self.threat_tab = threat_tab
        self.history_file = Path(__file__).parent.parent / "logs" / "threat_history.json"
        self.history_cache = []

        top = ttk.Frame(self)
        top.pack(fill="x", pady=3)
        ttk.Button(top, text="🔄 Load", command=self.load_history).pack(side="left", padx=4)
        ttk.Button(top, text="📤 Restore", command=self.restore_selected).pack(side="left", padx=4)
        ttk.Button(top, text="🗑️ Clear", command=self.clear_history).pack(side="left", padx=4)

        self.summary_text = tk.Text(self, height=4, bg="#1a1a1a", fg="#00ff99")
        self.summary_text.pack(fill="x", padx=5, pady=5)

        self.tree = ttk.Treeview(self, columns=("risk", "timestamp"), show="tree headings")
        self.tree.column("#0", width=300)
        self.tree.column("risk", width=100)
        self.tree.column("timestamp", width=200)
        self.tree.heading("#0", text="Event")
        self.tree.heading("risk", text="Risk")
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.pack(fill="both", expand=True, padx=5, pady=5)

    def load_history(self):
        def _worker():
            try:
                if not self.history_file.exists():
                    self.after(0, lambda: self.summary_text.insert("1.0", "No history file found"))
                    return
                with open(self.history_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.history_cache = data.get("events", [])

                def _ui():
                    self.tree.delete(*self.tree.get_children())
                    root = self.tree.insert("", "end", text=f"History ({len(self.history_cache)})", open=True)
                    for ev in self.history_cache[-200:]:
                        self.tree.insert(root, "end", text=ev.get("module", "event"), values=(ev.get("risk", ""), ev.get("timestamp", "")))
                    self.summary_text.config(state="normal")
                    self.summary_text.delete("1.0", "end")
                    self.summary_text.insert("1.0", f"Loaded {len(self.history_cache)} events")
                    self.summary_text.config(state="disabled")

                self.after(0, _ui)
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Error", str(e)))

        threading.Thread(target=_worker, daemon=True).start()

    def restore_selected(self):
        sel = self.tree.selection()
        if not sel or not self.threat_tab:
            return
        # For now show info - restoration depends on backend
        messagebox.showinfo("Info", "Restore not implemented in this build")

    def clear_history(self):
        if messagebox.askyesno("Confirm", "Clear history file?"):
            try:
                self.history_cache = []
                self.tree.delete(*self.tree.get_children())
                self.summary_text.config(state="normal")
                self.summary_text.delete("1.0", "end")
                self.summary_text.config(state="disabled")
            except Exception as e:
                messagebox.showerror("Error", str(e))

