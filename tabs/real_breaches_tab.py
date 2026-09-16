# xss_security_gui/tabs/real_breaches_tab.py
"""Real Breaches Tab - displays threats from real_breaches.json (scenarios and examples)
"""
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional
from pathlib import Path

from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge


class RealBreachesTab(ttk.Frame):
	"""Tab for viewing real breach scenarios"""

	def __init__(self, parent: tk.Misc, threat_tab: Optional[object] = None):
		super().__init__(parent)
		self.threat_tab = threat_tab
		self.breaches_cache = []
		self.data_file = Path(__file__).parent.parent / "logs" / "real_breaches.json"
		self._bridge = UIQueueBridge(self, poll_ms=100)

		top = ttk.Frame(self)
		top.pack(fill="x", pady=3)

		ttk.Button(top, text="🔄 Load Breaches", command=self.load_breaches).pack(side="left", padx=4)
		ttk.Button(top, text="📤 Send to Threat Tab", command=self.send_to_threat_tab).pack(side="left", padx=4)
		ttk.Button(top, text="💾 Export", command=self.export_data).pack(side="left", padx=4)

		self.summary_text = tk.Text(self, height=5, bg="#1a1a1a", fg="#ff6600")
		self.summary_text.pack(fill="x", padx=5, pady=5)

		self.tree = ttk.Treeview(self, columns=("type", "severity", "date"), show="tree headings")
		self.tree.column("#0", width=300)
		self.tree.column("type", width=150)
		self.tree.column("severity", width=100)
		self.tree.column("date", width=150)
		self.tree.heading("#0", text="Breach Details")
		self.tree.heading("type", text="Type")
		self.tree.heading("severity", text="Severity")
		self.tree.heading("date", text="Date")
		self.tree.pack(fill="both", expand=True, padx=5, pady=5)

		self.tree.bind("<Double-1>", self.on_tree_double_click)

	def load_breaches(self):
		def _worker():
			try:
				if not self.data_file.exists():
					self.after(0, lambda: messagebox.showwarning("File Not Found", f"real_breaches.json not found at {self.data_file}"))
					return

				with open(self.data_file, "r", encoding="utf-8") as f:
					data = json.load(f)

				self.breaches_cache = data.get("breaches", [])

				def _ui():
					self.tree.delete(*self.tree.get_children())
					root = self.tree.insert("", "end", text=f"Breach Scenarios ({len(self.breaches_cache)})", open=True)
					for breach in self.breaches_cache[:200]:
						name = breach.get("title", "Breach")
						btype = breach.get("type", "unknown")
						sev = breach.get("severity", "medium")
						date = breach.get("date_discovered", breach.get("date", "unknown"))
						self.tree.insert(root, "end", text=name, values=(btype, sev, date))

					self.summary_text.config(state="normal")
					self.summary_text.delete("1.0", "end")
					self.summary_text.insert("1.0", f"Loaded {len(self.breaches_cache)} scenarios")
					self.summary_text.config(state="disabled")

				self.after(0, _ui)
			except Exception as e:
				self.after(0, lambda: messagebox.showerror("Error", f"Load failed: {e}"))

		self._bridge.post_bg(_worker)

	def on_tree_double_click(self, event):
		item = self.tree.selection()
		if not item:
			return
		label = self.tree.item(item[0], "text")
		# find matching breach
		for b in self.breaches_cache:
			if b.get("title") == label:
				try:
					w = tk.Toplevel(self)
					w.title("Breach Details")
					txt = tk.Text(w, bg="#1a1a1a", fg="#ff6600")
					txt.pack(fill="both", expand=True)
					txt.insert("1.0", json.dumps(b, indent=2, ensure_ascii=False))
					txt.config(state="disabled")
				except Exception as e:
					messagebox.showerror("Error", str(e))
				break

	def send_to_threat_tab(self):
		if not self.threat_tab:
			messagebox.showwarning("Warning", "Threat Tab not available")
			return
		count = 0
		for breach in self.breaches_cache:
			try:
				artifact = {
					"type": "RealBreach",
					"category": "real_breach",
					"module": "RealBreaches",
					"risk": breach.get("severity", "medium"),
					"timestamp": breach.get("date_discovered", breach.get("date")),
					"result": breach,
				}
				if hasattr(self.threat_tab, "add_threat"):
					self.threat_tab.add_threat(artifact)
					count += 1
			except Exception:
				pass
		messagebox.showinfo("Success", f"Sent {count} breaches to Threat Tab")

	def export_data(self):
		path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
		if not path:
			return
		try:
			with open(path, "w", encoding="utf-8") as f:
				json.dump(self.breaches_cache, f, indent=2, ensure_ascii=False)
			messagebox.showinfo("Success", f"Exported to {path}")
		except Exception as e:
			messagebox.showerror("Error", f"Export failed: {e}")


