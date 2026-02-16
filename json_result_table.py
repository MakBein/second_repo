import tkinter as tk
from tkinter import ttk
import json
import os

class JSONResultTable(ttk.Frame):
    def __init__(self, parent, json_path="logs/crawler_results.json"):
        super().__init__(parent)
        self.json_path = json_path
        self.build_ui()

    def build_ui(self):
        self.tree = ttk.Treeview(self, columns=("url", "forms", "csp", "xss"), show="headings", height=25)
        self.tree.pack(fill="both", expand=True)

        for col in ("url", "forms", "csp", "xss"):
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=180 if col != "url" else 400, anchor="w")

        if os.path.exists(self.json_path):
            with open(self.json_path, encoding="utf-8") as f:
                data = json.load(f)
                for page in data:
                    url = page.get("url", "—")
                    forms = len(page.get("forms", []))
                    csp = page.get("headers", {}).get("CSP", "—")
                    xss = page.get("headers", {}).get("X-XSS-Protection", "—")
                    self.tree.insert("", "end", values=(url, forms, csp, xss))
        else:
            self.tree.insert("", "end", values=("❌ Нет crawler_results.json", "", "", ""))