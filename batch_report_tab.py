# xss_security_gui/batch_report_tab.py

import tkinter as tk
from tkinter import ttk
import csv
import os

class BatchReportTab(ttk.Frame):
    def __init__(self, parent, csv_path="logs/scan_report.csv"):
        super().__init__(parent)
        self.csv_path = csv_path
        self.data = []
        self.build_ui()

    def build_ui(self):
        filter_frame = ttk.Frame(self)
        filter_frame.pack(pady=5, fill="x")

        self.token_filter = tk.BooleanVar()
        ttk.Checkbutton(
            filter_frame, text="⚠️ Только с токенами", variable=self.token_filter,
            command=self.update_table
        ).pack(side="left", padx=5)

        self.no_csp_filter = tk.BooleanVar()
        ttk.Checkbutton(
            filter_frame, text="🚫 Без CSP", variable=self.no_csp_filter,
            command=self.update_table
        ).pack(side="left", padx=5)

        self.tree = ttk.Treeview(self, columns=(
            "url", "forms", "scripts", "links", "cms", "frameworks",
            "tokens", "graphql", "maps", "adaptive", "score"
        ), show="headings", height=30)

        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        headers = {
            "url": 320, "forms": 50, "scripts": 60, "links": 60,
            "cms": 80, "frameworks": 120, "tokens": 60,
            "graphql": 60, "maps": 60, "adaptive": 60, "score": 60
        }
        for col, width in headers.items():
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=width, anchor="w")

        self.tree.tag_configure("xss", background="#330000", foreground="yellow")
        self.load_data()

    def load_data(self):
        if not os.path.exists(self.csv_path):
            self.tree.insert("", "end", values=("❌ Файл scan_report.csv не найден",))
            return

        with open(self.csv_path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            self.data = list(reader)

        self.update_table()

    def update_table(self):
        self.tree.delete(*self.tree.get_children())

        for row in self.data:
            if self.token_filter.get() and int(row.get("Tokens", 0)) == 0:
                continue
            if self.no_csp_filter.get() and row.get("CMS", "").lower() != "none":
                continue

            tags = ("xss",) if int(row.get("Tokens", 0)) > 0 else ()
            self.tree.insert("", "end", values=[
                row.get("URL"),
                row.get("Forms"),
                row.get("Scripts"),
                row.get("Links"),
                row.get("CMS"),
                row.get("Frameworks"),
                row.get("Tokens"),
                row.get("GraphQL"),
                row.get("SourceMaps"),
                row.get("Adaptive"),
                row.get("Score")
            ], tags=tags)