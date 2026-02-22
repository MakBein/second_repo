# xss_security_gui/json_result_table.py
from tkinter import ttk
import json
import os
from pathlib import Path

# Импортируем универсальный путь из config_manager
from xss_security_gui.config_manager import CRAWLER_RESULTS_PATH


class JSONResultTable(ttk.Frame):
    def __init__(self, parent, json_path: Path = CRAWLER_RESULTS_PATH):
        super().__init__(parent)
        self.json_path = Path(json_path)
        self.build_ui()

    def build_ui(self):
        self.tree = ttk.Treeview(
            self,
            columns=("url", "forms", "csp", "xss"),
            show="headings",
            height=25
        )
        self.tree.pack(fill="both", expand=True)

        for col in ("url", "forms", "csp", "xss"):
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=180 if col != "url" else 400, anchor="w")

        if self.json_path.exists():
            try:
                with open(self.json_path, encoding="utf-8") as f:
                    data = json.load(f)
                    for page in data:
                        url = page.get("url", "—")
                        forms = len(page.get("forms", []))
                        csp = page.get("headers", {}).get("CSP", "—")
                        xss = page.get("headers", {}).get("X-XSS-Protection", "—")
                        self.tree.insert("", "end", values=(url, forms, csp, xss))
            except Exception as e:
                self.tree.insert("", "end", values=(f"❌ Ошибка чтения: {e}", "", "", ""))
        else:
            self.tree.insert("", "end", values=("❌ Нет crawler_results.json", "", "", ""))