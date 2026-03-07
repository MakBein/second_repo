import tkinter as tk
from tkinter import ttk, filedialog
import os
from datetime import datetime

class AttackReportTab(ttk.Frame):
    def __init__(self, parent, log_path="logs/auto_attack.log"):
        super().__init__(parent)
        self.log_path = log_path
        self.entries = []
        self.success_count = 0
        self.fail_count = 0
        self.sort_directions = {}
        self.build_ui()
        self.load_log()

    def build_ui(self):
        ctrl = ttk.Frame(self)
        ctrl.pack(pady=5)

        ttk.Button(ctrl, text="🔄 Обновить", command=self.load_log).pack(side="left", padx=5)
        ttk.Button(ctrl, text="📁 Сохранить отчёт", command=self.save_report).pack(side="left", padx=5)
        ttk.Button(ctrl, text="📤 Экспорт в CSV", command=self.export_to_csv).pack(side="left", padx=5)
        ttk.Button(ctrl, text="🟢 Только успешные", command=self.filter_successful).pack(side="left", padx=5)

        self.status_label = ttk.Label(ctrl, text="📊 Статистика: —")
        self.status_label.pack(side="left", padx=10)

        columns = ("target", "method", "status", "payload", "vector")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col.capitalize(), command=lambda c=col: self.sort_by_column(c))
            self.tree.column(col, width=150)
            self.sort_directions[col] = False
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

    def load_log(self):
        self.entries.clear()
        self.tree.delete(*self.tree.get_children())
        self.success_count = 0
        self.fail_count = 0

        if not os.path.exists(self.log_path):
            self.status_label.config(text="📛 Лог не найден.")
            return

        with open(self.log_path, encoding="utf-8") as f:
            lines = f.readlines()

        for line in lines:
            if not line.strip():
                continue
            parts = line.strip().split(" → ")
            if len(parts) < 4:
                continue

            vector, target, status, payload = parts[:4]
            method = "POST" if "Form" in vector or "Ajax" in vector else "GET"
            status_code = int(status) if status.isdigit() else 0

            entry = (target, method, status, payload, vector)
            self.entries.append(entry)
            self.tree.insert("", "end", values=entry)

            if 200 <= status_code < 300:
                self.success_count += 1
            else:
                self.fail_count += 1

        total = self.success_count + self.fail_count
        self.status_label.config(text=f"📊 Успешно: {self.success_count} / {total} атак")

    def save_report(self):
        if not self.entries:
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("Text", "*.txt")],
            title="Сохранить отчёт"
        )
        if not filename:
            return

        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"# 📊 Отчёт по XSS-атакам\n")
            f.write(f"Дата: {datetime.now()}\n\n")
            f.write(f"Успешно: {self.success_count} / {self.success_count + self.fail_count}\n\n")
            f.write("| Цель | Метод | Статус | Пейлоад | Вектор |\n")
            f.write("|------|--------|--------|---------|--------|\n")
            for entry in self.entries:
                f.write(f"| {' | '.join(entry)} |\n")

        self.status_label.config(text=f"✅ Отчёт сохранён: {os.path.basename(filename)}")

    def export_to_csv(self):
        if not self.entries:
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Экспорт в CSV"
        )
        if not filename:
            return

        with open(filename, "w", encoding="utf-8") as f:
            f.write("target,method,status,payload,vector\n")
            for entry in self.entries:
                f.write(",".join(entry) + "\n")

        self.status_label.config(text=f"📤 CSV экспортирован: {os.path.basename(filename)}")

    def filter_successful(self):
        self.tree.delete(*self.tree.get_children())
        count = 0
        for entry in self.entries:
            if entry[2].isdigit() and 200 <= int(entry[2]) < 300:
                self.tree.insert("", "end", values=entry)
                count += 1
        self.status_label.config(text=f"🟢 Фильтр: только успешные ({count})")
