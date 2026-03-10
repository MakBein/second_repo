# xss_security_gui/network_tab.py

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
from datetime import datetime

from xss_security_gui.network_checker import NetworkChecker
from xss_security_gui.settings import LOG_DIR


class NetworkTab(ttk.Frame):
    """
    NetworkTab ULTRA 8.0
    - Потокобезпечний лог
    - Кнопки: Очистить вывод, Сохранить данные, Экспорт JSON/Markdown
    - Автосохранение network_profile.json
    - Інтеграція з ThreatTab
    """

    def __init__(self, parent, threat_tab=None):
        super().__init__(parent)
        self.threat_tab = threat_tab
        self.last_results = {}  # для JSON/Markdown
        self.build_ui()

    # ---------------------------------------------------------
    # UI
    # ---------------------------------------------------------
    def build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill="x", pady=5)

        ttk.Label(top, text="🌐 Домен:").pack(side="left", padx=5)
        self.domain_entry = ttk.Entry(top, width=40)
        self.domain_entry.insert(0, "example.com")
        self.domain_entry.pack(side="left", padx=5)

        ttk.Button(top, text="🚀 Запустить проверку", command=self.run_scan).pack(side="left", padx=5)
        ttk.Button(top, text="🧹 Очистить вывод", command=self.clear_output).pack(side="left", padx=5)
        ttk.Button(top, text="💾 Сохранить данные", command=self.save_text).pack(side="left", padx=5)
        ttk.Button(top, text="📤 Экспорт JSON", command=self.export_json).pack(side="left", padx=5)
        ttk.Button(top, text="📝 Экспорт Markdown", command=self.export_markdown).pack(side="left", padx=5)

        self.output = tk.Text(
            self,
            height=25,
            bg="black",
            fg="lime",
            wrap="none",
            insertbackground="white"
        )
        self.output.pack(fill="both", expand=True, padx=5, pady=5)

    # ---------------------------------------------------------
    # Запуск NetworkChecker
    # ---------------------------------------------------------
    def run_scan(self):
        domain = self.domain_entry.get().strip()

        if not domain:
            messagebox.showerror("Ошибка", "Введите домен")
            return

        self.safe_log(f"🚀 Старт Network Scan для {domain}\n")

        try:
            checker = NetworkChecker(domain, gui_output=self.output)
            checker.run_all_checks()

            # Автосохранение профиля
            self.after(2000, lambda: self.autosave_profile(domain))

        except Exception as e:
            self.safe_log(f"❌ Ошибка запуска NetworkChecker: {e}")

    # ---------------------------------------------------------
    # Потокобезпечний лог
    # ---------------------------------------------------------
    def safe_log(self, text: str):
        self.after(0, lambda: self._append(text))

    def _append(self, text: str):
        try:
            self.output.insert("end", text + "\n")
            self.output.see("end")
        except Exception:
            print(text)

    # ---------------------------------------------------------
    # Очистить вывод
    # ---------------------------------------------------------
    def clear_output(self):
        self.output.delete("1.0", "end")

    # ---------------------------------------------------------
    # Сохранить текстовый лог
    # ---------------------------------------------------------
    def save_text(self):
        content = self.output.get("1.0", "end").strip()
        if not content:
            messagebox.showinfo("Сохранение", "Нет данных для сохранения")
            return

        file_path = filedialog.asksaveasfilename(
            title="Сохранить лог",
            defaultextension=".txt",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")]
        )

        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Сохранение", f"Данные сохранены:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить данные:\n{e}")

    # ---------------------------------------------------------
    # Автосохранение network_profile.json
    # ---------------------------------------------------------
    def autosave_profile(self, domain: str):
        """
        Збирає дані з ThreatConnector і зберігає у JSON.
        """
        try:
            profile = {
                "domain": domain,
                "timestamp": datetime.now().isoformat(),
                "results": self._collect_threat_data()
            }

            self.last_results = profile  # для експорту

            path = LOG_DIR / f"network_profile_{domain}.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(profile, f, indent=2, ensure_ascii=False)

            self.safe_log(f"💾 Профиль сохранён: {path}")

        except Exception as e:
            self.safe_log(f"❌ Ошибка автосохранения профиля: {e}")

    def _collect_threat_data(self):
        """
        Забирає всі записи NetworkChecker з ThreatTab.
        """
        if not self.threat_tab:
            return {}

        collected = []
        for item in self.threat_tab.get_all_threats():
            if item.get("module") == "NetworkChecker":
                collected.append(item)

        return collected

    # ---------------------------------------------------------
    # Экспорт JSON
    # ---------------------------------------------------------
    def export_json(self):
        if not self.last_results:
            messagebox.showinfo("Экспорт", "Нет данных для экспорта")
            return

        file_path = filedialog.asksaveasfilename(
            title="Экспорт JSON",
            defaultextension=".json",
            filetypes=[("JSON файлы", "*.json"), ("Все файлы", "*.*")]
        )

        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(self.last_results, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Экспорт", f"JSON сохранён:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось экспортировать JSON:\n{e}")

    # ---------------------------------------------------------
    # Экспорт Markdown
    # ---------------------------------------------------------
    def export_markdown(self):
        if not self.last_results:
            messagebox.showinfo("Экспорт", "Нет данных для экспорта")
            return

        file_path = filedialog.asksaveasfilename(
            title="Экспорт Markdown",
            defaultextension=".md",
            filetypes=[("Markdown файлы", "*.md"), ("Все файлы", "*.*")]
        )

        if not file_path:
            return

        try:
            md = self._build_markdown(self.last_results)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(md)
            messagebox.showinfo("Экспорт", f"Markdown сохранён:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось экспортировать Markdown:\n{e}")

    def _build_markdown(self, data: dict) -> str:
        md = f"# 🌐 Network Profile: {data['domain']}\n"
        md += f"Дата: **{data['timestamp']}**\n\n"

        for item in data["results"]:
            md += f"## 🔹 {item.get('result', {}).get('check', 'Check')}\n"
            md += f"- **Статус:** {item.get('result', {}).get('status')}\n"
            md += f"- **Источник:** {item.get('module')}\n"
            md += f"- **Цель:** {item.get('target')}\n\n"

        return md