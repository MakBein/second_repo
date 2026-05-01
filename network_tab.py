# xss_security_gui/network_tab.py

from __future__ import annotations

import json
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Dict, List, Optional

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from xss_security_gui.network_checker import NetworkChecker
from xss_security_gui.settings import LOG_DIR


class NetworkTab(ttk.Frame):
    """
    NetworkTab ULTRA 8.1 (hardended)

    - Потокобезпечный лог (через after)
    - Кнопки: Очистить вывод, Сохранить данные, Экспорт JSON/Markdown
    - Автосохранение network_profile_<domain>.json
    - Интеграция с ThreatTab (мягкая, без падений при отсутствии/поломке)
    """

    def __init__(self, parent: ttk.Notebook, threat_tab: Optional[ttk.Frame] = None) -> None:
        super().__init__(parent)
        self.threat_tab = threat_tab

        # Последний успешный профиль (для экспорта)
        self.last_results: Dict[str, Any] = {}

        # Гарантируем существование каталога логов
        try:
            Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
        except Exception:
            # Не валим GUI, просто продолжаем — сохранение может не сработать
            pass

        self.build_ui()

    # ---------------------------------------------------------
    # UI
    # ---------------------------------------------------------
    def build_ui(self) -> None:
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
            insertbackground="white",
        )
        self.output.pack(fill="both", expand=True, padx=5, pady=5)

    # ---------------------------------------------------------
    # Запуск NetworkChecker
    # ---------------------------------------------------------
    def run_scan(self) -> None:
        domain = self.domain_entry.get().strip()

        if not domain:
            messagebox.showerror("Ошибка", "Введите домен")
            return

        # Простейшая валидация домена (без фанатизма)
        if " " in domain or "/" in domain:
            messagebox.showerror("Ошибка", "Некорректный домен")
            return

        self.safe_log(f"🚀 Старт Network Scan для {domain}")

        try:
            checker = NetworkChecker(domain, gui_output=self.output)
            # Важно: если NetworkChecker внутри использует потоки и пишет в Text —
            # это потенциально небезопасно. Лучше, чтобы он звал наш safe_log.
            checker.run_all_checks()

            # Автосохранение профиля (через after, чтобы не блокировать)
            self.after(2000, lambda d=domain: self.autosave_profile(d))

        except Exception as e:
            self.safe_log(f"❌ Ошибка запуска NetworkChecker: {e!r}")

    # ---------------------------------------------------------
    # Потокобезпечный лог
    # ---------------------------------------------------------
    def safe_log(self, text: str) -> None:
        # Всегда через after, чтобы не трогать Text из чужих потоков
        self.after(0, lambda t=text: self._append(t))

    def _append(self, text: str) -> None:
        try:
            self.output.insert("end", text + "\n")
            self.output.see("end")
        except Exception:
            # В крайнем случае — в stdout, но не валим GUI
            print(text)

    # ---------------------------------------------------------
    # Очистить вывод
    # ---------------------------------------------------------
    def clear_output(self) -> None:
        try:
            self.output.delete("1.0", "end")
        except Exception:
            pass

    # ---------------------------------------------------------
    # Сохранить текстовый лог
    # ---------------------------------------------------------
    def save_text(self) -> None:
        try:
            content = self.output.get("1.0", "end").strip()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось прочитать вывод:\n{e}")
            return

        if not content:
            messagebox.showinfo("Сохранение", "Нет данных для сохранения")
            return

        file_path = filedialog.asksaveasfilename(
            title="Сохранить лог",
            defaultextension=".txt",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")],
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
    def autosave_profile(self, domain: str) -> None:
        """
        Собирает данные из ThreatTab и сохраняет в JSON.
        Не валит GUI при ошибках.
        """
        try:
            profile: Dict[str, Any] = {
                "domain": domain,
                "timestamp": datetime.now(UTC).isoformat(),
                "results": self._collect_threat_data(),
            }

            self.last_results = profile  # для экспорта

            path = Path(LOG_DIR) / f"network_profile_{domain}.json"
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

            with open(path, "w", encoding="utf-8") as f:
                json.dump(profile, f, indent=2, ensure_ascii=False)

            self.safe_log(f"💾 Профиль сохранён: {path}")

        except Exception as e:
            self.safe_log(f"❌ Ошибка автосохранения профиля: {e!r}")

    def _collect_threat_data(self) -> List[Dict[str, Any]]:
        """
        Забирает все записи NetworkChecker из ThreatTab.
        Возвращает список, даже если ThreatTab отсутствует или сломан.
        """
        if not self.threat_tab or not hasattr(self.threat_tab, "get_all_threats"):
            return []

        collected: List[Dict[str, Any]] = []
        try:
            for item in self.threat_tab.get_all_threats():
                if not isinstance(item, dict):
                    continue
                if item.get("module") == "NetworkChecker":
                    collected.append(item)
        except Exception:
            # Не валим GUI, просто возвращаем то, что успели
            pass

        return collected

    # ---------------------------------------------------------
    # Экспорт JSON
    # ---------------------------------------------------------
    def export_json(self) -> None:
        if not self.last_results:
            messagebox.showinfo("Экспорт", "Нет данных для экспорта")
            return

        file_path = filedialog.asksaveasfilename(
            title="Экспорт JSON",
            defaultextension=".json",
            filetypes=[("JSON файлы", "*.json"), ("Все файлы", "*.*")],
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
    def export_markdown(self) -> None:
        if not self.last_results:
            messagebox.showinfo("Экспорт", "Нет данных для экспорта")
            return

        file_path = filedialog.asksaveasfilename(
            title="Экспорт Markdown",
            defaultextension=".md",
            filetypes=[("Markdown файлы", "*.md"), ("Все файлы", "*.*")],
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

    def _build_markdown(self, data: Dict[str, Any]) -> str:
        domain = data.get("domain", "unknown")
        timestamp = data.get("timestamp", "")
        results = data.get("results", []) or []

        md = f"# 🌐 Network Profile: {domain}\n"
        if timestamp:
            md += f"Дата: **{timestamp}**\n\n"
        else:
            md += "\n"

        if not isinstance(results, list):
            results = []

        for item in results:
            if not isinstance(item, dict):
                continue

            result = item.get("result") or {}
            if not isinstance(result, dict):
                result = {}

            check_name = result.get("check", "Check")
            status = result.get("status", "unknown")
            module = item.get("module", "NetworkChecker")
            target = item.get("target", domain)

            md += f"## 🔹 {check_name}\n"
            md += f"- **Статус:** {status}\n"
            md += f"- **Источник:** {module}\n"
            md += f"- **Цель:** {target}\n\n"

        if not results:
            md += "_Нет результатов для отображения._\n"

        return md