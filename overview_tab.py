# xss_security_gui/overview_tab.py
# ============================================================
# OverviewTab 5.0 / Enterprise Edition
# ------------------------------------------------------------
# - Централизованный дашборд состояния движка
# - Интеграция с краулером, API‑парсером и Threat Intel
# - Без блокировки GUI (потоки + after)
# - Расширенные метрики: модули, severity, CSP, XSS‑хиты
# - Графики уровня Burp Suite Enterprise‑стиля
# - Полностью совместим с текущей архитектурой
# ============================================================

from __future__ import annotations

import datetime
import json
import os
import threading
from collections import Counter
from typing import Any, Callable, Dict, Optional, List

import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import ttk, messagebox, filedialog


from xss_security_gui.report_merger import ReportMerger
from xss_security_gui.crawler import crawl_site
from xss_security_gui.api_parser import extract_api_data


class OverviewTab(ttk.Frame):
    """
    Вкладка «Обзор» (Enterprise‑уровень):

    - Запуск краулера по URL (без блокировки GUI)
    - Запуск API‑парсера по стандартному или выбранному логу
    - Сводная статистика:
        • страницы, формы, XSS‑хиты
        • Threat‑отчёты, типы атак, последний отчёт
    """

    def __init__(self, parent, app, threat_tab: Optional[ttk.Frame] = None) -> None:
        super().__init__(parent)
        self.app = app
        self.threat_tab = threat_tab

        # Пути к основным артефактам
        self.crawler_path = os.path.join("logs", "crawler_results.json")
        self.deep_crawl_path = os.path.join("logs", "deep_crawl.json")
        self.threat_log_path = os.path.join("logs", "threat_intel.log")

        # Последние результаты API‑парсера (для графика)
        self.last_api_results: Dict[str, Any] = {}

        # Маппинг «лейбл → (StringVar, функция‑счётчик)»
        self.label_vars: Dict[str, tuple[tk.StringVar, Callable[[], Any]]] = {}

        self.build_ui()
        self.after(4000, self.refresh_stats)

    # ========================================================
    #  UI
    # ========================================================

    def build_ui(self) -> None:
        # Верхняя панель: URL + кнопки
        url_frame = ttk.Frame(self)
        url_frame.pack(pady=5, anchor="w", fill="x")

        ttk.Label(url_frame, text="🌐 URL для парсинга:").pack(side="left")
        self.url_entry = ttk.Entry(url_frame, width=50)
        self.url_entry.pack(side="left", padx=5)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=5, anchor="w", fill="x")

        ttk.Button(btn_frame, text="🧬 Парсить сайт", command=self.parse_site).pack(
            side="left", padx=4
        )
        ttk.Button(
            btn_frame, text="📈 CSP‑риски", command=self.show_csp_risk_chart
        ).pack(side="left", padx=4)
        ttk.Button(
            btn_frame, text="🧬 Парсить стандартный лог", command=self.run_api_parser
        ).pack(side="left", padx=4)
        ttk.Button(
            btn_frame, text="📂 Выбрать лог и парсить", command=self.run_api_parser_file
        ).pack(side="left", padx=4)
        ttk.Button(
            btn_frame, text="📊 API‑индикаторы", command=self.show_api_chart
        ).pack(side="left", padx=4)
        ttk.Button(
            btn_frame, text="📊 Threat‑модули", command=self.show_threat_module_chart
        ).pack(side="left", padx=4)
        ttk.Button(
            btn_frame, text="📊 Threat‑severity", command=self.show_threat_severity_chart
        ).pack(side="left", padx=4)
        ttk.Button(
            btn_frame,
            text="📊 Построить граф сайта",
            command=lambda: self.app.render_graph("graph.dot", "graph.svg"),
        ).pack(side="left", padx=4)

        # Кнопка сводного Threat‑отчёта (ReportMerger → ThreatAnalysisTab)
        ttk.Button(
            btn_frame,
            text="🧷 Сводный Threat‑отчёт",
            command=self.run_report_merger_async,
        ).pack(side="left", padx=4)

        # Кнопка обновления метрик
        ttk.Button(
            btn_frame,
            text="🔄 Обновить метрики",
            command=self.refresh_stats,
        ).pack(side="left", padx=4)

        # Блок метрик
        stats_frame = ttk.LabelFrame(self, text="📊 Обзор метрик")
        stats_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.stats: Dict[str, Callable[[], Any]] = {
            "🕸️ Страниц пройдено": self.count_pages,
            "📝 Форм найдено": self.count_forms,
            "🧪 XSS‑уязвимостей": self.count_hits,
            "📤 Threat Intel отчётов": self.count_threat_reports,
            "🧠 Threat типов атак": self.count_threat_types,
            "🕒 Последний Threat‑отчёт": self.last_threat_timestamp,
            "📡 Honeypot‑триггеров": lambda: self.count_lines("logs/honeypot_hits.log"),
            "✅ CSP включён на": self.count_csp_enabled,
            "🛡️ CSP: strong": lambda: self.count_csp_risks().get("strong", 0),
            "⚠️ CSP: moderate": lambda: self.count_csp_risks().get("moderate", 0),
            "🚨 CSP: weak": lambda: self.count_csp_risks().get("weak", 0),
            "❌ CSP: none": lambda: self.count_csp_risks().get("none", 0),
        }

        for label, func in self.stats.items():
            row = ttk.Frame(stats_frame)
            row.pack(pady=2, anchor="w", fill="x")
            var = tk.StringVar(value="...")
            ttk.Label(row, text=label, width=25).pack(side="left")
            ttk.Label(row, textvariable=var, foreground="lime").pack(side="left")
            self.label_vars[label] = (var, func)

    # ========================================================
    #  Интеграция с ReportMerger / ThreatAnalysisTab
    # ========================================================

    def run_report_merger_async(self):
        """Запускает ReportMerger в отдельном потоке и отправляет результат в ThreatAnalysisTab."""
        if not hasattr(self.app, "threat_tab") or self.app.threat_tab is None:
            messagebox.showwarning("Threat Intel", "ThreatAnalysisTab недоступен.")
            return

        def callback(report: Dict[str, Any], error: Optional[Exception]):
            if error:
                self.after(
                    0,
                    lambda: messagebox.showerror(
                        "Threat Report Merger", f"Ошибка объединения отчётов:\n{error}"
                    ),
                )
                return

            def send():
                try:
                    self.app.threat_tab.send_to_threat_intel("report_merger", report)
                    messagebox.showinfo(
                        "Threat Report Merger",
                        "Сводный Threat‑отчёт отправлен в Threat Intel.",
                    )
                except Exception as e:
                    messagebox.showerror(
                        "Threat Report Merger",
                        f"Ошибка отправки в Threat Intel:\n{e}",
                    )

            self.after(0, send)

        merger = ReportMerger()
        merger.merge_async(callback)

    # ========================================================
    #  Краулер
    # ========================================================

    def parse_site(self) -> None:
        url = self.url_entry.get().strip()
        if not url.startswith("http"):
            messagebox.showerror("Ошибка", "Укажи корректный URL (http/https).")
            return

        def gui_callback(payload: Dict[str, Any]) -> None:
            analyzer = getattr(self.app, "analyzer", None)
            if analyzer and hasattr(analyzer, "update_from_crawler"):
                self.app.after(0, analyzer.update_from_crawler, payload)

        def worker() -> None:
            try:
                crawl_site(url, gui_callback=gui_callback, parallel=True)
            except Exception as e:
                self.after(
                    0,
                    lambda: messagebox.showerror(
                        "Ошибка краулера", f"Не удалось выполнить краулинг:\n{e}"
                    ),
                )

        threading.Thread(target=worker, daemon=True, name="OverviewCrawler").start()
        messagebox.showinfo(
            "Запущено",
            "Краулер работает.\nРезультаты смотри во вкладке «Анализатор».",
        )

    # ========================================================
    #  API‑парсер
    # ========================================================

    def run_api_parser(self) -> None:
        """Запуск API‑парсера по стандартному логу form_fuzzer."""
        log_path = "logs/form_fuzz_hits.log"
        if not os.path.exists(log_path):
            messagebox.showwarning("Файл не найден", f"{log_path} отсутствует.")
            return

        def worker():
            try:
                results = extract_api_data(log_path, threat_tab=self.threat_tab)
                self.last_api_results = results
                total = sum(len(v) for v in results.values())
                self.after(
                    0,
                    lambda: messagebox.showinfo(
                        "✅ Парсинг завершён",
                        f"Найдено {total} индикаторов.\nРезультаты отправлены в Threat Intel.",
                    ),
                )
            except Exception as e:
                self.after(
                    0,
                    lambda: messagebox.showerror("❌ Ошибка парсинга", str(e)),
                )

        threading.Thread(target=worker, daemon=True, name="OverviewAPIParser").start()

    def run_api_parser_file(self) -> None:
        """Запуск API‑парсера по выбранному лог‑файлу."""
        path = filedialog.askopenfilename(
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")]
        )
        if not path:
            return

        def worker():
            try:
                results = extract_api_data(path, threat_tab=self.threat_tab)
                self.last_api_results = results
                total = sum(len(v) for v in results.values())
                self.after(
                    0,
                    lambda: messagebox.showinfo(
                        "✅ Парсинг завершён",
                        f"Найдено {total} индикаторов.\nРезультаты отправлены в Threat Intel.",
                    ),
                )
            except Exception as e:
                self.after(
                    0,
                    lambda: messagebox.showerror("❌ Ошибка парсинга", str(e)),
                )

        threading.Thread(target=worker, daemon=True, name="OverviewAPIParserFile").start()


    # ========================================================
    #  Графики: API‑индикаторы
    # ========================================================

    def show_api_chart(self) -> None:
        if not self.last_api_results:
            messagebox.showinfo("Нет данных", "Сначала запусти парсинг логов.")
            return

        data = self.last_api_results
        labels: List[str] = []
        sizes: List[int] = []

        for key in sorted(data.keys()):
            count = len(data[key])
            if count > 0:
                labels.append(f"{key} ({count})")
                sizes.append(count)

        if not sizes:
            messagebox.showinfo("Нет данных", "Индикаторов для графика не найдено.")
            return

        plt.figure(figsize=(7, 7))
        plt.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
        plt.title("📊 Индикаторы из логов (API‑парсер)")
        plt.axis("equal")
        plt.tight_layout()
        plt.show()

    # ========================================================
    #  Графики: CSP Risk Distribution
    # ========================================================

    def show_csp_risk_chart(self) -> None:
        data = self.count_csp_risks()
        if not data:
            tk.messagebox.showinfo("Немає даних", "CSP-статистика відсутня.")
            return

        labels: List[str] = []
        sizes: List[int] = []
        colors = {
            "strong": "#4CAF50",
            "moderate": "#FFEB3B",
            "weak": "#FF9800",
            "none": "#F44336",
        }

        for level in ["strong", "moderate", "weak", "none"]:
            count = data.get(level, 0)
            if count > 0:
                labels.append(f"{level} ({count})")
                sizes.append(count)

        if not sizes:
            tk.messagebox.showinfo("Немає даних", "CSP-статистика відсутня.")
            return

        plt.figure(figsize=(6, 6))
        plt.pie(
            sizes,
            labels=labels,
            colors=[colors[l.split()[0]] for l in labels],
            autopct="%1.1f%%",
            startangle=140,
        )
        plt.title("CSP Risk Distribution")
        plt.axis("equal")
        plt.tight_layout()
        plt.show()

    # ========================================================
    #  Графики: Threat Intel (модули и severity)
    # ========================================================

    def _load_threat_log_objects(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.threat_log_path):
            return []
        objs: List[Dict[str, Any]] = []
        try:
            with open(self.threat_log_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        objs.append(obj)
                    except Exception:
                        continue
        except Exception:
            return []
        return objs

    def show_threat_module_chart(self) -> None:
        objs = self._load_threat_log_objects()
        if not objs:
            messagebox.showinfo("Нет данных", "Threat‑лог пуст или недоступен.")
            return

        counter = Counter()
        for obj in objs:
            module = obj.get("module") or obj.get("type") or "unknown"
            counter[module] += 1

        if not counter:
            messagebox.showinfo("Нет данных", "Не удалось извлечь модули из Threat‑лога.")
            return

        modules = list(counter.keys())
        counts = [counter[m] for m in modules]

        plt.figure(figsize=(8, 5))
        plt.bar(modules, counts, color="#2196F3")
        plt.title("Threat Intel: распределение по модулям")
        plt.xlabel("Модуль")
        plt.ylabel("Количество артефактов")
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.show()

    def show_threat_severity_chart(self) -> None:
        objs = self._load_threat_log_objects()
        if not objs:
            messagebox.showinfo("Нет данных", "Threat‑лог пуст или недоступен.")
            return

        counter = Counter()
        for obj in objs:
            result = obj.get("result") or {}
            sev = result.get("severity") or obj.get("severity") or "info"
            counter[str(sev)] += 1

        if not counter:
            messagebox.showinfo("Нет данных", "Не удалось извлечь severity из Threat‑лога.")
            return

        levels = ["critical", "high", "medium", "low", "info", "none"]
        values = [counter.get(l, 0) for l in levels]

        if sum(values) == 0:
            messagebox.showinfo("Нет данных", "Severity‑метрики отсутствуют.")
            return

        colors = {
            "critical": "#B71C1C",
            "high": "#F44336",
            "medium": "#FF9800",
            "low": "#FFEB3B",
            "info": "#2196F3",
            "none": "#9E9E9E",
        }

        plt.figure(figsize=(8, 5))
        plt.bar(levels, values, color=[colors[l] for l in levels])
        plt.title("Threat Intel: распределение по severity")
        plt.xlabel("Severity")
        plt.ylabel("Количество артефактов")
        plt.tight_layout()
        plt.show()

    # ========================================================
    #  Периодическое обновление статистики
    # ========================================================

    def refresh_stats(self) -> None:
        for label, (var, func) in self.label_vars.items():
            try:
                var.set(str(func()))
            except Exception:
                var.set("—")
        self.after(5000, self.refresh_stats)

    # ========================================================
    #  Вспомогательные методы
    # ========================================================

    def get_data_path(self) -> str:
        # Предпочтение deep_crawl.json, fallback на crawler_results.json
        return (
            self.deep_crawl_path
            if os.path.exists(self.deep_crawl_path)
            else self.crawler_path
        )

    def count_lines(self, path: str) -> int:
        if not os.path.exists(path):
            return 0
        try:
            with open(path, encoding="utf-8") as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0

    # ========================================================
    #  Метрики
    # ========================================================

    def count_pages(self) -> int:
        path = self.get_data_path()
        if not os.path.exists(path):
            return 0
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return len(data)
            return len(data.get("pages", []))
        except Exception:
            return 0

    def count_threat_reports(self) -> int:
        if not os.path.exists(self.threat_log_path):
            return 0
        try:
            with open(self.threat_log_path, encoding="utf-8") as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0

    def count_threat_types(self) -> str:
        if not os.path.exists(self.threat_log_path):
            return "—"
        counter = Counter()
        try:
            with open(self.threat_log_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        typ = obj.get("type") or obj.get("module") or "unknown"
                        counter[typ] += 1
                    except Exception:
                        continue
        except Exception:
            return "—"

        if not counter:
            return "—"
        return ", ".join(f"{k}:{v}" for k, v in counter.items())

    def last_threat_timestamp(self) -> str:
        if not os.path.exists(self.threat_log_path):
            return "—"
        try:
            with open(self.threat_log_path, encoding="utf-8") as f:
                lines = [line for line in f if line.strip()]
            if not lines:
                return "—"
            last = json.loads(lines[-1])
            ts = last.get("timestamp")
            if not ts:
                return "—"
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                return ts
        except Exception:
            return "—"

    def count_forms(self) -> int:
        path = self.get_data_path()
        if not os.path.exists(path):
            return 0
        total = 0
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            pages = data if isinstance(data, list) else data.get("pages", [])
            for page in pages:
                total += len(page.get("forms", []))
        except Exception:
            pass
        return total

    def count_hits(self) -> int:
        return self.count_lines("logs/form_fuzz_hits.log") + self.count_lines(
            "logs/param_fuzz_hits.log"
        )

    def count_csp_enabled(self) -> int:
        path = self.get_data_path()
        if not os.path.exists(path):
            return 0
        total = 0
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            pages = data if isinstance(data, list) else data.get("pages", [])
            for page in pages:
                headers = page.get("headers", {})
                csp = headers.get("CSP") or headers.get("Content-Security-Policy")
                if csp and csp != "-":
                    total += 1
        except Exception:
            pass
        return total

    def count_csp_risks(self) -> Counter:
        path = self.get_data_path()
        counter = Counter()
        if not os.path.exists(path):
            return counter
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            pages = data if isinstance(data, list) else data.get("pages", [])
            for page in pages:
                risk = (
                    page.get("csp_risk_level")
                    or page.get("headers", {}).get("csp_risk_level")
                )
                if risk:
                    counter[str(risk)] += 1
        except Exception:
            pass
        return counter