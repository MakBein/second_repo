# xss_security_gui/autoanalyzer.py
"""
AutoAnalyzerTab ULTRA 6.2
Автоматический анализатор XSS Security Suite:
- Обход сайта
- Фуззинг параметров
- Фуззинг форм
- Глубокий анализ
Интеграция с settings.py и ThreatConnector
"""

import os
import sys
import webbrowser
import threading
import subprocess
import json
import tkinter as tk
from tkinter import ttk, messagebox

# Универсальные импорты
from xss_security_gui import settings
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
from utils.threat_sender import ThreatSenderMixin
from xss_security_gui.crawler import crawl_site, save_outputs
from xss_security_gui.form_fuzzer import fuzz_form
from xss_security_gui.param_fuzzer import fuzz_url_params
from xss_security_gui.crawler_plus import analyze_list
from xss_security_gui.svg_viewer import SVGViewer
from xss_security_gui.json_result_table import JSONResultTable


class AutoAnalyzerTab(ttk.Frame, ThreatSenderMixin):
    def __init__(self, parent, threat_tab=None):
        super().__init__(parent)
        self.links = []
        self.threat_tab = threat_tab
        self.result_box = tk.Text(
            self,
            wrap="word",
            height=25,
            bg="black",
            fg="lime",
            insertbackground="white"
        )
        self.build_ui()

    def _log(self, text: str):
        self.result_box.insert("end", text + "\n")
        self.result_box.see("end")

    def build_ui(self):
        control = ttk.Frame(self)
        control.pack(pady=5)

        ttk.Label(control, text="🔍 Домен:").grid(row=0, column=0, padx=5)
        self.url_entry = ttk.Entry(control, width=60)
        self.url_entry.grid(row=0, column=1, padx=5)

        ttk.Button(control, text="🕷️ Обойти сайт", command=self.crawl).grid(row=0, column=2, padx=5)
        ttk.Button(control, text="▶️ Проанализировать всё", command=self.fuzz_all).grid(row=0, column=3, padx=5)
        ttk.Button(control, text="📊 Отчёт JSON", command=self.show_json_report).grid(row=1, column=1, pady=4)
        ttk.Button(control, text="🗺 Карта сайта", command=self.show_svg_map).grid(row=1, column=2, pady=4)
        ttk.Button(control, text="📕 Лог ошибок", command=self.show_error_log).grid(row=1, column=3, pady=4)
        ttk.Button(control, text="🧬 Глубокий анализ", command=self.run_deep_analysis).grid(row=1, column=4, pady=4)
        ttk.Button(control, text="🎯 Фуззить формы", command=self.fuzz_forms).grid(row=1, column=5, pady=4)

        self.result_box.pack(padx=10, pady=5, fill="both", expand=True)

    # ============================================================
    #  Основные операции (в потоках)
    # ============================================================

    def crawl(self):
        domain = self.url_entry.get()
        if not domain.startswith("http"):
            messagebox.showwarning("Неверный ввод", "Укажите домен с http:// или https://")
            return
        threading.Thread(target=self._crawl_worker, args=(domain,), daemon=True).start()

    def _crawl_worker(self, domain):
        self.result_box.delete("1.0", "end")
        self._log(f"🌍 Обход сайта: {domain} ...")

        results = crawl_site(domain)
        save_outputs()

        if not results:
            self._log("⚠️ Ничего не найдено или сайт не откликнулся.")
            return

        all_links = []
        self._log(f"🔎 Найдено страниц: {len(results)}")

        for page in results:
            self._log(f"📄 {page.get('url', '[?]')}")
            for f in page.get("forms", []):
                self._log(f"   📝 {f.get('method', '?')} {f.get('action', '?')} → поля: {f.get('inputs', [])}")
            for script in page.get("scripts", []):
                self._log(f"   📦 {script}")
            all_links.append(page.get("url"))

        self.links = list(filter(None, set(all_links)))
        self._log("✅ Обход завершён. Готов к фуззингу.")

        svg_path = settings.LOG_DIR / "crawl_graph.svg"
        if svg_path.exists():
            webbrowser.open(str(svg_path))

        THREAT_CONNECTOR.emit(module="AutoAnalyzer", target=domain,
                              result={"check": "auto_crawl", "pages": results})

    def fuzz_all(self):
        if not self.links:
            messagebox.showinfo("Нет ссылок", "Сначала проведите обход сайта.")
            return
        threading.Thread(target=self._fuzz_all_worker, daemon=True).start()

    def _fuzz_all_worker(self):
        self._log("🚀 Запуск фуззинга всех URL...")
        all_findings = []
        for url in self.links:
            self._log(f"🎯 {url}")
            results = fuzz_url_params(url)
            if results:
                for key, payload, test_url in results:
                    self._log(f"✔️ XSS в параметре '{key}' → {test_url}")
                    all_findings.append({"param": key, "payload": payload, "url": test_url})
            else:
                self._log("❌ Нет уязвимости")
        self._log("✅ Фуззинг всех URL завершён.")
        THREAT_CONNECTOR.emit(module="AutoAnalyzer", target="links",
                              result={"check": "auto_fuzz", "findings": all_findings})

    def run_deep_analysis(self):
        if not self.links:
            messagebox.showinfo("Нет ссылок", "Сначала проведите обычный обход.")
            return
        threading.Thread(target=self._deep_analysis_worker, daemon=True).start()

    def _deep_analysis_worker(self):
        try:
            self._log("🧬 Запуск глубокого анализа...")
            analyze_list(self.links)
            self._log("✅ deep_crawl.json создан. Можно открыть вкладку Глубокий анализ.")
            THREAT_CONNECTOR.emit(module="AutoAnalyzer", target="deep_analysis",
                                  result={"check": "deep_analysis", "links": self.links})
        except Exception as e:
            self._log(f"❌ Ошибка при анализе: {e}")

    def fuzz_forms(self):
        threading.Thread(target=self._fuzz_forms_worker, daemon=True).start()

    def _fuzz_forms_worker(self):
        path = settings.JSON_CRAWL_EXPORT_PATH
        if not path.exists():
            self._log("❌ Нет результатов краулинга. Сначала обойдите сайт.")
            return
        try:
            with open(path, encoding="utf-8") as f:
                crawl_data = json.load(f)
        except Exception:
            self._log("❌ Ошибка чтения crawler_results.json")
            return

        self._log("🎯 Начинаю фуззинг всех форм...")
        form_findings = []
        for page in crawl_data:
            forms = page.get("forms", [])
            url = page.get("url", "")
            for form in forms:
                action = form.get("action") or url
                method = form.get("method", "GET")
                inputs = form.get("inputs", [])
                if not inputs:
                    continue
                self._log(f"🧪 Тестирую: {action} ({method}) с полями {inputs}...")
                results = fuzz_form(action, method, inputs)
                for res in results:
                    if res.get("vulnerable"):
                        self._log(f"⚠️ XSS на {res['url']} с payload: {res['payload']}")
                        form_findings.append(res)
        self._log("✅ Фуззинг форм завершён.")
        THREAT_CONNECTOR.emit(module="AutoAnalyzer", target="forms",
                              result={"check": "form_fuzzer", "findings": form_findings})

    # ============================================================
    #  Вспомогательные UI методы
    # ============================================================

    def show_svg_map(self):
        top = tk.Toplevel(self)
        top.title("🗺 Карта сайта")
        viewer = SVGViewer(top)
        viewer.pack(fill="both", expand=True)

    def show_json_report(self):
        top = tk.Toplevel(self)
        top.title("📊 JSON-отчёт по анализу")
        table = JSONResultTable(top)
        table.pack(fill="both", expand=True)

    def show_error_log(self):
        path = settings.CRAWLER_ERROR_LOG
        if os.path.exists(path):
            try:
                if os.name == "nt":  # Windows
                    subprocess.Popen(["notepad", str(path)])
                elif sys.platform == "darwin":  # macOS
                    subprocess.Popen(["open", str(path)])
                else:  # Linux/Unix
                    subprocess.Popen(["xdg-open", str(path)])
            except Exception as e:
                self._log(f"❌ Не удалось открыть лог: {e}")
        else:
            self._log("⚠️ Лог ошибок отсутствует. Ещё не было сбоев или он не создан.")