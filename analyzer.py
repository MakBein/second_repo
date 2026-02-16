# xss_security_gui/analyzer.py
# ============================================================
#  XSS Analyzer 6.0 (Extended Edition)
#  - Tkinter GUI
#  - AttackEngine integration
#  - Deep Crawler integration
#  - Threat Intel (ThreatSenderMixin / ThreatConnector)
#  - Неблокирующие операции (потоки + after)
#  - Расширенная работа с PAYLOADS (мульти‑категории)
#  - Доп. экспорт (JSON), очистка лога, гибкая генерация payload’ов
# ============================================================

import json
import os
import queue
import subprocess
import sys
import threading
import time
from typing import Any, Dict, Optional, List

import requests
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from xss_security_gui.param_fuzzer import fuzz_url_params
from xss_security_gui.payload_mutator import mutate_payload
from xss_security_gui.utils.threat_sender import ThreatSenderMixin
from xss_security_gui.payloads import PAYLOADS
from xss_security_gui.settings import LOG_SUCCESS_PATH, MAX_REPORT_LINE_LENGTH
from xss_security_gui.attack_engine import AttackEngine
from xss_security_gui.dom_parser import DOMParser
from xss_security_gui.crawler import crawl_site, save_outputs
from fpdf import FPDF
from fpdf import __version__ as fpdf_version

print(f"[FPDF] Используем версию FPDF: {fpdf_version}")

# ============================================================
#  Основной класс GUI-анализатора
# ============================================================

class XSSAnalyzerApp(ttk.Frame, ThreatSenderMixin):
    """
    Tkinter‑вкладка XSS‑анализатора:
    - XSStrike
    - DOM‑анализ
    - фуззинг параметров
    - мутатор
    - краулер
    - автоатака через AttackEngine
    - расширенная работа с PAYLOADS (XSS/SQLi/SSRF/LFI/и т.д.)
    """

    def __init__(
        self,
        parent,
        status_var: Optional[tk.StringVar] = None,
        full_analysis_tab: Optional[ttk.Frame] = None,
        threat_tab: Optional[ttk.Frame] = None,
    ):
        super().__init__(parent)

        self.status_var = status_var
        self.full_analysis_tab = full_analysis_tab
        self.threat_tab = threat_tab

        self.data_queue: "queue.Queue[Any]" = queue.Queue()
        self.after(100, self.process_queue)

        self.crawled_domain: str = ""
        self.crawled_scripts: List[Dict[str, Any]] = []
        self.full_data: Dict[str, Any] = {}

        self._dom_attack_running: bool = False
        self._crawler_running: bool = False

        self.log: str = ""

        self.attack_engine = AttackEngine(
            domain=self.crawled_domain,
            threat_sender=self.send_to_threat_intel,
            log_func=self.log_output,
        )

        self.payload_category_var = tk.StringVar(value="XSS")
        self.payload_buttons: List[ttk.Button] = []

        self.build_ui()

    # ========================================================
    #  UI
    # ========================================================

    def build_ui(self) -> None:
        input_frame = ttk.Frame(self)
        input_frame.pack(pady=10, fill=tk.X)

        ttk.Label(input_frame, text="🎯 URL / Payload:").grid(row=0, column=0, padx=5)
        self.input_entry = ttk.Entry(input_frame, width=70)
        self.input_entry.grid(row=0, column=1, padx=5)

        self.filter_var = tk.StringVar(value="All")
        ttk.Label(input_frame, text="Фильтр:").grid(row=0, column=2)
        ttk.Combobox(
            input_frame,
            textvariable=self.filter_var,
            values=["All", "Reflected", "Stored", "DOM-based"],
            width=12,
        ).grid(row=0, column=3, padx=5)

        ttk.Button(input_frame, text="▶️ Анализировать", command=self.scan).grid(
            row=0, column=4, padx=5
        )

        # Блок выбора категории payload’ов
        payload_frame = ttk.Frame(self)
        payload_frame.pack(pady=5, fill=tk.X)

        ttk.Label(payload_frame, text="Категория payload’ов:").pack(
            side="left", padx=10
        )

        categories = sorted(PAYLOADS.keys()) if isinstance(PAYLOADS, dict) else ["XSS"]
        if "XSS" not in categories:
            categories.insert(0, "XSS")

        cat_combo = ttk.Combobox(
            payload_frame,
            textvariable=self.payload_category_var,
            values=categories,
            width=18,
            state="readonly",
        )
        cat_combo.pack(side="left", padx=5)
        cat_combo.bind("<<ComboboxSelected>>", lambda e: self._rebuild_payload_buttons())

        # Генератор payload’ов (динамический)
        self.payload_buttons_frame = ttk.Frame(self)
        self.payload_buttons_frame.pack(pady=5, fill=tk.X)

        self._rebuild_payload_buttons()

        # Быстрые вставки
        extra_frame = ttk.Frame(self)
        extra_frame.pack(pady=5, fill=tk.X)

        ttk.Label(extra_frame, text="⚙️ Быстрые вставки:").pack(side="left", padx=10)
        quick_payloads = {
            "q=test": "https://gazprombank.ru/?search=",
            "window.name": "javascript:window.name='<img src=x onerror=alert(1)>'",
            "document.location": "javascript:document.location='javascript:alert(1)'",
            "simple XSS": "<script>alert(1)</script>",
            "img onerror": "<img src=x onerror=alert(1)>",
        }
        for label, value in quick_payloads.items():
            ttk.Button(
                extra_frame,
                text=label,
                command=lambda v=value: self.input_entry.insert(0, v),
            ).pack(side="left", padx=2)

        # Вывод
        self.output_box = tk.Text(
            self,
            height=25,
            wrap=tk.WORD,
            bg="black",
            fg="lime",
            insertbackground="white",
        )
        self.output_box.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        # Действия
        action_frame = ttk.Frame(self)
        action_frame.pack(pady=5)

        actions = [
            ("💾 Сохранить", self.save_to_file),
            ("📄 В PDF", self.export_pdf),
            ("📤 В JSON", self.export_json),
            ("🧹 Очистить лог", self.clear_log),
            ("📂 Загрузить лог", self.load_log),
            ("🧪 Фуззинг", self.run_fuzzing),
            ("🔁 Мутатор", self.run_mutator),
            ("🕸️ Краулер", self.run_crawler),
            ("📎 Атаковать точки", self.attack_found_targets),
            ("📎 Атаковать DOM-векторы", self.attack_dom_vectors),
            ("📤 Автоатака", self.run_auto_attack),
            ("📜 Анализ DOM", self.run_dom_analysis),
            ("⚠️ Проверка XSS-векторов", self.run_xss_vectors),
            ("🔗 Анализ ссылок", self.run_link_analysis),
            ("🎨 Анализ стилей", self.run_style_analysis),
            ("🖼️ Анализ медиа", self.run_media_analysis),
            ("🧩 Атрибуты Data/ARIA", self.run_attr_analysis),
            ("📝 Комментарии/NoScript", self.run_hidden_analysis),
            ("📊 Таблицы и SVG", self.run_struct_analysis),
        ]
        for label, cmd in actions:
            ttk.Button(action_frame, text=label, command=cmd).pack(
                side="left", padx=4
            )

    # ========================================================
    #  Динамическая генерация кнопок payload’ов
    # ========================================================

    def _rebuild_payload_buttons(self) -> None:
        for btn in self.payload_buttons:
            btn.destroy()
        self.payload_buttons.clear()

        for child in self.payload_buttons_frame.winfo_children():
            child.destroy()

        ttk.Label(self.payload_buttons_frame, text="Генератор Payload’ов:").pack(
            side="left", padx=10
        )

        category = self.payload_category_var.get()
        payload_map = PAYLOADS.get(category, {})

        if isinstance(payload_map, dict):
            types = list(payload_map.keys())
        elif isinstance(payload_map, list):
            types = payload_map
        else:
            types = []

        for typ in types:
            btn = ttk.Button(
                self.payload_buttons_frame,
                text=str(typ),
                command=lambda t=typ: self.insert_payload(str(t)),
            )
            btn.pack(side="left", padx=2)
            self.payload_buttons.append(btn)

    # ========================================================
    #  DOM / HTML вспомогательные
    # ========================================================

    def _get_dom_results(self) -> Optional[Dict[str, Any]]:
        html = self.log.strip()
        if not html:
            self.log_output(
                "⚠️ Нет HTML для анализа. Сначала запусти краулер или загрузи лог.",
                level="warn",
            )
            return None
        try:
            parser = DOMParser(html, threat_tab=self.threat_tab)
            return parser.extract_all()
        except Exception as e:
            self.log_output(f"❌ Ошибка DOMParser: {e}", level="error")
            return None

    def run_dom_analysis(self) -> None:
        results = self._get_dom_results()
        if results:
            self.log_output("📜 Полный DOM-анализ:")
            self.log_output(json.dumps(results, indent=2, ensure_ascii=False))
            self.send_to_threat_intel(
                "dom_analysis",
                {
                    "results": results,
                    "count": sum(
                        len(v) for v in results.values() if isinstance(v, list)
                    ),
                },
            )

    def run_xss_vectors(self) -> None:
        results = self._get_dom_results()
        if results:
            self.log_output("⚠️ Потенциальные XSS-векторы:")
            for ev in results.get("dom_events", []):
                self.log_output(f"{ev['tag']} {ev['event']} → {ev['risk_level']}")
            for js in results.get("inline_js", []):
                self.log_output(f"Inline JS: {js[:80]}...")
            for style in results.get("inline_styles", []):
                self.log_output(f"Inline style: {style['style']}")

    def run_link_analysis(self) -> None:
        results = self._get_dom_results()
        if results:
            self.log_output("🔗 Ссылки:")
            for link in results.get("links", []):
                self.log_output(f"{link['text']} → {link['href']}")
            base = results.get("base_tag", {})
            if base:
                self.log_output(f"Base href: {base.get('href')}")

    def run_style_analysis(self) -> None:
        results = self._get_dom_results()
        if results:
            self.log_output("🎨 Стили:")
            for style in results.get("styles", []):
                self.log_output(str(style))

    def run_media_analysis(self) -> None:
        results = self._get_dom_results()
        if results:
            self.log_output("🖼️ Медиа:")
            for media in results.get("media", []):
                self.log_output(str(media))

    def run_attr_analysis(self) -> None:
        results = self._get_dom_results()
        if results:
            self.log_output("🧩 Data/ARIA атрибуты:")
            for attr in results.get("data_attributes", []):
                self.log_output(str(attr))
            for attr in results.get("aria_attributes", []):
                self.log_output(str(attr))

    def run_hidden_analysis(self) -> None:
        results = self._get_dom_results()
        if results:
            self.log_output("📝 Комментарии и NoScript:")
            for c in results.get("comments", []):
                self.log_output(f"Комментарий: {c}")
            for ns in results.get("noscript", []):
                self.log_output(f"NoScript: {ns}")

    def run_struct_analysis(self) -> None:
        results = self._get_dom_results()
        if results:
            self.log_output("📊 Таблицы и SVG:")
            for table in results.get("tables", []):
                self.log_output(f"Таблица: {table}")
            for svg in results.get("svg", []):
                self.log_output(f"SVG: {svg['svg'][:100]}...")

    # ========================================================
    #  Атаки по найденным целям
    # ========================================================

    def attack_found_targets(self) -> None:
        if not self.crawled_scripts:
            messagebox.showinfo("Нет целей", "Сначала проведи краулинг.")
            return

        if getattr(self, "_crawler_running", False):
            self.log_output("⏳ Краулер ещё работает, подожди завершения.", level="warn")
            return

        self.update_status("⚔️ Запуск атаки по найденным точкам...")

        def worker() -> None:
            try:
                self.attack_engine.domain = self.crawled_domain
                self.attack_engine.attack_found_targets(self.crawled_scripts)
                self.after(
                    0, lambda: self.update_status("✔️ Атака по найденным точкам завершена.")
                )
            except Exception as e:
                self.after(
                    0,
                    lambda: self.log_output(
                        f"❌ Ошибка атаки по найденным точкам: {e}", level="error"
                    ),
                )
                self.after(
                    0, lambda: self.update_status("⚠️ Ошибка при атаке по точкам.")
                )

        threading.Thread(
            target=worker, daemon=True, name="AttackFoundTargets"
        ).start()

    def attack_dom_vectors(self) -> None:
        if not self.crawled_scripts:
            messagebox.showinfo("Нет данных", "Сначала проведи краулинг.")
            return

        if self._dom_attack_running:
            self.log_output("⚠️ DOM-атака уже выполняется.", level="warn")
            return

        if getattr(self, "_crawler_running", False):
            self.log_output("⏳ Краулер ещё работает, подожди завершения.", level="warn")
            return

        self._dom_attack_running = True
        self.update_status("⚔️ Запуск атаки по DOM-векторам...")
        self.log_output("⚔️ DOM-вектора: запуск анализа...")

        def worker() -> None:
            start_ts = time.time()
            try:
                self.attack_engine.domain = self.crawled_domain
                self.attack_engine.attack_dom_vectors(self.crawled_scripts)
                duration = round(time.time() - start_ts, 2)

                def finish_ok() -> None:
                    self.update_status("✔️ DOM-атака завершена.")
                    self.log_output(f"✔️ DOM-атака завершена за {duration} сек.")
                    self._dom_attack_running = False

                self.after(0, finish_ok)

            except Exception as e:
                def finish_err() -> None:
                    self.log_output(f"❌ Ошибка DOM-атаки: {e}", level="error")
                    self.update_status("⚠️ Ошибка при DOM-атаке.")
                    self._dom_attack_running = False

                self.after(0, finish_err)

        threading.Thread(
            target=worker, daemon=True, name="DOMAttackThread"
        ).start()

    def run_auto_attack(self) -> None:
        target = self.input_entry.get().strip() or self.crawled_domain
        crawl_json = getattr(self, "full_data", {})
        sandbox_info: Dict[str, Any] = {}

        if not target:
            self.log_output("⚠️ Нет цели для автоатаки.", level="warn")
            return

        self.update_status("⚔️ Автоатака...")

        def worker() -> None:
            try:
                self.attack_engine.domain = target
                self.attack_engine.run_auto_attack(crawl_json, sandbox_info)
                self.after(0, lambda: self.update_status("✔️ Автоатака завершена."))
            except Exception as e:
                self.after(
                    0,
                    lambda: self.log_output(f"❌ Ошибка автоатаки: {e}", level="error"),
                )
                self.after(
                    0, lambda: self.update_status("⚠️ Ошибка автоатаки.")
                )

        threading.Thread(target=worker, daemon=True, name="AutoAttack").start()

    def export_attack_results(self) -> None:
        try:
            self.attack_engine.export_results("logs/attack_results.json")
            self.log_output("💾 Результаты атак сохранены в logs/attack_results.json")
        except Exception as e:
            self.log_output(f"❌ Ошибка экспорта результатов: {e}", level="error")

    # ========================================================
    #  Логирование / статус
    # ========================================================

    def log_output(self, text: str, level: str = "info") -> None:
        prefix = {"info": "ℹ️", "warn": "⚠️", "error": "❌"}.get(level, "")
        timestamp = time.strftime("%H:%M:%S")
        line = f"[{timestamp}] {prefix} {text}\n"

        self.output_box.insert("end", line)
        self.output_box.see("end")

        try:
            total_lines = int(self.output_box.index("end-1c").split(".")[0])
            if total_lines > 2000:
                self.output_box.delete("1.0", "200.0")
        except Exception:
            pass

        self.log += line

    def update_status(self, msg: str) -> None:
        if self.status_var is not None:
            self.status_var.set(msg)

    def clear_log(self) -> None:
        self.output_box.delete("1.0", tk.END)
        self.log = ""
        self.log_output("🧹 Лог очищен.", level="info")

    # ========================================================
    #  Очередь от краулера
    # ========================================================

    def process_queue(self) -> None:
        try:
            while not self.data_queue.empty():
                item = self.data_queue.get_nowait()

                if isinstance(item, tuple) and len(item) == 2:
                    task_id, data = item
                else:
                    task_id, data = None, item

                if task_id == "crawler":
                    try:
                        self.update_from_crawler(data)
                    except Exception as e:
                        self.log_output(
                            f"Ошибка update_from_crawler: {e}", level="error"
                        )

                self.data_queue.task_done()

        except Exception as e:
            self.log_output(f"Ошибка обработки очереди: {e}", level="error")

        self.after(100, self.process_queue)

    def update_from_crawler(self, data: Dict[str, Any]) -> None:
        url = data.get("url", "")
        forms = data.get("forms_count", len(data.get("forms", [])))
        scripts = len(data.get("scripts", []))
        api_eps = data.get("api_endpoints", [])
        events = data.get("events", [])
        error = data.get("error")

        sensitive = 0
        for key in ("tokens", "api_keys", "cookies", "headers"):
            val = data.get(key)
            if isinstance(val, dict):
                sensitive += val.get("count", 0)
            elif isinstance(val, list):
                sensitive += len(val)

        self.log_output(f"🔗 URL: {url}")
        self.log_output(f"   📝 Forms: {forms}")
        self.log_output(f"   📦 Scripts: {scripts}")
        self.log_output(f"   🔌 API endpoints: {len(api_eps)}")
        self.log_output(f"   ⚡ Events: {len(events)}")
        self.log_output(f"   🔐 Sensitive: {sensitive}")

        if error:
            self.log_output(f"   ❌ Error: {error}", level="error")

        self.log_output("────────────────────────────────────────")

        severity = "low"
        if sensitive > 5 or not data.get("CSP"):
            severity = "high"

        self.send_to_threat_intel(
            "crawler_page",
            {
                "url": url,
                "forms": forms,
                "scripts": scripts,
                "api_endpoints": len(api_eps),
                "events": len(events),
                "sensitive": sensitive,
                "error": error,
                "severity": severity,
            },
        )

    # ========================================================
    #  Краулер
    # ========================================================

    def run_crawler(self) -> None:
        domain = self.input_entry.get().strip()
        if not domain:
            self.log_output("⚠️ Укажите домен или URL для краулинга.", level="warn")
            return

        if self._crawler_running:
            self.log_output("⚠️ Краулер уже выполняется.", level="warn")
            return

        self._crawler_running = True
        self.update_status("🕸️ Краулинг начался...")
        self.log_output(f"🕸️ Начат краулинг: {domain}")

        def gui_callback(payload: Dict[str, Any]) -> None:
            self.data_queue.put(("crawler", payload))

        def worker() -> None:
            result: Optional[Dict[str, Any]] = None
            try:
                result = crawl_site(
                    domain,
                    depth=0,
                    gui_callback=gui_callback,
                    parallel=True,
                )

                if not isinstance(result, dict):
                    self.after(
                        0,
                        lambda: self.log_output(
                            "❌ Краулер вернул неожиданный формат данных.",
                            level="error",
                        ),
                    )
                    return

                save_outputs(result)

                self.crawled_scripts = result.get("scripts", [])
                self.crawled_domain = domain
                self.full_data = result

            except KeyboardInterrupt:
                self.after(
                    0,
                    lambda: self.log_output(
                        "⏹ Краулинг прерван пользователем.", level="warn"
                    ),
                )
                self.after(0, lambda: self.update_status("⚠️ Прервано."))
                return

            except requests.Timeout:
                self.after(
                    0,
                    lambda: self.log_output(
                        "❌ Таймаут краулера", level="error"
                    ),
                )
                self.after(
                    0,
                    lambda: self.update_status("⚠️ Ошибка при краулинге."),
                )
                return

            except Exception as e:
                self.after(
                    0,
                    lambda: self.log_output(
                        f"❌ Ошибка краулера: {e}", level="error"
                    ),
                )
                self.after(
                    0,
                    lambda: self.update_status("⚠️ Ошибка при краулинге."),
                )
                return

            finally:
                self._crawler_running = False

            if result is None:
                return

            summary = {
                "domain": domain,
                "pages": len(result.get("pages", [])),
                "forms": len(result.get("forms", [])),
                "links": len(result.get("links", [])),
                "scripts": len(result.get("scripts", [])),
                "events": len(result.get("events", [])),
                "sensitive": result.get("sensitive_count", 0),
            }
            self.send_to_threat_intel("crawler_summary", summary)
            self.after(0, lambda: self.update_status("✔️ Краулинг завершён."))

        threading.Thread(target=worker, daemon=True, name="CrawlerThread").start()

    # ========================================================
    #  Вставка payload'ов
    # ========================================================

    def insert_payload(self, typ: str) -> None:
        category = self.payload_category_var.get()
        payload_map = PAYLOADS.get(category, {})

        if isinstance(payload_map, dict):
            payload = payload_map.get(typ, "")
        elif isinstance(payload_map, list):
            payload = typ if typ in payload_map else ""
        else:
            payload = ""

        self.input_entry.delete(0, tk.END)
        self.input_entry.insert(0, payload)

    # ========================================================
    #  XSStrike
    # ========================================================

    def scan(self) -> None:
        url = self.input_entry.get().strip()
        if not url:
            messagebox.showinfo("Пусто", "Введите URL или Payload.")
            return

        self.update_status("⏳ Запуск XSStrike...")
        self.output_box.delete("1.0", tk.END)
        self.log = ""

        def worker() -> None:
            try:
                xsstrike_path = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    "XSStrike",
                    "xsstrike.py",
                )

                if not os.path.exists(xsstrike_path):
                    raise FileNotFoundError(f"XSStrike не найден: {xsstrike_path}")

                result = subprocess.run(
                    [sys.executable, xsstrike_path, "-u", url],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    encoding="utf-8",
                    errors="replace",
                )

                output = result.stdout or result.stderr or ""
                selected = self.filter_var.get()

                if selected != "All":
                    output = "\n".join(
                        line
                        for line in output.splitlines()
                        if selected.lower() in line.lower()
                    )

                def update_gui() -> None:
                    self.log_output(output)
                    self.log = output

                    alerts = [
                        line
                        for line in output.splitlines()
                        if any(
                            x in line.lower()
                            for x in ["<script", "alert(", "stored xss", "reflected"]
                        )
                    ]

                    if alerts:
                        os.makedirs("logs", exist_ok=True)
                        with open(
                            LOG_SUCCESS_PATH, "a", encoding="utf-8"
                        ) as log_file:
                            log_file.write(
                                f"\n--- XSStrike Report ---\nURL: {url}\n{output}\n"
                            )

                    self.send_to_threat_intel(
                        "xsstrike",
                        {
                            "url": url,
                            "alerts": alerts,
                            "filter": selected,
                            "raw_output": output,
                            "count": len(alerts),
                        },
                    )

                    self.update_status("✔️ XSStrike завершён")

                self.after(0, update_gui)

            except subprocess.TimeoutExpired:
                self.after(
                    0,
                    lambda: self.log_output(
                        "❌ XSStrike превысил таймаут", level="error"
                    ),
                )
                self.after(
                    0, lambda: self.update_status("⚠️ XSStrike завис")
                )

            except FileNotFoundError as e:
                self.after(
                    0, lambda: self.log_output(f"❌ {e}", level="error")
                )
                self.after(
                    0, lambda: self.update_status("❌ XSStrike не найден")
                )

            except Exception as e:
                self.after(
                    0,
                    lambda: self.log_output(
                        f"❌ Ошибка XSStrike:\n{e}", level="error"
                    ),
                )
                self.after(
                    0, lambda: self.update_status("❌ Ошибка при анализе")
                )

        threading.Thread(target=worker, daemon=True, name="XSStrikeThread").start()

    # ========================================================
    #  Сохранение / загрузка / PDF / JSON
    # ========================================================

    def save_to_file(self) -> None:
        if not self.log.strip():
            messagebox.showinfo("Нет данных", "Сначала проанализируй!")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.log)

            messagebox.showinfo("Готово", f"Сохранено:\n{path}")

            self.send_to_threat_intel(
                "export_log",
                {
                    "path": path,
                    "size": len(self.log),
                    "lines": len(self.log.splitlines()),
                },
            )

        except Exception as e:
            messagebox.showerror("Ошибка сохранения", str(e))
            self.log_output(f"❌ Ошибка сохранения файла: {e}", level="error")

    def export_pdf(self) -> None:
        if not self.log.strip():
            messagebox.showinfo("Нет данных", "Сначала проанализируй!")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=10)
            pdf.add_page()
            pdf.set_font("Courier", size=10)

            for line in self.log.splitlines():
                safe_line = line[:MAX_REPORT_LINE_LENGTH]
                try:
                    pdf.multi_cell(0, 5, txt=safe_line)
                except Exception:
                    pdf.multi_cell(
                        0,
                        5,
                        txt=safe_line.encode("latin-1", "replace").decode("latin-1"),
                    )

            pdf.output(path)

            messagebox.showinfo("PDF создан", f"Файл:\n{path}")

            self.send_to_threat_intel(
                "export_pdf",
                {
                    "path": path,
                    "lines": len(self.log.splitlines()),
                },
            )

        except Exception as e:
            messagebox.showerror("Ошибка PDF", str(e))
            self.log_output(f"❌ Ошибка PDF-экспорта: {e}", level="error")

    def export_json(self) -> None:
        if not self.log.strip():
            messagebox.showinfo("Нет данных", "Сначала проанализируй!")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            lines = [l for l in self.log.splitlines() if l.strip()]
            data = {"lines": lines, "count": len(lines), "timestamp": time.time()}

            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            messagebox.showinfo("JSON создан", f"Файл:\n{path}")

            self.send_to_threat_intel(
                "export_json",
                {
                    "path": path,
                    "count": len(lines),
                },
            )

        except Exception as e:
            messagebox.showerror("Ошибка JSON", str(e))
            self.log_output(f"❌ Ошибка JSON-экспорта: {e}", level="error")

    def load_log(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("Log files", "*.txt *.log"), ("All files", "*.*")]
        )
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = f.read()

            self.output_box.delete("1.0", tk.END)
            self.log = ""
            self.log_output(data)

            self.send_to_threat_intel(
                "load_log",
                {
                    "path": path,
                    "size": len(data),
                    "lines": len(data.splitlines()),
                },
            )

        except Exception as e:
            messagebox.showerror("Ошибка загрузки", str(e))
            self.log_output(f"❌ Ошибка загрузки лога: {e}", level="error")

    def _log_result(self, text: str) -> None:
        try:
            self.log_output(text)
            os.makedirs("logs", exist_ok=True)
            with open("logs/auto_attack.log", "a", encoding="utf-8") as f:
                f.write(text + "\n")
        except Exception as e:
            self.log_output(
                f"❌ Ошибка записи в auto_attack.log: {e}", level="error"
            )

    # ========================================================
    #  Фуззинг / Мутатор
    # ========================================================

    def run_fuzzing(self) -> None:
        url = self.input_entry.get().strip()
        if not url:
            self.log_output("⚠️ Введите URL для фуззинга.", level="warn")
            return

        self.update_status("🔬 Запуск параметрического фуззинга...")
        self.output_box.delete("1.0", tk.END)
        self.log = ""

        def worker() -> None:
            try:
                results = fuzz_url_params(url)
                findings = [
                    {"param": key, "payload": payload, "url": test_url}
                    for key, payload, test_url in results
                ]

                def update_gui() -> None:
                    for f in findings:
                        self.log_output(
                            f"✔️ XSS в параметре {f['param']} → {f['url']}"
                        )
                    self.send_to_threat_intel(
                        "param_fuzzer",
                        {
                            "target": url,
                            "findings": findings,
                            "count": len(findings),
                            "severity": "high" if findings else "none",
                        },
                    )
                    self.update_status("✔️ Фуззинг завершён.")

                self.after(0, update_gui)

            except Exception as e:
                self.after(
                    0,
                    lambda: self.log_output(
                        f"❌ Ошибка фуззинга: {e}", level="error"
                    ),
                )
                self.after(
                    0, lambda: self.update_status("⚠️ Ошибка при фуззинге.")
                )

        threading.Thread(target=worker, daemon=True, name="FuzzingThread").start()

    def run_mutator(self) -> None:
        base = self.input_entry.get().strip()
        if not base:
            self.log_output("⚠️ Сначала введите базовый payload.", level="warn")
            return

        self.update_status("🔁 Генерация мутаций...")
        self.output_box.delete("1.0", tk.END)
        self.log = ""

        def worker() -> None:
            try:
                variants = set(mutate_payload(base))

                def update_gui() -> None:
                    for v in variants:
                        self.log_output(f"🔁 {v}")
                    self.send_to_threat_intel(
                        "mutator",
                        {
                            "base": base,
                            "variants": list(variants),
                            "count": len(variants),
                        },
                    )
                    self.update_status("✔️ Мутации завершены.")

                self.after(0, update_gui)

            except Exception as e:
                self.after(
                    0,
                    lambda: self.log_output(
                        f"❌ Ошибка мутаций: {e}", level="error"
                    ),
                )
                self.after(
                    0, lambda: self.update_status("⚠️ Ошибка при мутациях.")
                )

        threading.Thread(target=worker, daemon=True, name="MutatorThread").start()