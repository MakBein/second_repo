# xss_security_gui/deep_analysis_tab.py
# ============================================================
#  Deep Analysis Tab — ULTRA 6.0, интеграция с settings.py
# ============================================================

import json
import os
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import requests

from deep_crawler import deep_crawl_site
from utils.threat_sender import ThreatSenderMixin
from xss_security_gui import settings
from xss_security_gui.network_checker import NetworkChecker

class DeepAnalysisTab(ttk.Frame, ThreatSenderMixin):
    def __init__(self, parent, json_path=None, threat_tab=None):
        super().__init__(parent)
        # Централизованный путь
        self.json_path = json_path or str(settings.JSON_CRAWL_EXPORT_PATH)
        self.analysis_results = []
        self.full_data = []          # список страниц из results["details"]
        self.threat_tab = threat_tab
        self.sort_column = None
        self.sort_reverse = False

        self._deep_crawl_running = False
        self._attack_plan_running = False

        self.build_ui()

    # ============================================================
    #  UI
    # ============================================================

    def build_ui(self):
        top_frame = ttk.Frame(self)
        top_frame.pack(pady=5, fill="x")

        ttk.Button(top_frame, text="🔄 Запустить анализ", command=self.run_deep_crawl).pack(side="left", padx=5)
        ttk.Label(top_frame, text="Фильтр по CMS:").pack(side="left", padx=5)

        self.cms_filter = ttk.Combobox(top_frame, values=["Все"], state="readonly", width=20)
        self.cms_filter.current(0)
        self.cms_filter.pack(side="left")
        self.cms_filter.bind("<<ComboboxSelected>>", self.apply_filter)

        ttk.Button(top_frame, text="📄 Экспорт в TXT", command=self.export_to_txt).pack(side="right", padx=10)
        ttk.Button(self, text="📂 Открыть JSON", command=self.select_json_file).pack(side="right", padx=10)

        # Таблица
        self.tree = ttk.Treeview(
            self,
            columns=("url", "cms", "adaptive", "frameworks", "apis", "tokens", "graphql", "score", "flags"),
            show="headings",
            height=20
        )
        self.tree.pack(fill="both", expand=True, padx=10)

        headings = {
            "url": 300, "cms": 80, "adaptive": 70, "frameworks": 140,
            "apis": 60, "tokens": 70, "graphql": 80, "score": 60, "flags": 80
        }
        for col, width in headings.items():
            self.tree.heading(col, text=col.upper(), command=lambda c=col: self.sort_by_column(c))
            self.tree.column(col, width=width, anchor="w")

        self.tree.tag_configure("warn", background="#330000", foreground="yellow")
        self.tree.tag_configure("risk", background="#3b0000", foreground="red")
        self.tree.tag_configure("safe", background="#002b00", foreground="lightgreen")
        self.tree.bind("<<TreeviewSelect>>", self.show_details)

        # Детали
        self.detail_box = tk.Text(self, height=10, bg="#1e1e1e", fg="lime", wrap="word")
        self.detail_box.pack(fill="both", expand=True, padx=10, pady=5)

        # Attack plan
        ttk.Button(self, text="▶️ Запустить план атак", command=self.launch_attack_plan).pack(pady=5)

        self.attack_output = tk.Text(self, height=12, bg="#1a1a1a", fg="orange", wrap="word")
        self.attack_output.pack(fill="both", expand=True, padx=10, pady=5)
        ttk.Button(self, text="📤 Экспорт логов атак", command=self.export_attack_logs).pack(pady=5)

        # --- Блок сетевых проверок ---
        net_frame = ttk.Frame(self)
        net_frame.pack(pady=5, fill="x")

        ttk.Label(net_frame, text="🌐 Сетевые проверки:").pack(side="left", padx=5)
        ttk.Button(net_frame, text="ICMP", command=self.run_icmp).pack(side="left", padx=5)
        ttk.Button(net_frame, text="HTTP", command=self.run_http).pack(side="left", padx=5)
        ttk.Button(net_frame, text="TLS", command=self.run_tls).pack(side="left", padx=5)
        ttk.Button(net_frame, text="Port 443", command=self.run_port443).pack(side="left", padx=5)
        ttk.Button(net_frame, text="Все проверки", command=self.run_all_network_checks).pack(side="left", padx=5)

        self.network_output = tk.Text(self, height=10, bg="#0f0f0f", fg="cyan", wrap="word")
        self.network_output.pack(fill="both", expand=True, padx=10, pady=5)

        self.load_data()

    # ============================================================
    #  LOAD DATA
    # ============================================================

    def load_data(self):
        if not os.path.exists(self.json_path):
            self.full_data = []
            self.tree.insert(
                "",
                "end",
                values=("❌ Файл deep_crawl.json не найден", "", "", "", "", "", "", "", "")
            )
            return

        try:
            with open(self.json_path, encoding="utf-8") as f:
                data = json.load(f)
            self.full_data = data.get("details", [])
        except Exception as e:
            messagebox.showerror("Ошибка загрузки JSON", f"{e}")
            self.full_data = []

        cms_set = {s["cms"] for s in self.full_data if isinstance(s.get("cms"), str)}
        self.cms_filter["values"] = ["Все"] + sorted(list(cms_set))
        self.cms_filter.current(0)

        self.populate_table(self.full_data)

    # ============================================================
    #  NETWORK CHECKS ULTRA 6.1
    # ============================================================

    def _get_domain_for_check(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Нет выбора", "Выберите сайт в таблице для проверки.")
            return None
        item = self.tree.item(selected[0])
        return item["values"][0]

    def run_icmp(self):
        domain = self._get_domain_for_check()
        if domain:
            NetworkChecker(domain, self.network_output).check_icmp()

    def run_http(self):
        domain = self._get_domain_for_check()
        if domain:
            NetworkChecker(domain, self.network_output).check_http()

    def run_tls(self):
        domain = self._get_domain_for_check()
        if domain:
            NetworkChecker(domain, self.network_output).check_tls()

    def run_port443(self):
        domain = self._get_domain_for_check()
        if domain:
            NetworkChecker(domain, self.network_output).check_ports()

    def run_all_network_checks(self):
        domain = self._get_domain_for_check()
        if domain:
            NetworkChecker(domain, self.network_output).run_all_checks()

    # ============================================================
    #  TABLE / FILTER
    # ============================================================

    def export_to_txt(self):
        try:
            os.makedirs(settings.LOG_DIR, exist_ok=True)
            export_path = settings.LOG_DIR / "deep_analysis_export.txt"
            with open(export_path, "w", encoding="utf-8") as f:
                for item in self.analysis_results:
                    f.write(str(item) + "\n")
            print(f"[DeepAnalysis] Экспорт в TXT завершён: {export_path}")
        except Exception as e:
            print(f"[DeepAnalysis] Ошибка экспорта: {e}")

    def apply_filter(self, event=None):
        selected = self.cms_filter.get()
        if selected == "Все":
            filtered = self.full_data
        else:
            filtered = [s for s in self.full_data if s.get("cms") == selected]
        self.populate_table(filtered)

    def _format_frameworks(self, frameworks):
        if isinstance(frameworks, list):
            return ", ".join(str(x) for x in frameworks)
        if isinstance(frameworks, str):
            return frameworks
        return ""

    def populate_table(self, data):
        self.tree.delete(*self.tree.get_children())
        summary = []
        self.analysis_results = []

        for site in data:
            if not isinstance(site, dict):
                continue

            score = site.get("content_score") or 0
            headers = site.get("headers") or {}

            tags = ()
            if headers.get("unsafe_inline") and score > 3:
                tags = ("risk",)
            elif not headers.get("CSP") and site.get("tokens"):
                tags = ("warn",)
            elif score == 0:
                tags = ("safe",)

            flags = []
            if site.get("tokens"):
                flags.append(f"T:{len(site.get('tokens', []))}")
            if site.get("graphql"):
                flags.append(f"G:{len(site.get('graphql', []))}")
            if site.get("xss_reflected"):
                flags.append("🧨")
            if site.get("debug_flags"):
                flags.append("🐞")
            flags_str = " ".join(flags)

            row = (
                site.get("url", "—"),
                site.get("cms", "—"),
                "✅" if site.get("adaptive") else "✘",
                self._format_frameworks(site.get("frameworks")),
                len(site.get("api_endpoints", []) or []),
                len(site.get("tokens", []) or []),
                len(site.get("graphql", []) or []),
                score,
                flags_str
            )

            self.tree.insert("", "end", values=row, tags=tags)
            summary.append(row)
            self.analysis_results.append(site)

        self.send_to_threat_intel("deep_analysis", [
            {"url": row[0], "cms": row[1], "score": row[7], "flags": row[8]}
            for row in summary
        ])

    def sort_by_column(self, col):
        data = self.tree.get_children()
        if not data:
            return

        self.sort_reverse = not self.sort_reverse if self.sort_column == col else False
        self.sort_column = col

        rows = [(self.tree.set(k, col), k) for k in data]

        def try_float(val):
            try:
                return float(val)
            except ValueError:
                return val

        try:
            rows.sort(key=lambda t: try_float(t[0]), reverse=self.sort_reverse)
        except Exception:
            rows.sort(key=lambda t: t[0], reverse=self.sort_reverse)

        for index, (_, k) in enumerate(rows):
            self.tree.move(k, '', index)

    # ============================================================
    #  DETAILS
    # ============================================================

    def show_details(self, event):
        selected = self.tree.selection()
        if not selected:
            return

        item = self.tree.item(selected[0])
        url = item["values"][0]

        site = next((s for s in self.full_data if s.get("url") == url), None)
        if not site:
            return

        self.detail_box.delete("1.0", "end")
        self.detail_box.insert("end", f"🌍 URL: {site.get('url')}\n")
        self.detail_box.insert("end", f"CMS: {site.get('cms')}\n")
        self.detail_box.insert("end", f"Score: {site.get('content_score')}\n")
        self.detail_box.insert("end", f"Frameworks: {self._format_frameworks(site.get('frameworks'))}\n")
        self.detail_box.insert("end", f"API endpoints: {len(site.get('api_endpoints', []) or [])}\n")
        self.detail_box.insert("end", f"Tokens: {len(site.get('tokens', []) or [])}\n")
        self.detail_box.insert("end", f"GraphQL: {len(site.get('graphql', []) or [])}\n")
        self.detail_box.insert("end", f"Server: {site.get('server')}\n")
        self.detail_box.insert("end", f"Backend: {site.get('backend_framework')}\n")
        self.detail_box.insert("end", f"CSP: {site.get('csp_analysis')}\n")

    # ============================================================
    #  DEEP CRAWL
    # ============================================================

    def run_deep_crawl(self):
        url = self.ask_target_url()
        if not url:
            return

        if self._deep_crawl_running:
            self.detail_box.insert("end", "⚠️ Deep Crawl уже выполняется.\n")
            return

        self._deep_crawl_running = True
        self.detail_box.delete("1.0", "end")
        self.detail_box.insert("end", f"🔄 Запуск анализа по: {url}\n")

        def worker():
            start_ts = time.time()
            try:
                results = deep_crawl_site(url)

                os.makedirs(settings.LOG_DIR, exist_ok=True)
                with open(self.json_path, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)

                duration = round(time.time() - start_ts, 2)

                def finish_ok():
                    self.detail_box.insert("end", "✅ Анализ завершён. Загружаю результаты...\n")
                    self.detail_box.insert("end", f"⏱ Время выполнения: {duration} сек.\n")
                    self.full_data = results.get("details", [])
                    self.populate_table(self.full_data)
                    self._deep_crawl_running = False

                self.after(0, finish_ok)

            except Exception as e:
                def finish_err():
                    self.detail_box.insert("end", f"❌ Ошибка Deep Crawl: {e}\n")
                    self._deep_crawl_running = False
                self.after(0, finish_err)

        threading.Thread(target=worker, daemon=True).start()

    def ask_target_url(self):
        popup = tk.Toplevel(self)
        popup.title("Цель для анализа")
        tk.Label(popup, text="Введите URL:").pack(padx=10, pady=5)

        entry = tk.Entry(popup, width=50)
        entry.pack(padx=10, pady=5)
        entry.focus()

        result = {"url": None}

        def submit():
            result["url"] = entry.get().strip()
            popup.destroy()

        ttk.Button(popup, text="Запустить", command=submit).pack(pady=10)
        self.wait_window(popup)
        return result["url"]

    # ============================================================
    #  ATTACK PLAN
    # ============================================================

    def launch_attack_plan(self):
        if self._attack_plan_running:
            self.attack_output.insert("end", "⚠️ План атак уже выполняется.\n")
            return

        self._attack_plan_running = True
        self.attack_output.insert("end", "🚀 Запуск attack_plan...\n")

        def worker():
            attack_summary = []
            try:
                plan_path = settings.LOG_DIR / "attack_plan.json"
                try:
                    with open(plan_path, encoding="utf-8") as f:
                        plan = json.load(f)
                except Exception as e:
                    def err_load():
                        self.attack_output.insert("end", f"❌ Ошибка загрузки attack_plan: {e}\n")
                        self._attack_plan_running = False
                    self.after(0, err_load)
                    return

                targets = plan.get("targets", []) or []
                token_tests = plan.get("token_tests", []) or []
                plan_settings = plan.get("settings", {}) or {}
                delay = plan_settings.get("delay", settings.settings.get("crawl.delay", 1.0))

                for t in targets:
                    if not isinstance(t, dict):
                        continue
                    url = t.get("url")
                    method = (t.get("method") or "GET").upper()
                    headers = t.get("headers") or {}
                    vector = t.get("vector") or "Param"
                    param = t.get("param")
                    inputs = t.get("inputs") or []
                    payloads = t.get("payloads") or []

                    if not url or not payloads:
                        line = f"⚠️ Пропуск цели без url/payloads: {t}"
                        attack_summary.append(line)
                        self.after(0, lambda l=line: self.attack_output.insert("end", l + "\n"))
                        continue

                    for p in payloads:
                        try:
                            start = time.time()
                            if vector.lower() == "form" and inputs:
                                data = {i: p for i in inputs}
                                r = requests.request(method, url, data=data, headers=headers, timeout=10)
                            elif param:
                                r = requests.request(method, url, params={param: p}, headers=headers, timeout=10)
                            else:
                                r = requests.request(method, url, headers=headers, timeout=10)

                            elapsed = (time.time() - start) * 1000.0
                            status = r.status_code
                            text_sample = r.text[:20000] if isinstance(r.text, str) else ""
                            reflected = p in text_sample

                            hit = "✅ HIT" if status in (200, 201, 302) and reflected else "❌ MISS"
                            line = f"{hit} [{status}] {elapsed:.0f}ms → {url} ← {p}"
                            attack_summary.append(line)
                            self.after(0, lambda l=line: self.attack_output.insert("end", l + "\n"))

                            self.send_to_threat_intel("attack_request", [{
                                "url": url, "method": method, "payload": p,
                                "status": status, "reflected": reflected,
                                "elapsed_ms": elapsed
                            }])

                        except Exception as ex:
                            line = f"💥 Ошибка на {url}: {ex}"
                            attack_summary.append(line)
                            self.after(0, lambda l=line: self.attack_output.insert("end", l + "\n"))

                        time.sleep(delay)

                # --- Token tests ---
                for test in token_tests:
                    if not isinstance(test, dict):
                        continue
                    url = test.get("url") or "https://example.com/api/protected"
                    hname = test.get("header")
                    tpl = test.get("value_template")
                    candidates = test.get("candidates") or []

                    if not hname or not tpl or not candidates:
                        line = f"⚠️ Пропуск token_test без header/value_template/candidates: {test}"
                        attack_summary.append(line)
                        self.after(0, lambda l=line: self.attack_output.insert("end", l + "\n"))
                        continue

                    for token in candidates:
                        h = {hname: tpl.replace("{token}", token)}
                        try:
                            start = time.time()
                            r = requests.get(url, headers=h, timeout=10)
                            elapsed = (time.time() - start) * 1000.0

                            if r.status_code in (200, 201):
                                line = f"🔓 VALID TOKEN [{r.status_code}] {elapsed:.0f}ms: {token}"
                                severity = "high"
                                valid = True
                            else:
                                line = f"🔐 Invalid token [{r.status_code}] {elapsed:.0f}ms: {token}"
                                severity = "low"
                                valid = False

                            attack_summary.append(line)
                            self.after(0, lambda l=line: self.attack_output.insert("end", l + "\n"))

                            self.send_to_threat_intel("attack_token_test", [{
                                "url": url, "header": hname, "token": token,
                                "status": r.status_code, "valid": valid,
                                "elapsed_ms": elapsed, "severity": severity
                            }])

                        except Exception as err:
                            line = f"⚠️ Ошибка токена {token}: {err}"
                            attack_summary.append(line)
                            self.after(0, lambda l=line: self.attack_output.insert("end", l + "\n"))

                        time.sleep(delay)

                self.send_to_threat_intel("attack_plan", [{"result": line} for line in attack_summary])

                def finish_ok():
                    self.attack_output.insert("end", "✔️ План атак завершён.\n")
                    self._attack_plan_running = False

                self.after(0, finish_ok)

            except Exception as e:
                def finish_err():
                    self.attack_output.insert("end", f"❌ Ошибка выполнения attack_plan: {e}\n")
                    self._attack_plan_running = False

                self.after(0, finish_err)

        threading.Thread(target=worker, daemon=True).start()

    # ============================================================

    # =========================
    #       EXPORT LOGS
    # =========================

    def select_json_file(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if path:
            self.json_path = path
            self.load_data()

    def export_attack_logs(self):
        if not hasattr(self, "attack_output"):
            messagebox.showerror("Ошибка", "Поле attack_output ещё не создано.")
            return

        logs = self.attack_output.get("1.0", "end").strip()
        if not logs:
            messagebox.showinfo("Экспорт", "Лог атак пуст.")
            return

        try:
            os.makedirs(settings.LOG_DIR, exist_ok=True)
            export_path = settings.LOG_DIR / "attack_logs.md"
            with open(export_path, "w", encoding="utf-8") as f:
                f.write("# 🧨 XSS Attack Logs\n\n")
                for line in logs.splitlines():
                    f.write(f"- {line}\n")

            messagebox.showinfo("Экспорт завершён", f"Файл {export_path} создан.")
        except Exception as e:
            messagebox.showerror("Ошибка экспорта", f"{e}")
