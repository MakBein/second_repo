# xss_security_gui/main.py
"""
main.py — точка входа XSS Security Suite 6.0
Автор: Aleksandr + Copilot
"""
import sys
import shutil
import threading
import datetime
import json
import logging
import tkinter as tk
from tkinter import ttk
from typing import Optional

from XSStrike.core.fuzzer import fuzzer
from XSStrike.core.config import xsschecker

# ============================================================
#  Централизованная конфигурация (ULTRA Hybrid)
# ============================================================
from xss_security_gui.settings import (
    SETTINGS_JSON_PATH,
    GUI_STATE_PATH,
    settings,
    BASE_DIR,
    LOG_DIR,
    crawler_results_path,
    LOG_SUCCESS_PATH,
    ENABLE_AUTO_TRAPS,
    PAYLOADS_DIR,
)
from xss_security_gui.settings import (
    XSS_PAYLOAD_FILE,
    SQLI_PAYLOAD_FILE,
    CSRF_PAYLOAD_FILE,
    SSRF_PAYLOAD_FILE,
)

CRAWLER_RESULTS_PATH = crawler_results_path()
_logger = logging.getLogger(__name__)

# ============================================================
#  Импорты функциональных модулей
# ============================================================
from xss_security_gui.tabs.ai_verdict_tab import AIVerdictTab
from xss_security_gui.tabs.ai_training_tab import AITrainingTab
from xss_security_gui.ai_core.nn_model import load_trained_model
from xss_security_gui.live_monitor import LiveAttackMonitor
from xss_security_gui.threat_analysis.threat_connector import LIVE_MONITOR_QUEUE
from xss_security_gui.crawler import save_outputs, build_final_dict
from xss_security_gui.analyzer import XSSAnalyzerApp
from xss_security_gui.honeypot_monitor import monitor_log_thread
from xss_security_gui.honeypot_server import start_honeypot_server
from xss_security_gui.xss_detector import XSSDetector
from xss_security_gui.env_check import run_env_check
from xss_security_gui.visualizer import render_dot_to_svg
from xss_security_gui.js_inspector import analyze_js_file
from xss_security_gui.network_tab import NetworkTab
from xss_security_gui.utils.disable_ssl_warnings import disable_ssl_warnings

disable_ssl_warnings()

# ============================================================
#  GUI вкладки
# ============================================================
from xss_security_gui.settings_gui import SettingsTab
from xss_security_gui.gui.autorecon_dashboard_tab import AutoReconDashboardTab
from xss_security_gui.form_fuzzer_tab import FormFuzzerTab
from xss_security_gui.live_log_tab import LiveLogTab
from xss_security_gui.overview_tab import OverviewTab
from xss_security_gui.deep_analysis_tab import DeepAnalysisTab
from xss_security_gui.batch_report_tab import BatchReportTab
from xss_security_gui.settings_editor import SettingsEditor
from xss_security_gui.deep_scanner_tab import DeepScannerTab
from xss_security_gui.exploit_tab import ExploitTab
from xss_security_gui.idor_tab import IDORTab
from xss_security_gui.lfi_tab import LFITab
from xss_security_gui.site_map_tab import SiteMapTab
from xss_security_gui.full_analysis_tab import FullAnalysisTab
from xss_security_gui.threat_tab import ThreatAnalysisTab
from xss_security_gui.token_view_tab import TokenViewTab
from xss_security_gui.xss_tab import XSSTab
from xss_security_gui.sqli_tab import SQLiTab
from xss_security_gui.csrf_tab import CSRFTab
from xss_security_gui.ssrf_tab import SSRFTab
from xss_security_gui.gui.environment_tab import EnvironmentTab
from xss_security_gui.gui.security_dashboard_panel import SecurityDashboardPanel

# ============================================================
#  AutoRecon
# ============================================================
from xss_security_gui.auto_recon.scanner import EndpointScanner
from xss_security_gui.auto_recon.payloads import PayloadGenerator
from xss_security_gui.auto_recon.planner import AttackPlanner
from xss_security_gui.threat_tab_connector import ThreatIntelConnector

# ============================================================
#  Универсальный загрузчик файлов
# ============================================================
from xss_security_gui.file_loader import load_file, load_json, save_json

# ============================================================
#  PyQt Attack GUI
# ============================================================
from xss_security_gui.gui.attack_gui import AttackGUI

# ============================================================
#  Deep Crawler 5.0
# ============================================================
from xss_security_gui.deep_crawler import deep_crawl_site

# ============================================================
#  Версия приложения
# ============================================================
__version__ = "6.0"

# ============================================================
#  Основной Tkinter GUI
# ============================================================
class XSSSecurityGUI(tk.Tk):
    """
    Главный GUI-класс приложения.
    Управляет вкладками, логами, статусом, Deep Crawl, Threat Intel.
    """

    def __init__(self):
        super().__init__()
        self.title("🛡️ XSS Security GUI — Pro Edition")
        self.geometry("980x730")

        self.status = tk.StringVar(value="Готов к запуску")

        # Sidebar + Content Area вместо Notebook
        self.sidebar = None
        self.content_area = None
        self.tabs = {}

        self.honeypot_log = None
        self.log_view = None
        self.url_var = tk.StringVar(value="https://gazprombank.ru")
        self.url_frame: Optional[ttk.Frame] = None

        # Построение интерфейса (новая версия)
        self.build_tabs()

        # ============================================================
        #  AI Core — загрузка NN модели
        # ============================================================
        try:
            load_trained_model("models/nn_model_trained.joblib")
            print("[AI] NN Model loaded")
        except Exception as e:
            print("[AI] NN Model not loaded:", e)

            # URL input + dynamic tabs
        self.add_url_entry()
        self.load_dynamic_tabs()

        # Threat Intel + Detector
        self.threat_connector = ThreatIntelConnector()
        self.detector = XSSDetector(threat_tab=self.threat_tab)

        # UI elements
        self.create_status_bar()
        self.add_visualizer_button()
        self.add_deep_crawl_button()
        self.add_attack_gui_button()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Environment check
        env_status = run_env_check()
        print(env_status)
        self.log(env_status)

        print(f"[📦 Версия GUI] {__version__}")
        print(f"[AutoTrap] {'Включены' if ENABLE_AUTO_TRAPS else 'Отключены'}")

        current_theme = settings.get("gui.theme")
        print(f"[GUI] Тема интерфейса: {current_theme}")

    # ============================================================
    #  Построение вкладок GUI — Burp Suite Sidebar Edition
    # ============================================================
    def build_tabs(self):

        # === Основной контейнер ===
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)

        # === Sidebar ===
        self.sidebar = ttk.Frame(container, width=220)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # === Content Area ===
        self.content_area = ttk.Frame(container)
        self.content_area.pack(side="right", fill="both", expand=True)

        # === Группы вкладок ===
        self.tabs = {}

        # ------------------------------------------------------------
        # 1. Основные инструменты
        # ------------------------------------------------------------
        self._add_sidebar_group("Основные")
        self._add_sidebar_tab("📦 Threat Intel", lambda p: ThreatAnalysisTab(p))
        self._add_sidebar_tab("🕷️ Анализатор", lambda p: XSSAnalyzerApp(p, status_var=self.status, threat_tab=self.threat_tab))
        self._add_sidebar_tab("📶 Full Analysis", lambda p: FullAnalysisTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("📊 Обзор", lambda p: OverviewTab(p, app=self, threat_tab=self.threat_tab))
        self._add_sidebar_tab("🤖 AI Verdict", lambda p: AIVerdictTab(p))

        # ------------------------------------------------------------
        # 2. Deep Tools
        # ------------------------------------------------------------
        self._add_sidebar_group("Deep Tools")
        self._add_sidebar_tab("🧬 Deep Crawl", lambda p: DeepAnalysisTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("🛰️ Deep Scanner", lambda p: DeepScannerTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("💥 Эксплойты", lambda p: ExploitTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("🧪 Формы", lambda p: FormFuzzerTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("🔓 IDOR Тест", lambda p: IDORTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("📂 LFI Тест", lambda p: LFITab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("🗺️ Карта сайта", lambda p: SiteMapTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("🌐 Network Scanner", lambda p: NetworkTab(p, threat_tab=self.threat_tab))

        # ------------------------------------------------------------
        # 3. AI / ML
        # ------------------------------------------------------------
        self._add_sidebar_group("AI / ML")
        self._add_sidebar_tab("🤖 AI Training", lambda p: AITrainingTab(p))
        self._add_sidebar_tab("🛡️ Security Dashboard", lambda p: SecurityDashboardPanel(p))

        # ------------------------------------------------------------
        # 4. Логи и отчеты
        # ------------------------------------------------------------
        self._add_sidebar_group("Логи и отчеты")
        self._add_sidebar_tab("📊 Batch Report", lambda p: BatchReportTab(p))
        self._add_sidebar_tab("📶 События", lambda p: LiveLogTab(p))
        self._add_sidebar_tab("📁 Логи", lambda p: self._create_logs_tab(p))
        self._add_sidebar_tab("🎣 Honeypot", lambda p: self._create_honeypot_tab(p))

        # ------------------------------------------------------------
        # 5. Инструменты
        # ------------------------------------------------------------
        self._add_sidebar_group("Инструменты")
        self._add_sidebar_tab("🔐 Token Inspector", lambda p: TokenViewTab(p))
        self._add_sidebar_tab("🛠️ Настройки JSON", lambda p: SettingsEditor(p))
        self._add_sidebar_tab("⚙️ Настройки", lambda p: SettingsTab(p))
        self._add_sidebar_tab("🌍 Environment", lambda p: EnvironmentTab(p, env_path=BASE_DIR / ".env"))
        self._add_sidebar_tab("📡 AutoRecon Dashboard", lambda p: AutoReconDashboardTab(p))

        # Открыть первую вкладку
        self._open_tab("📦 Threat Intel")


    # ============================================================
    #  Sidebar helpers
    # ============================================================
    # ============================================================
    #  Sidebar helpers
    # ============================================================
    def _add_sidebar_group(self, title):
        lbl = ttk.Label(self.sidebar, text=title, font=("Segoe UI", 10, "bold"))
        lbl.pack(anchor="w", padx=12, pady=(15, 5))

    def _add_sidebar_tab(self, label, factory):
        btn = ttk.Button(self.sidebar, text=label, command=lambda: self._open_tab(label))
        btn.pack(fill="x", padx=12, pady=2)
        self.tabs[label] = factory

    def _open_tab(self, label):
        for child in self.content_area.winfo_children():
            child.destroy()

        tab = self.tabs[label](self.content_area)
        tab.pack(fill="both", expand=True)

        # Save references for important tabs
        if label == "📦 Threat Intel":
            self.threat_tab = tab
        elif label == "🕷️ Анализатор":
            self.analyzer = tab
        elif label == "📶 Full Analysis":
            self.full_analysis_tab = tab

    # ============================================================
    #  Поле ввода URL
    # ============================================================
    def add_url_entry(self):
        frame = ttk.Frame(self)
        frame.pack(side="top", fill="x", pady=4)

        ttk.Label(frame, text="🌐 Цільовий URL:").pack(side="left", padx=5)
        url_entry = ttk.Entry(frame, textvariable=self.url_var, width=60)
        url_entry.pack(side="left", padx=5)

        ttk.Button(
            frame,
            text="📂 Завантажити вкладки",
            command=self.load_dynamic_tabs,
        ).pack(side="left", padx=5)

        self.url_frame = frame

    # ============================================================
    #  Динамическая загрузка вкладок (XSS/SQLi/CSRF/SSRF)
    # ============================================================
    def load_dynamic_tabs(self):
        url = self.url_var.get().strip()
        if not url:
            self.log("⚠️ Введіть цільовий URL перед запуском вкладок.")
            return

        # Register dynamic tabs
        self.tabs["🛡️ SQLi"] = lambda p: SQLiTab(p, url, payload_file=str(SQLI_PAYLOAD_FILE))
        self.tabs["🛡️ XSS"] = lambda p: XSSTab(p, url, payload_file=str(XSS_PAYLOAD_FILE))
        self.tabs["🛡️ CSRF"] = lambda p: CSRFTab(p, url, payload_file=str(CSRF_PAYLOAD_FILE))
        self.tabs["🛡️ SSRF"] = lambda p: SSRFTab(p, url, payload_file=str(SSRF_PAYLOAD_FILE))

    # ============================================================
    #  Attack GUI
    # ============================================================
    def add_attack_gui_button(self):
        btn = ttk.Button(
            self.url_frame,
            text="🎛️ Attack GUI",
            command=self.launch_attack_gui,
        )
        btn.pack(side="left", padx=5)

    def launch_attack_gui(self):
        url = self.url_var.get().strip()
        if not url:
            self.log("⚠️ Введіть цільовий URL перед запуском Attack GUI.")
            return

        self.log(f"[🎛️] Запуск AttackGUI для: {url}")

        win = tk.Toplevel(self)
        win.title(f"AttackGUI — {url}")

        attack_frame = AttackGUI(win, domain=url)
        attack_frame.pack(fill="both", expand=True)

    # ============================================================
    #  Deep Crawl (потокобезопасный)
    # ============================================================
    def add_deep_crawl_button(self):
        btn = ttk.Button(
            self.url_frame,
            text="🧬 Deep Crawl",
            command=self.run_deep_crawl_threaded,
        )
        btn.pack(side="left", padx=5)

    def run_deep_crawl_threaded(self):
        threading.Thread(target=self._deep_crawl_worker, daemon=True).start()

    def _deep_crawl_worker(self):
        url = self.url_var.get().strip()
        if not url:
            self.after(0, lambda: self.log("⚠️ Введіть цільовий URL перед запуском Deep Crawl."))
            return

        self.after(0, lambda: self.status.set(f"🧬 Deep Crawl запущен для {url}"))
        self.after(0, lambda: self.log(f"[🧬] Запуск глубокого анализа: {url}"))

        try:
            result = deep_crawl_site(url)

            def apply_results():
                save_json(CRAWLER_RESULTS_PATH, result)
                self.log(f"[✅] Deep Crawl завершён. Результаты сохранены в {CRAWLER_RESULTS_PATH}")
                self.status.set("Deep Crawl завершён")

                self.propagate_crawler_results(result)

            self.after(0, apply_results)

            def send_to_threat():
                try:
                    self.threat_connector.report_crawler(result)
                    self.log("[📤] Результаты Deep Crawl отправлены в Threat Intel")
                except Exception as e:
                    self.log(f"[⚠️] Не удалось отправить Deep Crawl в Threat Intel: {e}")

            self.after(0, send_to_threat)

        except Exception as e:
            self.after(0, lambda: self.log(f"[❌] Ошибка Deep Crawl: {type(e).__name__}: {e}"))
            self.after(0, lambda: self.status.set("Ошибка Deep Crawl"))

    # ============================================================
    #  Передача результатов Deep Crawl во вкладки
    # ============================================================
    def propagate_crawler_results(self, result):
        if self.full_analysis_tab and hasattr(self.full_analysis_tab, "reload_from_crawler"):
            try:
                self.full_analysis_tab.reload_from_crawler(result)
            except Exception as e:
                self.log(f"[⚠️] Ошибка обновления FullAnalysisTab: {e}")

        if self.threat_tab and hasattr(self.threat_tab, "ingest_crawl_result"):
            try:
                self.threat_tab.ingest_crawl_result(result)
            except Exception as e:
                self.log(f"[⚠️] Ошибка передачи данных в ThreatTab: {e}")

    # ============================================================
    #  Honeypot + Logs
    # ============================================================
    def _create_honeypot_tab(self, parent):
        frame = ttk.Frame(parent)
        self.honeypot_log = tk.Text(frame, bg="#111", fg="cyan")
        self.honeypot_log.pack(fill="both", expand=True)

        threading.Thread(
            target=lambda: monitor_log_thread(self.honeypot_log),
            daemon=True,
        ).start()

        return frame

    def _create_logs_tab(self, parent):
        frame = ttk.Frame(parent)
        self.log_view = tk.Text(frame, bg="#222", fg="white")
        self.log_view.pack(fill="both", expand=True)
        self.load_logs()
        return frame

    def load_logs(self):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_content = load_file(LOG_SUCCESS_PATH, default="Файл логів не знайдено.")
        if self.log_view:
            self.log_view.insert("1.0", log_content)

    # ============================================================
    #  Статус бар
    # ============================================================
    def create_status_bar(self):
        ttk.Label(
            self,
            textvariable=self.status,
            relief="sunken",
            anchor="w",
        ).pack(side="bottom", fill="x")

    # ============================================================
    #  Кнопки визуализации и Threat Intel
    # ============================================================
    def add_visualizer_button(self):
        frame = ttk.Frame(self)
        frame.pack(side="bottom", fill="x")

        ttk.Button(
            frame,
            text="📈 Візуалізувати Graphviz",
            command=self.run_visualizer,
        ).pack(side="left")

        ttk.Button(
            frame,
            text="📤 Сводка в Threat Intel",
            command=self.send_attack_summary,
        ).pack(side="left")

    def send_attack_summary(self):
        try:
            engine = getattr(self.analyzer, "attack_engine", None)
            if engine and hasattr(engine, "send_summary_to_threat_intel"):
                engine.send_summary_to_threat_intel()
                summary = engine.get_summary()
                self.log("📤 Сводка атак отправлена:")
                self.log(json.dumps(summary, indent=2, ensure_ascii=False))
            else:
                self.log("⚠️ Attack Engine недоступен.")
        except Exception as e:
            self.log(f"❌ Ошибка отправки сводки: {e}")

    def run_visualizer(self):
        dot_file = LOG_DIR / "threat_graph.dot"
        svg_file = LOG_DIR / "threat_graph.svg"

        self.log(f"🖼️ Рендеринг графа: {dot_file}")
        self.status.set("Рендеринг Graphviz…")

        try:
            success, message = render_dot_to_svg(str(dot_file), str(svg_file))
            self.log(message)

            if success:
                import webbrowser
                webbrowser.open(str(svg_file))
            else:
                self.status.set("Ошибка рендера")
        except Exception as e:
            self.log(f"❌ Ошибка визуализации: {e}")
            self.status.set("Ошибка Graphviz")

    # ============================================================
    #  Логирование
    # ============================================================
    def log(self, text: str):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {text}"
        print(line)

        if self.log_view:
            try:
                self.log_view.insert("end", line + "\n")
                self.log_view.see("end")
            except Exception:
                pass

    # ============================================================
    #  Закрытие GUI
    # ============================================================
    def on_close(self):
        try:
            self.quit()
        except Exception:
            pass
        self.destroy()


def check_dependencies():
    if not SETTINGS_JSON_PATH.exists():
        print(f"[⚠️] settings.json не найден: {SETTINGS_JSON_PATH}")
    if not shutil.which("ngrok"):
        print("[⚠️] Ngrok не найден. Туннель будет недоступен.")


def show_usage():
    print(
        """
🔧 Использование:
    python -m xss_security_gui.main gui [domain]   # Запуск AttackGUI (Tkinter)
    python -m xss_security_gui.main tk             # Запуск XSSSecurityGUI
    python -m xss_security_gui.main crawl <url>    # Краулинг сайта
    python -m xss_security_gui.main js <path.js>   # Анализ JS-файла
    python -m xss_security_gui.main recon <url>    # Авторазведка
    python -m xss_security_gui.main --version      # Показать версию
    python -m xss_security_gui.main --help         # Показать справку
"""
    )


# ============================================================
#  Точка входа
# ============================================================
if __name__ == "__main__":
    args = sys.argv
    cmd = args[1].lower() if len(args) > 1 else "gui"

    if cmd == "--help" or cmd == "-h":
        show_usage()
        sys.exit(0)
    if cmd == "--version" or cmd == "-v":
        print(f"XSS Security Suite {__version__}")
        sys.exit(0)

    check_dependencies()

    try:
        threading.Thread(target=start_honeypot_server, daemon=True).start()
    except Exception as e:
        print(f"[⚠️] Honeypot не запущен: {e}")

    # ========================================================
    # AttackGUI (Tkinter)
    # ========================================================
    if cmd == "gui":
        print(f"[🛡️ AttackGUI] Запуск: {datetime.datetime.now().isoformat()}")

        domain = args[2] if len(args) >= 3 else "https://gazprombank.ru"

        root = tk.Tk()
        root.title("AttackGUI")

        gui = AttackGUI(root, domain=domain)
        gui.pack(fill="both", expand=True)

        root.mainloop()

    # ========================================================
    # XSSSecurityGUI (Tkinter)
    # ========================================================
    elif cmd == "tk":
        print(f"[🛡️ XSSSecurityGUI] Запуск: {datetime.datetime.now().isoformat()}")
        app = XSSSecurityGUI()
        app.mainloop()

    # ========================================================
    # CLI режими: crawl / js / recon / fuzz
    # ========================================================
    elif cmd in ("crawl", "js", "recon", "fuzz"):
        app = XSSSecurityGUI()

        def run_cli():
            def ui_log(msg: str):
                app.after(0, lambda: app.log(msg))

            def ui_call(fn, *a, **kw):
                app.after(0, lambda: fn(*a, **kw))

            try:
                # ----------------- CRAWL -----------------
                if cmd == "crawl" and len(args) == 3:
                    url = args[2]
                    ui_log(f"🕸️ Краулінг: {url}")

                    result = deep_crawl_site(url)  # завжди dict
                    pages = result.get("pages", [])
                    summary = result.get("summary", {})
                    raw = result.get("raw", {})

                    save_json(LOG_DIR / "deep_crawl.json", result)
                    save_json(LOG_DIR / "deep_pages.json", pages)

                    final = build_final_dict(pages)
                    if isinstance(final, str):
                        final = {"message": final}
                    elif isinstance(final, list):
                        final = {"items": final}
                    elif not isinstance(final, dict):
                        final = {"data": final}
                    # save_outputs(result, gui_callback=None)
                    save_outputs(final, gui_callback=None)
                    ui_log("✔️ Краулінг завершено. Дані збережено.")

                    ui_call(app.threat_connector.emit, "crawler", url, final)

                # ----------------- JS ANALYSIS -----------------
                elif cmd == "js" and len(args) == 3:
                    js_path = args[2]
                    ui_log(f"📜 Аналіз JS-файлу: {js_path}")

                    report = analyze_js_file(js_path)
                    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"js_analysis_{ts}.json"
                    save_json(LOG_DIR / filename, report)
                    ui_log(f"📁 Звіт по JS збережено: logs/{filename}")

                    ui_call(app.threat_connector.emit, "js_inspector", js_path, report)

                # ----------------- AUTORECON -----------------
                elif cmd == "recon" and len(args) == 3:
                    url = args[2]
                    ui_log(f"🔁 Авторозвідка: {url}")

                    endpoints = EndpointScanner(url).scan()
                    payloads = PayloadGenerator(endpoints).generate()
                    responses = AttackPlanner(payloads).execute()

                    ui_call(app.threat_connector.bulk, "auto_recon", url, responses)

                    report = app.threat_connector.generate_report()
                    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"auto_recon_{ts}.json"
                    save_json(LOG_DIR / filename, report)
                    ui_log(f"📁 Звіт збережено: logs/{filename}")
                    ui_log("📡 AutoRecon → Threat Intel відправлено")

                # ----------------- FUZZER -----------------
                elif cmd == "fuzz" and len(args) == 3:
                    url = args[2]
                    ui_log(f"🧪 Fuzzing: {url}")

                    params = {"q": xsschecker}
                    headers = {}
                    GET = True
                    delay = 1
                    timeout = 10
                    WAF = False
                    encoding = None

                    def fuzz_runner():
                        try:
                            fuzzer(
                                url, params, headers, GET, delay, timeout, WAF, encoding,
                                gui_callback=lambda text: app.after(0, lambda: app.log(text))
                            )
                        except Exception as e:
                            ui_log(f"❌ Помилка Fuzzer: {e}")

                    threading.Thread(target=fuzz_runner, daemon=True).start()

                else:
                    ui_log(
                        "⚠️ Невірні аргументи. Використовуйте: crawl <url> | js <path.js> | recon <url> | fuzz <url>")

            except Exception as e:
                ui_log(f"❌ Помилка CLI режиму ({cmd}): {type(e).__name__}: {e}")


        threading.Thread(target=run_cli, daemon=True).start()
        app.mainloop()