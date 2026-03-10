# xss_security_gui/main.py
"""
main.py — точка входа XSS Security Suite 5.0
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
#  Загрузка результатов предыдущего краулинга
# ============================================================
def load_crawler_results() -> dict:
    if not CRAWLER_RESULTS_PATH.exists():
        return {}
    try:
        return json.loads(CRAWLER_RESULTS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        _logger.warning("Ошибка чтения crawler_results: %s", e)
        return {}


crawler_results = load_crawler_results()
# ============================================================
#  Импорты функциональных модулей
# ============================================================
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
from xss_security_gui.attack_report_tab import AttackReportTab
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
__version__ = "5.0"
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
        self.tab_control = ttk.Notebook(self)
        self.tab_control.pack(fill="both", expand=True)

        self.honeypot_log = None
        self.log_view = None
        self.url_var = tk.StringVar(value="https://gazprombank.ru")

        # Построение интерфейса
        self.build_tabs()

        # Security Dashboard
        dashboard_panel = SecurityDashboardPanel(self.tab_control)
        self.tab_control.add(dashboard_panel, text="🛡️ Security Dashboard")

        self.add_url_entry()
        self.load_dynamic_tabs()

        # XSS Detector + Threat Intel
        self.threat_connector = ThreatIntelConnector()
        self.detector = XSSDetector(threat_tab=self.threat_tab)

        # Восстановление состояния GUI
        self.load_gui_state()
        self.create_status_bar()
        self.add_visualizer_button()
        self.add_deep_crawl_button()
        self.add_attack_gui_button()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Проверка окружения
        env_status = run_env_check()
        print(env_status)
        self.log(env_status)

        print(f"[📦 Версия GUI] {__version__}")
        print(f"[AutoTrap] {'Включены' if ENABLE_AUTO_TRAPS else 'Отключены'}")

        # Тема интерфейса из ULTRA Hybrid Settings
        current_theme = settings.get("gui.theme")
        print(f"[GUI] Тема интерфейса: {current_theme}")

    # ============================================================
    #  Построение вкладок GUI
    # ============================================================
    def build_tabs(self):
        self._add_threat_tab()
        self._add_analyzer_tab()
        self._add_full_analysis_tab()
        self._add_overview_tab()
        self._add_dynamic_tabs()
        self._add_misc_tabs()

    def _add_threat_tab(self):
        self.threat_tab = ThreatAnalysisTab(self.tab_control)
        self.tab_control.add(self.threat_tab, text="📦 Threat Intel")

    def _add_analyzer_tab(self):
        self.analyzer = XSSAnalyzerApp(
            self.tab_control,
            status_var=self.status,
            threat_tab=self.threat_tab,
        )
        self.tab_control.add(self.analyzer, text="🕷️ Анализатор")

    def _add_full_analysis_tab(self):
        self.full_analysis_tab = FullAnalysisTab(
            self.tab_control,
            threat_tab=self.threat_tab,
        )
        self.tab_control.add(self.full_analysis_tab, text="📶 Full Analysis")

    def _add_overview_tab(self):
        self.overview_tab = OverviewTab(
            self.tab_control,
            app=self,
            threat_tab=self.threat_tab
        )
        self.overview_tab.pack(fill="both", expand=True)
        self.tab_control.add(self.overview_tab, text="📊 Обзор")

    def _add_dynamic_tabs(self):
        tabs_with_threat = [
            (DeepAnalysisTab, "🧬 Deep Crawl"),
            (DeepScannerTab, "🛰️ Deep Scanner"),
            (ExploitTab, "💥 Эксплойты"),
            (FormFuzzerTab, "🧪 Формы"),
            (IDORTab, "🔓 IDOR Тест"),
            (LFITab, "📂 LFI Тест"),
            (SiteMapTab, "🗺️ Карта сайта"),
            (NetworkTab, "🌐 Network Scanner"),
        ]
        self.dynamic_tabs = []
        for cls, label in tabs_with_threat:
            tab = cls(self.tab_control, threat_tab=self.threat_tab)
            tab.pack(fill="both", expand=True)
            self.tab_control.add(tab, text=label)
            self.dynamic_tabs.append(tab)

    def _add_misc_tabs(self):
        batch_tab = BatchReportTab(self.tab_control)
        batch_tab.pack(fill="both", expand=True)
        self.tab_control.add(batch_tab, text="📊 Batch Report")

        settings_editor = SettingsEditor(self.tab_control)
        settings_editor.pack(fill="both", expand=True)
        self.tab_control.add(settings_editor, text="🛠️ Настройки JSON")

        live_log_tab = LiveLogTab(self.tab_control)
        live_log_tab.pack(fill="both", expand=True)
        self.tab_control.add(live_log_tab, text="📶 События")

        # Attack Report
        attack_report_tab = AttackReportTab(self.tab_control)
        attack_report_tab.pack(fill="both", expand=True)
        self.tab_control.add(attack_report_tab, text="📊 Отчёт по атаке")

        # Token Inspector
        token_tab = TokenViewTab(self.tab_control)
        token_tab.pack(fill="both", expand=True)
        self.tab_control.add(token_tab, text="🔐 Token Inspector")

        # Settings
        settings_tab = SettingsTab(self.tab_control)
        settings_tab.pack(fill="both", expand=True)
        self.tab_control.add(settings_tab, text="⚙️ Настройки")

        # Environment Viewer
        env_tab = EnvironmentTab(self.tab_control, env_path=BASE_DIR / ".env")
        env_tab.pack(fill="both", expand=True)
        self.tab_control.add(env_tab, text="🌍 Environment")

        # AutoRecon Dashboard
        dashboard_tab = AutoReconDashboardTab(self.tab_control)
        dashboard_tab.pack(fill="both", expand=True)
        self.tab_control.add(dashboard_tab, text="📡 AutoRecon Dashboard")

        # Honeypot
        honeypot_tab = ttk.Frame(self.tab_control)
        self.honeypot_log = tk.Text(honeypot_tab, bg="#111", fg="cyan", height=30)
        self.honeypot_log.pack(fill="both", expand=True)
        self.tab_control.add(honeypot_tab, text="🎣 Honeypot")

        threading.Thread(
            target=lambda: monitor_log_thread(self.honeypot_log),
            daemon=True,
        ).start()

        # Logs
        logs_tab = ttk.Frame(self.tab_control)
        self.log_view = tk.Text(logs_tab, bg="#222", fg="white")
        self.log_view.pack(fill="both", expand=True)
        self.load_logs()
        self.tab_control.add(logs_tab, text="📁 Логи")

    def load_logs(self):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_content = load_file(
            LOG_SUCCESS_PATH,  # передаємо повний шлях
            default="Файл логів не знайдено.",
        )
        self.log_view.insert("1.0", log_content)

    def add_threat_reload_button(self):
        frame = ttk.Frame(self)
        frame.pack(side="bottom", fill="x")
        ttk.Button(
            frame,
            text="📊 Оновити Threat Intel",
            command=self.threat_tab.reload_summary,
        ).pack(side="left")

    def add_mutate_button(self):
        btn = ttk.Button(self, text="🧬 Mutate Payloads", command=self.run_mutator)
        btn.pack()

    def run_mutator(self):
        self.analyzer.run_mutator()


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
    #  Кнопка Deep Crawl
    # ============================================================
    def add_deep_crawl_button(self):
        btn = ttk.Button(
            self.url_frame,
            text="🧬 Deep Crawl",
            command=self.run_deep_crawl_threaded,
        )
        btn.pack(side="left", padx=5)

    def add_attack_gui_button(self):
        btn = ttk.Button(
            self.url_frame,
            text="🎛️ Attack GUI",
            command=self.launch_attack_gui,
        )
        btn.pack(side="left", padx=5)

    def launch_attack_gui(self):
        """Запускает AttackGUI для указанного URL в отдельном окне Tkinter."""
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
    #  Динамическая загрузка вкладок (XSS/SQLi/CSRF/SSRF)
    # ============================================================
    def load_dynamic_tabs(self):
        url = self.url_var.get().strip()
        if not url:
            self.log("⚠️ Введіть цільовий URL перед запуском вкладок.")
            return

        existing = [self.tab_control.tab(i, "text") for i in range(self.tab_control.index("end"))]

        if "🛡️ SQLi" not in existing:
            tab = SQLiTab(self.tab_control, url, payload_file=str(SQLI_PAYLOAD_FILE))
            tab.pack(fill="both", expand=True)
            self.tab_control.add(tab, text="🛡️ SQLi")

        if "🛡️ XSS" not in existing:
            tab = XSSTab(self.tab_control, url, payload_file=str(XSS_PAYLOAD_FILE))
            tab.pack(fill="both", expand=True)
            self.tab_control.add(tab, text="🛡️ XSS")

        if "🛡️ CSRF" not in existing:
            tab = CSRFTab(self.tab_control, url, payload_file=str(CSRF_PAYLOAD_FILE))
            tab.pack(fill="both", expand=True)
            self.tab_control.add(tab, text="🛡️ CSRF")

        if "🛡️ SSRF" not in existing:
            tab = SSRFTab(self.tab_control, url, payload_file=str(SSRF_PAYLOAD_FILE))
            tab.pack(fill="both", expand=True)
            self.tab_control.add(tab, text="🛡️ SSRF")


    # ============================================================
    #  Рендеринг Graphviz
    # ============================================================
    def render_graph(self, dot_path, svg_path):
        self.log(f"🖼️ Рендеринг графа: {dot_path}")
        self.status.set("Рендеринг Graphviz…")

        def callback(success, message):
            self.after(0, self._on_graph_render_done, success, message)

        render_dot_to_svg(dot_path, svg_path, callback=callback)

    def _on_graph_render_done(self, success, message):
        self.log(message)
        self.status.set("Готово" if success else "Ошибка рендера")

        if success:
            try:
                import webbrowser
                webbrowser.open(message.split(": ", 1)[1])
            except Exception:
                pass

    # ============================================================
    #  Deep Crawl (потокобезопасный)
    # ============================================================
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
        for tab in self.dynamic_tabs:
            if hasattr(tab, "reload_from_crawler"):
                try:
                    tab.reload_from_crawler(result)
                except Exception as e:
                    self.log(f"[⚠️] Ошибка обновления вкладки {tab}: {e}")

        if hasattr(self.full_analysis_tab, "reload_from_crawler"):
            try:
                self.full_analysis_tab.reload_from_crawler(result)
            except Exception as e:
                self.log(f"[⚠️] Ошибка обновления FullAnalysisTab: {e}")

        if hasattr(self.threat_tab, "ingest_crawl_result"):
            try:
                self.threat_tab.ingest_crawl_result(result)
            except Exception as e:
                self.log(f"[⚠️] Ошибка передачи данных в ThreatTab: {e}")

    # ============================================================
    #  Сохранение состояния GUI
    # ============================================================
    def save_gui_state(self):
        try:
            index = self.tab_control.index(self.tab_control.select())
            save_json(GUI_STATE_PATH, {"last_tab": index})
        except Exception as e:
            self.log(f"⚠️ Не удалось сохранить состояние GUI: {e}")

    def load_gui_state(self):
        try:
            data = load_json(GUI_STATE_PATH, default={})
            last_index = data.get("last_tab", 0)

            if 0 <= last_index < self.tab_control.index("end"):
                self.tab_control.select(last_index)
        except Exception as e:
            self.log(f"⚠️ Не удалось загрузить состояние GUI: {e}")

    def on_close(self):
        self.save_gui_state()
        try:
            self.quit()
        except Exception:
            pass
        self.destroy()

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
                self.activate_logs_tab()
            else:
                self.log("⚠️ Attack Engine недоступен для отправки сводки.")
        except Exception as e:
            self.log(f"❌ Ошибка отправки сводки: {type(e).__name__}: {e}")

    def run_visualizer(self):
        dot_file = LOG_DIR / "threat_graph.dot"
        svg_file = LOG_DIR / "threat_graph.svg"

        self.log(f"🖼️ Рендеринг графа: {dot_file}")
        self.status.set("Рендеринг Graphviz…")

        try:
            success, message = render_dot_to_svg(str(dot_file), str(svg_file))
            self.log(message)

            if success:
                try:
                    import webbrowser
                    webbrowser.open(str(svg_file))
                except Exception as e:
                    self.log(f"⚠️ Не удалось открыть SVG: {e}")
            else:
                self.status.set("Ошибка рендера")
        except Exception as e:
            self.log(f"❌ Ошибка визуализации: {type(e).__name__}: {e}")
            self.status.set("Ошибка Graphviz")

    # ============================================================
    #  Логирование
    # ============================================================
    def log(self, text: str):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {text}"
        print(line)

        if getattr(self, "log_view", None):
            try:
                self.log_view.insert("end", line + "\n")
                self.log_view.see("end")
            except Exception:
                pass

    def activate_logs_tab(self):
        try:
            for i in range(self.tab_control.index("end")):
                if self.tab_control.tab(i, "text") == "📁 Логи":
                    self.tab_control.select(i)
                    return
            self.log("⚠️ Вкладка '📁 Логи' не найдена")
        except Exception as e:
            self.log(f"⚠️ Не удалось активировать вкладку логов: {e}")

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
                    ui_log(f"🔁 Авторазвідка: {url}")

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
