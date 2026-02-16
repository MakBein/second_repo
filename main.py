# xss_security_gui/main.py
# ============================================================
#  XSS Security Suite — main.py 5.0 (Ultimate Edition)
#  Полностью переписанная версия с поддержкой:
#  • Tkinter GUI
#  • PyQt AttackGUI
#  • Deep Crawler 5.0
#  • Threat Intel
#  • AutoRecon
#  • Honeypot ULTRA
#  • ULTRA Hybrid Settings
# ============================================================

import os
import sys
import shutil
import threading
import datetime
import json
import tkinter as tk
from tkinter import ttk
from PyQt5.QtWidgets import QApplication

# ============================================================
#  Централизованная конфигурация (ULTRA Hybrid)
# ============================================================
from xss_security_gui.settings import (
    settings,
    BASE_DIR,
    LOG_DIR,
    JSON_CRAWL_EXPORT_PATH,
    LOG_SUCCESS_PATH,
    ENABLE_AUTO_TRAPS,
)

GUI_STATE_FILE = LOG_DIR / "gui_state.json"
CRAWLER_RESULTS_PATH = JSON_CRAWL_EXPORT_PATH

# ============================================================
#  Загрузка результатов предыдущего краулинга
# ============================================================
if CRAWLER_RESULTS_PATH.exists():
    crawler_results = json.loads(CRAWLER_RESULTS_PATH.read_text(encoding="utf-8"))
else:
    print(f"⚠️ crawler_results.json не найден: {CRAWLER_RESULTS_PATH}")
    crawler_results = {}

# ============================================================
#  Импорты функциональных модулей
# ============================================================
from xss_security_gui.crawler import crawl_site, save_outputs, build_final_dict, nodes_json
from xss_security_gui.js_inspector import extract_js_insights
from xss_security_gui.analyzer import XSSAnalyzerApp
from xss_security_gui.honeypot_monitor import monitor_log_thread
from xss_security_gui.honeypot_server import start_honeypot_server
from xss_security_gui.xss_detector import XSSDetector
from xss_security_gui.env_check import run_env_check
from xss_security_gui.visualizer import render_dot_to_svg
from xss_security_gui.payload_mutator import mutate_async
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

# ============================================================
#  AutoRecon
# ============================================================
from xss_security_gui.auto_recon.scanner import EndpointScanner
from xss_security_gui.auto_recon.payloads import PayloadGenerator
from xss_security_gui.auto_recon.planner import AttackPlanner
from xss_security_gui.auto_recon.analyzer import ThreatConnector
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
from xss_security_gui.deep_crawler import (
    deep_crawl_site,
    detect_login_url,
    detect_logout_url,
    detect_backend_framework,
    detect_server,
    extract_opengraph,
    extract_json_ld,
    extract_meta_tags,
    calculate_page_risk,
    save_session,
    load_session,
)


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

        print(f"[📦 Версия GUI] 1.2.5")
        print(f"[AutoTrap] {'Включены' if ENABLE_AUTO_TRAPS else 'Отключены'}")

        # Тема интерфейса из ULTRA Hybrid Settings
        current_theme = settings.get("gui.theme")
        print(f"[GUI] Тема интерфейса: {current_theme}")

    # ============================================================
    #  Построение вкладок GUI
    # ============================================================
    def build_tabs(self):
        # Threat Intel
        self.threat_tab = ThreatAnalysisTab(self.tab_control)
        self.tab_control.add(self.threat_tab, text="📦 Threat Intel")

        # Analyzer
        self.analyzer = XSSAnalyzerApp(
            self.tab_control,
            status_var=self.status,
            threat_tab=self.threat_tab,
        )
        self.tab_control.add(self.analyzer, text="🕷️ Анализатор")

        # Full Analysis
        self.full_analysis_tab = FullAnalysisTab(
            self.tab_control,
            threat_tab=self.threat_tab,
        )
        self.tab_control.add(self.full_analysis_tab, text="📶 Full Analysis")

        # 📊 OverviewTab (Enterprise) — создаётся отдельно, т.к. требует app=self
        self.overview_tab = OverviewTab(
            self.tab_control,
            app=self,
            threat_tab=self.threat_tab
        )
        self.overview_tab.pack(fill="both", expand=True)
        self.tab_control.add(self.overview_tab, text="📊 Обзор")

        # Вкладки, принимающие threat_tab
        tabs_with_threat = [
            (DeepAnalysisTab, "🧬 Deep Crawl"),
            (DeepScannerTab, "🛰️ Deep Scanner"),
            (ExploitTab, "💥 Эксплойты"),
            (FormFuzzerTab, "🧪 Формы"),
            (IDORTab, "🔓 IDOR Тест"),
            (LFITab, "📂 LFI Тест"),
            (SiteMapTab, "🗺️ Карта сайта"),
        ]

        self.dynamic_tabs = []
        for cls, label in tabs_with_threat:
            tab = cls(self.tab_control, threat_tab=self.threat_tab)
            tab.pack(fill="both", expand=True)
            self.tab_control.add(tab, text=label)
            self.dynamic_tabs.append(tab)

        # Batch Report
        batch_tab = BatchReportTab(self.tab_control)
        batch_tab.pack(fill="both", expand=True)
        self.tab_control.add(batch_tab, text="📊 Batch Report")

        # Settings Editor
        settings_editor = SettingsEditor(self.tab_control)
        settings_editor.pack(fill="both", expand=True)
        self.tab_control.add(settings_editor, text="🛠️ Настройки JSON")

        # Live Log
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
            os.path.basename(LOG_SUCCESS_PATH),
            default="Файл логов не найден.",
        )
        self.log_view.insert("1.0", log_content)

    def add_threat_reload_button(self):
        frame = ttk.Frame(self)
        frame.pack(side="bottom", fill="x")
        ttk.Button(
            frame,
            text="📊 Обновить Threat Intel",
            command=self.threat_tab.reload_summary,
        ).pack(side="left")

    def add_mutate_button(self):
        btn = ttk.Button(self, text="🧬 Mutate Payloads", command=self.run_mutator)
        btn.pack()

    def run_mutator(self):
        threading.Thread(target=lambda: mutate_async(), daemon=True).start()
        self.log("🧬 Mutator запущен…")


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

    # ============================================================
    #  Кнопка Attack GUI (PyQt)
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

        def _run_qt():
            app = QApplication(sys.argv)
            gui = AttackGUI(target_url=url)
            gui.show()
            app.exec_()

        threading.Thread(target=_run_qt, daemon=True).start()

    # ============================================================
    #  Динамическая загрузка вкладок (XSS/SQLi/CSRF/SSRF)
    # ============================================================
    def load_dynamic_tabs(self):
        url = self.url_var.get().strip()
        if not url:
            self.log("⚠️ Введіть цільовий URL перед запуском вкладок.")
            return

        existing = [self.tab_control.tab(i, "text") for i in range(self.tab_control.index("end"))]

        xss_payload_path = BASE_DIR / "xss.json"
        sqli_payload_path = BASE_DIR / "sqli.json"
        csrf_payload_path = BASE_DIR / "csrf.json"
        ssrf_payload_path = BASE_DIR / "ssrf.json"

        if "🛡️ SQLi" not in existing:
            self.tab_control.add(
                SQLiTab(self.tab_control, url, payload_file=sqli_payload_path),
                text="🛡️ SQLi",
            )
        if "🛡️ XSS" not in existing:
            self.tab_control.add(
                XSSTab(self.tab_control, url, payload_file=xss_payload_path),
                text="🛡️ XSS",
            )
        if "🛡️ CSRF" not in existing:
            self.tab_control.add(
                CSRFTab(self.tab_control, url, payload_file=csrf_payload_path),
                text="🛡️ CSRF",
            )
        if "🛡️ SSRF" not in existing:
            self.tab_control.add(
                SSRFTab(self.tab_control, url, payload_file=ssrf_payload_path),
                text="🛡️ SSRF",
            )

    def render_graph(self, dot_path, svg_path):
        """Запускает рендеринг DOT → SVG в отдельном потоке."""
        self.log(f"🖼️ Рендеринг графа: {dot_path}")
        self.status.set("Рендеринг Graphviz…")

        def callback(success, message):
            # Обновляем GUI через after()
            self.after(0, lambda: self._on_graph_render_done(success, message))

        from xss_security_gui.visualizer import render_dot_to_svg
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
    #  Deep Crawl (в отдельном потоке)
    # ============================================================
    def run_deep_crawl_threaded(self):
        threading.Thread(target=self.run_deep_crawl, daemon=True).start()

    def run_deep_crawl(self):
        url = self.url_var.get().strip()
        if not url:
            self.log("⚠️ Введіть цільовий URL перед запуском Deep Crawl.")
            return

        self.status.set(f"🧬 Deep Crawl запущен для {url}")
        self.log(f"[🧬] Запуск глубокого анализа: {url}")

        try:
            result = deep_crawl_site(url)

            save_json(CRAWLER_RESULTS_PATH, result)
            self.log(f"[✅] Deep Crawl завершён. Результаты сохранены в {CRAWLER_RESULTS_PATH}")
            self.status.set("Deep Crawl завершён")

            self.propagate_crawler_results(result)

            try:
                self.threat_connector.report_crawler(result)
                self.log("[📤] Результаты Deep Crawl отправлены в Threat Intel")
            except Exception as e:
                self.log(f"[⚠️] Не удалось отправить Deep Crawl в Threat Intel: {e}")

        except Exception as e:
            self.log(f"[❌] Ошибка Deep Crawl: {type(e).__name__}: {e}")
            self.status.set("Ошибка Deep Crawl")

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
        index = self.tab_control.index(self.tab_control.select())
        save_json(GUI_STATE_FILE, {"last_tab": index})

    def load_gui_state(self):
        data = load_json(GUI_STATE_FILE, default={})
        last_index = data.get("last_tab", 0)
        if 0 <= last_index < self.tab_control.index("end"):
            self.tab_control.select(last_index)

    def on_close(self):
        self.save_gui_state()
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
            text="📈 Визуализировать Graphviz",
            command=self.run_visualizer,
        ).pack(side="left")

        ttk.Button(
            frame,
            text="📤 Сводка в Threat Intel",
            command=self.send_attack_summary,
        ).pack(side="left")

    def send_attack_summary(self):
        try:
            engine = self.analyzer.attack_engine
            engine.send_summary_to_threat_intel()
            summary = engine.get_summary()
            self.log("📤 Сводка атак отправлена:")
            self.log(json.dumps(summary, indent=2, ensure_ascii=False))
            self.activate_logs_tab()
        except Exception as e:
            self.log(f"❌ Ошибка отправки сводки: {type(e).__name__}: {e}")

    def run_visualizer(self):
        dot_file = LOG_DIR / "threat_graph.dot"
        svg_file = LOG_DIR / "threat_graph.svg"
        success, message = render_dot_to_svg(str(dot_file), str(svg_file))
        self.log(message)
        if success:
            try:
                import webbrowser
                webbrowser.open(str(svg_file))
            except Exception as e:
                self.log(f"⚠️ Не удалось открыть SVG: {e}")

    def log(self, text: str):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {text}"
        print(line)
        if self.log_view:
            self.log_view.insert("end", line + "\n")
            self.log_view.see("end")

    def activate_logs_tab(self):
        try:
            for i in range(self.tab_control.index("end")):
                if self.tab_control.tab(i, "text") == "📁 Логи":
                    self.tab_control.select(i)
                    return
            self.log("⚠️ Вкладка '📁 Логи' не найдена")
        except Exception as e:
            self.log(f"⚠️ Не удалось активировать вкладку логов: {e}")


# ============================================================
#  Проверка зависимостей
# ============================================================
def check_dependencies():
    settings_json = BASE_DIR / "settings.json"
    if not settings_json.exists():
        print(f"[⚠️] settings.json не найден: {settings_json}")

    if not shutil.which("ngrok"):
        print("[⚠️] Ngrok не найден. Туннель будет недоступен.")


# ============================================================
#  CLI справка
# ============================================================
def show_usage():
    print(
        """
🔧 Использование:
  python main.py gui                 # Запуск графического интерфейса (PyQt)
  python main.py tk                  # Запуск Tkinter GUI
  python main.py crawl <url>         # Краулинг сайта
  python main.py js <path.js>        # Анализ JS-файла
  python main.py recon <url>         # Автоматическая разведка
  python main.py --version           # Показать версию
  python main.py --help              # Показать справку
"""
    )


# ============================================================
#  Точка входа
# ============================================================
if __name__ == "__main__":
    check_dependencies()
    args = sys.argv
    cmd = args[1].lower() if len(args) > 1 else "gui"

    # Honeypot всегда запускается в отдельном потоке
    try:
        threading.Thread(target=start_honeypot_server, daemon=True).start()
    except Exception as e:
        print(f"[⚠️] Honeypot не запущен: {e}")

    # --------------------------------------------------------
    # GUI режимы
    # --------------------------------------------------------
    if cmd == "gui":
        print(f"[🛡️ AttackGUI] Запуск: {datetime.datetime.now().isoformat()}")
        app = QApplication(sys.argv)
        gui = AttackGUI(domain="https://gazprombank.ru")
        gui.show()
        sys.exit(app.exec_())

    elif cmd == "tk":
        print(f"[🛡️ XSSSecurityGUI] Запуск: {datetime.datetime.now().isoformat()}")
        app = XSSSecurityGUI()
        app.mainloop()

    # --------------------------------------------------------
    # CLI режимы
    # --------------------------------------------------------
    elif cmd in ("crawl", "js", "recon"):
        app = XSSSecurityGUI()

        try:
            app.after(500, app.activate_logs_tab)
        except Exception:
            pass

        env_status = run_env_check()
        print(env_status)
        app.log(env_status)

        def run_cli():
            try:
                # === CRAWL ===
                if cmd == "crawl" and len(args) == 3:
                    url = args[2]
                    app.log(f"🕸️ Краулинг: {url}")

                    raw, pages = crawl_site(url)

                    LOG_DIR.mkdir(parents=True, exist_ok=True)
                    save_json(LOG_DIR / "deep_crawl.json", {"pages": raw})
                    save_json(LOG_DIR / "deep_pages.json", pages)

                    final = build_final_dict(nodes_json)
                    save_outputs(final)
                    app.log("✔️ Краулинг завершён. Данные сохранены.")
                    app.threat_tab.send_to_threat_intel("crawler", final)

                # === JS ANALYSIS ===
                elif cmd == "js" and len(args) == 3:
                    path = args[2]
                    app.log(f"🔍 Анализ JS-файла: {path}")
                    insights = extract_js_insights(path)
                    for key, items in insights.items():
                        app.log(f"→ {key}: {items}")
                    app.threat_tab.send_to_threat_intel("js_inspector", insights)

                # === AUTO RECON ===
                elif cmd == "recon" and len(args) == 3:
                    url = args[2]
                    app.log(f"🔁 Авторазведка: {url}")

                    # 1. Сканирование
                    endpoints = EndpointScanner(url).scan()
                    payloads = PayloadGenerator(endpoints).generate()
                    responses = AttackPlanner(payloads).execute()

                    # 2. Генерация отчёта AutoRecon
                    report = ThreatConnector(responses).generate_report()

                    # 3. Сохранение отчёта
                    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"auto_recon_{ts}.json"
                    save_json(LOG_DIR / filename, report)

                    app.log(f"📁 Отчёт сохранён: logs/{filename}")

                    # 4. Threat Intel Pipeline 6.0
                    tic = ThreatIntelConnector()
                    tic.report_autorecon(report)
                    app.log("📡 AutoRecon → Threat Intel отправлено")

                    # 5. GUI Threat Tab
                    try:
                        app.threat_tab.send_to_threat_intel("auto_recon", report)
                    except Exception as e:
                        app.log(f"⚠️ Не удалось отправить в ThreatTab: {e}")

                else:
                    app.log("⚠️ Неверные аргументы. Используйте: crawl <url> | js <path.js> | recon <url>")

            except Exception as e:
                app.log(f"❌ Ошибка CLI режима ({cmd}): {type(e).__name__}: {e}")

        # Запуск CLI в отдельном потоке + основной GUI‑цикл
        threading.Thread(target=run_cli, daemon=True).start()
        app.mainloop()

    # --------------------------------------------------------
    # Справка и версия
    # --------------------------------------------------------
    elif cmd in ("--help", "help"):
        show_usage()

    elif cmd in ("--version", "version"):
        print("XSS Security Suite v3.0")

    else:
        show_usage()

