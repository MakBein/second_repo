# xss_security_gui/main.py
"""
main.py — точка входа XSS Security Suite 7.0 (refactored combat-grade edition)
Автор: Aleksandr + Copilot
"""

import sys
import shutil
import threading
import datetime
import json
import logging
import queue
from typing import Optional, Dict, Callable, Any, TypeVar

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
TabType = TypeVar("TabType", bound=ttk.Frame)
# ==============================
#  Безопасная консоль UTF-8
# ==============================
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ============================================================
#  XSStrike / Core
# ============================================================
from XSStrike.core.fuzzer import fuzzer
from XSStrike.core.config import xsschecker

# ============================================================
#  UI Queue Bridge (главный мост в Tkinter-поток)
# ============================================================
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge

# ============================================================
#  Combat Engine
# ============================================================
from xss_security_gui.combat_crawler import (
    is_active_target_allowed,
    run_combat_crawl,
)
from xss_security_gui.combat_results_tab import CombatResultsTab

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
    LOG_CRAWL_GRAPH_DOT,
    LOG_CRAWL_GRAPH_SVG,
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
from xss_security_gui.tabs.xss_flooder_tab import XSSFlooderTab
from xss_security_gui.live_monitor import LiveAttackMonitor
from xss_security_gui.threat_analysis.live_attack_monitor import AttackStreamProcessor
from xss_security_gui.crawler import (
    crawl_site,
    save_outputs,
    build_final_dict,
    reset_state,
    report_threatintel,
)

from xss_security_gui.analyzer import XSSAnalyzerApp
from xss_security_gui.honeypot_monitor import monitor_log_thread
from xss_security_gui.honeypot_server import start_honeypot_server
from xss_security_gui.xss_detector import XSSDetector
from xss_security_gui.env_check import run_env_check
from xss_security_gui.visualizer import render_dot_to_svg
from xss_security_gui.js_inspector import analyze_js_file
from xss_security_gui.mutator_task_manager import MutatorTaskManager
from xss_security_gui.threat_analysis.threat_connector import LIVE_MONITOR_QUEUE, ThreatConnector
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
from xss_security_gui.threat_analysis.internal_hosts_tab import InternalHostsTab
from xss_security_gui.token_view_tab import TokenViewTab
from xss_security_gui.xss_tab import XSSTab
from xss_security_gui.sqli_tab import SQLiTab
from xss_security_gui.csrf_tab import CSRFTab
from xss_security_gui.ssrf_tab import SSRFTab
from xss_security_gui.gui.internal_scan_tab import InternalScanTab
from xss_security_gui.gui.environment_tab import EnvironmentTab
from xss_security_gui.gui.security_dashboard_panel import SecurityDashboardPanel
from xss_security_gui.dom_parser_tab import DOMParserTab
from xss_security_gui.attack_report_tab import AttackReportTab
from xss_security_gui.autoanalyzer_tab import AutoAnalyzerTab
from xss_security_gui.gui.mutator_tasks_panel import MutatorTasksPanel
from xss_security_gui.gui.real_time_monitoring_tab import RealTimeMonitoringTab
from xss_security_gui.threat_analysis.accounts_tab import AccountsTab
from xss_security_gui.threat_analysis.account_intelligence_tab import AccountIntelligenceTab

# ============================================================
#  GUI вкладки (Threat Intelligence / Analyzer / Breaches )
# ============================================================
from xss_security_gui.proxy_tab import ProxyTab
from xss_security_gui.tree_view_tab import SuperCrawlerTreeViewTab
from xss_security_gui.monitor_tab import SuperCrawlerMonitorTab
from xss_security_gui.tabs.auto_modules_tab import AutoModulesTab

# ============================================================
#  AutoRecon
# ============================================================
from xss_security_gui.auto_recon.orchestrator import (
    AutoReconOrchestrator,
    run_full_autorecon,
    run_aggressive_scan,
)
from xss_security_gui.auto_recon.scope import (
    is_target_authorized,
    normalize_http_url,
)
from xss_security_gui.threat_tab_connector import ThreatIntelConnector

# ============================================================
#  Универсальный загрузчик файлов
# ============================================================
from xss_security_gui.file_loader import load_file, save_json

# ============================================================
#  Email Leak Integration
# ============================================================
from xss_security_gui.real_time_watcher import RealTimeThreatWatcher
from xss_security_gui.integrations.email_leak_worker import EmailLeakWorker
from xss_security_gui.integrations.email_leak_tab import EmailLeakWorkerTab

# Thread worker utility
from xss_security_gui.utils.thread_worker import init_global_worker, run_in_thread

# ============================================================
#  Deep Crawler 5.0
# ============================================================
from xss_security_gui.deep_crawler import deep_crawl_site

# ============================================================
#  Версия приложения
# ============================================================
__version__ = "7.0"


# ============================================================
#  Вспомогательные функции логирования
# ============================================================
def setup_logging():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / f"xss_gui_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    _logger.info("XSS Security Suite 7.0 started")
    _logger.info("Log file: %s", log_file)


# ============================================================
#  Основной Tkinter GUI
# ============================================================
class XSSSecurityGUI(tk.Tk):
    """
    Главный GUI-класс приложения.
    Управляет вкладками, логами, статусом, Deep Crawl, Threat Intel, Combat Mode.
    Все тяжёлые операции вынесены в фоновые потоки через run_in_thread + UIQueueBridge.
    """

    def __init__(self):
        super().__init__()
        self.title("🛡️ XSS Security Suite 7.0")
        self.geometry("980x730")

        self.status = tk.StringVar(value="Готов к запуску")

        # Sidebar + Content Area
        self.sidebar: Optional[ttk.Frame] = None
        self.content_area: Optional[ttk.Frame] = None
        self.tabs: Dict[str, Callable[[ttk.Frame], ttk.Frame]] = {}
        self._tab_instances: Dict[str, ttk.Frame] = {}
        # self.tabs: Dict[str, Callable[[ttk.Frame], tk.Widget]] = {}
        # self._tab_instances: Dict[str, tk.Widget] = {}


        self.honeypot_log = None
        self.log_view = None
        self.url_var = tk.StringVar(value="https://gazprombank.ru")
        self.url_frame: Optional[ttk.Frame] = None

        # SuperCrawler tabs (lazy singletons)
        self.supercrawler_monitor_tab: Optional[SuperCrawlerMonitorTab] = None
        self.supercrawler_tree_tab: Optional[SuperCrawlerTreeViewTab] = None

        # Initialize tab references
        self.threat_tab: Optional[ThreatAnalysisTab] = None
        self.analyzer: Optional[XSSAnalyzerApp] = None
        self.full_analysis_tab: Optional[FullAnalysisTab] = None
        self.real_time_watcher: Optional[RealTimeThreatWatcher] = None
        self.email_leak_worker: Optional[EmailLeakWorker] = None
        self.mutator_manager: MutatorTaskManager = MutatorTaskManager(max_workers=6)

        # Combat Mode
        self.combat_tab: Optional[CombatResultsTab] = None
        self._combat_result_queue: queue.Queue = queue.Queue()
        self._latest_combat_report: Optional[Dict[str, Any]] = None
        self._autorecon_running = False

        # MutatorManager callback → UIQueueBridge
        self.mutator_manager.on_task_finished = (
            lambda tid, result: self._ui_queue_bridge.post_ui(
                self._on_mutator_task_complete, tid, result
            )
        )

        # Sidebar groups
        self._group_containers: Dict[str, Dict] = {}
        self._current_group: Optional[str] = None

        # Lazy-loaded components
        self.threat_connector: Optional[ThreatIntelConnector] = None
        self.detector: Optional[XSSDetector] = None

        # Build UI
        self.build_tabs()

        # Init global ThreadWorker
        try:
            init_global_worker(self)
            _logger.info("[✅] Global ThreadWorker initialized")
        except Exception as e:
            _logger.warning("[⚠️] GlobalWorker init failed: %s", e)

        # URL input + dynamic tabs
        self.add_url_entry()
        self.load_dynamic_tabs()

        self.create_status_bar()
        self.add_visualizer_button()
        self.add_deep_crawl_button()
        self.add_attack_gui_button()
        self.add_super_crawl_button()
        self.add_crawl_graph_button()
        self.add_combat_button()
        self.add_autorecon_button()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Environment check (background)
        run_in_thread(self._env_check_background)

        _logger.info("[📦 Версия GUI] %s", __version__)
        _logger.info("[AutoTrap] %s", "Включены" if ENABLE_AUTO_TRAPS else "Отключены")

        current_theme = settings.get("gui.theme")
        _logger.info("[GUI] Тема интерфейса: %s", current_theme)

    # ============================================================
    #  ThreatConnector lazy init
    # ============================================================
    def _init_threat_connector_lazy(self):
        if self.threat_connector is not None:
            return
        try:
            self.threat_connector = ThreatIntelConnector()
            _logger.info("[✅] ThreatConnector initialized")
        except Exception as e:
            _logger.warning("[⚠️] ThreatConnector init failed: %s", e)
            self.threat_connector = None

    def get_threat_connector(self):
        if self.threat_connector is None:
            self._init_threat_connector_lazy()
        return self.threat_connector

    # ============================================================
    #  Detector lazy init
    # ============================================================
    def _init_detector_lazy(self):
        if self.detector is not None:
            return
        try:
            self.detector = XSSDetector(threat_tab=self.threat_tab)
            _logger.info("[✅] XSSDetector initialized")
        except Exception as e:
            _logger.warning("[⚠️] XSSDetector init failed: %s", e)
            self.detector = None

    def get_detector(self):
        if self.detector is None:
            self._init_detector_lazy()
        return self.detector

    # ============================================================
    #  SecurityDashboardPanel
    # ============================================================
    def _create_security_dashboard_tab(self, parent):
        try:
            return SecurityDashboardPanel(parent)
        except Exception as e:
            _logger.warning("[⚠️] SecurityDashboardPanel init failed: %s", e)
            frame = ttk.Frame(parent)
            ttk.Label(frame, text=f"Security Dashboard unavailable: {e}").pack(
                fill="both", expand=True
            )
            return frame

    # ============================================================
    #  SuperCrawler tabs wiring
    # ============================================================
    def _create_supercrawler_monitor_tab(self, parent):
        if self.supercrawler_monitor_tab is None:
            # передаємо root_url з головного інпуту
            self.supercrawler_monitor_tab = SuperCrawlerMonitorTab(
                parent,
                root_url=self.url_var.get(),
            )
        return self.supercrawler_monitor_tab

    def _create_supercrawler_tree_tab(self, parent):
        if self.supercrawler_tree_tab is None:
            self.supercrawler_tree_tab = SuperCrawlerTreeViewTab(parent)
        return self.supercrawler_tree_tab

    def _on_live_attack_event(self, data: Dict[str, Any]):
        try:
            self._event_queue.put(data)
        except Exception as e:
            print("[_on_live_attack_event] error:", e)

    # ============================================================
    #  Построение вкладок GUI — Burp Suite Sidebar Edition
    # ============================================================
    def build_tabs(self):
        # UIQueueBridge
        self._ui_queue_bridge = UIQueueBridge(self, poll_ms=100)

        # Main container
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)

        # Sidebar (scrollable)
        side_container = ttk.Frame(container, width=220)
        side_container.pack(side="left", fill="y")
        side_container.pack_propagate(False)

        side_container.rowconfigure(0, weight=1)
        side_container.columnconfigure(0, weight=1)

        side_canvas = tk.Canvas(side_container, width=180, highlightthickness=0)
        side_scroll = ttk.Scrollbar(
            side_container, orient="vertical", command=side_canvas.yview
        )
        side_canvas.configure(yscrollcommand=side_scroll.set)

        side_canvas.grid(row=0, column=0, sticky="nswe")
        side_scroll.grid(row=0, column=1, sticky="ns")

        sidebar_frame = ttk.Frame(side_canvas)
        side_canvas.create_window((0, 0), window=sidebar_frame, anchor="nw")

        btn_frame = ttk.Frame(side_container)
        btn_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 4))
        btn_up = ttk.Button(
            btn_frame,
            text="▲",
            width=3,
            command=lambda: side_canvas.yview_scroll(-3, "units"),
        )
        btn_down = ttk.Button(
            btn_frame,
            text="▼",
            width=3,
            command=lambda: side_canvas.yview_scroll(3, "units"),
        )
        btn_up.pack(side="left", padx=(6, 4))
        btn_down.pack(side="left")

        def _on_sidebar_config(event):
            try:
                side_canvas.configure(scrollregion=side_canvas.bbox("all"))
            except Exception:
                pass

        sidebar_frame.bind("<Configure>", _on_sidebar_config)

        def _on_sidebar_mousewheel(event):
            if hasattr(event, "delta") and event.delta:
                side_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            else:
                if getattr(event, "num", None) == 4:
                    side_canvas.yview_scroll(-1, "units")
                elif getattr(event, "num", None) == 5:
                    side_canvas.yview_scroll(1, "units")

        sidebar_frame.bind(
            "<Enter>",
            lambda e: sidebar_frame.bind_all(
                "<MouseWheel>", lambda ev: _on_sidebar_mousewheel(ev)
            ),
        )
        sidebar_frame.bind("<Leave>", lambda e: sidebar_frame.unbind_all("<MouseWheel>"))

        self.sidebar = sidebar_frame
        self._side_canvas = side_canvas

        # Content Area
        self.content_area = ttk.Frame(container)
        self.content_area.pack(side="right", fill="both", expand=True)

        # SuperCrawler Progress Bar
        self.supercrawl_progress = ttk.Progressbar(
            self.content_area, orient="horizontal", length=300, mode="determinate"
        )
        self.supercrawl_progress.pack(pady=5)
        self.supercrawl_progress["value"] = 0

        # LiveAttackMonitor (GUI)
        self._event_queue = queue.Queue()

        self._live_attack_gui = LiveAttackMonitor(
            parent=self.content_area,
            event_queue=self._event_queue
        )
        self._live_attack_gui.pack(fill="both", expand=True, padx=5, pady=5)

        # AttackStreamProcessor (backend)
        self._attack_stream = AttackStreamProcessor(
            ui=self._ui_queue_bridge,
            gui_callback=self._on_live_attack_event
        )

        # ------------------------------------------------------------
        # 1. Основные инструменты
        # ------------------------------------------------------------
        self._add_sidebar_group("Основные")
        self._add_sidebar_tab("🕷️ SuperCrawler Monitor", lambda p: self._create_supercrawler_monitor_tab(p))
        self._add_sidebar_tab("🌳 SuperCrawler Tree View", lambda p: self._create_supercrawler_tree_tab(p))
        self._add_sidebar_tab("🛰️ SSRF Tester", lambda p: SSRFTab(p, self.url_var.get()))
        self._add_sidebar_tab(
            "📦 Threat Intel",
            lambda p: ThreatAnalysisTab(p, result_queue=self._combat_result_queue)
        )

        self._add_sidebar_tab(
            "🕷️ Анализатор",
            lambda p: XSSAnalyzerApp(p, status_var=self.status, threat_tab=self.threat_tab),
        )
        self._add_sidebar_tab("📶 Full Analysis", lambda p: FullAnalysisTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("📊 Обзор", lambda p: OverviewTab(p, app=self, threat_tab=self.threat_tab))
        self._add_sidebar_tab("🤖 AI Verdict", lambda p: AIVerdictTab(p))
        self._add_sidebar_tab("👤 Accounts", lambda p: AccountsTab(p, self.get_threat_connector()))
        self._add_sidebar_tab(
            "🧠 Account Intelligence",
            lambda p: AccountIntelligenceTab(p, self.get_threat_connector()),
        )

        # ------------------------------------------------------------
        # 2. Deep Tools
        # ------------------------------------------------------------
        self._add_sidebar_group("Deep Tools")
        self._add_sidebar_tab("🚀 XSS Flooder", lambda p: XSSFlooderTab(p))
        self._add_sidebar_tab("🧬 Deep Crawl", lambda p: DeepAnalysisTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("🛰️ Deep Scanner", lambda p: DeepScannerTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("💥 Эксплойты", lambda p: ExploitTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("🧪 Формы", lambda p: FormFuzzerTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("🔓 IDOR Тест", lambda p: IDORTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("📂 LFI Тест", lambda p: LFITab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("🗺️ Карта сайта", lambda p: SiteMapTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("🌐 Network Scanner", lambda p: NetworkTab(p, threat_tab=self.threat_tab))

        # ------------------------------------------------------------
        # 3. Combat Mode
        # ------------------------------------------------------------
        self._add_sidebar_group("⚔️ БОЕВЫЕ АТАКИ")
        self._add_sidebar_tab(
            "🎯 Combat Results",
            lambda p: CombatResultsTab(
                p, result_queue=self._combat_result_queue, threat_tab=self.threat_tab
            ),
        )
        self._add_sidebar_tab(
            "⚡ AutoModules ULTRA",
            lambda p: AutoModulesTab(p, threat_tab=self.threat_tab),
        )

        # ------------------------------------------------------------
        # 4. AI / ML
        # ------------------------------------------------------------
        self._add_sidebar_group("AI / ML")
        self._add_sidebar_tab("🤖 AI Training", lambda p: AITrainingTab(p))
        self._add_sidebar_tab("🛡️ Security Dashboard", lambda p: self._create_security_dashboard_tab(p))

        # ------------------------------------------------------------
        # 5. Логи и отчеты
        # ------------------------------------------------------------
        self._add_sidebar_group("Логи и отчеты")
        self._add_sidebar_tab("📊 Batch Report", lambda p: BatchReportTab(p))
        self._add_sidebar_tab("📶 События", lambda p: LiveLogTab(p))
        self._add_sidebar_tab("📁 Логи", lambda p: self._create_logs_tab(p))
        self._add_sidebar_tab("🎣 Honeypot", lambda p: self._create_honeypot_tab(p))

        # ------------------------------------------------------------
        # 6. Инструменты
        # ------------------------------------------------------------
        self._add_sidebar_group("Инструменты")
        self._add_sidebar_tab("🔐 Token Inspector", lambda p: TokenViewTab(p))
        self._add_sidebar_tab("🛠️ Настройки JSON", lambda p: SettingsEditor(p))
        self._add_sidebar_tab("⚙️ Настройки", lambda p: SettingsTab(p))
        self._add_sidebar_tab("🌍 Environment", lambda p: EnvironmentTab(p, env_path=BASE_DIR / ".env"))
        self._add_sidebar_tab(
            "📡 AutoRecon Dashboard",
            lambda p: AutoReconDashboardTab(
                p,
                url_var=self.url_var,
            threat_tab=self.threat_tab,
                on_complete=self._on_autorecon_complete,
                on_email_audit=self._start_email_leak_audit,
            ),
        )
        self._add_sidebar_tab(
            "EmailLeakWorker",
            lambda p: EmailLeakWorkerTab(
                p,
                worker_provider=self._get_email_leak_worker,
                target_provider=lambda: self.url_var.get(),
            ),
        )
        self._add_sidebar_tab("🛰 Internal Scan", lambda p: InternalScanTab(p))

        # ------------------------------------------------------------
        # 7. Threat Intelligence
        # ------------------------------------------------------------
        self._add_sidebar_group("Threat Intelligence")
        self._add_sidebar_tab("🛰 Internal Hosts", lambda p: InternalHostsTab(p))
        self._add_sidebar_tab(
            "📡 Real-Time Monitoring",
            lambda p: RealTimeMonitoringTab(p, self._ui_queue_bridge, self.real_time_watcher),
        )

        # ------------------------------------------------------------
        # 8. Advanced Tools
        # ------------------------------------------------------------
        self._add_sidebar_group("Advanced Tools")
        self._add_sidebar_tab("🌐 DOM Parser", lambda p: DOMParserTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab("🛡️ Proxy", lambda p: ProxyTab(p))
        self._add_sidebar_tab("📄 Attack Report", lambda p: AttackReportTab(p))
        self._add_sidebar_tab("🔍 Auto Analyzer", lambda p: AutoAnalyzerTab(p, threat_tab=self.threat_tab))
        self._add_sidebar_tab(
            "🛡️ Defense Evasion Tasks",
            lambda p: MutatorTasksPanel(
                p, self.mutator_manager, ui_bridge=self._ui_queue_bridge
            ),
        )

        # Открыть первую вкладку
        self._open_tab("📦 Threat Intel")

    # ============================================================
    #  Sidebar helpers
    # ============================================================
    def _add_sidebar_group(self, title):
        header_frame = ttk.Frame(self.sidebar)
        header_frame.pack(fill="x", padx=8, pady=(12, 3))

        btn = ttk.Button(
            header_frame,
            text=f"{title} ▾",
            style="Toolbutton",
            command=lambda t=title: self._toggle_group(t),
        )
        btn.pack(side="left", fill="x", expand=True)

        container = ttk.Frame(self.sidebar)
        container.pack(fill="x", padx=12)

        self._group_containers[title] = {
            "header": header_frame,
            "button": btn,
            "container": container,
            "expanded": True,
        }

        self._current_group = title

    def _add_sidebar_tab(self, label, factory):
        container = None
        if self._current_group and self._current_group in self._group_containers:
            container = self._group_containers[self._current_group]["container"]

        target_parent = container if container is not None else self.sidebar
        btn = ttk.Button(target_parent, text=label, command=lambda: self._open_tab(label))
        btn.pack(fill="x", padx=12, pady=2)
        self.tabs[label] = factory  # type: Callable[[ttk.Frame], ThreatAnalysisTab]


    def _toggle_group(self, title: str):
        info = self._group_containers.get(title)
        if not info:
            return
        container = info["container"]
        btn = info["button"]
        if info.get("expanded"):
            container.pack_forget()
            btn.config(text=f"{title} ▸")
            info["expanded"] = False
        else:
            container.pack(fill="x", padx=12)
            btn.config(text=f"{title} ▾")
            info["expanded"] = True

    # ============================================================
    #  Безопасное открытие вкладок (lazy singleton)
    # ============================================================
    def _open_tab(self, label: str):
        def _ui():
            for child in self.content_area.winfo_children():
                child.pack_forget()

            # Threat Intel — singleton
            if label == "📦 Threat Intel":
                if self.threat_tab is None:
                    # 🔥 Явно вказуємо тип, чтобы PyCharm не думал что это Widget
                    self.threat_tab: ThreatAnalysisTab = self.tabs[label](
                        self.content_area,
                        result_queue=self._combat_result_queue
                    )

                    # 🔥 Запускаем Combat Event Reader (читает события из CombatCrawler)
                    self.threat_tab.start_combat_event_reader()

                self.threat_tab.pack(fill="both", expand=True)

                try:
                    self.get_detector()
                except Exception as e:
                    _logger.warning("[⚠️] Не удалось инициализировать XSSDetector: %s", e)

                if self.real_time_watcher is None:
                    self.real_time_watcher = RealTimeThreatWatcher(
                        threat_tab=self.threat_tab,
                        url=self.url_var.get(),
                        interval=15,
                        result_queue=self._combat_result_queue
                    )
                    self.real_time_watcher.start()

                return

            # Combat Results — singleton
            if label == "🎯 Combat Results":
                if self.combat_tab is None:
                    self.combat_tab = CombatResultsTab(
                        parent=self.content_area,
                        result_queue=self._combat_result_queue,
                        threat_tab=self.threat_tab,
                    )
                    if self._latest_combat_report is not None:
                        self.combat_tab.set_report(self._latest_combat_report)
                self._tab_instances[label] = self.combat_tab
                self.combat_tab.pack(fill="both", expand=True)
                return

            # Остальные вкладки — lazy singleton
            if label not in self.tabs:
                _logger.warning("[⚠️] Unknown tab label: %s", label)
                return

            if label not in self._tab_instances:
                try:
                    self._tab_instances[label] = self.tabs[label](self.content_area)
                except Exception as e:
                    _logger.error("[❌] Failed to create tab '%s': %s", label, e)
                    frame = ttk.Frame(self.content_area)
                    ttk.Label(
            frame,
                        text=f"Ошибка создания вкладки '{label}': {e}",
                    ).pack(fill="both", expand=True)
                    self._tab_instances[label] = frame

            tab_widget = self._tab_instances[label]
            tab_widget.pack(fill="both", expand=True)

        self._ui_queue_bridge.post_ui(_ui)

    # ============================================================
    #  Email Leak Integration init
    # ============================================================
    def _get_email_leak_worker(self) -> EmailLeakWorker:
        if self.email_leak_worker is None:
            self.email_leak_worker = EmailLeakWorker(
                threat_tab=self.threat_tab,
                ui_bridge=self._ui_queue_bridge,
                target_provider=lambda: self.url_var.get(),
                on_complete=self._on_email_leak_audit_complete,
            )
        else:
            self.email_leak_worker.threat_tab = self.threat_tab
        return self.email_leak_worker

    def _start_email_leak_audit(self, raw_target: Optional[str] = None):
        """Start active email-exposure verification from the AutoRecon Dashboard."""
        try:
            target = normalize_http_url(raw_target or self.url_var.get())
        except ValueError as exc:
            messagebox.showerror("Email Exposure Audit", str(exc), parent=self)
            return
        if not is_target_authorized(target):
            messagebox.showerror(
                "Email Exposure Audit заблокирован",
                "Цель отсутствует в ALLOW_REAL_RUN / ALLOWED_TARGETS.\n\n"
                f"Цель: {target}",
                parent=self,
            )
            return
        if not messagebox.askyesno(
            "Подтверждение Email Exposure Audit",
            "Будут собраны доступные страницы, адреса email и сведения о same-origin "
            "GET/POST-формах. При активной проверке разрешённые plain-text значения "
            "могут быть отправлены только в совпадающие поля same-origin форм. "
            "Пароли, файлы и исполняемые payload не отправляются. "
            "Редиректы проверяются пошагово и допускаются только внутри origin цели.\n\n"
            f"Запустить проверку {target}?",
            parent=self,
        ):
            return

        raw_values = simpledialog.askstring(
            "Поля для активной проверки",
            'Необязательно: JSON с именами полей и обычными тестовыми значениями, '
            'например {"q":"audit-check"}. Оставьте пустым для пассивного аудита.',
            parent=self,
        )
        if raw_values is None:
            return
        try:
            form_values = json.loads(raw_values) if raw_values.strip() else {}
            if not isinstance(form_values, dict) or any(
                not isinstance(name, str) or not isinstance(value, str)
                for name, value in form_values.items()
            ):
                raise ValueError("Ожидался JSON-объект со строковыми именами и значениями.")
        except (json.JSONDecodeError, ValueError) as exc:
            messagebox.showerror("Email Exposure Audit", str(exc), parent=self)
            return

        worker = self._get_email_leak_worker()
        try:
            started = worker.start(
                target,
                active_testing=bool(form_values),
                form_values=form_values,
            )
        except (TypeError, ValueError) as exc:
            messagebox.showerror("Email Exposure Audit", str(exc), parent=self)
            return
        if not started:
            messagebox.showinfo(
                "Email Exposure Audit",
                "Проверка уже выполняется.",
                parent=self,
            )

    def _on_email_leak_audit_complete(self, result: Dict[str, Any]) -> None:
        email_tab = self._tab_instances.get("EmailLeakWorker")
        if isinstance(email_tab, EmailLeakWorkerTab):
            if result.get("status") == "failed":
                email_tab.set_error(str(result.get("error", "unknown error")))
            else:
                email_tab.set_result(result)

        dashboard = self._tab_instances.get("📡 AutoRecon Dashboard")
        if isinstance(dashboard, AutoReconDashboardTab):
            if result.get("status") == "completed":
                dashboard.status_var.set(
                    f"Email audit complete — {result.get('page_count', 0)} pages, "
                    f"{len(result.get('emails', []))} masked emails, "
                    f"{result.get('requests', 0)} requests"
                )
                dashboard._append_output(
                    "\n📧 Email Exposure Audit complete: "
                    f"{result.get('page_count', 0)} pages, "
                    f"{result.get('form_count', 0)} forms, "
                    f"{len(result.get('emails', []))} masked email addresses, "
                    f"{len(result.get('form_submissions', []))} form submissions.\n"
                )
                dashboard.refresh_dashboard()
            else:
                dashboard.status_var.set(
                    f"Email audit {result.get('status')}: "
                    f"{result.get('error', 'no additional details')}"
                )


    # ============================================================
    #  Mutator task completion
    # ============================================================
    def _on_mutator_task_complete(self, task_id, result):
        """
        Інтеграція MutatorManager → Combat Results → Threat Intel.
        Повністю thread-safe: усі GUI-оновлення через UIQueueBridge.
        """
        if self._combat_result_queue is not None:
            self._combat_result_queue.put(result)

        if self.threat_tab:
            artifact = {
                "module": "DefenseEvasionLab",
                "target": result.get("payload", {}).get("url"),
                "timestamp": datetime.datetime.now().isoformat(),
                "result": {
                    "severity": result.get("risk", "info"),
                    "category": result.get("family", "defense_evasion"),
                    "payload": result.get("payload"),
                    "crawler": result.get("crawler_result"),
                },
            }
            self._ui_queue_bridge.post_ui(self.threat_tab.add_threat, artifact)

    # ============================================================
    #  Environment check (background)
    # ============================================================
    def _env_check_background(self):
        try:
            env_status = run_env_check()
            _logger.info("[ENV] %s", env_status)
            self._ui_queue_bridge.post_ui(lambda: self.status.set(env_status))
        except Exception as e:
            _logger.error("[❌] Env check failed: %s", e)

    # ============================================================
    #  URL entry + dynamic tabs
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

    def load_dynamic_tabs(self):
        url = self.url_var.get().strip()
        if not url:
            self.log("⚠️ Введіть цільовий URL перед запуском вкладок.")
            return

        self.tabs["🛡️ SQLi"] = lambda p: SQLiTab(p, url, payload_file=str(SQLI_PAYLOAD_FILE))
        self.tabs["🛡️ XSS"] = lambda p: XSSTab(p, url, payload_file=str(XSS_PAYLOAD_FILE))
        self.tabs["🛡️ CSRF"] = lambda p: CSRFTab(p, url, payload_file=str(CSRF_PAYLOAD_FILE))
        self.tabs["🛡️ SSRF"] = lambda p: SSRFTab(p, url, payload_file=str(SSRF_PAYLOAD_FILE))

        self.log("[📂] Динамічні вкладки успішно зареєстровані.")

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

        def _ui():
            try:
                from xss_security_gui.gui.attack_gui import AttackGUI
            except ImportError as exc:
                self.log(f"[❌] AttackGUI недоступен: {exc}")
                return
        win = tk.Toplevel(self)
        win.title(f"AttackGUI — {url}")

        attack_frame = AttackGUI(win, domain=url)
        attack_frame.pack(fill="both", expand=True)

        self._ui_queue_bridge.post_ui(_ui)

    # ============================================================
    #  Deep Crawl (safe)
    # ============================================================
    def add_deep_crawl_button(self):
        btn = ttk.Button(
            self.url_frame,
            text="🧬 Deep Crawl Enhanced",
            command=self._run_deep_crawl_safe,
        )
        btn.pack(side="left", padx=5)
        self._crawl_in_progress = False

    def _run_deep_crawl_safe(self):
        if self._crawl_in_progress:
            self.log("⚠️ Краулинг уже запущен. Дождитесь завершения.")
            return

        url = self.url_var.get().strip()
        if not url:
            self.log("⚠️ Введіть цільовий URL перед запуском Deep Crawl.")
            return

        self._crawl_in_progress = True
        self._run_deep_crawl_threaded(url)

    def add_super_crawl_button(self):
        btn = ttk.Button(
            self.url_frame,
            text="🕷️ Super Crawler",
            command=self._run_super_crawl_safe,
        )
        btn.pack(side="left", padx=5)

    def add_crawl_graph_button(self):
        btn = ttk.Button(
            self.url_frame,
            text="🕸️ Граф краулера",
            command=self.run_crawl_visualizer,
        )
        btn.pack(side="left", padx=5)

    def add_combat_button(self):
        btn = ttk.Button(
            self.url_frame,
            text="⚔️ БОЕВОЙ РЕЖИМ",
            command=self._launch_combat_cycle,
        )
        btn.pack(side="left", padx=5)

    def add_autorecon_button(self):
        btn = ttk.Button(
            self.url_frame,
            text="🎯 AutoRecon RT",
            command=self._launch_autorecon,
        )
        btn.pack(side="left", padx=5)

    def _launch_autorecon(self):
        """Run scoped AutoRecon after explicit authorization confirmation."""
        if getattr(self, "_autorecon_running", False):
            self.log("⚠️ AutoRecon уже выполняется.")
            return
        raw_url = self.url_var.get().strip()
        if not raw_url:
            self.log("⚠️ Введіть цільовий URL перед запуском AutoRecon.")
            return
        try:
            url = normalize_http_url(raw_url)
        except ValueError as exc:
            self.log(f"[❌] AutoRecon scope error: {exc}")
            return
        if not is_target_authorized(url):
            messagebox.showerror(
                "AutoRecon заблокирован",
                "Цель не разрешена политикой ALLOW_REAL_RUN / ALLOWED_TARGETS.\n\n"
                f"Цель: {url}",
                parent=self,
            )
            return
        if not messagebox.askyesno(
            "Подтверждение AutoRecon",
            "Цель входит в утвержденный allowlist.\n\n"
            "AutoRecon просканирует до 100 страниц (не более 200 сетевых запросов; "
            "ответ до 1 MiB). EndpointScanner проверяет отражение инертными "
            "canary-маркерами; отдельный активный этап может отправлять выбранные "
            "XSS-проверочные payloads в GET/POST-параметры. Поля паролей, файлов "
            "и секретов исключаются; отражение canary не является подтверждением XSS. "
            "Все запросы остаются в пределах этого origin. "
            "POST-запросы могут менять данные приложения. "
            "Редиректы проходят только после проверки каждого перехода; "
            "разрешены лишь URL того же origin.\n\n"
            f"Начать аудит {url}?",
            parent=self,
        ):
            return

        self._autorecon_running = True
        self.log(f"🎯 AutoRecon Orchestrator → {url}")
        self.status.set("AutoRecon: SCANNING…")
        self._open_tab("📡 AutoRecon Dashboard")
        self._ui_queue_bridge.post_bg(
            self._autorecon_worker,
            self._on_autorecon_done,
            url,
            True,
        )

    def _autorecon_worker(
        self, url: str, active_testing: bool = False
    ) -> Dict[str, Any]:
        def progress(msg: Dict[str, Any]) -> None:
            self._ui_queue_bridge.post_ui(self._on_autorecon_progress, msg)

        return run_full_autorecon(
            url,
            config={"active_testing": active_testing},
            callback=progress,
        )

    def _on_autorecon_progress(self, msg: Dict[str, Any]) -> None:
        stage = str(msg.get("stage") or "AUTO")
        status = str(msg.get("status") or "")
        details = msg.get("details") or {}
        extra = ""
        if details:
            extra = " " + json.dumps(details, ensure_ascii=False, default=str)[:180]
        self.log(f"[AutoRecon][{stage}] {status}{extra}")
        self.status.set(f"AutoRecon: {stage} / {status}")

    def _on_autorecon_done(self, result: Any) -> None:
        self._autorecon_running = False
        if isinstance(result, Exception):
            self.log(f"[❌] AutoRecon failed: {type(result).__name__}: {result}")
            self.status.set("AutoRecon: error")
            return
        self._on_autorecon_complete(result if isinstance(result, dict) else {"result": result})

    def _on_autorecon_complete(self, result: Dict[str, Any]) -> None:
        if result.get("status") == "blocked":
            reason = result.get("error", "Scope authorization failed")
            self.log(f"[🚫] AutoRecon blocked: {reason}")
            self.status.set("AutoRecon: scope blocked")
            return
        meta = result.get("metadata") or {}
        risk = meta.get("risk_level", "unknown")
        score = meta.get("risk_score", 0)
        duration = meta.get("duration_seconds")
        self.log(
            f"✅ AutoRecon complete | risk={risk} score={score} duration={duration}"
        )
        self.status.set(f"AutoRecon done — {risk}")

        connector = self.get_threat_connector()
        if connector:
            try:
                connector.emit("auto_recon", (meta.get("targets") or [self.url_var.get()])[0], {
                    "risk_level": risk,
                    "risk_score": score,
                    "threat_summary": result.get("threat_summary"),
                })
            except Exception as e:
                self.log(f"[⚠️] Threat Intel emit failed: {e}")

        if self.threat_tab and hasattr(self.threat_tab, "add_threat"):
            try:
                self.threat_tab.add_threat({
                    "module": "AutoReconOrchestrator",
                    "target": (meta.get("targets") or [self.url_var.get()])[0],
                    "result": {
                        "category": "auto_recon",
                        "risk": risk,
                        "score": score,
                    },
                })
            except Exception as e:
                self.log(f"[⚠️] ThreatTab update failed: {e}")

    # ============================================================
    #  Super Crawler
    # ============================================================
    def _run_super_crawl_safe(self):
        if getattr(self, "_crawl_in_progress", False):
            self.log("⚠️ Краулінг вже запущено.")
            return

        url = self.url_var.get().strip()
        if not url:
            self.log("⚠️ Введіть URL.")
            return

        self._crawl_in_progress = True

        run_in_thread(
            self._super_crawl_worker,
            name="SuperCrawl",
            on_start=self._on_supercrawl_start,
            on_progress=self._on_supercrawl_progress,
            on_success=lambda result: self._on_super_crawl_success(result, url),
            on_error=self._on_crawl_error,
            on_finally=self._on_supercrawl_finally,
        )

    def _on_supercrawl_start(self):
        def _ui():
            root_url = self.url_var.get().strip()

            if self.supercrawler_monitor_tab is not None:
                self.supercrawler_monitor_tab.set_progress(0)
                self.supercrawler_monitor_tab.set_status("SuperCrawler запущено…")
                self.supercrawler_monitor_tab.log_message("[🚀] Запуск SuperCrawler…")
                self.supercrawler_monitor_tab.clear_tree()
                if root_url:
                    self.supercrawler_monitor_tab.add_tree_node(
                        parent="",
                        label=root_url,
                        url=root_url,
                        status="root",
                    )

            if self.supercrawler_tree_tab is not None:
                self.supercrawler_tree_tab.clear()
                if root_url:
                    self.supercrawler_tree_tab.add_node(self.supercrawler_tree_tab.root, root_url)

            self.status.set("SuperCrawler запущено...")

        self._ui_queue_bridge.post_ui(_ui)

    def _on_supercrawl_progress(self, value):
        def _ui():
            self.supercrawl_progress["value"] = value
            msg = f"SuperCrawler: {value}%"
            self.status.set(msg)

            if self.supercrawler_monitor_tab is not None:
                self.supercrawler_monitor_tab.set_status(msg)
                self.supercrawler_monitor_tab.log_message(f"[📡] Прогрес: {value}%")

        self._ui_queue_bridge.post_ui(_ui)

    def _on_supercrawl_finally(self):
        def _ui():
            self._crawl_in_progress = False
            if self.supercrawler_monitor_tab is not None:
                self.supercrawler_monitor_tab.set_status("SuperCrawler завершено")

        self._ui_queue_bridge.post_ui(_ui)

    def _on_super_crawl_success(self, result, url):
        def _ui():
            self.supercrawl_progress["value"] = 100
            self.log(f"[✅] Super Crawler завершено: {url}")

            if self.supercrawler_monitor_tab is not None:
                self.supercrawler_monitor_tab.log_message(
                    f"[✅] Super Crawler завершено: {url}"
                )
                self.supercrawler_monitor_tab.set_status("SuperCrawler завершено")

            self.propagate_crawler_results(result)
            self._crawl_in_progress = False

        self._ui_queue_bridge.post_ui(_ui)

    def _super_crawl_worker(self, progress_callback, is_cancelled):
        url = self.url_var.get().strip()

        try:
            reset_state()
            progress_callback(5)

            def gui_callback(payload):
                if "crawler" in payload and self.threat_tab:
                    self._ui_queue_bridge.post_ui(
                        self.threat_tab.add_threat,
                        {"module": "crawler", "target": url, "result": payload["crawler"]},
                    )

                if "crawler" in payload and "url" in payload["crawler"]:
                    page_url = payload["crawler"]["url"]
                    self._ui_queue_bridge.post_ui(
                        self._update_supercrawler_tree,
                        page_url,
                    )

            if is_cancelled():
                return {"status": "cancelled"}

            progress_callback(20)
            node = crawl_site(url, depth=0, gui_callback=gui_callback, parallel=True)
            progress_callback(60)

            final = build_final_dict([node] if isinstance(node, dict) else node)
            progress_callback(80)

            save_outputs(final, gui_callback=gui_callback)
            progress_callback(90)

            save_json(CRAWLER_RESULTS_PATH, final)
            progress_callback(100)

            return final

        except Exception as e:
            return e

    def _update_supercrawler_tree(self, data):
        try:
            if isinstance(data, str):
                if self.supercrawler_monitor_tab is not None:
                    self.supercrawler_monitor_tab.add_tree_node(
                        parent="",
                        label=data,
                        url=data,
                        status="OK",
                    )

                if self.supercrawler_tree_tab is not None:
                    self.supercrawler_tree_tab.add_node(
                        self.supercrawler_tree_tab.root,
                        data,
                    )
                return

            if isinstance(data, dict) and "nodes" in data:
                nodes = data["nodes"]

                if self.supercrawler_monitor_tab is not None:
                    self.supercrawler_monitor_tab.update_tree(nodes)

                if self.supercrawler_tree_tab is not None:
                    self.supercrawler_tree_tab.update_tree(nodes)

        except Exception as e:
            print(f"[⚠️] Tree update failed: {e}")

    def run_crawl_visualizer(self):
        def _ui():
            dot_file = LOG_CRAWL_GRAPH_DOT
            svg_file = LOG_CRAWL_GRAPH_SVG

            if not dot_file.exists():
                self.log("⚠️ crawl_graph.dot не знайдено. Спочатку запустіть Super Crawler.")
                return

            ok, msg = render_dot_to_svg(str(dot_file), str(svg_file))
            self.log(msg)

        self._ui_queue_bridge.post_ui(_ui)

    # ============================================================
    #  Combat Mode (full cycle)
    # ============================================================
    def _launch_combat_cycle(self):
        url = self.url_var.get().strip()
        if not url:
            self.log("⚠️ Введіть цільовий URL перед запуском боевого режима.")
            return

        self.log(
            f"""
╔════════════════════════════════════════╗
║   🎯 ЗАПУСК ПОЛНОГО БОЕВОГО ЦИКЛА     ║
║   Target: {url[:40]:40}║
╚════════════════════════════════════════╝
"""
        )

        active_testing = False
        if is_active_target_allowed(url):
            active_testing = messagebox.askyesno(
                "Подтвердите активный аудит",
                "Цель находится в ALLOWED_TARGETS и ALLOW_REAL_RUN включен.\n\n"
                "Активная проверка отправит безвредный reflection-canary в формы "
                "GET/POST (кроме форм с паролями и загрузкой файлов). "
                "POST может изменить данные на сервере.\n\n"
                "Продолжить активную проверку?",
                parent=self,
            )
        else:
            self.log(
                "ℹ️ Цель не разрешена в ALLOWED_TARGETS или ALLOW_REAL_RUN отключен; "
                "активные GET/POST-проверки пропущены. Сбор страниц продолжится."
            )

        threading.Thread(
            target=self._combat_cycle_worker,
            args=(url, active_testing),
            daemon=True,
            name="CombatCycle",
        ).start()

    def _combat_cycle_worker(self, url: str, active_testing: bool = False):
        """Workers for combat cycle"""
        try:
            from xss_security_gui.combat_crawler import run_combat_crawl
            import traceback

            def progress_callback(msg: str, progress_pct: int):
                self.after(0, lambda: self.log(msg))
                self.after(0, lambda: self.status.set(f"{msg} ({progress_pct}%)"))

            # Запустить полный боевой цикл
            report = run_combat_crawl(
                target_url=url,
                result_queue=self._combat_result_queue,
                progress_callback=progress_callback,
                active_testing=active_testing,
            )

            self._ui_queue_bridge.post_ui(self._on_combat_cycle_complete, report)

            self.after(0, lambda: self.log(f"""
    ╔════════════════════════════════════════╗
    ║        ✅ БОЕВОЙ ЦИКЛ ЗАВЕРШЁН         ║
    ║   Щоб переглядати результати,         ║
    ║   перейдіть на вкладку "Combat Results" ║
    ╚════════════════════════════════════════╝
"""))

        except Exception as e:
            import traceback
            self.after(0, lambda: self.log(f"[❌] Помилка боевого цикла: {type(e).__name__}: {e}"))
            self.after(0, lambda: self.log(traceback.format_exc()))

    def _on_combat_cycle_complete(self, report: Dict[str, Any]) -> None:
        self._latest_combat_report = report
        if self.combat_tab is not None:
            self.combat_tab.set_report(report)

    # ============================================================
    #  Deep Crawl worker
    # ============================================================
    def _run_deep_crawl_threaded(self, url: str):
        def worker():
            try:
                result_data = self._deep_crawl_worker_enhanced(url)
                if result_data.get("success"):
                    self._ui_queue_bridge.post_ui(self._on_crawl_success, result_data)
                else:
                    self._ui_queue_bridge.post_ui(
                        self._on_crawl_error,
                        Exception(result_data.get("error", "Deep crawl failed")),
                    )
            except Exception as e:
                self._ui_queue_bridge.post_ui(self._on_crawl_error, e)

        try:
            self._ui_queue_bridge.post_bg(worker)
        except Exception as e:
            print(f"[⚠️] UIQueueBridge unavailable: {e}. Using threading.Thread.")
            threading.Thread(target=worker, daemon=True, name="DeepCrawl").start()

    def _deep_crawl_worker_enhanced(self, url: str) -> dict:
        try:
            reset_state()
        except Exception as e:
            print(f"[⚠️] reset_state() failed before Deep Crawl: {e}")

        try:
            self._ui_queue_bridge.post_ui(
                self._update_crawl_progress,
                "STARTING",
                url,
                0,
            )

            print(f"[🧬] Запуск глубокого анализа: {url}")
            result = deep_crawl_site(url)

            if not isinstance(result, dict):
                raise RuntimeError(f"Invalid result type: {type(result).__name__}")

            summary = result.get("summary", {})
            diagnostic = result.get("diagnostic", {})

            return {
                "success": True,
                "result": result,
                "summary": summary,
                "diagnostic": diagnostic,
                "url": url,
            }

        except Exception as e:
            import traceback

            tb = traceback.format_exc()
            print(f"[❌] Deep Crawl error: {type(e).__name__}: {e}")
            print(tb)

            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
                "traceback": tb,
                "url": url,
            }

    def _on_crawl_success(self, result_data: dict):
        def _ui():
            result = result_data.get("result", {}) or {}
            summary = result_data.get("summary", {}) or {}
            url = result_data.get("url", "unknown")

            try:
                save_json(CRAWLER_RESULTS_PATH, result)
            except Exception as e:
                self.log(f"[⚠️] Ошибка сохранения результатов: {e}")

            scan_status = summary.get("scan_status", "UNKNOWN")
            quality_score = summary.get("quality_score", 0)
            pages_crawled = summary.get("pages_crawled", 0)
            error_count = summary.get("error_count", 0)

            self._update_crawl_progress("COMPLETE", url, 100)

            self.log(
                f"""
[✅] Deep Crawl ЗАВЕРШЕН
    • Статус: {scan_status}
    • Качество: {quality_score}%
    • Страниц краулено: {pages_crawled}
    • Ошибок: {error_count}
    • Результаты: {CRAWLER_RESULTS_PATH}
"""
            )

            self.propagate_crawler_results(result)

            recs = summary.get("recommendations", [])
            if recs:
                self.log("[💡] Рекомендации:\n" + "\n".join(f"  {r}" for r in recs[:3]))

            self._crawl_in_progress = False

        self._ui_queue_bridge.post_ui(_ui)

    def _on_crawl_error(self, error: Exception):
        def _ui():
            error_msg = str(error)
            error_type = type(error).__name__

            self._update_crawl_progress("ERROR", "N/A", 0)

            self.log(
                f"[❌] Ошибка Deep Crawl:\n"
                f"  • Тип: {error_type}\n"
                f"  • Сообщение: {error_msg}"
            )

            self.status.set(f"❌ Ошибка: {error_type}")
            self._crawl_in_progress = False

        self._ui_queue_bridge.post_ui(_ui)

    def _update_crawl_progress(self, status: str, url: str, progress: int):
        def _ui():
            status_map = {
                "STARTING": f"🚀 Начало краулинга: {url}",
                "CRAWLING": f"🕷️ Краулинг: {url} ({progress}%)",
                "ANALYZING": f"🔍 Анализ: {url}",
                "COMPLETE": f"✅ Завершено: {url}",
                "ERROR": f"❌ Ошибка краулинга",
                "TIMEOUT": f"⏱️ Таймаут: {url}",
            }

            message = status_map.get(status, status)
            self.status.set(message)
            self.log(f"[{status}] {message}")

        self._ui_queue_bridge.post_ui(_ui)

    # ============================================================
    #  Передача результатов краулера во вкладки
    # ============================================================
    def propagate_crawler_results(self, result):
        try:
            if isinstance(result, dict) and "nodes" in result:
                normalized = result
            elif isinstance(result, dict) and "url" in result:
                normalized = build_final_dict([result])
            elif isinstance(result, list):
                normalized = build_final_dict(result)
            else:
                normalized = build_final_dict([result])
        except Exception as e:
            self.log(f"[⚠️] Ошибка нормализации результата краулера: {e}")
            return

        def heavy_processing():
            outputs = {"normalized": normalized}

            try:
                if self.full_analysis_tab and hasattr(self.full_analysis_tab, "prepare_crawler_data"):
                    outputs["full"] = self.full_analysis_tab.prepare_crawler_data(normalized)
            except Exception as e:
                outputs["full_error"] = str(e)

            try:
                if self.threat_tab and hasattr(self.threat_tab, "prepare_crawl_ingest"):
                    outputs["threat"] = self.threat_tab.prepare_crawl_ingest(normalized)
            except Exception as e:
                outputs["threat_error"] = str(e)

            try:
                site_map_tab = self.tabs.get("🗺️ Карта сайта")
                if site_map_tab and hasattr(site_map_tab, "prepare_crawler_data"):
                    outputs["sitemap"] = site_map_tab.prepare_crawler_data(normalized)
            except Exception as e:
                outputs["sitemap_error"] = str(e)

            try:
                auto_tab = self.tabs.get("🔍 Auto Analyzer")
                if auto_tab and hasattr(auto_tab, "prepare_crawler_data"):
                    outputs["auto"] = auto_tab.prepare_crawler_data(normalized)
            except Exception as e:
                outputs["auto_error"] = str(e)

            return outputs

        def apply_results(outputs):
            normalized_local = outputs.get("normalized")

            if self.full_analysis_tab and "full" in outputs:
                try:
                    self.full_analysis_tab.reload_from_crawler(outputs["full"])
                except Exception as e:
                    self.log(f"[⚠️] Ошибка обновления FullAnalysisTab: {e}")

            if self.threat_tab and "threat" in outputs:
                try:
                    self.threat_tab.ingest_crawl_result(outputs["threat"])
                except Exception as e:
                    self.log(f"[⚠️] Ошибка передачи данных в ThreatTab: {e}")

            site_map_tab = self.tabs.get("🗺️ Карта сайта")
            if site_map_tab and "sitemap" in outputs:
                try:
                    site_map_tab.reload_from_crawler(outputs["sitemap"])
                except Exception as e:
                    self.log(f"[⚠️] Ошибка обновления Карты сайта: {e}")

            auto_tab = self.tabs.get("🔍 Auto Analyzer")
            if auto_tab and "auto" in outputs:
                try:
                    auto_tab.ingest_crawler_data(outputs["auto"])
                except Exception as e:
                    self.log(f"[⚠️] Ошибка передачи данных в AutoAnalyzerTab: {e}")

            if normalized_local is not None:
                self._ui_queue_bridge.post_ui(self._update_supercrawler_tree, normalized_local)

            self.log("[📡] Результаты краулера успешно распространены по вкладкам.")

        run_in_thread(
            heavy_processing,
            name="CrawlerPostProcess",
            on_success=lambda outputs: self._ui_queue_bridge.post_ui(apply_results, outputs),
        )

    # ============================================================
    #  Honeypot + Logs
    # ============================================================
    def _create_honeypot_tab(self, parent):
        frame = ttk.Frame(parent)
        self.honeypot_log = tk.Text(frame, bg="#111", fg="cyan")
        self.honeypot_log.pack(fill="both", expand=True)

        class _GuiTextProxy:
            def __init__(self, tk_text, tk_root):
                self._text = tk_text
                self._root = tk_root
                self.output_box = tk_text

            def insert(self, index, text):
                try:
                    self._root.after(
                        0,
                        lambda: (self._text.insert(index, text), self._text.see("end")),
                    )
                except Exception:
                    pass

            def see(self, index):
                try:
                    self._root.after(0, lambda: self._text.see(index))
                except Exception:
                    pass

        proxy = _GuiTextProxy(self.honeypot_log, self)

        try:
            run_in_thread(lambda: monitor_log_thread(proxy))
        except Exception as e:
            print(f"[⚠️] Cannot use run_in_thread for honeypot: {e}")
            threading.Thread(
                target=lambda: monitor_log_thread(proxy),
                daemon=True,
                name="HoneypotMonitor",
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
    #  Статус бар + анимация
    # ============================================================
    def create_status_bar(self):
        status_frame = ttk.Frame(self)
        status_frame.pack(side="bottom", fill="x")

        ttk.Label(
            status_frame,
            textvariable=self.status,
            relief="sunken",
            anchor="w",
        ).pack(side="left", fill="both", expand=True)

        self.progress_label = ttk.Label(status_frame, text="⏹️", relief="sunken", width=3)
        self.progress_label.pack(side="right", padx=2)
        self._progress_animation = 0
        self._progress_animating = True
        self._start_progress_animation()

    def _start_progress_animation(self) -> None:
        self._tick_progress_animation()

    def _tick_progress_animation(self) -> None:
        if not getattr(self, "_progress_animating", False):
            return

        idle_frames = ("⏹️", "💤", "✅")
        busy_frames = ("🕷️", "🔄", "⏳")
        frames = busy_frames if getattr(self, "_crawl_in_progress", False) else idle_frames

        self._progress_animation = (self._progress_animation + 1) % len(frames)
        try:
            if hasattr(self, "progress_label") and self.progress_label.winfo_exists():
                self.progress_label.config(text=frames[self._progress_animation])
        except Exception:
            pass

        self.after(600, self._tick_progress_animation)

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

                connector = self.get_threat_connector()
                if connector:
                    try:
                        connector.emit("attack_summary", "attack_engine", summary)
                    except Exception as e:
                        self.log(f"[⚠️] Не удалось отправить сводку в ThreatConnector: {e}")
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
    def log(self, message: str):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_message = f"[{ts}] {message}"

        _logger.info(full_message)

        if getattr(self, "log_view", None) is not None and self.log_view.winfo_exists():

            def _ui():
                try:
                    self.log_view.insert("end", full_message + "\n")
                    self.log_view.see("end")
                except Exception as e:
                    _logger.warning("[⚠️] GUI log write failed: %s", e)

            if hasattr(self, "_ui_queue_bridge") and self._ui_queue_bridge is not None:
                self._ui_queue_bridge.post_ui(_ui)
            else:
                try:
                    _ui()
                except Exception:
                    pass

        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            with open(LOG_SUCCESS_PATH, "a", encoding="utf-8") as f:
                f.write(full_message + "\n")
        except Exception as e:
            _logger.warning("[⚠️] Не удалось записать лог в файл: %s", e)

    # ============================================================
    #  Закрытие GUI
    # ============================================================
    def on_close(self):
        _logger.info("[🛑] Shutdown requested")

        try:
            if hasattr(self, "_progress_animating"):
                self._progress_animating = False
        except Exception:
            pass

        try:
            self._autorecon_running = False
        except Exception:
            pass

        try:
            if getattr(self, "_attack_stream", None) is not None:
                self._attack_stream.stop()
        except Exception as e:
            _logger.warning("[⚠️] AttackStreamProcessor stop failed: %s", e)

        try:
            if hasattr(self, "_ui_queue_bridge") and self._ui_queue_bridge is not None:
                self._ui_queue_bridge.stop()
        except Exception as e:
            _logger.warning("[⚠️] UIQueueBridge stop failed: %s", e)

        try:
            if getattr(self, "real_time_watcher", None) is not None:
                self.real_time_watcher.stop()
        except Exception as e:
            _logger.warning("[⚠️] RealTimeWatcher stop failed: %s", e)

        try:
            if getattr(self, "email_leak_worker", None) is not None:
                self.email_leak_worker.stop()
        except Exception as e:
            _logger.warning("[⚠️] EmailLeakWorker stop failed: %s", e)

        try:
            if getattr(self, "mutator_manager", None) is not None:
                self.mutator_manager.shutdown()
        except Exception as e:
            _logger.warning("[⚠️] MutatorManager shutdown failed: %s", e)

        try:
            self.quit()
        except Exception:
            pass

        try:
            self.destroy()
        except Exception as e:
            _logger.error("[❌] GUI destroy failed: %s", e)


# ============================================================
#  CLI helpers
# ============================================================
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
    python -m xss_security_gui.main recon <url>    # AutoRecon Orchestrator (recon→analyze→attack→report)
    python -m xss_security_gui.main recon <url> --aggressive
    python -m xss_security_gui.main fuzz <url>     # XSStrike Fuzzer
    python -m xss_security_gui.main --version      # Показать версию
    python -m xss_security_gui.main --help         # Показать справку
"""
    )


# ============================================================
#  Точка входа
# ============================================================
if __name__ == "__main__":
    setup_logging()

    args = sys.argv
    cmd = args[1].lower() if len(args) > 1 else "gui"

    if cmd in ("--help", "-h"):
        show_usage()
        sys.exit(0)

    if cmd in ("--version", "-v"):
        print(f"XSS Security Suite {__version__}")
        sys.exit(0)

    check_dependencies()

    try:
        threading.Thread(target=start_honeypot_server, daemon=True).start()
    except Exception as e:
        print(f"[⚠️] Honeypot не запущен: {e}")

    if cmd == "gui":
        print(f"[🛡️ AttackGUI] Запуск: {datetime.datetime.now().isoformat()}")

        domain = args[2] if len(args) >= 3 else "https://gazprombank.ru"

        from xss_security_gui.gui.attack_gui import AttackGUI

        root = tk.Tk()
        root.title("AttackGUI")

        gui = AttackGUI(root, domain=domain)
        gui.pack(fill="both", expand=True)

        root.mainloop()

    elif cmd == "tk":
        print(f"[🛡️ XSSSecurityGUI] Запуск: {datetime.datetime.now().isoformat()}")
        try:
            app = XSSSecurityGUI()
        except Exception as e:
            import traceback
            print(f"[❌] GUI не запустился: {type(e).__name__}: {e}")
            traceback.print_exc()
            sys.exit(1)
        app.mainloop()

    elif cmd in ("crawl", "js", "recon", "fuzz"):
        app = XSSSecurityGUI()

        def run_cli():
            def ui_log(msg: str):
                app.after(0, lambda: app.log(msg))

            def ui_call(fn, *a, **kw):
                app.after(0, lambda: fn(*a, **kw))

            try:
                if cmd == "crawl" and len(args) == 3:
                    url = args[2]
                    ui_log(f"🕸️ Краулінг: {url}")

                    result = deep_crawl_site(url)
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

                    save_outputs(final, gui_callback=None)
                    ui_log("✔️ Краулінг завершено. Дані збережено.")

                    ui_call(app.get_threat_connector().emit, "crawler", url, final)

                elif cmd == "js" and len(args) == 3:
                    js_path = args[2]
                    ui_log(f"📜 Аналіз JS-файлу: {js_path}")

                    report = analyze_js_file(js_path)
                    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"js_analysis_{ts}.json"
                    save_json(LOG_DIR / filename, report)
                    ui_log(f"📁 Звіт по JS збережено: logs/{filename}")

                    ui_call(app.get_threat_connector().emit, "js_inspector", js_path, report)

                elif cmd == "recon" and len(args) >= 3:
                    url = args[2]
                    aggressive = "--aggressive" in args
                    ui_log(f"🎯 AutoRecon Orchestrator: {url} (aggressive={aggressive})")

                    def progress(msg):
                        stage = msg.get("stage", "?")
                        status = msg.get("status", "")
                        ui_log(f"[{stage}] {status} {msg.get('details') or ''}")

                    runner = run_aggressive_scan if aggressive else run_full_autorecon
                    report = runner(url, callback=progress)

                    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"auto_recon_{ts}.json"
                    save_json(LOG_DIR / filename, report)
                    ui_log(f"📁 Звіт: logs/{filename}")

                    meta = (report or {}).get("metadata") or {}
                    ui_log(
                        f"✅ risk={meta.get('risk_level')} score={meta.get('risk_score')}"
                    )
                    ui_call(
                        app.get_threat_connector().emit,
                        "auto_recon",
                        url,
                        report.get("threat_summary") if isinstance(report, dict) else report,
                    )
                    ui_log("📡 AutoRecon Orchestrator → Threat Intel")

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
                                url,
                                params,
                                headers,
                                GET,
                                delay,
                                timeout,
                                WAF,
                                encoding,
                                gui_callback=lambda text: app.after(
                                    0, lambda: app.log(text)
                                ),
                            )
                        except Exception as e:
                            ui_log(f"❌ Помилка Fuzzer: {e}")

                    threading.Thread(target=fuzz_runner, daemon=True).start()

                else:
                    ui_log(
                        "⚠️ Невірні аргументи. Використовуйте: crawl <url> | js <path.js> | recon <url> | fuzz <url>"
                    )

            except Exception as e:
                ui_log(f"❌ Помилка CLI режиму ({cmd}): {type(e).__name__}: {e}")

        threading.Thread(target=run_cli, daemon=True).start()
        app.mainloop()


    # ============================================================
    #  Combat Mode (Боевой режим с реальными атаками)
    # ============================================================
    def add_combat_button(self):
        """Add Combat Mode button"""
        btn = ttk.Button(
            self.url_frame,
            text="⚔️ БОЕВОЙ РЕЖИМ",
            command=self._launch_combat_cycle
        )
        btn.pack(side="left", padx=5)


    def _launch_combat_cycle(self):
        """Launch full combat cycle (crawl + analyze + attack)"""
        url = self.url_var.get().strip()
        if not url:
            self.log("⚠️ Введіть цільовий URL перед запуском боевого режима.")
            return

        self.log(f"""
    ╔════════════════════════════════════════╗
    ║   🎯 ЗАПУСК ПОЛНОГО БОЕВОГО ЦИКЛА     ║
    ║   Target: {url[:40]:40}║
    ╚════════════════════════════════════════╝
    """)

        # Запустить в фоновом потоке
        threading.Thread(
            target=self._combat_cycle_worker,
            args=(url,),
            daemon=True,
            name="CombatCycle"
        ).start()


    def _combat_cycle_worker(self, url: str):
        """Workers for combat cycle"""
        try:
            from xss_security_gui.combat_crawler import run_combat_crawl

            def progress_callback(msg: str, progress_pct: int):
                self.after(0, lambda: self.log(msg))
                self.after(0, lambda: self.status.set(f"{msg} ({progress_pct}%)"))

            # Запустить полный боевой цикл
            report = run_combat_crawl(
                target_url=url,
                result_queue=self._combat_result_queue,
                progress_callback=progress_callback
            )

            # Отправить результаты в очередь для GUI
            self._combat_result_queue.put({
                "type": "combat_complete",
                "data": report,
                "timestamp": datetime.datetime.now().isoformat()
            })

            self.after(0, lambda: self.log(f"""
    ╔════════════════════════════════════════╗
    ║        ✅ БОЕВОЙ ЦИКЛ ЗАВЕРШЁН         ║
    ║   Щоб переглядати результати,         ║
    ║   перейдіть на вкладку "Combat Results" ║
    ╚════════════════════════════════════════╝
    """))

        except Exception as e:
            self.after(0, lambda: self.log(f"[❌] Помилка боевого цикла: {type(e).__name__}: {e}"))
            import traceback
            self.after(0, lambda: self.log(traceback.format_exc()))
