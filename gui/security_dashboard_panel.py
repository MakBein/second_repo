# xss_security_gui/gui/security_dashboard_panel.py
# ============================================================
# SecurityDashboardPanel 10.0 — Combat Edition
# ============================================================

import tkinter as tk
from tkinter import ttk
from typing import Dict, Any, List
import time

from xss_security_gui.auto_recon import token_extractor
from xss_security_gui.gui.xss_log_viewer import XSSLogViewer
from xss_security_gui.auto_recon.scanner import load_reflected_responses
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge
from xss_security_gui.utils.threat_sender import normalize_threat_artifact
from xss_security_gui.threat_analysis.live_attack_monitor import AttackStreamProcessor



class SecurityDashboardPanel(tk.Frame):
    """
    Security Dashboard Panel 10.0 — Combat Edition
    ----------------------------------------------
    • TokenExtractor (async)
    • XSSLogViewer (NDJSON → summary)
    • Scanner artifacts (normalized)
    • Cross‑module heatmap 2.0 (LiveAttackMonitor)
    • Timeline 2.0 (LiveAttackMonitor)
    • Risk‑score events
    • Attack‑chain detection
    • ThreadWorker 10.0 integration:
        - thread events
        - thread metrics
        - watchdog alerts
        - progress updates
    • Повна інтеграція з ThreatConnector
    """

    def __init__(self, parent, ui: UIQueueBridge, threat_monitor: AttackStreamProcessor, app=None):
        super().__init__(parent)

        self.ui = ui
        self.monitor = threat_monitor
        self.app = app

        # Output window
        self.output = tk.Text(self, height=26, bg="#111", fg="#0ff", wrap="word")
        self.output.pack(fill="both", expand=True, padx=5, pady=5)

        # Tags
        self.output.tag_config("TITLE", foreground="#00eaff", font=("Segoe UI", 11, "bold"))
        self.output.tag_config("HIGH", foreground="#ff4d4f")
        self.output.tag_config("INFO", foreground="#faad14")
        self.output.tag_config("OK", foreground="#52c41a")
        self.output.tag_config("THREAD", foreground="#9effff")
        self.output.tag_config("WATCHDOG", foreground="#ff4d4f", font=("Segoe UI", 10, "bold"))

        # Buttons
        self.bruteforce_toggle = tk.BooleanVar(value=True)
        self.aggressive_toggle = tk.BooleanVar(value=False)

        toggle_frame = ttk.Frame(self)
        toggle_frame.pack(fill="x", padx=5, pady=(5, 0))
        ttk.Checkbutton(toggle_frame, text="🛡️ Login probe enabled", variable=self.bruteforce_toggle).pack(side="left", padx=(0, 10))
        ttk.Checkbutton(toggle_frame, text="⚠️ Aggressive mode (approved targets only)", variable=self.aggressive_toggle).pack(side="left")

        ttk.Button(self, text="🔍 Аналіз токенів", command=self.run_token_analysis).pack(fill="x", padx=5, pady=2)
        ttk.Button(self, text="🔥 Red Team AutoScan + Login Probe", command=self.run_red_team_autoscan_from_dashboard).pack(fill="x", padx=5, pady=2)
        ttk.Button(self, text="🔓 Brute Force Login", command=self.run_bruteforce_login_from_dashboard).pack(fill="x", padx=5, pady=2)
        ttk.Button(self, text="💉 SQLi Auto-Test", command=self.run_sqli_autotest_from_dashboard).pack(fill="x", padx=5, pady=2)
        ttk.Button(self, text="📜 Логи XSS", command=self.show_xss_logs).pack(fill="x", padx=5, pady=2)
        ttk.Button(self, text="📦 Артефакти Scanner", command=self.show_scanner_artifacts).pack(fill="x", padx=5, pady=2)
        ttk.Button(self, text="🔥 Cross‑Module Heatmap", command=self.show_cross_module_heatmap).pack(fill="x", padx=5, pady=2)
        ttk.Button(self, text="📈 Timeline", command=self.show_timeline).pack(fill="x", padx=5, pady=2)
        ttk.Button(self, text="⚡ Risk‑Score Events", command=self.show_risk_scores).pack(fill="x", padx=5, pady=2)
        ttk.Button(self, text="🧩 Attack Chains", command=self.show_attack_chains).pack(fill="x", padx=5, pady=2)

        # ThreadWorker 10.0 integration buttons
        ttk.Button(self, text="🧵 Thread Events", command=self.show_thread_events).pack(fill="x", padx=5, pady=2)
        ttk.Button(self, text="📊 Thread Metrics", command=self.show_thread_metrics).pack(fill="x", padx=5, pady=2)
        ttk.Button(self, text="🚨 Watchdog Alerts", command=self.show_watchdog_alerts).pack(fill="x", padx=5, pady=2)

        # XSSLogViewer
        self.log_viewer = XSSLogViewer(gui_callback=self.on_log_event)

        # ThreadWorker integration buffers
        self.thread_events: List[Dict[str, Any]] = []
        self.thread_metrics: Dict[str, Any] = {}
        self.watchdog_alerts: List[Dict[str, Any]] = []

    # ============================================================
    # ThreadWorker 10.0 Integration API
    # ============================================================
    def run_red_team_autoscan_from_dashboard(self):
        if self.app is not None and hasattr(self.app, "launch_red_team_dashboard_scan"):
            self._write("\n🔥 Triggering Red Team AutoScan from Security Dashboard...\n", "TITLE")
            self._write(f"Login probe enabled: {self.bruteforce_toggle.get()} | Aggressive mode: {self.aggressive_toggle.get()}\n", "INFO")
            self.app.launch_red_team_dashboard_scan(
                bruteforce_enabled=self.bruteforce_toggle.get(),
                aggressive=self.aggressive_toggle.get(),
                login_probe_enabled=self.bruteforce_toggle.get(),
            )
            return
        self._write("\n⚠️ Red Team AutoScan unavailable: main app callback not connected.\n", "INFO")

    def run_sqli_autotest_from_dashboard(self):
        if self.app is not None and hasattr(self.app, "launch_sqli_dashboard_scan"):
            self._write("\n💉 Triggering SQLi Auto-Test from Security Dashboard...\n", "TITLE")
            self._write(f"Aggressive SQLi mode: {self.aggressive_toggle.get()}\n", "INFO")
            self.app.launch_sqli_dashboard_scan(
                aggressive=self.aggressive_toggle.get(),
            )
            return
        self._write("\n⚠️ SQLi Auto-Test unavailable: main app callback not connected.\n", "INFO")

    def run_bruteforce_login_from_dashboard(self):
        if self.app is not None and hasattr(self.app, "launch_bruteforce_dashboard_attack"):
            self._write("\n🔓 Triggering brute-force login attack from Security Dashboard...\n", "TITLE")
            self._write(f"Login probe enabled: {self.bruteforce_toggle.get()} | Aggressive mode: {self.aggressive_toggle.get()}\n", "INFO")
            self.app.launch_bruteforce_dashboard_attack(
                aggressive=self.aggressive_toggle.get(),
                enabled=self.bruteforce_toggle.get(),
            )
            return
        self._write("\n⚠️ Brute-force login attack unavailable: main app callback not connected.\n", "INFO")

    def update_thread_event(self, name: str, event: str, data: Any = None):
        self.thread_events.append({
            "name": name,
            "event": event,
            "data": data,
            "ts": time.time()
        })

    def update_thread_metrics(self, metrics: Dict[str, Any]):
        self.thread_metrics = metrics

    def update_watchdog_alert(self, name: str, error: Exception):
        self.watchdog_alerts.append({
            "name": name,
            "error": str(error),
            "ts": time.time()
        })

    # ============================================================
    # Thread Events
    # ============================================================
    def show_thread_events(self):
        self._write("\n🧵 Thread Events:\n", "TITLE")

        if not self.thread_events:
            self._write("  (немає подій)\n")
            return

        for e in self.thread_events[-50:]:
            ts = time.strftime("%H:%M:%S", time.localtime(e["ts"]))
            self._write(f"[{ts}] {e['name']} → {e['event']} → {e['data']}\n", "THREAD")

    # ============================================================
    # Thread Metrics
    # ============================================================
    def show_thread_metrics(self):
        self._write("\n📊 Thread Metrics:\n", "TITLE")

        if not self.thread_metrics:
            self._write("  (немає метрик)\n")
            return

        for k, v in self.thread_metrics.items():
            self._write(f"{k}: {v}\n", "INFO")

    # ============================================================
    # Watchdog Alerts
    # ============================================================
    def show_watchdog_alerts(self):
        self._write("\n🚨 Watchdog Alerts:\n", "TITLE")

        if not self.watchdog_alerts:
            self._write("  (немає alert'ів)\n")
            return

        for a in self.watchdog_alerts[-20:]:
            ts = time.strftime("%H:%M:%S", time.localtime(a["ts"]))
            self._write(f"[{ts}] {a['name']} → {a['error']}\n", "WATCHDOG")

    # ============================================================
    # TokenExtractor (async)
    # ============================================================
    def run_token_analysis(self):
        headers = {"Authorization": "Bearer eyJhbGciOi..."}
        html = "<html><input type='hidden' name='csrf' value='abc123'></html>"

        self._write("⏳ Запущен аналіз токенів...\n", "INFO")

        token_extractor.analyze_from_gui(
            headers,
            html,
            callback=lambda result: self.ui.call_ui(self.on_token_analysis_done, result)
        )

    def on_token_analysis_done(self, analyzed):
        self._write("✅ Аналіз токенів завершено.\n", "OK")
        for token in analyzed:
            self._write(f"{token['source']} → {token['risk_level']}\n")

    # ============================================================
    # XSSLogViewer
    # ============================================================
    def show_xss_logs(self):
        self._write("\n📜 XSS Logs Summary:\n", "TITLE")
        summary = self.log_viewer.render_summary()

        self._write(f"Всего артефактів: {summary['total']}\n")
        for cat, count in summary["by_category"].items():
            self._write(f"  {cat}: {count}\n")

    def on_log_event(self, data):
        self._write("=== Оновлення XSSLogViewer ===\n")
        self._write(str(data) + "\n")

    # ============================================================
    # Scanner artifacts
    # ============================================================
    def show_scanner_artifacts(self):
        self._write("\n📦 Scanner Artifacts:\n", "TITLE")
        artifacts = load_reflected_responses()
        self._write(f"Завантажено {len(artifacts)} артефактів\n")

        for r in artifacts[:10]:
            norm = normalize_threat_artifact(r)
            self._write(f"{norm['url']} → {norm['category']}\n")

    # ============================================================
    # Cross‑module heatmap 2.0
    # ============================================================
    def show_cross_module_heatmap(self):
        heatmap = self.monitor.build_cross_module_heatmap()

        self._write("\n🔥 Cross‑Module Heatmap 2.0:\n", "TITLE")
        if not heatmap:
            self._write("  (порожньо)\n")
            return

        for row in heatmap:
            self._write(
                f"  {row['module']} → {row['category']} → {row['risk']} = {row['count']}\n"
            )

    # ============================================================
    # Timeline 2.0
    # ============================================================
    def show_timeline(self):
        timeline = self.monitor.build_timeline()

        self._write("\n📈 Timeline (останні 60 хв):\n", "TITLE")
        if not timeline:
            self._write("  (порожньо)\n")
            return

        for point in timeline:
            self._write(f"  {point['ts']} → {point['count']}\n")

    # ============================================================
    # Risk‑Score Events
    # ============================================================
    def show_risk_scores(self):
        self._write("\n⚡ Risk‑Score Events:\n", "TITLE")

        events = list(self.monitor._events)[-50:]
        for e in events:
            risk = e.get("risk", "unknown")
            url = e.get("url") or e.get("target")
            self._write(f"{url} → risk={risk}\n")

    # ============================================================
    # Attack Chains
    # ============================================================
    def show_attack_chains(self):
        self._write("\n🧩 Attack Chains:\n", "TITLE")

        chains = []
        for e in self.monitor._events:
            chain = self.monitor._detect_attack_chain(e)
            if chain:
                chains.append(chain)

        if not chains:
            self._write("  (немає ланцюжків атак)\n")
            return

        for c in chains[-10:]:
            self._write(f"{c['chain']} → {c['risk']} → {c['url']}\n")

    # ============================================================
    # Helpers
    # ============================================================
    def _write(self, text: str, tag: str | None = None):
        if tag is None:
            self.output.insert("end", text)
        else:
            self.output.insert("end", text, tag)
        self.output.see("end")


