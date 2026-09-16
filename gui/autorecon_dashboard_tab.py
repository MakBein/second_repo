# xss_security_gui/gui/autorecon_dashboard_tab.py

import tkinter as tk
from tkinter import ttk
import json
from typing import Dict, Any

from xss_security_gui.gui.autorecon_dashboard import AutoReconDashboard
from xss_security_gui.auto_recon.orchestrator import run_full_autorecon
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge


class AutoReconDashboardTab(ttk.Frame):
    """
    AutoRecon Dashboard Tab — Red Team Edition 10.0
    ------------------------------------------------
    • Пагінація, heatmap, top targets
    • Асинхронний запуск AutoRecon Enterprise
    • Повна інтеграція з оркестратором (update_report)
    • Підтримка Threat Intel (ingest_autorecon)
    • Підтримка History/Kill Chain (refresh)
    • Безпечні оновлення GUI через UIQueueBridge
    """

    def __init__(self, parent):
        super().__init__(parent)
        self._bridge = UIQueueBridge(self, poll_ms=80)

        # Dashboard logic
        self.dashboard = AutoReconDashboard(gui_callback=self.on_dashboard_event)

        # Storage for last AutoRecon report
        self.last_report: Dict[str, Any] = {}

        # GUI layout
        self.build_ui()

        # Auto-refresh when tab becomes visible
        self.bind("<Visibility>", lambda e: self.refresh_dashboard())

    # ---------------------------------------------------------
    # GUI
    # ---------------------------------------------------------
    def build_ui(self):
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", pady=5)

        # Основні кнопки
        ttk.Button(btn_frame, text="🔄 Обновить", command=self.refresh_dashboard).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="📦 Модуль: XSS", command=lambda: self.dashboard.get_by_module("XSS")).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🔥 High Severity", command=lambda: self.dashboard.get_by_severity("high")).pack(side="left", padx=5)

        # Target search
        self.target_var = tk.StringVar()
        ttk.Entry(btn_frame, textvariable=self.target_var, width=40).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🎯 По URL", command=lambda: self.dashboard.get_by_target(self.target_var.get())).pack(side="left", padx=5)

        # AutoRecon
        ttk.Button(btn_frame, text="🚀 Run AutoRecon", command=self.run_autorecon_async).pack(side="left", padx=10)

        # Нові кнопки
        ttk.Button(btn_frame, text="📊 Heatmap", command=self.show_heatmap).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🎯 Top Targets", command=self.show_top_targets).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="⚡ Live Refresh", command=self.live_refresh).pack(side="left", padx=5)

        # Output
        self.output = tk.Text(self, bg="#111", fg="#0f0", height=30)
        self.output.pack(fill="both", expand=True, pady=5)

    # ---------------------------------------------------------
    # Callback from AutoReconDashboard
    # ---------------------------------------------------------
    def on_dashboard_event(self, data: Dict[str, Any]):
        """Получает данные от AutoReconDashboard и выводит в GUI."""
        self._append_output("\n=== AutoRecon Dashboard Update ===\n\n")
        for key, value in data.items():
            self._append_output(f"[{key}]\n{value}\n\n")

    # ---------------------------------------------------------
    # Оновлення Dashboard
    # ---------------------------------------------------------
    def refresh_dashboard(self):
        """Обновляет сводку при открытии вкладки."""
        self._append_output("\n[🔄] Обновление Dashboard...\n")
        payload = self.dashboard.build_dashboard_payload()
        self._append_output(json.dumps(payload, indent=2, ensure_ascii=False))

    # ---------------------------------------------------------
    # Heatmap
    # ---------------------------------------------------------
    def show_heatmap(self):
        self._append_output("\n[📊] Генерация Heatmap...\n")
        payload = self.dashboard.build_dashboard_payload()
        heatmap = payload.get("risk_heatmap", {})
        self._append_output(f"Heatmap:\n{json.dumps(heatmap, indent=2, ensure_ascii=False)}\n")

    # ---------------------------------------------------------
    # Top Targets
    # ---------------------------------------------------------
    def show_top_targets(self):
        self._append_output("\n[🎯] Top Targets...\n")
        payload = self.dashboard.build_dashboard_payload()
        top_targets = payload.get("top_targets", [])
        self._append_output(f"Top Targets:\n{json.dumps(top_targets, indent=2, ensure_ascii=False)}\n")

    # ---------------------------------------------------------
    # Live Refresh
    # ---------------------------------------------------------
    def live_refresh(self):
        self._append_output("\n[⚡] Live Refresh...\n")
        payload = self.dashboard.refresh_live()
        self._append_output(json.dumps(payload, indent=2, ensure_ascii=False))

    # ---------------------------------------------------------
    # Запуск AutoRecon Enterprise
    # ---------------------------------------------------------
    def run_autorecon_async(self):
        """Асинхронный запуск AutoRecon, чтобы GUI не зависал."""
        target = self.target_var.get().strip()
        if not target:
            self._append_output("\n⚠️ Введите URL перед запуском AutoRecon.\n")
            return

        self._append_output(f"\n🚀 Запуск AutoRecon Enterprise для: {target}\n")
        self._bridge.post_bg(self._run_autorecon, target)

    def _run_autorecon(self, target: str):
        """Фактический запуск AutoRecon в фоне."""
        try:
            result = run_full_autorecon(target)
            self.last_report = result

            self._safe_append("\n✅ AutoRecon завершено.\n")
            self._safe_append(f"\n📊 Threat Summary:\n{json.dumps(result.get('threat_summary', {}), indent=2, ensure_ascii=False)}\n")

            # Auto-update dashboard
            self._bridge.post_ui(self.refresh_dashboard)

        except Exception as e:
            self._safe_append(f"\n❌ Ошибка AutoRecon: {e}\n")

    # ---------------------------------------------------------
    # Red Team Integration Methods (Fix unresolved references)
    # ---------------------------------------------------------
    def update_report(self, report: Dict[str, Any]):
        """
        Получает итоговый отчёт AutoRecon и обновляет Dashboard.
        Используется GUI-оркестратором.
        """
        try:
            self.last_report = report
            self._append_output("\n=== AutoRecon Report Received ===\n")
            self._append_output(json.dumps(report, indent=2, ensure_ascii=False))
        except Exception as e:
            self._append_output(f"\n[update_report error] {e}\n")

    def ingest_autorecon(self, report: Dict[str, Any]):
        """
        Threat Intel ingestion (если Dashboard используется как часть ThreatAnalysisTab).
        """
        try:
            self.last_report = report
            self._append_output("\n=== Threat Intel: AutoRecon Ingest ===\n")
            self._append_output(json.dumps(report, indent=2, ensure_ascii=False))
        except Exception as e:
            self._append_output(f"\n[ingest_autorecon error] {e}\n")

    def refresh(self):
        """
        Kill Chain / History refresh compatibility.
        """
        try:
            self._append_output("\n[📅] Refresh triggered\n")
            self.refresh_dashboard()
        except Exception as e:
            self._append_output(f"\n[refresh error] {e}\n")

    # ---------------------------------------------------------
    # Безопасное обновление GUI
    # ---------------------------------------------------------
    def _append_output(self, text: str):
        self.output.insert("end", text)
        self.output.see("end")

    def _safe_append(self, text: str):
        self.after(0, lambda: self._append_output(text))

    def destroy(self):
        try:
            self._bridge.stop()
        except Exception:
            pass
        super().destroy()

