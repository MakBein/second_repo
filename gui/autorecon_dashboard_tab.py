# xss_security_gui/gui/autorecon_dashboard_tab.py
import tkinter as tk
from tkinter import ttk
import threading
from typing import Dict, Any

from xss_security_gui.gui.autorecon_dashboard import AutoReconDashboard
from xss_security_gui.auto_recon.run_full_autorecon import run_full_autorecon


class AutoReconDashboardTab(ttk.Frame):
    """
    GUI-вкладка AutoRecon Dashboard:
    • показывает сводку ThreatConnector 2.0
    • позволяет фильтровать по модулю, severity, target
    • запускает AutoRecon 2.0 асинхронно
    """

    def __init__(self, parent):
        super().__init__(parent)

        # Dashboard logic
        self.dashboard = AutoReconDashboard(gui_callback=self.on_dashboard_event)

        # GUI layout
        self.build_ui()

        # Автоматическое обновление при открытии вкладки
        self.bind("<Visibility>", lambda e: self.refresh_dashboard())

    # ---------------------------------------------------------
    # GUI
    # ---------------------------------------------------------
    def build_ui(self):
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", pady=5)

        ttk.Button(btn_frame, text="🔄 Обновить", command=self.refresh_dashboard).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="📦 Модуль: XSS", command=lambda: self.dashboard.get_by_module("XSS")).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🔥 High Severity", command=lambda: self.dashboard.get_by_severity("high")).pack(side="left", padx=5)

        self.target_var = tk.StringVar()
        ttk.Entry(btn_frame, textvariable=self.target_var, width=40).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🎯 По URL", command=lambda: self.dashboard.get_by_target(self.target_var.get())).pack(side="left", padx=5)

        ttk.Button(btn_frame, text="🚀 Run AutoRecon 2.0", command=self.run_autorecon_async).pack(side="left", padx=10)

        self.output = tk.Text(self, bg="#111", fg="#0f0", height=30)
        self.output.pack(fill="both", expand=True, pady=5)

    # ---------------------------------------------------------
    # Події Dashboard
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
        self.dashboard.build_dashboard_payload()

    # ---------------------------------------------------------
    # Запуск AutoRecon 2.0
    # ---------------------------------------------------------
    def run_autorecon_async(self):
        """Асинхронный запуск AutoRecon, чтобы GUI не зависал."""
        target = self.target_var.get().strip()
        if not target:
            self._append_output("\n⚠️ Введите URL перед запуском AutoRecon.\n")
            return

        self._append_output(f"\n🚀 Запуск AutoRecon 2.0 для: {target}\n")

        threading.Thread(target=self._run_autorecon, args=(target,), daemon=True).start()

    def _run_autorecon(self, target: str):
        """Фактический запуск AutoRecon в фоне."""
        try:
            result = run_full_autorecon(target)
            self._safe_append("\n✅ AutoRecon завершено.\n")
            self._safe_append(f"\n📊 Підсумок:\n{result['threat_summary']}\n")
        except Exception as e:
            self._safe_append(f"\n❌ Ошибка AutoRecon: {e}\n")

        self._safe_append("\n🔄 Обновление Dashboard...\n")
        self.refresh_dashboard()

    # ---------------------------------------------------------
    # Безопасное обновление GUI
    # ---------------------------------------------------------
    def _append_output(self, text: str):
        """Добавляет текст в output из главного потока."""
        self.output.insert("end", text)
        self.output.see("end")

    def _safe_append(self, text: str):
        """Безопасное добавление текста из фонового потока."""
        self.after(0, lambda: self._append_output(text))