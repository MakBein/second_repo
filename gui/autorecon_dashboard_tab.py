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
    • показує зведення ThreatConnector 2.0
    • дозволяє переглядати модулі, severity, target
    • запускає AutoRecon 2.0
    """

    def __init__(self, parent):
        super().__init__(parent)

        # Dashboard logic
        self.dashboard = AutoReconDashboard(gui_callback=self.on_dashboard_event)

        # GUI layout
        self.build_ui()

        # Автоматичне оновлення при відкритті вкладки
        self.bind("<Visibility>", lambda e: self.refresh_dashboard())

    # ---------------------------------------------------------
    # GUI
    # ---------------------------------------------------------
    def build_ui(self):
        # Верхня панель кнопок
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", pady=5)

        ttk.Button(btn_frame, text="🔄 Обновить", command=self.refresh_dashboard).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="📦 Модуль: XSS", command=lambda: self.dashboard.get_by_module("XSS")).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🔥 High Severity", command=lambda: self.dashboard.get_by_severity("high")).pack(side="left", padx=5)

        # Поле для target
        self.target_var = tk.StringVar()
        ttk.Entry(btn_frame, textvariable=self.target_var, width=40).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🎯 По URL", command=lambda: self.dashboard.get_by_target(self.target_var.get())).pack(side="left", padx=5)

        # Кнопка запуску AutoRecon 2.0
        ttk.Button(btn_frame, text="🚀 Run AutoRecon 2.0", command=self.run_autorecon_async).pack(side="left", padx=10)

        # Основне вікно виводу
        self.output = tk.Text(self, bg="#111", fg="#0f0", height=30)
        self.output.pack(fill="both", expand=True, pady=5)

    # ---------------------------------------------------------
    # Події Dashboard
    # ---------------------------------------------------------
    def on_dashboard_event(self, data: Dict[str, Any]):
        """Отримує дані від AutoReconDashboard і виводить у GUI."""
        self.output.insert("end", "\n=== AutoRecon Dashboard Update ===\n\n")

        for key, value in data.items():
            self.output.insert("end", f"[{key}]\n{value}\n\n")

        self.output.see("end")

    # ---------------------------------------------------------
    # Оновлення Dashboard
    # ---------------------------------------------------------
    def refresh_dashboard(self):
        """Оновлює зведення при відкритті вкладки."""
        self.output.insert("end", "\n[🔄] Обновление Dashboard...\n")
        self.dashboard.build_dashboard_payload()

    # ---------------------------------------------------------
    # Запуск AutoRecon 2.0
    # ---------------------------------------------------------
    def run_autorecon_async(self):
        """Асинхронний запуск, щоб GUI не зависав."""
        target = self.target_var.get().strip()
        if not target:
            self.output.insert("end", "\n⚠️ Введите URL перед запуском AutoRecon.\n")
            return

        self.output.insert("end", f"\n🚀 Запуск AutoRecon 2.0 для: {target}\n")
        self.output.see("end")

        threading.Thread(target=self._run_autorecon, args=(target,), daemon=True).start()

    def _run_autorecon(self, target: str):
        """Фактичний запуск AutoRecon."""
        try:
            result = run_full_autorecon(target)
            self.output.insert("end", "\n✅ AutoRecon завершено.\n")
            self.output.insert("end", f"\n📊 Підсумок:\n{result['threat_summary']}\n")
        except Exception as e:
            self.output.insert("end", f"\n❌ Ошибка AutoRecon: {e}\n")

        self.output.insert("end", "\n🔄 Обновление Dashboard...\n")
        self.refresh_dashboard()
        self.output.see("end")