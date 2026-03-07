# xss_security_gui/gui/security_dashboard_panel.py

import tkinter as tk
from tkinter import ttk
from xss_security_gui.auto_recon import token_extractor
from xss_security_gui.gui.xss_log_viewer import XSSLogViewer
from xss_security_gui.auto_recon.scanner import load_reflected_responses


class SecurityDashboardPanel(tk.Frame):
    """
    Security Dashboard Panel (Tkinter)
    • Анализ токенов (TokenExtractor)
    • Просмотр логов XSS (XSSLogViewer)
    • Загрузка артефактов (Scanner)
    """

    def __init__(self, parent):
        super().__init__(parent)

        # Основное окно вывода
        self.output = tk.Text(self, height=20, bg="#111", fg="cyan")
        self.output.pack(fill="both", expand=True, padx=5, pady=5)

        # Кнопки управления
        btn_tokens = ttk.Button(self, text="🔍 Анализ токенов", command=self.run_token_analysis)
        btn_tokens.pack(fill="x", padx=5, pady=2)

        btn_logs = ttk.Button(self, text="📜 Логи XSS", command=self.show_xss_logs)
        btn_logs.pack(fill="x", padx=5, pady=2)

        btn_scanner = ttk.Button(self, text="📦 Артефакты Scanner", command=self.show_scanner_artifacts)
        btn_scanner.pack(fill="x", padx=5, pady=2)

        # Инициализация XSSLogViewer
        self.log_viewer = XSSLogViewer(gui_callback=self.on_log_event)

    # ---------------------------------------------------------
    # TokenExtractor (асинхронный анализ)
    # ---------------------------------------------------------
    def run_token_analysis(self):
        headers = {"Authorization": "Bearer eyJhbGciOi..."}  # пример
        html = "<html><input type='hidden' name='csrf' value='abc123'></html>"

        self.output.insert("end", "⏳ Запущен анализ токенов...\n")

        token_extractor.analyze_from_gui(headers, html, callback=self.on_token_analysis_done)

    def on_token_analysis_done(self, analyzed):
        self.output.insert("end", "✅ Анализ токенов завершён.\n")
        for token in analyzed:
            self.output.insert("end", f"{token['source']} → {token['risk_level']}\n")

    # ---------------------------------------------------------
    # XSSLogViewer (сводка и детали)
    # ---------------------------------------------------------
    def show_xss_logs(self):
        self.output.insert("end", "[🔄] Загрузка логов XSS...\n")
        summary = self.log_viewer.render_summary()
        self.output.insert("end", f"Всего артефактов: {summary['total']}\n")
        for cat, count in summary["by_category"].items():
            self.output.insert("end", f"  {cat}: {count}\n")

    def on_log_event(self, data):
        self.output.insert("end", "=== Обновление XSSLogViewer ===\n")
        self.output.insert("end", str(data) + "\n")

    # ---------------------------------------------------------
    # Scanner (артефакты)
    # ---------------------------------------------------------
    def show_scanner_artifacts(self):
        self.output.insert("end", "[🔄] Загрузка артефактов Scanner...\n")
        artifacts = load_reflected_responses()
        self.output.insert("end", f"Загружено {len(artifacts)} артефактов\n")
        for r in artifacts[:5]:  # показываем первые 5
            self.output.insert("end", f"{r.get('url')} → {r.get('category')}\n")