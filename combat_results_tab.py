# xss_security_gui/combat_results_tab.py
"""
Combat Results Tab — Визуализация результатов боевых атак в GUI
Без фризов, с прогрессом в реальном времени и динамическим обновлением
"""
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import queue
import time
from typing import Dict, Any, Optional, Callable
from datetime import datetime
import json

class CombatResultsTab(ttk.Frame):
    """
    GUI вкладка для отображения результатов боевых атак.
    Потокобезопасная, обновляется в реальном времени.
    """

    def __init__(self, parent, result_queue: queue.Queue = None, **kwargs):
        super().__init__(parent, **kwargs)

        self.result_queue = result_queue or queue.Queue()
        self.root = parent

        # Получаем root window для after()
        while hasattr(parent, "master") and parent.master:
            parent = parent.master
        self.tk_root = parent

        # Состояние
        self.is_running = False
        self.events_received = []
        self.current_progress = 0

        self._build_ui()
        self._start_queue_monitor()

    def _build_ui(self):
        """Построить UI"""

        # === Заголовок ===
        header = ttk.Frame(self)
        header.pack(fill="x", padx=10, pady=10)

        ttk.Label(header, text="🎯 БОЕВЫЕ АТАКИ — Результаты",
                  font=("Helvetica", 14, "bold")).pack(side="left")

        self.status_label = ttk.Label(header, text="🔴 Ожидание...",
                                      font=("Helvetica", 10))
        self.status_label.pack(side="right")

        # === Прогресс ===
        progress_frame = ttk.Frame(self)
        progress_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(progress_frame, text="Прогресс:").pack(side="left", padx=5)

        self.progress_bar = ttk.Progressbar(progress_frame, mode="determinate",
                                            length=300, orient="horizontal")
        self.progress_bar.pack(side="left", fill="x", expand=True, padx=5)

        self.progress_label = ttk.Label(progress_frame, text="0%", width=5)
        self.progress_label.pack(side="left", padx=5)

        # === Основной контент (3 колонки) ===
        main_container = ttk.PanedWindow(self, orient="horizontal")
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        # --- Левая колонка: События/ход выполнения ---
        left_frame = ttk.LabelFrame(main_container, text="📋 События", width=250)
        main_container.add(left_frame, weight=1)

        left_scroll_y = ttk.Scrollbar(left_frame, orient="vertical")
        left_scroll_y.pack(side="right", fill="y")

        self.events_text = tk.Text(left_frame, height=20, width=25,
                                   yscrollcommand=left_scroll_y.set,
                                   bg="#1e1e1e", fg="#00ff00", font=("Courier", 8))
        self.events_text.pack(side="left", fill="both", expand=True)
        left_scroll_y.config(command=self.events_text.yview)

        # --- Средняя колонка: Результаты атак ---
        mid_frame = ttk.LabelFrame(main_container, text="🎯 Результаты Атак", width=300)
        main_container.add(mid_frame, weight=2)

        mid_scroll_y = ttk.Scrollbar(mid_frame, orient="vertical")
        mid_scroll_y.pack(side="right", fill="y")

        self.results_text = scrolledtext.ScrolledText(mid_frame, height=20,
                                                      bg="#1a1a1a", fg="#ffffff",
                                                      font=("Courier", 8),
                                                      relief="flat")
        self.results_text.pack(side="left", fill="both", expand=True)

        # Цветовая схема для результатов
        self.results_text.tag_config("xss_found", foreground="#ff6b6b", font=("Courier", 8, "bold"))
        self.results_text.tag_config("sqli_found", foreground="#ffa500", font=("Courier", 8, "bold"))
        self.results_text.tag_config("critical", foreground="#ff0000", font=("Courier", 8, "bold"))
        self.results_text.tag_config("high", foreground="#ff9900", font=("Courier", 8, "bold"))
        self.results_text.tag_config("medium", foreground="#ffff00", font=("Courier", 8, "bold"))
        self.results_text.tag_config("info", foreground="#00ff00", font=("Courier", 8))

        # --- Правая колонка: Статистика ---
        right_frame = ttk.LabelFrame(main_container, text="📊 Статистика", width=250)
        main_container.add(right_frame, weight=1)

        right_scroll_y = ttk.Scrollbar(right_frame, orient="vertical")
        right_scroll_y.pack(side="right", fill="y")

        self.stats_text = tk.Text(right_frame, height=20, width=25,
                                  yscrollcommand=right_scroll_y.set,
                                  bg="#0a0a0a", fg="#cyan", font=("Courier", 8))
        self.stats_text.pack(side="left", fill="both", expand=True)
        right_scroll_y.config(command=self.stats_text.yview)

        # === Кнопки внизу ===
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=10, pady=10)

        self.clear_btn = ttk.Button(btn_frame, text="🗑️ Очистить",
                                    command=self._clear_display)
        self.clear_btn.pack(side="left", padx=5)

        self.export_btn = ttk.Button(btn_frame, text="💾 Экспортировать",
                                     command=self._export_results)
        self.export_btn.pack(side="left", padx=5)

        ttk.Button(btn_frame, text="❌ Остановить",
                  command=self._stop_combat).pack(side="left", padx=5)

    def _start_queue_monitor(self):
        """Запустить монитор очереди результатов"""
        def monitor():
            while True:
                try:
                    event = self.result_queue.get(timeout=1)
                    self.tk_root.after(0, self._process_event, event)
                except queue.Empty:
                    continue
                except Exception as e:
                    print(f"Queue monitor error: {e}")
                    break

        thread = threading.Thread(target=monitor, daemon=True, name="QueueMonitor")
        thread.start()

    def _process_event(self, event: Dict[str, Any]):
        """Обработать событие из очереди (в Tkinter потоке)"""
        event_type = event.get("type", "unknown")
        timestamp = event.get("timestamp", "")

        if event_type == "progress":
            self._handle_progress(event)
        elif event_type == "attack_result":
            self._handle_attack_result(event)
        elif event_type == "crawl_complete":
            self._handle_crawl_complete(event)
        elif event_type == "attacks_complete":
            self._handle_attacks_complete(event)
        elif event_type == "combat_complete":
            self._handle_combat_complete(event)
        else:
            self._handle_generic_event(event)

        # Добавляем в события лог
        self.events_text.insert("end", f"[{timestamp[11:19]}] {event_type}\n")
        self.events_text.see("end")

    def _handle_progress(self, event: Dict[str, Any]):
        """Обработать обновление прогресса"""
        msg = event.get("message", "")
        progress = event.get("progress", 0)

        self.current_progress = progress
        self.progress_bar["value"] = progress
        self.progress_label.config(text=f"{progress}%")
        self.status_label.config(text=msg)

    def _handle_attack_result(self, event: Dict[str, Any]):
        """Обработать результат одной атаки"""
        data = event.get("data", {})

        # Форматируем результат
        attack_type = data.get("attack_type", "UNKNOWN")
        vulnerable = data.get("vulnerable", False)
        severity = data.get("severity", "INFO")
        endpoint = data.get("endpoint", "")

        # Показываем в окне результатов
        if vulnerable:
            icon = "🔴 УЯЗВИМ"
            tag = severity.lower()
        else:
            icon = "🟢"
            tag = "info"

        line = f"{icon} [{attack_type}] {endpoint[:50]} ({severity})\n"
        self.results_text.insert("end", line, tag)
        self.results_text.see("end")

    def _handle_crawl_complete(self, event: Dict[str, Any]):
        """Обработать завершение краулинга"""
        data = event.get("data", {})

        text = "\n=== ЭТАП 1: КРАУЛИНГ ===\n"
        text += f"📍 Страниц найдено: {data.get('pages_found', 0)}\n"
        text += f"📜 Скриптов найдено: {data.get('scripts_found', 0)}\n"
        text += f"🔗 Endpoints найдено: {data.get('endpoints_found', 0)}\n"
        text += f"📊 Статус: {data.get('status', 'UNKNOWN')}\n"
        text += f"⭐ Качество: {data.get('quality_score', 0)}%\n"

        self.stats_text.insert("end", text)
        self.stats_text.see("end")

    def _handle_attacks_complete(self, event: Dict[str, Any]):
        """Обработать завершение атак"""
        data = event.get("data", {})

        text = "\n=== ЭТАП 3: АТАКИ ===\n"
        text += f"🔴 XSS найдено: {data.get('xss_found', 0)}\n"
        text += f"🟠 SQLi найдено: {data.get('sqli_found', 0)}\n"
        text += f"🟡 CSRF найдено: {data.get('csrf_found', 0)}\n"
        text += f"🟣 SSRF найдено: {data.get('ssrf_found', 0)}\n"
        text += f"🟤 LFI найдено: {data.get('lfi_found', 0)}\n"
        text += f"\n🎯 ВСЕГО УЯЗВИМО: {data.get('total_vulnerable', 0)}\n"
        text += f"🚨 CRITICAL: {data.get('critical_severity', 0)}\n"

        self.stats_text.insert("end", text)
        self.stats_text.see("end")

    def _handle_combat_complete(self, event: Dict[str, Any]):
        """Обработать полное завершение"""
        data = event.get("data", {})

        vuln_summary = data.get("vulnerability_summary", {})

        text = "\n=== ФИНАЛЬНЫЙ ОТЧЁТ ===\n"
        text += f"🎯 Риск-уровень: {vuln_summary.get('risk_level', 'UNKNOWN')}\n"
        text += f"🔴 CRITICAL: {vuln_summary.get('critical', 0)}\n"
        text += f"🟠 HIGH: {vuln_summary.get('high', 0)}\n"
        text += f"🟡 MEDIUM: {vuln_summary.get('medium', 0)}\n"
        text += f"🟢 LOW: {vuln_summary.get('low', 0)}\n"
        text += f"📊 ВСЕГО: {vuln_summary.get('total', 0)}\n"
        text += f"\n✅ БОЕВОЙ ЦИКЛ ЗАВЕРШЁН\n"

        self.stats_text.insert("end", text)
        self.stats_text.see("end")

        self.status_label.config(text="✅ ГОТОВО")

    def _handle_generic_event(self, event: Dict[str, Any]):
        """Обработать генерический event"""
        event_type = event.get("type", "unknown")
        self.results_text.insert("end", f"[{event_type}] Event received\n", "info")
        self.results_text.see("end")

    def _clear_display(self):
        """Очистить все окна"""
        self.events_text.delete("1.0", "end")
        self.results_text.delete("1.0", "end")
        self.stats_text.delete("1.0", "end")
        self.progress_bar["value"] = 0
        self.progress_label.config(text="0%")
        self.status_label.config(text="🔴 Ожидание...")

    def _export_results(self):
        """Экспортировать результаты"""
        from pathlib import Path
        from xss_security_gui.settings import LOG_DIR

        # Собираем текст из всех окон
        export_data = {
            "timestamp": datetime.now().isoformat(),
            "events": self.events_text.get("1.0", "end"),
            "results": self.results_text.get("1.0", "end"),
            "statistics": self.stats_text.get("1.0", "end"),
        }

        # Сохраняем
        export_path = Path(LOG_DIR) / f"combat_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        try:
            with open(export_path, "w", encoding="utf-8") as f:
                f.write("=== БОЕВЫЕ АТАКИ - ЭКСПОРТ РЕЗУЛЬТАТОВ ===\n")
                f.write(f"Время: {export_data['timestamp']}\n\n")
                f.write("=== СОБЫТИЯ ===\n")
                f.write(export_data["events"])
                f.write("\n=== РЕЗУЛЬТАТЫ ===\n")
                f.write(export_data["results"])
                f.write("\n=== СТАТИСТИКА ===\n")
                f.write(export_data["statistics"])

            self.status_label.config(text=f"✅ Экспортировано: {export_path.name}")
        except Exception as e:
            self.status_label.config(text=f"❌ Ошибка экспорта: {e}")

    def _stop_combat(self):
        """Остановить боевой цикл"""
        self.status_label.config(text="⏸️ Остановка...")
        # Сигнал в очередь для остановки
        try:
            self.result_queue.put({
                "type": "stop_requested",
                "timestamp": datetime.now().isoformat()
            })
        except Exception:
            pass

