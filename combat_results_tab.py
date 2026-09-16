# xss_security_gui/combat_results_tab.py
"""
Combat Results Tab — Візуалізація результатів боєвих атак в GUI.
Варіант A: збережено поточний UI, переписана внутрішня архітектура:
- чиста обробка черги
- модульні хендлери подій
- акуратна інтеграція з Threat Intel
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import queue
import logging
from typing import Dict, Any, Optional, Callable
from datetime import datetime
from pathlib import Path
import json

from xss_security_gui.threat_data_loader import ThreatDataLoader
from xss_security_gui.threat_tab import ThreatAnalysisTab

logger = logging.getLogger(__name__)


class CombatResultsTab(ttk.Frame):
    """
    GUI вкладка для відображення результатів боєвих атак.
    Потокобезпечна, оновлюється в реальному часі.
    """

    SEVERITY_TAGS = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "info",
        "info": "info",
        "unknown": "info",
    }

    def __init__(
        self,
        parent,
        result_queue: Optional[queue.Queue] = None,
        on_stop: Optional[Callable[[], None]] = None,
        threat_tab: Optional[ThreatAnalysisTab] = None,
        **kwargs,
    ):
        super().__init__(parent, **kwargs)

        # Queue + інтеграція
        self.result_queue = result_queue or queue.Queue()
        self.on_stop = on_stop
        self.threat_tab = threat_tab

        # Root для after()
        tk_root = parent
        while hasattr(tk_root, "master") and tk_root.master:
            tk_root = tk_root.master
        self.tk_root = tk_root

        # Стан
        self.is_running = False
        self.current_progress = 0
        self._monitor_running = False
        self._last_stats: Dict[str, Any] = {}
        self._last_combat_summary: Dict[str, Any] = {}
        self._artifact_cache = set()

        # UI
        self._build_ui()
        self._init_handlers()
        self._start_queue_monitor()

    # ============================================================
    #  UI
    # ============================================================

    def _build_ui(self):
        """Побудова UI — 3 колонки + прогрес + кнопки."""

        # Заголовок
        header = ttk.Frame(self)
        header.pack(fill="x", padx=10, pady=10)

        ttk.Label(
            header,
            text="🎯 БОЕВЫЕ АТАКИ — Результаты",
            font=("Helvetica", 14, "bold"),
        ).pack(side="left")

        self.status_label = ttk.Label(
            header,
            text="🔴 Ожидание...",
            font=("Helvetica", 10),
        )
        self.status_label.pack(side="right")

        # Прогрес
        progress_frame = ttk.Frame(self)
        progress_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(progress_frame, text="Прогресс:").pack(side="left", padx=5)

        self.progress_bar = ttk.Progressbar(
            progress_frame,
            mode="determinate",
            length=300,
            orient="horizontal",
        )
        self.progress_bar.pack(side="left", fill="x", expand=True, padx=5)

        self.progress_label = ttk.Label(progress_frame, text="0%", width=5)
        self.progress_label.pack(side="left", padx=5)

        # Основний контейнер (3 колонки)
        main_container = ttk.PanedWindow(self, orient="horizontal")
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Лева колонка — Events
        left_frame = ttk.LabelFrame(main_container, text="📋 События", width=250)
        main_container.add(left_frame, weight=1)

        left_scroll_y = ttk.Scrollbar(left_frame, orient="vertical")
        left_scroll_y.pack(side="right", fill="y")

        self.events_text = tk.Text(
            left_frame,
            height=20,
            width=25,
            yscrollcommand=left_scroll_y.set,
            bg="#1e1e1e",
            fg="#00ff00",
            font=("Courier", 8),
        )
        self.events_text.pack(side="left", fill="both", expand=True)
        left_scroll_y.config(command=self.events_text.yview)

        # Середня колонка — Results
        mid_frame = ttk.LabelFrame(main_container, text="🎯 Результаты Атак", width=300)
        main_container.add(mid_frame, weight=2)

        self.results_text = scrolledtext.ScrolledText(
            mid_frame,
            height=20,
            bg="#1a1a1a",
            fg="#ffffff",
            font=("Courier", 8),
            relief="flat",
        )
        self.results_text.pack(side="left", fill="both", expand=True)

        for tag, color in {
            "critical": "#ff0000",
            "high": "#ff9900",
            "medium": "#ffff00",
            "info": "#00ff00",
        }.items():
            self.results_text.tag_config(tag, foreground=color, font=("Courier", 8, "bold"))

        # Права колонка — Stats
        right_frame = ttk.LabelFrame(main_container, text="📊 Статистика", width=250)
        main_container.add(right_frame, weight=1)

        right_scroll_y = ttk.Scrollbar(right_frame, orient="vertical")
        right_scroll_y.pack(side="right", fill="y")

        self.stats_text = tk.Text(
            right_frame,
            height=20,
            width=25,
            yscrollcommand=right_scroll_y.set,
            bg="#0a0a0a",
            fg="#00ffff",
            font=("Courier", 8),
        )
        self.stats_text.pack(side="left", fill="both", expand=True)
        right_scroll_y.config(command=self.stats_text.yview)

        # Кнопки
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=10, pady=10)

        ttk.Button(btn_frame, text="🗑️ Очистить", command=self._clear_display).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="💾 Экспортировать", command=self._export_results).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="❌ Остановить", command=self._stop_combat).pack(side="left", padx=5)

    def _init_handlers(self):
        """Реєстрація хендлерів подій."""
        self._handlers: Dict[str, Callable[[Dict[str, Any]], None]] = {
            "progress": self._handle_progress,
            "attack_result": self._handle_attack_result,
            "crawl_complete": self._handle_crawl_complete,
            "attacks_complete": self._handle_attacks_complete,
            "combat_complete": self._handle_combat_complete,
        }

    # ============================================================
    #  QUEUE MONITOR
    # ============================================================

    def _start_queue_monitor(self):
        """Запуск монітора черги результатів."""
        self._monitor_running = True

        def monitor():
            while self._monitor_running:
                try:
                    event = self.result_queue.get(timeout=1)
                except queue.Empty:
                    continue
                except Exception as e:
                    logger.exception("Queue monitor error: %s", e)
                    break

                if not self.tk_root.winfo_exists():
                    break

                try:
                    self.tk_root.after(0, self._process_event, event)
                except Exception as e:
                    logger.exception("Error scheduling event processing: %s", e)
                    break

        threading.Thread(
            target=monitor,
            daemon=True,
            name="CombatResultsQueueMonitor",
        ).start()

    def destroy(self):
        """Коректне завершення монітора."""
        self._monitor_running = False
        super().destroy()

    # ============================================================
    #  THREAT INTEL INTEGRATION
    # ============================================================

    def _emit_threat_artifact(self, data: Dict[str, Any]):
        """
        Створити артефакт загрози і відправити в Threat Intel.
        - валідація
        - анти‑дублікатор
        - нормалізація через ThreatDataLoader
        - потокобезпечне додавання в ThreatAnalysisTab
        """

        if not self.threat_tab:
            logger.warning("Threat artifact skipped: threat_tab is None")
            return

        try:
            attack_type = str(data.get("attack_type", "UNKNOWN"))
            endpoint = str(data.get("endpoint", "")).strip()
            severity_raw = str(data.get("severity", "info")).lower()
            vulnerable = bool(data.get("vulnerable", False))
            payload = data.get("payload", "")

            if not endpoint:
                logger.warning("Threat artifact skipped: empty endpoint")
                return

            sev = severity_raw if vulnerable else "info"
            risk = sev

            unique_key = f"{attack_type}:{endpoint}:{sev}:{payload}"
            unique_hash = hash(unique_key)

            if unique_hash in self._artifact_cache:
                logger.info("Duplicate combat artifact skipped: %s", unique_key)
                return

            self._artifact_cache.add(unique_hash)

            artifact = {
                "module": "CombatEngine",
                "target": endpoint,
                "timestamp": datetime.now().isoformat(),
                "result": {
                    "severity": sev,
                    "category": "combat_attack",
                    "source": "combat_tab",
                    "type": attack_type,
                    "risk": risk,
                    "url": endpoint,
                    "payload": payload,
                    "tags": [
                        "combat",
                        "live_attack",
                        attack_type.lower(),
                        f"severity_{sev}",
                    ],
                },
            }

            loader = ThreatDataLoader()
            gui_artifact = loader.convert_artifact_for_gui(artifact)
            if not gui_artifact:
                logger.error("ThreatDataLoader returned None for artifact: %s", artifact)
                return

            bridge = getattr(self.threat_tab, "_bridge", None)
            if bridge:
                bridge.post_ui(self.threat_tab.add_threat, gui_artifact)
            else:
                self.threat_tab.after(0, self.threat_tab.add_threat, gui_artifact)

            logger.info(
                "Combat artifact emitted: type=%s risk=%s endpoint=%s",
                attack_type, risk, endpoint
            )

        except Exception as e:
            logger.exception("Fatal error emitting threat artifact: %s", e)

    # ============================================================
    #  EVENT PROCESSING
    # ============================================================

    def _process_event(self, event: Dict[str, Any]):
        """Центральний диспетчер подій Combat Engine."""
        event_type = event.get("type", "unknown")
        timestamp = event.get("timestamp", "")

        handler = self._handlers.get(event_type, self._handle_generic_event)
        try:
            handler(event)
        except Exception as e:
            logger.exception("Error handling event %s: %s", event_type, e)

        ts = timestamp.split("T")[1][:8] if "T" in timestamp else timestamp
        self.events_text.insert("end", f"[{ts}] {event_type}\n")
        self.events_text.see("end")

    def _handle_progress(self, event: Dict[str, Any]):
        data = event.get("data", {}) or {}
        msg = event.get("message", "") or data.get("message", "")
        progress = int(event.get("progress", data.get("progress", 0)))

        self.current_progress = progress
        self.progress_bar["value"] = progress
        self.progress_label.config(text=f"{progress}%")
        self.status_label.config(text=msg or "Combat progress...")

    def _handle_attack_result(self, event: Dict[str, Any]):
        data = event.get("data", {}) or {}

        attack_type = data.get("attack_type", "UNKNOWN")
        vulnerable = bool(data.get("vulnerable", False))
        severity_raw = str(data.get("severity", "info"))
        endpoint = str(data.get("endpoint", ""))

        sev = severity_raw.lower()
        tag = self.SEVERITY_TAGS.get(sev, "info")

        icon = "🔴 УЯЗВИМ" if vulnerable else "🟢"
        line = f"{icon} [{attack_type}] {endpoint[:80]} ({sev.upper()})\n"

        self.results_text.insert("end", line, tag)
        self.results_text.see("end")

        if vulnerable:
            self._emit_threat_artifact(data)

    def _handle_crawl_complete(self, event: Dict[str, Any]):
        data = event.get("data", {}) or {}

        text = "\n=== ЭТАП 1: КРАУЛИНГ ===\n"
        text += f"📍 Страниц найдено: {data.get('pages_found', 0)}\n"
        text += f"📜 Скриптов найдено: {data.get('scripts_found', 0)}\n"
        text += f"🔗 Endpoints найдено: {data.get('endpoints_found', 0)}\n"
        text += f"📊 Статус: {data.get('status', 'UNKNOWN')}\n"
        text += f"⭐ Качество: {data.get('quality_score', 0)}%\n"

        self.stats_text.insert("end", text)
        self.stats_text.see("end")

    def _handle_attacks_complete(self, event: Dict[str, Any]):
        data = event.get("data", {}) or {}
        self._last_stats = data

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
        data = event.get("data", {}) or {}
        vuln_summary = data.get("vulnerability_summary", {}) or {}
        self._last_combat_summary = vuln_summary

        # ==== PII / Account Intelligence ====
        email = data.get("email") or "—"
        password = data.get("password") or "—"
        phone = data.get("phone") or "—"
        credit_card = data.get("credit_card") or "—"

        text = "\n=== ФИНАЛЬНЫЙ ОТЧЁТ ===\n"
        text += f"🎯 Риск-уровень: {vuln_summary.get('risk_level', 'UNKNOWN')}\n"
        text += f"🔴 CRITICAL: {vuln_summary.get('critical', 0)}\n"
        text += f"🟠 HIGH: {vuln_summary.get('high', 0)}\n"
        text += f"🟡 MEDIUM: {vuln_summary.get('medium', 0)}\n"
        text += f"🟢 LOW: {vuln_summary.get('low', 0)}\n"
        text += f"📊 ВСЕГО: {vuln_summary.get('total', 0)}\n"

        # === PII / Account Intelligence ===
        text += "\n=== PII / Account Intelligence ===\n"
        text += f"📧 Email: {email}\n"
        text += f"🔐 Password: {password}\n"
        text += f"📱 Phone: {phone}\n"
        text += f"💳 Card: {credit_card}\n"

        text += "\n✅ БОЕВОЙ ЦИКЛ ЗАВЕРШЁН\n"

        self.stats_text.insert("end", text)
        self.stats_text.see("end")

        self.status_label.config(text="✅ ГОТОВО")

        # === Emit artifact to Threat Tab ===
        if self.threat_tab:
            try:
                artifact = {
                    "module": "CombatEngine",
                    "target": "",
                    "timestamp": datetime.now().isoformat(),
                    "result": {
                        "severity": vuln_summary.get("risk_level", "unknown"),
                        "category": "combat_summary",
                        "source": "combat_tab",
                        "type": "combat_cycle",
                        "risk": vuln_summary.get("risk_level", "unknown"),
                        "url": "",
                        "payload": "",
                        "tags": ["combat", "summary", "live_attack"],
                        "summary": vuln_summary,
                        "email": email,
                        "password": password,
                        "phone": phone,
                        "credit_card": credit_card,
                    },
                }

                loader = ThreatDataLoader()
                gui_artifact = loader.convert_artifact_for_gui(artifact)

                bridge = getattr(self.threat_tab, "_bridge", None)
                if bridge:
                    bridge.post_ui(self.threat_tab.add_threat, gui_artifact)
                else:
                    self.threat_tab.after(0, self.threat_tab.add_threat, gui_artifact)

            except Exception as e:
                logger.exception("Error emitting combat summary artifact: %s", e)

    def _handle_generic_event(self, event: Dict[str, Any]):
        event_type = event.get("type", "unknown")
        self.results_text.insert("end", f"[{event_type}] Event received\n", "info")
        self.results_text.see("end")

    # ============================================================
    #  ACTIONS
    # ============================================================

    def _clear_display(self):
        self.events_text.delete("1.0", "end")
        self.results_text.delete("1.0", "end")
        self.stats_text.delete("1.0", "end")
        self.progress_bar["value"] = 0
        self.progress_label.config(text="0%")
        self.status_label.config(text="🔴 Ожидание...")
        self._last_stats = {}
        self._last_combat_summary = {}
        self._artifact_cache.clear()

    def _stop_combat(self):
        """
        Остановить боевой цикл:
        - оновити статус
        - відправити сигнал у чергу
        - викликати on_stop, якщо задано
        """
        self.status_label.config(text="⏸️ Остановка...")

        try:
            self.result_queue.put({
                "type": "stop_requested",
                "timestamp": datetime.now().isoformat(),
            })
        except Exception as e:
            logger.warning("Failed to put stop_requested into result_queue: %s", e)

        if self.on_stop:
            try:
                self.on_stop()
            except Exception as e:
                logger.exception("Error in on_stop callback: %s", e)

    def _export_results(self):
        try:
            from xss_security_gui.settings import LOG_DIR
        except Exception:
            LOG_DIR = "logs"

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_txt_path = Path(LOG_DIR) / f"combat_export_{ts}.txt"
        export_json_path = Path(LOG_DIR) / f"combat_export_{ts}.json"
        export_txt_path.parent.mkdir(parents=True, exist_ok=True)

        export_data = {
            "timestamp": datetime.now().isoformat(),
            "events": self.events_text.get("1.0", "end"),
            "results": self.results_text.get("1.0", "end"),
            "statistics_text": self.stats_text.get("1.0", "end"),
            "stats_struct": self._last_stats,
            "combat_summary": self._last_combat_summary,
        }

        try:
            with export_txt_path.open("w", encoding="utf-8") as f:
                f.write("=== БОЕВЫЕ АТАКИ - ЭКСПОРТ РЕЗУЛЬТАТОВ ===\n")
                f.write(f"Время: {export_data['timestamp']}\n\n")

                f.write("=== СОБЫТИЯ ===\n")
                f.write(export_data["events"])
                f.write("\n")

                f.write("=== РЕЗУЛЬТАТЫ ===\n")
                f.write(export_data["results"])
                f.write("\n")

                f.write("=== СТАТИСТИКА (ТЕКСТ) ===\n")
                f.write(export_data["statistics_text"])
                f.write("\n")

                f.write("=== СТАТИСТИКА (СТРУКТУРА) ===\n")
                f.write(json.dumps(export_data["stats_struct"], ensure_ascii=False, indent=2))
                f.write("\n")

                f.write("=== ФИНАЛЬНЫЙ ОТЧЁТ ===\n")
                f.write(json.dumps(export_data["combat_summary"], ensure_ascii=False, indent=2))
                f.write("\n")

            with export_json_path.open("w", encoding="utf-8") as jf:
                json.dump(export_data, jf, ensure_ascii=False, indent=2)

            self.status_label.config(text=f"✅ Экспортировано: {export_txt_path.name}")
            logger.info("Combat results exported to %s and %s", export_txt_path, export_json_path)

        except Exception as e:
            self.status_label.config(text=f"❌ Ошибка экспорта: {e}")
            logger.exception("Combat export error: %s", e)




