# xss_security_gui/gui/attack_gui.py

import logging
import os
import threading
import json
from datetime import datetime
from typing import Callable, Dict, Any, Optional


from xss_security_gui import DIRS

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit,
    QProgressBar, QLabel, QHBoxLayout, QFileDialog, QMessageBox, QTabWidget, QTreeWidget, QTreeWidgetItem
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject

from xss_security_gui.attack_engine import AttackEngine
from xss_security_gui.mutator_task_manager import MutatorTaskManager
from xss_security_gui.gui.mutator_tasks_panel import MutatorTasksPanel
from xss_security_gui.payload_mutator import mutate_task
from xss_security_gui.mutation_queue import MUTATION_ATTACK_QUEUE


class GuiSignals(QObject):
    """
    Потокобезопасные сигналы для обновления GUI из фонового потока.
    """
    log: pyqtSignal = pyqtSignal(str, str)             # msg, level
    status: pyqtSignal = pyqtSignal(str)               # статусная строка
    progress_set_max: pyqtSignal = pyqtSignal(int)     # максимум прогресса
    progress_set_val: pyqtSignal = pyqtSignal(int)     # текущее значение прогресса
    progress_inc: pyqtSignal = pyqtSignal()            # инкремент прогресса


class AttackGUI(QWidget):
    """
    Графический интерфейс для запуска автоатак с визуализацией прогресса.
    """

    def __init__(self, domain: str,
                 threat_sender: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        super().__init__()

        self.domain = domain
        self.threat_sender = threat_sender or (lambda *a, **kw: None)

        self.setWindowTitle("AutoRecon 3.0 — Attack GUI")
        self.setMinimumSize(900, 600)

        # === Виджеты ===
        self.title = QLabel(f"Цель: {self.domain}")
        self.title.setAlignment(Qt.AlignLeft)

        self.progress = QProgressBar()
        self.progress.setMinimum(0)
        self.progress.setMaximum(5)
        self.progress.setValue(0)

        self.status_label = QLabel("Статус: ожидание")
        self.status_label.setAlignment(Qt.AlignLeft)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)

        self.btn_load_crawl = QPushButton("📂 Загрузить deep_crawl.json")
        self.btn_run_attack = QPushButton("🧨 Запустить автоатаку")
        self.btn_stop_attack = QPushButton("⏹️ Остановить атаку")
        self.btn_export_results = QPushButton("💾 Экспорт результатов")
        self.btn_send_summary = QPushButton("📤 Отправить сводку в Threat Intel")

        # === Tabs (включая Mutator Tasks) ===
        self.tabs = QTabWidget()
        self.mutator_manager = MutatorTaskManager()
        self.mutator_panel = MutatorTasksPanel(self.mutator_manager)
        # === Таблица XSS‑результатов ===
        self.xss_tree = QTreeWidget()
        self.xss_tree.setColumnCount(5)
        self.xss_tree.setHeaderLabels(["URL", "Статус", "Reflected", "Length", "Payload"])
        self.xss_tree.setAlternatingRowColors(True)
        self.xss_tree.setRootIsDecorated(False)
        self.tabs.addTab(self.mutator_panel, "Mutator Tasks")

        # === Layout ===
        top_bar = QHBoxLayout()
        top_bar.addWidget(self.title)
        top_bar.addStretch()
        top_bar.addWidget(self.status_label)

        btn_bar = QHBoxLayout()
        btn_bar.addWidget(self.btn_load_crawl)
        btn_bar.addWidget(self.btn_run_attack)
        btn_bar.addWidget(self.btn_stop_attack)
        btn_bar.addWidget(self.btn_export_results)
        btn_bar.addWidget(self.btn_send_summary)

        layout = QVBoxLayout()
        layout.addLayout(top_bar)
        layout.addWidget(self.progress)
        layout.addLayout(btn_bar)
        layout.addWidget(self.log_output)
        layout.addWidget(self.tabs)
        self.setLayout(layout)

        # === Состояние ===
        self.engine = AttackEngine(
            self.domain,
            threat_sender=self._send_to_threat_intel,
            log_func=self._log_proxy
        )
        self._start_mutation_worker()

        self.crawl_json: Dict[str, Any] = {}
        self._module_count = 5
        self._completed_modules = 0
        self._attack_thread: Optional[threading.Thread] = None
        self._stop_requested = False
        self.mutation_count = 0
        self.mutation_hits = 0

        # === Сигналы ===
        self.signals: GuiSignals = GuiSignals()

        self.signals.log.connect(self._on_log_signal)
        self.signals.status.connect(self._on_status_signal)
        self.signals.progress_set_max.connect(self.progress.setMaximum)
        self.signals.progress_set_val.connect(self.progress.setValue)
        self.signals.progress_inc.connect(self._increment_progress)

        self.btn_load_crawl.clicked.connect(self._on_load_crawl)
        self.btn_run_attack.clicked.connect(self._on_run_attack_threaded)
        self.btn_stop_attack.clicked.connect(self._on_stop_attack)
        self.btn_export_results.clicked.connect(self._on_export_results)
        self.btn_send_summary.clicked.connect(self._on_send_summary)

        # Таймер для отзывчивости GUI
        self.ui_timer = QTimer(self)
        self.ui_timer.setInterval(250)
        self.ui_timer.timeout.connect(lambda: None)
        self.ui_timer.start()

    # === Потокобезопасный лог-прокси ===
    def _log_proxy(self, msg: str, level: str = "info") -> None:
        self.signals.log.emit(msg, level)

        if any(k in msg.lower() for k in ["модуль завершён", "завершён", "завершена"]):
            self.signals.progress_inc.emit()

    # === Threat Intel ===
    def _send_to_threat_intel(self, attack_type: str, data: Dict[str, Any]) -> None:
        """
        Унифицированная отправка событий в Threat Intel (ULTRA 6.x)
        attack_type → module
        data → result
        """
        try:
            self.threat_sender(
                module=attack_type,
                target=data.get("target", self.domain),
                result=data
            )
        except Exception as e:
            self.signals.log.emit(
                f"❌ Ошибка Threat Intel: {type(e).__name__}: {e}",
                "error"
            )

    def _start_mutation_worker(self):
        """
        Запускает отдельный поток, который:
        • слушает очередь MUTATION_ATTACK_QUEUE
        • выполняет атаки мутантами
        • обновляет GUI
        """
        t = threading.Thread(
            target=self._mutation_worker,
            daemon=True,
            name="MutationWorkerThread"
        )
        t.start()


    # === Обработчики сигналов ===
    def _on_log_signal(self, msg: str, level: str = "info") -> None:
        self.log_output.append(f"[{level.upper()}] {msg}")

    def _on_status_signal(self, text: str) -> None:
        self.status_label.setText(text)

    def _on_send_summary(self) -> None:
        """
        Safe placeholder for sending summary report.
        """
        try:
            QMessageBox.information(
                self,
                "Отправка сводки",
                "Функция отправки сводного отчёта пока не реализована."
            )
            logging.info("Пользователь нажал 'Отправить сводку'. Функция не реализована.")
        except Exception as e:
            logging.error(f"Ошибка в _on_send_summary: {e}", exc_info=True)

    # === Прогресс ===
    def _increment_progress(self) -> None:
        self._completed_modules = min(self._module_count, self._completed_modules + 1)
        self.progress.setValue(self._completed_modules)

    def _reset_progress(self, count: int) -> None:
        self._module_count = count
        self._completed_modules = 0
        self.signals.progress_set_max.emit(count)
        self.signals.progress_set_val.emit(0)

    # === Загрузка deep_crawl.json ===
    def _on_load_crawl(self) -> None:
        default_dir = DIRS["logs"]

        path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите deep_crawl.json",
            default_dir,
            "JSON Files (*.json)"
        )

        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                self.crawl_json = json.load(f)

            self.signals.log.emit(f"📂 Загружен deep_crawl.json: {path}", "info")

        except Exception as e:
            self.signals.log.emit(
                f"❌ Ошибка загрузки deep_crawl.json: {type(e).__name__}: {e}",
                "error"
            )

    def _mutation_worker(self):
        """
        Основной Mutation→Attack pipeline:
        • получает мутант из очереди
        • вызывает AutoAttackEngine
        • логирует
        • обновляет таблицу XSS‑результатов
        • безопасен к ошибкам
        """
        while True:
            try:
                # (priority, task)
                priority, task = MUTATION_ATTACK_QUEUE.get()

                category = task["category"]
                payload = task["payload"]
                framework = task.get("framework", "generic")

                # URL берём из GUI
                url = getattr(self, "url_entry", None)
                if url:
                    url = url.text().strip()
                if not url:
                    url = getattr(self, "default_url", self.domain)

                # Выполняем атаку
                result = self.engine.attack_payload(url, payload)
                # === ЭФФЕКТИВНОСТЬ МУТАЦИЙ ===
                # Инициализация счётчиков, если их ещё нет
                if not hasattr(self, "mutation_count"):
                    self.mutation_count = 0
                if not hasattr(self, "mutation_hits"):
                    self.mutation_hits = 0

                self.mutation_count += 1
                if result.get("reflected"):
                    self.mutation_hits += 1

                # Обновляем статусную строку
                self.signals.status.emit(
                    f"Mutations: {self.mutation_count} | Hits: {self.mutation_hits}"
                )

                # Лог в GUI
                status = result.get("status")
                self.signals.log.emit(
                    f"[Mutator→Attack][prio={priority}] {payload} → {status}",
                    "info"
                )

                # Обновление таблицы XSS‑результатов
                self._add_xss_result(
                    url=url,
                    status=status,
                    reflected=result.get("reflected"),
                    length=result.get("length"),
                    payload=payload
                )

            except Exception as e:
                self.signals.log.emit(
                    f"❌ Ошибка в Mutation Worker: {type(e).__name__}: {e}",
                    "error"
                )

    def _add_xss_result(self, url, status, reflected, length, payload):
        try:
            tag = "reflected" if reflected else "clean"
            self.xss_tree.insert(
                "",
                "end",
                values=(url, status, reflected, length, payload),
                tags=(tag,)
            )
        except Exception as e:
            self.signals.log.emit(
                f"❌ Ошибка добавления результата XSS: {e}",
                "error"
            )

    def _on_export_results(self) -> None:
        """
        Export attack results with multiple format options.
        """
        try:
            export_dir = DIRS.get("exports", DIRS.get("logs", "."))
            os.makedirs(export_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"attack_results_{self.domain}_{timestamp}"

            export_formats = {
                "JSON (*.json)": f"{base_filename}.json",
                "CSV (*.csv)": f"{base_filename}.csv",
                "Text (*.txt)": f"{base_filename}.txt"
            }

            filename, selected_filter = QFileDialog.getSaveFileName(
                self,
                "Экспорт результатов атаки",
                os.path.join(export_dir, base_filename),
                ";;".join(export_formats.keys())
            )

            if not filename:
                return

            export_format = selected_filter.split()[0].lower()

            if export_format == "json":
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(self.engine.get_attack_results(), f, indent=2, ensure_ascii=False)

            elif export_format == "csv":
                results = self.engine.get_attack_results()
                with open(filename, "w", encoding="utf-8") as f:
                    f.write("key,value\n")
                    for item in results:
                        for k, v in item.items():
                            f.write(f"{k},{v}\n")

            elif export_format == "text":
                results = self.engine.get_attack_results()
                with open(filename, "w", encoding="utf-8") as f:
                    for item in results:
                        f.write(str(item) + "\n")

        except Exception as e:
            logging.error(f"Ошибка экспорта результатов: {e}", exc_info=True)

    # === Запуск атаки ===
    def _on_run_attack_threaded(self) -> None:
        if self._attack_thread and self._attack_thread.is_alive():
            QMessageBox.warning(self, "Выполняется", "Атака уже выполняется. Дождитесь завершения.")
            return

        if not self.crawl_json:
            self.signals.log.emit("⚠️ deep_crawl.json не загружен. Использую минимальные данные.", "warn")
            self.crawl_json = {"visited": [self.domain]}

        self._stop_requested = False
        self._reset_progress(count=5)
        self.signals.status.emit("Статус: выполняется…")
        self.signals.log.emit("🧨 Запуск автоатаки в фоне…", "info")

        self._attack_thread = threading.Thread(target=self._run_attack_background, daemon=True)
        self._attack_thread.start()

    def _on_stop_attack(self) -> None:
        if self._attack_thread and self._attack_thread.is_alive():
            self._stop_requested = True
            self.signals.status.emit("Статус: остановка запрошена…")
            self.signals.log.emit("⏹️ Остановка атаки…", "warn")
        else:
            self.signals.log.emit("⚠️ Нет активной атаки для остановки.", "warn")

    # === Фоновая атака ===
    def _run_attack_background(self) -> None:
        try:
            from xss_security_gui import LOGS_DIR
            from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
            from xss_security_gui.payloads import PAYLOADS

            self.engine.log_func = self._log_proxy

            deep_crawl_path = os.path.join(LOGS_DIR, "deep_crawl.json")

            if os.path.exists(deep_crawl_path):
                try:
                    with open(deep_crawl_path, "r", encoding="utf-8") as f:
                        raw = json.load(f)

                    self.crawl_json.update(raw.get("pages", {}))
                    scripts = list(self.crawl_json.get("js_insights", {}).values())
                    self.crawl_json["scripts"] = scripts

                    self.signals.log.emit(
                        f"📌 Загружено JS-скриптов: {len(scripts)}",
                        "info"
                    )

                except Exception as e:
                    self.signals.log.emit(
                        f"⚠️ Ошибка чтения deep_crawl.json: {e}",
                        "warn"
                    )
                    self.crawl_json.setdefault("scripts", [])
            else:
                self.signals.log.emit(
                    f"⚠️ Файл deep_crawl.json не найден по пути: {deep_crawl_path}",
                    "warn"
                )
                self.crawl_json.setdefault("scripts", [])

            base_visited = self.crawl_json.get("visited", [self.domain])

            modules = [
                ("API Endpoints", {
                    "visited": base_visited,
                    "api_endpoints": self.crawl_json.get("api_endpoints", []),
                }, "api_endpoints"),

                ("Token Brute Force", {
                    "visited": base_visited,
                    "tokens": self.crawl_json.get("tokens", []),
                }, "tokens"),

                ("Parameters Discovery", {
                    "visited": base_visited,
                    "parameters": self.crawl_json.get("parameters", []),
                }, "parameters"),

                ("User IDs Enumeration", {
                    "visited": base_visited,
                    "user_ids": self.crawl_json.get("user_ids", []),
                }, "user_ids"),

                ("XSS Targets", {
                    "visited": base_visited,
                    "xss_targets": self.crawl_json.get("xss_targets", []),
                }, "xss_targets"),

                ("GraphQL Endpoints", {
                    "visited": base_visited,
                    "graphql": self.crawl_json.get("graphql", []),
                }, "graphql"),

                ("JS Sensitive Analysis", {
                    "visited": base_visited,
                    "scripts": self.crawl_json.get("scripts", []),
                }, "js_insights"),

                ("Security Headers Review", {
                    "visited": base_visited,
                    "headers": self.crawl_json.get("headers", []),
                }, "headers"),

                ("CSP Weakness Scan", {
                    "visited": base_visited,
                    "csp": self.crawl_json.get("csp_analysis", []),
                }, "csp_analysis"),

                ("Secrets & Keys", {
                    "visited": base_visited,
                    "secrets": self.crawl_json.get("secrets", []),
                    "api_keys": self.crawl_json.get("api_keys", []),
                }, "secrets"),

                ("JWT Tokens", {
                    "visited": base_visited,
                    "jwt_tokens": self.crawl_json.get("jwt_tokens", []),
                }, "jwt_tokens"),

                ("Forms & Inputs", {
                    "visited": base_visited,
                    "forms": self.crawl_json.get("forms", []),
                    "input_fields": self.crawl_json.get("input_fields", []),
                }, "forms"),

                ("Error Pages & Stacktraces", {
                    "visited": base_visited,
                    "errors": self.crawl_json.get("errors", []),
                }, "errors"),
            ]

            total_modules = len(modules)

            for idx, (name, payload, artifact_key) in enumerate(modules, start=1):

                if self._stop_requested:
                    self.signals.status.emit("Статус: остановлено пользователем")
                    self.signals.log.emit(f"⏹️ Атака прервана на модуле {name}", "warn")
                    return

                self.signals.status.emit(
                    f"Статус: выполняется {idx}/{total_modules} — {name}"
                )
                self.signals.log.emit(f"▶️ Запуск модуля: {name}", "info")

                try:
                    self.engine.run_modular_auto_attack(payload)

                    # Автоматическая генерация мутантов для каждого XSS Target
                    if name == "XSS Targets":
                        xss_targets = self.crawl_json.get("xss_targets", [])
                        # ожидаем список структур, где есть payload или raw_payload
                        for target in xss_targets:
                            base_payload = None
                            if isinstance(target, dict):
                                base_payload = target.get("payload") or target.get("raw_payload")
                            elif isinstance(target, str):
                                base_payload = target

                            if not base_payload:
                                continue

                            self.mutator_manager.submit(
                                mutate_task,
                                "Reflected",
                                base_payload,
                                "generic"
                            )

                    artifacts = []
                    data = self.crawl_json.get(artifact_key, [])

                    if isinstance(data, dict):
                        for target, items in data.items():
                            artifacts.append({
                                "severity": "info",
                                "category": artifact_key,
                                "source": name,
                                "items": items,
                            })
                            THREAT_CONNECTOR.bulk(
                                module=name,
                                target=target,
                                results=[artifacts[-1]],
                            )
                    elif isinstance(data, list):
                        artifacts.append({
                            "severity": "info",
                            "category": artifact_key,
                            "source": name,
                            "items": data,
                        })
                        THREAT_CONNECTOR.emit(
                            module=name,
                            target=self.domain,
                            result=artifacts[-1],
                        )

                    self.signals.log.emit(f"✔️ Модуль {name} завершён", "info")
                    self.signals.progress_inc.emit()

                except Exception as mod_err:
                    self.signals.log.emit(
                        f"❌ Ошибка в модуле {name}: {mod_err}",
                        "error"
                    )
                    THREAT_CONNECTOR.emit(
                        module=f"{name} (error)",
                        target=self.domain,
                        result={
                            "severity": "error",
                            "category": "auto_attack",
                            "source": "GUI",
                            "message": str(mod_err),
                        },
                    )
                    continue

            try:
                self.engine.export_results()
                self.engine.send_summary_to_threat_intel()
                PAYLOADS.export_stats_to_threat_intel()
            except Exception as export_err:
                self.signals.log.emit(
                    f"⚠️ Ошибка экспорта/Threat Intel: {export_err}",
                    "warn"
                )
                THREAT_CONNECTOR.emit(
                    module="Export/ThreatIntel",
                    target=self.domain,
                    result={
                        "severity": "warn",
                        "category": "export",
                        "source": "GUI",
                        "message": str(export_err),
                    },
                )

            self.signals.status.emit("Статус: завершено")
            self.signals.log.emit("✔️ Автоатака завершена полностью.", "info")
            self.signals.progress_set_val.emit(self._module_count)

        except Exception as e:
            self.signals.status.emit("Статус: ошибка")
            self.signals.log.emit(
                f"❌ Ошибка автоатаки: {type(e).__name__}: {e}",
                "error"
            )
            try:
                from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
                THREAT_CONNECTOR.emit(
                    module="AutoAttackEngine",
                    target=self.domain,
                    result={
                        "severity": "error",
                        "category": "engine",
                        "source": "GUI",
                        "message": f"{type(e).__name__}: {e}",
                    },
                )
            except Exception:
                pass