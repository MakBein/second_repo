# xss_security_gui/gui/attack_gui.py
import csv
import os
import threading
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from queue import Empty

import requests

from xss_security_gui.threat_analysis.sqli_worker import SQLiWorker
from xss_security_gui.threat_analysis.sqli_module import SQLiTester

from xss_security_gui import DIRS, settings
from xss_security_gui.attack_engine import AttackEngine
from xss_security_gui.core.waf_engine import WAFDetector, WAFType, HTTPEvasionWrapper
from xss_security_gui.mutator_task_manager import MutatorTaskManager
from xss_security_gui.gui.mutator_tasks_panel import MutatorTasksPanel
from xss_security_gui.mutation_queue import MUTATION_ATTACK_QUEUE
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge
from xss_security_gui.auto_modules.dom_and_endpoints import build_headers_list
from xss_security_gui.auto_modules.module_families import MODULE_FAMILIES



class AttackGUI(tk.Frame):
    """
    Графический интерфейс для запуска автоатак с визуализацией прогресса (Tkinter).
    """

    # Единый список модулей автоатаки (раньше дублировался в двух методах).
    MODULES = [
        "API Endpoints", "Token Brute Force", "Parameters Discovery", "User IDs Enumeration",
        "XSS Targets", "GraphQL Endpoints", "JS Sensitive Analysis", "Security Headers Review",
        "CSP Weakness Scan", "Secrets & Keys", "JWT Tokens", "Forms & Inputs", "Error Pages & Stacktraces",
    ]

    def __init__(self, parent, domain: str, threat_sender=None):
        super().__init__(parent)

        self._alive = True

        self.domain = domain
        self.threat_sender = threat_sender or (lambda *a, **kw: None)

        # === WAF Engine 14.0 ===
        self.waf_detector = WAFDetector()
        self.waf_evasion = HTTPEvasionWrapper()
        self._detected_waf: Optional[WAFType] = None
        self._waf_scan_running = False
        self._waf_max_attempts = int(settings.get("attack.waf_max_attempts", 8) or 8)
        self._waf_auto_scan = bool(settings.get("attack.waf_auto_scan", True))

        # === Заголовок и статус ===
        top_bar = ttk.Frame(self)
        top_bar.pack(fill="x", pady=5)

        self.title = ttk.Label(top_bar, text=f"Цель: {self.domain}")
        self.title.pack(side="left")

        self.waf_status_label = ttk.Label(top_bar, text="WAF: не проверен")
        self.waf_status_label.pack(side="right", padx=(0, 12))

        self.status_label = ttk.Label(top_bar, text="Статус: ожидание")
        self.status_label.pack(side="right")

        # === Прогресс ===
        self.progress = ttk.Progressbar(self, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(fill="x", padx=5, pady=5)

        # === Кнопки управления ===
        btn_bar = ttk.Frame(self)
        btn_bar.pack(fill="x", pady=5)

        self.btn_load_crawl = ttk.Button(btn_bar, text="📂 Загрузить deep_crawl.json", command=self._on_load_crawl)
        self.btn_load_crawl.pack(side="left", padx=2)

        self.btn_run_attack = ttk.Button(btn_bar, text="🧨 Запустить автоатаку", command=self._on_run_attack_threaded)
        self.btn_run_attack.pack(side="left", padx=2)

        self.btn_stop_attack = ttk.Button(btn_bar, text="⏹️ Остановить атаку", command=self._on_stop_attack)
        self.btn_stop_attack.pack(side="left", padx=2)

        self.btn_export_results = ttk.Button(btn_bar, text="💾 Экспорт результатов", command=self._on_export_results)
        self.btn_export_results.pack(side="left", padx=2)

        self.btn_send_summary = ttk.Button(btn_bar, text="📤 Отправить сводку", command=self._on_send_summary)
        self.btn_send_summary.pack(side="left", padx=2)

        self.btn_scan_waf = ttk.Button(btn_bar, text="🛡️ Scan WAF", command=self._on_scan_waf)
        self.btn_scan_waf.pack(side="left", padx=2)

        self._waf_evasion_var = tk.BooleanVar(
            value=bool(settings.get("attack.waf_evasion", settings.get("sqli.waf_evasion_default", True)))
        )
        ttk.Checkbutton(
            btn_bar,
            text="WAF Evasion",
            variable=self._waf_evasion_var,
        ).pack(side="left", padx=4)

        # === Лог вывода ===
        self.log_output = tk.Text(self, height=15, bg="#111", fg="lime")
        self.log_output.pack(fill="both", expand=True, padx=5, pady=5)

        # === Tabs (Mutator Tasks + XSS Results) ===
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True)

        self.mutator_manager = MutatorTaskManager()

        # Thread-safe мост обновлений GUI (нужен MutatorTasksPanel 9.0).
        self.ui_bridge = UIQueueBridge(self, poll_ms=80)

        # MutatorTasksPanel 9.0 требует ui_bridge и сам вешает колбеки менеджера
        # (on_task_added / started / finished / error) на свою отрисовку.
        self.mutator_panel = MutatorTasksPanel(
            self.tabs, self.mutator_manager, ui_bridge=self.ui_bridge
        )
        self.tabs.add(self.mutator_panel, text="Mutator Tasks")

        # Панель уже владеет on_task_finished. Оборачиваем его так, чтобы наша
        # вкладка «XSS Results» тоже получала результаты, не отбирая колбек у панели.
        _panel_finished = self.mutator_manager.on_task_finished

        def _chained_finished(task_id, result, _panel_cb=_panel_finished):
            if callable(_panel_cb):
                try:
                    _panel_cb(task_id, result)
                except Exception:
                    pass
            self._safe_call(self._on_mutator_task_finished, task_id, result)

        self.mutator_manager.on_task_finished = _chained_finished

        self.xss_tree = ttk.Treeview(
            self.tabs,
            columns=("url", "status", "reflected", "length", "payload"),
            show="headings"
        )
        for col in ("url", "status", "reflected", "length", "payload"):
            self.xss_tree.heading(col, text=col.capitalize())
        self.tabs.add(self.xss_tree, text="XSS Results")

        # === SQLi Results ===
        self.sqli_tree = ttk.Treeview(
            self.tabs,
            columns=("payload", "status", "code", "body_hit", "header_hit", "severity", "raw"),
            show="headings"
        )

        columns = [
            ("payload", "Payload", 300),
            ("status", "Status", 120),
            ("code", "HTTP Code", 80),
            ("body_hit", "Body Hit", 80),
            ("header_hit", "Header Hit", 80),
            ("severity", "Severity", 80),
            ("raw", "Raw Sample", 400),
        ]

        for col, text, width in columns:
            self.sqli_tree.heading(col, text=text)
            self.sqli_tree.column(col, width=width, anchor="w")

        self.tabs.add(self.sqli_tree, text="SQLi Results")

        # === WAF Intel ===
        self.waf_tree = ttk.Treeview(
            self.tabs,
            columns=("url", "waf_type", "confidence", "score", "success_rate", "attempts"),
            show="headings",
        )
        waf_columns = [
            ("url", "URL", 260),
            ("waf_type", "WAF", 160),
            ("confidence", "Confidence", 90),
            ("score", "Score", 70),
            ("success_rate", "Evasion %", 90),
            ("attempts", "Attempts", 80),
        ]
        for col, text, width in waf_columns:
            self.waf_tree.heading(col, text=text)
            self.waf_tree.column(col, width=width, anchor="w")
        self.waf_tree.tag_configure("detected", foreground="#ff6b6b")
        self.waf_tree.tag_configure("clean", foreground="#69db7c")
        self.tabs.add(self.waf_tree, text="WAF Intel")

        # === Состояние ===
        self.engine = AttackEngine(
            self.domain,
            threat_sender=self._send_to_threat_intel,
            log_func=self._log_proxy
        )

        # === SQLi Tester створюється тут (ПЕРШИМ) ===
        sqli_payloads = self._load_sqli_payloads()

        self.sqli_tester = SQLiTester(
            base_url=self.domain,
            param="id",
            base_value="1",
            payloads=sqli_payloads,
            output_callback=None
        )

        # === SQLi Worker створюється ТІЛЬКИ ПІСЛЯ тестера ===
        self.sqli_worker = SQLiWorker(self.sqli_tester)

        # === Mutator Worker ===
        self._start_mutation_worker()

        # === Запускаємо читання черги SQLi Worker ===
        self.after(50, self._poll_sqli_queue)

        self.crawl_json = {}
        self._attack_thread = None
        self._stop_requested = False
        self.mutation_count = 0
        self.mutation_hits = 0

        if self._waf_auto_scan:
            self.after(300, self._on_scan_waf)

    # === Потокобезопасные вызовы ===
    def _safe_call(self, fn, *args, **kwargs):
        if not self._alive:
            return
        if threading.current_thread() is threading.main_thread():
            try:
                fn(*args, **kwargs)
            except tk.TclError:
                pass  # виджет уже уничтожен
        else:
            try:
                self.after(0, lambda: fn(*args, **kwargs))
            except (tk.TclError, RuntimeError):
                pass  # after() после destroy()

    # === Лог-прокси ===
    def _log_proxy(self, msg: str, level: str = "info") -> None:
        self._safe_call(self.log_output.insert, "end", f"[{level.upper()}] {msg}\n")
        self._safe_call(self.log_output.see, "end")

    # === Threat Intel ===
    def _send_to_threat_intel(self, module=None, target=None, result=None, **kwargs):
        try:
            if module:
                self._safe_call(self._log_proxy, f"📡 Threat Intel: модуль={module}", "info")
            self.threat_sender(module=module, target=target, result=result, **kwargs)
        except Exception as e:
            self._safe_call(self._log_proxy, f"❌ Ошибка Threat Intel: {type(e).__name__}: {e}", "error")

    def _load_secrets(self) -> dict:
        """
        Загружает секреты только из безопасных источников (переменные окружения).
        Не хранит секреты в репозитории.
        """
        return {
            "api_key": os.environ.get("XSS_API_KEY"),
            "auth_token": os.environ.get("XSS_AUTH_TOKEN"),
            # добавьте другие ключи по необходимости, но не хардкодьте значения
        }

    def _on_task_added(self, task_id, payload):
        # Мутаторні задачі
        if isinstance(payload, dict) and "family" in payload:
            label = payload["payload"]
        else:
            # Модульні задачі
            label = str(payload)

        self.mutator_panel.add_task(task_id, label)

    def _load_sqli_payloads(self):
        path = os.path.join(DIRS.get("payloads", "."), "sqli.json") # r"C:\Users\sanch\PycharmProjects\itproger\xss_security_gui\payloads\sqli.json"

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)  # твій JSON з категоріями
                return data
        except Exception as e:
            self._safe_call(self._log_proxy, f"❌ Не удалось загрузить SQLi payloads: {e}", "error")
            return {"default": []}

    def _poll_sqli_queue(self):
        if not self._alive:
            return
        try:
            while True:
                event = self.sqli_worker.queue.get_nowait()
                self._handle_sqli_event(event)
        except Empty:
            pass
        except Exception as e:
            self._safe_call(self._log_proxy, f"❌ Ошибка чтения очереди SQLi: {e}", "error")

        if self._alive:
            try:
                self.after(50, self._poll_sqli_queue)
            except (tk.TclError, RuntimeError):
                pass

    def _handle_sqli_event(self, event):
        etype = event["type"]

        if etype == "result":
            self._safe_call(self._add_sqli_result, event)
            self._safe_call(self._log_proxy, f"[SQLi] Результат получен для payload: {event.get('payload')}", "info")

        elif etype == "error":
            self._safe_call(self._log_proxy, f"[SQLi ERROR] {event['error']}", "error")

        elif etype == "done":
            self._safe_call(self._log_proxy, "SQLi тестирование завершено", "info")

    def _on_mutator_task_finished(self, task_id, result):
        payload = result.get("payload")

        # Мутаторна задача
        if isinstance(payload, dict) and "family" in payload:
            label = payload["payload"]
            status = result.get("status")
            reflected = result.get("reflected")
            length = result.get("length")

            if reflected:
                self.mutation_hits += 1

            self._safe_call(
                self._add_xss_result,
                self.domain,
                status,
                reflected,
                length,
                label
            )

            self._safe_call(
                self._log_proxy,
                f"[Mutator DONE] {label} → {status}",
                "info"
            )

        else:
            # Модульна задача: MutatorTasksPanel 9.0 сам оновлює свій рядок через
            # on_task_finished. Тут лише логуємо підсумок (раніше був виклик
            # panel.update_task(task_id, <рядок>), але панель очікує dict-результат
            # і рядок призводив до AttributeError).
            module_name = payload
            count = result.get("count", 0)
            error = result.get("error")

            if error:
                final_status = f"🔴 Ошибка: {error}"
            else:
                final_status = f"🟢 Готово ({count} элементов)"

            self._safe_call(
                self._log_proxy,
                f"[Module DONE] {module_name} → {final_status}",
                "info",
            )

    def _add_sqli_result(self, event):
        payload = event.get("payload")
        status = event.get("status", "-")
        code = event.get("code", "-")
        body_hit = event.get("body_hit", False)
        header_hit = event.get("header_hit", False)
        severity = event.get("severity", "info")
        raw = event.get("raw", "")

        # Обрізаємо raw, щоб не ламати GUI
        if raw and len(raw) > 200:
            raw = raw[:200] + "..."

        self.sqli_tree.insert(
            "",
            "end",
            values=(payload, status, code, body_hit, header_hit, severity, raw)
        )

    def _start_mutation_worker(self):
        threading.Thread(target=self._mutation_worker, daemon=True).start()

    def _increment_progress(self):
        self.progress["value"] = min(self.progress["maximum"], self.progress["value"] + 1)

    def _reset_progress(self, count: int):
        self.progress["maximum"] = count
        self.progress["value"] = 0

    def _on_load_crawl(self):
        path = filedialog.askopenfilename(
            initialdir=DIRS["logs"],
            title="Выберите deep_crawl.json",
            filetypes=[("JSON Files", "*.json")]
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.crawl_json = json.load(f)
            self._safe_call(self._log_proxy, f"📂 Загружен deep_crawl.json: {path}", "info")
        except Exception as e:
            self._safe_call(self._log_proxy, f"❌ Ошибка загрузки deep_crawl.json: {type(e).__name__}: {e}", "error")

    def _mutation_worker(self):
        while self._alive and not getattr(self, "_stop_requested", False):
            try:
                item = MUTATION_ATTACK_QUEUE.get(timeout=1)
            except Empty:
                continue
            except Exception as e:
                self._safe_call(
                    self._log_proxy,
                    f"❌ Ошибка очереди мутаций: {type(e).__name__}: {e}",
                    "error"
                )
                continue

            # payload_mutator кладёт (priority, dict). Защищаемся от чужих форм
            # (напр. кортежей планировщика MutatorTaskManager), чтобы не падать
            # на распаковке и не воровать чужие задачи.
            if not (isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], dict)):
                MUTATION_ATTACK_QUEUE.task_done()
                continue

            priority, task = item

            # === ФИЛЬТР НЕ-XSS ЗАДАЧ ===
            category = task.get("category", "").lower()
            if "xss" not in category:
                # НЕ вызываем submit → задача НЕ попадёт в MutatorTasksPanel
                MUTATION_ATTACK_QUEUE.task_done()
                continue

            # === Только XSS задачи доходят сюда ===
            payload = task["payload"]
            generated = task.get("generated", 1)
            risk = task.get("risk", 1)
            family = task.get("family", "generic")
            tags = task.get("tags", [])
            url = getattr(self, "default_url", self.domain)

            tag_str = ", ".join(tags) if tags else "no-tags"
            self._safe_call(
                self._log_proxy,
                f"[Mutator→Queue][prio={priority}] "
                f"family={family} | risk={risk} | payload={payload} | tags=[{tag_str}]",
                "info"
            )

            # === ТОЛЬКО ТЕПЕР submit() ===
            task_id = self.mutator_manager.submit(
                self._waf_aware_attack_payload,
                url,
                payload,
                payload={
                    "payload": payload,
                    "generated": generated,
                    "risk": risk,
                    "family": family,
                    "tags": tags,
                }
            )

            self.mutation_count += 1
            self._safe_call(
                self.status_label.config,
                text=f"Mutations: {self.mutation_count} | Hits: {self.mutation_hits}"
            )

            self._safe_call(
                self._log_proxy,
                f"[Mutator→Attack] task_id={task_id} | risk={risk} | family={family} | payload={payload}",
                "info"
            )

            MUTATION_ATTACK_QUEUE.task_done()

    def _add_xss_result(self, url, status, reflected, length, payload):
        try:
            tag = "reflected" if reflected else "clean"
            self._safe_call(
                self.xss_tree.insert,
                "", "end",
                values=(url, status, reflected, length, payload),
                tags=(tag,)
            )
        except Exception as e:
            self._safe_call(self._log_proxy, f"❌ Ошибка добавления результата XSS: {e}", "error")

    def _on_export_results(self):
        """Export attack results with multiple format options."""
        try:
            export_dir = DIRS.get("exports", DIRS.get("logs", "."))
            os.makedirs(export_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            parsed = urlparse(self.domain)
            safe_domain = parsed.netloc or self.domain
            safe_domain = safe_domain.replace(":", "_")

            base_filename = f"attack_results_{safe_domain}_{timestamp}"

            filename = filedialog.asksaveasfilename(
                initialdir=export_dir,
                initialfile=base_filename,
                title="Экспорт результатов атаки",
                filetypes=[("JSON", "*.json"), ("CSV", "*.csv"), ("Text", "*.txt")]
            )

            if not filename:
                return

            results = self.engine.get_attack_results()

            if filename.endswith(".json"):
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)

            elif filename.endswith(".csv"):
                if results:
                    keys = results[0].keys()
                    with open(filename, "w", newline="", encoding="utf-8") as f:
                        writer = csv.DictWriter(f, fieldnames=keys)
                        writer.writeheader()
                        writer.writerows(results)

            elif filename.endswith(".txt"):
                with open(filename, "w", encoding="utf-8") as f:
                    for item in results:
                        line = " | ".join(f"{k}: {v}" for k, v in item.items())
                        f.write(line + "\n")

            self._safe_call(self._log_proxy, f"✅ Результаты успешно экспортированы: {filename}", "info")

        except Exception as e:
            self._safe_call(self._log_proxy, f"❌ Ошибка экспорта результатов: {type(e).__name__}: {e}", "error")

    def _on_run_attack_threaded(self):
        if self._attack_thread and self._attack_thread.is_alive():
            messagebox.showwarning("Выполняется", "Атака уже выполняется. Дождитесь завершения.")
            return

        if not self.crawl_json:
            self._safe_call(self._log_proxy, "⚠️ deep_crawl.json не загружен. Использую минимальные данные.", "warn")
            self.crawl_json = {"visited": [self.domain]}

        self._stop_requested = False
        # === Запуск SQLi Worker (только один раз) ===
        if not getattr(self, "_sqli_worker_started", False):
            try:
                self.sqli_worker.start()
                self._sqli_worker_started = True
                self._safe_call(self._log_proxy, "🚀 SQLi Worker запущен в фоне", "info")
            except Exception as e:
                self._safe_call(self._log_proxy, f"⚠️ SQLi Worker уже запущен/ошибка старта: {e}", "warn")

        self._reset_progress(len(self.MODULES))

        self._safe_call(self.status_label.config, text="Статус: выполняется…")
        self._safe_call(self._log_proxy, "🧨 Запуск автоатаки в фоне…", "info")

        if self._waf_auto_scan and not self._detected_waf and not self._waf_scan_running:
            self._on_scan_waf(block_until_done=True)

        self._attack_thread = threading.Thread(target=self._run_attack_background, daemon=True)
        self._attack_thread.start()

    def _on_stop_attack(self):
        if self._attack_thread and self._attack_thread.is_alive():
            self._stop_requested = True
            self._safe_call(self.status_label.config, text="Статус: остановка запрошена…")
            self._safe_call(self._log_proxy, "⏹️ Остановка атаки…", "warn")
        else:
            self._safe_call(self._log_proxy, "⚠️ Нет активной атаки для остановки.", "warn")

    def _run_attack_background(self) -> None:
        try:
            deep_crawl_path = os.path.join(DIRS.get("logs", "."), "deep_crawl.json")
            if os.path.exists(deep_crawl_path):
                try:
                    with open(deep_crawl_path, "r", encoding="utf-8") as f:
                        raw = json.load(f)
                    self.crawl_json.update(raw.get("pages", {}))
                    scripts = list(self.crawl_json.get("js_insights", {}).values())
                    self.crawl_json["scripts"] = scripts
                    self._safe_call(self._log_proxy, f"📌 Загружено JS-скриптов: {len(scripts)}", "info")
                except Exception as e:
                    self._safe_call(self._log_proxy, f"❌ Ошибка загрузки deep_crawl.json: {type(e).__name__}: {e}",
                                    "error")
            else:
                self._safe_call(self._log_proxy, f"⚠️ Файл deep_crawl.json не найден: {deep_crawl_path}", "warn")
                self.crawl_json.setdefault("scripts", [])

            base_visited = self.crawl_json.get("visited", [self.domain])
            session = self.engine._load_session_cookies()
            headers_list = build_headers_list(self.crawl_json.get("tokens", []))
            tokens = self.engine.generate_tokens()

            modules = self.MODULES

            self._reset_progress(len(modules))
            self._safe_call(self.status_label.config, text="Статус: выполняется…")
            self._safe_call(self._log_proxy, "🧨 Запуск автоатаки (циклический режим)…", "info")

            allowed_targets = getattr(settings, "ALLOWED_TARGETS", [])
            allow_real = getattr(settings, "ALLOW_REAL_RUN", True)
            secrets = self._load_secrets()

            while not self._stop_requested:
                for idx, name in enumerate(modules, start=1):

                    if self._stop_requested:
                        self._safe_call(
                            self._log_proxy,
                            "🛑 Атака остановлена пользователем.",
                            "warn"
                        )
                        break

                    self._safe_call(
                        self._log_proxy,
                        f"▶️ Запуск модуля {idx}/{len(modules)}: {name}",
                        "info"
                    )

                    handler = self.engine.module_handlers.get(name)
                    if not handler:
                        self._safe_call(
                            self._log_proxy,
                            f"⚠️ Нет обработчика для модуля: {name}",
                            "warn"
                        )
                        continue

                    ctx = {
                        "session": session,
                        "base_url": base_visited[0] if base_visited else self.domain,
                        "headers_list": headers_list,
                        "crawl": self.crawl_json,
                        "tokens": tokens,
                        "secrets": secrets,
                        "settings": {"allow_real_run": allow_real},
                        "domain": self.domain,
                    }

                    try:
                        if allow_real and (
                                self.domain in allowed_targets or urlparse(self.domain).netloc in allowed_targets
                        ):
                            result = handler(ctx)
                        else:
                            try:
                                result = handler(ctx)
                            except Exception as e:
                                result = {
                                    "status": "skipped",
                                    "reason": "real-run-not-allowed",
                                    "error": str(e)
                                }

                    except Exception as e:
                        result = {"status": "error", "error": str(e)}
                        self._safe_call(
                            self._log_proxy,
                            f"❌ Ошибка в модуле {name}: {type(e).__name__}: {e}",
                            "error"
                        )

                    # Нормализуем не-dict результат обработчика ДО обращения к
                    # result[...]. Раньше result["family"]=... падало с TypeError,
                    # если handler возвращал не-словарь (list/str/None), а мёртвая
                    # проверка isinstance стояла уже после присваивания.
                    if not isinstance(result, dict):
                        result = {"status": "ok", "data": result}

                    # === ДОБАВЛЯЕМ МЕТАДАННЫЕ СЕМЕЙСТВА ===
                    module_meta = MODULE_FAMILIES.get(name, {})

                    result["family"] = module_meta.get("family", "-")
                    result["risk"] = module_meta.get("risk", "-")
                    result["tags"] = module_meta.get("tags", [])

                    try:
                        self.engine._record_result(name, result)
                    except Exception as e:
                        self._safe_call(
                            self._log_proxy,
                            f"❌ Ошибка записи результата модуля {name}: {e}",
                            "error"
                        )

                    self._safe_call(
                        self._log_proxy,
                        f"✅ Завершён модуль {idx}/{len(modules)}: {name}",
                        "info"
                    )

                    # === ЗАПУСК МОДУЛЯ ЧЕРЕЗ MUTATOR MANAGER ===
                    self.mutator_manager.submit(
                        handler,
                        ctx,
                        payload={
                            "payload": name,
                            "family": module_meta.get("family"),
                            "risk": module_meta.get("risk"),
                            "tags": module_meta.get("tags"),
                            "generated": 0
                        },
                        task_type="module"
                    )

                    self._safe_call(
                        self._log_proxy,
                        f"[Mutator] Модуль отправлен в очередь: {name}",
                        "info"
                    )

                    # Переходим к следующему модулю, не блокируя GUI
                    self._safe_call(self._increment_progress)
                    time.sleep(0.2)

                time.sleep(0.3)

            export_dir = DIRS.get("exports", DIRS.get("logs", "."))
            os.makedirs(export_dir, exist_ok=True)
            safe_domain = self.engine._sanitize_domain(self.domain)
            filename = os.path.join(
                export_dir,
                f"attack_results_{safe_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )

            with open(filename, "w", encoding="utf-8") as f:
                json.dump({
                    "attack_results": self.engine.get_attack_results(),
                    "waf_stats": self.waf_detector.get_stats(),
                    "waf_detections": self._export_waf_detections(),
                }, f, indent=2, ensure_ascii=False)

            self._safe_call(self._log_proxy, f"✅ Все результаты сохранены: {filename}", "info")
            self._safe_call(self.status_label.config, text="Статус: завершено")
        except Exception as e:
            self._safe_call(self._log_proxy, f"❌ Ошибка фоновой атаки: {type(e).__name__}: {e}", "error")
            self._safe_call(self.status_label.config, text="Статус: ошибка")

    def _on_send_summary(self):
        messagebox.showinfo("Отправка сводки", "Сводка формируется в фоне...")
        threading.Thread(target=self._send_summary_worker, daemon=True).start()

    def _send_summary_worker(self):
        """Фоновая логика формирования и сохранения сводного отчёта."""
        try:
            # Получаем результаты атаки
            results = self.engine.get_attack_results()

            # Формируем путь для сохранения
            export_dir = DIRS.get("exports", DIRS.get("logs", "."))
            os.makedirs(export_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_domain = self.engine._sanitize_domain(self.domain)

            filename = os.path.join(
                export_dir,
                f"attack_summary_{safe_domain}_{timestamp}.json"
            )

            # Сохраняем в JSON
            with open(filename, "w", encoding="utf-8") as f:
                json.dump({
                    "attack_results": results,
                    "waf_stats": self.waf_detector.get_stats(),
                    "waf_detections": self._export_waf_detections(),
                }, f, indent=2, ensure_ascii=False)

            # Threat Intel: WAF summary
            self._send_to_threat_intel(
                module="waf_engine",
                target=self.domain,
                result={
                    "stats": self.waf_detector.get_stats(),
                    "detections": self._export_waf_detections(),
                },
            )

            # Логируем короткий статус
            self._safe_call(self._log_proxy, f"📋 Сводка успешно сохранена: {filename}", "info")

        except Exception as e:
            self._safe_call(self._log_proxy, f"❌ Ошибка формирования сводки: {type(e).__name__}: {e}", "error")

    # ============================================================
    #  WAF Engine 14.0 — detection, evasion, reporting
    # ============================================================

    @property
    def _waf_evasion_enabled(self) -> bool:
        try:
            return bool(self._waf_evasion_var.get())
        except tk.TclError:
            return True

    def _on_scan_waf(self, block_until_done: bool = False) -> None:
        """Запуск fingerprinting WAF в фоне (UIQueueBridge)."""
        if self._waf_scan_running:
            if not block_until_done:
                self._safe_call(self._log_proxy, "⚠️ WAF scan уже выполняется", "warn")
            return

        self._waf_scan_running = True
        self._safe_call(self.waf_status_label.config, text="WAF: сканирование…")
        self._safe_call(self._log_proxy, f"🛡️ WAF scan: {self.domain}", "info")

        if block_until_done:
            done = threading.Event()

            def _worker():
                try:
                    self._waf_scan_worker()
                finally:
                    done.set()

            threading.Thread(target=_worker, daemon=True, name="WAFScanSync").start()
            done.wait(timeout=30)
            return

        try:
            self.ui_bridge.run_bg(self._waf_scan_worker, name="WAFScan")
        except Exception:
            threading.Thread(target=self._waf_scan_worker, daemon=True, name="WAFScan").start()

    def _waf_scan_worker(self) -> None:
        """HTTP baseline + WAFDetector fingerprinting (фоновый поток)."""
        url = self.domain if self.domain.startswith("http") else f"https://{self.domain}"
        try:
            resp = requests.get(
                url,
                timeout=int(settings.get("http.request_timeout", 10) or 10),
                verify=bool(settings.get("http.verify_ssl", False)),
                allow_redirects=True,
                headers={"User-Agent": settings.get("http.default_user_agent", "Mozilla/5.0")},
            )
            headers = {str(k): str(v) for k, v in resp.headers.items()}
            waf_type = self.waf_detector.detect_waf(url, resp.text, headers, resp.status_code)
            record = self.waf_detector.get_detection(url) or {}
            self.ui_bridge.post_ui(self._on_waf_scan_complete, url, waf_type, record, resp.status_code)
        except Exception as exc:
            self.ui_bridge.post_ui(self._on_waf_scan_error, url, str(exc))
        finally:
            self._waf_scan_running = False

    def _on_waf_scan_complete(
        self,
        url: str,
        waf_type: Optional[WAFType],
        record: Dict[str, Any],
        status_code: int,
    ) -> None:
        self._detected_waf = waf_type
        if waf_type:
            conf = record.get("confidence", 0)
            label = f"WAF: {waf_type.value} ({conf:.0%})"
            self.waf_status_label.config(text=label)
            self._log_proxy(
                f"🛡️ Обнаружен WAF: {waf_type.value} | confidence={conf:.0%} | HTTP {status_code}",
                "warn",
            )
        else:
            self.waf_status_label.config(text="WAF: не обнаружен")
            self._log_proxy(f"✅ WAF не обнаружен (HTTP {status_code})", "info")

        self._refresh_waf_tree()
        self._send_to_threat_intel(
            module="waf_detection",
            target=url,
            result={
                "waf_type": waf_type.value if waf_type else None,
                "detection": record,
                "http_status": status_code,
            },
        )

    def _on_waf_scan_error(self, url: str, error: str) -> None:
        self.waf_status_label.config(text="WAF: ошибка скана")
        self._log_proxy(f"❌ WAF scan failed for {url}: {error}", "error")

    def _refresh_waf_tree(self) -> None:
        """Обновить вкладку WAF Intel из detector state."""
        try:
            self.waf_tree.delete(*self.waf_tree.get_children())
        except tk.TclError:
            return

        with self.waf_detector._lock:
            detections = {u: dict(d) for u, d in self.waf_detector.detected_wafes.items()}

        for url, rec in detections.items():
            waf_obj = rec.get("type")
            waf_name = waf_obj.value if isinstance(waf_obj, WAFType) else str(waf_obj or "—")
            conf = rec.get("confidence", 0)
            score = rec.get("score", 0)
            success_rate = self.waf_detector.get_success_rate(url)
            attempts = len(self.waf_detector.evasion_attempts.get(url, []))
            tag = "detected" if waf_name != "—" else "clean"
            self.waf_tree.insert(
                "",
                "end",
                values=(
                    url[:120],
                    waf_name,
                    f"{conf:.0%}" if isinstance(conf, float) else conf,
                    score,
                    f"{success_rate:.1f}%",
                    attempts,
                ),
                tags=(tag,),
            )

    def _waf_aware_attack_payload(self, url: str, payload: str) -> dict:
        """
        Обёртка над AttackEngine.attack_payload с HTTPEvasionWrapper.
        При включённом WAF Evasion пробует baseline + evasion variants.
        """
        if not self._waf_evasion_enabled:
            return self.engine.attack_payload(url, payload)

        try:
            status, text, detected = self.waf_evasion.send_with_evasion(
                url,
                "GET",
                payload,
                max_attempts=self._waf_max_attempts,
            )
            body = text or ""
            reflected = payload in body
            effective_payload = payload

            if not reflected and body:
                for variant in self.waf_detector.get_evasion_payloads(
                    payload, detected or self._detected_waf, max_variants=12
                ):
                    if variant in body:
                        reflected = True
                        effective_payload = variant
                        break

            blocked = status in (401, 403, 405, 406, 409, 429, 501, 503)
            if detected and not self._detected_waf:
                self._detected_waf = detected
                self._safe_call(
                    self.waf_status_label.config,
                    text=f"WAF: {detected.value}",
                )

            result = {
                "status": "blocked" if blocked and not reflected else "ok",
                "reflected": reflected,
                "length": len(body),
                "response": body[:500],
                "http_status": status,
                "waf_detected": (detected or self._detected_waf).value
                if (detected or self._detected_waf)
                else None,
                "payload_used": effective_payload,
                "waf_evasion": True,
            }
            self._safe_call(self._refresh_waf_tree)
            return result
        except Exception as exc:
            self._safe_call(self._log_proxy, f"⚠️ WAF evasion fallback: {exc}", "warn")
            return self.engine.attack_payload(url, payload)

    def _export_waf_detections(self) -> List[Dict[str, Any]]:
        """Сериализуемые записи WAF для экспорта / Threat Intel."""
        out: List[Dict[str, Any]] = []
        with self.waf_detector._lock:
            items = list(self.waf_detector.detected_wafes.items())
        for url, rec in items:
            waf_obj = rec.get("type")
            out.append({
                "url": url,
                "waf_type": waf_obj.value if isinstance(waf_obj, WAFType) else str(waf_obj),
                "confidence": rec.get("confidence"),
                "score": rec.get("score"),
                "signals": rec.get("signals"),
                "candidates": rec.get("candidates"),
                "success_rate": self.waf_detector.get_success_rate(url),
                "top_payloads": self.waf_detector.get_most_effective_payloads(url, top_n=5),
            })
        return out

    # === Cleanup ===
    def destroy(self) -> None:
        """Останавливает фоновые циклы/потоки, чтобы не было TclError и зомби-потоков."""
        self._alive = False
        self._stop_requested = True
        self._waf_scan_running = False

        # SQLi worker
        try:
            if getattr(self, "sqli_worker", None) and hasattr(self.sqli_worker, "stop"):
                self.sqli_worker.stop()
        except Exception:
            pass

        # Mutator manager (thread pool)
        try:
            if getattr(self, "mutator_manager", None):
                self.mutator_manager.shutdown(wait=False)
        except Exception:
            pass

        # UI bridge (after-poll loop)
        try:
            if getattr(self, "ui_bridge", None) and hasattr(self.ui_bridge, "stop"):
                self.ui_bridge.stop()
        except Exception:
            pass

        super().destroy()
