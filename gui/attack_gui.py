# xss_security_gui/gui/attack_gui.py
import csv
import os
import threading
import json
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from urllib.parse import urlparse
from queue import Empty

from xss_security_gui.threat_analysis.sqli_worker import SQLiWorker
from xss_security_gui.threat_analysis.sqli_module import SQLiTester

from xss_security_gui import DIRS, settings
from xss_security_gui.attack_engine import AttackEngine
from xss_security_gui.mutator_task_manager import MutatorTaskManager
from xss_security_gui.gui.mutator_tasks_panel import MutatorTasksPanel
from xss_security_gui.mutation_queue import MUTATION_ATTACK_QUEUE
from xss_security_gui.auto_modules.dom_and_endpoints import build_headers_list
from xss_security_gui.auto_modules.module_families import MODULE_FAMILIES



class AttackGUI(tk.Frame):
    """
    Графический интерфейс для запуска автоатак с визуализацией прогресса (Tkinter).
    """

    def __init__(self, parent, domain: str, threat_sender=None):
        super().__init__(parent)

        self.domain = domain
        self.threat_sender = threat_sender or (lambda *a, **kw: None)

        # === Заголовок и статус ===
        top_bar = ttk.Frame(self)
        top_bar.pack(fill="x", pady=5)

        self.title = ttk.Label(top_bar, text=f"Цель: {self.domain}")
        self.title.pack(side="left")

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

        # === Лог вывода ===
        self.log_output = tk.Text(self, height=15, bg="#111", fg="lime")
        self.log_output.pack(fill="both", expand=True, padx=5, pady=5)

        # === Tabs (Mutator Tasks + XSS Results) ===
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True)

        self.mutator_manager = MutatorTaskManager()

        self.mutator_manager.on_task_added = self._on_task_added
        self.mutator_manager.on_task_finished = self._on_mutator_task_finished
        self.mutator_panel = MutatorTasksPanel(self.tabs, self.mutator_manager)
        self.tabs.add(self.mutator_panel, text="Mutator Tasks")

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

    # === Потокобезопасные вызовы ===
    def _safe_call(self, fn, *args, **kwargs):
        if threading.current_thread() is threading.main_thread():
            fn(*args, **kwargs)
        else:
            self.after(0, lambda: fn(*args, **kwargs))

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
        path = r"C:\Users\sanch\PycharmProjects\itproger\xss_security_gui\payloads\sqli.json"

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)  # твій JSON з категоріями
                return data
        except Exception as e:
            self._safe_call(self._log_proxy, f"❌ Не удалось загрузить SQLi payloads: {e}", "error")
            return {"default": []}

    def _poll_sqli_queue(self):
        try:
            while True:
                event = self.sqli_worker.queue.get_nowait()
                self._handle_sqli_event(event)
        except Empty:
            pass

        self.after(50, self._poll_sqli_queue)

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
            # Модульна задача
            module_name = payload
            status = result.get("status", "done")
            count = result.get("count", 0)
            error = result.get("error")

            if error:
                final_status = f"🔴 Ошибка: {error}"
            else:
                final_status = f"🟢 Готово ({count} элементов)"

            self.mutator_panel.update_task(task_id, final_status)

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
        while not getattr(self, "_stop_requested", False):
            try:
                priority, task = MUTATION_ATTACK_QUEUE.get(timeout=1)
            except Empty:
                continue
            except Exception as e:
                self._safe_call(
                    self._log_proxy,
                    f"❌ Ошибка очереди мутаций: {type(e).__name__}: {e}",
                    "error"
                )
                continue

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
                self.engine.attack_payload,
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
        # === Запуск SQLi Worker ===
        self.sqli_worker.start()
        self._safe_call(self._log_proxy, "🚀 SQLi Worker запущен в фоне", "info")

        modules = [
            "API Endpoints", "Token Brute Force", "Parameters Discovery", "User IDs Enumeration",
            "XSS Targets", "GraphQL Endpoints", "JS Sensitive Analysis", "Security Headers Review",
            "CSP Weakness Scan", "Secrets & Keys", "JWT Tokens", "Forms & Inputs", "Error Pages & Stacktraces"
        ]
        self._reset_progress(len(modules))

        self._safe_call(self.status_label.config, text="Статус: выполняется…")
        self._safe_call(self._log_proxy, "🧨 Запуск автоатаки в фоне…", "info")

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

            modules = [
                "API Endpoints", "Token Brute Force", "Parameters Discovery", "User IDs Enumeration",
                "XSS Targets", "GraphQL Endpoints", "JS Sensitive Analysis", "Security Headers Review",
                "CSP Weakness Scan", "Secrets & Keys", "JWT Tokens", "Forms & Inputs", "Error Pages & Stacktraces"
            ]

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
                        if not isinstance(result, dict):
                            result = {
                                "status": "ok",
                                "data": result
                            }
                        self._safe_call(
                            self._log_proxy,
                            f"❌ Ошибка в модуле {name}: {type(e).__name__}: {e}",
                            "error"
                        )
                    # === ДОБАВЛЯЕМ МЕТАДАННЫЕ СЕМЕЙСТВА ===
                    module_meta = MODULE_FAMILIES.get(name, {})

                    result["family"] = module_meta.get("family", "-")
                    result["risk"] = module_meta.get("risk", "-")
                    result["tags"] = module_meta.get("tags", [])

                    if isinstance(result, dict):
                        try:
                            self.engine._record_result(name, result)
                        except Exception as e:
                            self._safe_call(
                                self._log_proxy,
                                f"❌ Ошибка записи результата модуля {name}: {e}",
                                "error"
                            )
                    else:
                        self._safe_call(
                            self._log_proxy,
                            f"⚠️ Модуль {name} вернул неожиданный результат.",
                            "warn"
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
                json.dump(self.engine.get_attack_results(), f, indent=2, ensure_ascii=False)

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
                json.dump(results, f, indent=2, ensure_ascii=False)

            # Логируем короткий статус
            self._safe_call(self._log_proxy, f"📋 Сводка успешно сохранена: {filename}", "info")

        except Exception as e:
            self._safe_call(self._log_proxy, f"❌ Ошибка формирования сводки: {type(e).__name__}: {e}", "error")
