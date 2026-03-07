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

from xss_security_gui import DIRS, settings
from xss_security_gui.attack_engine import AttackEngine
from xss_security_gui.mutator_task_manager import MutatorTaskManager
from xss_security_gui.gui.mutator_tasks_panel import MutatorTasksPanel
from xss_security_gui.mutation_queue import MUTATION_ATTACK_QUEUE
from xss_security_gui.auto_modules.dom_and_endpoints import build_headers_list


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

        # === Состояние ===
        self.engine = AttackEngine(
            self.domain,
            threat_sender=self._send_to_threat_intel,
            log_func=self._log_proxy
        )
        self._start_mutation_worker()

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
                self._safe_call(self._log_proxy, f"❌ Ошибка очереди мутаций: {type(e).__name__}: {e}", "error")
                continue

            payload = task["payload"]
            url = getattr(self, "default_url", self.domain)

            result = self.engine.attack_payload(url, payload)

            self.mutation_count += 1
            if result.get("reflected"):
                self.mutation_hits += 1

            self._safe_call(
                self.status_label.config,
                text=f"Mutations: {self.mutation_count} | Hits: {self.mutation_hits}"
            )

            self._safe_call(
                self._log_proxy,
                f"[Mutator→Attack][prio={priority}] {payload} → {result.get('status')}", "info"
            )

            self._safe_call(
                self._add_xss_result,
                url, result.get("status"), result.get("reflected"),
                result.get("length"), payload
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
