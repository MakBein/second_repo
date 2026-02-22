# xss_security_gui/gui/attack_gui.py

import csv
import os
import threading
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from xss_security_gui import DIRS
from xss_security_gui.attack_engine import AttackEngine
from xss_security_gui.mutator_task_manager import MutatorTaskManager
from xss_security_gui.gui.mutator_tasks_panel import MutatorTasksPanel
from xss_security_gui.mutation_queue import MUTATION_ATTACK_QUEUE


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
        self.mutator_panel = MutatorTasksPanel(self.tabs, self.mutator_manager)  # MutatorTasksPanel должен быть tk.Frame
        self.tabs.add(self.mutator_panel, text="Mutator Tasks")

        # Таблица XSS‑результатов
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
        self._module_count = 5
        self._completed_modules = 0
        self._attack_thread = None
        self._stop_requested = False
        self.mutation_count = 0
        self.mutation_hits = 0

    # === Лог-прокси ===
    def _log_proxy(self, msg: str, level: str = "info") -> None:
        self.log_output.insert("end", f"[{level.upper()}] {msg}\n")
        self.log_output.see("end")
        if "завершён" in msg.lower():
            self._increment_progress()

    # === Threat Intel ===
    def _send_to_threat_intel(self, attack_type: str, data: dict) -> None:
        try:
            self.threat_sender(module=attack_type, target=data.get("target", self.domain), result=data)
        except Exception as e:
            self._log_proxy(f"❌ Ошибка Threat Intel: {type(e).__name__}: {e}", "error")

    def _start_mutation_worker(self):
        threading.Thread(target=self._mutation_worker, daemon=True).start()

    def _run_attack(self):
        self._log_proxy("⚡ Атака выполняется...", "info")

    def _increment_progress(self):
        self._completed_modules = min(self._module_count, self._completed_modules + 1)
        self.progress["value"] = self._completed_modules

    def _reset_progress(self, count: int):
        self._module_count = count
        self._completed_modules = 0
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
            self._log_proxy(f"📂 Загружен deep_crawl.json: {path}", "info")
        except Exception as e:
            self._log_proxy(f"❌ Ошибка загрузки deep_crawl.json: {type(e).__name__}: {e}", "error")

    def _mutation_worker(self):
        while not getattr(self, "_stop_requested", False):
            try:
                try:
                    priority, task = MUTATION_ATTACK_QUEUE.get(timeout=1)
                except Exception:
                    continue

                payload = task["payload"]
                url = getattr(self, "default_url", self.domain)

                result = self.engine.attack_payload(url, payload)

                self.mutation_count += 1
                if result.get("reflected"):
                    self.mutation_hits += 1

                self.status_label.config(
                    text=f"Mutations: {self.mutation_count} | Hits: {self.mutation_hits}"
                )

                self._log_proxy(f"[Mutator→Attack][prio={priority}] {payload} → {result.get('status')}", "info")

                self._add_xss_result(
                    url=url,
                    status=result.get("status"),
                    reflected=result.get("reflected"),
                    length=result.get("length"),
                    payload=payload
                )

                MUTATION_ATTACK_QUEUE.task_done()

            except Exception as e:
                self._log_proxy(f"❌ Ошибка в Mutation Worker: {type(e).__name__}: {e}", "error")

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
            self._log_proxy(f"❌ Ошибка добавления результата XSS: {e}", "error")

    def _on_export_results(self):
        """Export attack results with multiple format options."""
        try:
            export_dir = DIRS.get("exports", DIRS.get("logs", "."))
            os.makedirs(export_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"attack_results_{self.domain}_{timestamp}"

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

            self._log_proxy(f"✅ Результаты успешно экспортированы: {filename}", "info")

        except Exception as e:
            self._log_proxy(f"❌ Ошибка экспорта результатов: {type(e).__name__}: {e}", "error")

    def _on_run_attack_threaded(self):
        if self._attack_thread and self._attack_thread.is_alive():
            messagebox.showwarning("Выполняется", "Атака уже выполняется. Дождитесь завершения.")
            return

        if not self.crawl_json:
            self._log_proxy("⚠️ deep_crawl.json не загружен. Использую минимальные данные.", "warn")
            self.crawl_json = {"visited": [self.domain]}

        self._stop_requested = False
        self._reset_progress(count=5)
        self.status_label.config(text="Статус: выполняется…")
        self._log_proxy("🧨 Запуск автоатаки в фоне…", "info")

        self._attack_thread = threading.Thread(target=self._run_attack_background, daemon=True)
        self._attack_thread.start()

    def _on_stop_attack(self):
        if self._attack_thread and self._attack_thread.is_alive():
            self._stop_requested = True
            self.status_label.config(text="Статус: остановка запрошена…")
            self._log_proxy("⏹️ Остановка атаки…", "warn")
        else:
            self._log_proxy("⚠️ Нет активной атаки для остановки.", "warn")

    # === Фоновая атака ===
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

                    self._log_proxy(f"📌 Загружено JS-скриптов: {len(scripts)}", "info")
                except Exception as e:
                    self._log_proxy(f"❌ Ошибка загрузки deep_crawl.json: {type(e).__name__}: {e}", "error")
            else:
                self._log_proxy(f"⚠️ Файл deep_crawl.json не найден по пути: {deep_crawl_path}", "warn")
                self.crawl_json.setdefault("scripts", [])

            base_visited = self.crawl_json.get("visited", [self.domain])

            modules = [
                ("API Endpoints", {"visited": base_visited, "api_endpoints": self.crawl_json.get("api_endpoints", [])},
                 "api_endpoints"),
                ("Token Brute Force", {"visited": base_visited, "tokens": self.crawl_json.get("tokens", [])}, "tokens"),
                ("Parameters Discovery", {"visited": base_visited, "parameters": self.crawl_json.get("parameters", [])},
                 "parameters"),
                ("User IDs Enumeration", {"visited": base_visited, "user_ids": self.crawl_json.get("user_ids", [])},
                 "user_ids"),
                ("XSS Targets", {"visited": base_visited, "xss_targets": self.crawl_json.get("xss_targets", [])},
                 "xss_targets"),
                ("GraphQL Endpoints", {"visited": base_visited, "graphql": self.crawl_json.get("graphql", [])},
                 "graphql"),
                ("JS Sensitive Analysis", {"visited": base_visited, "scripts": self.crawl_json.get("scripts", [])},
                 "js_insights"),
                ("Security Headers Review", {"visited": base_visited, "headers": self.crawl_json.get("headers", [])},
                 "headers"),
                ("CSP Weakness Scan", {"visited": base_visited, "csp": self.crawl_json.get("csp_analysis", [])},
                 "csp_analysis"),
                ("Secrets & Keys", {"visited": base_visited, "secrets": self.crawl_json.get("secrets", []),
                                    "api_keys": self.crawl_json.get("api_keys", [])}, "secrets"),
                ("JWT Tokens", {"visited": base_visited, "jwt_tokens": self.crawl_json.get("jwt_tokens", [])},
                 "jwt_tokens"),
                ("Forms & Inputs", {"visited": base_visited, "forms": self.crawl_json.get("forms", []),
                                    "input_fields": self.crawl_json.get("input_fields", [])}, "forms"),
                ("Error Pages & Stacktraces", {"visited": base_visited, "errors": self.crawl_json.get("errors", [])},
                 "errors"),
            ]

            total_modules = len(modules)
            self._reset_progress(total_modules)

            results = []

            for idx, (name, data, key) in enumerate(modules, start=1):
                if self._stop_requested:
                    self._log_proxy("⏹️ Атака остановлена пользователем.", "warn")
                    break

                try:
                    self._log_proxy(f"▶️ Запуск модуля {idx}/{total_modules}: {name}", "info")

                    # Виконання атаки (короткий результат)
                    result = self.engine.run_module(name, data)

                    # Зберігаємо деталі у results (для файла)
                    results.append({
                        "module": name,
                        "status": result.get("status", "unknown"),
                        "found": len(result.get("items", []))
                    })

                    # У GUI показуємо тільки короткий статус
                    self.status_label.config(
                        text=f"{name}: {result.get('status', 'done')} ({len(result.get('items', []))} найдено)")
                    self._increment_progress()

                except Exception as e:
                    self._log_proxy(f"❌ Ошибка в модуле {name}: {type(e).__name__}: {e}", "error")

            # Зберігаємо всі детальні результати у файл
            export_dir = DIRS.get("exports", DIRS.get("logs", "."))
            os.makedirs(export_dir, exist_ok=True)
            filename = os.path.join(export_dir,
                                    f"attack_results_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

            with open(filename, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

            self._log_proxy(f"✅ Все результаты сохранены в файл: {filename}", "info")
            self.status_label.config(text="Статус: завершено")

        except Exception as e:
            self._log_proxy(f"❌ Ошибка фоновой атаки: {type(e).__name__}: {e}", "error")
            self.status_label.config(text="Статус: ошибка")

    def _on_send_summary(self):
        """
        Отправка сводного отчёта в фоне, чтобы не блокировать GUI.
        """
        # Мгновенное уведомление пользователю
        messagebox.showinfo("Отправка сводки", "Сводка формируется в фоне...")

        # Запускаем отдельный поток
        threading.Thread(target=self._send_summary_worker, daemon=True).start()

    def _send_summary_worker(self):
        """
        Фоновая логика формирования и сохранения сводного отчёта.
        """
        try:
            # Получаем результаты атаки
            results = self.engine.get_attack_results()

            # Формируем путь для сохранения
            export_dir = DIRS.get("exports", DIRS.get("logs", "."))
            os.makedirs(export_dir, exist_ok=True)

            filename = os.path.join(
                export_dir,
                f"attack_summary_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )

            # Сохраняем в JSON
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

            # Логируем короткий статус
            self._log_proxy(f"📋 Сводка успешно сохранена: {filename}", "info")

        except Exception as e:
            self._log_proxy(f"❌ Ошибка формирования сводки: {type(e).__name__}: {e}", "error")
