# xss_security_gui/form_fuzzer_tab.py

from __future__ import annotations

import json
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from datetime import datetime
from typing import Optional, List, Dict, Any

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from xss_security_gui.form_fuzzer import fuzz_form
from xss_security_gui.utils.threat_sender import ThreatSenderMixin
from xss_security_gui.utils.core_utils import normalize_url
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
from xss_security_gui.settings import LOG_DIR, JSON_CRAWL_EXPORT_PATH

log = logging.getLogger(__name__)


class FormFuzzerTab(ttk.Frame, ThreatSenderMixin):
    """
    Enterprise 6.0 FormFuzzerTab
    ----------------------------
    • Агрессивный фуззер форм с многопоточностью
    • Интеграция с ThreatConnector (ULTRA‑6.5 emit API)
    • Расширенные настройки и безопасное завершение потоков
    """

    def __init__(
        self,
        parent,
        json_path: str = str(JSON_CRAWL_EXPORT_PATH),
        threat_tab: Optional[ttk.Frame] = None,
        max_workers: int = 30,
        timeout: float = 6.0,
        aggressive_mode: bool = True,
    ):
        super().__init__(parent)

        # Основные параметры
        self.json_path = json_path
        self.forms: List[Dict[str, Any]] = []
        self.threat_tab = threat_tab

        # Состояние фуззинга
        self.is_fuzzing = False
        self.fuzzing_thread: Optional[threading.Thread] = None
        self.executor: Optional[ThreadPoolExecutor] = None

        # Настройки фуззинга
        self.max_workers = max_workers
        self.timeout = timeout
        self.aggressive_mode = aggressive_mode

        # Гарантируем существование директории JSON
        os.makedirs(os.path.dirname(self.json_path), exist_ok=True)

        # Логирование
        log.info(
            "[FormFuzzerTab] Инициализация: json_path=%s, max_workers=%s, timeout=%s, aggressive=%s",
            self.json_path,
            self.max_workers,
            self.timeout,
            self.aggressive_mode,
        )

        # Построение интерфейса
        self.build_ui()

    # ============================================================
    #  UI
    # ============================================================

    def build_ui(self):
        """Построение интерфейса FormFuzzerTab"""
        # Панель управления
        ctrl = ttk.Frame(self)
        ctrl.pack(pady=5, fill="x")

        # Кнопки управления
        btn_frame = ttk.LabelFrame(ctrl, text="📌 Управление")
        btn_frame.pack(side="left", padx=5, fill="x")

        ttk.Button(btn_frame, text="📥 Загрузить формы", command=self.load_forms).pack(
            side="left", padx=4, pady=2
        )
        ttk.Button(btn_frame, text="🧪 Фуззить все", command=self.start_fuzzing).pack(
            side="left", padx=4, pady=2
        )
        ttk.Button(btn_frame, text="🛑 Остановить", command=self.stop_fuzzing).pack(
            side="left", padx=4, pady=2
        )
        ttk.Button(btn_frame, text="♻️ Очистить", command=self.clear_results).pack(
            side="left", padx=4, pady=2
        )
        ttk.Button(btn_frame, text="💾 Экспорт", command=self.export_results).pack(
            side="left", padx=4, pady=2
        )

        # Настройки
        settings_frame = ttk.LabelFrame(ctrl, text="⚙️ Настройки")
        settings_frame.pack(side="left", padx=10, fill="x", expand=True)

        ttk.Label(settings_frame, text="Потоков:").grid(
            row=0, column=0, padx=2, pady=2, sticky="w"
        )
        self.workers_spin = ttk.Spinbox(settings_frame, from_=1, to=100, width=8)
        self.workers_spin.set(str(self.max_workers))
        self.workers_spin.grid(row=0, column=1, padx=2, pady=2)

        ttk.Label(settings_frame, text="Таймаут (сек):").grid(
            row=0, column=2, padx=2, pady=2, sticky="w"
        )
        self.timeout_spin = ttk.Spinbox(settings_frame, from_=1, to=30, width=8)
        self.timeout_spin.set(str(self.timeout))
        self.timeout_spin.grid(row=0, column=3, padx=2, pady=2)

        self.aggressive_var = tk.BooleanVar(value=self.aggressive_mode)
        ttk.Checkbutton(
            settings_frame,
            text="🔥 Агрессивный режим",
            variable=self.aggressive_var,
        ).grid(row=0, column=4, padx=5, pady=2)

        # Путь к JSON
        path_frame = ttk.LabelFrame(ctrl, text="📂 Файл JSON")
        path_frame.pack(side="right", padx=5, fill="x")
        self.json_path_entry = ttk.Entry(path_frame, width=40)
        self.json_path_entry.insert(0, self.json_path)
        self.json_path_entry.pack(side="left", padx=2, pady=2, fill="x", expand=True)
        ttk.Button(path_frame, text="🔍", command=self.select_json_file, width=4).pack(
            side="left", padx=2, pady=2
        )

        # Прогресс-бар
        self.progress = ttk.Progressbar(self, mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=4)

        # Статус
        self.status_label = ttk.Label(
            self,
            text="Готов к запуску",
            foreground="cyan",
            font=("Consolas", 10, "bold"),
        )
        self.status_label.pack(pady=2)

        # Результаты
        result_frame = ttk.LabelFrame(self, text="📊 Результаты")
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.result_box = tk.Text(
            result_frame,
            height=30,
            bg="black",
            fg="lime",
            insertbackground="white",
            wrap="word",
            font=("Consolas", 10),
        )
        scrollbar = ttk.Scrollbar(
            result_frame, orient="vertical", command=self.result_box.yview
        )
        self.result_box.configure(yscrollcommand=scrollbar.set)

        self.result_box.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Настройка тегов для подсветки
        self.result_box.tag_config(
            "success", foreground="lime", font=("Consolas", 10, "bold")
        )
        self.result_box.tag_config(
            "error", foreground="red", font=("Consolas", 10, "bold")
        )
        self.result_box.tag_config("info", foreground="cyan", font=("Consolas", 9))
        self.result_box.tag_config("warning", foreground="orange", font=("Consolas", 9))
        self.result_box.tag_config(
            "xss",
            foreground="yellow",
            background="#440000",
            font=("Consolas", 10, "bold"),
        )
        self.result_box.tag_config(
            "system",
            foreground="white",
            background="#222222",
            font=("Consolas", 9, "italic"),
        )

    # ============================================================
    #  Логирование и статус
    # ============================================================

    def log(self, text: str, tag: Optional[str] = None, level: str = "info"):
        """
        Потокобезопасное логирование в GUI и системный лог.
        • text: сообщение
        • tag: тег для Text-виджета (если None — определяется по level)
        • level: уровень ('info', 'success', 'warning', 'error', 'xss')
        """
        if not text:
            return

        if tag is None:
            tag_map = {
                "info": "info",
                "success": "success",
                "warning": "warning",
                "error": "error",
                "xss": "xss",
            }
            tag = tag_map.get(level, "info")

        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {text}"

        def _log_gui():
            self.result_box.insert("end", formatted + "\n", tag)
            self.result_box.see("end")

        # Системный лог
        if level == "error":
            log.error(formatted)
        elif level == "warning":
            log.warning(formatted)
        elif level == "success":
            log.info(formatted)
        elif level == "xss":
            log.info("[XSS] %s", formatted)
        else:
            log.info(formatted)

        # Безопасное обновление GUI
        if threading.current_thread() == threading.main_thread():
            _log_gui()
        else:
            self.after(0, _log_gui)

    def update_status(self, text: str, level: str = "info"):
        """
        Обновление статуса в UI с поддержкой уровней.
        • text: текст статуса
        • level: уровень ('info', 'success', 'warning', 'error')
        """

        def _update():
            self.status_label.config(text=text)
            if level == "success":
                self.status_label.config(foreground="lime")
            elif level == "warning":
                self.status_label.config(foreground="orange")
            elif level == "error":
                self.status_label.config(foreground="red")
            else:
                self.status_label.config(foreground="cyan")

        log.info("[FormFuzzer] Status update → %s: %s", level.upper(), text)

        if threading.current_thread() == threading.main_thread():
            _update()
        else:
            self.after(0, _update)

    def clear_results(self):
        """Очистка результатов"""
        self.result_box.delete("1.0", "end")
        self.progress["value"] = 0
        self.update_status("Готов к запуску")

    # ============================================================
    #  Работа с JSON
    # ============================================================

    def select_json_file(self):
        """
        Выбор JSON файла с результатами краулинга.
        """
        path = filedialog.askopenfilename(
            title="Выберите JSON файл с результатами краулинга",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )

        if not path:
            self.log("⚠️ Выбор файла отменён пользователем", "warning")
            return

        if not os.path.exists(path):
            self.log(f"❌ Файл не найден: {path}", "error")
            messagebox.showerror("Ошибка", f"Файл не найден:\n{path}")
            return

        self.json_path = path
        self.json_path_entry.delete(0, "end")
        self.json_path_entry.insert(0, path)

        self.log(f"📂 Выбран JSON файл: {path}", "info")
        self.update_status("Файл выбран, готов к загрузке")

    def load_forms(self):
        """
        Загрузка форм из JSON с расширенной обработкой ошибок и статистикой.
        • Проверяет структуру JSON
        • Извлекает формы и их параметры
        • Логирует статистику и отправляет артефакты в ThreatConnector
        """
        self.forms.clear()
        self.result_box.delete("1.0", "end")

        json_path = self.json_path_entry.get().strip() or self.json_path
        if not os.path.exists(json_path):
            self.log(f"❌ Файл не найден: {json_path}", "error")
            messagebox.showerror("Ошибка", f"Файл не найден:\n{json_path}")
            return

        try:
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            self.log(f"❌ Ошибка парсинга JSON: {e}", "error")
            messagebox.showerror("Ошибка", f"Невалидный JSON:\n{e}")
            return
        except Exception as e:
            self.log(f"❌ Ошибка чтения файла: {e}", "error")
            messagebox.showerror("Ошибка", f"Ошибка чтения файла:\n{e}")
            return

        if not isinstance(data, list):
            self.log("❌ JSON должен содержать массив страниц", "error")
            return

        forms_count, skipped_pages, skipped_forms = 0, 0, 0

        for page_idx, page in enumerate(data, 1):
            if not isinstance(page, dict):
                skipped_pages += 1
                self.log(f"⚠️ Пропущена невалидная страница #{page_idx}", "warning")
                continue

            url = page.get("url", "")
            forms = page.get("forms", [])
            if not url or not forms:
                skipped_pages += 1
                continue

            for form in forms:
                if not isinstance(form, dict):
                    skipped_forms += 1
                    continue

                inputs = form.get("inputs", [])
                if not inputs:
                    skipped_forms += 1
                    continue

                form_entry = {
                    "url": normalize_url(url),
                    "action": form.get("action", ""),
                    "method": form.get("method", "GET").upper(),
                    "inputs": inputs,
                    "handlers": form.get("handlers", "—"),
                    "page_url": url,
                }
                self.forms.append(form_entry)
                forms_count += 1

                # --- ULTRA‑6.5 ThreatConnector ---
                THREAT_CONNECTOR.emit(
                    module="FormLoader",
                    target=url,
                    result={
                        "severity": "info",
                        "category": "form_loaded",
                        "form": form_entry,
                    }
                )

        self.log("=" * 60, "info")
        self.log(f"✅ Загружено форм: {forms_count}", "success")
        self.log(
            f"⚠️ Пропущено страниц: {skipped_pages}",
            "warning" if skipped_pages else "info",
        )
        self.log(
            f"⚠️ Пропущено форм: {skipped_forms}",
            "warning" if skipped_forms else "info",
        )
        self.update_status(
            f"Загружено {forms_count} форм (пропущено {skipped_pages} страниц, {skipped_forms} форм)"
        )

    # ============================================================
    #  Запуск / остановка фуззинга
    # ============================================================

    def start_fuzzing(self):
        """Запуск агрессивного фуззинга всех форм"""
        if not self.forms:
            messagebox.showwarning("⚠️ Нет форм", "Сначала загрузите формы")
            return

        if self.is_fuzzing:
            messagebox.showwarning("⚠️ Уже выполняется", "Фуззинг уже запущен")
            return

        try:
            self.max_workers = int(self.workers_spin.get())
        except ValueError:
            self.max_workers = 30

        try:
            self.timeout = float(self.timeout_spin.get())
        except ValueError:
            self.timeout = 6.0

        self.aggressive_mode = self.aggressive_var.get()

        self.is_fuzzing = True
        self.fuzzing_thread = threading.Thread(
            target=self._fuzz_all_forms_thread,
            name="FormFuzzerWorker",
            daemon=True,
        )
        self.fuzzing_thread.start()
        self.update_status("Фуззинг запущен...")

    def stop_fuzzing(self):
        """Остановка фуззинга"""
        if not self.is_fuzzing:
            return

        self.is_fuzzing = False
        if self.executor:
            try:
                self.executor.shutdown(wait=False, cancel_futures=True)
            except Exception as e:
                log.error("[FormFuzzer] Ошибка при остановке executor: %s", e)

        self.log("🛑 Остановка фуззинга...", "warning")
        self.update_status("Остановка...")

    def _fuzz_all_forms_thread(self):
        """Основной поток фуззинга с параллельной обработкой форм"""
        total_forms = len(self.forms)
        self.log(f"🎯 Начинаем XSS-фуззинг {total_forms} форм", "info")
        self.log(
            f"⚙️ Настройки: {self.max_workers} потоков, таймаут {self.timeout}s, "
            f"агрессивный режим: {self.aggressive_mode}",
            "info",
        )
        self.log("=" * 80, "info")

        self.progress["maximum"] = total_forms
        self.progress["value"] = 0

        processed, errors, all_hits = 0, 0, []

        with ThreadPoolExecutor(max_workers=min(self.max_workers, total_forms)) as executor:
            self.executor = executor
            futures: Dict[Future, Dict[str, Any]] = {
                executor.submit(self._fuzz_single_form, form, idx + 1, total_forms): form
                for idx, form in enumerate(self.forms)
            }

            for future in as_completed(futures):
                if not self.is_fuzzing:
                    break

                form = futures[future]

                try:
                    hits = future.result()

                    if hits:
                        all_hits.extend(hits)

                        for hit in hits:
                            # Локальный лог
                            self._log_to_file(form, hit)

                            # --- ThreatConnector ULTRA‑6.5 ---
                            THREAT_CONNECTOR.emit(
                                module="FormFuzzer",
                                target=form.get("url", ""),
                                result={
                                    "severity": "high",
                                    "category": "xss_hit",
                                    "payload": hit.get("payload"),
                                    "status": hit.get("status"),
                                    "vulnerable": True,
                                    "snippet": hit.get("snippet"),
                                    "inputs": form.get("inputs", []),
                                    "method": form.get("method", "GET"),
                                    "action": form.get("action", ""),
                                    "timestamp": hit.get("timestamp"),
                                }
                            )

                    processed += 1
                    self.progress["value"] = processed
                    self.update_status(
                        f"Обработано: {processed}/{total_forms} | Найдено XSS: {len(all_hits)}"
                    )

                except Exception as e:
                    errors += 1
                    self.log(
                        f"❌ Ошибка при обработке формы {form.get('url', 'unknown')}: {e}",
                        "error",
                    )
                    processed += 1
                    self.progress["value"] = processed

        self.executor = None
        self.is_fuzzing = False

        self.log("=" * 80, "info")
        self.log("✅ Фуззинг завершён!", "success")
        self.log("📊 Статистика:", "info")
        self.log(f"   • Обработано форм: {processed}/{total_forms}", "info")
        self.log(
            f"   • Найдено XSS: {len(all_hits)}",
            "success" if all_hits else "info",
        )
        self.log(
            f"   • Ошибок: {errors}",
            "error" if errors > 0 else "info",
        )

        self.update_status(
            f"Завершено: {processed} форм, {len(all_hits)} XSS найдено"
        )

        if all_hits:
            messagebox.showinfo(
                "✅ Результаты",
                f"Найдено {len(all_hits)} XSS уязвимостей!\nПроверьте логи для деталей.",
            )

    # ============================================================
    #  Фуззинг одной формы
    # ============================================================

    def _fuzz_single_form(
        self, form: Dict[str, Any], idx: int, total: int
    ) -> List[Dict[str, Any]]:
        """Фуззинг одной формы"""
        try:
            action = form.get("action", "")
            base_url = form.get("url", "")

            if action.startswith(("http://", "https://")):
                full_url = action
            elif action.startswith("/"):
                full_url = base_url.rstrip("/") + action
            else:
                full_url = base_url.rstrip("/") + "/" + action if action else base_url

            full_url = normalize_url(full_url)
            inputs = form.get("inputs", [])
            if not inputs:
                return []

            method = form.get("method", "GET")

            suspicious = [
                i
                for i in inputs
                if any(
                    x in i.lower()
                    for x in [
                        "query",
                        "search",
                        "msg",
                        "comment",
                        "text",
                        "input",
                        "data",
                        "content",
                    ]
                )
            ]

            self.log(f"\n📨 [{idx}/{total}] {method} {full_url}", "info")
            self.log(f"🔧 Параметры: {inputs}", "info")
            if suspicious:
                self.log(f"⚠️ Подозрительные поля: {suspicious}", "warning")
            if form.get("handlers") and form.get("handlers") != "—":
                self.log(f"🧠 JS обработчики: {form['handlers']}", "info")

            results = fuzz_form(
                action_url=full_url,
                method=method,
                inputs=inputs,
                max_workers=self.max_workers if self.aggressive_mode else 10,
                timeout=self.timeout,
                allowlist=None,
            )

            hits: List[Dict[str, Any]] = []
            for r in results:
                if r.get("vulnerable"):
                    artifact = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "module": "FormFuzzer",
                        "target": full_url,
                        "param": form.get("inputs", []),
                        "payload": r.get("payload", ""),
                        "category": r.get("category", "unknown"),
                        "status": r.get("status", "detected"),
                        "severity": "high",
                        "vulnerable": True,
                        "snippet": r.get("snippet", ""),
                    }
                    hits.append(artifact)
                    self.log(
                        f"  ✔️ XSS НАЙДЕН: {artifact['payload'][:60]}... "
                        f"[{artifact['category']}] Status: {artifact['status']}",
                        "xss",
                    )
            if not hits:
                self.log("  ❌ Уязвимость не найдена", "info")

            return hits

        except Exception as e:
            self.log(f"  ❌ Ошибка при фуззинге формы: {e}", "error")
            return []

    # ============================================================
    #  Логирование результатов и экспорт
    # ============================================================

    def _log_to_file(self, form: Dict[str, Any], result: Dict[str, Any]):
        """
        Детальное логирование найденных уязвимостей.
        Записывает артефакт в текстовый лог и NDJSON для последующей обработки.
        """
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            text_log = LOG_DIR / "gui_fuzzer_results.log"
            ndjson_log = LOG_DIR / "gui_fuzzer_results.ndjson"

            artifact = {
                "timestamp": datetime.utcnow().isoformat(),
                "module": "FormFuzzer",
                "target": form.get("action") or form.get("url", "unknown"),
                "method": form.get("method", "GET"),
                "inputs": form.get("inputs", []),
                "handlers": form.get("handlers", "—"),
                "payload": result.get("payload", "—"),
                "category": result.get("category", "-"),
                "status": result.get("status", "-"),
                "severity": "high" if result.get("vulnerable") else "info",
                "vulnerable": result.get("vulnerable", False),
                "snippet": result.get("snippet", "").strip()[:500],
                "error": result.get("error"),
            }

            # Текстовый лог
            with open(text_log, "a", encoding="utf-8") as f:
                f.write(f"\n{'=' * 80}\n")
                f.write(f"[{artifact['timestamp']}] {artifact['module']} RESULT\n")
                f.write(f"{'=' * 80}\n")
                for key, val in artifact.items():
                    f.write(f"{key}: {val}\n")
                f.write(f"{'=' * 80}\n\n")

            # NDJSON лог
            with open(ndjson_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(artifact, ensure_ascii=False) + "\n")

            # ThreatConnector ULTRA‑6.5
            THREAT_CONNECTOR.emit(
                module="FormFuzzer",
                target=artifact["target"],
                result=artifact,
            )

            log.info(
                "[FormFuzzer] Артефакт записан: %s payload=%s",
                artifact["target"],
                artifact["payload"],
            )

        except Exception as e:
            self.log(f"⚠️ Ошибка записи в лог: {e}", "warning")
            log.error("[FormFuzzer] Ошибка записи в лог: %s", e)

    def export_results(self):
        """
        Экспорт результатов фуззинга в JSON с артефактами и статистикой.
        Формирует единый отчёт для анализа и Threat Intel.
        """
        if not self.forms:
            messagebox.showwarning(
                "⚠️ Нет данных", "Сначала загрузите и протестируйте формы"
            )
            return

        path = filedialog.asksaveasfilename(
            title="Сохранить результаты",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            # ThreatConnector ULTRA‑6.5: артефакты в формате {module, target, result}
            artifacts = THREAT_CONNECTOR.filter_by_module("FormFuzzer")

            export_data = {
                "exported_at": datetime.now().isoformat(),
                "total_forms": len(self.forms),
                "total_artifacts": len(artifacts),
                "stats": {
                    "xss_found": sum(
                        1 for a in artifacts
                        if a.get("result", {}).get("vulnerable")
                    ),
                    "errors": sum(
                        1 for a in artifacts
                        if a.get("result", {}).get("status") == "error"
                    ),
                },
                "forms": self.forms,
                "artifacts": artifacts,
            }

            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)

            self.log(f"✅ Результаты экспортированы: {path}", "success")
            messagebox.showinfo("✅ Экспорт", f"Результаты сохранены в:\n{path}")

        except Exception as e:
            self.log(f"❌ Ошибка экспорта: {e}", "error")
            messagebox.showerror(
                "Ошибка", f"Не удалось экспортировать результаты:\n{e}"
            )
