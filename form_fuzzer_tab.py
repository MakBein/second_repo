# xss_security_gui/form_fuzzer_tab.py

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os
import threading
from datetime import datetime
from typing import Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from form_fuzzer import fuzz_form
from utils.threat_sender import ThreatSenderMixin
from utils.core_utils import normalize_url


class FormFuzzerTab(ttk.Frame, ThreatSenderMixin):
    """Агрессивный фуззер форм с многопоточностью и расширенными настройками"""
    
    def __init__(self, parent, json_path="logs/crawler_results.json", threat_tab=None):
        super().__init__(parent)
        self.json_path = json_path
        self.forms: List[Dict[str, Any]] = []
        self.threat_tab = threat_tab
        self.is_fuzzing = False
        self.fuzzing_thread: Optional[threading.Thread] = None
        self.executor: Optional[ThreadPoolExecutor] = None
        
        # Агрессивные настройки по умолчанию
        self.max_workers = 30  # Больше потоков для агрессивного фуззинга
        self.timeout = 6.0  # Увеличенный таймаут
        self.aggressive_mode = True
        
        self.build_ui()

    def build_ui(self):
        """Построение интерфейса с расширенными настройками"""
        # Панель управления
        ctrl = ttk.Frame(self)
        ctrl.pack(pady=5, fill="x")
        
        # Основные кнопки
        btn_frame = ttk.Frame(ctrl)
        btn_frame.pack(side="left", padx=5)
        
        ttk.Button(btn_frame, text="📥 Загрузить формы", command=self.load_forms).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="🧪 Фуззить все", command=self.start_fuzzing).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="🛑 Остановить", command=self.stop_fuzzing).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="♻️ Очистить", command=self.clear_results).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="💾 Экспорт", command=self.export_results).pack(side="left", padx=2)
        
        # Настройки агрессивности
        settings_frame = ttk.LabelFrame(ctrl, text="⚙️ Агрессивные настройки")
        settings_frame.pack(side="left", padx=10, fill="x", expand=True)
        
        ttk.Label(settings_frame, text="Потоков:").grid(row=0, column=0, padx=2)
        self.workers_spin = ttk.Spinbox(settings_frame, from_=1, to=100, width=8)
        self.workers_spin.set(str(self.max_workers))
        self.workers_spin.grid(row=0, column=1, padx=2)
        
        ttk.Label(settings_frame, text="Таймаут:").grid(row=0, column=2, padx=2)
        self.timeout_spin = ttk.Spinbox(settings_frame, from_=1, to=30, width=8)
        self.timeout_spin.set(str(self.timeout))
        self.timeout_spin.grid(row=0, column=3, padx=2)
        
        self.aggressive_var = tk.BooleanVar(value=self.aggressive_mode)
        ttk.Checkbutton(
            settings_frame,
            text="🔥 Агрессивный режим",
            variable=self.aggressive_var
        ).grid(row=0, column=4, padx=5)
        
        # Путь к JSON
        path_frame = ttk.Frame(ctrl)
        path_frame.pack(side="right", padx=5)
        ttk.Label(path_frame, text="JSON:").pack(side="left", padx=2)
        self.json_path_entry = ttk.Entry(path_frame, width=30)
        self.json_path_entry.insert(0, self.json_path)
        self.json_path_entry.pack(side="left", padx=2)
        ttk.Button(path_frame, text="📂", command=self.select_json_file, width=3).pack(side="left", padx=2)
        
        # Прогресс-бар
        self.progress = ttk.Progressbar(self, mode='determinate')
        self.progress.pack(fill="x", padx=10, pady=2)
        
        self.status_label = ttk.Label(self, text="Готов к запуску")
        self.status_label.pack(pady=2)
        
        # Результаты
        result_frame = ttk.Frame(self)
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.result_box = tk.Text(result_frame, height=30, bg="black", fg="lime", insertbackground="white", wrap="word")
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.result_box.yview)
        self.result_box.configure(yscrollcommand=scrollbar.set)
        
        self.result_box.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Настройка тегов для подсветки
        self.result_box.tag_config("xss", foreground="yellow", background="#440000", font=("Consolas", 10, "bold"))
        self.result_box.tag_config("success", foreground="lime", font=("Consolas", 10))
        self.result_box.tag_config("error", foreground="red", font=("Consolas", 10))
        self.result_box.tag_config("info", foreground="cyan", font=("Consolas", 9))
        self.result_box.tag_config("warning", foreground="orange", font=("Consolas", 9))

    def log(self, text: str, tag: Optional[str] = None):
        """Потокобезопасное логирование"""
        def _log():
            self.result_box.insert("end", text + "\n", tag)
            self.result_box.see("end")
        
        if threading.current_thread() == threading.main_thread():
            _log()
        else:
            self.after(0, _log)

    def update_status(self, text: str):
        """Обновление статуса"""
        def _update():
            self.status_label.config(text=text)
        
        if threading.current_thread() == threading.main_thread():
            _update()
        else:
            self.after(0, _update)

    def clear_results(self):
        """Очистка результатов"""
        self.result_box.delete("1.0", "end")
        self.progress['value'] = 0
        self.update_status("Готов к запуску")

    def select_json_file(self):
        """Выбор JSON файла"""
        path = filedialog.askopenfilename(
            title="Выбери JSON файл с результатами краулинга",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if path:
            self.json_path = path
            self.json_path_entry.delete(0, "end")
            self.json_path_entry.insert(0, path)

    def load_forms(self):
        """Загрузка форм из JSON с улучшенной обработкой ошибок"""
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

        forms_count = 0
        for page_idx, page in enumerate(data, 1):
            if not isinstance(page, dict):
                self.log(f"⚠️ Пропущена невалидная страница #{page_idx}", "warning")
                continue

            url = page.get("url", "")
            if not url:
                continue

            forms = page.get("forms", [])
            if not forms:
                continue

            for form in forms:
                if not isinstance(form, dict):
                    continue
                
                inputs = form.get("inputs", [])
                if not inputs:  # Пропускаем формы без полей
                    continue

                handlers = form.get("js_events", {})
                handler_info = ", ".join(f"{k}: {v}" for k, v in handlers.items()) if handlers else "—"

                self.forms.append({
                    "url": normalize_url(url),
                    "action": form.get("action", ""),
                    "method": form.get("method", "GET").upper(),
                    "inputs": inputs,
                    "handlers": handler_info,
                    "page_url": url
                })
                forms_count += 1

        self.log(f"✅ Загружено форм: {forms_count}", "success")
        self.update_status(f"Загружено {forms_count} форм")
        
        if forms_count == 0:
            messagebox.showwarning("⚠️ Нет форм", "Не найдено форм с полями для тестирования")

    def start_fuzzing(self):
        """Запуск агрессивного фуззинга всех форм"""
        if not self.forms:
            messagebox.showwarning("⚠️ Нет форм", "Сначала загрузите формы")
            return

        if self.is_fuzzing:
            messagebox.showwarning("⚠️ Уже выполняется", "Фуззинг уже запущен")
            return

        # Получаем настройки из UI
        try:
            self.max_workers = int(self.workers_spin.get())
        except ValueError:
            self.max_workers = 30
        
        try:
            self.timeout = float(self.timeout_spin.get())
        except ValueError:
            self.timeout = 6.0
        
        self.aggressive_mode = self.aggressive_var.get()
        
        # Запускаем в отдельном потоке
        self.is_fuzzing = True
        self.fuzzing_thread = threading.Thread(target=self._fuzz_all_forms_thread, daemon=True)
        self.fuzzing_thread.start()

    def stop_fuzzing(self):
        """Остановка фуззинга"""
        if not self.is_fuzzing:
            return
        
        self.is_fuzzing = False
        if self.executor:
            # Останавливаем executor (завершит текущие задачи, но не начнёт новые)
            self.executor.shutdown(wait=False, cancel_futures=True)
        
        self.log("🛑 Остановка фуззинга...", "warning")
        self.update_status("Остановка...")

    def _fuzz_all_forms_thread(self):
        """Основной поток фуззинга с параллельной обработкой форм"""
        total_forms = len(self.forms)
        self.log(f"🎯 Начинаем агрессивный XSS-фуззинг {total_forms} форм...", "info")
        self.log(f"⚙️ Настройки: {self.max_workers} потоков, таймаут {self.timeout}s, агрессивный режим: {self.aggressive_mode}", "info")
        self.log("=" * 80, "info")
        
        self.progress['maximum'] = total_forms
        self.progress['value'] = 0
        
        all_hits = []
        processed = 0
        errors = 0
        
        # Используем ThreadPoolExecutor для параллельной обработки форм
        with ThreadPoolExecutor(max_workers=min(self.max_workers, total_forms)) as executor:
            self.executor = executor
            futures: Dict[Future, Dict[str, Any]] = {}
            
            # Запускаем фуззинг всех форм параллельно
            for form in self.forms:
                if not self.is_fuzzing:
                    break
                
                future = executor.submit(self._fuzz_single_form, form, processed + 1, total_forms)
                futures[future] = form
            
            # Обрабатываем результаты по мере готовности
            for future in as_completed(futures):
                if not self.is_fuzzing:
                    break
                
                form = futures[future]
                try:
                    hits = future.result()
                    if hits:
                        all_hits.extend(hits)
                        for hit in hits:
                            self._log_to_file(form, hit)
                            # Отправка в Threat Intel
                            if self.threat_tab:
                                self.send_to_threat_intel("form_fuzzer", [hit])
                    
                    processed += 1
                    self.progress['value'] = processed
                    self.update_status(f"Обработано: {processed}/{total_forms} | Найдено XSS: {len(all_hits)}")
                    
                except Exception as e:
                    errors += 1
                    self.log(f"❌ Ошибка при обработке формы {form.get('url', 'unknown')}: {e}", "error")
                    processed += 1
                    self.progress['value'] = processed
        
        self.executor = None
        self.is_fuzzing = False
        
        # Итоговая статистика
        self.log("=" * 80, "info")
        self.log(f"✅ Фуззинг завершён!", "success")
        self.log(f"📊 Статистика:", "info")
        self.log(f"   • Обработано форм: {processed}/{total_forms}", "info")
        self.log(f"   • Найдено XSS: {len(all_hits)}", "success" if all_hits else "info")
        self.log(f"   • Ошибок: {errors}", "error" if errors > 0 else "info")
        
        self.update_status(f"Завершено: {processed} форм, {len(all_hits)} XSS найдено")
        
        if all_hits:
            messagebox.showinfo("✅ Результаты", f"Найдено {len(all_hits)} XSS уязвимостей!\nПроверьте логи для деталей.")

    def _fuzz_single_form(self, form: Dict[str, Any], idx: int, total: int) -> List[Dict[str, Any]]:
        """Фуззинг одной формы"""
        try:
            action = form.get("action", "")
            base_url = form.get("url", "")
            
            # Формируем полный URL
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
            
            # Определяем подозрительные поля
            suspicious = [
                i for i in inputs 
                if any(x in i.lower() for x in ["query", "search", "msg", "comment", "text", "input", "data", "content"])
            ]
            
            # Логируем информацию о форме
            self.log(f"\n📨 [{idx}/{total}] {method} {full_url}", "info")
            self.log(f"🔧 Параметры: {inputs}", "info")
            if suspicious:
                self.log(f"⚠️ Подозрительные поля: {suspicious}", "warning")
            if form.get("handlers") and form.get("handlers") != "—":
                self.log(f"🧠 JS обработчики: {form['handlers']}", "info")
            
            # Запускаем фуззинг с агрессивными настройками
            results = fuzz_form(
                action_url=full_url,
                method=method,
                inputs=inputs,
                max_workers=self.max_workers if self.aggressive_mode else 10,
                timeout=self.timeout,
                allowlist=None  # Можно добавить проверку allowlist
            )
            
            hits = [r for r in results if r.get("vulnerable")]
            
            if hits:
                for hit in hits:
                    payload = hit.get("payload", "")
                    category = hit.get("category", "❓")
                    status = hit.get("status", "?")
                    self.log(f"  ✔️ XSS НАЙДЕН: {payload[:60]}... [{category}] Status: {status}", "xss")
            else:
                self.log(f"  ❌ Уязвимость не найдена", "info")
            
            return hits
            
        except Exception as e:
            self.log(f"  ❌ Ошибка при фуззинге формы: {e}", "error")
            return []

    def _log_to_file(self, form: Dict[str, Any], result: Dict[str, Any]):
        """Детальное логирование найденных уязвимостей"""
        try:
            os.makedirs("logs", exist_ok=True)
            with open("logs/gui_fuzzer_results.log", "a", encoding="utf-8") as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"[{datetime.now()}] XSS DETECTED\n")
                f.write(f"{'='*80}\n")
                f.write(f"URL: {form.get('action') or form.get('url', 'unknown')}\n")
                f.write(f"Method: {form.get('method', 'GET')}\n")
                f.write(f"Inputs: {form.get('inputs', [])}\n")
                f.write(f"Handlers: {form.get('handlers', '—')}\n")
                f.write(f"Payload: {result.get('payload', '—')}\n")
                f.write(f"Category: {result.get('category', '-')}\n")
                f.write(f"Status: {result.get('status', '-')}\n")
                f.write(f"Vulnerable: {result.get('vulnerable', False)}\n")
                snippet = result.get('snippet', '').strip()[:500]
                f.write(f"Snippet: {snippet}\n")
                if result.get('error'):
                    f.write(f"Error: {result.get('error')}\n")
                f.write(f"{'='*80}\n\n")
        except Exception as e:
            self.log(f"⚠️ Ошибка записи в лог: {e}", "warning")

    def export_results(self):
        """Экспорт результатов в JSON"""
        if not self.forms:
            messagebox.showwarning("⚠️ Нет данных", "Сначала загрузите и протестируйте формы")
            return
        
        path = filedialog.asksaveasfilename(
            title="Сохранить результаты",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not path:
            return
        
        try:
            # Читаем существующие результаты из лога
            results = []
            log_path = "logs/gui_fuzzer_results.log"
            if os.path.exists(log_path):
                # Парсим лог для извлечения результатов
                # (упрощённая версия - можно улучшить)
                pass
            
            # Экспортируем формы и их статус
            export_data = {
                "exported_at": datetime.now().isoformat(),
                "total_forms": len(self.forms),
                "forms": self.forms
            }
            
            with open(path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            self.log(f"✅ Результаты экспортированы: {path}", "success")
            messagebox.showinfo("✅ Экспорт", f"Результаты сохранены в:\n{path}")
            
        except Exception as e:
            self.log(f"❌ Ошибка экспорта: {e}", "error")
            messagebox.showerror("Ошибка", f"Не удалось экспортировать результаты:\n{e}")
