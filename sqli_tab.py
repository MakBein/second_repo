# xss_security_gui/sqli_tab.py

import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Any, Dict, List

from xss_security_gui.settings import settings
from xss_security_gui.threat_analysis.sqli_module import SQLiTester


class SQLiTab(ttk.Frame):
    def __init__(self, parent, url: str, payload_file: str | None = None):
        super().__init__(parent)

        self.loop_running = False
        self.url = url

        # Керування потоками
        self.active_tests = 0
        self.max_workers = 5

        # Безпечний доступ до settings
        default_file = (
            settings.get("sqli.payload_file")
            if isinstance(settings, dict)
            else getattr(settings, "SQLI_PAYLOAD_FILE", "sqli_payloads.json")
        )

        self.payload_file = payload_file or default_file
        self.payloads: Dict[str, list] = self._load_payloads()

        self._build_ui()

    # ---------------------------------------------------------
    # Цикл SQLi
    # ---------------------------------------------------------
    def start_loop(self):
        if self.loop_running:
            return
        if not self.payloads:
            self._safe_log("❌ Payload-и не завантажені — цикл не запущено\n")
            return

        self.loop_running = True
        self._safe_log("🔁 Цикл SQLi запущено\n")
        self.run_sqli_cycle()

    def stop_loop(self):
        if self.loop_running:
            self._safe_log("⛔ Цикл зупинено\n")
        self.loop_running = False

    def _on_test_finish(self, result: Dict[str, Any]):
        self.active_tests = max(0, self.active_tests - 1)
        self.display_result(result)

    def run_sqli_cycle(self):
        if not self.loop_running:
            return

        if self.active_tests < self.max_workers:
            self._try_start_test_from_cycle()

        self.after(300, self.run_sqli_cycle)

    def _try_start_test_from_cycle(self) -> bool:
        if not self.payloads:
            self._safe_log("⚠️ Цикл: payload-и не завантажені, запуск неможливий\n")
            return False

        param = self.param_entry.get().strip()
        base_value = self.value_entry.get().strip()
        category = self.category_var.get()

        if not param or not base_value:
            self._safe_log("⚠️ Цикл: порожній параметр або значення — тест не буде запущено\n")
            return False

        if category == "Всі категорії":
            selected_payloads = self.payloads
        else:
            cat_payloads = self.payloads.get(category) or []
            if not cat_payloads:
                self._safe_log(f"⚠️ Цикл: у категорії '{category}' немає payload-ів\n")
                return False
            selected_payloads = {category: cat_payloads}

        tester = SQLiTester(
            base_url=self.url,
            param=param,
            base_value=base_value,
            payloads=selected_payloads,
            output_callback=self._on_test_finish,
        )
        tester.start()
        self.active_tests += 1

        self._safe_log(
            f"🔁 Цикл: запущено SQLi-тест (param={param}, category={category}, активних={self.active_tests})\n"
        )
        return True

    # ---------------------------------------------------------
    # Payload loader
    # ---------------------------------------------------------
    def _load_payloads(self) -> Dict[str, list]:
        try:
            with open(self.payload_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                raise ValueError("Файл payload-ів повинен містити JSON-об'єкт з категоріями")

            return data

        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося завантажити SQLi payload-и:\n{e}")
            return {}

    # ---------------------------------------------------------
    # UI builder
    # ---------------------------------------------------------
    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill="x", pady=5)

        # URL
        ttk.Label(top, text="Цільовий URL:").grid(row=0, column=0, sticky="w", padx=5)
        self.url_var = tk.StringVar(value=self.url)

        self.url_entry = ttk.Entry(top, textvariable=self.url_var, width=70)
        self.url_entry.grid(row=0, column=1, columnspan=3, sticky="we", padx=5)

        ttk.Button(top, text="Оновити URL", command=self.update_url).grid(
            row=0, column=4, sticky="w", padx=5
        )

        # Параметр
        ttk.Label(top, text="Параметр:").grid(row=1, column=0, sticky="w", padx=5)
        self.param_entry = ttk.Entry(top, width=20)
        self.param_entry.insert(0, "id")
        self.param_entry.grid(row=1, column=1, sticky="w", padx=5)

        # Значення
        ttk.Label(top, text="Базове значення:").grid(row=1, column=2, sticky="e", padx=5)
        self.value_entry = ttk.Entry(top, width=20)
        self.value_entry.insert(0, "1")
        self.value_entry.grid(row=1, column=3, sticky="w", padx=5)

        # Категорія payload-ів
        ttk.Label(top, text="Категорія payload-ів:").grid(row=2, column=0, sticky="w", padx=5)
        self.category_var = tk.StringVar(self)
        categories = ["Всі категорії"] + sorted(self.payloads.keys())
        self.category_var.set("Всі категорії")

        self.category_combo = ttk.Combobox(
            top, textvariable=self.category_var, values=categories, state="readonly"
        )
        self.category_combo.grid(row=2, column=1, sticky="w", padx=5)

        # Ліміт потоків
        ttk.Label(top, text="Макс. потоків:").grid(row=3, column=0, sticky="w", padx=5)
        self.workers_var = tk.IntVar(value=self.max_workers)
        workers_spin = ttk.Spinbox(
            top,
            from_=1,
            to=50,
            textvariable=self.workers_var,
            width=5,
            command=self._update_workers,
        )
        workers_spin.grid(row=3, column=1, sticky="w", padx=5)

        # Детальний лог
        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Детальний лог", variable=self.verbose_var).grid(
            row=3, column=2, sticky="w", padx=5
        )

        # Buttons
        btn_frame = ttk.Frame(top)
        btn_frame.grid(row=3, column=3, columnspan=2, sticky="e", padx=5)

        ttk.Button(btn_frame, text="💉 Разовий запуск", command=self.run_tests).pack(
            side="left", padx=3
        )
        ttk.Button(btn_frame, text="🔁 Цикл", command=self.start_loop).pack(
            side="left", padx=3
        )
        ttk.Button(btn_frame, text="⛔ Зупинити", command=self.stop_loop).pack(
            side="left", padx=3
        )
        ttk.Button(btn_frame, text="🧹 Очистити вивід", command=self.clear_output).pack(
            side="left", padx=3
        )
        ttk.Button(btn_frame, text="📂 Вибрати payload-файл", command=self.choose_payload_file).pack(
            side="left", padx=3
        )
        ttk.Button(btn_frame, text="🗑 Очистити лог артефактів", command=self.clear_artifact_log).pack(
            side="left", padx=3
        )

        # Output
        self.output = tk.Text(
            self, height=20, wrap="none", bg="black", fg="lime", insertbackground="white"
        )
        self.output.pack(fill="both", expand=True, padx=5, pady=5)

        # Теги для кольорів
        self.output.tag_config("HIGH", foreground="lime")
        self.output.tag_config("INFO", foreground="yellow")
        self.output.tag_config("ERROR", foreground="red")

    # ---------------------------------------------------------
    # Thread-safe log
    # ---------------------------------------------------------
    def _safe_log(self, data) -> None:
        self.after(0, lambda: self._append_text(data))

    def _append_text(self, data) -> None:
        if isinstance(data, tuple):
            text, tag = data
            self.output.insert("end", text, tag)
        else:
            self.output.insert("end", data)
        self.output.see("end")

    # ---------------------------------------------------------
    # Actions
    # ---------------------------------------------------------
    def _update_workers(self):
        value = self.workers_var.get()
        if value < 1:
            value = 1
        self.max_workers = value
        self.workers_var.set(value)
        self._safe_log(f"⚙️ Макс. потоків встановлено: {self.max_workers}\n")

    def run_tests(self):
        if not self.payloads:
            messagebox.showerror("Помилка", "Payload-и не завантажені")
            return

        param = self.param_entry.get().strip()
        base_value = self.value_entry.get().strip()
        category = self.category_var.get()

        if not param or not base_value:
            self._safe_log("⚠️ Введіть параметр і значення перед запуском\n")
            return

        if self.active_tests >= self.max_workers:
            self._safe_log("⚠️ Досягнуто ліміт потоків, дочекайтесь завершення\n")
            return

        if category == "Всі категорії":
            selected_payloads = self.payloads
        else:
            selected_payloads = {category: self.payloads.get(category, [])}

        tester = SQLiTester(
            base_url=self.url,
            param=param,
            base_value=base_value,
            payloads=selected_payloads,
            output_callback=self._on_test_finish,
        )
        tester.start()
        self.active_tests += 1

        self._safe_log(f"🚀 Запущено SQLi-тестування для {self.url} (param={param})\n")

    def update_url(self):
        self.url = self.url_var.get().strip()
        self._safe_log(f"🔄 URL оновлено: {self.url}\n")

    def display_result(self, result: Dict[str, Any]):
        # if not result:
        #     return
        # Основні поля
        details = result.get("details", {})
        severity = result.get("severity") or details.get("severity") or "INFO"

        length = details.get("response_length")
        http_status = details.get("http_status", "?")
        body_hit = details.get("body_hit", False)
        header_hit = details.get("header_hit", False)

        category = result.get("category", "?")
        payload = result.get("payload", "?")

        # Вибір кольору
        tag = "HIGH" if severity == "HIGH" else ("ERROR" if severity == "ERROR" else "INFO")

        len_part = f"(len={length})" if isinstance(length, (int, float)) else ""
        line = (
            f"[{category}] {payload} → {severity} "
            f"(HTTP {http_status}) {len_part} "
            f"(body={body_hit}, waf={header_hit})\n"
        )

        self._safe_log((line, tag))

        # Детальний лог
        if self.verbose_var.get():
            raw = details.get("raw")
            if raw:
                self._safe_log((f"RAW: {raw[:500]}\n", tag))

    def clear_output(self):
        self.output.delete("1.0", "end")

    def choose_payload_file(self):
        path = filedialog.askopenfilename(
            title="Вибрати файл SQLi payload-ів",
            filetypes=[("JSON файли", "*.json"), ("Всі файли", "*.*")],
        )
        if not path:
            return

        self.payload_file = path
        self.payloads = self._load_payloads()

        categories = ["Всі категорії"] + sorted(self.payloads.keys())
        self.category_combo["values"] = categories
        self.category_var.set("Всі категорії")

        self._safe_log(f"✅ Payload-и завантажено з: {path}\n")

    def clear_artifact_log(self):
        artifact_path = (
            settings.get("threat_intel.artifact_path")
            if isinstance(settings, dict)
            else getattr(settings, "THREAT_INTEL_ARTIFACT_PATH", "threat_artifacts.json")
        )

        try:
            # Переконуємось, що директорія існує
            import os
            os.makedirs(os.path.dirname(artifact_path), exist_ok=True)

            with open(artifact_path, "w", encoding="utf-8") as f:
                json.dump([], f)

            self._safe_log(f"✅ Лог артефактів очищено: {artifact_path}\n")

        except Exception as e:
            self._safe_log(f"❌ Помилка очищення: {e}\n")
