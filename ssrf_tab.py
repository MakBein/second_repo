# xss_security_gui/ssrf_tab.py

from __future__ import annotations

import json
import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Any, Dict, List

from xss_security_gui.settings import settings
from xss_security_gui.threat_analysis.ssrf_module import SSRFTester


class SSRFTab(ttk.Frame):
    """
    SSRFTab (ULTRA Hybrid 6.5+)
    ---------------------------
    • Гнучке завантаження payload-файлу (settings / аргумент / дефолт)
    • Потокобезпечний лог (через .after)
    • Кольорові теги (HIGH / INFO / ERROR)
    • Контроль потоків (active_tests, max_workers)
    • Уніфікований формат результатів (TesterBase + Threat Intel)
    • Стабільність GUI навіть при помилках
    """

    MAX_CYCLE_RUNS = 3

    def __init__(self, parent, url: str, payload_file: str | None = None) -> None:
        super().__init__(parent)

        self.url = url
        self.loop_running = False
        self.active_tests = 0
        self.max_workers = 5
        self._cycle_runs = 0
        self._cycle_budget: RequestBudget | None = None
        self._active_tester: SSRFTester | None = None

        default_file = (
            settings.get("ssrf.payload_file")
            if isinstance(settings, dict)
            else getattr(settings, "SSRF_PAYLOAD_FILE", "ssrf_payloads.json")
        )

        self.payload_file: str = payload_file or default_file
        self.payloads: Dict[str, List[str]] = self._load_payloads()

        self._build_ui()

    # ---------------------------------------------------------
    # Payload loader
    # ---------------------------------------------------------
    def _load_payloads(self) -> Dict[str, List[str]]:
        try:
            with open(self.payload_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                raise ValueError("Файл payload-ів повинен містити JSON-об'єкт з категоріями")

            normalized: Dict[str, List[str]] = {}
            for k, v in data.items():
                if isinstance(v, list):
                    normalized[k] = v
                else:
                    normalized[k] = [str(v)]
            return normalized

        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося завантажити SSRF payload-и:\n{e}")
            return {}

    # ---------------------------------------------------------
    # UI builder
    # ---------------------------------------------------------
    def _build_ui(self) -> None:
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
        self.param_entry.insert(0, "url")
        self.param_entry.grid(row=1, column=1, sticky="w", padx=5)

        # Значення
        ttk.Label(top, text="Базове значення:").grid(row=1, column=2, sticky="e", padx=5)
        self.value_entry = ttk.Entry(top, width=25)
        self.value_entry.insert(0, "")
        self.value_entry.grid(row=1, column=3, sticky="w", padx=5)

        # Категорія payload-ів
        ttk.Label(top, text="Категорія payload-ів:").grid(row=2, column=0, sticky="w", padx=5)
        self.category_var = tk.StringVar(self)
        categories = ["Всі категорії"] + sorted(self.payloads.keys())
        self.category_var.set("Всі категорії")

        self.category_combo = ttk.Combobox(
            top,
            textvariable=self.category_var,
            values=categories,
            state="readonly",
        )
        self.category_combo.grid(row=2, column=1, sticky="w", padx=5)

        # Ліміт потоків
        ttk.Label(top, text="Паралельні тести (фіксовано 1):").grid(
            row=3, column=0, sticky="w", padx=5
        )
        self.workers_var = tk.IntVar(value=1)
        workers_spin = ttk.Spinbox(
            top,
            from_=1,
            to=1,
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
            self,
            height=20,
            wrap="none",
            bg="black",
            fg="white",
            insertbackground="white",
        )
        self.output.pack(fill="both", expand=True, padx=5, pady=5)

        # Теги
        self.output.tag_config("HIGH", foreground="lime")
        self.output.tag_config("INFO", foreground="yellow")
        self.output.tag_config("ERROR", foreground="red")

    # ---------------------------------------------------------
    # Thread-safe log
    # ---------------------------------------------------------
    def _safe_log(self, data: Any) -> None:
        self.after(0, lambda: self._append_text(data))

    def _append_text(self, data: Any) -> None:
        if isinstance(data, tuple):
            text, tag = data
            self.output.insert("end", text, tag)
        else:
            self.output.insert("end", data)
        self.output.see("end")

    # ---------------------------------------------------------
    # Workers
    # ---------------------------------------------------------
    def _update_workers(self) -> None:
        self.max_workers = 1
        self.workers_var.set(self.max_workers)

    # ---------------------------------------------------------
    # URL update
    # ---------------------------------------------------------
    def update_url(self) -> None:
        from xss_security_gui.auto_recon.scope import (
            is_target_authorized,
            normalize_http_url,
        )

        try:
            self.url = normalize_http_url(self.url_var.get())
        except ValueError as exc:
            self._safe_log((f"❌ Некоректний URL: {exc}\n", "ERROR"))
            return

        if not is_target_authorized(self.url):
            self._safe_log(
                (
                    "🚫 Реальні запити вимкнені: ціль має бути дозволена "
                    "через ALLOW_REAL_RUN і ALLOWED_TARGETS.\n",
                    "ERROR",
                )
            )
            return
        self._safe_log(f"🔄 Авторизовану ціль оновлено: {self.url}\n")

    # ---------------------------------------------------------
    # Single run
    # ---------------------------------------------------------
    def run_tests(self) -> None:
        from xss_security_gui.auto_recon.scope import (
            is_target_authorized,
            normalize_http_url,
        )

        if not self.payloads:
            messagebox.showerror("Помилка", "Payload-и не завантажені")
            return

        if self.active_tests:
            self._safe_log("⚠️ Дочекайтесь завершення поточного SSRF-запуску\n")
            return

        param = self.param_entry.get().strip()
        base_value = self.value_entry.get().strip()
        category = self.category_var.get()

        try:
            target = normalize_http_url(self.url_var.get())
        except ValueError as exc:
            self._safe_log((f"❌ Некоректний URL: {exc}\n", "ERROR"))
            return
        if not is_target_authorized(target):
            self._safe_log(
                (
                    f"🚫 Запуск заблоковано: {target} не дозволений "
                    "політикою ALLOW_REAL_RUN/ALLOWED_TARGETS.\n",
                    "ERROR",
                )
            )
            return
        if not param:
            self._safe_log("⚠️ Параметр не може бути порожнім\n")
            return

        if category == "Всі категорії":
            selected_payloads = self.payloads
        else:
            selected_payloads = {category: self.payloads.get(category, [])}

        self.url = target
        self._start_tester(target, param, base_value, selected_payloads)

    # ---------------------------------------------------------
    # Loop mode
    # ---------------------------------------------------------
    def start_loop(self) -> None:
        from xss_security_gui.auto_recon.scope import (
            RequestBudget,
            is_target_authorized,
            normalize_http_url,
        )

        if self.loop_running:
            return
        if not self.payloads:
            self._safe_log("❌ Payload-и не завантажені — цикл не запущено\n")
            return

        try:
            self.url = normalize_http_url(self.url_var.get())
        except ValueError as exc:
            self._safe_log((f"❌ Некоректний URL: {exc}\n", "ERROR"))
            return
        if not is_target_authorized(self.url):
            self._safe_log(
                (
                    "🚫 Цикл заблоковано: потрібні ALLOW_REAL_RUN і "
                    "дозволений хост у ALLOWED_TARGETS.\n",
                    "ERROR",
                )
            )
            return

        self.loop_running = True
        self._cycle_runs = 0
        self._cycle_budget = RequestBudget(
            SSRFTester.MAX_REQUESTS * self.MAX_CYCLE_RUNS
        )
        self._safe_log(
            f"🔁 Цикл SSRF запущено (ліміт {self.MAX_CYCLE_RUNS} проходи, "
            f"до {self._cycle_budget.limit} запитів)\n"
        )
        self._run_ssrf_cycle()

    def stop_loop(self) -> None:
        if self.loop_running:
            self._safe_log("⛔ Цикл зупинено\n")
        self.loop_running = False
        tester = self._active_tester
        if tester is not None and tester.is_alive():
            tester.stop()
            self._safe_log("⏹️ Надіслано запит на зупинку активного тесту\n")

    def _run_ssrf_cycle(self) -> None:
        if not self.loop_running:
            return

        if self.active_tests == 0:
            self._try_start_test_from_cycle()

        if self.loop_running:
            self.after(300, self._run_ssrf_cycle)

    def _try_start_test_from_cycle(self) -> bool:
        from xss_security_gui.auto_recon.scope import is_target_authorized

        if not self.payloads:
            self._safe_log("⚠️ Цикл: payload-и не завантажені, запуск неможливий\n")
            return False

        param = self.param_entry.get().strip()
        base_value = self.value_entry.get().strip()
        category = self.category_var.get()

        if not param:
            self._safe_log("⚠️ Цикл: порожній параметр — тест не буде запущено\n")
            return False

        if category == "Всі категорії":
            selected_payloads = self.payloads
        else:
            cat_payloads = self.payloads.get(category) or []
            if not cat_payloads:
                self._safe_log(f"⚠️ Цикл: у категорії '{category}' немає payload-ів\n")
                return False
            selected_payloads = {category: cat_payloads}

        if self.active_tests:
            return False
        if not is_target_authorized(self.url):
            self._safe_log(("🚫 Ціль втратила дозвіл; цикл зупинено.\n", "ERROR"))
            self.stop_loop()
            return False

        budget = self._cycle_budget
        if budget is None or budget.used >= budget.limit:
            self.stop_loop()
            return False
        self._cycle_runs += 1
        self._start_tester(
            self.url, param, base_value, selected_payloads, request_budget=budget
        )
        return True

    def _start_tester(
        self,
        target: str,
        param: str,
        base_value: str,
        payloads: Dict[str, List[str]],
        request_budget: RequestBudget | None = None,
    ) -> None:
        tester = SSRFTester(
            base_url=target,
            param=param,
            base_value=base_value,
            payloads=payloads,
            output_callback=self._on_test_finish,
            request_budget=request_budget,
        )
        self.active_tests = 1
        try:
            tester.start()
        except RuntimeError as exc:
            self.active_tests = 0
            self._safe_log((f"❌ Не вдалося запустити SSRF-тест: {exc}\n", "ERROR"))
            return
        self._active_tester = tester
        threading.Thread(
            target=self._watch_tester,
            args=(tester,),
            daemon=True,
        ).start()
        self._safe_log(
            f"🚀 SSRF-тест запущено для {target}; ліміт запитів: "
            f"{request_budget.limit if request_budget else SSRFTester.MAX_REQUESTS}\n"
        )

    def _watch_tester(self, tester: SSRFTester) -> None:
        tester.join()
        self.after(0, self._on_tester_finished, tester)

    def _on_tester_finished(self, tester: SSRFTester) -> None:
        if not self.winfo_exists():
            return
        self.active_tests = 0
        if self._active_tester is tester:
            self._active_tester = None
        if self.loop_running:
            if self._cycle_runs >= self.MAX_CYCLE_RUNS:
                self.stop_loop()
                self._safe_log("✅ Досягнуто ліміт проходів SSRF-циклу\n")
            elif (
                self._cycle_budget is None
                or self._cycle_budget.used >= self._cycle_budget.limit
            ):
                self.stop_loop()
                self._safe_log("✅ Досягнуто ліміт запитів SSRF-циклу\n")
        self._safe_log("[INFO] SSRF-тест завершився\n")

    # ---------------------------------------------------------
    # Callback from tester
    # ---------------------------------------------------------
    def _on_test_finish(self, result: Dict[str, Any]) -> None:
        self.display_result(result)

    # ---------------------------------------------------------
    # Display result
    # ---------------------------------------------------------
    def display_result(self, result: Dict[str, Any]) -> None:
        if not result:
            self._safe_log("⚠️ Порожній результат від SSRFTester\n")
            return

        details = result.get("details", {})
        severity = result.get("severity") or details.get("severity") or "INFO"

        category = result.get("category", "?")
        payload = result.get("payload", "?")

        http_status = details.get("http_status", "?")
        resp_len = details.get("response_length")
        redirected_to_local = details.get("redirected_to_local", False)
        body_hit = details.get("body_hit", False)
        body_hint = details.get("body_hint", False)
        header_hit = details.get("header_hit", False)

        len_part = f"(len={resp_len})" if isinstance(resp_len, (int, float)) else ""

        line = (
            f"[{category}] {payload} → {severity} "
            f"(HTTP {http_status}) {len_part} "
            f"(body={body_hit}, hint={body_hint}, hdr={header_hit}, "
            f"local={redirected_to_local})\n"
        )

        tag = "HIGH" if severity == "HIGH" else ("ERROR" if severity == "ERROR" else "INFO")
        self._safe_log((line, tag))

        if self.verbose_var.get():
            raw = details.get("raw")
            if raw:
                self._safe_log((f"RAW: {raw[:500]}\n", tag))

    # ---------------------------------------------------------
    # Clear output
    # ---------------------------------------------------------
    def clear_output(self) -> None:
        self.output.delete("1.0", "end")

    # ---------------------------------------------------------
    # Choose payload file
    # ---------------------------------------------------------
    def choose_payload_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Вибрати файл SSRF payload-ів",
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

    # ---------------------------------------------------------
    # Clear artifact log
    # ---------------------------------------------------------
    def clear_artifact_log(self) -> None:
        artifact_path = (
            settings.get("threat_intel.artifact_path")
            if isinstance(settings, dict)
            else getattr(settings, "THREAT_INTEL_ARTIFACT_PATH", "threat_artifacts.json")
        )

        try:
            os.makedirs(os.path.dirname(artifact_path), exist_ok=True)
            with open(artifact_path, "w", encoding="utf-8") as f:
                json.dump([], f)
            self._safe_log(f"✅ Лог артефактів очищено: {artifact_path}\n")
        except Exception as e:
            self._safe_log(f"❌ Помилка очищення: {e}\n")