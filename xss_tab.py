# xss_security_gui/xss_tab.py

import os
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Any, Dict, List

from xss_security_gui.settings import settings
from xss_security_gui.threat_analysis.xss_module import XSSTester


class XSSTab(ttk.Frame):
    """
    XSSTab (ULTRA Hybrid 6.5+)
    --------------------------
    • Потокобезпечний лог
    • Кольорові теги (HIGH / MEDIUM / LOW / INFO / ERROR)
    • Контроль потоків (active_tests, max_workers)
    • Циклічний режим тестування
    • Уніфікований формат результатів (TesterBase)
    • Відображення контексту XSS (JS/HTML/Attribute/URL)
    """

    def __init__(self, parent: tk.Misc, url: str, payload_file: str | None = None) -> None:
        super().__init__(parent)

        self.url = url
        self.active_tests = 0
        self.max_workers = 5
        self.loop_running = False

        default_payload_file = settings.get("xss.payload_file", "xss_payloads.json")
        base_dir = os.path.dirname(__file__)
        self.payload_file = payload_file or os.path.join(base_dir, default_payload_file)

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
                raise ValueError("Файл payload-ів повинен містити JSON-об'єкт")

            normalized: Dict[str, List[str]] = {}
            for cat, items in data.items():
                normalized[cat] = [str(x) for x in items] if isinstance(items, list) else [str(items)]
            return normalized

        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося завантажити XSS payload-и:\n{e}")
            return {}

    # ---------------------------------------------------------
    # UI builder
    # ---------------------------------------------------------
    def _build_ui(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill="x", pady=5)

        ttk.Label(top, text="Цільовий URL:").grid(row=0, column=0, sticky="w", padx=5)
        self.url_var = tk.StringVar(value=self.url)
        self.url_entry = ttk.Entry(top, textvariable=self.url_var, width=70)
        self.url_entry.grid(row=0, column=1, columnspan=3, sticky="we", padx=5)

        ttk.Button(top, text="Оновити URL", command=self.update_url).grid(
            row=0, column=4, sticky="w", padx=5
        )

        ttk.Label(top, text="Параметр:").grid(row=1, column=0, sticky="w", padx=5)
        self.param_entry = ttk.Entry(top, width=20)
        self.param_entry.insert(0, "q")
        self.param_entry.grid(row=1, column=1, sticky="w", padx=5)

        ttk.Label(top, text="Базове значення:").grid(row=1, column=2, sticky="e", padx=5)
        self.value_entry = ttk.Entry(top, width=20)
        self.value_entry.insert(0, "")
        self.value_entry.grid(row=1, column=3, sticky="w", padx=5)

        ttk.Label(top, text="Категорія payload-ів:").grid(row=2, column=0, sticky="w", padx=5)
        self.category_var = tk.StringVar(self)
        categories = ["Всі категорії"] + sorted(self.payloads.keys())
        self.category_var.set("Всі категорії")

        self.category_combo = ttk.Combobox(
            top, textvariable=self.category_var, values=categories, state="readonly"
        )
        self.category_combo.grid(row=2, column=1, sticky="w", padx=5)

        ttk.Label(top, text="Макс. потоків:").grid(row=3, column=0, sticky="w", padx=5)
        self.workers_var = tk.IntVar(value=self.max_workers)
        workers_spin = ttk.Spinbox(
            top, from_=1, to=50, textvariable=self.workers_var, width=5, command=self._update_workers
        )
        workers_spin.grid(row=3, column=1, sticky="w", padx=5)

        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Детальний лог", variable=self.verbose_var).grid(
            row=3, column=2, sticky="w", padx=5
        )

        btn_frame = ttk.Frame(top)
        btn_frame.grid(row=3, column=3, columnspan=2, sticky="e", padx=5)

        ttk.Button(btn_frame, text="💉 Разовий запуск", command=self.run_tests).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="🔁 Цикл", command=self.start_loop).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="⛔ Зупинити", command=self.stop_loop).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="🧹 Очистити", command=self.clear_output).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="📂 Payload-файл", command=self.choose_payload_file).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="🗑 Артефакти", command=self.clear_artifact_log).pack(side="left", padx=3)

        self.output = tk.Text(
            self, height=20, wrap="none", bg="black", fg="white", insertbackground="white"
        )
        self.output.pack(fill="both", expand=True, padx=5, pady=5)

        self.output.tag_config("HIGH", foreground="lime")
        self.output.tag_config("MEDIUM", foreground="yellow")
        self.output.tag_config("LOW", foreground="cyan")
        self.output.tag_config("INFO", foreground="white")
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
        value = self.workers_var.get()
        if value < 1:
            value = 1
        self.max_workers = value
        self.workers_var.set(value)
        self._safe_log(f"⚙️ Макс. потоків встановлено: {self.max_workers}\n")

    # ---------------------------------------------------------
    # URL update
    # ---------------------------------------------------------
    def update_url(self) -> None:
        self.url = self.url_var.get().strip()
        self._safe_log(f"🔄 URL оновлено: {self.url}\n")

    # ---------------------------------------------------------
    # Single run
    # ---------------------------------------------------------
    def run_tests(self) -> None:
        if not self.payloads:
            messagebox.showerror("Помилка", "Payload-и не завантажені")
            return

        if self.active_tests >= self.max_workers:
            self._safe_log("⚠️ Досягнуто ліміт потоків\n")
            return

        param = self.param_entry.get().strip()
        base_value = self.value_entry.get().strip()
        category = self.category_var.get()

        if not param:
            self._safe_log("⚠️ Параметр не може бути порожнім\n")
            return

        selected_payloads = (
            self.payloads if category == "Всі категорії" else {category: self.payloads.get(category, [])}
        )

        tester = XSSTester(
            base_url=self.url,
            param=param,
            base_value=base_value,
            payloads=selected_payloads,
            output_callback=self._on_test_finish,
        )
        tester.start()
        self.active_tests += 1

        self._safe_log(f"🚀 Запущено XSS-тестування для {self.url} (param={param})\n")

    # ---------------------------------------------------------
    # Loop mode
    # ---------------------------------------------------------
    def start_loop(self) -> None:
        if self.loop_running:
            return
        if not self.payloads:
            self._safe_log("❌ Payload-и не завантажені — цикл не запущено\n")
            return

        self.loop_running = True
        self._safe_log("🔁 Цикл XSS запущено\n")
        self._run_xss_cycle()

    def stop_loop(self) -> None:
        if self.loop_running:
            self._safe_log("⛔ Цикл зупинено\n")
        self.loop_running = False

    def _run_xss_cycle(self) -> None:
        if not self.loop_running:
            return

        if self.active_tests < self.max_workers:
            self._try_start_test_from_cycle()

        self.after(300, self._run_xss_cycle)

    def _try_start_test_from_cycle(self) -> bool:
        param = self.param_entry.get().strip()
        base_value = self.value_entry.get().strip()
        category = self.category_var.get()

        if not param:
            self._safe_log("⚠️ Цикл: порожній параметр\n")
            return False

        selected_payloads = (
            self.payloads if category == "Всі категорії" else {category: self.payloads.get(category, [])}
        )

        tester = XSSTester(
            base_url=self.url,
            param=param,
            base_value=base_value,
            payloads=selected_payloads,
            output_callback=self._on_test_finish,
        )
        tester.start()
        self.active_tests += 1

        self._safe_log(
            f"🔁 Цикл: XSS-тест запущено (param={param}, category={category}, активних={self.active_tests})\n"
        )
        return True

    # ---------------------------------------------------------
    # Callback
    # ---------------------------------------------------------
    def _on_test_finish(self, result: Dict[str, Any]) -> None:
        self.active_tests = max(0, self.active_tests - 1)
        self.display_result(result)

    # ---------------------------------------------------------
    # Display result
    # ---------------------------------------------------------
    def display_result(self, result: Dict[str, Any]) -> None:
        if not isinstance(result, dict):
            self._safe_log("⚠️ Некоректний результат\n")
            return

        details = result.get("details", {})
        severity = result.get("severity") or details.get("severity") or "INFO"

        category = result.get("category", "?")
        payload = result.get("payload", "?")
        context = details.get("context_type", "Unknown")
        reflected = details.get("reflected", False)

        http_status = details.get("http_status", "?")
        resp_len = details.get("response_length")
        len_part = f"(len={resp_len})" if isinstance(resp_len, (int, float)) else ""

        line = (
            f"[{category}] {payload} → {severity} "
            f"(HTTP {http_status}) {len_part} "
            f"(reflected={reflected}, ctx={context})\n"
        )

        tag = severity if severity in ("HIGH", "MEDIUM", "LOW", "INFO", "ERROR") else "INFO"
        self._safe_log((line, tag))

        if self.verbose_var.get():
            snippet = details.get("context_snippet")
            if snippet:
                self._safe_log((f"CTX: {snippet[:500]}\n", tag))

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
            title="Вибрати файл XSS payload-ів",
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
        artifact_path = settings.get("threat_intel.artifact_path", "threat_artifacts.json")
        try:
            os.makedirs(os.path.dirname(artifact_path), exist_ok=True)
            with open(artifact_path, "w", encoding="utf-8") as f:
                json.dump([], f)
            self._safe_log(f"✅ Лог артефактів очищено: {artifact_path}\n")
        except Exception as e:
            self._safe_log(f"❌ Помилка очищення: {e}\n")