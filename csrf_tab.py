# xss_security_gui/csrf_tab.py
import tkinter as tk
import json
from pathlib import Path
from typing import Any, Dict

from xss_security_gui.settings import PAYLOADS_DIR, THREAT_INTEL_ARTIFACT_PATH
from xss_security_gui.threat_analysis.csrf_module import CSRFTester


class CSRFTab(tk.Frame):
    def __init__(self, parent, url: str, payload_file: str | Path | None = None):
        super().__init__(parent)

        self.url = url
        self.active_tests = 0
        self.max_workers = 5

        # === Путь к payload-файлу ===
        self.payload_file = Path(payload_file) if payload_file else PAYLOADS_DIR / "csrf.json"

        # === Загрузка payload-ов ===
        self.payloads: Dict[str, list] = self._load_payloads()

        # === UI ===
        self._build_ui()

    # ============================================================
    #  Загрузка payload-ов
    # ============================================================
    def _load_payloads(self) -> Dict[str, list]:
        try:
            with open(self.payload_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
                print(f"[CSRF] Ожидался dict в {self.payload_file}, получено {type(data).__name__}")
        except Exception as e:
            print(f"[CSRF] Ошибка загрузки payload-файла: {e}")
        return {}

    # ============================================================
    #  UI
    # ============================================================
    def _build_ui(self) -> None:
        tk.Label(self, text="Параметр:").pack()
        self.param_entry = tk.Entry(self)
        self.param_entry.insert(0, "action")
        self.param_entry.pack()

        tk.Label(self, text="Значение:").pack()
        self.value_entry = tk.Entry(self)
        self.value_entry.insert(0, "")
        self.value_entry.pack()

        tk.Label(self, text="Категория payload-ов:").pack()
        self.category_var = tk.StringVar(self)
        self.category_var.set("Все категории")

        categories = ["Все категории"] + sorted(self.payloads.keys())
        tk.OptionMenu(self, self.category_var, *categories).pack()

        tk.Button(self, text="💉 Запустить", command=self.run_tests).pack()
        tk.Button(self, text="🧹 Очистить вывод", command=self.clear_output).pack()
        tk.Button(self, text="🗑 Очистить лог артефактов", command=self.clear_artifact_log).pack()

        self.output = tk.Text(self, height=20, bg="black", fg="white", insertbackground="white")
        self.output.pack(fill="both", expand=True)

        # Цветовые теги
        self.output.tag_config("HIGH", foreground="lime")
        self.output.tag_config("MEDIUM", foreground="yellow")
        self.output.tag_config("LOW", foreground="cyan")
        self.output.tag_config("INFO", foreground="white")
        self.output.tag_config("ERROR", foreground="red")

    # ============================================================
    #  Запуск тестов
    # ============================================================
    def run_tests(self) -> None:
        if self.active_tests >= self.max_workers:
            self._safe_log("⚠️ Достигнут лимит потоков, дождитесь завершения.\n")
            return

        param = self.param_entry.get().strip()
        base_value = self.value_entry.get()
        category = self.category_var.get()

        if not param:
            self._safe_log("⚠️ Параметр пустой — укажи имя параметра.\n")
            return

        if category == "Все категории":
            selected_payloads = self.payloads
        else:
            selected_payloads = {category: self.payloads.get(category, [])}

        tester = CSRFTester(
            base_url=self.url,
            param=param,
            base_value=base_value,
            payloads=selected_payloads,
            output_callback=self.display_result,
        )
        tester.start()
        self.active_tests += 1

        self._safe_log(f"🚀 Запущено CSRF-тестирование для {self.url} (param={param})\n")

    # ============================================================
    #  Потокобезопасный логгер в Text
    # ============================================================
    def _safe_log(self, data: Any) -> None:
        self.after(0, lambda: self._append_text(data))

    def _append_text(self, data: Any) -> None:
        if isinstance(data, tuple):
            text, tag = data
            self.output.insert("end", text, tag)
        else:
            self.output.insert("end", data)
        self.output.see("end")

    # ============================================================
    #  Вывод результата
    # ============================================================
    def display_result(self, result: Dict[str, Any]) -> None:
        self.active_tests = max(0, self.active_tests - 1)

        if not result:
            self._safe_log("⚠️ Пустой результат от CSRFTester\n")
            return

        details = result.get("details", {})
        severity = result.get("severity") or details.get("severity") or "INFO"

        category = result.get("category", "unknown")
        payload = result.get("payload", "<no payload>")

        http_status = details.get("http_status", "?")
        resp_len = details.get("response_length")
        len_part = f"(len={resp_len})" if isinstance(resp_len, (int, float)) else ""

        line = (
            f"[{category}] {payload} → {severity} "
            f"(HTTP {http_status}) {len_part}\n"
        )

        tag = severity if severity in ("HIGH", "MEDIUM", "LOW", "ERROR", "INFO") else "INFO"
        self._safe_log((line, tag))

    # ============================================================
    #  Очистка вывода
    # ============================================================
    def clear_output(self) -> None:
        self.output.delete("1.0", "end")

    # ============================================================
    #  Очистка Threat Intel артефактов
    # ============================================================
    def clear_artifact_log(self) -> None:
        try:
            with open(THREAT_INTEL_ARTIFACT_PATH, "w", encoding="utf-8") as f:
                json.dump([], f)
            self._safe_log("✅ Лог артефактов очищен\n")
        except Exception as e:
            self._safe_log(f"❌ Ошибка очистки: {e}\n")