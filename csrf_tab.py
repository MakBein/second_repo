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

        # === Путь к payload-файлу ===
        if payload_file is None:
            self.payload_file = PAYLOADS_DIR / "csrf.json"
        else:
            self.payload_file = Path(payload_file)

        # === Загрузка payload-ов ===
        self.payloads: Dict[str, list] = {}
        try:
            with open(self.payload_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    self.payloads = data
                else:
                    print(f"[CSRF] Ожидался dict в {self.payload_file}, получено {type(data).__name__}")
        except Exception as e:
            print(f"[CSRF] Ошибка загрузки payload-файла: {e}")

        # === UI ===
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

        self.output = tk.Text(self, height=20)
        self.output.pack(fill="both", expand=True)

    # ============================================================
    #  Запуск тестов
    # ============================================================
    def run_tests(self) -> None:
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

    # ============================================================
    #  Потокобезопасный логгер в Text
    # ============================================================
    def _safe_log(self, text: str) -> None:
        # Викликати тільки з будь-якого потоку — оновлення піде в mainloop
        self.after(0, lambda: self._append_text(text))

    def _append_text(self, text: str) -> None:
        self.output.insert("end", text)
        self.output.see("end")

    # ============================================================
    #  Вывод результата
    # ============================================================
    def display_result(self, result: Dict[str, Any]) -> None:
        """
        Гнучкий вивід результатів:
        - не падає, якщо немає ключів
        - акуратно показує тільки те, що є
        """
        category = result.get("category", "unknown")
        payload = result.get("payload", "<no payload>")
        status = result.get("status", "unknown")

        # response_length може бути відсутнім — не крешимося
        resp_len = result.get("response_length")
        if isinstance(resp_len, (int, float)):
            len_part = f"(len={resp_len})"
        else:
            len_part = ""

        line = f"[{category}] {payload} → {status} {len_part}\n"
        self._safe_log(line)

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