# xss_security_gui/csrf_tab.py
import tkinter as tk
import json
from pathlib import Path

from xss_security_gui.settings import PAYLOADS_DIR, THREAT_INTEL_ARTIFACT_PATH
from xss_security_gui.threat_analysis.csrf_module import CSRFTester


class CSRFTab(tk.Frame):
    def __init__(self, parent, url: str, payload_file: str = None):
        super().__init__(parent)

        self.url = url

        # === Путь к payload-файлу ===
        if payload_file is None:
            self.payload_file = PAYLOADS_DIR / "csrf.json"
        else:
            self.payload_file = Path(payload_file)

        # === Загрузка payload-ов ===
        try:
            with open(self.payload_file, "r", encoding="utf-8") as f:
                self.payloads = json.load(f)
        except Exception as e:
            self.payloads = {}
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

        categories = ["Все категории"] + list(self.payloads.keys())
        tk.OptionMenu(self, self.category_var, *categories).pack()

        tk.Button(self, text="💉 Запустить", command=self.run_tests).pack()
        tk.Button(self, text="🧹 Очистить вывод", command=self.clear_output).pack()
        tk.Button(self, text="🗑 Очистить лог артефактов", command=self.clear_artifact_log).pack()

        self.output = tk.Text(self, height=20)
        self.output.pack(fill="both", expand=True)

    # ============================================================
    #  Запуск тестов
    # ============================================================
    def run_tests(self):
        param = self.param_entry.get()
        base_value = self.value_entry.get()
        category = self.category_var.get()

        if category == "Все категории":
            selected_payloads = self.payloads
        else:
            selected_payloads = {category: self.payloads.get(category, [])}

        tester = CSRFTester(
            base_url=self.url,
            param=param,
            base_value=base_value,
            payloads=selected_payloads,
            output_callback=self.display_result
        )
        tester.start()

    # ============================================================
    #  Вывод результата
    # ============================================================
    def display_result(self, result):
        line = (
            f"[{result['category']}] "
            f"{result['payload']} → {result['status']} "
            f"(len={result['response_length']})\n"
        )
        self.output.insert("end", line)
        self.output.see("end")

    # ============================================================
    #  Очистка вывода
    # ============================================================
    def clear_output(self):
        self.output.delete("1.0", "end")

    # ============================================================
    #  Очистка Threat Intel артефактов
    # ============================================================
    def clear_artifact_log(self):
        try:
            with open(THREAT_INTEL_ARTIFACT_PATH, "w", encoding="utf-8") as f:
                json.dump([], f)
            self.output.insert("end", "✅ Лог артефактов очищен\n")
        except Exception as e:
            self.output.insert("end", f"❌ Ошибка очистки: {e}\n")