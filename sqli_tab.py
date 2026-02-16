# xss_security_gui/sqli_tab.py

import tkinter as tk
import json
from threat_analysis.sqli_module import SQLiTester


class SQLiTab(tk.Frame):
    def __init__(self, parent, url, payload_file="payloads/sqli.json"):
        super().__init__(parent)
        self.url = url
        self.payload_file = payload_file

        # Завантаження payload-ів
        try:
            with open(self.payload_file, "r", encoding="utf-8") as f:
                self.payloads = json.load(f)
        except Exception as e:
            self.payloads = {}
            tk.Label(self, text=f"❌ Помилка завантаження payload-ів: {e}", fg="red").pack()

        # Поле параметра
        tk.Label(self, text="Параметр:").pack()
        self.param_entry = tk.Entry(self)
        self.param_entry.insert(0, "id")
        self.param_entry.pack()

        # Поле значення
        tk.Label(self, text="Значення:").pack()
        self.value_entry = tk.Entry(self)
        self.value_entry.insert(0, "1")
        self.value_entry.pack()

        # Вибір категорії
        tk.Label(self, text="Категорія payload-ів:").pack()
        self.category_var = tk.StringVar(self)
        self.category_var.set("Всі категорії")
        categories = ["Всі категорії"] + list(self.payloads.keys())
        tk.OptionMenu(self, self.category_var, *categories).pack()

        # Кнопки
        tk.Button(self, text="💉 Запустити", command=self.run_tests).pack()
        tk.Button(self, text="🧹 Очистити вивід", command=lambda: self.output.delete("1.0", "end")).pack()
        tk.Button(self, text="🗑 Очистити лог артефактів", command=self.clear_artifact_log).pack()

        # Вивід
        self.output = tk.Text(self, height=20)
        self.output.pack(fill="both", expand=True)

    def run_tests(self):
        param = self.param_entry.get().strip()
        base_value = self.value_entry.get().strip()
        category = self.category_var.get()

        if not param or not base_value:
            self.output.insert("end", "⚠️ Введіть параметр і значення перед запуском\n")
            return

        # Вибір payload-ів
        if category == "Всі категорії":
            selected_payloads = self.payloads
        else:
            selected_payloads = {category: self.payloads.get(category, [])}

        # Запуск потоку
        tester = SQLiTester(
            base_url=self.url,
            param=param,
            base_value=base_value,
            payloads=selected_payloads,
            output_callback=self.display_result
        )
        tester.start()

    def display_result(self, result):
        line = f"[{result['category']}] {result['payload']} → {result['status']} (len={result['response_length']})\n"
        self.output.insert("end", line)
        self.output.see("end")

    def clear_artifact_log(self):
        try:
            with open("threat_intel_artifact.json", "w", encoding="utf-8") as f:
                json.dump([], f)
            self.output.insert("end", "✅ Лог артефактів очищено\n")
        except Exception as e:
            self.output.insert("end", f"❌ Помилка очищення: {e}\n")