# xss_security_gui/xss_tab.py
import os
import tkinter as tk
import json
from threat_analysis.xss_module import XSSTester


class XSSTab(tk.Frame):
    def __init__(self, parent, url, payload_file=None):
        super().__init__(parent)
        self.url = url
        if payload_file is None:
            # ищем рядом с самим файлом xss_tab.py
            self.payload_file = os.path.join(os.path.dirname(__file__), "xss.json")
        else:
            self.payload_file = payload_file

        with open(self.payload_file, "r", encoding="utf-8") as f:
            self.payloads = json.load(f)

        tk.Label(self, text="Параметр:").pack()
        self.param_entry = tk.Entry(self)
        self.param_entry.insert(0, "q")
        self.param_entry.pack()

        tk.Label(self, text="Значення:").pack()
        self.value_entry = tk.Entry(self)
        self.value_entry.insert(0, "")
        self.value_entry.pack()

        tk.Label(self, text="Категорія payload-ів:").pack()
        self.category_var = tk.StringVar(self)
        self.category_var.set("Всі категорії")
        categories = ["Всі категорії"] + list(self.payloads.keys())
        tk.OptionMenu(self, self.category_var, *categories).pack()

        tk.Button(self, text="💉 Запустити", command=self.run_tests).pack()
        tk.Button(self, text="🧹 Очистити вивід", command=lambda: self.output.delete("1.0", "end")).pack()
        tk.Button(self, text="🗑 Очистити лог артефактів", command=self.clear_artifact_log).pack()

        self.output = tk.Text(self, height=20)
        self.output.pack(fill="both", expand=True)

    def run_tests(self):
        param = self.param_entry.get()
        base_value = self.value_entry.get()
        category = self.category_var.get()

        if category == "Всі категорії":
            selected_payloads = self.payloads
        else:
            selected_payloads = {category: self.payloads[category]}

        tester = XSSTester(
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