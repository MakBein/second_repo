# xss_security_gui/lfi_tab.py

import tkinter as tk
from tkinter import ttk, messagebox
from lfi_tester import test_lfi_payloads
import threading

class LFITab(ttk.Frame):
    def __init__(self, parent, threat_tab=None):
        super().__init__(parent)
        self.threat_tab = threat_tab
        self.build_ui()

    def build_ui(self):
        ctrl = ttk.Frame(self)
        ctrl.pack(pady=5)

        ttk.Label(ctrl, text="📂 URL:").pack(side="left", padx=5)
        self.url_entry = ttk.Entry(ctrl, width=60)
        self.url_entry.pack(side="left", padx=5)

        ttk.Label(ctrl, text="🔑 Параметр:").pack(side="left")
        self.param_entry = ttk.Entry(ctrl, width=12)
        self.param_entry.insert(0, "file")
        self.param_entry.pack(side="left", padx=5)

        ttk.Button(ctrl, text="🧪 Тестировать LFI", command=self.start_test).pack(side="left", padx=5)
        ttk.Button(ctrl, text="♻️ Очистить", command=self.clear_output).pack(side="left", padx=5)

        self.output_box = tk.Text(self, height=25, bg="black", fg="lime", wrap="none", insertbackground="white")
        self.output_box.pack(fill="both", expand=True, padx=10, pady=5)

    def start_test(self):
        url = self.url_entry.get().strip()
        param = self.param_entry.get().strip()
        if not url.startswith("http") or not param:
            messagebox.showerror("Ошибка", "Укажи корректный URL и имя параметра")
            return

        self.output_box.insert("end", f"📂 Старт LFI-анализа: {url} [param={param}]\n")
        threading.Thread(target=lambda: self.run_test(url, param), daemon=True).start()

    def run_test(self, url, param):
        results = test_lfi_payloads(url, param)
        for res in results:
            mark = "✅ Уязвимо" if res["suspicious"] else "⚠️ Нет сигнатур"
            self.output_box.insert(
                "end",
                f"{mark} | {res['payload']} → {res['url']} | Status={res['status']} | Len={res['length']}\n"
            )

            # === Интеграция с Threat Intel (если вкладка передана) ===
            if self.threat_tab:
                self.threat_tab.add_threat({
                    "type": "LFI",
                    "url": res["url"],
                    "payload": res["payload"],
                    "status": res["status"],
                    "length": res["length"],
                    "suspicious": res["suspicious"],
                    "source": "LFI Scanner"
                })

    def clear_output(self):
        self.output_box.delete("1.0", "end")