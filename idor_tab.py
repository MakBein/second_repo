# xss_security_gui/idor_tab.py

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from idor_tester import fuzz_id_parameter
import threading
import json

class IDORTab(ttk.Frame):
    def __init__(self, parent, threat_tab=None):
        super().__init__(parent)
        self.threat_tab = threat_tab
        self.results = []
        self.build_ui()

    def build_ui(self):
        ctrl = ttk.Frame(self)
        ctrl.pack(pady=5)

        ttk.Label(ctrl, text="🔗 URL:").pack(side="left", padx=5)
        self.url_entry = ttk.Entry(ctrl, width=60)
        self.url_entry.pack(side="left", padx=5)

        ttk.Label(ctrl, text="🔑 Параметр:").pack(side="left")
        self.param_entry = ttk.Entry(ctrl, width=10)
        self.param_entry.insert(0, "user_id")
        self.param_entry.pack(side="left", padx=5)

        ttk.Label(ctrl, text="📦 Метод:").pack(side="left")
        self.method_combo = ttk.Combobox(ctrl, values=["GET", "POST"], width=6)
        self.method_combo.set("GET")
        self.method_combo.pack(side="left", padx=5)

        ttk.Label(ctrl, text="🔐 Token:").pack(side="left")
        self.token_entry = ttk.Entry(ctrl, width=20)
        self.token_entry.pack(side="left", padx=5)

        ttk.Label(ctrl, text="🔢 Start:").pack(side="left")
        self.start_entry = ttk.Entry(ctrl, width=5)
        self.start_entry.insert(0, "1")
        self.start_entry.pack(side="left", padx=2)

        ttk.Label(ctrl, text="Stop:").pack(side="left")
        self.stop_entry = ttk.Entry(ctrl, width=5)
        self.stop_entry.insert(0, "5")
        self.stop_entry.pack(side="left", padx=2)

        ttk.Label(ctrl, text="⏱️ Delay:").pack(side="left")
        self.delay_entry = ttk.Entry(ctrl, width=5)
        self.delay_entry.insert(0, "0.5")
        self.delay_entry.pack(side="left", padx=2)

        ttk.Label(ctrl, text="🧭 Agent:").pack(side="left")
        self.agent_entry = ttk.Entry(ctrl, width=20)
        self.agent_entry.insert(0, "Aleksandr-IDOR-Scanner")
        self.agent_entry.pack(side="left", padx=2)

        ttk.Button(ctrl, text="🧪 Тестировать", command=self.start_test).pack(side="left", padx=5)
        ttk.Button(ctrl, text="♻️ Очистить", command=self.clear_result).pack(side="left", padx=5)
        ttk.Button(ctrl, text="📤 Экспорт", command=self.export_result).pack(side="left", padx=5)

        self.result_box = tk.Text(self, bg="black", fg="lime", height=25, wrap="none", insertbackground="white")
        self.result_box.pack(fill="both", expand=True, padx=10, pady=5)

    def start_test(self):
        url = self.url_entry.get().strip()
        param = self.param_entry.get().strip()
        method = self.method_combo.get().strip()
        token = self.token_entry.get().strip()
        start = self.start_entry.get().strip()
        stop = self.stop_entry.get().strip()
        delay = self.delay_entry.get().strip()
        agent = self.agent_entry.get().strip()

        if not url.startswith("http") or not param:
            messagebox.showerror("Ошибка", "Укажи корректный URL и имя параметра")
            return

        try:
            start = int(start)
            stop = int(stop)
            delay = float(delay)
        except ValueError:
            messagebox.showerror("Ошибка", "Start, Stop и Delay должны быть числами")
            return

        self.result_box.insert("end", f"\n🧬 Запуск IDOR-теста: {url} [param={param}, method={method}]\n")
        threading.Thread(target=lambda: self.run_idor(url, param, method, token, start, stop, delay, agent), daemon=True).start()

    def run_idor(self, url, param, method, token, start, stop, delay, agent):
        try:
            headers = {"User-Agent": agent}
            results = fuzz_id_parameter(
                url,
                param=param,
                start=start,
                stop=stop,
                method=method,
                headers=headers,
                delay=delay,
                auth_token=token if token else None
            )
            self.results = results
            for r in sorted(results, key=lambda x: x["status"]):
                status = r["status"]
                diff = "✅ Различие" if r["differs"] else "⚠️ Похоже на повтор"
                line = f"{diff} | {r['url']} | [{status}] | len={r['length']} | hash={r['hash']}\n"
                if "error" in r:
                    line += f"   ❌ Ошибка: {r['error']}\n"
                self.result_box.insert("end", line)
        except Exception as e:
            self.result_box.insert("end", f"❌ Ошибка: {e}\n")

    def clear_result(self):
        self.result_box.delete("1.0", "end")
        self.results = []

    def export_result(self):
        if not self.results:
            messagebox.showinfo("Экспорт", "Нет данных для экспорта")
            return

        export_type = tk.simpledialog.askstring("Формат экспорта", "Выбери формат: markdown или json")
        if not export_type:
            return

        export_type = export_type.lower().strip()
        if export_type not in ["markdown", "json"]:
            messagebox.showerror("Ошибка", "Поддерживаются только markdown и json")
            return

        ext = ".md" if export_type == "markdown" else ".json"
        file_path = filedialog.asksaveasfilename(defaultextension=ext, filetypes=[("Все файлы", "*.*")])
        if not file_path:
            return

        try:
            if export_type == "markdown":
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("# 🧬 IDOR Scan Results\n\n")
                    for r in self.results:
                        mark = "✅" if r["differs"] else "⚠️"
                        f.write(f"{mark} `{r['url']}`\n")
                        f.write(f"- Status: `{r['status']}`\n")
                        f.write(f"- Length: `{r['length']}`\n")
                        f.write(f"- Hash: `{r['hash']}`\n")
                        if "error" in r:
                            f.write(f"- ❌ Error: `{r['error']}`\n")
                        f.write("\n")
            else:  # JSON
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(self.results, f, indent=2, ensure_ascii=False)

            messagebox.showinfo("Экспорт", f"Результаты сохранены в:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Ошибка экспорта", str(e))


