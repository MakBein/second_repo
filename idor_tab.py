# xss_security_gui/idor_tab.py

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from xss_security_gui.idor_tester import fuzz_id_parameter
import threading
import json


class IDORTab(ttk.Frame):
    def __init__(self, parent, threat_tab=None):
        super().__init__(parent)
        self.threat_tab = threat_tab
        self.results = []
        self.build_ui()

    # -----------------------------
    # UI
    # -----------------------------
    def build_ui(self):
        ctrl = ttk.Frame(self)
        ctrl.pack(pady=5)

        def add_labeled_entry(parent, label, width, default=""):
            ttk.Label(parent, text=label).pack(side="left", padx=5)
            entry = ttk.Entry(parent, width=width)
            entry.insert(0, default)
            entry.pack(side="left", padx=5)
            return entry

        self.url_entry = add_labeled_entry(ctrl, "🔗 URL:", 60)
        self.param_entry = add_labeled_entry(ctrl, "🔑 Параметр:", 10, "user_id")

        ttk.Label(ctrl, text="📦 Метод:").pack(side="left")
        self.method_combo = ttk.Combobox(ctrl, values=["GET", "POST"], width=6)
        self.method_combo.set("GET")
        self.method_combo.pack(side="left", padx=5)

        self.token_entry = add_labeled_entry(ctrl, "🔐 Token:", 20)
        self.start_entry = add_labeled_entry(ctrl, "🔢 Start:", 5, "1")
        self.stop_entry = add_labeled_entry(ctrl, "Stop:", 5, "5")
        self.delay_entry = add_labeled_entry(ctrl, "⏱️ Delay:", 5, "0.5")
        self.agent_entry = add_labeled_entry(ctrl, "🧭 Agent:", 20, "Aleksandr-IDOR-Scanner")

        ttk.Button(ctrl, text="🧪 Тестировать", command=self.start_test).pack(side="left", padx=5)
        ttk.Button(ctrl, text="♻️ Очистить", command=self.clear_result).pack(side="left", padx=5)
        ttk.Button(ctrl, text="📤 Экспорт", command=self.export_result).pack(side="left", padx=5)

        self.result_box = tk.Text(
            self, bg="black", fg="lime", height=25,
            wrap="none", insertbackground="white"
        )
        self.result_box.pack(fill="both", expand=True, padx=10, pady=5)

    # -----------------------------
    # Validation
    # -----------------------------
    def validate_inputs(self):
        url = self.url_entry.get().strip()
        param = self.param_entry.get().strip()
        method = self.method_combo.get().strip()
        token = self.token_entry.get().strip()

        if not url.startswith("http") or not param:
            messagebox.showerror("Ошибка", "Укажи корректный URL и имя параметра")
            return None

        try:
            start = int(self.start_entry.get().strip())
            stop = int(self.stop_entry.get().strip())
            delay = float(self.delay_entry.get().strip())
        except ValueError:
            messagebox.showerror("Ошибка", "Start, Stop и Delay должны быть числами")
            return None

        return url, param, method, token, start, stop, delay

    # -----------------------------
    # Start test
    # -----------------------------
    def start_test(self):
        validated = self.validate_inputs()
        if not validated:
            return

        url, param, method, token, start, stop, delay = validated
        agent = self.agent_entry.get().strip()

        self.result_box.insert(
            "end",
            f"\n🧬 Запуск IDOR-теста: {url} [param={param}, method={method}]\n"
        )

        threading.Thread(
            target=lambda: self.run_idor(url, param, method, token, start, stop, delay, agent),
            daemon=True
        ).start()

    # -----------------------------
    # Run IDOR logic
    # -----------------------------
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
                auth_token=token or None
            )

            self.results = results

            for r in sorted(results, key=lambda x: x["status"]):
                diff = "✅ Различие" if r["differs"] else "⚠️ Похоже на повтор"
                line = f"{diff} | {r['url']} | [{r['status']}] | len={r['length']} | hash={r['hash']}\n"

                if "error" in r:
                    line += f"   ❌ Ошибка: {r['error']}\n"

                self.result_box.insert("end", line)

        except Exception as e:
            self.result_box.insert("end", f"❌ Ошибка: {e}\n")

    # -----------------------------
    # Clear
    # -----------------------------
    def clear_result(self):
        self.result_box.delete("1.0", "end")
        self.results = []

    # -----------------------------
    # Export
    # -----------------------------
    def export_result(self):
        if not self.results:
            messagebox.showinfo("Экспорт", "Нет данных для экспорта")
            return

        export_type = simpledialog.askstring(
            "Формат экспорта",
            "Выбери формат: markdown или json"
        )

        if not export_type:
            return

        export_type = export_type.lower().strip()
        if export_type not in ("markdown", "json"):
            messagebox.showerror("Ошибка", "Поддерживаются только markdown и json")
            return

        ext = ".md" if export_type == "markdown" else ".json"
        file_path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[("Все файлы", "*.*")]
        )

        if not file_path:
            return

        try:
            if export_type == "markdown":
                self.export_markdown(file_path)
            else:
                self.export_json(file_path)

            messagebox.showinfo("Экспорт", f"Результаты сохранены в:\n{file_path}")

        except Exception as e:
            messagebox.showerror("Ошибка экспорта", str(e))

    # -----------------------------
    # Export helpers
    # -----------------------------
    def export_markdown(self, file_path):
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

    def export_json(self, file_path):
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)


