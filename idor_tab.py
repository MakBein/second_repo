# xss_security_gui/idor_tab.py

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import threading
import json
from typing import Any, Dict, List

from xss_security_gui.idor_tester import fuzz_id_parameter


class IDORTab(ttk.Frame):
    """
    IDORTab ULTRA 6.x
    • Потокобезпечний лог
    • Уніфікований формат результатів
    • Чистий, структурований код
    • Threat Intel інтеграція у стандартному форматі
    """

    def __init__(self, parent, threat_tab=None):
        super().__init__(parent)
        self.threat_tab = threat_tab
        self.results: List[Dict[str, Any]] = []
        self._build_ui()

    # ---------------------------------------------------------
    # UI
    # ---------------------------------------------------------
    def _build_ui(self):
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
        self.method_combo = ttk.Combobox(ctrl, values=["GET", "POST"], width=6, state="readonly")
        self.method_combo.set("GET")
        self.method_combo.pack(side="left", padx=5)

        self.token_entry = add_labeled_entry(ctrl, "🔐 Token:", 20)
        self.start_entry = add_labeled_entry(ctrl, "🔢 Start:", 5, "1")
        self.stop_entry = add_labeled_entry(ctrl, "Stop:", 5, "5")
        self.delay_entry = add_labeled_entry(ctrl, "⏱️ Delay:", 5, "0.5")
        self.agent_entry = add_labeled_entry(ctrl, "🧭 Agent:", 20, "Aleksandr-IDOR-Scanner")

        ttk.Button(ctrl, text="🧪 Тестувати", command=self.start_test).pack(side="left", padx=5)
        ttk.Button(ctrl, text="♻️ Очистити", command=self.clear_result).pack(side="left", padx=5)
        ttk.Button(ctrl, text="📤 Експорт", command=self.export_result).pack(side="left", padx=5)

        self.result_box = tk.Text(
            self,
            bg="black",
            fg="lime",
            height=25,
            wrap="none",
            insertbackground="white",
        )
        self.result_box.pack(fill="both", expand=True, padx=10, pady=5)

    # ---------------------------------------------------------
    # Thread-safe log
    # ---------------------------------------------------------
    def _safe_log(self, text: str) -> None:
        self.after(0, lambda: self._append(text))

    def _append(self, text: str) -> None:
        self.result_box.insert("end", text)
        self.result_box.see("end")

    # ---------------------------------------------------------
    # Validation
    # ---------------------------------------------------------
    def validate_inputs(self):
        url = self.url_entry.get().strip()
        param = self.param_entry.get().strip()
        method = self.method_combo.get().strip()
        token = self.token_entry.get().strip()

        if not url.startswith("http") or not param:
            messagebox.showerror("Помилка", "Вкажи коректний URL і параметр")
            return None

        try:
            start = int(self.start_entry.get().strip())
            stop = int(self.stop_entry.get().strip())
            delay = float(self.delay_entry.get().strip())
        except ValueError:
            messagebox.showerror("Помилка", "Start, Stop і Delay повинні бути числами")
            return None

        return url, param, method, token, start, stop, delay

    # ---------------------------------------------------------
    # Start test
    # ---------------------------------------------------------
    def start_test(self):
        validated = self.validate_inputs()
        if not validated:
            return

        url, param, method, token, start, stop, delay = validated
        agent = self.agent_entry.get().strip()

        self._safe_log(f"\n🧬 Запуск IDOR-тесту: {url} [param={param}, method={method}]\n")

        threading.Thread(
            target=lambda: self._run_idor(url, param, method, token, start, stop, delay, agent),
            daemon=True,
        ).start()

    # ---------------------------------------------------------
    # Run IDOR logic
    # ---------------------------------------------------------
    def _run_idor(self, url, param, method, token, start, stop, delay, agent):
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
                auth_token=token or None,
            )

            self.results = results

            for r in sorted(results, key=lambda x: x.get("status", 0)):
                differs = r.get("differs", False)
                mark = "✅ Різниця" if differs else "⚠️ Повтор"
                status = r.get("status", "?")
                length = r.get("length", "?")
                hash_ = r.get("hash", "?")
                full_url = r.get("url", "?")

                line = f"{mark} | {full_url} | [{status}] | len={length} | hash={hash_}\n"

                if "error" in r:
                    line += f"   ❌ Помилка: {r['error']}\n"

                self._safe_log(line)

                # Threat Intel
                if self.threat_tab:
                    self.threat_tab.add_threat({
                        "type": "IDOR",
                        "url": full_url,
                        "payload": r.get("value", None),
                        "status": status,
                        "length": length,
                        "differs": differs,
                        "hash": hash_,
                        "source": "IDOR Scanner",
                    })

        except Exception as e:
            self._safe_log(f"❌ Помилка: {e}\n")

    # ---------------------------------------------------------
    # Clear
    # ---------------------------------------------------------
    def clear_result(self):
        self.result_box.delete("1.0", "end")
        self.results = []

    # ---------------------------------------------------------
    # Export
    # ---------------------------------------------------------
    def export_result(self):
        if not self.results:
            messagebox.showinfo("Експорт", "Немає даних для експорту")
            return

        export_type = simpledialog.askstring(
            "Формат експорту",
            "Вибери формат: markdown або json",
        )

        if not export_type:
            return

        export_type = export_type.lower().strip()
        if export_type not in ("markdown", "json"):
            messagebox.showerror("Помилка", "Підтримуються тільки markdown і json")
            return

        ext = ".md" if export_type == "markdown" else ".json"
        file_path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[("Усі файли", "*.*")],
        )

        if not file_path:
            return

        try:
            if export_type == "markdown":
                self._export_markdown(file_path)
            else:
                self._export_json(file_path)

            messagebox.showinfo("Експорт", f"Результати збережено:\n{file_path}")

        except Exception as e:
            messagebox.showerror("Помилка експорту", str(e))

    # ---------------------------------------------------------
    # Export helpers
    # ---------------------------------------------------------
    def _export_markdown(self, file_path):
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("# 🧬 IDOR Scan Results\n\n")
            for r in self.results:
                mark = "✅" if r.get("differs") else "⚠️"
                f.write(f"{mark} `{r.get('url')}`\n")
                f.write(f"- Status: `{r.get('status')}`\n")
                f.write(f"- Length: `{r.get('length')}`\n")
                f.write(f"- Hash: `{r.get('hash')}`\n")
                if "error" in r:
                    f.write(f"- ❌ Error: `{r['error']}`\n")
                f.write("\n")

    def _export_json(self, file_path):
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)


