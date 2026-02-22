# xss_security_gui/lfi_tab.py

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import json

from xss_security_gui.settings import settings
from xss_security_gui.lfi_tester import test_lfi_payloads


class LFITab(ttk.Frame):
    def __init__(self, parent, threat_tab=None):
        super().__init__(parent)
        self.threat_tab = threat_tab
        self._build_ui()

    # ---------------------------------------------------------
    # UI builder
    # ---------------------------------------------------------
    def _build_ui(self):
        ctrl = ttk.Frame(self)
        ctrl.pack(pady=5, fill="x")

        # URL
        ttk.Label(ctrl, text="📂 URL:").grid(row=0, column=0, sticky="w", padx=5)
        self.url_entry = ttk.Entry(ctrl, width=60)
        self.url_entry.grid(row=0, column=1, padx=5)

        # Параметр
        ttk.Label(ctrl, text="🔑 Параметр:").grid(row=0, column=2, sticky="e", padx=5)
        self.param_entry = ttk.Entry(ctrl, width=12)
        self.param_entry.insert(0, "file")
        self.param_entry.grid(row=0, column=3, padx=5)

        # Buttons
        btn_frame = ttk.Frame(ctrl)
        btn_frame.grid(row=1, column=0, columnspan=4, pady=5)

        ttk.Button(btn_frame, text="🧪 Тестировать LFI", command=self.start_test).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🧹 Очистить вывод", command=self.clear_output).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🗑 Очистить лог артефактов", command=self.clear_artifact_log).pack(side="left", padx=5)

        # Output box
        self.output_box = tk.Text(
            self, height=25, bg="black", fg="lime",
            wrap="none", insertbackground="white"
        )
        self.output_box.pack(fill="both", expand=True, padx=10, pady=5)

    # ---------------------------------------------------------
    # Start test
    # ---------------------------------------------------------
    def start_test(self):
        url = self.url_entry.get().strip()
        param = self.param_entry.get().strip()

        if not url.startswith("http"):
            messagebox.showerror("Ошибка", "Укажи корректный URL (http/https)")
            return

        if not param:
            messagebox.showerror("Ошибка", "Параметр не может быть пустым")
            return

        self.output_box.insert("end", f"📂 Старт LFI-анализа: {url} [param={param}]\n")
        self.output_box.see("end")

        threading.Thread(
            target=lambda: self._run_test(url, param),
            daemon=True
        ).start()

    # ---------------------------------------------------------
    # Run test logic
    # ---------------------------------------------------------
    def _run_test(self, url, param):
        try:
            results = test_lfi_payloads(
                base_url=url,
                param=param,
                payloads=settings.LFI_PAYLOADS,
                delay=settings.LFI_DELAY,
                timeout=settings.REQUEST_TIMEOUT
            )
        except Exception as e:
            self.output_box.insert("end", f"❌ Ошибка выполнения: {e}\n")
            return

        for res in results:
            mark = "✅ Уязвимо" if res["suspicious"] else "⚠️ Нет сигнатур"
            line = (
                f"{mark} | {res['payload']} → {res['url']} | "
                f"Status={res['status']} | Len={res['length']}\n"
            )
            self.output_box.insert("end", line)
            self.output_box.see("end")

            # Threat Intel integration
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

    # ---------------------------------------------------------
    # Clear output
    # ---------------------------------------------------------
    def clear_output(self):
        self.output_box.delete("1.0", "end")

    # ---------------------------------------------------------
    # Clear artifact log
    # ---------------------------------------------------------
    def clear_artifact_log(self):
        artifact_path = settings.THREAT_INTEL_ARTIFACT_PATH
        try:
            with open(artifact_path, "w", encoding="utf-8") as f:
                json.dump([], f)
            self.output_box.insert("end", f"✅ Лог артефактов очищено: {artifact_path}\n")
        except Exception as e:
            self.output_box.insert("end", f"❌ Ошибка очистки: {e}\n")
        self.output_box.see("end")