# xss_security_gui/lfi_tab.py

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import json


from xss_security_gui.settings import settings
from xss_security_gui.lfi_tester import test_lfi_payloads


class LFITab(ttk.Frame):
    """
    LFITab ULTRA 6.x
    • Потокобезпечний лог
    • Уніфікований формат виводу (як XSS/SSRF/SQLi)
    • Безпечний доступ до settings
    • Threat Intel інтеграція у стандартному форматі
    """

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

        ttk.Button(btn_frame, text="🧪 Тестувати LFI", command=self.start_test).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🧹 Очистити вивід", command=self.clear_output).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🗑 Очистити лог артефактів", command=self.clear_artifact_log).pack(side="left", padx=5)

        # Output box
        self.output_box = tk.Text(
            self,
            height=25,
            bg="black",
            fg="lime",
            wrap="none",
            insertbackground="white",
        )
        self.output_box.pack(fill="both", expand=True, padx=10, pady=5)

    # ---------------------------------------------------------
    # Thread-safe log
    # ---------------------------------------------------------
    def _safe_log(self, text: str) -> None:
        self.after(0, lambda: self._append(text))

    def _append(self, text: str) -> None:
        self.output_box.insert("end", text)
        self.output_box.see("end")

    # ---------------------------------------------------------
    # Start test
    # ---------------------------------------------------------
    def start_test(self):
        url = self.url_entry.get().strip()
        param = self.param_entry.get().strip()

        if not url.startswith("http"):
            messagebox.showerror("Помилка", "Вкажіть коректний URL (http/https)")
            return

        if not param:
            messagebox.showerror("Помилка", "Параметр не може бути порожнім")
            return

        self._safe_log(f"📂 Старт LFI-аналізу: {url} [param={param}]\n")

        threading.Thread(
            target=lambda: self._run_test(url, param),
            daemon=True
        ).start()

    # ---------------------------------------------------------
    # Run test logic
    # ---------------------------------------------------------
    def _run_test(self, url: str, param: str):
        try:
            results = test_lfi_payloads(
                base_url=url,
                param=param,
                payloads=getattr(settings, "LFI_PAYLOADS", []),
                delay=getattr(settings, "LFI_DELAY", 0.5),
                timeout=getattr(settings, "REQUEST_TIMEOUT", 10),
            )
        except Exception as e:
            self._safe_log(f"❌ Помилка виконання: {e}\n")
            return

        for res in results:
            suspicious = res.get("suspicious", False)
            payload = res.get("payload", "?")
            full_url = res.get("url", "?")
            status = res.get("status", "?")
            length = res.get("length", "?")

            mark = "✅ Уразливо" if suspicious else "⚠️ Немає сигнатур"
            line = f"{mark} | {payload} → {full_url} | Status={status} | Len={length}\n"
            self._safe_log(line)

            # Threat Intel integration
            if self.threat_tab:
                self.threat_tab.add_threat({
                    "type": "LFI",
                    "url": full_url,
                    "payload": payload,
                    "status": status,
                    "length": length,
                    "suspicious": suspicious,
                    "source": "LFI Scanner",
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
        artifact_path = getattr(settings, "THREAT_INTEL_ARTIFACT_PATH", "threat_artifacts.json")

        try:
            with open(artifact_path, "w", encoding="utf-8") as f:
                json.dump([], f)
            self._safe_log(f"✅ Лог артефактів очищено: {artifact_path}\n")
        except Exception as e:
            self._safe_log(f"❌ Помилка очищення: {e}\n")