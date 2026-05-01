# xss_security_gui/idor_tab.py

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import threading
import json
from typing import Any, Dict, List, Optional

from xss_security_gui.idor_tester import fuzz_id_parameter


class IDORTab(ttk.Frame):
    """
    IDORTab ULTRA 7.x
    • Потокобезпечний лог
    • Уніфікований формат результатів
    • Threat Intel інтеграція (normalized severity)
    • Стабільність GUI навіть при помилках
    • Підтримка кількох паралельних тестів
    """

    def __init__(self, parent, threat_tab=None):
        super().__init__(parent)
        self.threat_tab = threat_tab

        # всі результати (накопичувально, а не перезапис)
        self.results: List[Dict[str, Any]] = []

        # контроль паралельних тестів
        self.active_tests = 0
        self.max_workers = 3

        # простий лок для потокобезпечних змін
        self._lock = threading.Lock()

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
            if default:
                entry.insert(0, default)
            entry.pack(side="left", padx=5)
            return entry

        self.url_entry = add_labeled_entry(ctrl, "🔗 URL:", 60)
        self.param_entry = add_labeled_entry(ctrl, "🔑 Параметр:", 10, "user_id")

        ttk.Label(ctrl, text="📦 Метод:").pack(side="left")
        self.method_combo = ttk.Combobox(
            ctrl, values=["GET", "POST"], width=6, state="readonly"
        )
        self.method_combo.set("GET")
        self.method_combo.pack(side="left", padx=5)

        self.token_entry = add_labeled_entry(ctrl, "🔐 Token:", 20)
        self.start_entry = add_labeled_entry(ctrl, "🔢 Start:", 5, "1")
        self.stop_entry = add_labeled_entry(ctrl, "Stop:", 5, "5")
        self.delay_entry = add_labeled_entry(ctrl, "⏱️ Delay:", 5, "0.5")
        self.agent_entry = add_labeled_entry(
            ctrl, "🧭 Agent:", 20, "Aleksandr-IDOR-Scanner"
        )

        ttk.Button(ctrl, text="🧪 Тестувати", command=self.start_test).pack(
            side="left", padx=5
        )
        ttk.Button(ctrl, text="♻️ Очистити", command=self.clear_result).pack(
            side="left", padx=5
        )
        ttk.Button(ctrl, text="📤 Експорт", command=self.export_result).pack(
            side="left", padx=5
        )

        self.result_box = tk.Text(
            self,
            bg="black",
            fg="white",
            height=25,
            wrap="none",
            insertbackground="white",
        )
        self.result_box.pack(fill="both", expand=True, padx=10, pady=5)

        # Кольорові теги
        self.result_box.tag_config("HIGH", foreground="lime")
        self.result_box.tag_config("MEDIUM", foreground="yellow")
        self.result_box.tag_config("LOW", foreground="cyan")
        self.result_box.tag_config("INFO", foreground="white")
        self.result_box.tag_config("ERROR", foreground="red")

    # ---------------------------------------------------------
    # Thread-safe log
    # ---------------------------------------------------------
    def _safe_log(self, data: Any) -> None:
        self.after(0, lambda: self._append(data))

    def _append(self, data: Any) -> None:
        if isinstance(data, tuple):
            text, tag = data
            self.result_box.insert("end", text, tag)
        else:
            self.result_box.insert("end", data)
        self.result_box.see("end")

    # ---------------------------------------------------------
    # Validation
    # ---------------------------------------------------------
    def validate_inputs(self) -> Optional[tuple]:
        url = self.url_entry.get().strip()
        param = self.param_entry.get().strip()
        method = self.method_combo.get().strip().upper()
        token = self.token_entry.get().strip()

        if not url.startswith("http") or not param:
            messagebox.showerror("Помилка", "Вкажи коректний URL і параметр")
            return None

        if method not in ("GET", "POST"):
            messagebox.showerror("Помилка", "Метод повинен бути GET або POST")
            return None

        try:
            start = int(self.start_entry.get().strip())
            stop = int(self.stop_entry.get().strip())
            delay = float(self.delay_entry.get().strip())
        except ValueError:
            messagebox.showerror("Помилка", "Start, Stop і Delay повинні бути числами")
            return None

        if start > stop:
            messagebox.showerror("Помилка", "Start не може бути більшим за Stop")
            return None

        return url, param, method, token, start, stop, delay

    # ---------------------------------------------------------
    # Start test
    # ---------------------------------------------------------
    def start_test(self):
        with self._lock:
            if self.active_tests >= self.max_workers:
                self._safe_log("⚠️ Досягнуто ліміт потоків, зачекай завершення.\n")
                return

        validated = self.validate_inputs()
        if not validated:
            return

        url, param, method, token, start, stop, delay = validated
        agent = self.agent_entry.get().strip() or "Aleksandr-IDOR-Scanner"

        self._safe_log(
            f"\n🧬 Запуск IDOR-тесту: {url} [param={param}, method={method}, range={start}-{stop}]\n"
        )

        with self._lock:
            self.active_tests += 1

        t = threading.Thread(
            target=lambda: self._run_idor(
                url, param, method, token, start, stop, delay, agent
            ),
            daemon=True,
            name=f"IDOR-{url}-{param}",
        )
        t.start()

    # ---------------------------------------------------------
    # Severity нормалізація для Threat Intel
    # ---------------------------------------------------------
    @staticmethod
    def _map_severity(differs: bool) -> str:
        # Threat Intel очікує: critical, high, medium, low, info, none
        return "high" if differs else "info"

    # ---------------------------------------------------------
    # Run IDOR logic
    # ---------------------------------------------------------
    def _run_idor(self, url, param, method, token, start, stop, delay, agent):
        try:
            headers = {"User-Agent": agent}

            try:
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
            except Exception as e:
                self._safe_log((f"❌ Помилка виконання fuzz_id_parameter: {e}\n", "ERROR"))
                return

            if not results:
                self._safe_log("ℹ️ IDOR-тест завершено, але результатів немає.\n")
                return

            # накопичуємо результати, а не перезаписуємо
            with self._lock:
                self.results.extend(results)

            # сортуємо по статусу, але без падіння, якщо статус None/?
            def _status_key(x: Dict[str, Any]) -> int:
                try:
                    return int(x.get("status", 0))
                except Exception:
                    return 0

            for r in sorted(results, key=_status_key):
                differs = bool(r.get("differs", False))
                mark = "✅ Різниця" if differs else "⚠️ Повтор"
                status = r.get("status", "?")
                length = r.get("length", "?")
                hash_ = r.get("hash", "?")
                full_url = r.get("url") or url
                value = r.get("value")

                severity_tag = "HIGH" if differs else "INFO"
                severity_norm = self._map_severity(differs)

                line = (
                    f"{mark} | {full_url} | [status={status}] "
                    f"| len={length} | hash={hash_}\n"
                )
                self._safe_log((line, severity_tag))

                if "error" in r:
                    self._safe_log((f"   ❌ Помилка: {r['error']}\n", "ERROR"))

                # Threat Intel інтеграція
                if self.threat_tab and hasattr(self.threat_tab, "add_threat"):
                    try:
                        self.threat_tab.add_threat(
                            {
                                "type": "IDOR",
                                "url": full_url,
                                "payload": value,
                                "status": status,
                                "length": length,
                                "differs": differs,
                                "hash": hash_,
                                "severity": severity_norm,
                                "source": "IDOR Scanner",
                            }
                        )
                    except Exception as e:
                        self._safe_log(
                            (f"   ❌ Помилка Threat Intel інтеграції: {e}\n", "ERROR")
                        )

        except Exception as e:
            self._safe_log((f"❌ Помилка: {e}\n", "ERROR"))

        finally:
            with self._lock:
                self.active_tests = max(0, self.active_tests - 1)

    # ---------------------------------------------------------
    # Clear
    # ---------------------------------------------------------
    def clear_result(self):
        self.result_box.delete("1.0", "end")
        with self._lock:
            self.results = []

    # ---------------------------------------------------------
    # Export
    # ---------------------------------------------------------
    def export_result(self):
        with self._lock:
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
        with self._lock:
            data = list(self.results)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write("# 🧬 IDOR Scan Results\n\n")
            for r in data:
                mark = "✅" if r.get("differs") else "⚠️"
                url = r.get("url") or "unknown"
                status = r.get("status", "?")
                length = r.get("length", "?")
                hash_ = r.get("hash", "?")
                f.write(f"{mark} `{url}`\n")
                f.write(f"- Status: `{status}`\n")
                f.write(f"- Length: `{length}`\n")
                f.write(f"- Hash: `{hash_}`\n")
                if "error" in r:
                    f.write(f"- ❌ Error: `{r['error']}`\n")
                f.write("\n")

    def _export_json(self, file_path):
        with self._lock:
            data = list(self.results)

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
