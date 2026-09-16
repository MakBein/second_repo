# xss_security_gui/auto_recon/xss_flooder_tab.py
import tkinter as tk
from tkinter import ttk, scrolledtext
from xss_security_gui.auto_recon.xss_flooder import start_flood
from xss_security_gui.utils.safe_call import safe_invoke
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge


class XSSFlooderTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        # Declare attributes
        self.attack_types_frame = None
        self.attack_vars = {}
        self.use_ai_var = None
        self.workers_var = None
        self.cycles_var = None
        self.log_area = None
        self._running = False
        self._last_stats = {}

        self._bridge = UIQueueBridge(self, poll_ms=50)
        self.build_ui()

    def build_ui(self):
        ttk.Label(
            self,
            text="🚀 AI-Powered XSS & SQLi Flooder",
            font=("Arial", 16)
        ).pack(pady=10)
        ttk.Label(
            self,
            text="Controlled flood for security testing (not for production attacks)."
        ).pack(pady=5)

        # Attack types selection
        ttk.Label(self, text="Attack Types:").pack(anchor="w", padx=10)
        self.attack_types_frame = ttk.Frame(self)
        self.attack_types_frame.pack(fill="x", padx=10, pady=5)

        self.attack_vars = {}
        attack_options = ["xss", "sqli_stacked", "sqli_union", "sqli_boolean", "sqli_time"]
        for attack in attack_options:
            var = tk.BooleanVar()
            self.attack_vars[attack] = var
            ttk.Checkbutton(
                self.attack_types_frame,
                text=attack.upper(),
                variable=var
            ).pack(side="left", padx=5)

        # AI toggle
        self.use_ai_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            self,
            text="Use AI Learning & Generation",
            variable=self.use_ai_var
        ).pack(anchor="w", padx=10, pady=5)

        # Workers
        ttk.Label(self, text="Max Workers (1–50):").pack(anchor="w", padx=10)
        self.workers_var = tk.IntVar(value=10)
        ttk.Spinbox(
            self,
            from_=1,
            to=50,
            textvariable=self.workers_var
        ).pack(fill="x", padx=10, pady=5)

        # Cycles
        ttk.Label(self, text="Flood Cycles (1–10):").pack(anchor="w", padx=10)
        self.cycles_var = tk.IntVar(value=1)
        ttk.Spinbox(
            self,
            from_=1,
            to=10,
            textvariable=self.cycles_var
        ).pack(fill="x", padx=10, pady=5)

        # Control buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        ttk.Button(
            btn_frame,
            text="🚀 Start AI Flood",
            command=self.start_flood_attack
        ).pack(side="left", padx=5)
        ttk.Button(
            btn_frame,
            text="🛑 Stop",
            command=self.stop_flood
        ).pack(side="left", padx=5)

        # Log area
        ttk.Label(self, text="Attack Log:").pack(anchor="w", padx=10)
        self.log_area = scrolledtext.ScrolledText(self, height=15, wrap=tk.WORD)
        self.log_area.pack(fill="both", expand=True, padx=10, pady=5)

    def start_flood_attack(self):
        if self._running:
            self.log("Flood already running, stop it first.")
            return

        selected_attacks = [
            attack for attack, var in self.attack_vars.items() if var.get()
        ]
        if not selected_attacks:
            self.log("No attack types selected!")
            return

        attack_types = selected_attacks
        use_ai = self.use_ai_var.get()
        max_workers = max(1, min(50, self.workers_var.get()))
        flood_count = max(1, min(10, self.cycles_var.get()))

        self._running = True
        self._last_stats = {"sent": 0, "success": 0, "errors": 0}

        self.log(
            f"Starting controlled flood: types={attack_types}, "
            f"AI={use_ai}, workers={max_workers}, cycles={flood_count}"
        )

        try:
            self._bridge.post_bg(
                lambda: self.run_flood(attack_types, use_ai, max_workers, flood_count)
            )
        except Exception:
            import threading as _th
            _th.Thread(
                target=self.run_flood,
                args=(attack_types, use_ai, max_workers, flood_count),
                daemon=True
            ).start()

    def stop_flood(self):
        # Здесь предполагается, что start_flood поддерживает флаг отмены,
        # либо ты добавишь его позже.
        if not self._running:
            self.log("No active flood to stop.")
            return
        self._running = False
        self.log("Stop requested — flood will finish current cycle and exit.")

    def run_flood(self, attack_types, use_ai, max_workers, flood_count):
        try:
            start_flood(
                attack_types=attack_types,
                use_ai=use_ai,
                max_workers=max_workers,
                flood_count=flood_count,
                callback=self.log_callback,
                running_flag=lambda: self._running,
                stats_callback=self.stats_callback,
            )
            if self._running:
                self.log("Flood completed successfully.")
            else:
                self.log("Flood stopped by user.")
        except Exception as e:
            self._last_stats["errors"] += 1
            self.log(f"Flood failed: {e}")
        finally:
            self._running = False

    def log_callback(self, url, status, snippet):
        msg = f"[{status}] {url} - {snippet[:80]}..."
        self.log(msg)

    def stats_callback(self, sent: int, success: int, errors: int):
        self._last_stats["sent"] = sent
        self._last_stats["success"] = success
        self._last_stats["errors"] = errors
        self.log(
            f"[STATS] sent={sent}, success={success}, errors={errors}"
        )

    def log(self, message: str):
        safe_invoke(self.log_area.insert, "end", f"{message}\n")
        try:
            safe_invoke(self.log_area.see, "end")
        except Exception:
            pass

