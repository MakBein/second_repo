import tkinter as tk
from tkinter import ttk, scrolledtext
import threading

from xss_security_gui.auto_recon.xss_flooder import start_flood

class XSSFlooderTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.build_ui()

    def build_ui(self):
        ttk.Label(self, text="🚀 AI-Powered XSS & SQLi Flooder", font=("Arial", 16)).pack(pady=10)
        ttk.Label(self, text="Advanced flooding with AI learning and bypass techniques.").pack(pady=5)

        # Attack types selection
        ttk.Label(self, text="Attack Types:").pack(anchor="w", padx=10)
        self.attack_types_frame = ttk.Frame(self)
        self.attack_types_frame.pack(fill="x", padx=10, pady=5)

        self.attack_vars = {}
        attack_options = ["xss", "sqli_stacked", "sqli_union", "sqli_boolean", "sqli_time"]
        for attack in attack_options:
            var = tk.BooleanVar()
            self.attack_vars[attack] = var
            ttk.Checkbutton(self.attack_types_frame, text=attack.upper(), variable=var).pack(side="left", padx=5)

        # AI toggle
        self.use_ai_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self, text="Use AI Learning & Generation", variable=self.use_ai_var).pack(anchor="w", padx=10, pady=5)

        # Workers
        ttk.Label(self, text="Max Workers:").pack(anchor="w", padx=10)
        self.workers_var = tk.IntVar(value=10)
        ttk.Spinbox(self, from_=1, to=50, textvariable=self.workers_var).pack(fill="x", padx=10, pady=5)

        # Cycles
        ttk.Label(self, text="Flood Cycles:").pack(anchor="w", padx=10)
        self.cycles_var = tk.IntVar(value=1)
        ttk.Spinbox(self, from_=1, to=10, textvariable=self.cycles_var).pack(fill="x", padx=10, pady=5)

        # Start button
        ttk.Button(self, text="🚀 Start AI Flood", command=self.start_flood_attack).pack(pady=10)

        # Log area
        ttk.Label(self, text="Attack Log:").pack(anchor="w", padx=10)
        self.log_area = scrolledtext.ScrolledText(self, height=15, wrap=tk.WORD)
        self.log_area.pack(fill="both", expand=True, padx=10, pady=5)

    def start_flood_attack(self):
        # Get selected attack types
        selected_attacks = [attack for attack, var in self.attack_vars.items() if var.get()]
        if not selected_attacks:
            self.log("No attack types selected!")
            return

        # Parameters
        attack_types = selected_attacks
        use_ai = self.use_ai_var.get()
        max_workers = self.workers_var.get()
        flood_count = self.cycles_var.get()

        self.log(f"Starting AI-powered flood with types: {attack_types}, AI: {use_ai}, workers: {max_workers}, cycles: {flood_count}")

        # Run in thread to avoid blocking GUI
        thread = threading.Thread(target=self.run_flood, args=(attack_types, use_ai, max_workers, flood_count), daemon=True)
        thread.start()

    def run_flood(self, attack_types, use_ai, max_workers, flood_count):
        try:
            start_flood(
                attack_types=attack_types,
                use_ai=use_ai,
                max_workers=max_workers,
                flood_count=flood_count,
                callback=self.log_callback
            )
            self.log("Flood completed successfully!")
        except Exception as e:
            self.log(f"Flood failed: {e}")

    def log_callback(self, url, status, snippet):
        self.log(f"[{status}] {url} - {snippet[:50]}...")

    def log(self, message):
        self.log_area.insert(tk.END, f"{message}\n")
        self.log_area.see(tk.END)</content>
<parameter name="filePath">C:\Users\sanch\PycharmProjects\itproger\xss_security_gui\tabs\xss_flooder_tab.py
