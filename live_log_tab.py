import tkinter as tk
from tkinter import ttk
import threading
import time
import os

class LiveLogTab(ttk.Frame):
    def __init__(self, parent, watch_files=None):
        super().__init__(parent)
        self.watch_files = watch_files or [
            "logs/form_fuzz_hits.log",
            "logs/param_fuzz_hits.log",
            "logs/honeypot_hits.log"
        ]
        self.text = tk.Text(self, height=30, bg="black", fg="lime", insertbackground="white")
        self.text.pack(fill="both", expand=True)
        self.stop_flag = False
        threading.Thread(target=self.update_loop, daemon=True).start()

    def update_loop(self):
        last_data = {}
        while not self.stop_flag:
            combined = ""
            for path in self.watch_files:
                if os.path.exists(path):
                    with open(path, encoding="utf-8") as f:
                        data = f.read()
                    if path not in last_data or data != last_data[path]:
                        combined += f"\n===== {os.path.basename(path)} =====\n" + data
                        last_data[path] = data
            if combined:
                self.text.delete("1.0", "end")
                self.text.insert("end", combined)
            time.sleep(3)