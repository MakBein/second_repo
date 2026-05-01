# xss_security_gui/tabs/ai_training_tab.py
# Enterprise AI Training Tab — SAFE MODE 30.0

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import tkinter as tk
from tkinter import ttk, messagebox

from xss_security_gui.ai_core.train_nn_model import AITrainingRunner
from xss_security_gui.settings import AI_MODEL_PATH


class AITrainingTab(ttk.Frame):
    """
    Вкладка для тренування AI-моделі (ENTERPRISE SAFE MODE):

    - запуск train_from_logs() у окремому потоці (GUI ніколи не блокується)
    - індикатор прогресу (indeterminate)
    - показ ключових метрик (F1, precision, recall для класу "1")
    - кнопки для відкриття training_report.json та ai_training.log
    - захист від повторного запуску під час активного тренування
    """

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self._is_training = False
        self._root = self.winfo_toplevel()
        self._runner = AITrainingRunner(self._root, poll_ms=100)

        self._build_ui()

    # ------------------------------------------------------------
    # UI
    # ------------------------------------------------------------
    def _build_ui(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill="x", pady=10)

        self.train_button = ttk.Button(
            top,
            text="🤖 Train AI from logs",
            command=self._on_train_clicked,
        )
        self.train_button.pack(side="left", padx=5)

        self.progress = ttk.Progressbar(top, mode="indeterminate", length=180)
        self.progress.pack(side="left", padx=10)

        self.status_label = ttk.Label(self, text="Idle")
        self.status_label.pack(fill="x", pady=(0, 5))

        self.metrics_box = tk.Text(
            self,
            height=10,
            bg="#111",
            fg="#0f0",
            insertbackground="#0f0",
            wrap="word",
        )
        self.metrics_box.pack(fill="both", expand=True, padx=5, pady=5)
        self.metrics_box.insert("end", "AI training metrics will appear here.\n")
        self.metrics_box.config(state="disabled")

        bottom = ttk.Frame(self)
        bottom.pack(fill="x", pady=10)

        ttk.Button(
            bottom,
            text="📄 Open training_report.json",
            command=self._open_training_report,
        ).pack(side="left", padx=5)

        ttk.Button(
            bottom,
            text="📜 Open ai_training.log",
            command=self._open_training_log,
        ).pack(side="left", padx=5)

        ttk.Button(
            bottom,
            text="📂 Open model folder",
            command=self._open_model_folder,
        ).pack(side="left", padx=5)

    # ------------------------------------------------------------
    # Training
    # ------------------------------------------------------------
    def _on_train_clicked(self) -> None:
        if self._is_training:
            return

        self._is_training = True
        self.train_button.config(state="disabled")
        self.status_label.config(text="Training in progress…")
        self._set_metrics_text("🚀 Starting training from logs…\n")
        self.progress.start(10)

        self._runner.train_async(
            on_done=lambda _task_id, report: self._update_metrics(report),
            on_error=lambda _task_id, err: self._on_training_error(err),
        )

    def _on_training_error(self, e: Exception) -> None:
        self.progress.stop()
        self._is_training = False
        self.train_button.config(state="normal")
        self.status_label.config(text="Error")

        self._append_metrics_text(f"❌ Training error: {e}\n")
        messagebox.showerror("AI Training", f"Training failed:\n{e}")

    def _update_metrics(self, report: Dict[str, Any]) -> None:
        self.progress.stop()
        self._is_training = False
        self.train_button.config(state="normal")

        msg = report.get("message", "Training completed.")
        cls = report.get("metrics", {}).get("classification_report")

        self.status_label.config(text=msg)

        lines = [f"✅ {msg}\n"]

        if cls and "1" in cls:
            c1 = cls["1"]
            prec = c1.get("precision")
            rec = c1.get("recall")
            f1 = c1.get("f1-score")

            lines.append("Class 1 (malicious):")
            if prec is not None:
                lines.append(f"  • precision: {prec:.4f}")
            if rec is not None:
                lines.append(f"  • recall:    {rec:.4f}")
            if f1 is not None:
                lines.append(f"  • F1-score:  {f1:.4f}")
            lines.append("")

        files_stats = report.get("files_stats") or {}
        if files_stats:
            lines.append("Files stats:")
            lines.append(f"  • total:      {files_stats.get('files_total', 0)}")
            lines.append(f"  • processed:  {files_stats.get('files_processed', 0)}")
            lines.append(f"  • skipped:    {files_stats.get('files_skipped_size', 0)}")
            lines.append(f"  • read errors:{files_stats.get('files_failed_read', 0)}")
            lines.append("")

        model_path = report.get("model_path") or str(AI_MODEL_PATH)
        lines.append(f"Model path: {model_path}")
        log_path = report.get("training_log_path") or str(Path(AI_MODEL_PATH).parent / "ai_training.log")
        lines.append(f"Training log: {log_path}")
        lines.append("\n=== Done ===\n")

        self._set_metrics_text("\n".join(lines))

    # ------------------------------------------------------------
    # File open helpers
    # ------------------------------------------------------------
    def _open_training_report(self) -> None:
        path = Path(AI_MODEL_PATH).parent / "training_report.json"
        if not path.exists():
            self._append_metrics_text("⚠ training_report.json not found\n")
            self.status_label.config(text="training_report.json not found")
            return

        try:
            import webbrowser
            webbrowser.open(str(path))
        except Exception:
            self._append_metrics_text(f"⚠ Cannot open: {path}\n")
            self.status_label.config(text=f"Cannot open training_report.json")

    def _open_training_log(self) -> None:
        path = Path(AI_MODEL_PATH).parent / "ai_training.log"
        if not path.exists():
            self._append_metrics_text("⚠ ai_training.log not found\n")
            self.status_label.config(text="ai_training.log not found")
            return

        try:
            import webbrowser
            webbrowser.open(str(path))
        except Exception:
            self._append_metrics_text(f"⚠ Cannot open: {path}\n")
            self.status_label.config(text="Cannot open ai_training.log")

    def _open_model_folder(self) -> None:
        folder = Path(AI_MODEL_PATH).parent
        try:
            import os
            import subprocess
            if os.name == "nt":
                os.startfile(str(folder))
            elif os.name == "posix":
                subprocess.Popen(["xdg-open", str(folder)])
            else:
                subprocess.Popen(["open", str(folder)])
        except Exception:
            self._append_metrics_text(f"⚠ Cannot open folder: {folder}\n")
            self.status_label.config(text="Cannot open model folder")

    # ------------------------------------------------------------
    # Text helpers
    # ------------------------------------------------------------
    def _set_metrics_text(self, text: str) -> None:
        self.metrics_box.config(state="normal")
        self.metrics_box.delete("1.0", "end")
        self.metrics_box.insert("end", text)
        self.metrics_box.see("end")
        self.metrics_box.config(state="disabled")

    def _append_metrics_text(self, text: str) -> None:
        self.metrics_box.config(state="normal")
        self.metrics_box.insert("end", text)
        self.metrics_box.see("end")
        self.metrics_box.config(state="disabled")

    def destroy(self) -> None:
        try:
            self._runner.stop()
        except Exception:
            pass
        super().destroy()

