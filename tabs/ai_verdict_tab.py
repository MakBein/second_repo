# xss_security_gui/ai_verdict_tab.py (SAFE MODE 20.0)

import tkinter as tk
from tkinter import ttk
from typing import Dict, Any, List, Optional
import queue
import threading

from xss_security_gui.settings import (
    AI_SAFE_MODE,
    AI_FALLBACK_ON_ERROR,
)

from xss_security_gui.ai_core.risk_engine import analyze_security_risk
from xss_security_gui.js_inspector import extract_js_insights


# ============================================================
#  Worker (SAFE MODE)
# ============================================================

class AIVerdictWorker(threading.Thread):
    """
    Окремий воркер-потік для AI-аналізу.
    SAFE MODE гарантує, що GUI не впаде.
    """

    def __init__(self, task_queue: "queue.Queue[Dict[str, Any]]", result_queue: "queue.Queue[Dict[str, Any]]"):
        super().__init__(daemon=True)
        self._tasks = task_queue
        self._results = result_queue
        self._running = True

    def run(self) -> None:
        while self._running:
            task = self._tasks.get()
            if task.get("type") == "__STOP__":
                break

            if task.get("type") == "ANALYZE":
                task_id = task["task_id"]
                raw_js = task["raw_js"]

                try:
                    js_insights = extract_js_insights(raw_js)
                    result = analyze_security_risk(js_insights, raw_js)
                    result["task_id"] = task_id

                except Exception as e:
                    print(f"[AI Core] AIVerdictWorker error: {e}")

                    if AI_SAFE_MODE or AI_FALLBACK_ON_ERROR:
                        result = {
                            "task_id": task_id,
                            "error": f"AI SAFE MODE: {e}",
                            "risk_score": 0.0,
                            "risk_level": "info",
                            "ml_score": 0.0,
                            "nn_score": 0.0,
                            "heuristic_score": 0.0,
                            "entropy": 0.0,
                            "complexity": 0.0,
                        }
                    else:
                        raise

                self._results.put(result)

    def stop(self) -> None:
        self._running = False
        self._tasks.put({"type": "__STOP__"})


# ============================================================
#  AI Verdict Tab (SAFE MODE)
# ============================================================

class AIVerdictTab(ttk.Frame):
    """
    Вкладка AI Verdict:
    - асинхронний AI-аналіз
    - SAFE MODE: GUI ніколи не падає
    - кольорові рівні ризику
    - сортування, фільтри, прогрес
    """

    def __init__(self, master: tk.Misc, **kwargs):
        super().__init__(master, **kwargs)

        # Черги
        self._task_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._result_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()

        # Worker
        self._worker = AIVerdictWorker(self._task_queue, self._result_queue)
        self._worker.start()

        # Стан
        self._next_task_id = 1
        self._current_filter_level: Optional[str] = None
        self._sort_desc = True

        # UI
        self._build_ui()

        # Polling
        self._poll_results()

    # ============================================================
    #  UI
    # ============================================================

    def _build_ui(self) -> None:
        top_frame = ttk.Frame(self)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.analyze_button = ttk.Button(top_frame, text="Analyze JS", command=self._on_analyze_clicked)
        self.analyze_button.pack(side=tk.LEFT)

        ttk.Label(top_frame, text="Filter:").pack(side=tk.LEFT, padx=(10, 2))

        self.filter_var = tk.StringVar(value="all")
        filter_combo = ttk.Combobox(
            top_frame,
            textvariable=self.filter_var,
            values=["all", "high", "medium", "low", "info"],
            width=8,
            state="readonly",
        )
        filter_combo.pack(side=tk.LEFT)
        filter_combo.bind("<<ComboboxSelected>>", self._on_filter_changed)

        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(top_frame, textvariable=self.status_var).pack(side=tk.RIGHT)

        # Progress
        self.progress = ttk.Progressbar(top_frame, mode="indeterminate", length=120)
        self.progress.pack(side=tk.RIGHT, padx=(0, 10))

        # Table
        columns = ("risk_score", "risk_level", "ml_score", "nn_score", "heuristic_score", "entropy", "complexity")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=12)
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        for col in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=80, anchor=tk.CENTER)

        # Details
        bottom_frame = ttk.Frame(self)
        bottom_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))

        ttk.Label(bottom_frame, text="AI Summary / Reasons:").pack(anchor="w")

        self.details_text = tk.Text(bottom_frame, height=8, wrap="word")
        self.details_text.pack(fill=tk.BOTH, expand=True)

        self.tree.bind("<<TreeviewSelect>>", self._on_row_selected)

        self._results_by_id: Dict[str, Dict[str, Any]] = {}

    # ============================================================
    #  Events
    # ============================================================

    def analyze_js_snippet(self, raw_js: str) -> None:
        self._enqueue_task(raw_js)

    def _on_analyze_clicked(self) -> None:
        from tkinter import simpledialog
        raw_js = simpledialog.askstring("Analyze JS", "Встав JS-код для аналізу:")
        if raw_js:
            self._enqueue_task(raw_js)

    def _on_filter_changed(self, _event=None) -> None:
        value = self.filter_var.get()
        self._current_filter_level = None if value == "all" else value
        self._refilter_tree()

    def _on_row_selected(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return

        item_id = sel[0]
        task_id = self.tree.item(item_id, "text")
        result = self._results_by_id.get(task_id)

        self.details_text.delete("1.0", tk.END)

        if not result:
            return

        if "error" in result:
            self.details_text.insert(tk.END, f"[AI SAFE MODE] {result['error']}\n")
            return

        self.details_text.insert(tk.END, f"Risk: {result['risk_score']:.2f} ({result['risk_level']})\n\n")
        self.details_text.insert(tk.END, "Summary:\n")
        self.details_text.insert(tk.END, result.get("llm_summary", "") + "\n\n")
        self.details_text.insert(tk.END, "Reasons:\n")
        for r in result.get("llm_reasons", []):
            self.details_text.insert(tk.END, f" - {r}\n")

    # ============================================================
    #  Task handling
    # ============================================================

    def _enqueue_task(self, raw_js: str) -> None:
        task_id = f"T{self._next_task_id}"
        self._next_task_id += 1

        self.status_var.set(f"Analyzing {task_id}...")
        self.progress.start(10)

        self._task_queue.put({
            "type": "ANALYZE",
            "task_id": task_id,
            "raw_js": raw_js,
        })

    def _poll_results(self) -> None:
        try:
            while True:
                result = self._result_queue.get_nowait()
                self._handle_result(result)
        except queue.Empty:
            pass

        self.after(100, self._poll_results)

    def _handle_result(self, result: Dict[str, Any]) -> None:
        task_id = result.get("task_id", "?")
        self._results_by_id[task_id] = result

        self.progress.stop()
        self.status_var.set(f"Done {task_id}")

        if "error" in result:
            self._insert_row(task_id, result, error=True)
            return

        self._insert_row(task_id, result)
        self._refilter_tree()

    # ============================================================
    #  Tree helpers
    # ============================================================

    def _insert_row(self, task_id: str, result: Dict[str, Any], error: bool = False) -> None:
        score = result.get("risk_score", 0.0)
        level = result.get("risk_level", "info")

        values = (
            f"{score:.2f}",
            level,
            f"{result.get('ml_score', 0.0):.2f}",
            f"{result.get('nn_score', 0.0):.2f}",
            f"{result.get('heuristic_score', 0.0):.2f}",
            f"{result.get('entropy', 0.0):.2f}",
            f"{result.get('complexity', 0.0):.2f}",
        )

        tags = ["error"] if error else [f"level_{level}"]

        item_id = self.tree.insert("", tk.END, text=task_id, values=values, tags=tags)

        self.tree.tag_configure("level_high", foreground="red")
        self.tree.tag_configure("level_medium", foreground="orange")
        self.tree.tag_configure("level_low", foreground="green")
        self.tree.tag_configure("level_info", foreground="gray")
        self.tree.tag_configure("error", foreground="red")

        return item_id

    def _refilter_tree(self) -> None:
        level_filter = self._current_filter_level

        for item in self.tree.get_children(""):
            level = self.tree.set(item, "risk_level")

            if level_filter is None or level == level_filter:
                self.tree.detach(item)
                self.tree.move(item, "", "end")
            else:
                self.tree.detach(item)

    def _sort_by(self, column: str) -> None:
        items = list(self.tree.get_children(""))
        if not items:
            return

        def parse_value(item_id: str):
            val = self.tree.set(item_id, column)
            try:
                return float(val)
            except ValueError:
                return val

        items.sort(key=parse_value, reverse=self._sort_desc)
        self._sort_desc = not self._sort_desc

        for idx, item_id in enumerate(items):
            self.tree.move(item_id, "", idx)

    # ============================================================
    #  Cleanup
    # ============================================================

    def destroy(self) -> None:
        try:
            self._worker.stop()
        except Exception:
            pass
        super().destroy()


