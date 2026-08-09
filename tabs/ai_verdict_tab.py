# xss_security_gui/ai_verdict_tab.py
import tkinter as tk
from tkinter import ttk
from typing import Dict, Any, List, Optional
import queue
import threading

from xss_security_gui.ai_core.risk_engine import analyze_security_risk
from xss_security_gui.js_inspector import extract_js_insights


class AIVerdictWorker(threading.Thread):
    """
    Окремий воркер-потік для AI-аналізу, щоб не блокувати GUI.
    Приймає задачі через чергу, повертає результати через іншу чергу.
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
                    result = {"task_id": task_id, "error": str(e)}

                self._results.put(result)

    def stop(self) -> None:
        self._running = False
        self._tasks.put({"type": "__STOP__"})


class AIVerdictTab(ttk.Frame):
    """
    Вкладка AI Verdict:
    - приймає JS-код
    - ганяє через AI Core (risk_engine)
    - показує результати в таблиці
    - має сортування, фільтри, кольорові рівні ризику
    """

    def __init__(self, master: tk.Misc, **kwargs):
        super().__init__(master, **kwargs)

        # === Черги для воркера ===
        self._task_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._result_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()

        # === Воркер ===
        self._worker = AIVerdictWorker(self._task_queue, self._result_queue)
        self._worker.start()

        # === Стан ===
        self._next_task_id = 1
        self._current_filter_level: Optional[str] = None
        self._sort_desc = True

        # === UI ===
        self._build_ui()

        # === Пулінг результатів ===
        self._poll_results()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        # Верхня панель: кнопки, фільтри, статус
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
        status_label = ttk.Label(top_frame, textvariable=self.status_var)
        status_label.pack(side=tk.RIGHT)

        # Прогрес-індикатор
        self.progress = ttk.Progressbar(top_frame, mode="indeterminate", length=120)
        self.progress.pack(side=tk.RIGHT, padx=(0, 10))

        # Основна таблиця
        columns = ("risk_score", "risk_level", "ml_score", "nn_score", "heuristic_score", "entropy", "complexity")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=12)
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tree.heading("risk_score", text="Risk", command=lambda: self._sort_by("risk_score"))
        self.tree.heading("risk_level", text="Level", command=lambda: self._sort_by("risk_level"))
        self.tree.heading("ml_score", text="ML", command=lambda: self._sort_by("ml_score"))
        self.tree.heading("nn_score", text="NN", command=lambda: self._sort_by("nn_score"))
        self.tree.heading("heuristic_score", text="Heur", command=lambda: self._sort_by("heuristic_score"))
        self.tree.heading("entropy", text="Entropy", command=lambda: self._sort_by("entropy"))
        self.tree.heading("complexity", text="Complex", command=lambda: self._sort_by("complexity"))

        for col in columns:
            self.tree.column(col, width=80, anchor=tk.CENTER)

        # Кольорові стилі для рівнів ризику
        style = ttk.Style(self)
        style.map("Treeview", foreground=self._map_treeview_color)

        # Нижній блок: деталі / reasons
        bottom_frame = ttk.Frame(self)
        bottom_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))

        ttk.Label(bottom_frame, text="AI Summary / Reasons:").pack(anchor="w")

        self.details_text = tk.Text(bottom_frame, height=8, wrap="word")
        self.details_text.pack(fill=tk.BOTH, expand=True)

        self.tree.bind("<<TreeviewSelect>>", self._on_row_selected)

        # Локальний кеш результатів: task_id -> result
        self._results_by_id: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ Color mapping

    def _map_treeview_color(self, *_):
        # ttk.Style.map callback не дає доступу до item, тому робимо через tags
        # а тут просто повертаємо дефолт
        return [("!disabled", "black")]

    # ------------------------------------------------------------------ Public API

    def analyze_js_snippet(self, raw_js: str) -> None:
        """
        Публічний метод: ти можеш викликати його з інших вкладок,
        передаючи JS-код для аналізу.
        """
        self._enqueue_task(raw_js)

    # ------------------------------------------------------------------ Events

    def _on_analyze_clicked(self) -> None:
        # Тут ти можеш взяти JS з іншого віджета (наприклад, з редактора)
        # Для прикладу — простий input dialog або зовнішній виклик.
        # Зараз просто заглушка:
        from tkinter import simpledialog
        raw_js = simpledialog.askstring("Analyze JS", "Встав JS-код для аналізу:")
        if not raw_js:
            return
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
        task_id = self.tree.set(item_id, "risk_score")  # не дуже, краще зберігати окремо
        # Ми збережемо task_id в item tags або values — зробимо простіше:
        task_id = self.tree.item(item_id, "text")
        if not task_id:
            return

        result = self._results_by_id.get(task_id)
        if not result:
            return

        self.details_text.delete("1.0", tk.END)

        if "error" in result:
            self.details_text.insert(tk.END, f"[AI ERROR] {result['error']}\n")
            return

        self.details_text.insert(tk.END, f"Risk: {result.get('risk_score', 0.0):.2f} ({result.get('risk_level')})\n\n")
        self.details_text.insert(tk.END, "Summary:\n")
        self.details_text.insert(tk.END, result.get("llm_summary", "") + "\n\n")
        self.details_text.insert(tk.END, "Reasons:\n")
        for r in result.get("llm_reasons", []):
            self.details_text.insert(tk.END, f" - {r}\n")

    # ------------------------------------------------------------------ Task handling

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
            # можна показати в таблиці як окремий рядок з error
            self._insert_row(task_id, {
                "risk_score": 0.0,
                "risk_level": "info",
                "ml_score": 0.0,
                "nn_score": 0.0,
                "heuristic_score": 0.0,
                "entropy": 0.0,
                "complexity": 0.0,
            }, error=True)
            return

        self._insert_row(task_id, result)
        self._refilter_tree()

    # ------------------------------------------------------------------ Tree helpers

    def _insert_row(self, task_id: str, result: Dict[str, Any], error: bool = False) -> None:
        score = result.get("risk_score", 0.0)
        level = result.get("risk_level", "info")
        ml = result.get("ml_score", 0.0)
        nn = result.get("nn_score", 0.0)
        heuristic = result.get("heuristic_score", 0.0)
        entropy = result.get("entropy", 0.0)
        complexity = result.get("complexity", 0.0)

        values = (f"{score:.2f}", level, f"{ml:.2f}", f"{nn:.2f}", f"{heuristic:.2f}", f"{entropy:.2f}", f"{complexity:.2f}")

        tags: List[str] = []
        if error:
            tags.append("error")
        else:
            tags.append(f"level_{level}")

        item_id = self.tree.insert("", tk.END, text=task_id, values=values, tags=tags)

        # Кольори через tags
        if level == "high":
            self.tree.tag_configure("level_high", foreground="red")
        elif level == "medium":
            self.tree.tag_configure("level_medium", foreground="orange")
        elif level == "low":
            self.tree.tag_configure("level_low", foreground="green")
        elif level == "info":
            self.tree.tag_configure("level_info", foreground="gray")

        self.tree.tag_configure("error", foreground="red")

        return item_id

    def _refilter_tree(self) -> None:
        level_filter = self._current_filter_level

        for item in self.tree.get_children(""):
            if level_filter is None:
                self.tree.item(item, open=True)
                self.tree.detach(item)
                self.tree.move(item, "", "end")
                continue

            level = self.tree.set(item, "risk_level")
            if level == level_filter:
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

    # ------------------------------------------------------------------ Cleanup

    def destroy(self) -> None:
        try:
            self._worker.stop()
        except Exception:
            pass
        super().destroy()

