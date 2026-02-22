# xss_security_gui/gui/mutator_tasks_panel.py

import tkinter as tk
from tkinter import ttk


class MutatorTasksPanel(tk.Frame):
    """
    Панель для отображения активных задач мутатора.
    • Реагирует на события task_manager
    • Отображает статус каждой задачи
    """

    def __init__(self, parent, task_manager):
        super().__init__(parent)
        self.task_manager = task_manager

        # Заголовок
        self.label = ttk.Label(self, text="Активные задачи мутатора:", font=("Segoe UI", 11, "bold"))
        self.label.pack(anchor="w", padx=5, pady=5)

        # Контейнер для таблицы + скролбары
        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Горизонтальный и вертикальный скролбары
        x_scroll = ttk.Scrollbar(frame, orient="horizontal")
        y_scroll = ttk.Scrollbar(frame, orient="vertical")

        # Список задач (Treeview)
        self.tree = ttk.Treeview(
            frame,
            columns=("task", "status"),
            show="headings",
            xscrollcommand=x_scroll.set,
            yscrollcommand=y_scroll.set
        )
        self.tree.heading("task", text="Задача")
        self.tree.heading("status", text="Статус")

        # Задаем ширину колонок
        self.tree.column("task", width=400, anchor="w")
        self.tree.column("status", width=200, anchor="center")

        # Пакуем таблицу и скролбары
        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        x_scroll.config(command=self.tree.xview)
        y_scroll.config(command=self.tree.yview)

        # Подключение событий task_manager
        task_manager.task_added = self.on_task_added
        task_manager.task_finished = self.on_task_finished

    # ---------------------------------------------------------
    # Добавление новой задачи
    # ---------------------------------------------------------
    def on_task_added(self, task_id: str, payload: str):
        """Добавляет задачу в список."""
        self.tree.insert("", "end", iid=task_id, values=(payload, "🟡 В процессе"))

    # ---------------------------------------------------------
    # Завершение задачи
    # ---------------------------------------------------------
    def on_task_finished(self, task_id: str, result: dict):
        """Обновляет статус задачи при завершении."""
        if not self.tree.exists(task_id):
            return
        self._update_task_item(task_id, result)

    # ---------------------------------------------------------
    # Вспомогательный метод обновления текста задачи
    # ---------------------------------------------------------
    def _update_task_item(self, task_id: str, result: dict):
        """Обновляет статус задачи в зависимости от результата."""
        payload = self.tree.item(task_id)["values"][0]

        if not isinstance(result, dict):
            self.tree.item(task_id, values=(payload, "🔴 Ошибка"))
            return

        if "error" in result:
            self.tree.item(task_id, values=(payload, f"🔴 Ошибка: {result['error']}"))
        else:
            generated = result.get("generated", 0)
            self.tree.item(task_id, values=(payload, f"🟢 Готово ({generated} мутантов)"))