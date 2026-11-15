# xss_security_gui/tabs/tree_view_tab.py
"""
SuperCrawlerTreeViewTab — окрема вкладка GUI для дерева краулера.
Повністю ізольована від main.py:
- власний Frame
- власний TreeView
- власний root-вузол
- готова для оновлення через UIQueueBridge
- не блокує GUI
"""

import tkinter as tk
from tkinter import ttk


class SuperCrawlerTreeViewTab(ttk.Frame):
    """
    Вкладка Live Tree View — показує дерево URL-ів, які SuperCrawler знаходить у реальному часі.
    """

    def __init__(self, parent):
        super().__init__(parent)

        # Заголовок
        ttk.Label(
            self,
            text="SuperCrawler Tree View",
            font=("Segoe UI", 14, "bold")
        ).pack(pady=5)

        # Дерево
        self.tree = ttk.Treeview(self)
        self.tree.pack(fill="both", expand=True)

        # Кореневий елемент
        self.root = self.tree.insert("", "end", text="Crawler Root", open=True)

    # ------------------------------------------------------------
    # API для main.py / SuperCrawlerRunner
    # ------------------------------------------------------------
    def add_node(self, parent, text):
        """
        Додає новий вузол у дерево.
        Викликається тільки з головного потоку через UIQueueBridge.
        """
        try:
            return self.tree.insert(parent, "end", text=text)
        except Exception:
            return None

    def clear(self):
        """
        Очищає дерево перед новим запуском.
        """
        try:
            self.tree.delete(*self.tree.get_children())
            self.root = self.tree.insert("", "end", text="Crawler Root", open=True)
        except Exception:
            pass

    def update_tree(self, nodes):
        """
        Повне оновлення дерева (наприклад, після завершення краулера).
        nodes — список словників:
            { "label": "...", "children": [...] }
        """
        try:
            self.clear()

            def add_recursive(parent, node):
                item = self.tree.insert(parent, "end", text=node.get("label", ""))
                for child in node.get("children", []):
                    add_recursive(item, child)

            for n in nodes:
                add_recursive(self.root, n)

        except Exception:
            pass
