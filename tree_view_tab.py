"""Hierarchical URL view for pages discovered by the SuperCrawler."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from xss_security_gui.tabs.xss_flooder_tab import XSSFlooderTab


class SuperCrawlerTreeViewTab(ttk.Frame):
    """Show crawler URL nodes and allow an explicit audit of the selected URL."""

    def __init__(self, parent, **kwargs: Any) -> None:
        super().__init__(parent, **kwargs)
        self._urls: dict[str, str] = {}
        self.root = ""

        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", padx=8, pady=6)
        self.status_var = tk.StringVar(value="Страниц: 0")
        ttk.Label(toolbar, textvariable=self.status_var, anchor="w").pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(
            toolbar, text="Аудит выбранного URL", command=self.audit_selected
        ).pack(side="right")

        self.tree = ttk.Treeview(
            self,
            columns=("url", "status"),
            show="tree headings",
            selectmode="browse",
        )
        self.tree.heading("#0", text="Узел")
        self.tree.heading("url", text="URL")
        self.tree.heading("status", text="Состояние")
        self.tree.column("#0", width=220, anchor="w")
        self.tree.column("url", width=560, anchor="w")
        self.tree.column("status", width=140, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.tree.bind("<Double-1>", lambda _event: self.audit_selected())

    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._urls.clear()
        self.status_var.set("Страниц: 0")

    def add_node(self, parent: str, node: Any) -> str:
        parent_id = parent if parent and self.tree.exists(parent) else ""
        if isinstance(node, dict):
            url = str(node.get("url") or node.get("target") or "")
            label = str(node.get("label") or url or "Узел")
            status = str(node.get("status") or node.get("error") or "OK")
        else:
            url = str(node)
            label = url
            status = "OK"

        item_id = self.tree.insert(
            parent_id,
            "end",
            text=label,
            values=(url, status),
            open=True,
        )
        if url:
            self._urls[item_id] = url
        self.status_var.set(f"Страниц: {len(self._urls)}")
        return item_id

    def update_tree(self, nodes: Any) -> None:
        if isinstance(nodes, dict):
            nodes = nodes.get("nodes", [nodes])
        if not isinstance(nodes, (list, tuple)):
            return

        self.clear()
        for node in nodes:
            if isinstance(node, (str, dict)):
                self.add_node(self.root, node)

    def audit_selected(self) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        target = self._urls.get(selected[0])
        if not target:
            return

        window = tk.Toplevel(self)
        window.title(f"Аудит — {target}")
        window.geometry("1000x650")
        tab = XSSFlooderTab(window)
        tab.target_var.set(target)
        tab.pack(fill="both", expand=True)
