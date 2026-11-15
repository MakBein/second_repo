"""Live progress and page list for the SuperCrawler."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Optional

from xss_security_gui.tabs.xss_flooder_tab import XSSFlooderTab


class SuperCrawlerMonitorTab(ttk.Frame):
    """Display crawl status, progress, discovered pages, and per-page log entries."""

    def __init__(
        self,
        parent,
        root_url: str = "",
        target_provider: Optional[Callable[[], str]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(parent, **kwargs)
        self.root_url = root_url
        self.target_provider = target_provider
        self.status_var = tk.StringVar(value="Ожидание краулера")
        self.progress_var = tk.IntVar(value=0)

        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", padx=8, pady=6)
        ttk.Label(toolbar, textvariable=self.status_var, anchor="w").pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(toolbar, text="Аудит URL", command=self.open_audit).pack(side="right")

        self.progress_bar = ttk.Progressbar(
            self, variable=self.progress_var, maximum=100, mode="determinate"
        )
        self.progress_bar.pack(fill="x", padx=8, pady=(0, 6))

        content = ttk.Panedwindow(self, orient="vertical")
        content.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        page_frame = ttk.Labelframe(content, text="Обнаруженные страницы")
        self.tree = ttk.Treeview(
            page_frame,
            columns=("url", "status"),
            show="tree headings",
        )
        self.tree.heading("#0", text="Страница")
        self.tree.heading("url", text="URL")
        self.tree.heading("status", text="Состояние")
        self.tree.column("#0", width=180, anchor="w")
        self.tree.column("url", width=520, anchor="w")
        self.tree.column("status", width=120, anchor="w")
        self.tree.pack(fill="both", expand=True)
        content.add(page_frame, weight=3)

        log_frame = ttk.Labelframe(content, text="События")
        self.log_view = tk.Text(log_frame, height=7, wrap="word", state="disabled")
        self.log_view.pack(fill="both", expand=True)
        content.add(log_frame, weight=1)

    def set_progress(self, value: int) -> None:
        self.progress_var.set(max(0, min(100, int(value))))

    def set_status(self, message: str) -> None:
        self.status_var.set(str(message))

    def log_message(self, message: str) -> None:
        self.log_view.configure(state="normal")
        self.log_view.insert("end", str(message) + "\n")
        self.log_view.see("end")
        self.log_view.configure(state="disabled")

    def clear_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())

    def add_tree_node(
        self,
        parent: str = "",
        label: str = "",
        url: str = "",
        status: str = "",
    ) -> str:
        parent_id = parent if parent and self.tree.exists(parent) else ""
        return self.tree.insert(
            parent_id,
            "end",
            text=str(label or url),
            values=(str(url), str(status)),
            open=True,
        )

    def update_tree(self, nodes: Any) -> None:
        if isinstance(nodes, dict):
            nodes = nodes.get("nodes", [nodes])
        if not isinstance(nodes, (list, tuple)):
            return

        self.clear_tree()
        for node in nodes:
            if isinstance(node, str):
                self.add_tree_node(label=node, url=node, status="OK")
                continue
            if not isinstance(node, dict):
                continue
            url = str(node.get("url") or node.get("target") or "")
            if not url:
                continue
            status = str(node.get("status") or node.get("error") or "OK")
            self.add_tree_node(label=url, url=url, status=status)

    def _resolve_audit_target(self) -> str:
        target = self.root_url.strip()
        if self.target_provider is not None:
            try:
                target = str(self.target_provider() or "").strip() or target
            except Exception as exc:
                self.log_message(f"Не удалось получить URL для аудита: {exc}")
        return target

    def open_audit(self) -> None:
        target = self._resolve_audit_target()
        if not target:
            self.log_message("Укажите целевой URL в нижнем поле перед аудитом.")
            return
        window = tk.Toplevel(self)
        window.title(f"Аудит — {target}")
        window.geometry("1000x650")
        tab = XSSFlooderTab(window)
        tab.target_var.set(target)
        tab.pack(fill="both", expand=True)
