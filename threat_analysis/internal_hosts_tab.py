"""Local inventory of internal hosts found in stored Threat Intel artifacts."""

from __future__ import annotations

import ipaddress
import re
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Any
from urllib.parse import urlparse

from xss_security_gui.auto_recon.scope import is_target_authorized, normalize_http_url
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge

_IP_PATTERN = re.compile(
    r"(?<![\w.])(?:"
    r"(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"169\.254\.\d{1,3}\.\d{1,3}"
    r")(?![\w.])"
)


def _internal_host(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private or ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


class InternalHostsTab(ttk.Frame):
    """List private IPs already present in local Threat Intel data."""

    def __init__(self, parent, **kwargs: Any) -> None:
        super().__init__(parent, **kwargs)
        self._bridge = UIQueueBridge(self, poll_ms=50)
        self._refresh_lock = threading.Lock()
        self._destroyed = False
        self._host_sources: dict[str, set[str]] = {}

        header = ttk.Frame(self, padding=(12, 10, 12, 4))
        header.pack(fill="x")
        ttk.Label(
            header, text="Internal Hosts", font=("TkDefaultFont", 14, "bold")
        ).pack(anchor="w")
        ttk.Label(
            header,
            text="Инвентаризация внутренних IP из локально сохранённых Threat Intel артефактов.",
        ).pack(anchor="w", pady=(2, 0))

        toolbar = ttk.Frame(self, padding=(12, 6))
        toolbar.pack(fill="x")
        ttk.Label(toolbar, text="Поиск").pack(side="left", padx=(0, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(toolbar, textvariable=self.search_var)
        search_entry.pack(side="left", fill="x", expand=True)
        self.search_var.trace_add("write", self._apply_filter)
        self.refresh_button = ttk.Button(
            toolbar, text="Обновить", command=self.refresh
        )
        self.refresh_button.pack(side="right", padx=(8, 0))
        self.audit_button = ttk.Button(
            toolbar, text="Проверить разрешение", command=self.audit_selected
        )
        self.audit_button.pack(side="right")

        self.status_var = tk.StringVar(value="Подключение к локальному хранилищу…")
        ttk.Label(self, textvariable=self.status_var, anchor="w").pack(
            fill="x", padx=12, pady=(0, 6)
        )
        self.summary_var = tk.StringVar(value="IP-адресов: 0  |  Источников: 0")
        summary = ttk.LabelFrame(self, text="Сводка", padding=8)
        summary.pack(fill="x", padx=12, pady=(0, 8))
        ttk.Label(summary, textvariable=self.summary_var).pack(anchor="w")

        content = ttk.Panedwindow(self, orient="vertical")
        content.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        table_frame = ttk.Frame(content)
        details_frame = ttk.LabelFrame(
            content, text="Источники выбранного адреса", padding=8
        )
        content.add(table_frame, weight=3)
        content.add(details_frame, weight=1)
        self.tree = ttk.Treeview(
            table_frame,
            columns=("host", "source", "module"),
            show="headings",
            selectmode="browse",
        )
        for column, title, width in (
            ("host", "Внутренний IP", 180),
            ("source", "Артефакт / цель", 350),
            ("module", "Модуль", 180),
        ):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, minwidth=90, anchor="w")
        y_scroll = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.tree.yview
        )
        x_scroll = ttk.Scrollbar(
            table_frame, orient="horizontal", command=self.tree.xview
        )
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.tree.bind("<Double-1>", lambda _event: self.audit_selected())
        self.tree.bind("<<TreeviewSelect>>", self._show_host_details)
        self.empty_state = ttk.Label(
            table_frame,
            text="Пока нет внутренних IP. Обновите список после сохранения Threat Intel артефактов.",
            anchor="center",
        )
        self.empty_state.place(relx=0.5, rely=0.5, anchor="center")
        self.details_box = ScrolledText(
            details_frame, height=5, wrap="word", state="disabled"
        )
        self.details_box.pack(fill="both", expand=True)
        self._visible_rows: list[tuple[str, str, str]] = []
        self.bind("<Destroy>", self._on_destroy, add=True)
        self.refresh()

    def refresh(self) -> None:
        if self._destroyed or not self._refresh_lock.acquire(blocking=False):
            return
        self.status_var.set("Поиск внутренних адресов в локальных артефактах…")
        self.refresh_button.configure(state="disabled")

        def worker() -> None:
            try:
                artifacts = THREAT_CONNECTOR.load_all()
                if not isinstance(artifacts, list):
                    raise TypeError("ThreatConnector.load_all() must return a list")
                artifacts = artifacts[-5000:]
                found: dict[str, set[str]] = {}
                for artifact in artifacts:
                    if not isinstance(artifact, dict):
                        continue
                    source = str(artifact.get("target") or "unknown")
                    module = str(artifact.get("module") or "unknown")
                    result = artifact.get("result")
                    text = f"{source} {module} {result!r}"
                    for candidate in _IP_PATTERN.findall(text):
                        if _internal_host(candidate):
                            found.setdefault(candidate, set()).add(
                                f"{module}: {source}"
                            )
                self._bridge.post_ui(self._render, found)
            except Exception as exc:
                self._bridge.post_ui(self._show_error, exc)
            finally:
                self._refresh_lock.release()

        threading.Thread(
            target=worker, name="InternalHostsRefresh", daemon=True
        ).start()

    def _render(self, found: dict[str, set[str]]) -> None:
        if self._destroyed:
            return
        self._host_sources = found
        self._apply_filter()
        self.refresh_button.configure(state="normal")

    def _apply_filter(self, *_args: Any) -> None:
        if self._destroyed:
            return
        search = self.search_var.get().strip().casefold()
        self.tree.delete(*self.tree.get_children())
        self._visible_rows = []
        for host, sources in sorted(self._host_sources.items()):
            for source in sorted(sources):
                module, _, target = source.partition(": ")
                if search and search not in " ".join(
                    (host, target, module)
                ).casefold():
                    continue
                self._visible_rows.append((host, target, module))
                self.tree.insert("", "end", values=(host, target, module))
        if self._visible_rows:
            self.empty_state.place_forget()
        else:
            self.empty_state.place(relx=0.5, rely=0.5, anchor="center")
        source_count = sum(len(sources) for sources in self._host_sources.values())
        self.summary_var.set(
            f"IP-адресов: {len(self._host_sources)}  |  "
            f"Источников: {source_count}  |  Показано: {len(self._visible_rows)}"
        )
        self.status_var.set(
            f"Загружено адресов: {len(self._host_sources)} "
            f"из локальных Threat Intel артефактов"
        )

    def _show_host_details(self, _event: tk.Event | None = None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        index = self.tree.index(selection[0])
        if index >= len(self._visible_rows):
            return
        host, _target, _module = self._visible_rows[index]
        sources = sorted(self._host_sources.get(host, set()))
        self.details_box.configure(state="normal")
        self.details_box.delete("1.0", "end")
        self.details_box.insert(
            "1.0",
            f"IP-адрес: {host}\nКоличество источников: {len(sources)}\n\n"
            + "\n".join(sources),
        )
        self.details_box.configure(state="disabled")

    def _show_error(self, error: Exception) -> None:
        if not self._destroyed:
            self.refresh_button.configure(state="normal")
            self._host_sources = {}
            self._apply_filter()
            self.status_var.set(
                f"Ошибка загрузки Threat Intel: {type(error).__name__}: {error}"
            )

    def audit_selected(self) -> None:
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo(
                "Internal Hosts", "Выберите адрес из списка.", parent=self
            )
            return

        values = self.tree.item(selection[0], "values")
        if not values:
            return
        host = str(values[0])
        source_url = str(values[1])
        parsed = urlparse(source_url)
        if parsed.scheme not in ("http", "https") or parsed.hostname != host:
            messagebox.showwarning(
                "Ціль не визначена",
                "Джерело не підтверджує HTTP(S)-адресу для цього IP. "
                "Аудит не запускався.",
                parent=self,
            )
            return
        try:
            target = normalize_http_url(source_url)
        except ValueError as exc:
            messagebox.showerror("Некоректна ціль", str(exc), parent=self)
            return
        if not is_target_authorized(target):
            messagebox.showwarning(
                "Ціль не дозволена",
                "Аудит доступний лише для цілей, явно внесених "
                "до списку авторизованих.",
                parent=self,
            )
            return

        window = tk.Toplevel(self)
        window.title(f"Проверка разрешения — {host}")
        window.geometry("620x220")
        ttk.Label(
            window,
            text=f"Ціль: {target}\nАктивний аудит не запускається автоматично.",
            padding=12,
        ).pack(fill="x")

    def _on_destroy(self, event: tk.Event) -> None:
        if event.widget is self:
            self._destroyed = True
            self._bridge.stop()
