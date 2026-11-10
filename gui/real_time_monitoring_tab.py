"""Read-only live view of watcher status and persisted threat events."""

from __future__ import annotations

import json
import threading
import tkinter as tk
from tkinter import ttk
from typing import Any

from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


class RealTimeMonitoringTab(ttk.Frame):
    """Show watcher telemetry and recent local Threat Intel records."""

    REFRESH_MS = 5000

    def __init__(self, parent, ui_bridge, watcher=None, **kwargs: Any) -> None:
        super().__init__(parent, **kwargs)
        self.ui_bridge = ui_bridge
        self.watcher = watcher
        self._refresh_lock = threading.Lock()
        self._refresh_scheduled: str | None = None
        self._destroyed = False

        header = ttk.Frame(self, padding=(12, 10, 12, 4))
        header.pack(fill="x")
        ttk.Label(
            header, text="Real-Time Monitoring", font=("TkDefaultFont", 14, "bold")
        ).pack(anchor="w")
        ttk.Label(
            header,
            text="Огляд збережених подій Threat Intelligence та стану моніторингу.",
        ).pack(anchor="w", pady=(2, 0))

        toolbar = ttk.Frame(self, padding=(12, 6))
        toolbar.pack(fill="x")
        self.status_var = tk.StringVar(value="Підключення до сховища подій…")
        ttk.Label(toolbar, textvariable=self.status_var, anchor="w").pack(
            side="left", fill="x", expand=True
        )
        self.refresh_button = ttk.Button(
            toolbar, text="Оновити", command=self.refresh
        )
        self.refresh_button.pack(side="right")

        summary = ttk.LabelFrame(self, text="Зведення", padding=8)
        summary.pack(fill="x", padx=12, pady=(0, 8))
        self.summary_var = tk.StringVar(value="Подій: 0  |  Високий ризик: 0")
        ttk.Label(summary, textvariable=self.summary_var).pack(anchor="w")

        filters = ttk.Frame(self, padding=(12, 0, 12, 8))
        filters.pack(fill="x")
        ttk.Label(filters, text="Ризик").pack(side="left", padx=(0, 5))
        self.severity_filter = ttk.Combobox(
            filters,
            values=("Усі", "critical", "high", "medium", "low", "info"),
            state="readonly",
            width=12,
        )
        self.severity_filter.set("Усі")
        self.severity_filter.pack(side="left", padx=(0, 12))
        self.severity_filter.bind("<<ComboboxSelected>>", self._apply_filters)
        ttk.Label(filters, text="Пошук").pack(side="left", padx=(0, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(filters, textvariable=self.search_var)
        search_entry.pack(side="left", fill="x", expand=True)
        self.search_var.trace_add("write", self._apply_filters)

        table_frame = ttk.Frame(self, padding=(12, 0, 12, 8))
        table_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(
            table_frame,
            columns=("timestamp", "module", "severity", "target", "category"),
            show="headings",
            height=14,
        )
        for column, title, width in (
            ("timestamp", "Время", 170),
            ("module", "Модуль", 170),
            ("severity", "Риск", 90),
            ("target", "Цель", 300),
            ("category", "Категория", 180),
        ):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, minwidth=70, anchor="w")
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
        self.tree.tag_configure("critical", foreground="#b00020")
        self.tree.tag_configure("high", foreground="#c65911")
        self.tree.tag_configure("medium", foreground="#9c6500")
        self.tree.tag_configure("low", foreground="#356b3b")
        self.tree.bind("<<TreeviewSelect>>", self._show_event_details)

        self.empty_state = ttk.Label(
            table_frame,
            text="Подій ще немає. Натисніть «Оновити», щоб перевірити сховище.",
            anchor="center",
        )
        self.empty_state.place(relx=0.5, rely=0.5, anchor="center")

        details_frame = ttk.LabelFrame(
            self, text="Деталі вибраної події", padding=8
        )
        details_frame.pack(fill="x", padx=12, pady=(0, 12))
        self.details_box = tk.Text(details_frame, height=5, wrap="word", state="disabled")
        self.details_box.pack(fill="both", expand=True)
        self._artifacts: list[dict[str, Any]] = []
        self._visible_artifacts: list[dict[str, Any]] = []
        self.bind("<Destroy>", self._on_destroy, add=True)
        self.refresh()

    def refresh(self) -> None:
        if self._destroyed or not self._refresh_lock.acquire(blocking=False):
            return
        self.status_var.set("Обновление событий…")
        self.refresh_button.configure(state="disabled")

        def worker() -> None:
            try:
                artifacts = THREAT_CONNECTOR.load_all()
                if not isinstance(artifacts, list):
                    raise TypeError("ThreatConnector.load_all() must return a list")
                artifacts = sorted(
                    (item for item in artifacts if isinstance(item, dict)),
                    key=lambda item: str(item.get("timestamp", "")),
                    reverse=True,
                )[:100]
                watcher_status = (
                    self.watcher.get_status() if self.watcher is not None else "недоступен"
                )
                watcher_url = getattr(self.watcher, "url", "—")
                watcher_interval = getattr(self.watcher, "interval", "—")
                retry_stats = (
                    self.watcher.get_retry_stats()
                    if self.watcher is not None
                    and callable(getattr(self.watcher, "get_retry_stats", None))
                    else {}
                )
                self.ui_bridge.post_ui(
                    self._render,
                    artifacts,
                    watcher_status,
                    watcher_url,
                    watcher_interval,
                    retry_stats,
                )
            except Exception as exc:
                self.ui_bridge.post_ui(self._show_error, exc)
            finally:
                self._refresh_lock.release()

        threading.Thread(
            target=worker, name="RealtimeMonitoringRefresh", daemon=True
        ).start()

    def _render(
        self,
        artifacts: list[dict[str, Any]],
        watcher_status: str,
        watcher_url: str,
        watcher_interval: Any,
        retry_stats: dict[str, Any],
    ) -> None:
        if self._destroyed:
            return
        retry_summary = ", ".join(
            f"{key}={value}" for key, value in sorted(retry_stats.items())
        ) or "нет данных"
        self.status_var.set(
            f"Монітор: {watcher_status} | Ціль: {watcher_url} | "
            f"Інтервал: {watcher_interval} с | Повтори: {retry_summary}"
        )
        self._artifacts = artifacts
        self._apply_filters()
        self.refresh_button.configure(state="normal")
        if self._refresh_scheduled is None:
            self._refresh_scheduled = self.after(
                self.REFRESH_MS, self._scheduled_refresh
            )

    def _apply_filters(self, *_args: Any) -> None:
        if self._destroyed:
            return
        selected_severity = self.severity_filter.get().lower()
        search = self.search_var.get().strip().casefold()
        filtered: list[dict[str, Any]] = []
        for artifact in self._artifacts:
            result = artifact.get("result")
            result = result if isinstance(result, dict) else {}
            severity = str(
                result.get("severity")
                or artifact.get("severity")
                or "info"
            ).lower()
            searchable = " ".join(
                str(value)
                for value in (
                    artifact.get("timestamp", ""),
                    artifact.get("module", ""),
                    artifact.get("target", ""),
                    result.get("category", artifact.get("category", "")),
                )
            ).casefold()
            if selected_severity not in {"", "усі"} and severity != selected_severity:
                continue
            if search and search not in searchable:
                continue
            filtered.append(artifact)

        self._visible_artifacts = filtered
        self.tree.delete(*self.tree.get_children())
        for artifact in filtered:
            result = artifact.get("result")
            result = result if isinstance(result, dict) else {}
            severity = str(
                result.get("severity") or artifact.get("severity") or "info"
            ).lower()
            self.tree.insert(
                "",
                "end",
                values=(
                    artifact.get("timestamp", result.get("timestamp", "—")),
                    artifact.get("module", "—"),
                    severity.upper(),
                    artifact.get("target", "—"),
                    result.get("category", artifact.get("category", "—")),
                ),
                tags=(severity,)
                if severity in {"critical", "high", "medium", "low"}
                else (),
            )
        if filtered:
            self.empty_state.place_forget()
        else:
            self.empty_state.place(relx=0.5, rely=0.5, anchor="center")
        high_risk = sum(
            1
            for artifact in self._artifacts
            if str(
                (artifact.get("result") or {}).get("severity")
                if isinstance(artifact.get("result"), dict)
                else artifact.get("severity", "info")
            ).lower()
            in {"critical", "high"}
        )
        self.summary_var.set(
            f"Подій: {len(self._artifacts)}  |  Високий ризик: {high_risk}  "
            f"|  Показано: {len(filtered)}"
        )

    def _show_event_details(self, _event: tk.Event | None = None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        index = self.tree.index(selection[0])
        if index >= len(self._visible_artifacts):
            return
        artifact = self._visible_artifacts[index]
        result = artifact.get("result")
        result = result if isinstance(result, dict) else {}
        safe_details = {
            "Время": artifact.get("timestamp", "—"),
            "Модуль": artifact.get("module", "—"),
            "Риск": result.get("severity", artifact.get("severity", "info")),
            "Цель": artifact.get("target", "—"),
            "Категория": result.get("category", artifact.get("category", "—")),
            "Источник": result.get("source", artifact.get("source", "—")),
            "Теги": result.get("tags", artifact.get("tags", [])),
        }
        self.details_box.configure(state="normal")
        self.details_box.delete("1.0", "end")
        self.details_box.insert(
            "1.0", json.dumps(safe_details, ensure_ascii=False, indent=2, default=str)
        )
        self.details_box.configure(state="disabled")

    def _show_error(self, error: Exception) -> None:
        if not self._destroyed:
            self.status_var.set(
                f"Не вдалося завантажити події: {type(error).__name__}: {error}"
            )
            self.refresh_button.configure(state="normal")
            self._artifacts = []
            self._apply_filters()
            if self._refresh_scheduled is None:
                self._refresh_scheduled = self.after(
                    self.REFRESH_MS, self._scheduled_refresh
                )

    def _scheduled_refresh(self) -> None:
        self._refresh_scheduled = None
        self.refresh()

    def _on_destroy(self, event: tk.Event) -> None:
        if event.widget is self:
            self._destroyed = True
            if self._refresh_scheduled is not None:
                self.after_cancel(self._refresh_scheduled)
                self._refresh_scheduled = None
