"""Tkinter view for passive combat-cycle reports."""

from __future__ import annotations

import json
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any


class CombatResultsTab(ttk.Frame):
    """Display a combat report without consuming the application's shared event queue."""

    def __init__(self, parent, result_queue=None, threat_tab=None) -> None:
        super().__init__(parent)
        self.result_queue = result_queue
        self.threat_tab = threat_tab
        self.report: dict[str, Any] | None = None

        header = ttk.Frame(self)
        header.pack(fill="x", padx=8, pady=8)
        self.status_var = ttk.Label(
            header, text="Отчет еще не сформирован", anchor="w"
        )
        self.status_var.pack(side="left", fill="x", expand=True)
        ttk.Button(header, text="Экспорт JSON", command=self.export_report).pack(
            side="right", padx=(8, 0)
        )

        self.tree = ttk.Treeview(
            self,
            columns=("severity", "url", "category", "description"),
            show="headings",
        )
        for column, title, width in (
            ("severity", "Риск", 90),
            ("url", "URL", 300),
            ("category", "Тип", 180),
            ("description", "Описание", 420),
        ):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, anchor="w")
        self.tree.tag_configure("critical", foreground="#b00020")
        self.tree.tag_configure("high", foreground="#c65911")
        self.tree.tag_configure("medium", foreground="#9c6500")
        self.tree.tag_configure("low", foreground="#3f6f9f")
        self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    def set_report(self, report: dict[str, Any]) -> None:
        """Replace the displayed report; intended to be called on the Tk UI thread."""
        self.report = report
        summary = report.get("vulnerability_summary") or {}
        scope = report.get("scope") or {}
        path = report.get("report_path", "")
        self.status_var.config(
            text=(
                f"Статус: {report.get('status', 'unknown')} | "
                f"Страниц: {len(report.get('pages') or [])} | "
                f"Находок: {summary.get('total_vulnerable', 0)} "
                f"(critical: {summary.get('critical', 0)}, "
                f"high: {summary.get('high', 0)}, "
                f"medium: {summary.get('medium', 0)}) | "
                f"Активных запросов: {scope.get('active_requests', 0)}"
                + (f" | {path}" if path else "")
            )
        )

        self.tree.delete(*self.tree.get_children())
        for finding in (report.get("findings") or [])[:500]:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity", "info")).lower()
            self.tree.insert(
                "",
                "end",
                values=(
                    severity.upper(),
                    finding.get("url", ""),
                    finding.get("category", ""),
                    finding.get("description", ""),
                ),
                tags=(severity,) if severity in {"critical", "high", "medium", "low"} else (),
            )

        if not self.tree.get_children():
            self.tree.insert(
                "",
                "end",
                values=("-", report.get("target", ""), "-", "Находок не обнаружено"),
            )

    def export_report(self) -> None:
        if self.report is None:
            messagebox.showinfo("Экспорт отчета", "Сначала запустите аудит.")
            return

        path = filedialog.asksaveasfilename(
            parent=self,
            title="Сохранить отчет",
            defaultextension=".json",
            filetypes=(("JSON", "*.json"),),
        )
        if not path:
            return

        try:
            Path(path).write_text(
                json.dumps(self.report, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            messagebox.showerror("Ошибка экспорта", str(exc), parent=self)
            return

        self.status_var.config(text=f"Отчет экспортирован: {path}")
