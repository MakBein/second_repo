from __future__ import annotations

import json
import logging
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from typing import Any, Callable

from xss_security_gui.auto_recon.scope import is_target_authorized, normalize_http_url
from xss_security_gui.integrations.email_leak_worker import EmailLeakWorker

logger = logging.getLogger(__name__)


class EmailLeakWorkerTab(ttk.Frame):
    """Allowlisted Chromium audit: JS DOM, unmasked emails, GET/POST form inventory."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        worker_provider: Callable[[], EmailLeakWorker],
        target_provider: Callable[[], str],
    ) -> None:
        super().__init__(parent)
        self._worker_provider = worker_provider
        self._target_provider = target_provider
        self._build_ui()
        worker = self._worker_provider()
        if worker.is_running():
            self.status_var.set("Аудит выполняется в фоновом потоке…")
            self.stop_button.configure(state="normal")
            self.start_button.configure(state="disabled")
        elif worker.last_result is not None:
            self.set_result(worker.last_result)

    def _build_ui(self) -> None:
        header = ttk.Frame(self, padding=(12, 10, 12, 4))
        header.pack(fill="x")
        ttk.Label(
            header, text="Email Exposure Audit", font=("TkDefaultFont", 14, "bold")
        ).pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Chromium (Playwright) відкриває same-origin сторінки дозволеної цілі, "
                "аналізує DOM після JavaScript і надсилає GET/POST у виявлені форми. "
                "Адреси email у вкладці не маскуються."
            ),
            wraplength=900,
        ).pack(anchor="w", pady=(2, 0))

        controls = ttk.Frame(self, padding=(12, 6))
        controls.pack(fill="x")
        ttk.Label(controls, text="Авторизованный URL").grid(
            row=0, column=0, sticky="w"
        )
        self.target_var = tk.StringVar(value=self._target_provider())
        self.target_entry = ttk.Entry(controls, textvariable=self.target_var)
        self.target_entry.grid(row=0, column=1, sticky="ew", padx=8)
        self.start_button = ttk.Button(
            controls, text="Запустить аудит", command=self.start_audit
        )
        self.start_button.grid(row=0, column=2, padx=3)
        self.stop_button = ttk.Button(
            controls, text="Остановить", command=self.stop_audit, state="disabled"
        )
        self.stop_button.grid(row=0, column=3, padx=3)
        controls.columnconfigure(1, weight=1)

        self.status_var = tk.StringVar(value="Готов к запуску")
        ttk.Label(self, textvariable=self.status_var, padding=(12, 4)).pack(
            anchor="w", fill="x"
        )
        self.summary_var = tk.StringVar(
            value="Страниц: 0  |  Email: 0  |  Форм: 0  |  Запросов: 0"
        )
        summary = ttk.LabelFrame(self, text="Сводка последнего аудита", padding=8)
        summary.pack(fill="x", padx=12, pady=(0, 8))
        ttk.Label(summary, textvariable=self.summary_var).pack(anchor="w")

        self.workspace = ttk.Notebook(self)
        self.workspace.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        overview = ttk.Frame(self.workspace, padding=8)
        forms_page = ttk.Frame(self.workspace, padding=8)
        activity_page = ttk.Frame(self.workspace, padding=8)
        self.workspace.add(overview, text="Опубликованные email")
        self.workspace.add(forms_page, text="Обнаруженные формы")
        self.workspace.add(activity_page, text="Отчёт")

        self.email_tree = ttk.Treeview(
            overview,
            columns=("email", "sources"),
            show="headings",
            height=12,
        )
        self.email_tree.heading("email", text="Email")
        self.email_tree.heading("sources", text="Источники")
        self.email_tree.column("email", width=260, minwidth=160, anchor="w")
        self.email_tree.column("sources", width=600, minwidth=220, anchor="w")
        email_scroll = ttk.Scrollbar(
            overview, orient="vertical", command=self.email_tree.yview
        )
        self.email_tree.configure(yscrollcommand=email_scroll.set)
        self.email_tree.pack(side="left", fill="both", expand=True)
        email_scroll.pack(side="right", fill="y")
        self.email_empty = ttk.Label(
            overview, text="После аудита здесь появятся найденные адреса.", anchor="center"
        )
        self.email_empty.place(relx=0.5, rely=0.5, anchor="center")

        self.form_tree = ttk.Treeview(
            forms_page,
            columns=("action", "method", "fields"),
            show="headings",
            height=12,
        )
        for column, title, width in (
            ("action", "Same-origin action", 420),
            ("method", "Метод", 80),
            ("fields", "Поля (name:type)", 420),
        ):
            self.form_tree.heading(column, text=title)
            self.form_tree.column(column, width=width, minwidth=70, anchor="w")
        form_scroll = ttk.Scrollbar(
            forms_page, orient="vertical", command=self.form_tree.yview
        )
        self.form_tree.configure(yscrollcommand=form_scroll.set)
        self.form_tree.pack(side="left", fill="both", expand=True)
        form_scroll.pack(side="right", fill="y")
        ttk.Label(
            forms_page,
            text="Форми інвентаризуються з DOM після JS. Для allowlist-цілі надсилаються GET/POST.",
        ).pack(anchor="w", pady=(6, 0))

        output_frame = ttk.Frame(activity_page)
        output_frame.pack(fill="both", expand=True)
        self.output = ScrolledText(output_frame, wrap="word", state="disabled")
        self.output.pack(fill="both", expand=True)

    def start_audit(self) -> None:
        try:
            target = normalize_http_url(self.target_var.get())
        except (AttributeError, TypeError, ValueError) as exc:
            self.status_var.set(f"Некорректный URL: {exc}")
            return
        if not is_target_authorized(target):
            self.status_var.set(
                "Запуск заблокирован: домен не разрешён в ALLOW_REAL_RUN / ALLOWED_TARGETS."
            )
            return

        try:
            self.start_button.configure(state="disabled")
            worker = self._worker_provider()
            started = worker.start(target, active_testing=True)
        except (TypeError, ValueError) as exc:
            self.start_button.configure(state="normal")
            self.status_var.set(f"Аудит не запущен: {exc}")
            return

        if not started:
            self.start_button.configure(state="normal")
            self.status_var.set("Аудит уже выполняется.")
            return

        self.target_var.set(target)
        self.status_var.set("Аудит выполняется в фоновом потоке…")
        self.stop_button.configure(state="normal")
        self._write_output(f"Аудит запущен для {target}\n")

    def stop_audit(self) -> None:
        worker = self._worker_provider()
        if worker.is_running():
            worker.stop()
            self.status_var.set("Останавливаю аудит…")
            self.stop_button.configure(state="disabled")

    def set_result(self, result: dict[str, Any]) -> None:
        status = result.get("status", "unknown")
        emails = result.get("emails", [])
        sources = result.get("email_sources", {})
        forms = result.get("forms", [])
        submissions = result.get("form_submissions", [])
        if not isinstance(emails, list):
            emails = []
        if not isinstance(sources, dict):
            sources = {}
        if not isinstance(forms, list):
            forms = []
        if not isinstance(submissions, list):
            submissions = []

        self.status_var.set(
            f"Аудит {status}: {result.get('page_count', 0)} страниц, "
            f"{len(emails)} email, "
            f"{len(submissions)} GET/POST, "
            f"{result.get('requests', 0)} запросов."
        )
        self.summary_var.set(
            f"Страниц: {result.get('page_count', 0)}  |  "
            f"Email: {len(emails)}  |  Форм: {len(forms)}  |  "
            f"Відправки: {len(submissions)}  |  "
            f"Запросов: {result.get('requests', 0)}"
        )
        self.email_tree.delete(*self.email_tree.get_children())
        for email in sorted(str(item) for item in emails):
            email_sources = sources.get(email, [])
            if not isinstance(email_sources, list):
                email_sources = []
            self.email_tree.insert(
                "",
                "end",
                values=(email, ", ".join(map(str, email_sources))),
            )
        if emails:
            self.email_empty.place_forget()
        else:
            self.email_empty.place(relx=0.5, rely=0.5, anchor="center")

        self.form_tree.delete(*self.form_tree.get_children())
        for form in forms:
            if not isinstance(form, dict):
                continue
            self.form_tree.insert(
                "",
                "end",
                values=(
                    form.get("action") or form.get("url") or "—",
                    form.get("method", "—"),
                    self._format_fields(form),
                ),
            )

        self.stop_button.configure(state="disabled")
        self.start_button.configure(state="normal")
        report = {
            "status": status,
            "target": result.get("target", "—"),
            "engine": result.get("engine", "—"),
            "active_testing": result.get("active_testing", True),
            "page_count": result.get("page_count", 0),
            "email_count": len(emails),
            "emails": [str(item) for item in emails],
            "forms": forms,
            "form_submissions": submissions,
            "requests": result.get("requests", 0),
        }
        self._write_output(json.dumps(report, ensure_ascii=False, indent=2, default=str))

    def set_error(self, error: str) -> None:
        self.status_var.set(f"Ошибка аудита: {error}")
        self.stop_button.configure(state="disabled")
        self.start_button.configure(state="normal")

    def _write_output(self, text: str) -> None:
        try:
            self.output.configure(state="normal")
            self.output.insert("end", text.rstrip() + "\n\n")
            self.output.see("end")
            self.output.configure(state="disabled")
        except tk.TclError:
            logger.debug("Email audit tab was closed before output could be updated")

    @staticmethod
    def _format_fields(form: dict[str, Any]) -> str:
        fields = form.get("fields")
        if isinstance(fields, list) and fields:
            parts = []
            for field in fields:
                if not isinstance(field, dict):
                    continue
                name = str(field.get("name") or "—")
                field_type = str(field.get("type") or "text")
                parts.append(f"{name}:{field_type}")
            return ", ".join(parts) if parts else "—"
        return str(form.get("input_count", 0))
