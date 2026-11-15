"""Read-only account-related Threat Intel records with sensitive fields masked."""

from __future__ import annotations

import json
import threading
import tkinter as tk
from tkinter import ttk
from typing import Any

from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge


_ACCOUNT_TERMS = (
    "account",
    "identity",
    "email",
    "credential",
    "user",
    "login",
    "pii",
)
_SENSITIVE_TERMS = (
    "password",
    "passwd",
    "secret",
    "token",
    "cookie",
    "authorization",
    "api_key",
    "apikey",
    "access_key",
)


def _mask_email(value: str) -> str:
    local, separator, domain = value.partition("@")
    if not separator:
        return value[:2] + ("…" if len(value) > 2 else "")
    return f"{local[:1]}…@{domain}"


def _safe_summary(value: Any, key: str = "") -> str:
    normalized_key = key.lower().replace("-", "_")
    if any(marker in normalized_key for marker in _SENSITIVE_TERMS):
        return "[скрыто]"
    if isinstance(value, dict):
        parts = []
        for child_key, child_value in list(value.items())[:12]:
            parts.append(f"{child_key}: {_safe_summary(child_value, str(child_key))}")
        return "; ".join(parts)
    if isinstance(value, list):
        return ", ".join(_safe_summary(item, key) for item in value[:8])
    if isinstance(value, str):
        if "@" in value and len(value) < 255:
            return _mask_email(value)
        return value[:240]
    if value is None or isinstance(value, (bool, int, float)):
        return str(value)
    return type(value).__name__


class AccountsTab(ttk.Frame):
    """Browse account/identity artifacts already stored in Threat Intel."""

    def __init__(self, parent, threat_connector, **kwargs: Any) -> None:
        super().__init__(parent, **kwargs)
        self.threat_connector = threat_connector
        self._refresh_lock = threading.Lock()
        self._bridge = UIQueueBridge(self, poll_ms=50)
        self._destroyed = False

        header = ttk.Frame(self)
        header.pack(fill="x", padx=8, pady=8)
        ttk.Label(
            header,
            text="Локальные account / identity артефакты Threat Intel",
        ).pack(side="left", fill="x", expand=True)
        ttk.Button(header, text="Обновить", command=self.refresh).pack(side="right")

        self.status_var = tk.StringVar(value="Готово")
        ttk.Label(self, textvariable=self.status_var, anchor="w").pack(
            fill="x", padx=8, pady=(0, 5)
        )
        self.tree = ttk.Treeview(
            self,
            columns=("timestamp", "module", "target", "category", "summary"),
            show="headings",
        )
        for column, title, width in (
            ("timestamp", "Время", 165),
            ("module", "Модуль", 150),
            ("target", "Источник / цель", 250),
            ("category", "Категория", 150),
            ("summary", "Сводка (секреты скрыты)", 500),
        ):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.bind("<Destroy>", self._on_destroy, add=True)
        self.refresh()

    def refresh(self) -> None:
        if self._destroyed or not self._refresh_lock.acquire(blocking=False):
            return
        self.status_var.set("Загрузка account-артефактов…")

        def worker() -> None:
            try:
                artifacts = self.threat_connector.query(
                    limit=1000,
                    offset=0,
                    order_by="timestamp",
                    order_desc=True,
                )
                accounts = [
                    artifact
                    for artifact in artifacts
                    if self._is_account_artifact(artifact)
                ]
                self._bridge.post_ui(self._render, accounts)
            except Exception as exc:
                self._bridge.post_ui(self._show_error, exc)
            finally:
                self._refresh_lock.release()

        threading.Thread(target=worker, name="AccountsTabRefresh", daemon=True).start()

    @staticmethod
    def _is_account_artifact(artifact: Any) -> bool:
        if not isinstance(artifact, dict):
            return False
        module = str(artifact.get("module", "")).lower()
        result = artifact.get("result")
        if not isinstance(result, dict):
            result = {}
        category = str(result.get("category") or artifact.get("category") or "").lower()
        content = f"{module} {category} {json.dumps(result, ensure_ascii=False, default=str)}".lower()
        return any(term in content for term in _ACCOUNT_TERMS)

    def _render(self, artifacts: list[dict[str, Any]]) -> None:
        if self._destroyed:
            return
        self.tree.delete(*self.tree.get_children())
        for artifact in artifacts:
            result = artifact.get("result")
            result = result if isinstance(result, dict) else {}
            category = result.get("category", artifact.get("category", "—"))
            self.tree.insert(
                "",
                "end",
                values=(
                    artifact.get("timestamp", result.get("timestamp", "—")),
                    artifact.get("module", "—"),
                    artifact.get("target", "—"),
                    category,
                    _safe_summary(result),
                ),
            )
        self.status_var.set(f"Загружено account-артефактов: {len(artifacts)}")

    def _show_error(self, error: Exception) -> None:
        if not self._destroyed:
            self.status_var.set(
                f"Ошибка загрузки: {type(error).__name__}: {error}"
            )

    def _on_destroy(self, event: tk.Event) -> None:
        if event.widget is self:
            self._destroyed = True
            self._bridge.stop()
