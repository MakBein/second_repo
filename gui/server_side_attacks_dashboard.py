# xss_security_gui/gui/server_side_attacks_dashboard.py

import tkinter as tk
from tkinter import ttk
from typing import Any, Dict, List, Optional

from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge


class ServerSideAttacksDashboard(ttk.Frame):
    """
    Server-Side Attacks Dashboard 1.0
    ---------------------------------
    • Агрегація LFI / SSRF / RCE / ENV / PASSWD
    • Дані приходять з ThreatConnector / LiveAttackMonitor
    • Burp/ZAP-style: таблиця + деталі
    • Thread-safe оновлення через UIQueueBridge
    """

    COLUMNS = ("time", "type", "module", "url", "payload", "risk", "status")

    def __init__(self, parent, ui_bridge: Optional[UIQueueBridge] = None):
        super().__init__(parent)

        self.ui = ui_bridge or UIQueueBridge(self, poll_ms=50)
        self.attacks: List[Dict[str, Any]] = []

        self._build_ui()

    # ---------------------------------------------------------
    # UI
    # ---------------------------------------------------------
    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        title = ttk.Label(
            self,
            text="Server-Side Attacks Dashboard",
            font=("Segoe UI", 14, "bold"),
        )
        title.grid(row=0, column=0, sticky="w", padx=10, pady=(8, 4))

        # Верхня панель фільтрів
        filter_frame = ttk.Frame(self)
        filter_frame.grid(row=0, column=0, sticky="e", padx=10, pady=(8, 4))

        ttk.Label(filter_frame, text="Тип:").pack(side="left", padx=3)
        self.type_var = tk.StringVar(value="ALL")
        type_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.type_var,
            values=["ALL", "LFI", "SSRF", "RCE", "ENV", "PASSWD"],
            state="readonly",
            width=8,
        )
        type_combo.pack(side="left", padx=3)

        ttk.Label(filter_frame, text="Ризик:").pack(side="left", padx=3)
        self.risk_var = tk.StringVar(value="ALL")
        risk_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.risk_var,
            values=["ALL", "critical", "high", "medium", "low"],
            state="readonly",
            width=10,
        )
        risk_combo.pack(side="left", padx=3)

        ttk.Button(filter_frame, text="Apply", command=self._refresh_table).pack(side="left", padx=3)
        ttk.Button(filter_frame, text="Clear", command=self._clear_filters).pack(side="left", padx=3)

        # Таблиця
        self.tree = ttk.Treeview(
            self,
            columns=self.COLUMNS,
            show="headings",
            height=18,
        )
        for col in self.COLUMNS:
            self.tree.heading(col, text=col.upper())
        self.tree.column("time", width=130)
        self.tree.column("type", width=70)
        self.tree.column("module", width=90)
        self.tree.column("url", width=260)
        self.tree.column("payload", width=200)
        self.tree.column("risk", width=80)
        self.tree.column("status", width=80)

        self.tree.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # Нижня панель деталей
        details_frame = ttk.LabelFrame(self, text="Details")
        details_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 8))
        details_frame.columnconfigure(0, weight=1)
        details_frame.rowconfigure(0, weight=1)

        self.details_text = tk.Text(
            details_frame,
            height=8,
            wrap="word",
            bg="#111",
            fg="cyan",
            insertbackground="white",
        )
        self.details_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

    # ---------------------------------------------------------
    # Публічний API: прийом артефактів
    # ---------------------------------------------------------
    def ingest_artifact(self, artifact: Dict[str, Any]) -> None:
        """
        Викликається з ThreatConnector / LiveAttackMonitor / вкладок.
        Артефакт вже має бути нормалізований (normalize_threat_artifact).
        """
        # Фільтруємо тільки server-side речі
        atype = (artifact.get("type") or "").upper()
        if atype not in {"LFI", "SSRF", "RCE"}:
            # Додаткові евристи для ENV/PASSWD
            if not artifact.get("env_exposed") and not artifact.get("passwd_exposed"):
                return

        self.attacks.append(artifact)
        self.ui.call_ui(self._append_row, artifact)

    # ---------------------------------------------------------
    # Додавання рядка в таблицю
    # ---------------------------------------------------------
    def _append_row(self, artifact: Dict[str, Any]) -> None:
        """
        Додає рядок у таблицю Server-Side Attacks Dashboard.
        Підтримує email_leak, ENV, PASSWD, SSRF, RCE, LFI.
        """

        # === Тип атаки ===
        atype = artifact.get("type", "").upper()

        # === Ризик ===
        risk = artifact.get("risk", artifact.get("severity", "")).lower()

        # === Іконки по типу ===
        icon = ""
        if artifact.get("category") == "email_leak":
            icon = "📧"
        elif atype == "LFI":
            icon = "📂"
        elif atype == "SSRF":
            icon = "🌐"
        elif atype == "RCE":
            icon = "💥"
        elif artifact.get("env_exposed"):
            icon = "🔑"
        elif artifact.get("passwd_exposed"):
            icon = "👤"

        # === Формуємо рядок ===
        row = (
            artifact.get("ts", artifact.get("time", "")),
            f"{icon} {atype}",
            artifact.get("module", ""),
            artifact.get("url", ""),
            artifact.get("payload", ""),
            risk,
            artifact.get("status", artifact.get("http_status", "")),
        )

        self.tree.insert("", "end", values=row)

    def _artifact_to_row(self, a: Dict[str, Any]):
        return (
            a.get("ts", a.get("time", "")),
            a.get("type", ""),
            a.get("module", ""),
            a.get("url", ""),
            a.get("payload", ""),
            a.get("risk", a.get("severity", "")),
            a.get("status", a.get("http_status", "")),
        )

    # ---------------------------------------------------------
    # Фільтри
    # ---------------------------------------------------------
    def _clear_filters(self):
        self.type_var.set("ALL")
        self.risk_var.set("ALL")
        self._refresh_table()

    def _refresh_table(self):
        t_filter = self.type_var.get().upper()
        r_filter = self.risk_var.get().lower()

        for row_id in self.tree.get_children():
            self.tree.delete(row_id)

        for a in self.attacks:
            atype = (a.get("type") or "").upper()
            risk = (a.get("risk") or a.get("severity") or "").lower()

            if t_filter != "ALL" and atype != t_filter:
                continue
            if r_filter != "ALL" and risk != r_filter:
                continue

            self.tree.insert("", "end", values=self._artifact_to_row(a))

    # ---------------------------------------------------------
    # Деталі
    # ---------------------------------------------------------
    def _on_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return

        values = self.tree.item(sel[0], "values")
        # Шукаємо артефакт по time+type+url+payload
        time_v, type_v, module_v, url_v, payload_v, *_ = values

        found = None
        for a in self.attacks:
            if (
                (a.get("ts") == time_v or a.get("time") == time_v)
                and a.get("type") == type_v
                and a.get("url") == url_v
                and a.get("payload") == payload_v
            ):
                found = a
                break

        self.details_text.delete("1.0", "end")
        if not found:
            self.details_text.insert("end", "Артефакт не знайдено.\n")
            return

        pretty = self._format_details(found)
        self.details_text.insert("end", pretty)

    def _format_details(self, a: Dict[str, Any]) -> str:
        lines = []
        lines.append(f"Type: {a.get('type')}")
        lines.append(f"Module: {a.get('module')}")
        lines.append(f"URL: {a.get('url')}")
        lines.append(f"Payload: {a.get('payload')}")
        lines.append(f"Risk: {a.get('risk', a.get('severity'))}")
        lines.append(f"Status: {a.get('status', a.get('http_status'))}")
        lines.append("")

        # Спеціальні прапорці
        if a.get("env_exposed"):
            lines.append("⚠ ENV exposed: true")
        if a.get("passwd_exposed"):
            lines.append("⚠ /etc/passwd exposed: true")
        if a.get("redirected_to_local"):
            lines.append("⚠ Redirected to local/internal host")
        if a.get("body_hit"):
            lines.append("⚠ Body hit: true")
        if a.get("header_hit"):
            lines.append("⚠ Header hit: true")

        lines.append("")
        raw = a.get("body_snippet") or a.get("raw") or ""
        if raw:
            lines.append("Body snippet / raw:")
            lines.append(raw[:1000])

        suggestions = a.get("suggestions") or []
        if suggestions:
            lines.append("")
            lines.append("Auto‑Exploit Suggestions:")
            for s in suggestions:
                lines.append(f" • {s}")

        return "\n".join(lines)

    # ---------------------------------------------------------
    # Destroy
    # ---------------------------------------------------------
    def destroy(self):
        try:
            self.ui.stop()
        except Exception:
            pass
        super().destroy()
