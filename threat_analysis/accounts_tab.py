# xss_security_gui/threat_analysis/accounts_tab.py
from tkinter import ttk
import tkinter as tk
from typing import List, Dict, Any

from xss_security_gui.threat_analysis.account_intel import AccountIntelPipeline


class AccountsTab(ttk.Frame):
    """
    Threat Intel Accounts Tab 11.0
    - працює на Account Intelligence Pipeline 11.0
    - показує всі акаунти, витягнуті AccountExtractor 11.0 + AccountAggregator 10.0
    - підтримує сортування по колонкам
    - підсвічує ризик (low/medium/high)
    - фільтрація по email/username/URL
    - без падінь, навіть якщо ThreatConnector тимчасово порожній/кривий
    """

    def __init__(self, master, threat_intel_connector, **kwargs):
        super().__init__(master, **kwargs)
        self.threat_intel_connector = threat_intel_connector
        self._accounts: List[Dict[str, Any]] = []
        self._build_ui()
        self.refresh()

    # ------------------------------------------------------------
    # UI
    # ------------------------------------------------------------
    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self)
        toolbar.pack(side=tk.TOP, fill=tk.X)

        self.refresh_btn = ttk.Button(toolbar, text="🔄 Refresh Accounts", command=self.refresh)
        self.refresh_btn.pack(side=tk.LEFT, padx=5, pady=5)

        ttk.Label(toolbar, text="Filter:").pack(side=tk.LEFT, padx=(10, 2))
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(toolbar, textvariable=self.filter_var, width=30)
        self.filter_entry.pack(side=tk.LEFT, padx=2)
        self.filter_entry.bind("<Return>", lambda e: self._apply_filter())

        self.info_label = ttk.Label(toolbar, text="Accounts: 0")
        self.info_label.pack(side=tk.LEFT, padx=10)

        columns = (
            "risk",
            "username",
            "email",
            "password",
            "phone",
            "credit_card",
            "source",
            "url",
        )

        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=20)
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        headers = {
            "risk": "Risk",
            "username": "Username",
            "email": "Email",
            "password": "Password",
            "phone": "Phone",
            "credit_card": "Card",
            "source": "Source",
            "url": "URL",
        }

        widths = {
            "risk": 60,
            "username": 140,
            "email": 180,
            "password": 160,
            "phone": 120,
            "credit_card": 150,
            "source": 120,
            "url": 260,
        }

        for col, text in headers.items():
            self.tree.heading(col, text=text, command=lambda c=col: self._sort_by(c, False))
            self.tree.column(col, width=widths.get(col, 120), anchor=tk.W, stretch=True)

        self.tree.tag_configure("low", foreground="#2e7d32")
        self.tree.tag_configure("medium", foreground="#f9a825")
        self.tree.tag_configure("high", foreground="#c62828")

        self._menu = tk.Menu(self, tearoff=0)
        self._menu.add_command(label="Copy username", command=lambda: self._copy_field("username"))
        self._menu.add_command(label="Copy email", command=lambda: self._copy_field("email"))
        self._menu.add_command(label="Copy password", command=lambda: self._copy_field("password"))
        self._menu.add_command(label="Copy URL", command=lambda: self._copy_field("url"))

        self.tree.bind("<Button-3>", self._on_right_click)

    # ------------------------------------------------------------
    # Data loading (Account Intelligence 11.0)
    # ------------------------------------------------------------
    def refresh(self) -> None:
        artifacts: List[Dict[str, Any]] = []

        try:
            if self.threat_intel_connector is not None:
                if hasattr(self.threat_intel_connector, "get_artifacts"):
                    artifacts = self.threat_intel_connector.get_artifacts()
                else:
                    artifacts = self.threat_intel_connector.load_artifacts()
        except Exception:
            artifacts = []

        try:
            pipeline = AccountIntelPipeline(artifacts)
            account_artifact = pipeline.build_threat_artifact()
            self._accounts = account_artifact.get("accounts", []) or []
        except Exception:
            self._accounts = []

        self._render(self._accounts)

    # ------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------
    def _render(self, accounts: List[Dict[str, Any]]) -> None:
        for row in self.tree.get_children():
            self.tree.delete(row)

        for acc in accounts:
            risk = acc.get("risk", 0)
            tag = self._risk_tag(risk)

            self.tree.insert(
                "",
                tk.END,
                values=(
                    risk,
                    acc.get("username") or "",
                    acc.get("email") or "",
                    acc.get("password") or "",
                    acc.get("phone") or "",
                    acc.get("credit_card") or "",
                    acc.get("source") or "",
                    acc.get("url") or "",
                ),
                tags=(tag,),
            )

        self.info_label.config(text=f"Accounts: {len(accounts)}")

    # ------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------
    def _apply_filter(self) -> None:
        q = (self.filter_var.get() or "").strip().lower()
        if not q:
            self._render(self._accounts)
            return

        filtered = []
        for acc in self._accounts:
            haystack = " ".join(
                str(acc.get(k) or "").lower()
                for k in ("username", "email", "url", "source")
            )
            if q in haystack:
                filtered.append(acc)

        self._render(filtered)

    # ------------------------------------------------------------
    # Risk helpers
    # ------------------------------------------------------------
    def _risk_tag(self, risk: int) -> str:
        if risk >= 100:
            return "high"
        if risk >= 50:
            return "medium"
        return "low"

    # ------------------------------------------------------------
    # Sorting
    # ------------------------------------------------------------
    def _sort_by(self, col: str, descending: bool) -> None:
        data = [(self.tree.set(child, col), child) for child in self.tree.get_children("")]

        try:
            data.sort(key=lambda t: int(t[0]), reverse=descending)
        except ValueError:
            data.sort(key=lambda t: t[0], reverse=descending)

        for index, (_, child) in enumerate(data):
            self.tree.move(child, "", index)

        self.tree.heading(col, command=lambda: self._sort_by(col, not descending))

    # ------------------------------------------------------------
    # Context menu handlers
    # ------------------------------------------------------------
    def _on_right_click(self, event) -> None:
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return
        self.tree.selection_set(row_id)
        self._menu.tk_popup(event.x_root, event.y_root)

    def _copy_field(self, field: str) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        item_id = sel[0]
        values = self.tree.item(item_id, "values")
        columns = ["risk", "username", "email", "password", "phone", "credit_card", "source", "url"]
        if field not in columns:
            return
        idx = columns.index(field)
        val = values[idx]
        if not val:
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(val)
        except Exception:
            pass




