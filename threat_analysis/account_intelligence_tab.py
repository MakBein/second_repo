# xss_security_gui/threat_analysis/account_intelligence_tab.py
import tkinter as tk
from tkinter import ttk
from typing import Any, Dict, List

from xss_security_gui.threat_data_loader import ThreatDataLoader
from xss_security_gui.threat_analysis.account_intel import AccountIntelPipeline


class AccountIntelligenceTab(ttk.Frame):
    """
    Account Intelligence 11.0 — аналітична вкладка акаунтів:
    - використовує AccountIntelPipeline (AccountExtractor 11.0 + AccountAggregator 10.0)
    - агрегує акаунти з усіх артефактів Threat Intel / ThreatConnector
    - показує повний профіль акаунта
    - групує, сортує, підсвічує ризики
    - аналізує домени email (public / corporate / suspicious)
    - корелює домени між собою
    """

    def __init__(self, parent: tk.Widget, threat_connector: Any):
        super().__init__(parent)
        self.threat_connector = threat_connector

        self._accounts: List[Dict[str, Any]] = []
        self._domains: List[Dict[str, Any]] = []
        self._domain_corr: List[Dict[str, Any]] = []

        self._selected_account: Dict[str, Any] = {}

        self._build_ui()
        self.refresh_data()

    # ------------------------------------------------------------
    # UI
    # ------------------------------------------------------------
    def _build_ui(self) -> None:
        # Верхня панель керування
        toolbar = ttk.Frame(self)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.filter_var = tk.StringVar(value="")
        ttk.Label(toolbar, text="Filter (email / username / source / domain):").pack(side=tk.LEFT)
        ttk.Entry(toolbar, textvariable=self.filter_var, width=35).pack(side=tk.LEFT, padx=5)

        ttk.Button(toolbar, text="Apply", command=self.apply_filter).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Reset", command=self.reset_filter).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Refresh", command=self.refresh_data).pack(side=tk.RIGHT, padx=5)

        # Основний спліт: таблиця акаунтів + деталі
        main_pane = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Ліва частина — таблиця акаунтів
        left_frame = ttk.Frame(main_pane)
        main_pane.add(left_frame, weight=3)

        columns = (
            "risk",
            "username",
            "email",
            "phone",
            "credit_card",
            "source",
            "url",
        )

        self.tree = ttk.Treeview(
            left_frame,
            columns=columns,
            show="headings",
            height=20,
        )
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tree.heading("risk", text="Risk")
        self.tree.heading("username", text="Username")
        self.tree.heading("email", text="Email")
        self.tree.heading("phone", text="Phone")
        self.tree.heading("credit_card", text="Card")
        self.tree.heading("source", text="Source")
        self.tree.heading("url", text="URL")

        self.tree.column("risk", width=70, anchor=tk.CENTER)
        self.tree.column("username", width=150, anchor=tk.W)
        self.tree.column("email", width=200, anchor=tk.W)
        self.tree.column("phone", width=130, anchor=tk.W)
        self.tree.column("credit_card", width=170, anchor=tk.W)
        self.tree.column("source", width=150, anchor=tk.W)
        self.tree.column("url", width=280, anchor=tk.W)

        # Risk-based coloring
        self.tree.tag_configure("CRITICAL", foreground="#ff4d4d", font=("TkDefaultFont", 9, "bold"))
        self.tree.tag_configure("HIGH", foreground="#ff9900")
        self.tree.tag_configure("MEDIUM", foreground="#ffd700")
        self.tree.tag_configure("LOW", foreground="#66ccff")
        self.tree.tag_configure("INFO", foreground="#cccccc")

        self.tree.bind("<<TreeviewSelect>>", self._on_account_select)

        # Права частина — деталі акаунта + домени
        right_frame = ttk.Frame(main_pane)
        main_pane.add(right_frame, weight=2)

        # Деталі акаунта
        details_frame = ttk.LabelFrame(right_frame, text="Account Details")
        details_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.details_text = tk.Text(details_frame, height=14, wrap="word")
        self.details_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.details_text.configure(state="disabled")

        # Таблиця доменів email
        domain_frame = ttk.LabelFrame(right_frame, text="Email Domains Intelligence")
        domain_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.domain_tree = ttk.Treeview(
            domain_frame,
            columns=("domain", "count", "risk", "category"),
            show="headings",
            height=8,
        )
        self.domain_tree.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.domain_tree.heading("domain", text="Domain")
        self.domain_tree.heading("count", text="Accounts")
        self.domain_tree.heading("risk", text="Risk")
        self.domain_tree.heading("category", text="Category")

        self.domain_tree.column("domain", width=200, anchor=tk.W)
        self.domain_tree.column("count", width=80, anchor=tk.CENTER)
        self.domain_tree.column("risk", width=100, anchor=tk.CENTER)
        self.domain_tree.column("category", width=140, anchor=tk.CENTER)

        self.domain_tree.tag_configure("CRITICAL", foreground="#ff4d4d", font=("TkDefaultFont", 9, "bold"))
        self.domain_tree.tag_configure("HIGH", foreground="#ff9900")
        self.domain_tree.tag_configure("MEDIUM", foreground="#ffd700")
        self.domain_tree.tag_configure("LOW", foreground="#66ccff")
        self.domain_tree.tag_configure("INFO", foreground="#cccccc")

        # Таблиця кореляцій доменів
        corr_frame = ttk.LabelFrame(self, text="Domain Correlation")
        corr_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.corr_tree = ttk.Treeview(
            corr_frame,
            columns=("domain", "related", "shared", "risk"),
            show="headings",
            height=8,
        )
        self.corr_tree.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.corr_tree.heading("domain", text="Domain")
        self.corr_tree.heading("related", text="Related Domain")
        self.corr_tree.heading("shared", text="Shared Accounts")
        self.corr_tree.heading("risk", text="Risk")

        self.corr_tree.column("domain", width=200, anchor=tk.W)
        self.corr_tree.column("related", width=200, anchor=tk.W)
        self.corr_tree.column("shared", width=120, anchor=tk.CENTER)
        self.corr_tree.column("risk", width=120, anchor=tk.CENTER)

        self.corr_tree.tag_configure("CRITICAL", foreground="#ff4d4d", font=("TkDefaultFont", 9, "bold"))
        self.corr_tree.tag_configure("HIGH", foreground="#ff9900")
        self.corr_tree.tag_configure("MEDIUM", foreground="#ffd700")
        self.corr_tree.tag_configure("LOW", foreground="#66ccff")
        self.corr_tree.tag_configure("INFO", foreground="#cccccc")

        # Стилі для ризиків
        style = ttk.Style(self)
        style.map(
            "Treeview",
            foreground=[
                ("selected", "white"),
            ],
        )

    def _treeview_color_map(self, *_):
        return [("selected", "white")]

    # ------------------------------------------------------------
    # Data loading (Account Intelligence 11.0 pipeline)
    # ------------------------------------------------------------
    def refresh_data(self) -> None:
        """
        Завантажує артефакти з ThreatConnector (якщо доступний) або ThreatDataLoader,
        проганяє AccountIntelPipeline 11.0, аналізує домени і оновлює таблиці.
        """
        artifacts: List[Dict[str, Any]] = []

        if self.threat_connector and hasattr(self.threat_connector, "get_artifacts"):
            try:
                artifacts = self.threat_connector.get_artifacts()
            except Exception:
                artifacts = []
        if not artifacts:
            loader = ThreatDataLoader()
            loader.load()
            artifacts = loader.artifacts

        pipeline = AccountIntelPipeline(artifacts)
        account_artifact = pipeline.build_threat_artifact()

        self._accounts = account_artifact.get("accounts", []) or []
        self._accounts.sort(key=lambda a: a.get("risk", 0), reverse=True)

        self._domains = self._aggregate_domains(self._accounts)
        self._reload_tree(self._accounts)
        self._reload_domain_tree(self._domains)

        self._domain_corr = self._aggregate_domain_correlation(self._accounts)
        self._reload_corr_tree(self._domain_corr)

        self._clear_details()

    def _reload_tree(self, accounts: List[Dict[str, Any]]) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        for acc in accounts:
            risk_score = acc.get("risk", 0)
            risk_label = self._risk_label(risk_score)

            self.tree.insert(
                "",
                tk.END,
                values=(
                    risk_label,
                    acc.get("username") or "",
                    acc.get("email") or "",
                    acc.get("phone") or "",
                    acc.get("credit_card") or "",
                    acc.get("source") or "",
                    acc.get("url") or "",
                ),
            )

    def _risk_label(self, score: int) -> str:
        if score >= 140:
            return "CRITICAL"
        if score >= 90:
            return "HIGH"
        if score >= 45:
            return "MEDIUM"
        if score >= 10:
            return "LOW"
        return "INFO"

    # ------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------
    def apply_filter(self) -> None:
        q = (self.filter_var.get() or "").strip().lower()
        if not q:
            self._reload_tree(self._accounts)
            self._reload_domain_tree(self._domains)
            self._reload_corr_tree(self._domain_corr)
            self._clear_details()
            return

        filtered_accounts = []
        for acc in self._accounts:
            haystack = " ".join(
                str(acc.get(k) or "").lower()
                for k in ("username", "email", "phone", "source", "url")
            )
            if q in haystack:
                filtered_accounts.append(acc)

        filtered_domains = []
        for d in self._domains:
            if q in d["domain"].lower():
                filtered_domains.append(d)

        filtered_corr = []
        for c in self._domain_corr:
            if q in c["domain"].lower() or q in c["related"].lower():
                filtered_corr.append(c)

        self._reload_tree(filtered_accounts)
        self._reload_domain_tree(filtered_domains)
        self._reload_corr_tree(filtered_corr)
        self._clear_details()

    def reset_filter(self) -> None:
        self.filter_var.set("")
        self._reload_tree(self._accounts)
        self._reload_domain_tree(self._domains)
        self._reload_corr_tree(self._domain_corr)
        self._clear_details()

    # ------------------------------------------------------------
    # Domain Intelligence
    # ------------------------------------------------------------
    def _aggregate_domains(self, accounts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        domain_map: Dict[str, Dict[str, Any]] = {}

        for acc in accounts:
            email = acc.get("email")
            if not email or "@" not in email:
                continue

            domain = email.split("@")[1].lower().strip()

            if domain not in domain_map:
                domain_map[domain] = {
                    "domain": domain,
                    "count": 0,
                    "risk": 0,
                    "category": self._domain_category(domain),
                }

            domain_map[domain]["count"] += 1
            domain_map[domain]["risk"] += acc.get("risk", 0)

        domains = list(domain_map.values())
        domains.sort(key=lambda d: d["count"], reverse=True)

        return domains

    def _domain_category(self, domain: str) -> str:
        public_common = {
            "gmail.com",
            "yahoo.com",
            "outlook.com",
            "hotmail.com",
            "live.com",
            "icloud.com",
        }
        ru_cis_public = {
            "yandex.ru",
            "yandex.ua",
            "mail.ru",
            "bk.ru",
            "list.ru",
            "inbox.ru",
            "rambler.ru",
        }
        privacy_focused = {
            "protonmail.com",
            "tutanota.com",
            "cock.li",
            "riseup.net",
        }

        d = domain.lower()

        if d in public_common:
            return "Public (Global)"
        if d in ru_cis_public:
            return "Public (RU/CIS)"
        if d in privacy_focused:
            return "Privacy / Underground"
        if "." in d and not any(d.endswith(x) for x in public_common | ru_cis_public | privacy_focused):
            return "Corporate / Custom"
        return "Unknown"

    def _reload_domain_tree(self, domains: List[Dict[str, Any]]) -> None:
        for item in self.domain_tree.get_children():
            self.domain_tree.delete(item)

        for d in domains:
            risk_label = self._risk_label(d["risk"])
            self.domain_tree.insert(
                "",
                tk.END,
                values=(d["domain"], d["count"], risk_label, d["category"]),
            )

    # ------------------------------------------------------------
    # Account details
    # ------------------------------------------------------------
    def _on_account_select(self, event: Any) -> None:
        sel = self.tree.selection()
        if not sel:
            self._clear_details()
            return

        item_id = sel[0]
        values = self.tree.item(item_id, "values")
        email = values[2] if len(values) > 2 else None

        acc = None
        if email:
            for a in self._accounts:
                if (a.get("email") or "").lower() == str(email).lower():
                    acc = a
                    break

        if not acc:
            self._clear_details()
            return

        self._selected_account = acc
        self._render_details(acc)

    def _clear_details(self) -> None:
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", tk.END)
        self.details_text.configure(state="disabled")

    def _render_details(self, acc: Dict[str, Any]) -> None:
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", tk.END)

        lines = []

        lines.append(f"Risk: {self._risk_label(acc.get('risk', 0))} ({acc.get('risk', 0)})")
        lines.append("")

        lines.append(f"Username: {acc.get('username') or '-'}")
        lines.append(f"Email:    {acc.get('email') or '-'}")
        lines.append(f"Phone:    {acc.get('phone') or '-'}")
        lines.append(f"Address:  {acc.get('address') or '-'}")
        lines.append("")
        lines.append(f"Credit Card: {acc.get('credit_card') or '-'}")
        lines.append(f"CVV:         {acc.get('cvv') or '-'}")
        lines.append(f"Expiry:      {acc.get('expiry') or '-'}")
        lines.append("")
        lines.append(f"Source: {acc.get('source') or '-'}")
        lines.append(f"URL:    {acc.get('url') or '-'}")
        lines.append(f"Artifact Hash: {acc.get('artifact_hash') or '-'}")
        lines.append("")
        lines.append("Raw fields:")
        for k in sorted(acc.keys()):
            if k in {
                "risk", "username", "email", "phone", "address",
                "credit_card", "cvv", "expiry", "source", "url", "artifact_hash"
            }:
                continue
            lines.append(f"  {k}: {acc.get(k)}")

        self.details_text.insert("1.0", "\n".join(lines))
        self.details_text.configure(state="disabled")

    # ------------------------------------------------------------
    # Domain correlation
    # ------------------------------------------------------------
    def _aggregate_domain_correlation(self, accounts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        domain_users: Dict[str, set] = {}

        for acc in accounts:
            email = acc.get("email")
            if not email or "@" not in email:
                continue

            domain = email.split("@")[1].lower().strip()
            username = acc.get("username") or email

            domain_users.setdefault(domain, set()).add(username)

        correlations: List[Dict[str, Any]] = []
        domains = list(domain_users.keys())

        for i in range(len(domains)):
            for j in range(i + 1, len(domains)):
                d1 = domains[i]
                d2 = domains[j]

                shared = domain_users[d1].intersection(domain_users[d2])
                shared_count = len(shared)

                if shared_count == 0:
                    continue

                risk = self._domain_corr_risk(d1, d2, shared_count)

                correlations.append({
                    "domain": d1,
                    "related": d2,
                    "shared": shared_count,
                    "risk": risk,
                })

        correlations.sort(key=lambda c: c["shared"], reverse=True)
        return correlations

    def _domain_corr_risk(self, d1: str, d2: str, shared: int) -> str:
        suspicious = {"protonmail.com", "tutanota.com", "cock.li", "mail.ru", "yandex.ru", "rambler.ru"}
        corporate = lambda d: "." in d and d not in suspicious and d not in {
            "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "icloud.com"
        }

        if (d1 in suspicious and corporate(d2)) or (d2 in suspicious and corporate(d1)):
            return "CRITICAL"

        if d1 in suspicious and d2 in suspicious:
            return "HIGH"

        if (d1 in suspicious or d2 in suspicious) and shared >= 2:
            return "MEDIUM"

        if shared >= 1:
            return "LOW"

        return "INFO"

    def _reload_corr_tree(self, correlations: List[Dict[str, Any]]) -> None:
        for item in self.corr_tree.get_children():
            self.corr_tree.delete(item)

        for c in correlations:
            self.corr_tree.insert(
                "",
                tk.END,
                values=(c["domain"], c["related"], c["shared"], c["risk"]),
            )

