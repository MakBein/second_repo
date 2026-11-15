# xss_security_gui/gui/defense_evasion_lab.py
# ============================================================
# DefenseEvasionLab 9.0 — async, safe, ThreatConnector‑friendly
# ============================================================

import tkinter as tk
from tkinter import ttk
import threading
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple, Callable

from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


class DefenseEvasionLab(ttk.Frame):
    """
    Defense Evasion Lab 9.0
    -----------------------
    • Асинхронний запуск технік
    • Безпечні оновлення GUI через after()
    • Інтеграція з MutatorManager
    • Інтеграція з ThreatConnector (emit)
    • Risk‑aware UI (кольори, теги)
    • Підтримка 10+ технік обходу захистів
    """

    TECHNIQUES: List[Tuple[str, str, str]] = [
        ("WAF Evasion", "waf_evasion", "high"),
        ("Rate Limit Bypass", "rate_limit", "medium"),
        ("CSRF Token Tamper", "csrf_tamper", "high"),
        ("CSP Bypass", "csp_bypass", "critical"),
        ("Unicode Smuggling", "unicode_smuggle", "medium"),
        ("SQLi Filter Bypass", "sqli_bypass", "high"),
        ("SSRF Alias Attack", "ssrf_alias", "critical"),
        ("LFI Normalization Bypass", "lfi_bypass", "high"),
        ("JWT Forgery", "jwt_forge", "critical"),
        ("Anti‑Bot Probe", "bot_probe", "low"),
    ]

    RISK_COLORS: Dict[str, str] = {
        "critical": "#ff4d4f",
        "high": "#ff7a45",
        "medium": "#faad14",
        "low": "#52c41a",
    }

    def __init__(
        self,
        parent: tk.Widget,
        mutator_manager: Optional[Any] = None,
        threat_tab: Optional[Any] = None,
        target_url: str = "http://test.local",
    ) -> None:
        super().__init__(parent)

        self.mutator_manager = mutator_manager
        self.threat_tab = threat_tab
        self.target_url = target_url

        self._build_header()
        self._build_tree()
        self._populate_techniques()
        self._build_controls()
        self._build_log()

    # ============================================================
    # UI BUILDERS
    # ============================================================

    def _build_header(self) -> None:
        ttk.Label(
            self,
            text="🛡️ Defense Evasion Lab 9.0",
            font=("Helvetica", 14, "bold")
        ).pack(pady=10)

    def _build_tree(self) -> None:
        self.tree = ttk.Treeview(
            self,
            columns=("tech", "risk", "status"),
            show="headings",
            height=12,
        )
        self.tree.heading("tech", text="Technique")
        self.tree.heading("risk", text="Risk")
        self.tree.heading("status", text="Status")

        self.tree.column("tech", width=240, anchor="w")
        self.tree.column("risk", width=80, anchor="center")
        self.tree.column("status", width=120, anchor="center")

        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        # стилі для ризику
        style = ttk.Style(self)
        for risk, color in self.RISK_COLORS.items():
            style.configure(f"Risk{risk.capitalize()}.Treeview", foreground=color)

    def _populate_techniques(self) -> None:
        for name, key, risk in self.TECHNIQUES:
            tag = f"risk_{risk}"
            self.tree.insert(
                "",
                "end",
                iid=key,
                values=(name, risk.upper(), "pending"),
                tags=(tag,),
            )
            self.tree.tag_configure(tag, foreground=self.RISK_COLORS[risk])

    def _build_controls(self) -> None:
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="🚀 Запустити всі", command=self.run_all).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🎯 Запустити вибрані", command=self.run_selected).pack(side="left", padx=5)

    def _build_log(self) -> None:
        self.log = tk.Text(
            self,
            height=8,
            bg="#111",
            fg="#0f0",
            insertbackground="#0f0",
        )
        self.log.pack(fill="x", padx=10, pady=10)
        self._log("[🛡️] Defense Evasion Lab 9.0 готовий до запуску…")

    # ============================================================
    # LOGGING
    # ============================================================

    def _log(self, msg: str) -> None:
        self.log.insert("end", f"{msg}\n")
        self.log.see("end")

    # ============================================================
    # PUBLIC ACTIONS
    # ============================================================

    def run_all(self) -> None:
        for _, key, _ in self.TECHNIQUES:
            self._run_technique(key)

    def run_selected(self) -> None:
        selection = self.tree.selection()
        if not selection:
            self._log("[⚠] Не вибрано жодної техніки.")
            return
        for item in selection:
            self._run_technique(item)

    # ============================================================
    # INTERNAL EXECUTION
    # ============================================================

    def _run_technique(self, key: str) -> None:
        if key not in [k for _, k, _ in self.TECHNIQUES]:
            self._log(f"[❌] Невідома техніка: {key}")
            return

        self.tree.set(key, "status", "running")
        self._log(f"[▶] Запуск техніки: {key}…")

        threading.Thread(
            target=self._worker_safe,
            args=(key,),
            daemon=True,
        ).start()

    def _worker_safe(self, key: str) -> None:
        try:
            payload = self._generate_payload(key)
            self._submit_mutator_task(key, payload)
            self._push_to_threat_intel(key, payload)

            self._post_ui(lambda: self._set_status_done(key))
        except Exception as e:
            self._post_ui(lambda: self._set_status_error(key, e))

    def _post_ui(self, func: Callable[[], None]) -> None:
        try:
            self.after(0, func)
        except Exception:
            pass

    def _set_status_done(self, key: str) -> None:
        self.tree.set(key, "status", "done")
        self._log(f"[✓] {key}: завершено успішно.")

    def _set_status_error(self, key: str, e: Exception) -> None:
        self.tree.set(key, "status", "error")
        self._log(f"[❌] {key}: помилка — {e}")

    # ============================================================
    # MUTATOR / THREAT INTEL
    # ============================================================

    def _submit_mutator_task(self, key: str, payload: str) -> None:
        if not self.mutator_manager:
            self._log(f"[⚠] MutatorManager не налаштований, пропускаю {key}.")
            return

        meta = {
            "payload": payload,
            "family": "defense_evasion",
            "risk": "high",
            "tags": [key],
            "generated": 1,
        }

        # ВАЖЛИВО: meta передається як keyword `payload=`, а не позиційно.
        # MutatorTaskManager.submit(fn, *args, payload=..., family=..., risk=...)
        # використовує `payload` для відображення у панелі, а *args віддає у fn.
        # Раніше meta йшла позиційно → self._crawler_attack(url, payload, meta)
        # падало з TypeError (зайвий позиційний аргумент).
        task_id = self.mutator_manager.submit(
            self._crawler_attack,
            self.target_url,
            payload,
            payload=meta,
            family="defense_evasion",
            risk="high",
        )

        self._log(f"[✓] Mutator task submitted: {key} → {payload} (task_id={task_id})")

    def _crawler_attack(self, url: str, payload: str, **kwargs):
        from xss_security_gui.combat_crawler import run_combat_crawl

        return run_combat_crawl(
            url=url,
            payload=payload,
            mode="defense_evasion",
            meta=kwargs.get("payload", {})
        )

    def _push_to_threat_intel(self, key: str, payload: str) -> None:
        """
        DefenseEvasionLab 9.0 → ThreatConnector.emit()
        """
        artifact = {
            "module": "DefenseEvasionLab",
            "target": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "result": {
                "severity": "info",
                "category": "defense_evasion",
                "type": key,
                "payload": payload,
                "tags": ["evasion", key],
            },
        }

        try:
            THREAT_CONNECTOR.emit(
                module="DefenseEvasionLab",
                target=self.target_url,
                result=artifact["result"],
            )
            self._log(f"[📡] Threat Intel оновлено: {key}")
        except Exception as e:
            self._log(f"[⚠] Не вдалося оновити Threat Intel: {e}")

    # ============================================================
    # PAYLOAD GENERATION
    # ============================================================

    def _generate_payload(self, key: str) -> str:
        payloads: Dict[str, str] = {
            "waf_evasion": "<ScRiPt>alert(1)</ScRiPt>",
            "rate_limit": "GET /?burst=1",
            "csrf_tamper": "csrf_token=invalid",
            "csp_bypass": "<svg/onload=alert(1)>",
            "unicode_smuggle": "ja\u2028vascript:alert(1)",
            "sqli_bypass": "' OR SLEEP(1)--",
            "ssrf_alias": "http://127.1/",
            "lfi_bypass": "../../../../../etc/passwd",
            "jwt_forge": "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
            "bot_probe": "User-Agent: curl/7.88",
        }
        if key not in payloads:
            raise ValueError(f"Unknown technique key: {key}")
        return payloads[key]

