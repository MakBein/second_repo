# xss_security_gui/gui/autorecon_dashboard_tab.py

import json
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Callable, Dict, Optional

from xss_security_gui.gui.autorecon_dashboard import AutoReconDashboard
from xss_security_gui.auto_recon.orchestrator import run_full_autorecon, run_aggressive_scan
from xss_security_gui.auto_recon.scope import is_target_authorized, normalize_http_url
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge


class AutoReconDashboardTab(ttk.Frame):
    """
    AutoRecon Dashboard — Red Team control surface.
    Runs AutoReconOrchestrator in a worker thread and streams kill-chain progress.
    """

    def __init__(
        self,
        parent,
        url_var: Optional[tk.StringVar] = None,
        threat_tab=None,
        on_complete: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_email_audit: Optional[Callable[[str], None]] = None,
    ):
        super().__init__(parent)
        self._bridge = UIQueueBridge(self, poll_ms=80)
        self.url_var = url_var
        self.threat_tab = threat_tab
        self.on_complete = on_complete
        self.on_email_audit = on_email_audit
        self._running = False

        self.dashboard = AutoReconDashboard(gui_callback=self.on_dashboard_event)
        self.build_ui()
        self.bind("<Visibility>", lambda e: self.refresh_dashboard())

    def build_ui(self):
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", pady=5)

        ttk.Button(btn_frame, text="🔄 Обновить", command=self.refresh_dashboard).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="📦 Модуль: XSS", command=lambda: self.dashboard.get_by_module("XSS")).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🔥 High Severity", command=lambda: self.dashboard.get_by_severity("high")).pack(side="left", padx=5)

        self.target_var = tk.StringVar()
        if self.url_var is not None:
            try:
                self.target_var.set(self.url_var.get())
            except Exception:
                pass
        ttk.Entry(btn_frame, textvariable=self.target_var, width=40).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🎯 По URL", command=lambda: self.dashboard.get_by_target(self.target_var.get())).pack(side="left", padx=5)

        ttk.Button(btn_frame, text="🚀 Run AutoRecon", command=self.run_autorecon_async).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="⚔️ Aggressive", command=lambda: self.run_autorecon_async(aggressive=True)).pack(side="left", padx=2)
        ttk.Button(
            btn_frame,
            text="📧 Email Exposure Audit",
            command=lambda: self.on_email_audit(self._resolve_target()),
            state="normal" if self.on_email_audit is not None else "disabled",
        ).pack(side="left", padx=4)

        ttk.Button(btn_frame, text="📊 Heatmap", command=self.show_heatmap).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🎯 Top Targets", command=self.show_top_targets).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="⚡ Live Refresh", command=self.live_refresh).pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(self, textvariable=self.status_var).pack(fill="x", padx=8)

        self.output = tk.Text(self, bg="#111", fg="#0f0", height=30)
        self.output.pack(fill="both", expand=True, pady=5)

    def on_dashboard_event(self, data: Dict[str, Any]):
        self._append_output("\n=== AutoRecon Dashboard Update ===\n\n")
        for key, value in data.items():
            self._append_output(f"[{key}]\n{value}\n\n")

    def refresh_dashboard(self):
        self._append_output("\n[🔄] Обновление Dashboard...\n")
        self.dashboard.build_dashboard_payload()

    def show_heatmap(self):
        self._append_output("\n[📊] Генерация Heatmap...\n")
        payload = self.dashboard.build_dashboard_payload()
        self._append_output(f"Heatmap:\n{payload.get('risk_heatmap', {})}\n")

    def show_top_targets(self):
        self._append_output("\n[🎯] Top Targets...\n")
        payload = self.dashboard.build_dashboard_payload()
        self._append_output(f"Top Targets:\n{payload.get('top_targets', [])}\n")

    def live_refresh(self):
        self._append_output("\n[⚡] Live Refresh...\n")
        self.dashboard.refresh_live()

    def _resolve_target(self) -> str:
        target = (self.target_var.get() or "").strip()
        if not target and self.url_var is not None:
            target = (self.url_var.get() or "").strip()
            if target:
                self.target_var.set(target)
        return target

    def run_autorecon_async(self, aggressive: bool = False):
        if self._running:
            self._append_output("\n⚠️ AutoRecon already running.\n")
            return
        raw_target = self._resolve_target()
        if not raw_target:
            self._append_output("\n⚠️ Введите URL перед запуском AutoRecon.\n")
            return
        try:
            target = normalize_http_url(raw_target)
        except ValueError as exc:
            self._append_output(f"\n❌ Некорректная цель: {exc}\n")
            return
        if not is_target_authorized(target):
            self._append_output(
                "\n🚫 Запуск заблокирован: цель отсутствует в "
                "ALLOW_REAL_RUN/ALLOWED_TARGETS.\n"
            )
            return
        mode = "AGGRESSIVE" if aggressive else "STANDARD"
        warning = (
            "Агрессивный профиль использует до 10 workers и 200 активных запросов. "
            if aggressive
            else "Активный режим выполняет ограниченные GET/POST-проверки. "
        )
        if not messagebox.askyesno(
            "Подтверждение AutoRecon",
            f"Разрешенная цель: {target}\n\n{warning}"
            "Всего не более 200 сетевых запросов; просмотрено до 100 страниц, "
            "каждый ответ ограничен 1 MiB. "
            "EndpointScanner проверяет отражение инертным canary-маркером; отдельный "
            "атакующий этап AutoRecon может отправить выбранные XSS-проверочные payloads. "
            "Поля паролей, файлов и секретов исключены из отправки. "
            "Canary-отражение не считается подтвержденной XSS-уязвимостью. "
            "POST может менять состояние приложения. Все запросы ограничены "
            "origin цели; каждый редирект проверяется, внешние origin не проходят.\n\n"
            "Продолжить?",
            parent=self,
        ):
            return

        self._running = True
        self.status_var.set(f"Running ({mode})…")
        self._append_output(f"\n🚀 AutoRecon Orchestrator [{mode}] → {target}\n")

        def _worker():
            def progress(msg: Dict[str, Any]):
                stage = msg.get("stage", "?")
                status = msg.get("status", "")
                details = msg.get("details") or {}
                line = f"[{stage}] {status}"
                if details:
                    line += f" {json.dumps(details, ensure_ascii=False, default=str)[:240]}"
                self._bridge.post_ui(self._append_output, line + "\n")
                self._bridge.post_ui(self.status_var.set, f"{stage} / {status}")

            if aggressive:
                return run_aggressive_scan(
                    target,
                    callback=progress,
                    active_testing=True,
                )
            return run_full_autorecon(
                target,
                config={"active_testing": True},
                callback=progress,
            )

        self._bridge.post_bg(_worker, self._on_orchestrator_done)

    def _on_orchestrator_done(self, result: Any):
        self._running = False
        if isinstance(result, Exception):
            self.status_var.set("Failed")
            self._append_output(f"\n❌ AutoRecon error: {result}\n")
            return

        if not isinstance(result, dict):
            self.status_var.set("Done")
            self._append_output(f"\n✅ AutoRecon finished: {result}\n")
            return

        if result.get("status") == "blocked":
            self.status_var.set("Blocked by target scope")
            self._append_output(f"\n🚫 AutoRecon blocked: {result.get('error')}\n")
            return

        meta = result.get("metadata") or {}
        self.status_var.set(f"Done — risk {meta.get('risk_level', 'n/a')}")
        self._append_output("\n✅ AutoRecon pipeline complete.\n")
        self._append_output(
            f"Risk: {meta.get('risk_level')} (score {meta.get('risk_score')})\n"
            f"Duration: {meta.get('duration_seconds')}\n"
        )
        threat = result.get("threat_summary") or {}
        if threat:
            self._append_output(f"Threat summary:\n{json.dumps(threat, ensure_ascii=False, default=str)[:2000]}\n")

        if self.threat_tab and hasattr(self.threat_tab, "add_threat"):
            try:
                self.threat_tab.add_threat({
                    "module": "AutoReconOrchestrator",
                    "target": (meta.get("targets") or [""])[0],
                    "result": {
                        "category": "auto_recon",
                        "risk": meta.get("risk_level"),
                        "score": meta.get("risk_score"),
                    },
                })
            except Exception:
                pass

        if callable(self.on_complete):
            try:
                self.on_complete(result)
            except Exception:
                pass

        self._append_output("\n🔄 Обновление Dashboard...\n")
        self.refresh_dashboard()

    def _append_output(self, text: str):
        self.output.insert("end", text)
        self.output.see("end")

    def destroy(self):
        try:
            self._bridge.stop()
        except Exception:
            pass
        super().destroy()
