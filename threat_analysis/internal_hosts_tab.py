# xss_security_gui/threat_analysis/internal_hosts_tab.py
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Dict, List

from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
from xss_security_gui.utils.thread_worker import run_in_thread
from xss_security_gui.utils.safe_call import safe_invoke


class InternalHostsTab(ttk.Frame):
    """
    Internal Host Intelligence 11.0 — Combat Edition
    ------------------------------------------------
    • Показує всі внутрішні хости, знайдені SSRF-модулем
    • Групує за типами (loopback, RFC1918, metadata, Kubernetes, Consul, Docker, Redis)
    • Показує SSRF-chain (redirect → internal)
    • Показує порт‑скан, сервіс‑детекцію, cloud‑fingerprinting
    • Асинхронне оновлення без фризів GUI (ThreadWorker)
    • ThreatConnector-friendly артефакт
    """

    def __init__(self, parent: tk.Widget):
        super().__init__(parent)

        # Верхня панель
        top = ttk.Frame(self)
        top.pack(fill="x", pady=5)

        ttk.Button(top, text="🔄 Оновити", command=self.reload_async).pack(side="left", padx=5)

        # Дерево
        self.tree = ttk.Treeview(
            self,
            columns=("type", "risk", "count"),
            show="tree headings",
        )
        self.tree.heading("#0", text="Host")
        self.tree.heading("type", text="Тип")
        self.tree.heading("risk", text="Risk")
        self.tree.heading("count", text="Попадань")

        self.tree.column("#0", width=350, anchor="w")
        self.tree.column("type", width=200, anchor="w")
        self.tree.column("risk", width=120, anchor="center")
        self.tree.column("count", width=120, anchor="center")

        self.tree.pack(fill="both", expand=True)

        self.reload_async()

    # ---------------------------------------------------------
    # Асинхронне оновлення (ThreadWorker)
    # ---------------------------------------------------------
    def reload_async(self):
        def work_fn(progress, is_cancelled):
            return self._load_data()

        def on_success(result):
            safe_invoke(self._render, result)

        run_in_thread(
            work_fn,
            name="InternalHostsTabReload",
            on_success=on_success,
            on_progress=None,
            on_error=lambda e: None,
            on_finally=None,
        )

    # ---------------------------------------------------------
    # Завантаження даних з ThreatConnector
    # ---------------------------------------------------------
    def _load_data(self) -> List[Dict[str, Any]]:
        try:
            summary = THREAT_CONNECTOR.summary()
        except Exception:
            return []

        entries = summary.get("entries", [])
        hosts: Dict[str, Dict[str, Any]] = {}

        for e in entries:
            if e.get("module") != "SSRF":
                continue

            details = e.get("details") or e
            host = details.get("final_url") or ""
            host_type = self._classify(details)
            risk = self._risk(details)

            if not host_type:
                continue

            if host not in hosts:
                hosts[host] = {
                    "type": host_type,
                    "risk": risk,
                    "count": 0,
                    "ports": details.get("open_ports", []),
                    "services": details.get("services", []),
                    "chain": details.get("ssrf_chain", []),
                }

            hosts[host]["count"] += 1

        return sorted(hosts.items(), key=lambda x: -x[1]["count"])

    # ---------------------------------------------------------
    # Рендер
    # ---------------------------------------------------------
    def _render(self, items: List[Any]):
        self.tree.delete(*self.tree.get_children())

        for host, info in items:
            node = self.tree.insert(
                "",
                "end",
                text=host,
                values=(info["type"], info["risk"], info["count"]),
            )

            # Порти
            for p in info.get("ports", []):
                self.tree.insert(node, "end", text=f"Port {p} open")

            # Сервіси
            for svc in info.get("services", []):
                self.tree.insert(node, "end", text=f"Service: {svc}")

            # SSRF-chain
            chain = info.get("chain", [])
            if chain:
                chain_node = self.tree.insert(node, "end", text="SSRF Chain")
                for step in chain:
                    self.tree.insert(chain_node, "end", text=f"→ {step}")

    # ---------------------------------------------------------
    # Класифікація хоста за типом
    # ---------------------------------------------------------
    def _classify(self, d: Dict[str, Any]) -> str:
        if d.get("cloud_metadata"):
            return f"Cloud Metadata ({d['cloud_metadata']})"

        if d.get("jenkins_console_detected"):
            return "Jenkins Internal"

        if d.get("docker_api_detected"):
            return "Docker API"

        if d.get("redis_service_detected"):
            return "Redis Internal"

        if d.get("kubernetes_api_detected"):
            return "Kubernetes API"

        if d.get("consul_service_detected"):
            return "Consul Internal"

        if d.get("lan_access"):
            return "RFC1918 LAN"

        if d.get("loopback_access"):
            return "Loopback"

        if d.get("redirected_to_internal"):
            return "Internal Redirect"

        if d.get("ssrf_chain"):
            return "SSRF Chain"

        return "Unknown Internal"

    # ---------------------------------------------------------
    # Risk Engine 11.0
    # ---------------------------------------------------------
    def _risk(self, d: Dict[str, Any]) -> str:
        score = 0

        if d.get("cloud_metadata"):
            score += 50
        if d.get("docker_api_detected"):
            score += 40
        if d.get("redis_service_detected"):
            score += 30
        if d.get("kubernetes_api_detected"):
            score += 45
        if d.get("consul_service_detected"):
            score += 35
        if d.get("lan_access"):
            score += 20
        if d.get("loopback_access"):
            score += 10
        if d.get("redirected_to_internal"):
            score += 25
        if d.get("ssrf_chain"):
            score += 30

        if score >= 120:
            return "CRITICAL"
        if score >= 80:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        return "LOW"
