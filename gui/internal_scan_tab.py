# xss_security_gui/gui/internal_scan_tab.py
# ============================================================
# InternalScanTab 11.3 — async, paginated, heatmap, Internal Attack Chains 3.0
# ============================================================

import json
import ipaddress
import tkinter as tk
from tkinter import ttk, filedialog
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import List, Dict, Any

from xss_security_gui.threat_analysis.ssrf_module import SSRFTester
from xss_security_gui.threat_analysis.internal_hosts_tab import InternalHostsTab
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


class InternalScanTab(ttk.Frame):
    """
    Internal Scan Tab 11.3 — Enterprise Recon Panel
    ----------------------------------------------
    • Multi-host scanning (thread pool, safe UI updates)
    • CIDR → список хостів (IPv4/IPv6)
    • Пагінація результатів (не завалює Treeview)
    • Heatmap + risk‑score 2.0
    • Internal Attack Chains 3.0 (SSRF → Internal → RCE / Admin / DB)
    • Graphviz-ready export (nodes + edges)
    • Інтеграція з Threat Intel (auto-tagging + normalized artifacts + chains)
    • Таблиця + лог + статус (без падінь і зависань)
    • Повністю сумісно з ThreatEngine 12.0 / LiveAttackMonitor 11.0
    """

    def __init__(self, parent):
        super().__init__(parent)

        self.executor = ThreadPoolExecutor(max_workers=20)
        self.running = False
        self.results: List[Dict[str, Any]] = []
        self.total_hosts = 0
        self.completed_hosts = 0

        self._bridge = UIQueueBridge(self, poll_ms=50)

        self._build_ui()

    # ============================================================
    # UI
    # ============================================================
    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill="x", pady=5)

        ttk.Label(top, text="Hosts / CIDR (через кому або з нового рядка):").grid(row=0, column=0, sticky="w", padx=5)

        self.host_var = tk.Text(top, height=3, width=50)
        self.host_var.grid(row=0, column=1, padx=5)

        self.btn_start = ttk.Button(top, text="Start Scan", command=self.start_scan)
        self.btn_start.grid(row=0, column=2, padx=5)

        self.btn_stop = ttk.Button(top, text="Stop", command=self.stop_scan, state="disabled")
        self.btn_stop.grid(row=0, column=3, padx=5)

        ttk.Button(top, text="Save JSON", command=self.save_results_json).grid(row=0, column=4, padx=5)
        ttk.Button(top, text="Export Graph Data", command=self.export_graph_data).grid(row=0, column=5, padx=5)
        ttk.Button(top, text="Analyze Results", command=self.analyze_results).grid(row=0, column=6, padx=5)
        ttk.Button(top, text="Attack Chains 3.0", command=self.show_attack_chains).grid(row=0, column=7, padx=5)

        # Пагінація
        ttk.Label(top, text="Page size:").grid(row=1, column=0, sticky="w", padx=5)
        self.page_size_var = tk.IntVar(value=200)
        ttk.Entry(top, textvariable=self.page_size_var, width=10).grid(row=1, column=1, sticky="w")

        ttk.Button(top, text="Next Page", command=self.next_page).grid(row=1, column=2, padx=5)
        ttk.Button(top, text="Prev Page", command=self.prev_page).grid(row=1, column=3, padx=5)

        self.current_page = 0

        # Панель
        center = ttk.PanedWindow(self, orient="vertical")
        center.pack(fill="both", expand=True, padx=5, pady=5)

        # Таблиця
        table_frame = ttk.Frame(center)
        self.tree = ttk.Treeview(
            table_frame,
            columns=("host", "ports", "risk", "status", "time"),
            show="headings",
            height=10,
        )

        for col, text in [
            ("host", "Host"),
            ("ports", "Open Ports"),
            ("risk", "Risk Score"),
            ("status", "Status"),
            ("time", "Timestamp"),
        ]:
            self.tree.heading(col, text=text)
            self.tree.column(col, width=180, anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        center.add(table_frame, weight=1)

        # Лог
        log_frame = ttk.Frame(center)
        self.output = tk.Text(log_frame, height=12, bg="black", fg="white", wrap="none")
        log_vsb = ttk.Scrollbar(log_frame, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=log_vsb.set)

        self.output.grid(row=0, column=0, sticky="nsew")
        log_vsb.grid(row=0, column=1, sticky="ns")
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.output.tag_config("HIGH", foreground="lime")
        self.output.tag_config("INFO", foreground="yellow")
        self.output.tag_config("ERROR", foreground="red")
        self.output.tag_config("CHAIN", foreground="cyan")

        center.add(log_frame, weight=1)

        # Статус
        self.status = tk.StringVar(value="Готово")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", padx=5, pady=(0, 5))

    # ============================================================
    # CIDR / Host parsing
    # ============================================================
    def _expand_hosts(self, raw: str) -> List[str]:
        hosts: List[str] = []

        for line in raw.splitlines():
            for part in line.split(","):
                h = part.strip()
                if not h:
                    continue

                try:
                    if "/" in h:
                        net = ipaddress.ip_network(h, strict=False)
                        hosts.extend(str(ip) for ip in net.hosts())
                        continue
                except Exception:
                    pass

                hosts.append(h)

        return list(dict.fromkeys(hosts))

    # ============================================================
    # Logging (UI-safe)
    # ============================================================
    def log(self, text: str, tag: str | None = None) -> None:
        def _do_log():
            self.output.insert("end", text, tag)
            self.output.see("end")

        if self.winfo_exists():
            self._bridge.post_ui(_do_log)

    # ============================================================
    # Scan control
    # ============================================================
    def start_scan(self):
        raw = self.host_var.get("1.0", "end").strip()
        if not raw:
            self.log("⚠️ Введіть хоча б один host або CIDR\n", "ERROR")
            return

        hosts = self._expand_hosts(raw)
        if not hosts:
            self.log("⚠️ Немає валідних хостів\n", "ERROR")
            return

        self.running = True
        self.results.clear()
        self.total_hosts = len(hosts)
        self.completed_hosts = 0
        self.current_page = 0

        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")

        self.tree.delete(*self.tree.get_children())

        self.log(f"🚀 Починаю сканування {len(hosts)} хостів\n", "INFO")
        self.status.set(f"Scanning 0/{self.total_hosts} hosts")

        for host in hosts:
            self.executor.submit(self._scan_worker, host)

    def stop_scan(self):
        self.running = False
        self.btn_stop.configure(state="disabled")
        self.btn_start.configure(state="normal")
        self.status.set("Сканування зупинено")
        self.log("⛔ Сканування зупинено\n", "ERROR")

    # ============================================================
    # Internal Attack Chains 3.0 — детектор
    # ============================================================
    def _detect_internal_chain(self, result: Dict[str, Any]) -> Dict[str, Any] | None:
        """
        Internal Attack Chains 3.0
        --------------------------
        • InternalScan → Admin Service (ports 80/443 + host like 'admin', 'panel')
        • InternalScan → DB Service (ports 5432/3306/1433)
        • InternalScan → RCE Surface (ports 22/3389/5900/8080)
        """
        host = result["host"]
        ports = result["open_ports"]

        if not ports:
            return None

        chain = None
        details = ""
        risk = "medium"

        # Admin surface
        if any(p in (80, 443, 8080) for p in ports) and any(
            kw in host.lower() for kw in ("admin", "panel", "mgr", "cp")
        ):
            chain = "InternalScan → Admin Service"
            details = "Internal admin-like host with web ports open"
            risk = "high"

        # DB surface
        if any(p in (5432, 3306, 1433) for p in ports):
            chain = "InternalScan → DB Service"
            details = "Database ports exposed internally"
            risk = "critical"

        # RCE surface
        if any(p in (22, 3389, 5900) for p in ports):
            chain = "InternalScan → RCE Surface"
            details = "Remote access ports exposed (SSH/RDP/VNC)"
            risk = "critical"

        if not chain:
            return None

        return {
            "type": "CHAIN",
            "chain": chain,
            "risk": risk,
            "url": host,
            "payload": f"ports={ports}",
            "module": "internal_scan_chain",
            "details": details,
            "suggestions": [
                "Спробуй banner‑grabbing для сервісів.",
                "Перевір weak creds / default logins.",
                "Побудуй pivot‑ланцюжок через цей хост.",
            ],
        }

    # ============================================================
    # Worker
    # ============================================================
    def _scan_worker(self, host: str) -> None:
        try:
            tester = SSRFTester(
                base_url="https://example.com",
                param="url",
                base_value="",
                payloads=[],
            )

            ports = tester._scan_internal_ports(host)
            risk_score = len(ports)

            if not self.running:
                return

            result = {
                "host": host,
                "open_ports": ports,
                "risk": risk_score,
                "timestamp": datetime.utcnow().isoformat().replace("+00:00", "Z"),
                "status": "OK" if ports else "No open ports",
            }
            self.results.append(result)

            self._bridge.post_ui(self._update_ui_for_result, result)

            # Internal hosts correlation
            try:
                if ports:
                    InternalHostsTab.add_internal_host_static(host)
            except Exception:
                pass

            # Threat Intel auto-tagging (Pipeline 11.0 normalized)
            try:
                THREAT_CONNECTOR.emit(
                    module="InternalScan",
                    target=host,
                    result={
                        "category": "internal_recon",
                        "risk": "medium" if ports else "low",
                        "ports": ports,
                        "timestamp": result["timestamp"],
                        "type": "internal_scan",
                        "raw": f"ports={ports}",
                    },
                )
            except Exception:
                pass

            # Internal Attack Chains 3.0 → ThreatConnector / LiveAttackMonitor
            try:
                chain = self._detect_internal_chain(result)
                if chain:
                    THREAT_CONNECTOR.emit(
                        module="InternalScanChain",
                        target=host,
                        result=chain,
                    )
                    self.log(
                        f"🧩 CHAIN {chain['chain']} → {host} (risk={chain['risk']})\n",
                        "CHAIN",
                    )
            except Exception:
                pass

        except Exception as e:
            self.log(f"❌ Помилка для {host}: {e}\n", "ERROR")

        finally:
            self.completed_hosts += 1
            if self.running and self.winfo_exists():
                self._bridge.post_ui(
                    lambda: self.status.set(f"Scanning {self.completed_hosts}/{self.total_hosts} hosts")
                )

            if self.completed_hosts == self.total_hosts:
                self.running = False
                if self.winfo_exists():
                    self._bridge.post_ui(self._on_scan_complete)

    # ============================================================
    # UI update
    # ============================================================
    def _update_ui_for_result(self, result: Dict[str, Any]) -> None:
        if not self.winfo_exists():
            return

        host = result["host"]
        ports = result["open_ports"]
        risk = result["risk"]
        ts = result["timestamp"]
        status = result["status"]

        ports_str = ", ".join(str(p) for p in ports) if ports else "-"

        self.tree.insert("", "end", values=(host, ports_str, risk, status, ts))

        if ports:
            self.log(f"🟢 {host}: відкриті порти → {ports_str}\n", "HIGH")
        else:
            self.log(f"🔴 {host}: немає відкритих портів\n", "INFO")

    # ============================================================
    # Pagination
    # ============================================================
    def next_page(self):
        self.current_page += 1
        self._render_page()

    def prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
        self._render_page()

    def _render_page(self):
        page_size = self.page_size_var.get()
        start = self.current_page * page_size
        end = start + page_size

        self.tree.delete(*self.tree.get_children())

        for r in self.results[start:end]:
            ports_str = ", ".join(str(p) for p in r["open_ports"]) if r["open_ports"] else "-"
            self.tree.insert("", "end", values=(r["host"], ports_str, r["risk"], r["status"], r["timestamp"]))

        self.log(f"[📄] Показую сторінку {self.current_page}\n", "INFO")

    # ============================================================
    # Analysis
    # ============================================================
    def analyze_results(self):
        if not self.results:
            self.log("⚠️ Немає результатів для аналізу\n", "ERROR")
            return

        self.log("\n=== 📊 ANALYSIS REPORT ===\n", "INFO")

        groups: Dict[int, List[str]] = {}
        for r in self.results:
            count = len(r["open_ports"])
            groups.setdefault(count, []).append(r["host"])

        for count, hosts in sorted(groups.items()):
            self.log(f"• {count} відкритих портів → {hosts}\n", "INFO")

        self.log("\n=== 🔥 HEATMAP ===\n", "INFO")
        for r in self.results:
            bar = "#" * len(r["open_ports"])
            tag = "HIGH" if bar else "INFO"
            self.log(f"{r['host']}: {bar}\n", tag)

    # ============================================================
    # Attack Chains view
    # ============================================================
    def show_attack_chains(self):
        if not self.results:
            self.log("⚠️ Немає результатів для ланцюжків атак\n", "ERROR")
            return

        self.log("\n=== 🧩 INTERNAL ATTACK CHAINS 3.0 ===\n", "CHAIN")

        for r in self.results:
            chain = self._detect_internal_chain(r)
            if chain:
                self.log(
                    f"{chain['chain']} → {r['host']} (ports={r['open_ports']}, risk={chain['risk']})\n",
                    "CHAIN",
                )

    # ============================================================
    # Graph Export
    # ============================================================
    def export_graph_data(self):
        if not self.results:
            self.log("⚠️ Немає даних для експорту\n", "ERROR")
            return

        graph = {
            "nodes": [],
            "edges": [],
        }

        for r in self.results:
            graph["nodes"].append({
                "id": r["host"],
                "label": r["host"],
                "ports": r["open_ports"],
                "risk": r["risk"],
            })

        self.clipboard_clear()
        self.clipboard_append(json.dumps(graph, indent=4))

        self.log("📋 Graph data скопійовано в буфер\n", "INFO")

    # ============================================================
    # Save JSON
    # ============================================================
    def save_results_json(self):
        if not self.results:
            self.log("⚠️ Немає результатів для збереження\n", "ERROR")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
        )
        if not path:
            return

        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=4)

        self.log(f"💾 JSON збережено: {path}\n", "INFO")

    # ============================================================
    # Cleanup
    # ============================================================
    def destroy(self) -> None:
        try:
            self.running = False
            self.executor.shutdown(wait=False)
            self._bridge.stop()
        except Exception:
            pass
        super().destroy()





