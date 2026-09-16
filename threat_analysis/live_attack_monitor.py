# xss_security_gui/threat_analysis/live_attack_monitor.py
# ============================================================
# AttackStreamProcessor 11.0 — async, correlation, risk‑score, heatmap 2.0
# ============================================================

import datetime
from typing import Dict, Any, List, Optional, Callable
from collections import defaultdict, deque

from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge
from xss_security_gui.utils.threat_sender import register_threat_listener


class AttackStreamProcessor:
    """
    AttackStreamProcessor 11.0
    ----------------------
    • приймає ThreatConnector події
    • будує timeline 2.0
    • будує heatmap 2.0 (module × category × risk)
    • будує attack‑chains (Correlation Engine 2.0)
    • рахує risk‑score (RiskScoreEngine)
    • віддає все в GUI через UIQueueBridge
    """

    def __init__(
        self,
        ui: UIQueueBridge,
        gui_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        max_events: int = 2000,
    ):
        self.ui = ui
        self.gui_callback = gui_callback
        self.max_events = max(200, int(max_events))

        self._events: deque[Dict[str, Any]] = deque(maxlen=self.max_events)

        register_threat_listener(self._on_threat_event)

    # ============================================================
    # Safe emit
    # ============================================================
    def _emit(self, key: str, payload: Any) -> None:
        if not self.gui_callback:
            return
        try:
            self.ui.call_ui(self.gui_callback, {key: payload})
        except Exception as e:
            print(f"[LiveAttackMonitor] gui_callback error: {e}")

    # ============================================================
    # Main event handler
    # ============================================================
    def _on_threat_event(self, artifact: Dict[str, Any]) -> None:
        """Отримує події з ThreatConnector."""
        art = dict(artifact)

        # Нормалізований timestamp для timeline 2.0
        if "_ts" not in art:
            art["_ts"] = datetime.datetime.utcnow().isoformat()

        self._events.append(art)

        # 1) Raw event → GUI
        self._emit("live_attack_event", art)

        # 2) Timeline 2.0
        self._emit("live_attack_timeline", self.build_timeline())

        # 3) Heatmap 2.0
        self._emit("live_attack_heatmap", self.build_cross_module_heatmap())

        # 4) Risk score
        risk_score = self._calculate_risk_score(art)
        self._emit("live_attack_risk_score", {"artifact": art, "risk_score": risk_score})

        # 5) Attack chain detection
        chain = self._detect_attack_chain(art)
        if chain:
            self._emit("live_attack_chain", chain)

            # Forward to Server-Side Dashboard (якщо є)
            try:
                if hasattr(self.ui, "app") and getattr(self.ui.app, "server_side_dashboard", None):
                    self.ui.app.server_side_dashboard.ingest_artifact(chain)
            except Exception as e:
                print("[LiveAttackMonitor] Dashboard chain forward error:", e)

    # ============================================================
    # Risk Score Engine 2.0
    # ============================================================
    def _calculate_risk_score(self, artifact: Dict[str, Any]) -> int:
        """
        RiskScoreEngine 2.0
        -------------------
        • XSS → 3
        • SQLi → 4
        • SSRF → 5
        • LFI → 4
        • RCE → 6
        • ENV leak → 5
        • default → 1
        """

        atype = (artifact.get("type") or "").lower()
        body = (artifact.get("body_snippet") or artifact.get("raw") or "").lower()

        if "rce" in atype or "exec" in body:
            return 6
        if "ssrf" in atype:
            return 5
        if "env" in body or "app_key" in body or "db_password" in body:
            return 5
        if "sqli" in atype or "union select" in body:
            return 4
        if "lfi" in atype:
            return 4
        if "xss" in atype:
            return 3

        return 1

    # ============================================================
    # Correlation Engine 2.0
    # ============================================================
    def _detect_attack_chain(self, artifact: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        AttackChainEngine 2.0
        ---------------------
        • LFI → ENV leak
        • LFI → /etc/passwd
        • SSRF → Cloud Metadata
        • SSRF → Internal Service
        • SQLi → RCE
        • XSS → Admin Panel
        """

        atype = (artifact.get("type") or "").upper()
        url = artifact.get("url") or artifact.get("target")
        payload = artifact.get("payload", "")
        body = (artifact.get("body_snippet") or artifact.get("raw") or "").lower()

        # LFI → ENV leak
        if atype == "LFI" and ("app_key=" in body or "db_password" in body or ".env" in payload):
            return {
                "type": "CHAIN",
                "chain": "LFI → ENV Leak",
                "risk": "critical",
                "url": url,
                "payload": payload,
                "module": "correlation_engine",
                "details": "ENV secrets exposed",
                "suggestions": [
                    "Спробуй витягнути повний .env.",
                    "Перевір креденшіали БД.",
                    "Спробуй JWT forging через APP_KEY.",
                ],
            }

        # LFI → /etc/passwd
        if atype == "LFI" and ("root:x:0:" in body or "/etc/passwd" in payload):
            return {
                "type": "CHAIN",
                "chain": "LFI → /etc/passwd",
                "risk": "high",
                "url": url,
                "payload": payload,
                "details": "System user list exposed",
                "suggestions": [
                    "Спробуй log poisoning → RCE.",
                    "Перевір php://filter.",
                ],
            }

        # SSRF → Cloud Metadata
        if atype == "SSRF" and ("169.254.169.254" in payload or "metadata" in payload):
            return {
                "type": "CHAIN",
                "chain": "SSRF → Cloud Metadata",
                "risk": "critical",
                "url": url,
                "payload": payload,
                "details": "Cloud IAM credentials possible",
                "suggestions": [
                    "Отримай IAM credentials.",
                    "Перевір S3 / Storage доступ.",
                ],
            }

        # SSRF → Internal Service
        if atype == "SSRF" and ("localhost" in payload or "127.0.0.1" in payload):
            return {
                "type": "CHAIN",
                "chain": "SSRF → Internal Service",
                "risk": "high",
                "url": url,
                "payload": payload,
                "details": "Internal service reachable",
                "suggestions": [
                    "Проскануй внутрішні порти.",
                    "Перевір /admin /debug.",
                ],
            }

        # SQLi → RCE
        if atype == "SQLI" and ("xp_cmdshell" in body or "exec(" in body):
            return {
                "type": "CHAIN",
                "chain": "SQLi → RCE",
                "risk": "critical",
                "url": url,
                "payload": payload,
                "details": "SQL injection escalated to RCE",
                "suggestions": [
                    "Спробуй отримати shell.",
                    "Перевір lateral movement.",
                ],
            }

        # XSS → Admin Panel
        if atype == "XSS" and ("admin" in (url or "").lower()):
            return {
                "type": "CHAIN",
                "chain": "XSS → Admin Panel",
                "risk": "high",
                "url": url,
                "payload": payload,
                "details": "XSS inside admin panel",
                "suggestions": [
                    "Спробуй cookie theft.",
                    "Спробуй CSRF → privilege escalation.",
                ],
            }

        return None

    # ============================================================
    # Timeline 2.0
    # ============================================================
    def build_timeline(self, window_minutes: int = 60) -> List[Dict[str, Any]]:
        now = datetime.datetime.utcnow()
        cutoff = now - datetime.timedelta(minutes=window_minutes)

        buckets = defaultdict(int)

        for e in self._events:
            ts_raw = e.get("_ts")
            if not ts_raw:
                continue
            try:
                dt = datetime.datetime.fromisoformat(ts_raw)
            except Exception:
                continue

            if dt < cutoff:
                continue

            bucket = dt.replace(second=0, microsecond=0)
            buckets[bucket] += 1

        return [{"ts": k.isoformat(), "count": v} for k, v in sorted(buckets.items())]

    # ============================================================
    # Heatmap 2.0
    # ============================================================
    def build_cross_module_heatmap(self) -> List[Dict[str, Any]]:
        matrix = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

        for e in self._events:
            module = e.get("module", "unknown")
            category = e.get("category", "unknown")
            risk = (e.get("risk") or "unknown").lower()
            matrix[module][category][risk] += 1

        heatmap: List[Dict[str, Any]] = []
        for module, cats in matrix.items():
            for category, risks in cats.items():
                for risk, count in risks.items():
                    heatmap.append({
                        "module": module,
                        "category": category,
                        "risk": risk,
                        "count": count,
                    })

        # Сортуємо за кількістю, щоб Dashboard показував найгарячіші модулі
        return sorted(heatmap, key=lambda x: x["count"], reverse=True)


