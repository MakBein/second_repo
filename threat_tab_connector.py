# xss_security_gui/threat_tab_connector.py
# ============================================================
#  ThreatIntelConnector — High-Level API for ThreatConnector 6.0
# ============================================================

from __future__ import annotations

import hashlib
from datetime import datetime, UTC
from typing import Any, Dict, List

from xss_security_gui.threat_analysis.threat_connector import (
    ThreatConnector,
    SQLiteBackend,
)


class ThreatIntelConnector:
    """
    Высокоуровневый адаптер над ThreatConnector 6.0.
    Используется XSSAttacker, AutoRecon, DeepCrawler, Analyzer, GUI.
    """

    def __init__(self) -> None:
        backend = SQLiteBackend("threat_intel.db")
        self.tc = ThreatConnector(backend=backend)

    # ============================================================
    #  Normalizer — гарантирует, что в Threat Intel всегда идёт dict
    # ============================================================
    def _normalize(self, data: Any) -> Dict[str, Any]:
        if isinstance(data, dict):
            return data
        if isinstance(data, str):
            return {"message": data}
        if isinstance(data, list):
            return {"items": data}
        return {"data": data}

    # ============================================================
    #  Internal unified sender
    # ============================================================
    def _send(self, module: str, target: str, result: Any) -> None:
        result = self._normalize(result)

        raw = f"{module}:{target}:{str(result)}"
        h = hashlib.sha256(raw.encode("utf-8")).hexdigest()

        artifact = {
            "_hash": h,
            "timestamp": datetime.now(UTC).isoformat(),
            "module": module,
            "target": target,
            "result": result,
        }

        # ThreatConnector 6.0 expects: add_artifact(module, target, [artifact])
        self.tc.add_artifact(module, target, [artifact])

    # ============================================================
    #  NEW: Generic event emitter (GUI → Threat Intel)
    # ============================================================
    def emit(self, module: str, target: str, data: Any) -> None:
        self._send(module, target, data)

    # ============================================================
    #  NEW: Bulk event emitter (AutoRecon)
    # ============================================================
    def bulk(self, module: str, target: str, items: List[Any]) -> None:
        for item in items:
            self._send(module, target, item)

    # ============================================================
    #  NEW: Summary generator (GUI → Threat Intel)
    # ============================================================
    def generate_report(self) -> Dict[str, Any]:
        """
        Возвращает агрегированный отчёт Threat Intel.
        """
        try:
            data = self.tc.export_all()
            return self._normalize(data)
        except Exception:
            return {}

    # ============================================================
    #  XSS
    # ============================================================
    def report_xss(self, url: str, payload: str, status: int) -> None:
        self._send(
            "xss",
            url,
            {
                "payload": payload,
                "status": status,
                "severity": "high",
                "category": "xss",
                "source": "engine",
            },
        )

    # ============================================================
    #  SQLi
    # ============================================================
    def report_sqli(self, url: str, payload: str, status: int) -> None:
        self._send(
            "sqli",
            url,
            {
                "payload": payload,
                "status": status,
                "severity": "critical",
                "category": "sqli",
                "source": "engine",
            },
        )

    # ============================================================
    #  CSRF
    # ============================================================
    def report_csrf(self, url: str, token: str) -> None:
        self._send(
            "csrf",
            url,
            {
                "token": token,
                "severity": "medium",
                "category": "csrf",
                "source": "engine",
            },
        )

    # ============================================================
    #  Deep Crawler
    # ============================================================
    def report_crawler(self, result: Dict[str, Any]) -> None:
        target = result.get("root", "unknown")
        self._send(
            "crawler",
            target,
            {
                "summary": result.get("summary", {}),
                "pages": result.get("pages", []),
                "severity": "info",
                "category": "crawler",
                "source": "crawler",
            },
        )

    # ============================================================
    #  AutoRecon
    # ============================================================
    def report_autorecon(self, report: Dict[str, Any]) -> None:
        target = report.get("target", "unknown")
        self._send(
            "autorecon",
            target,
            {
                "report": report,
                "severity": "info",
                "category": "autorecon",
                "source": "engine",
            },
        )

    # ============================================================
    #  Generic summary
    # ============================================================
    def report_summary(self, module: str, target: str, summary: Dict[str, Any]) -> None:
        self._send(
            module,
            target,
            {
                "summary": summary,
                "severity": "info",
                "category": module,
                "source": "gui",
            },
        )