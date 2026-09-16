# xss_security_gui/threat_tab_connector.py
# ============================================================
#  ThreatIntelConnector — High-Level API for ThreatConnector 7.0
#  (расширенный поиск + threat-query API)
# ============================================================

from __future__ import annotations
from datetime import datetime, UTC
from typing import Any, Dict, List, Optional, Iterable

from xss_security_gui.threat_analysis.threat_connector import (
    ThreatConnector,
    SQLiteBackend,
)


class ThreatIntelConnector:
    """
    Высокоуровневый адаптер над ThreatConnector 7.0.
    Используется XSSAttacker, AutoRecon, DeepCrawler, Analyzer, GUI.
    """

    def __init__(self, backend: Optional[Any] = None) -> None:
        """
        backend — опциональный DI. Если не передан — создаётся GUI‑friendly SQLite backend.
        """
        backend = backend or SQLiteBackend("threat_intel.db")
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
        """
        Унифицированная отправка события в ThreatConnector.
        ThreatConnector сам:
            • добавляет timestamp
            • добавляет module/target
            • хеширует артефакт
            • выполняет дедупликацию
        """
        result = self._normalize(result)
        result.setdefault("timestamp", datetime.now(UTC).isoformat())

        try:
            self.tc.emit(module, target, result)
        except AttributeError:
            self.tc.add_artifact(module, target, [result])

    # ============================================================
    #  Generic event emitter (GUI → Threat Intel)
    # ============================================================
    def emit(self, module: str, target: str, data: Any) -> None:
        self._send(module, target, data)

    # ============================================================
    #  Bulk event emitter (AutoRecon, массовые результаты)
    # ============================================================
    def bulk(self, module: str, target: str, items: Iterable[Any]) -> None:
        for item in items:
            self._send(module, target, item)

    # ============================================================
    #  Summary generator (GUI → Threat Intel)
    # ============================================================
    def generate_report(self) -> Dict[str, Any]:
        try:
            data = self.tc.export_all()
            return self._normalize(data)
        except Exception:
            return {}

    # ============================================================
    #  Threat‑query API (расширенный поиск + пагинация)
    # ============================================================
    def query(
        self,
        *,
        category: Optional[str] = None,
        risk: Optional[str] = None,
        module: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "timestamp",
        order_desc: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Threat‑query API:
        - category / risk / module — фильтры
        - search — полнотекстовый поиск по JSON‑blob’у
        - limit/offset — пагинация для GUI
        - order_by — поле сортировки (timestamp/risk/module/category)
        """
        try:
            return self.tc.query(
                category=category,
                risk=risk,
                module=module,
                search=search,
                limit=limit,
                offset=offset,
                order_by=order_by,
                order_desc=order_desc,
            )
        except AttributeError:
            # Fallback: экспорт и ручная фильтрация (медленнее, но безопасно)
            data = self.tc.export_all() or {}
            artifacts = data.get("artifacts", []) or []

            def match(a: Dict[str, Any]) -> bool:
                res = a.get("result") or {}
                if category and res.get("category") != category:
                    return False
                if risk and str(res.get("risk", "")).lower() != str(risk).lower():
                    return False
                if module and str(a.get("module", "")).lower() != str(module).lower():
                    return False
                if search:
                    blob = f"{a} {res}".lower()
                    if search.lower() not in blob:
                        return False
                return True

            filtered = [a for a in artifacts if match(a)]

            key_map = {
                "timestamp": lambda x: (x.get("result") or {}).get("timestamp", ""),
                "risk": lambda x: (x.get("result") or {}).get("risk", ""),
                "module": lambda x: x.get("module", ""),
                "category": lambda x: (x.get("result") or {}).get("category", ""),
            }
            key = key_map.get(order_by, key_map["timestamp"])
            filtered.sort(key=key, reverse=order_desc)

            return filtered[offset : offset + limit]

    # ============================================================
    #  Count API (for lazy pagination)
    # ============================================================
    def count(
        self,
        *,
        category: Optional[str] = None,
        risk: Optional[str] = None,
        module: Optional[str] = None,
        search: Optional[str] = None,
    ) -> int:
        """Return total matching artifacts count for pagination."""
        try:
            return self.tc.count(
                category=category,
                risk=risk,
                module=module,
                search=search,
            )
        except (AttributeError, Exception):
            return len(self.query(
                category=category, risk=risk, module=module,
                search=search, limit=999_999_999,
            ))

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
        from xss_security_gui.utils.pii_aggregator import (
            aggregate_pii_from_crawler,
            build_email_leak_artifact,
            pii_has_data,
        )

        target = result.get("root") or result.get("url") or "unknown"
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

        pii = aggregate_pii_from_crawler(result)
        if pii_has_data(pii):
            artifact = build_email_leak_artifact(pii, target_url=str(target), source="crawler")
            if artifact:
                self._send("crawler", target, artifact)

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

    # ============================================================
    #  Shutdown (важно для корректного завершения воркера)
    # ============================================================
    def shutdown(self) -> None:
        try:
            self.tc.shutdown()
        except Exception:
            pass
