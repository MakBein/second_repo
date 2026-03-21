# xss_security_gui/threat_tab_connector.py
# ============================================================
#  ThreatIntelConnector — High-Level API for ThreatConnector 6.0
# ============================================================

from __future__ import annotations
from datetime import datetime, UTC
from typing import Any, Dict, List, Optional

from xss_security_gui.threat_analysis.threat_connector import (
    ThreatConnector,
    SQLiteBackend,
)


class ThreatIntelConnector:
    """
    Высокоуровневый адаптер над ThreatConnector 6.0.
    Используется XSSAttacker, AutoRecon, DeepCrawler, Analyzer, GUI.
    """

    def __init__(self, backend: Optional[Any] = None) -> None:
        """
        backend — опциональный DI. Если не передан — создаётся SQLite backend.
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

        # Добавляем timestamp на уровне high-level API
        result.setdefault("timestamp", datetime.now(UTC).isoformat())

        try:
            # Современный API ThreatConnector 6.0
            self.tc.emit(module, target, result)
        except AttributeError:
            # Fallback для старых версий
            self.tc.add_artifact(module, target, [result])

    # ============================================================
    #  Generic event emitter (GUI → Threat Intel)
    # ============================================================
    def emit(self, module: str, target: str, data: Any) -> None:
        """
        Универсальный emitter для GUI/модулей.
        Пример:
            tic.emit("gui", "main_window", {"event": "button_click"})
        """
        self._send(module, target, data)

    # ============================================================
    #  Bulk event emitter (AutoRecon, массовые результаты)
    # ============================================================
    def bulk(self, module: str, target: str, items: List[Any]) -> None:
        """
        Массовая отправка событий.
        Каждый элемент отправляется отдельно, чтобы ThreatConnector
        мог корректно дедуплицировать.
        """
        for item in items:
            self._send(module, target, item)

    # ============================================================
    #  Summary generator (GUI → Threat Intel)
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
        """
        Универсальный summary‑репорт для GUI/модулей.
        Пример:
            tic.report_summary("tokens", "session", {"high": 3, "medium": 5})
        """
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
        """
        Корректно завершает ThreatConnector worker thread.
        """
        try:
            self.tc.shutdown()
        except Exception:
            pass