# xss_security_gui/gui/autorecon_dashboard.py

from typing import Dict, Any, List, Optional
from collections import Counter
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


class AutoReconDashboard:
    """
    AutoRecon Dashboard (ULTRA‑6.5)
    --------------------------------
    • Читает глобальный ThreatConnector
    • Строит сводку по модулям, severity и target
    • Возвращает payload для GUI через callback
    """

    def __init__(self, gui_callback: Optional[callable] = None, log_file: str = "logs/threat_intel.ndjson"):
        self.gui_callback = gui_callback
        self.connector = THREAT_CONNECTOR  # единый глобальный объект
        self.log_file = log_file

    # ---------------------------------------------------------
    # Вспомогательный метод для безопасного вызова callback
    # ---------------------------------------------------------
    def _emit(self, key: str, payload: Any) -> None:
        if self.gui_callback:
            try:
                self.gui_callback({key: payload})
            except Exception as e:
                # Логируем, но не ломаем пайплайн
                print(f"[AutoReconDashboard] Ошибка gui_callback: {e}")

    # ---------------------------------------------------------
    # Базовые данные
    # ---------------------------------------------------------
    def load_summary(self) -> Dict[str, Any]:
        summary = self.connector.summary()
        self._emit("autorecon_summary", summary)
        return summary

    def load_all(self) -> List[Dict[str, Any]]:
        return self.connector.load_all()

    # ---------------------------------------------------------
    # Детали по модулю
    # ---------------------------------------------------------
    def get_by_module(self, module: str) -> List[Dict[str, Any]]:
        items = self.connector.filter_by_module(module)
        self._emit("autorecon_module_details", {"module": module, "items": items})
        return items

    # ---------------------------------------------------------
    # Детали по severity
    # ---------------------------------------------------------
    def get_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        items = self.connector.filter_by_severity(severity)
        self._emit("autorecon_severity_details", {"severity": severity, "items": items})
        return items

    # ---------------------------------------------------------
    # Детали по target
    # ---------------------------------------------------------
    def get_by_target(self, target: str) -> List[Dict[str, Any]]:
        items = self.connector.filter_by_target(target)
        self._emit("autorecon_target_details", {"target": target, "items": items})
        return items

    # ---------------------------------------------------------
    # Комплексный payload для GUI
    # ---------------------------------------------------------
    def build_dashboard_payload(self) -> Dict[str, Any]:
        summary = self.connector.summary()
        all_items = self.connector.load_all()

        # Группировка по severity через Counter
        severities = [
            a.get("result", {}).get("severity", "unknown")
            for a in all_items
        ]
        by_severity = dict(Counter(severities))

        payload = {
            "summary": summary,
            "by_severity": by_severity,
            "total_artifacts": len(all_items),
        }

        self._emit("autorecon_dashboard", payload)
        return payload