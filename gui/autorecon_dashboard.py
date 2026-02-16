# xss_security_gui/gui/autorecon_dashboard.py

from typing import Dict, Any, List, Optional

from xss_security_gui.threat_analysis.threat_connector import ThreatConnector


class AutoReconDashboard:
    """
    Логічна вкладка "AutoRecon Dashboard":
    • читає ThreatConnector 2.0 NDJSON-лог
    • показує зведення по модулях
    • дає деталі по вибраному модулю / target / severity
    • готова до інтеграції з будь-яким GUI (через callback)
    """

    def __init__(self, gui_callback=None, log_file: str = "logs/threat_intel.ndjson"):
        self.gui_callback = gui_callback
        self.connector = ThreatConnector(log_file=log_file)

    # -----------------------------
    # Базові дані
    # -----------------------------
    def load_summary(self) -> Dict[str, Any]:
        summary = self.connector.summary()
        if self.gui_callback:
            self.gui_callback({"autorecon_summary": summary})
        return summary

    def load_all(self) -> List[Dict[str, Any]]:
        return self.connector.load_all()

    # -----------------------------
    # Деталі по модулю
    # -----------------------------
    def get_by_module(self, module: str) -> List[Dict[str, Any]]:
        items = self.connector.filter_by_module(module)
        if self.gui_callback:
            self.gui_callback({
                "autorecon_module_details": {
                    "module": module,
                    "items": items
                }
            })
        return items

    # -----------------------------
    # Деталі по severity
    # -----------------------------
    def get_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        items = self.connector.filter_by_severity(severity)
        if self.gui_callback:
            self.gui_callback({
                "autorecon_severity_details": {
                    "severity": severity,
                    "items": items
                }
            })
        return items

    # -----------------------------
    # Деталі по target
    # -----------------------------
    def get_by_target(self, target: str) -> List[Dict[str, Any]]:
        items = self.connector.filter_by_target(target)
        if self.gui_callback:
            self.gui_callback({
                "autorecon_target_details": {
                    "target": target,
                    "items": items
                }
            })
        return items

    # -----------------------------
    # Комплексний payload для GUI
    # -----------------------------
    def build_dashboard_payload(self) -> Dict[str, Any]:
        summary = self.connector.summary()
        all_items = self.connector.load_all()

        by_severity: Dict[str, int] = {}
        for a in all_items:
            sev = a.get("result", {}).get("severity", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        payload = {
            "summary": summary,
            "by_severity": by_severity,
            "total_artifacts": len(all_items),
        }

        if self.gui_callback:
            self.gui_callback({"autorecon_dashboard": payload})

        return payload