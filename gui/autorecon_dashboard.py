# xss_security_gui/gui/autorecon_dashboard.py
# ============================================================
# AutoReconDashboard 9.0 — heatmap, live, async‑friendly
# ============================================================

from typing import Dict, Any, List, Optional, Callable, Tuple
from collections import Counter, defaultdict

from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


GuiCallback = Callable[[Dict[str, Any]], None]


class AutoReconDashboard:
    """
    AutoRecon Dashboard 9.0
    -----------------------
    • Працює через ThreatConnector (SQLite / Elastic)
    • НЕ викликає load_all() → немає фризів GUI
    • Використовує SQL‑пагінацію (query(limit/offset, filters))
    • Будує:
        - summary
        - by_severity
        - by_module
        - by_target (top N)
        - risk heatmap (module × risk)
    • Має stream‑режим для великих даних
    • Повертає payload для GUI через callback
    """

    def __init__(self, gui_callback: Optional[GuiCallback] = None):
        self.gui_callback = gui_callback
        self.connector = THREAT_CONNECTOR

    # ---------------------------------------------------------
    # Безпечний callback
    # ---------------------------------------------------------
    def _emit(self, key: str, payload: Any) -> None:
        if self.gui_callback:
            try:
                self.gui_callback({key: payload})
            except Exception as e:
                print(f"[AutoReconDashboard 9.0] Ошибка gui_callback: {e}")

    # ---------------------------------------------------------
    # Summary (миттєво, без load_all)
    # ---------------------------------------------------------
    def load_summary(self) -> Dict[str, Any]:
        summary = self.connector.summary()
        self._emit("autorecon_summary", summary)
        return summary

    # ---------------------------------------------------------
    # Пагіноване завантаження (не блокує GUI)
    # ---------------------------------------------------------
    def load_page(
        self,
        limit: int = 500,
        offset: int = 0,
        category: Optional[str] = None,
        risk: Optional[str] = None,
        module: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        items = self.connector.query(
            category=category,
            risk=risk,
            module=module,
            search=search,
            limit=limit,
            offset=offset,
        )
        return items

    # ---------------------------------------------------------
    # Деталі по модулю (SQL‑фільтр)
    # ---------------------------------------------------------
    def get_by_module(self, module: str, limit: int = 500, offset: int = 0) -> List[Dict[str, Any]]:
        items = self.connector.query(module=module, limit=limit, offset=offset)
        self._emit("autorecon_module_details", {"module": module, "items": items})
        return items

    # ---------------------------------------------------------
    # Деталі по severity (через sample)
    # ---------------------------------------------------------
    def get_by_severity(self, severity: str, limit: int = 500, offset: int = 0) -> List[Dict[str, Any]]:
        items = self.connector.query(limit=limit, offset=offset)
        filtered = [a for a in items if (a.get("result") or {}).get("severity") == severity]
        self._emit("autorecon_severity_details", {"severity": severity, "items": filtered})
        return filtered

    # ---------------------------------------------------------
    # Деталі по target (через sample)
    # ---------------------------------------------------------
    def get_by_target(self, target: str, limit: int = 500, offset: int = 0) -> List[Dict[str, Any]]:
        items = self.connector.query(limit=limit, offset=offset)
        filtered = [a for a in items if a.get("target") == target]
        self._emit("autorecon_target_details", {"target": target, "items": filtered})
        return filtered

    # ---------------------------------------------------------
    # Stream‑режим (для великих даних)
    # ---------------------------------------------------------
    def stream_all(self, batch_size: int = 1000):
        offset = 0
        while True:
            batch = self.connector.query(limit=batch_size, offset=offset)
            if not batch:
                break
            yield batch
            offset += batch_size

    # ---------------------------------------------------------
    # Heatmap: module × risk
    # ---------------------------------------------------------
    def _build_risk_heatmap(self, sample: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
        heatmap: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for a in sample:
            mod = a.get("module", "unknown")
            res = a.get("result") or {}
            risk = str(res.get("risk", "unknown")).lower()
            heatmap[mod][risk] += 1

        # Перетворюємо defaultdict → звичайний dict
        return {mod: dict(risks) for mod, risks in heatmap.items()}

    # ---------------------------------------------------------
    # Top targets (за кількістю артефактів)
    # ---------------------------------------------------------
    def _build_top_targets(self, sample: List[Dict[str, Any]], top_n: int = 10) -> List[Tuple[str, int]]:
        counter = Counter()
        for a in sample:
            tgt = a.get("target", "unknown")
            counter[tgt] += 1
        return counter.most_common(top_n)

    # ---------------------------------------------------------
    # Dashboard payload (без load_all, на sample)
    # ---------------------------------------------------------
    def build_dashboard_payload(self, sample_size: int = 5000) -> Dict[str, Any]:
        """
        Створює payload без повного load_all().
        Використовує sample_size для швидкого аналізу.
        """

        summary = self.connector.summary()
        sample = self.connector.query(limit=sample_size, offset=0)

        severities = [
            (a.get("result") or {}).get("severity", "unknown")
            for a in sample
        ]
        by_severity = dict(Counter(severities))

        modules = [
            a.get("module", "unknown")
            for a in sample
        ]
        by_module = dict(Counter(modules))

        heatmap = self._build_risk_heatmap(sample)
        top_targets = self._build_top_targets(sample, top_n=10)

        payload = {
            "summary": summary,
            "sample_size": len(sample),
            "total_artifacts": summary.get("total", 0),
            "by_severity": by_severity,
            "by_module": by_module,
            "risk_heatmap": heatmap,
            "top_targets": top_targets,
        }

        self._emit("autorecon_dashboard", payload)
        return payload

    # ---------------------------------------------------------
    # Live‑update для GUI (можна викликати періодично)
    # ---------------------------------------------------------
    def refresh_live(self, sample_size: int = 2000) -> None:
        payload = self.build_dashboard_payload(sample_size=sample_size)
        self._emit("autorecon_live_update", payload)

