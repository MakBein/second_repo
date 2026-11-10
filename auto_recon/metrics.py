# xss_security_gui/auto_recon/metrics.py
"""In-memory operation metrics for AutoReconOrchestrator."""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Optional


class MetricsCollector:
    def __init__(self) -> None:
        self._ops: Dict[str, Dict[str, Any]] = {}

    def start_operation(self, name: str, meta: Optional[Dict[str, Any]] = None) -> str:
        op_id = uuid.uuid4().hex[:12]
        self._ops[op_id] = {
            "name": name,
            "meta": meta or {},
            "started_at": time.time(),
            "finished_at": None,
            "success": None,
            "items_processed": 0,
        }
        return op_id

    def finish_operation(
        self,
        op_id: str,
        success: bool = True,
        items_processed: int = 0,
    ) -> None:
        rec = self._ops.get(op_id)
        if not rec:
            return
        rec["finished_at"] = time.time()
        rec["success"] = bool(success)
        rec["items_processed"] = int(items_processed)
        rec["duration"] = rec["finished_at"] - rec["started_at"]

    def get_summary(self) -> Dict[str, Any]:
        ops = list(self._ops.values())
        return {
            "operations": len(ops),
            "success": sum(1 for o in ops if o.get("success") is True),
            "failed": sum(1 for o in ops if o.get("success") is False),
            "items_processed": sum(int(o.get("items_processed") or 0) for o in ops),
            "details": ops,
        }


_COLLECTOR: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    global _COLLECTOR
    if _COLLECTOR is None:
        _COLLECTOR = MetricsCollector()
    return _COLLECTOR
