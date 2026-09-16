# xss_security_gui/auto_recon/metrics.py
"""
Metrics — Red Team Telemetry Engine для AutoRecon.
Особенности:
• MITRE-aware метрики
• Threat-aware scoring
• OPSEC-aware анализ
• Корреляция сессий и фаз
• Integrity hashing
• Аномалия-трейсинг
• Multi-channel вывод (ops / perf / vuln / intel)
"""

import json
import time
import datetime
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, List
from enum import Enum
from collections import defaultdict
import threading

from xss_security_gui.settings import LOG_DIR
from xss_security_gui.auto_recon.user_tracker import get_user_context


class MetricChannel(Enum):
    OPS = "ops"
    PERF = "perf"
    VULN = "vuln"
    INTEL = "intel"
    ANOMALY = "anomaly"


class MetricType(Enum):
    DURATION = "duration"
    COUNT = "count"
    RATE = "rate"
    PERCENTAGE = "percentage"
    SUCCESS_RATE = "success_rate"
    ERROR_RATE = "error_rate"


class OperationMetrics:
    """Метрика одной операции (Red Team-aware)."""

    def __init__(self, operation_name: str, start_time: Optional[float] = None):
        self.operation_name = operation_name
        self.start_time = start_time or time.time()
        self.end_time: Optional[float] = None
        self.duration: Optional[float] = None

        self.success_count = 0
        self.error_count = 0
        self.total_count = 0
        self.items_processed = 0

        self.tags: Dict[str, Any] = {}

        # Red Team context
        ctx = get_user_context()
        self.session_id = ctx.user.session_id
        self.phase = ctx.current_phase
        self.opsec_mode = ctx.opsec_mode
        self.threat_level = ctx.threat_level

    def finish(self):
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time

    def success(self, items: int = 1):
        self.success_count += 1
        self.total_count += 1
        self.items_processed += items

    def error(self, items: int = 1):
        self.error_count += 1
        self.total_count += 1

    def get_success_rate(self) -> float:
        return (self.success_count / self.total_count * 100) if self.total_count else 0.0

    def get_error_rate(self) -> float:
        return (self.error_count / self.total_count * 100) if self.total_count else 0.0

    def to_dict(self) -> Dict[str, Any]:
        entry = {
            "operation": self.operation_name,
            "start_time": datetime.datetime.fromtimestamp(self.start_time).isoformat(),
            "end_time": datetime.datetime.fromtimestamp(self.end_time).isoformat() if self.end_time else None,
            "duration_seconds": self.duration,
            "success_count": self.success_count,
            "error_count": self.error_count,
            "total_count": self.total_count,
            "items_processed": self.items_processed,
            "success_rate_percent": self.get_success_rate(),
            "error_rate_percent": self.get_error_rate(),
            "throughput_items_per_sec": self.items_processed / self.duration if self.duration else 0,
            "tags": self.tags,

            # Red Team context
            "session_id": self.session_id,
            "phase": self.phase,
            "opsec_mode": self.opsec_mode,
            "threat_level": self.threat_level,
        }

        # Integrity hash
        entry["integrity_hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
        return entry


class MetricsCollector:
    """Red Team Telemetry Collector."""

    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = log_dir or LOG_DIR / "auto_recon" / "metrics"
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.ops_log = self.log_dir / "ops.ndjson"
        self.perf_log = self.log_dir / "perf.ndjson"
        self.vuln_log = self.log_dir / "vuln.ndjson"
        self.intel_log = self.log_dir / "intel.ndjson"
        self.anomaly_log = self.log_dir / "anomaly.ndjson"

        self.metrics: Dict[str, OperationMetrics] = {}
        self.completed_metrics: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    # ==========================
    #  Operation tracking
    # ==========================
    def start_operation(self, operation_name: str, tags: Optional[Dict[str, Any]] = None) -> str:
        op_id = f"{operation_name}_{int(time.time() * 1000)}"
        metric = OperationMetrics(operation_name)

        if tags:
            metric.tags = tags

        with self._lock:
            self.metrics[op_id] = metric

        return op_id

    def finish_operation(self, op_id: str, success: bool = True, items_processed: int = 0) -> Optional[Dict[str, Any]]:
        with self._lock:
            if op_id not in self.metrics:
                return None

            metric = self.metrics.pop(op_id)
            metric.finish()

            if success:
                metric.success(items_processed)
            else:
                metric.error()

            result = metric.to_dict()
            self.completed_metrics.append(result)

            self._write_metric(result, MetricChannel.PERF)

            # Anomaly detection
            if metric.duration and metric.duration > 10:  # long operation
                self._write_metric(
                    {
                        "timestamp": datetime.datetime.utcnow().isoformat(),
                        "event": "anomaly_long_operation",
                        "operation": metric.operation_name,
                        "duration": metric.duration,
                        "session_id": metric.session_id,
                        "phase": metric.phase,
                    },
                    MetricChannel.ANOMALY
                )

            return result

    # ==========================
    #  Vulnerability tracking
    # ==========================
    def record_vulnerability(self, vuln_type: str, target: str, severity: str, details: Optional[Dict[str, Any]] = None):
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "event": "vulnerability",
            "type": vuln_type,
            "target": target,
            "severity": severity,
            "details": details or {},
        }
        self._write_metric(entry, MetricChannel.VULN)

    # ==========================
    #  Intel tracking
    # ==========================
    def record_intel(self, intel_type: str, data: Dict[str, Any]):
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "event": "intel",
            "intel_type": intel_type,
            "data": data,
        }
        self._write_metric(entry, MetricChannel.INTEL)

    # ==========================
    #  Internal writer
    # ==========================
    def _write_metric(self, entry: Dict[str, Any], channel: MetricChannel):
        log_map = {
            MetricChannel.OPS: self.ops_log,
            MetricChannel.PERF: self.perf_log,
            MetricChannel.VULN: self.vuln_log,
            MetricChannel.INTEL: self.intel_log,
            MetricChannel.ANOMALY: self.anomaly_log,
        }

        path = log_map[channel]

        try:
            with self._lock:
                with path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[MetricsCollector] Error writing metric: {e}")

    # ==========================
    #  Summary
    # ==========================
    def get_summary(self) -> Dict[str, Any]:
        total_ops = len(self.completed_metrics)
        successful_ops = sum(1 for m in self.completed_metrics if m["error_count"] == 0)
        failed_ops = total_ops - successful_ops

        total_duration = sum(m.get("duration_seconds", 0) or 0 for m in self.completed_metrics)
        total_items = sum(m.get("items_processed", 0) for m in self.completed_metrics)

        avg_duration = total_duration / total_ops if total_ops else 0
        avg_throughput = total_items / total_duration if total_duration else 0

        return {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "total_operations": total_ops,
            "successful_operations": successful_ops,
            "failed_operations": failed_ops,
            "success_rate_percent": (successful_ops / total_ops * 100) if total_ops else 0,
            "average_duration_seconds": avg_duration,
            "average_throughput_items_per_sec": avg_throughput,
        }


# Глобальный экземпляр
_global_metrics = MetricsCollector()


def get_metrics_collector() -> MetricsCollector:
    return _global_metrics


__all__ = [
    "OperationMetrics",
    "MetricsCollector",
    "MetricType",
    "MetricChannel",
    "get_metrics_collector",
]


