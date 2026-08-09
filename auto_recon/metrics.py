# xss_security_gui/auto_recon/metrics.py
"""
Metrics — сбор и анализ метрик операций AutoRecon.
Функции:
• Время выполнения операций
• Статистика сканирования
• Анализ эффективности
• Генерация метрик в JSON/CSV
"""

import json
import time
import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from enum import Enum
from collections import defaultdict
import threading

from xss_security_gui.settings import LOG_DIR


class MetricType(Enum):
    """Типы метрик."""
    DURATION = "duration"
    COUNT = "count"
    RATE = "rate"
    PERCENTAGE = "percentage"
    SUCCESS_RATE = "success_rate"
    ERROR_RATE = "error_rate"


class OperationMetrics:
    """Метрика одной операции."""

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

    def finish(self):
        """Завершает операцию и расчитывает duration."""
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time

    def success(self, items: int = 1):
        """Регистрирует успешное выполнение."""
        self.success_count += 1
        self.total_count += 1
        self.items_processed += items

    def error(self, items: int = 1):
        """Регистрирует ошибку."""
        self.error_count += 1
        self.total_count += 1

    def get_success_rate(self) -> float:
        """Возвращает процент успеха."""
        if self.total_count == 0:
            return 0.0
        return (self.success_count / self.total_count) * 100

    def get_error_rate(self) -> float:
        """Возвращает процент ошибок."""
        if self.total_count == 0:
            return 0.0
        return (self.error_count / self.total_count) * 100

    def to_dict(self) -> Dict[str, Any]:
        """Преобразует метрику в словарь."""
        return {
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
            "throughput_items_per_sec": self.items_processed / self.duration if self.duration and self.duration > 0 else 0,
            "tags": self.tags,
        }


class MetricsCollector:
    """Центральный сборщик метрик."""

    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = log_dir or LOG_DIR / "auto_recon" / "metrics"
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.metrics_log = self.log_dir / "metrics.ndjson"
        self.summary_log = self.log_dir / "summary.json"

        self.metrics: Dict[str, OperationMetrics] = {}
        self.completed_metrics: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def start_operation(self, operation_name: str, tags: Optional[Dict[str, Any]] = None) -> str:
        """Начинает отслеживание операции. Возвращает ID операции."""
        op_id = f"{operation_name}_{int(time.time() * 1000)}"
        metric = OperationMetrics(operation_name, time.time())

        if tags:
            metric.tags = tags

        with self._lock:
            self.metrics[op_id] = metric

        return op_id

    def finish_operation(
        self,
        op_id: str,
        success: bool = True,
        items_processed: int = 0,
    ) -> Optional[Dict[str, Any]]:
        """Завершает отслеживание операции."""
        with self._lock:
            if op_id not in self.metrics:
                return None

            metric = self.metrics.pop(op_id)
            metric.finish()

            if success:
                metric.success(items_processed)
            else:
                metric.error()

            result_dict = metric.to_dict()
            self.completed_metrics.append(result_dict)

            # Логирование в NDJSON
            self._write_metric_log(result_dict)

            # Trim to prevent memory bloat
            if len(self.completed_metrics) > 10000:
                self.completed_metrics = self.completed_metrics[-5000:]

            return result_dict

    def _write_metric_log(self, metric_dict: Dict[str, Any]):
        """Записывает метрику в лог."""
        try:
            with self.metrics_log.open("a", encoding="utf-8") as f:
                f.write(json.dumps(metric_dict, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[MetricsCollector] Error writing metric log: {e}")

    def record_vulnerability(
        self,
        vuln_type: str,
        target: str,
        severity: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Записывает информацию об уязвимости."""
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "event": "vulnerability",
            "type": vuln_type,
            "target": target,
            "severity": severity,
            "details": details or {},
        }

        with self._lock:
            with self.metrics_log.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def get_summary(self) -> Dict[str, Any]:
        """Генерирует сводку метрик."""
        total_operations = len(self.completed_metrics)
        successful_ops = sum(1 for m in self.completed_metrics if m["error_count"] == 0)
        failed_ops = sum(1 for m in self.completed_metrics if m["error_count"] > 0)

        total_duration = sum(m.get("duration_seconds", 0) or 0 for m in self.completed_metrics)
        total_items = sum(m.get("items_processed", 0) for m in self.completed_metrics)

        avg_duration = total_duration / total_operations if total_operations > 0 else 0
        avg_throughput = total_items / total_duration if total_duration > 0 else 0

        operation_types = defaultdict(lambda: {"count": 0, "success": 0, "duration": 0})

        for metric in self.completed_metrics:
            op_name = metric["operation"]
            operation_types[op_name]["count"] += 1
            if metric["error_count"] == 0:
                operation_types[op_name]["success"] += 1
            operation_types[op_name]["duration"] += metric.get("duration_seconds", 0)

        summary = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "total_operations": total_operations,
            "successful_operations": successful_ops,
            "failed_operations": failed_ops,
            "success_rate_percent": (successful_ops / total_operations * 100) if total_operations > 0 else 0,
            "total_duration_seconds": total_duration,
            "average_duration_seconds": avg_duration,
            "total_items_processed": total_items,
            "average_throughput_items_per_sec": avg_throughput,
            "operation_summary": dict(operation_types),
        }

        return summary

    def save_summary(self) -> Path:
        """Сохраняет итоговую сводку."""
        summary = self.get_summary()

        with self.summary_log.open("w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        return self.summary_log

    def export_metrics_csv(self, filename: Optional[str] = None) -> Path:
        """Экспортирует метрики в CSV."""
        import csv

        filename = filename or "metrics_export.csv"
        path = self.log_dir / filename

        with path.open("w", newline="", encoding="utf-8") as f:
            if self.completed_metrics:
                writer = csv.DictWriter(f, fieldnames=self.completed_metrics[0].keys())
                writer.writeheader()
                writer.writerows(self.completed_metrics)

        return path

    def load_metrics(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Загружает метрики из файла."""
        metrics: List[Dict[str, Any]] = []

        if not self.metrics_log.exists():
            return metrics

        try:
            with self.metrics_log.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            metrics.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass

            return metrics[-limit:]
        except Exception:
            return []


# Глобальный экземпляр
_global_metrics = MetricsCollector()


def get_metrics_collector() -> MetricsCollector:
    """Возвращает глобальный collector метрик."""
    return _global_metrics


__all__ = [
    "OperationMetrics",
    "MetricsCollector",
    "MetricType",
    "get_metrics_collector",
]

