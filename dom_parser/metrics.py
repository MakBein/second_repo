# xss_security_gui/dom_parser/metrics.py
"""
Metrics collection for DOMParser ULTRA 7.0
"""

import logging
import threading
import time
from typing import Dict, Any, List
from dataclasses import dataclass, field, asdict
from collections import defaultdict


@dataclass
class ParseMetrics:
    """Метрики одного парсинга"""
    start_time: float = field(default_factory=time.time)
    end_time: float = None
    html_size: int = 0
    cache_hit: bool = False
    error: str = None
    category_times: Dict[str, float] = field(default_factory=dict)
    
    @property
    def duration(self) -> float:
        """Время выполнения (сек)"""
        if self.end_time is None:
            return None
        return self.end_time - self.start_time

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MetricsCollector:
    """
    Сборщик метрик парсинга.
    Аккумулирует данные и предоставляет статистику.
    """

    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self.metrics: List[ParseMetrics] = []
        self._lock = threading.RLock()
        self.log = logging.getLogger("MetricsCollector")
        
        # Агрегированные метрики
        self.total_parses = 0
        self.total_errors = 0
        self.total_cache_hits = 0
        self.category_stats = defaultdict(lambda: {"count": 0, "total_time": 0})

    def record(self, metrics: ParseMetrics) -> None:
        """Записать метрики парсинга"""
        with self._lock:
            self.metrics.append(metrics)
            
            if len(self.metrics) > self.max_history:
                self.metrics.pop(0)
            
            # Агрегировать
            self.total_parses += 1
            if metrics.error:
                self.total_errors += 1
            if metrics.cache_hit:
                self.total_cache_hits += 1
            
            for category, category_time in metrics.category_times.items():
                self.category_stats[category]["count"] += 1
                self.category_stats[category]["total_time"] += category_time

    def get_summary(self) -> Dict[str, Any]:
        """Получить сводку метрик"""
        with self._lock:
            if self.total_parses == 0:
                return {"total_parses": 0, "error_rate": 0}

            cache_hit_rate = self.total_cache_hits / self.total_parses
            error_rate = self.total_errors / self.total_parses

            # Средние времена по категориям
            category_avg = {}
            for cat, stats in self.category_stats.items():
                if stats["count"] > 0:
                    category_avg[cat] = stats["total_time"] / stats["count"]

            return {
                "total_parses": self.total_parses,
                "total_errors": self.total_errors,
                "total_cache_hits": self.total_cache_hits,
                "cache_hit_rate": cache_hit_rate,
                "error_rate": error_rate,
                "category_avg_times": category_avg,
            }

    def get_recent(self, count: int = 10) -> List[Dict[str, Any]]:
        """Получить последние N метрик"""
        with self._lock:
            recent = self.metrics[-count:]
            return [m.to_dict() for m in recent]

    def reset(self) -> None:
        """Очистить метрики"""
        with self._lock:
            self.metrics.clear()
            self.total_parses = 0
            self.total_errors = 0
            self.total_cache_hits = 0
            self.category_stats.clear()

    def get_performance_rating(self) -> str:
        """Рейтинг производительности: Excellent / Good / Fair / Poor"""
        if self.total_parses == 0:
            return "Unknown"

        summary = self.get_summary()
        error_rate = summary["error_rate"]
        cache_hit_rate = summary["cache_hit_rate"]

        if error_rate > 0.1:
            return "Poor"
        elif error_rate > 0.05:
            return "Fair"
        elif cache_hit_rate < 0.3:
            return "Good"
        else:
            return "Excellent"


class ProgressTracker:
    """
    Трекер прогресса парсинга.
    Используется для обновления UI.
    """

    def __init__(self, callbacks: List[callable] = None):
        self.callbacks = callbacks or []
        self._lock = threading.Lock()
        self.current = 0
        self.total = 0
        self.status = ""
        self.start_time = time.time()

    def set_total(self, total: int) -> None:
        """Установить общее количество"""
        with self._lock:
            self.total = total
            self.current = 0
            self.start_time = time.time()

    def update(self, current: int = None, status: str = None) -> None:
        """Обновить прогресс"""
        with self._lock:
            if current is not None:
                self.current = current
            if status is not None:
                self.status = status

            self._notify()

    def increment(self, count: int = 1) -> None:
        """Увеличить счетчик"""
        with self._lock:
            self.current += count
            self._notify()

    def set_status(self, status: str) -> None:
        """Обновить статус"""
        with self._lock:
            self.status = status
            self._notify()

    def _notify(self) -> None:
        """Уведомить все callbacks"""
        if self.total > 0:
            percentage = (self.current / self.total) * 100
        else:
            percentage = 0

        elapsed = time.time() - self.start_time
        
        progress_data = {
            "current": self.current,
            "total": self.total,
            "percentage": percentage,
            "status": self.status,
            "elapsed": elapsed,
        }

        for callback in self.callbacks:
            try:
                self._dispatch_callback(callback, progress_data)
            except Exception as e:
                logging.error(f"Progress callback failed: {e}")

    def finish(self) -> None:
        """Завершить прогресс"""
        with self._lock:
            self.current = self.total
            self.status = "Complete"
            self._notify()

    @staticmethod
    def _dispatch_callback(callback, payload: Dict[str, Any]) -> None:
        owner = getattr(callback, "__self__", None)
        after = getattr(owner, "after", None)
        if callable(after):
            after(0, lambda p=payload: callback(p))
        else:
            callback(payload)

