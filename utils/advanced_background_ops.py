# xss_security_gui/utils/advanced_background_ops.py
# ============================================================
# AdvancedBackgroundOps 9.0 — async, safe, throttled, monitored
# ============================================================

import time
import threading
import json
import random
import hashlib
from typing import Callable, Any, Optional, Dict, List, Tuple
from functools import wraps
from collections import defaultdict
from datetime import datetime

from xss_security_gui.utils.thread_worker import get_global_worker


# ============================================================
# CacheEngine 2.0 (TTL + LRU)
# ============================================================

class OperationCache:
    def __init__(self, ttl_seconds: int = 300, max_items: int = 5000):
        self.ttl = ttl_seconds
        self.max_items = max_items
        self.cache: Dict[str, Tuple[Any, float]] = {}
        self._lock = threading.Lock()

    def _purge_if_needed(self):
        if len(self.cache) > self.max_items:
            # LRU purge
            sorted_items = sorted(self.cache.items(), key=lambda x: x[1][1])
            for k, _ in sorted_items[: len(self.cache) // 3]:
                del self.cache[k]

    def get_key(self, func_name: str, args: tuple, kwargs: dict) -> str:
        key_str = f"{func_name}:{str(args)}:{str(sorted(kwargs.items()))}"
        return hashlib.md5(key_str.encode()).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self.cache:
                value, ts = self.cache[key]
                if time.time() - ts < self.ttl:
                    return value
                del self.cache[key]
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self.cache[key] = (value, time.time())
            self._purge_if_needed()

    def clear(self):
        with self._lock:
            self.cache.clear()


# ============================================================
# CircuitBreaker 2.0
# ============================================================

class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, timeout_seconds: int = 60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout_seconds
        self.failures = 0
        self.last_failure_time = None
        self.state = "closed"
        self._lock = threading.Lock()

    def is_open(self) -> bool:
        with self._lock:
            if self.state == "open":
                if time.time() - self.last_failure_time > self.timeout:
                    self.state = "half-open"
                    return False
                return True
            return False

    def record_failure(self):
        with self._lock:
            self.failures += 1
            self.last_failure_time = time.time()
            if self.failures >= self.failure_threshold:
                self.state = "open"

    def record_success(self):
        with self._lock:
            self.failures = 0
            self.state = "closed"


# ============================================================
# MetricsEngine 2.0
# ============================================================

class OperationMetrics:
    def __init__(self):
        self.metrics: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "total": 0,
            "successful": 0,
            "failed": 0,
            "total_time": 0.0,
            "avg_time": 0.0,
            "p95": 0.0,
            "p99": 0.0,
            "errors": [],
            "durations": [],
        })
        self._lock = threading.Lock()

    def record_operation(self, name: str, success: bool, duration: float, error: Optional[Exception] = None):
        with self._lock:
            m = self.metrics[name]
            m["total"] += 1
            m["total_time"] += duration
            m["durations"].append(duration)
            m["avg_time"] = m["total_time"] / m["total"]

            # percentiles
            ds = sorted(m["durations"])
            if ds:
                m["p95"] = ds[int(len(ds) * 0.95)]
                m["p99"] = ds[int(len(ds) * 0.99)]

            if success:
                m["successful"] += 1
            else:
                m["failed"] += 1
                if error:
                    m["errors"].append({
                        "time": datetime.now().isoformat(),
                        "error": str(error)
                    })

    def get_metrics(self, name: str) -> Dict[str, Any]:
        with self._lock:
            return self.metrics.get(name, {})

    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return dict(self.metrics)


_cache = OperationCache()
_circuit_breaker = CircuitBreaker()
_metrics = OperationMetrics()


# ============================================================
# RetryEngine 2.0 (backoff + jitter)
# ============================================================

def retry_with_backoff(max_retries: int = 3, base_delay: float = 1.0, backoff_factor: float = 2.0):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            delay = base_delay
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise
                    jitter = random.uniform(0, 0.3)
                    print(f"[⚠ RETRY] {func.__name__} attempt {attempt+1}/{max_retries}, waiting {delay+jitter:.2f}s")
                    time.sleep(delay + jitter)
                    delay *= backoff_factor
        return wrapper
    return decorator


# ============================================================
# RateLimitEngine 2.0 (token bucket)
# ============================================================

def with_rate_limit(ops_per_sec: float = 10.0):
    bucket = {"tokens": ops_per_sec, "last": time.time()}
    interval = 1.0

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            elapsed = now - bucket["last"]
            bucket["last"] = now

            bucket["tokens"] = min(ops_per_sec, bucket["tokens"] + elapsed * ops_per_sec)

            if bucket["tokens"] < 1:
                sleep_time = (1 - bucket["tokens"]) / ops_per_sec
                time.sleep(sleep_time)
                bucket["tokens"] = 0

            bucket["tokens"] -= 1
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ============================================================
# CircuitBreaker wrapper
# ============================================================

def with_circuit_breaker(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if _circuit_breaker.is_open():
            raise RuntimeError(f"Circuit breaker OPEN for {func.__name__}")

        try:
            result = func(*args, **kwargs)
            _circuit_breaker.record_success()
            return result
        except Exception as e:
            _circuit_breaker.record_failure()
            raise
    return wrapper


# ============================================================
# CachedOperation
# ============================================================

def cached_operation(ttl_seconds: int = 300):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = _cache.get_key(func.__name__, args, kwargs)
            cached = _cache.get(key)
            if cached is not None:
                print(f"[💾 CACHE] Using cached result for {func.__name__}")
                return cached

            result = func(*args, **kwargs)
            _cache.set(key, result)
            return result
        return wrapper
    return decorator


# ============================================================
# BatchEngine 2.0
# ============================================================

def run_batched_operation(
    items: List[Any],
    batch_size: int,
    processor: Callable[[List[Any]], Any],
    operation_name: str = "BatchOp",
    on_batch_complete: Optional[Callable[[int, Any], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
) -> Optional[threading.Thread]:

    worker = get_global_worker()
    if not worker:
        return None

    def batch_work(progress_fn, is_cancelled_fn):
        results = []
        total = len(items)

        for idx in range(0, total, batch_size):
            if is_cancelled_fn():
                break

            batch = items[idx: idx + batch_size]

            try:
                result = processor(batch)
                results.append(result)

                if on_batch_complete:
                    on_batch_complete(idx // batch_size + 1, result)

                progress = int(100 * (idx + len(batch)) / total)
                progress_fn(progress)

            except Exception as e:
                print(f"[❌ {operation_name}] Batch error: {e}")
                if on_error:
                    on_error(e)

        return results

    return worker.run_async(batch_work, name=operation_name, on_progress=None)


# ============================================================
# MonitoredOperation
# ============================================================

def run_monitored_operation(
    operation: Callable[[], Any],
    operation_name: str = "MonitoredOp",
    on_success: Optional[Callable[[Any], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
) -> Optional[threading.Thread]:

    worker = get_global_worker()
    if not worker:
        return None

    def monitored_work(progress_fn, is_cancelled_fn):
        start = time.time()
        try:
            result = operation()
            duration = time.time() - start
            _metrics.record_operation(operation_name, True, duration)

            if on_success:
                on_success(result)

            return result

        except Exception as e:
            duration = time.time() - start
            _metrics.record_operation(operation_name, False, duration, e)

            if on_error:
                on_error(e)

            raise

    return worker.run_async(monitored_work, name=operation_name)


# ============================================================
# Stats API
# ============================================================

def get_operation_stats(operation_name: str) -> Dict[str, Any]:
    return _metrics.get_metrics(operation_name)


def get_all_stats() -> Dict[str, Dict[str, Any]]:
    return _metrics.get_all_metrics()


def print_stats():
    stats = get_all_stats()
    if not stats:
        print("Статистика: НЕМАЄ ОПЕРАЦІЙ")
        return

    print("\n" + "=" * 70)
    print("📊 СТАТИСТИКА ОПЕРАЦІЙ")
    print("=" * 70)

    for op_name, m in stats.items():
        print(f"\n📌 {op_name}:")
        print(f"   Всього: {m['total']}")
        print(f"   Успішних: {m['successful']} ✅")
        print(f"   Помилок: {m['failed']} ❌")
        print(f"   Середній час: {m['avg_time']:.2f}s")
        print(f"   p95: {m['p95']:.2f}s")
        print(f"   p99: {m['p99']:.2f}s")

        if m["errors"]:
            print("   Останні помилки:")
            for err in m["errors"][-3:]:
                print(f"     - {err['time']}: {err['error']}")

    print("\n" + "=" * 70 + "\n")


def clear_cache():
    _cache.clear()
    print("[🧹] Кеш очищений")


# Aliases
batch_operation = run_batched_operation
monitor_op = run_monitored_operation
stats = get_all_stats
print_stats = print_stats

