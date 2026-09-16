# xss_security_gui/utils/aggressive_fuzz_engine.py
# ============================================================
# AggressiveFuzzEngine 9.0 — async, throttled, monitored, safe
# ============================================================

import concurrent.futures
import time
import threading
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
import requests

from xss_security_gui.utils.advanced_background_ops import (
    CircuitBreaker,
    OperationMetrics,
    retry_with_backoff,
    with_rate_limit,
)


@dataclass
class FuzzConfig:
    """Конфіг для агресивного фуззингу."""
    max_workers: int = 40
    timeout: float = 8.0
    max_retries: int = 3
    retry_backoff: float = 1.5
    rate_limit: float = 80.0
    batch_size: int = 100
    max_rps: float = 120.0
    aggressive_mode: bool = True


class AggressiveFuzzer:
    """Боєва версія фуззера для форм — ULTRA 9.0."""

    def __init__(self, config: FuzzConfig = None):
        self.config = config or FuzzConfig()
        self.circuit_breaker = CircuitBreaker(failure_threshold=12, timeout_seconds=25)
        self.metrics = OperationMetrics()
        self._lock = threading.Lock()

        self.active_requests = 0
        self.total_requests = 0
        self.total_errors = 0

    # ============================================================
    # Core request engine (retry + rate-limit + circuit-breaker)
    # ============================================================
    @retry_with_backoff(max_retries=3, base_delay=0.4, backoff_factor=2.0)
    @with_rate_limit(ops_per_sec=100)
    def _send_request(
        self,
        session: requests.Session,
        method: str,
        url: str,
        payload: str,
        form_data: Dict[str, Any],
        timeout: float,
    ) -> Dict[str, Any]:

        if self.circuit_breaker.is_open():
            raise RuntimeError("Circuit breaker відкритий — фуззинг призупинено")

        with self._lock:
            self.active_requests += 1
            self.total_requests += 1

        try:
            mutated = self._mutate_form(form_data, payload)

            start_time = time.time()

            if method == "POST":
                response = session.post(url, data=mutated, timeout=timeout)
            else:
                response = session.get(url, params=mutated, timeout=timeout)

            duration = time.time() - start_time
            reflected = payload.lower() in response.text.lower()

            self.metrics.record_operation("fuzz_request", True, duration)
            self.circuit_breaker.record_success()

            return {
                "url": url,
                "payload": payload,
                "status": response.status_code,
                "reflected": reflected,
                "response_length": len(response.text),
                "duration": duration,
                "method": method,
            }

        except Exception as e:
            duration = time.time() - start_time
            self.metrics.record_operation("fuzz_request", False, duration, e)
            self.circuit_breaker.record_failure()
            self.total_errors += 1
            raise

        finally:
            with self._lock:
                self.active_requests -= 1

    # ============================================================
    # MutationEngine 2.0
    # ============================================================
    def _mutate_form(self, form_data: Dict[str, Any], payload: str) -> Dict[str, Any]:
        mutated = form_data.copy()
        keys = list(mutated.keys())[:5]

        for key in keys:
            mutated[key] = payload

        return mutated

    # ============================================================
    # Aggressive fuzzing pipeline
    # ============================================================
    def fuzz_forms_aggressive(
        self,
        forms: List[Dict[str, Any]],
        payloads: List[str],
        on_result: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> List[Dict[str, Any]]:

        results = []
        total_tasks = len(forms) * len(payloads)
        completed = 0

        print(f"[🔥 AGGRESSIVE FUZZER 9.0] {len(forms)} форм × {len(payloads)} payload-ів")

        session = self._build_session()

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                futures = []

                for form in forms:
                    url = form.get("url")
                    data = form.get("data", {})
                    method = form.get("method", "GET").upper()

                    if not url:
                        continue

                    for payload in payloads:
                        futures.append(
                            executor.submit(
                                self._send_request,
                                session,
                                method,
                                url,
                                payload,
                                data,
                                self.config.timeout,
                            )
                        )

                for future in concurrent.futures.as_completed(futures, timeout=300):
                    try:
                        result = future.result()
                        results.append(result)

                        if on_result:
                            on_result(result)

                        completed += 1
                        if on_progress:
                            on_progress(completed, total_tasks)

                        if result["reflected"]:
                            print(f"[⚠️ REFLECTED] {result['url']} → {result['payload']}")

                        if completed % 50 == 0:
                            print(f"[📊] {completed}/{total_tasks} ({100*completed//total_tasks}%)")

                    except Exception as e:
                        print(f"[❌ ERROR] {e}")
                        completed += 1

        finally:
            session.close()

        self._print_final_stats(results)
        return results

    # ============================================================
    # Session builder
    # ============================================================
    def _build_session(self) -> requests.Session:
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            max_retries=self.config.max_retries,
            pool_connections=self.config.max_workers,
            pool_maxsize=self.config.max_workers,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    # ============================================================
    # Final stats
    # ============================================================
    def _print_final_stats(self, results: List[Dict[str, Any]]):
        stats = self.metrics.get_metrics("fuzz_request")

        print("\n[✅ FUZZING COMPLETE 9.0]")
        print(f"   Всього запитів: {self.total_requests}")
        print(f"   Успішних: {stats['successful']}")
        print(f"   Помилок: {self.total_errors}")
        print(f"   Reflected: {sum(1 for r in results if r.get('reflected'))}")
        print(f"   Avg time: {stats['avg_time']:.3f}s")
        print(f"   p95: {stats['p95']:.3f}s")
        print(f"   p99: {stats['p99']:.3f}s\n")

    # ============================================================
    # Stats API
    # ============================================================
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "active_requests": self.active_requests,
            "total_errors": self.total_errors,
            "error_rate": (self.total_errors / max(1, self.total_requests)) * 100,
            "circuit_breaker_state": self.circuit_breaker.state,
            "metrics": self.metrics.get_metrics("fuzz_request"),
        }


from typing import cast

# ============================================================
# Global fuzzer
# ============================================================

_global_fuzzer: AggressiveFuzzer | None = None


def get_fuzzer() -> AggressiveFuzzer:
    """Отримати глобальний фуззер (гарантовано AggressiveFuzzer)."""
    global _global_fuzzer
    if _global_fuzzer is None:
        _global_fuzzer = AggressiveFuzzer()
    return cast(AggressiveFuzzer, _global_fuzzer)


def reset_fuzzer():
    global _global_fuzzer
    _global_fuzzer = None


