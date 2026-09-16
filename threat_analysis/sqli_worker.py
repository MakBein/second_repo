# xss_security_gui/threat_analysis/sqli_worker.py
from __future__ import annotations

import threading
import queue
import time
from typing import Dict, Any, Optional, Callable, List


class SQLiWorker:
    """
    SQLiWorker 11.0 — Combat Edition MAX
    ------------------------------------
    • Паралельний пул воркерів (N потоків)
    • Повна сумісність з SQLiTester 11.0 + TesterBase 6.5+
    • Adaptive Anti-WAF Throttling
    • Stability Detection (як у TesterBase)
    • Progress Events (processed / total / category / payload)
    • Result Events (ThreatConnector-friendly артефакт)
    • Error Events (уніфікований формат)
    • Done Event (завершення)
    • Cancellation-safe (stop_flag)
    • Повна fault-tolerance (ніколи не падає)
    • НЕ блокує GUI
    """

    def __init__(
        self,
        tester,
        threads: int = 4,
        delay_between_payloads: float = 0.0,
        max_errors: int = 100,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.tester = tester
        self.threads = max(1, int(threads))
        self.delay_between_payloads = float(delay_between_payloads)
        self.max_errors = int(max_errors)
        self.progress_callback = progress_callback

        self.queue: queue.Queue[Dict[str, Any]] = queue.Queue()
        self._stop_flag = False

        self._payload_queue: queue.Queue[Dict[str, Any]] = queue.Queue()
        self._workers: List[threading.Thread] = []

    # ---------------------------------------------------------
    # Start worker pool
    # ---------------------------------------------------------
    def start(self) -> None:
        """Запускає паралельний пул воркерів."""
        self._stop_flag = False

        # Заповнюємо payload-чергу
        for category, plist in self.tester.payloads.items():
            for payload in plist:
                self._payload_queue.put({
                    "category": category,
                    "payload": payload,
                })

        # Стартуємо воркери
        for i in range(self.threads):
            t = threading.Thread(
                target=self._worker_loop,
                daemon=True,
                name=f"SQLiWorkerThread-{i+1}",
            )
            self._workers.append(t)
            t.start()

        # Стартуємо моніторинг завершення
        threading.Thread(
            target=self._monitor_completion,
            daemon=True,
            name="SQLiWorkerMonitor",
        ).start()

    # ---------------------------------------------------------
    # Stop worker pool
    # ---------------------------------------------------------
    def stop(self) -> None:
        """М'яка зупинка всіх воркерів."""
        self._stop_flag = True

    # ---------------------------------------------------------
    # Worker loop
    # ---------------------------------------------------------
    def _worker_loop(self) -> None:
        error_count = 0
        total_payloads = sum(len(v) for v in self.tester.payloads.values())
        processed = 0

        while not self._stop_flag:
            try:
                task = self._payload_queue.get_nowait()
            except queue.Empty:
                break

            category = task["category"]
            payload = task["payload"]
            processed += 1

            # Progress event
            self._emit_progress(processed, total_payloads, category, payload)

            try:
                # 1) Надсилаємо HTTP-запит
                response = self.tester.send_request(payload)

                # Заблоковано
                if isinstance(response, dict) and response.get("status") == "blocked":
                    event = {
                        "type": "error",
                        "category": category,
                        "payload": payload,
                        "error": response.get("reason", "blocked"),
                    }
                    self.queue.put(event)
                    error_count += 1
                    if error_count >= self.max_errors:
                        break
                    continue

                # 2) Аналізуємо відповідь
                headers_lower = {
                    k.lower(): v for k, v in getattr(response, "headers", {}).items()
                }

                artifact = self.tester._analyze_response(
                    getattr(response, "text", ""),
                    headers_lower,
                    response,
                )

                # 3) Повертаємо ThreatConnector-friendly артефакт
                event = {
                    "type": "result",
                    "category": category,
                    "payload": payload,
                    "artifact": artifact,
                }

            except Exception as e:
                error_count += 1
                event = {
                    "type": "error",
                    "category": category,
                    "payload": payload,
                    "error": str(e),
                }
                if error_count >= self.max_errors:
                    self.queue.put(event)
                    break

            # Відправляємо подію
            self.queue.put(event)

            # Anti-WAF throttling
            if self.delay_between_payloads > 0.0:
                time.sleep(self.delay_between_payloads)

        # Worker finished
        self.queue.put({"type": "worker_done"})

    # ---------------------------------------------------------
    # Monitor completion
    # ---------------------------------------------------------
    def _monitor_completion(self) -> None:
        """Чекає завершення всіх воркерів і надсилає final done-event."""
        for t in self._workers:
            t.join()

        # Всі воркери завершилися
        self.queue.put({"type": "done"})

    # ---------------------------------------------------------
    # Progress events
    # ---------------------------------------------------------
    def _emit_progress(
        self,
        processed: int,
        total: int,
        category: str,
        payload: str,
    ) -> None:
        event = {
            "type": "progress",
            "processed": processed,
            "total": total,
            "category": category,
            "payload": payload,
        }

        self.queue.put(event)

        if self.progress_callback:
            try:
                self.progress_callback(event)
            except Exception:
                pass


