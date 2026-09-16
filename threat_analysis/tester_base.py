# xss_security_gui/threat_analysis/tester_base.py
"""
TesterBase 11.0 — Combat Edition
================================
Базовий клас для всіх тестерів (SQLi, XSS, CSRF, SSRF, LFI, RCE).

• Повна сумісність з ThreatConnector 11.0
• Повна сумісність з SQLiTester 11.0 / XSS / CSRF / SSRF / LFI / RCE
• Адаптивний троттлінг (anti‑WAF)
• Stability‑window (детекція однакових відповідей)
• Ретраї, таймаути, User-Agent, проксі, SSL‑verify
• Хуки до/після payload
• Повна fault‑tolerance (ніколи не падає)
• Повна cancellation‑safety
• Повна thread‑safety
• Уніфікований ThreatConnector‑friendly формат результатів
"""

from __future__ import annotations

import threading
import logging
import time
import hashlib
from typing import Dict, Any, List, Optional, Callable

from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
from xss_security_gui.settings import settings


class TesterBase(threading.Thread):
    """Базовий клас для тестерів уразливостей (11.0)."""

    def __init__(
        self,
        module_name: str,
        base_url: str,
        param: str,
        base_value: str,
        payloads: Dict[str, List[str]],
        output_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        super().__init__(daemon=True)

        self.module_name = module_name
        self.base_url = base_url
        self.param = param
        self.base_value = base_value
        self.payloads = payloads
        self.output_callback = output_callback
        self.connector = THREAT_CONNECTOR
        self.results: List[Dict[str, Any]] = []

        # ================================
        # Hybrid Settings 11.0
        # ================================
        self.timeout: int = int(settings.get("http.request_timeout", 7))
        self.max_retries: int = int(settings.get("network.max_retries", 3))
        self.retry_delay: float = float(settings.get("network.retry_delay", 1.0))

        # User-Agent
        self.default_headers: Dict[str, str] = {
            "User-Agent": settings.get("http.default_user_agent", "XSS-Security-GUI/11.0")
        }

        # Logging
        self.logger = logging.getLogger(f"{__name__}.{self.module_name}")
        log_level = settings.get("logging.level", "INFO").upper()
        self.logger.setLevel(getattr(logging, log_level, logging.INFO))

        # Stability / Throttle
        self.last_hashes: List[str] = []
        self.throttle_delay: float = 0.0
        self._stability_window: int = int(settings.get("analysis.stability_window", 10))
        self._throttle_step_up: float = float(settings.get("analysis.throttle_step_up", 0.2))
        self._throttle_step_down: float = float(settings.get("analysis.throttle_step_down", 0.1))
        self._throttle_max: float = float(settings.get("analysis.throttle_max", 2.0))

        # Lifecycle
        self._stop_event = threading.Event()

    # ============================================================
    # Lifecycle
    # ============================================================
    def stop(self) -> None:
        """М'яка зупинка тестера."""
        self.logger.info("[%s] Stop requested", self.module_name)
        self._stop_event.set()

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    # ============================================================
    # Main testing loop
    # ============================================================
    def run(self) -> None:
        total_payloads = sum(len(v) for v in self.payloads.values())
        self.logger.info(
            "[%s] Starting test for %s (payloads=%d)",
            self.module_name,
            self.base_url,
            total_payloads,
        )

        for category, plist in self.payloads.items():
            for payload in plist:
                if self.is_stopped():
                    self.logger.info(
                        "[%s] Aborted by user (category=%s, payload=%r)",
                        self.module_name,
                        category,
                        payload,
                    )
                    self._flush_results()
                    return

                full_value = f"{self.base_value}{payload}"

                # Before hook
                self._before_payload(category, payload, full_value)

                result = self._execute_with_retries(category, payload, full_value)
                if result is not None:
                    self.results.append(result)
                    self._safe_emit(result)

                # After hook
                self._after_payload(category, payload, full_value, result)

        self._flush_results()

    # ============================================================
    # Flush results to ThreatConnector
    # ============================================================
    def _flush_results(self) -> None:
        if not self.results:
            return
        try:
            self.connector.add_artifact(self.module_name, self.base_url, self.results)
            self.logger.info(
                "[%s] %d results sent to ThreatConnector",
                self.module_name,
                len(self.results),
            )
        except Exception as e:
            self.logger.error(
                "[%s] Failed to send artifacts to ThreatConnector: %s",
                self.module_name,
                e,
            )

    # ============================================================
    # Safe GUI callback
    # ============================================================
    def _safe_emit(self, result: Dict[str, Any]) -> None:
        if not self.output_callback:
            return
        try:
            cb = self.output_callback
            owner = getattr(cb, "__self__", None)
            after = getattr(owner, "after", None)
            if callable(after):
                after(0, lambda r=result: cb(r))
            else:
                cb(result)
        except Exception as e:
            self.logger.error(
                "[%s] output_callback error: %s (result=%r)",
                self.module_name,
                e,
                result,
            )

    # ============================================================
    # Retry engine
    # ============================================================
    def _execute_with_retries(
        self,
        category: str,
        payload: str,
        full_value: str,
    ) -> Optional[Dict[str, Any]]:
        last_error: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 1):
            if self.is_stopped():
                return None

            start = time.monotonic()
            try:
                result = self._test_single(category, payload, full_value)
                if result is None:
                    return None

                duration = time.monotonic() - start
                result.setdefault("duration", duration)
                result.setdefault("module", self.module_name)
                result.setdefault("url", self.base_url)
                result.setdefault("param", self.param)
                result.setdefault("payload", payload)
                result.setdefault("category", category)
                result.setdefault("status", "success")

                return result

            except Exception as e:
                last_error = e
                self.logger.error(
                    "[%s] Error payload=%r (attempt %d/%d): %s",
                    self.module_name,
                    payload,
                    attempt,
                    self.max_retries,
                    e,
                )
                if attempt < self.max_retries and not self.is_stopped():
                    time.sleep(self.retry_delay)

        if last_error is not None:
            return self._format_error_result(category, payload, last_error)

        return None

    # ============================================================
    # Single payload test
    # ============================================================
    def _test_single(self, category: str, payload: str, full_value: str) -> Dict[str, Any]:
        self._apply_throttle()

        response = self.send_request(full_value)

        if isinstance(response, dict) and response.get("status") == "blocked":
            return self._format_result(
                category=category,
                payload=payload,
                severity="INFO",
                details={
                    "status": "skipped",
                    "reason": response.get("reason"),
                    "response_length": 0,
                    "http_status": None,
                    "body_hit": False,
                    "header_hit": False,
                },
            )

        text = response.text.lower()
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}

        analysis = self._analyze_response(text, headers_lower, response)

        # Stability detection
        if self._check_stability(response.text):
            analysis["severity"] = "INFO"
            analysis["filtered"] = True
            analysis["note"] = "Server returns identical responses — filter active."
            self.throttle_delay = min(self.throttle_delay + self._throttle_step_up, self._throttle_max)
        else:
            self.throttle_delay = max(self.throttle_delay - self._throttle_step_down, 0.0)

        return self._format_result(
            category=category,
            payload=payload,
            severity=analysis.get("severity", "INFO"),
            details=analysis,
        )

    # ============================================================
    # Throttle + stability
    # ============================================================
    def _apply_throttle(self) -> None:
        if self.throttle_delay > 0:
            time.sleep(self.throttle_delay)

    def _hash_body(self, text: str) -> str:
        return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()

    def _check_stability(self, response_text: str) -> bool:
        h = self._hash_body(response_text)
        self.last_hashes.append(h)
        if len(self.last_hashes) > self._stability_window:
            self.last_hashes.pop(0)
        return len(self.last_hashes) >= 2 and len(set(self.last_hashes)) == 1

    # ============================================================
    # Hooks
    # ============================================================
    def _before_payload(self, category: str, payload: str, full_value: str) -> None:
        pass

    def _after_payload(
        self,
        category: str,
        payload: str,
        full_value: str,
        result: Optional[Dict[str, Any]],
    ) -> None:
        pass

    # ============================================================
    # Methods to override
    # ============================================================
    def send_request(self, full_value: str):
        raise NotImplementedError("send_request() must be implemented in subclass")

    def _analyze_response(
        self,
        text: str,
        headers_lower: Dict[str, str],
        response,
    ) -> Dict[str, Any]:
        raise NotImplementedError("_analyze_response() must be implemented in subclass")

    # ============================================================
    # Unified result formats
    # ============================================================
    def _format_result(
        self,
        category: str,
        payload: str,
        severity: str,
        details: Any,
        **extra: Any,
    ) -> Dict[str, Any]:
        base: Dict[str, Any] = {
            "module": self.module_name,
            "url": self.base_url,
            "param": self.param,
            "payload": payload,
            "category": category,
            "severity": severity,
            "details": details,
            "status": "success",
        }
        base.update(extra)
        return base

    def _format_error_result(
        self,
        category: str,
        payload: str,
        error: Exception,
    ) -> Dict[str, Any]:
        return {
            "module": self.module_name,
            "url": self.base_url,
            "param": self.param,
            "payload": payload,
            "category": category,
            "severity": "error",
            "details": str(error),
            "status": "error",
        }
