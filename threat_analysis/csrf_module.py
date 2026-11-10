# xss_security_gui/threat_analysis/csrf_module.py
"""
CSRFTester 11.0 — Combat Edition
================================
• Перевірка CSRF-захисту (Origin/Referer, SameSite, Secure, HttpOnly)
• Аналіз тіла відповіді на ознаки успішної операції
• Повністю ThreatConnector-friendly артефакт
• Підтримка асинхронного запуску через ThreadWorker 10.0
• Розширений severity engine (LOW/MEDIUM/HIGH/CRITICAL)
"""

from __future__ import annotations

import requests
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Callable

from xss_security_gui.threat_analysis.tester_base import TesterBase
from xss_security_gui.settings import settings
from xss_security_gui.utils.thread_worker import run_in_thread
from xss_security_gui.utils.safe_call import safe_invoke


class CSRFTester(TesterBase):
    """Модуль тестування CSRF-захисту (рівень ZAP/OWASP + ThreatConnector)."""

    BODY_INDICATORS = ["success", "done", "updated", "changed", "saved", "ok", "completed"]

    def __init__(
        self,
        base_url: str,
        param: str,
        base_value: str,
        payloads: Dict[str, List[str]],
        output_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        referer: str = "https://gazprombank.ru",
        origin: str = "https://gazprombank.ru",
        threat_connector: Any | None = None,
    ):
        super().__init__("CSRF", base_url, param, base_value, payloads, output_callback)

        self.referer = referer
        self.origin = origin
        self.timeout = settings.get("http.request_timeout", 7)
        self.threat_connector = threat_connector

    # ---------------------------------------------------------
    # HTTP-запрос (TesterBase.send_request)
    # ---------------------------------------------------------
    def send_request(self, full_value: str):
        try:
            headers = {
                "Referer": self.referer,
                "Origin": self.origin,
            }

            response = requests.get(
                self.base_url,
                params={self.param: full_value},
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
            )
            return response

        except Exception as e:
            return {"status": "blocked", "reason": str(e)}

    # ---------------------------------------------------------
    # Анализ ответа (TesterBase._analyze_response)
    # ---------------------------------------------------------
    def _analyze_response(
        self,
        text: str,
        headers_lower: Dict[str, str],
        response,
    ) -> Dict[str, Any]:

        # Cookie-защита
        set_cookie = headers_lower.get("set-cookie", "")
        missing_samesite = "samesite" not in set_cookie
        missing_secure = "secure" not in set_cookie
        missing_httponly = "httponly" not in set_cookie

        # CSRF-токены в заголовках
        missing_csrf_header = "x-csrf-token" not in headers_lower

        # Origin/Referer policy
        missing_origin_check = (
            response.status_code == 200
            and "origin" not in headers_lower
            and "referer" not in headers_lower
        )

        # Подозрительные ключевые слова в теле
        body_hit = any(x in text.lower() for x in self.BODY_INDICATORS)

        # Severity
        severity = self._assess_severity(
            missing_samesite,
            missing_secure,
            missing_httponly,
            missing_csrf_header,
            missing_origin_check,
            body_hit,
        )

        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "module": "CSRFTester",
            "category": "csrf_test",
            "target": self.base_url,
            "http_status": response.status_code,
            "response_length": len(response.text),
            "headers": dict(response.headers),
            "final_url": response.url,
            "redirects": [h.url for h in response.history],
            "body_hit": body_hit,
            "missing_samesite": missing_samesite,
            "missing_secure": missing_secure,
            "missing_httponly": missing_httponly,
            "missing_csrf_header": missing_csrf_header,
            "missing_origin_check": missing_origin_check,
            "severity": severity,
            "status": "success",
        }

        # ThreatConnector інтеграція
        if self.threat_connector:
            try:
                self.threat_connector.add_artifact(result)
            except Exception:
                pass

        return result

    # ---------------------------------------------------------
    # Severity логика 11.0
    # ---------------------------------------------------------
    @staticmethod
    def _assess_severity(
        missing_samesite: bool,
        missing_secure: bool,
        missing_httponly: bool,
        missing_csrf_header: bool,
        missing_origin_check: bool,
        body_hit: bool,
    ) -> str:

        # CRITICAL — тіло показує успішну операцію + відсутній CSRF-захист
        if body_hit and (missing_csrf_header or missing_origin_check):
            return "CRITICAL"

        # HIGH — відсутні ключові cookie-флаги або CSRF-заголовок
        if (
            missing_csrf_header
            or missing_samesite
            or missing_secure
            or missing_httponly
            or body_hit
        ):
            return "HIGH"

        # MEDIUM — немає Origin/Referer policy
        if missing_origin_check:
            return "MEDIUM"

        # LOW — мінімальні ризики
        return "LOW"

    # ---------------------------------------------------------
    # Async / ThreadWorker інтеграція
    # ---------------------------------------------------------
    def run_async(
        self,
        full_value: str,
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:

        def work_fn(progress, is_cancelled):
            response = self.send_request(full_value)
            if isinstance(response, dict):  # blocked
                return response
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            return self._analyze_response(response.text, headers_lower, response)

        def on_success(result: Dict[str, Any]) -> None:
            if callback:
                safe_invoke(callback, result)

        def on_error(e: Exception) -> None:
            if callback:
                safe_invoke(callback, {"status": "error", "error": str(e)})

        run_in_thread(
            work_fn,
            name="CSRFTester",
            on_success=on_success,
            on_progress=None,
            on_error=on_error,
            on_finally=None,
        )
