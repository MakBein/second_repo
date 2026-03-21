# xss_security_gui/threat_analysis/csrf_module.py
"""
CSRFTester (ULTRA Hybrid 6.5)
-----------------------------
• Проверяет наличие CSRF-защиты
• Анализирует заголовки и тело ответа
• Работает через универсальный TesterBase
• Возвращает унифицированный результат для Threat Intel
"""

import requests
from datetime import datetime, timezone
from typing import Dict, Any, List

from xss_security_gui.threat_analysis.tester_base import TesterBase
from xss_security_gui.settings import settings


class CSRFTester(TesterBase):
    """Модуль тестирования CSRF-защиты (уровень ZAP/OWASP)."""

    BODY_INDICATORS = ["success", "done", "updated", "changed", "saved", "ok", "completed"]

    def __init__(
        self,
        base_url: str,
        param: str,
        base_value: str,
        payloads: Dict[str, List[str]],
        output_callback=None,
        referer: str = "https://gazprombank.ru",
        origin: str = "https://gazprombank.ru",
    ):
        super().__init__("CSRF", base_url, param, base_value, payloads, output_callback)

        self.referer = referer
        self.origin = origin
        self.timeout = settings.get("http.request_timeout", 7)

    # ---------------------------------------------------------
    # HTTP-запрос (контракт TesterBase.send_request)
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
    # Анализ ответа (контракт TesterBase._analyze_response)
    # ---------------------------------------------------------
    def _analyze_response(
        self,
        text: str,
        headers_lower: Dict[str, str],
        response,
    ) -> Dict[str, Any]:

        # === Cookie-защита ===
        set_cookie = headers_lower.get("set-cookie", "")
        missing_samesite = "samesite" not in set_cookie
        missing_secure = "secure" not in set_cookie
        missing_httponly = "httponly" not in set_cookie

        # === CSRF-токены в заголовках ===
        missing_csrf_header = "x-csrf-token" not in headers_lower

        # === Origin/Referer policy ===
        missing_origin_check = (
            response.status_code == 200
            and "origin" not in headers_lower
            and "referer" not in headers_lower
        )

        # === Подозрительные ключевые слова в теле ===
        body_hit = any(x in text for x in self.BODY_INDICATORS)

        # === Оценка риска ===
        severity = self._assess_severity(
            missing_samesite,
            missing_secure,
            missing_httponly,
            missing_csrf_header,
            missing_origin_check,
            body_hit,
        )

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
        }

    # ---------------------------------------------------------
    # Severity логика (уровень ZAP)
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

        # === HIGH ===
        if (
            missing_csrf_header
            or missing_samesite
            or missing_secure
            or missing_httponly
            or body_hit
        ):
            return "HIGH"

        # === MEDIUM ===
        if missing_origin_check:
            return "MEDIUM"

        # === LOW ===
        return "LOW"