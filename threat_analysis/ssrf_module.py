# xss_security_gui/threat_analysis/ssrf_module.py
"""
SSRFTester (ULTRA Hybrid 6.5)
-----------------------------
• Проверяет параметры на наличие SSRF-уязвимостей
• Использует расширенные индикаторы (metadata, localhost, cloud endpoints)
• Интегрирован с settings.py и TesterBase
• Возвращает унифицированный результат для Threat Intel
"""

import requests
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from xss_security_gui.settings import settings
from xss_security_gui.threat_analysis.tester_base import TesterBase


class SSRFTester(TesterBase):
    """Модуль тестирования SSRF-уязвимостей."""

    def __init__(
        self,
        base_url: str,
        param: str,
        base_value: str,
        payloads: List[str],
        output_callback: Optional[callable] = None,
        timeout: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        body_indicators: Optional[List[str]] = None,
        header_indicators: Optional[List[str]] = None,
    ):
        # Оборачиваем список payload-ов в категорию "default",
        # чтобы соответствовать контракту TesterBase (Dict[str, List[str]])
        super().__init__("SSRF", base_url, param, base_value, {"default": payloads}, output_callback)

        # Настройки из settings.py
        self.timeout = timeout or settings.REQUEST_TIMEOUT
        self.headers = headers or {"User-Agent": settings.DEFAULT_USER_AGENT}

        # Индикаторы тела и заголовков
        self.body_indicators = body_indicators or (
            getattr(settings, "SSRF_BODY_INDICATORS", None)
            or [
                "169.254.", "metadata", "ec2", "internal", "localhost", "127.0.0.1",
                "google.internal", "azure", "gcp", "aws", "openstack",
                "file://", "ftp://", "unix://",
            ]
        )

        self.header_indicators = header_indicators or (
            getattr(settings, "SSRF_HEADER_INDICATORS", None)
            or ["via", "x-forwarded-for", "x-aws-", "metadata", "x-real-ip"]
        )

    # ---------------------------------------------------------
    # HTTP-запрос (контракт TesterBase.send_request)
    # ---------------------------------------------------------
    def send_request(self, full_value: str):
        try:
            response = requests.get(
                self.base_url,
                params={self.param: full_value},
                timeout=self.timeout,
                headers=self.headers,
                allow_redirects=True,
            )
            return response
        except Exception as e:
            # Возвращаем dict, чтобы TesterBase мог оформить это как "blocked"/error
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
        # === Индикаторы SSRF ===
        body_hit = any(ind in text for ind in self.body_indicators)
        header_hit = any(ind in headers_lower for ind in self.header_indicators)
        suspicious_status = response.status_code in (500, 502, 503, 504)

        # === Анализ редиректов ===
        redirected_to_local = False
        if response.history:
            for h in response.history:
                loc = h.headers.get("Location", "").lower()
                if "127.0.0.1" in loc or "localhost" in loc:
                    redirected_to_local = True

        if "127.0.0.1" in response.url or "localhost" in response.url:
            redirected_to_local = True

        severity = self._assess_severity(
            body_hit=body_hit,
            header_hit=header_hit,
            suspicious_status=suspicious_status,
            redirected_to_local=redirected_to_local,
        )

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "http_status": response.status_code,
            "response_length": len(response.text),
            "headers": dict(response.headers),
            "final_url": response.url,
            "redirects": [h.url for h in response.history],
            "body_hit": body_hit,
            "header_hit": header_hit,
            "redirected_to_local": redirected_to_local,
            "severity": severity,
        }

    @staticmethod
    def _assess_severity(
        body_hit: bool,
        header_hit: bool,
        suspicious_status: bool,
        redirected_to_local: bool,
    ) -> str:
        """Оценка риска SSRF."""
        if body_hit or header_hit or suspicious_status or redirected_to_local:
            return "HIGH"
        return "INFO"