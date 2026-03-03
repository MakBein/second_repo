# xss_security_gui/threat_analysis/ssrf_module.py
"""
SSRFTester (ULTRA Hybrid 6.5)
-----------------------------
• Проверяет параметры на наличие SSRF-уязвимостей
• Использует расширенные индикаторы (metadata, localhost, cloud endpoints)
• Интегрирован с settings.py
• Возвращает унифицированный результат для Threat Intel
"""

import requests
from datetime import datetime
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
        super().__init__("SSRF", base_url, param, base_value, {"default": payloads}, output_callback)

        # Настройки из settings.py
        self.timeout = timeout or settings.REQUEST_TIMEOUT
        self.headers = headers or {"User-Agent": settings.DEFAULT_USER_AGENT}

        # Индикаторы тела и заголовков
        self.body_indicators = body_indicators or (
            settings.SSRF_BODY_INDICATORS
            or [
                "169.254.", "metadata", "ec2", "internal", "localhost", "127.0.0.1",
                "google.internal", "azure", "gcp", "aws", "openstack",
                "file://", "ftp://", "unix://",
            ]
        )

        self.header_indicators = header_indicators or (
            settings.SSRF_HEADER_INDICATORS
            or ["via", "x-forwarded-for", "x-aws-", "metadata", "x-real-ip"]
        )

    def _test_single(self, category: str, payload: str, full_value: str) -> Dict[str, Any]:
        """Тестирует один payload на SSRF."""
        try:
            response = requests.get(
                self.base_url,
                params={self.param: full_value},
                timeout=self.timeout,
                headers=self.headers,
                allow_redirects=True,
            )

            text = response.text.lower()
            headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}

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

            severity = self._assess_severity(body_hit, header_hit, suspicious_status, redirected_to_local)

            result = self._format_result(
                category=category,
                payload=payload,
                severity=severity,
                details={
                    "timestamp": datetime.utcnow().isoformat(),
                    "http_status": response.status_code,
                    "response_length": len(response.text),
                    "headers": dict(response.headers),
                    "final_url": response.url,
                    "redirects": [h.url for h in response.history],
                    "body_hit": body_hit,
                    "header_hit": header_hit,
                    "redirected_to_local": redirected_to_local,
                },
            )

            self.logger.info(f"[SSRFTester] {self.base_url} param={self.param} payload={payload} → {severity}")
            return result

        except Exception as e:
            result = self._format_result(
                category=category,
                payload=payload,
                severity="ERROR",
                details={
                    "timestamp": datetime.utcnow().isoformat(),
                    "status": "error",
                    "error": str(e),
                    "response_length": 0,
                },
            )
            self.logger.error(f"[SSRFTester] Ошибка при тестировании {self.base_url}: {e}")
            return result

    @staticmethod
    def _assess_severity(body_hit: bool, header_hit: bool, suspicious_status: bool, redirected_to_local: bool) -> str:
        """Оценка риска SSRF."""
        if body_hit or header_hit or suspicious_status or redirected_to_local:
            return "HIGH"
        return "INFO"