# xss_security_gui/threat_analysis/ssrf_module.py
import logging
import requests
from datetime import datetime
from typing import Dict, Any, Optional, List

from xss_security_gui.settings import settings
from xss_security_gui.threat_analysis.tester_base import TesterBase


class SSRFTester(TesterBase):
    """
    Enterprise 6.5 SSRF Tester
    --------------------------
    • Проверяет параметры на наличие SSRF-уязвимостей
    • Использует расширенные индикаторы (metadata, localhost, cloud endpoints)
    • Интегрирован с settings.py
    • Возвращает унифицированный результат для Threat Intel
    """

    def __init__(
        self,
        base_url: str,
        param: str,
        base_value: str,
        payloads: List[str],
        output_callback: Optional[callable] = None,
        timeout: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None
    ):
        super().__init__("SSRF", base_url, param, base_value, payloads, output_callback)

        # Настройки из settings.py
        self.timeout = timeout or settings.REQUEST_TIMEOUT
        self.headers = headers or {
            "User-Agent": settings.DEFAULT_USER_AGENT
        }

        # Индикаторы из settings.py (или дефолтные)
        self.body_indicators = (
            settings.SSRF_BODY_INDICATORS or
            [
                "169.254.", "metadata", "ec2", "internal", "localhost", "127.0.0.1",
                "google.internal", "azure", "gcp", "aws", "openstack",
                "file://", "ftp://", "unix://"
            ]
        )

        self.header_indicators = (
            settings.SSRF_HEADER_INDICATORS or
            [
                "via", "x-forwarded-for", "x-aws-", "metadata", "x-real-ip"
            ]
        )

    # ---------------------------------------------------------
    # Основной тест одного payload
    # ---------------------------------------------------------
    def _test_single(self, category: str, payload: str, full_value: str) -> Dict[str, Any]:
        """
        Тестирует один payload на SSRF.
        Возвращает результат в формате Threat Intel.
        """

        result: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat(),
            "module": "SSRF",
            "category": category,
            "param": self.param,
            "payload": payload,
            "target": self.base_url
        }

        try:
            response = requests.get(
                self.base_url,
                params={self.param: full_value},
                timeout=self.timeout,
                headers=self.headers,
                allow_redirects=True
            )

            text = response.text.lower()
            headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}

            # ---------------------------------------------------------
            # Индикаторы SSRF
            # ---------------------------------------------------------
            body_hit = any(ind in text for ind in self.body_indicators)
            header_hit = any(ind in headers_lower for ind in self.header_indicators)
            suspicious_status = response.status_code in (500, 502, 503, 504)

            # ---------------------------------------------------------
            # Анализ редиректов
            # ---------------------------------------------------------
            redirected_to_local = False

            # История редиректов
            if response.history:
                for h in response.history:
                    loc = h.headers.get("Location", "").lower()
                    if "127.0.0.1" in loc or "localhost" in loc:
                        redirected_to_local = True

            # Финальный URL
            if "127.0.0.1" in response.url or "localhost" in response.url:
                redirected_to_local = True

            # ---------------------------------------------------------
            # Формирование статуса
            # ---------------------------------------------------------
            if body_hit or header_hit or suspicious_status or redirected_to_local:
                status = "possible SSRF"
                severity = "high"
            else:
                status = "no signal"
                severity = "info"

            result.update({
                "status": status,
                "severity": severity,
                "http_status": response.status_code,
                "response_length": len(response.text),
                "headers": dict(response.headers),
                "final_url": response.url,
                "redirects": [h.url for h in response.history],
            })

            logging.info(
                f"[SSRFTester] {self.base_url} param={self.param} "
                f"payload={payload} → {status}"
            )
            logging.debug(
                f"[SSRFTester] Response length={len(response.text)} "
                f"status={response.status_code}"
            )

            return result

        except Exception as e:
            result.update({
                "status": "error",
                "severity": "error",
                "error": str(e),
                "response_length": 0
            })
            logging.error(f"[SSRFTester] Ошибка при тестировании {self.base_url}: {e}")
            return result