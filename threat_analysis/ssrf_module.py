# xss_security_gui/threat_analysis/ssrf_module.py
import logging
import requests
from datetime import datetime
from typing import Dict, Any, Optional, List

from xss_security_gui.threat_analysis.tester_base import TesterBase


class SSRFTester(TesterBase):
    """
    Enterprise 6.0 SSRF Tester
    --------------------------
    • Проверяет параметры на наличие SSRF-уязвимостей
    • Использует расширенные индикаторы (metadata, localhost, cloud endpoints)
    • Возвращает унифицированный результат для Threat Intel
    """

    DEFAULT_BODY_INDICATORS: List[str] = [
        "169.254.", "metadata", "ec2", "internal", "localhost", "127.0.0.1",
        "google.internal", "azure", "gcp", "aws", "openstack",
        "file://", "ftp://", "unix://"
    ]

    DEFAULT_HEADER_INDICATORS: List[str] = [
        "via", "x-forwarded-for", "x-aws-", "metadata", "x-real-ip"
    ]

    def __init__(
        self,
        base_url: str,
        param: str,
        base_value: str,
        payloads: List[str],
        output_callback: Optional[callable] = None,
        timeout: int = 7,
        headers: Optional[Dict[str, str]] = None
    ):
        super().__init__("SSRF", base_url, param, base_value, payloads, output_callback)
        self.timeout = timeout
        self.headers = headers or {"User-Agent": "XSS-Security-GUI/6.0"}

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
            r = requests.get(
                self.base_url,
                params={self.param: full_value},
                timeout=self.timeout,
                headers=self.headers,
                allow_redirects=True
            )

            text = r.text.lower()
            headers = {k.lower(): v.lower() for k, v in r.headers.items()}

            # === Индикаторы SSRF ===
            body_hit = any(ind in text for ind in self.DEFAULT_BODY_INDICATORS)
            header_hit = any(ind in headers for ind in self.DEFAULT_HEADER_INDICATORS)
            suspicious_status = r.status_code in (500, 502, 503, 504)

            # === Анализ редиректов ===
            redirected_to_local = False
            if r.history:
                for h in r.history:
                    loc = h.headers.get("Location", "").lower()
                    if "127.0.0.1" in loc or "localhost" in loc:
                        redirected_to_local = True
            if "127.0.0.1" in r.url or "localhost" in r.url:
                redirected_to_local = True

            # === Формирование статуса и severity ===
            if body_hit or header_hit or suspicious_status or redirected_to_local:
                status = "possible SSRF"
                severity = "high"
            else:
                status = "no signal"
                severity = "info"

            result.update({
                "status": status,
                "severity": severity,
                "http_status": r.status_code,
                "response_length": len(r.text),
                "headers": dict(r.headers),
                "final_url": r.url,
                "redirects": [h.url for h in r.history],
            })

            logging.info(f"[SSRFTester] {self.base_url} param={self.param} payload={payload} → {status}")
            logging.debug(f"[SSRFTester] Response length={len(r.text)} status={r.status_code}")

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