# xss_security_gui/threat_analysis/sqli_module.py
"""
SQLiTester (ULTRA Hybrid 6.5)
-----------------------------
• Проверяет параметры на наличие SQL-инъекций
• Использует расширенные индикаторы ошибок и WAF
• Интегрирован с settings.py
• Возвращает унифицированный результат для Threat Intel
"""

import requests
from datetime import datetime
from typing import Dict, Any, Optional, List

from xss_security_gui.settings import settings
from xss_security_gui.threat_analysis.tester_base import TesterBase


class SQLiTester(TesterBase):
    """Модуль тестирования SQL-инъекций."""

    def __init__(
        self,
        base_url: str,
        param: str,
        base_value: str,
        payloads: List[str],
        output_callback: Optional[callable] = None,
        timeout: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        error_indicators: Optional[List[str]] = None,
        waf_indicators: Optional[List[str]] = None,
    ):
        super().__init__("SQLi", base_url, param, base_value, {"default": payloads}, output_callback)

        # Настройки из settings.py
        self.timeout = timeout or settings.REQUEST_TIMEOUT
        self.headers = headers or {"User-Agent": settings.DEFAULT_USER_AGENT}

        # Индикаторы ошибок и WAF
        self.error_indicators = error_indicators or (
            settings.SQLI_ERROR_INDICATORS
            or [
                "sql syntax", "mysql", "postgres", "sqlite", "odbc",
                "warning", "fatal error", "unclosed quotation mark",
                "unexpected end of input", "query failed",
                "native client", "syntax error", "invalid query",
                "unexpected token", "unterminated string", "invalid column",
            ]
        )

        self.waf_indicators = waf_indicators or (
            settings.SQLI_WAF_INDICATORS
            or [
                "waf", "blocked", "forbidden", "security", "mod_security",
                "access denied", "firewall", "request rejected",
            ]
        )

    def _test_single(self, category: str, payload: str, full_value: str) -> Dict[str, Any]:
        """Тестирует один payload на SQLi."""
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

            # === Индикаторы SQLi и WAF ===
            body_hit = any(ind in text for ind in self.error_indicators)
            header_hit = any(ind in headers_lower for ind in self.waf_indicators)
            suspicious_status = response.status_code in (500, 502, 503, 504)

            severity = self._assess_severity(body_hit, header_hit, suspicious_status)

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
                    "body_hit": body_hit,
                    "header_hit": header_hit,
                },
            )

            self.logger.info(
                f"[SQLiTester] {self.base_url} param={self.param} payload={payload} → {severity}"
            )
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
            self.logger.error(f"[SQLiTester] Ошибка при тестировании {self.base_url}: {e}")
            return result

    @staticmethod
    def _assess_severity(body_hit: bool, header_hit: bool, suspicious_status: bool) -> str:
        """Оценка риска SQLi."""
        if body_hit or header_hit or suspicious_status:
            return "HIGH"
        return "INFO"