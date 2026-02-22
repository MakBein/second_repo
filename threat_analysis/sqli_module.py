# xss_security_gui/threat_analysis/sqli_module.py
import logging
import requests
from datetime import datetime
from typing import Dict, Any, Optional, List

from xss_security_gui.settings import settings
from xss_security_gui.threat_analysis.tester_base import TesterBase


class SQLiTester(TesterBase):
    """
    Enterprise 6.5 SQL Injection Tester
    -----------------------------------
    • Проверяет параметры на наличие SQL-инъекций
    • Использует расширенные индикаторы ошибок и WAF
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
        super().__init__("SQLi", base_url, param, base_value, payloads, output_callback)

        # Настройки из settings.py
        self.timeout = timeout or settings.REQUEST_TIMEOUT
        self.headers = headers or {
            "User-Agent": settings.DEFAULT_USER_AGENT
        }

        # Индикаторы ошибок и WAF из settings.py
        self.error_indicators = (
            settings.SQLI_ERROR_INDICATORS or
            [
                "sql syntax", "mysql", "postgres", "sqlite", "odbc",
                "warning", "fatal error", "unclosed quotation mark",
                "unexpected end of input", "query failed",
                "native client", "syntax error", "invalid query",
                "unexpected token", "unterminated string", "invalid column"
            ]
        )

        self.waf_indicators = (
            settings.SQLI_WAF_INDICATORS or
            [
                "waf", "blocked", "forbidden", "security", "mod_security",
                "access denied", "firewall", "request rejected"
            ]
        )

    # ---------------------------------------------------------
    # Основной тест одного payload
    # ---------------------------------------------------------
    def _test_single(self, category: str, payload: str, full_value: str) -> Dict[str, Any]:
        """
        Тестирует один payload на SQLi.
        Возвращает результат в формате Threat Intel.
        """

        result: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat(),
            "module": "SQLi",
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
            # Индикаторы SQLi и WAF
            # ---------------------------------------------------------
            body_hit = any(ind in text for ind in self.error_indicators)
            header_hit = any(ind in headers_lower for ind in self.waf_indicators)
            suspicious_status = response.status_code in (500, 502, 503, 504)

            if body_hit or header_hit or suspicious_status:
                status = "possible SQLi"
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
            })

            logging.info(
                f"[SQLiTester] {self.base_url} param={self.param} "
                f"payload={payload} → {status}"
            )
            logging.debug(
                f"[SQLiTester] Response length={len(response.text)} "
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
            logging.error(f"[SQLiTester] Ошибка при тестировании {self.base_url}: {e}")
            return result