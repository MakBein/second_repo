# xss_security_gui/threat_analysis/sqli_module.py
"""
SQLiTester (ULTRA Hybrid 6.5)
-----------------------------
• Проверяет параметры на наличие SQL-инъекций
• Использует расширенные индикаторы ошибок и WAF
• Интегрирован с settings.py
• Возвращает унифицированный результат для Threat Intel
"""

import json
import requests
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

from xss_security_gui.settings import settings
from xss_security_gui.threat_analysis.tester_base import TesterBase


def application(environ, start_response):
    if environ["REQUEST_METHOD"] == "POST" and environ["PATH_INFO"] == "/__test__/sql":
        try:
            size = int(environ.get("CONTENT_LENGTH", 0))
            body = environ["wsgi.input"].read(size)
            data = json.loads(body)
            query = data.get("query")

            conn = sqlite3.connect("test.db")
            cur = conn.cursor()
            cur.execute(query)
            rows = cur.fetchall()

            response = json.dumps({"status": "ok", "rows": rows})
        except Exception as e:
            response = json.dumps({"status": "error", "error": str(e)})

        start_response("200 OK", [("Content-Type", "application/json")])
        return [response.encode()]

    start_response("404 Not Found", [])
    return [b"Not Found"]


class SQLiTester(TesterBase):
    """Модуль тестирования SQL-инъекций."""

    def __init__(
        self,
        base_url: str,
        param: str,
        base_value: str,
        payloads: Dict[str, List[str]],
        output_callback: Optional[callable] = None,
        timeout: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        error_indicators: Optional[List[str]] = None,
        waf_indicators: Optional[List[str]] = None,
    ):
        super().__init__("SQLi", base_url, param, base_value, payloads, output_callback)

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

    # ---------------------------------------------------------
    # HTTP-запрос (контракт TesterBase.send_request)
    # ---------------------------------------------------------
    def send_request(self, full_value: str):
        domain = urlparse(self.base_url).hostname
        if domain not in settings.ALLOWED_TARGETS:
            return {"status": "blocked", "reason": "domain-not-allowed"}

        response = requests.get(
            self.base_url,
            params={self.param: full_value},
            timeout=self.timeout,
            headers=self.headers,
            allow_redirects=True,
        )
        return response

    # ---------------------------------------------------------
    # Анализ ответа (контракт TesterBase._analyze_response)
    # ---------------------------------------------------------
    def _analyze_response(
        self,
        text: str,
        headers_lower: Dict[str, str],
        response,
    ) -> Dict[str, Any]:
        body_hit = any(ind in text for ind in self.error_indicators)
        header_hit = any(ind in headers_lower for ind in self.waf_indicators)
        suspicious_status = response.status_code in (500, 502, 503, 504)

        severity = self._assess_severity(body_hit, header_hit, suspicious_status)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "http_status": response.status_code,
            "response_length": len(response.text),
            "headers": dict(response.headers),
            "final_url": response.url,
            "body_hit": body_hit,
            "header_hit": header_hit,
            "severity": severity,
        }

    @staticmethod
    def _assess_severity(body_hit: bool, header_hit: bool, suspicious_status: bool) -> str:
        """Оценка риска SQLi."""
        if body_hit or header_hit or suspicious_status:
            return "HIGH"
        return "INFO"

    # ---------------------------------------------------------
    # Тестовый SQL-эндпоинт (для локального стенда)
    # ---------------------------------------------------------
    def execute_sql(self, query: str):
        domain = urlparse(self.base_url).hostname
        if domain not in settings.ALLOWED_TARGETS:
            return {"status": "blocked", "reason": "domain-not-allowed"}

        endpoint = self.base_url.rstrip("/") + "/__test__/sql"
        response = requests.post(endpoint, json={"query": query}, timeout=5)
        return response.json()
