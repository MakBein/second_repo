# xss_security_gui/threat_analysis/sqli_module.py
"""
SQLiTester (ULTRA Hybrid 6.5+)
------------------------------
• GET/POST, Session, прокси и verify из settings
• Согласованная с AttackEngine проверка ALLOW_REAL_RUN / ALLOWED_TARGETS
• Опциональный обход WAF: варианты кодировки пробелов и повтор запросов
"""

import json
import re
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import requests

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


def _sqli_host_allowed(hostname: Optional[str]) -> bool:
    """Та же логика, что у реальных атак: ALLOW_REAL_RUN + ALLOWED_TARGETS (поддомены)."""
    if not hostname:
        return False
    if not getattr(settings, "ALLOW_REAL_RUN", True):
        return False
    allowed = getattr(settings, "ALLOWED_TARGETS", None) or []
    if not allowed:
        return True
    host = hostname.lower()
    for a in allowed:
        a = (a or "").lower().strip()
        if not a:
            continue
        if host == a or host.endswith("." + a):
            return True
    return False


def _waf_sqli_variants(value: str, max_variants: int = 4) -> List[str]:
    """
    Варианты значения параметра для обхода простых WAF (пробелы, регистр ключевых слов).
    Не ломает семантику для большинства СУБД.
    """
    out: List[str] = []
    seen = set()

    def add(s: str) -> None:
        if s not in seen and len(seen) < max_variants:
            seen.add(s)
            out.append(s)

    add(value)
    if " " in value:
        add(value.replace(" ", "/**/"))
        add(re.sub(r" +", "\t", value))
    if re.search(r"\bOR\b", value, re.I):
        add(re.sub(r"\bOR\b", "oR", value, count=1, flags=re.I))
    if re.search(r"\bAND\b", value, re.I):
        add(re.sub(r"\bAND\b", "AnD", value, count=1, flags=re.I))
    if re.search(r"\bUNION\b", value, re.I):
        add(re.sub(r"\bUNION\b", "UnIoN", value, count=1, flags=re.I))
    if re.search(r"\bSELECT\b", value, re.I):
        add(re.sub(r"\bSELECT\b", "SeLeCt", value, count=1, flags=re.I))
    if len(out) < max_variants and "%" not in value[:8]:
        add(value.replace("'", "%27").replace(" ", "%20"))
    return out[:max_variants]


class SQLiTester(TesterBase):
    """Модуль тестирования SQL-инъекций."""

    def __init__(
        self,
        base_url: str,
        param: str,
        base_value: str,
        payloads: Dict[str, List[str]],
        output_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        timeout: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        error_indicators: Optional[List[str]] = None,
        waf_indicators: Optional[List[str]] = None,
        waf_evasion: bool = False,
        try_post_fallback: bool = False,
        aggressive_headers: bool = False,
        inter_attempt_delay: float = 0.0,
    ):
        super().__init__("SQLi", base_url, param, base_value, payloads, output_callback)

        self.timeout = int(
            timeout
            or getattr(settings, "REQUEST_TIMEOUT", None)
            or settings.get("http.request_timeout", 10)
            or 10
        )
        self.waf_evasion = bool(waf_evasion)
        self.try_post_fallback = bool(try_post_fallback)
        self.aggressive_headers = bool(aggressive_headers)
        self.inter_attempt_delay = float(inter_attempt_delay)

        ua = getattr(settings, "DEFAULT_USER_AGENT", None) or settings.get(
            "http.default_user_agent", "XSS-Security-GUI/6.5"
        )
        base_hdr: Dict[str, str] = {"User-Agent": str(ua)}
        if headers:
            base_hdr.update(headers)
        if self.aggressive_headers:
            base_hdr.setdefault(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            base_hdr.setdefault("Accept-Language", "en-US,en;q=0.9")
            base_hdr.setdefault("Cache-Control", "no-cache")
        self.headers = base_hdr

        self.error_indicators = list(
            error_indicators
            or settings.SQLI_ERROR_INDICATORS
            or [
                "sql syntax",
                "mysql",
                "postgres",
                "sqlite",
                "odbc",
                "warning",
                "fatal error",
                "unclosed quotation mark",
                "unexpected end of input",
                "query failed",
                "native client",
                "syntax error",
                "invalid query",
                "unexpected token",
                "unterminated string",
                "invalid column",
                "sqlstate",
                "psql:",
                "ora-",
                "microsoft ole db",
                "jdbc",
                "sqlite3.operationalerror",
            ]
        )

        self.waf_indicators = list(
            waf_indicators
            or settings.SQLI_WAF_INDICATORS
            or [
                "waf",
                "blocked",
                "forbidden",
                "security",
                "mod_security",
                "access denied",
                "firewall",
                "request rejected",
                "cloudflare",
                "incapsula",
                "akamai",
                "perimeterx",
                "captcha",
                "rate limit",
            ]
        )

        self._http = requests.Session()
        proxies = settings.get("http.proxies")
        if proxies and isinstance(proxies, dict):
            self._http.proxies.update({k: v for k, v in proxies.items() if v})
        self.verify = bool(settings.get("http.verify_ssl", False))

    # ---------------------------------------------------------
    # HTTP-запрос (контракт TesterBase.send_request)
    # ---------------------------------------------------------
    def send_request(self, full_value: str) -> Union[requests.Response, Dict[str, Any]]:
        parsed = urlparse(self.base_url)
        if not _sqli_host_allowed(parsed.hostname):
            return {"status": "blocked", "reason": "domain-not-allowed"}

        values = _waf_sqli_variants(full_value, 6) if self.waf_evasion else [full_value]
        attempts: List[Tuple[str, str]] = []
        for v in values:
            attempts.append(("GET", v))
        if self.try_post_fallback:
            attempts.append(("POST", values[0]))

        last_exc: Optional[Exception] = None
        response: Optional[requests.Response] = None

        for method, val in attempts:
            if self.inter_attempt_delay > 0:
                time.sleep(self.inter_attempt_delay)
            try:
                if method == "GET":
                    response = self._http.get(
                        self.base_url,
                        params={self.param: val},
                        timeout=self.timeout,
                        headers=self.headers,
                        allow_redirects=True,
                        verify=self.verify,
                    )
                else:
                    response = self._http.post(
                        self.base_url,
                        data={self.param: val},
                        timeout=self.timeout,
                        headers={**self.headers, "Content-Type": "application/x-www-form-urlencoded"},
                        allow_redirects=True,
                        verify=self.verify,
                    )
                if response is not None:
                    if response.status_code in (403, 406) and len(attempts) > 1:
                        continue
                    return response
            except requests.RequestException as e:
                last_exc = e
                continue

        if last_exc is not None:
            raise last_exc
        if response is not None:
            return response
        return {"status": "blocked", "reason": "all-attempts-failed"}

    # ---------------------------------------------------------
    # Анализ ответа (контракт TesterBase._analyze_response)
    # ---------------------------------------------------------
    def _analyze_response(
        self,
        text: str,
        headers_lower: Dict[str, str],
        response,
    ) -> Dict[str, Any]:
        body_hit = any(ind.lower() in text for ind in self.error_indicators)
        header_hit = any(
            any(w in hk or w in hv for w in self.waf_indicators)
            for hk, hv in headers_lower.items()
        )
        suspicious_status = response.status_code in (500, 502, 503, 504)

        severity = self._assess_severity(body_hit, header_hit, suspicious_status)

        raw_sample = response.text[:1200] if response.text else ""

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "http_status": response.status_code,
            "response_length": len(response.text or ""),
            "headers": dict(response.headers),
            "final_url": response.url,
            "body_hit": body_hit,
            "header_hit": header_hit,
            "severity": severity,
            "raw": raw_sample,
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
        if not _sqli_host_allowed(domain):
            return {"status": "blocked", "reason": "domain-not-allowed"}

        endpoint = self.base_url.rstrip("/") + "/__test__/sql"
        response = requests.post(endpoint, json={"query": query}, timeout=5)
        return response.json()
