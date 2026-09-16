# xss_security_gui/threat_analysis/sqli_module.py
"""
SQLiTester 11.0 — Combat Edition
================================
• GET/POST, Session, Proxy, SSL-verify
• WAF-bypass engine 11.0 (encoding, obfuscation, keyword mutation)
• DB fingerprinting (MySQL/Postgres/Oracle/MSSQL/SQLite)
• Boolean-based, Error-based, Time-based SQLi detection
• ThreatConnector-friendly артефакт
• Асинхронний запуск через ThreadWorker 10.0
• Повністю стабільний, без падінь
"""

from __future__ import annotations

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
from xss_security_gui.utils.thread_worker import run_in_thread
from xss_security_gui.utils.safe_call import safe_invoke


# ---------------------------------------------------------
# Allow-list logic (same as AttackEngine)
# ---------------------------------------------------------
def _sqli_host_allowed(hostname: Optional[str]) -> bool:
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


# ---------------------------------------------------------
# WAF bypass engine 11.0
# ---------------------------------------------------------
def _waf_sqli_variants(value: str, max_variants: int = 6) -> List[str]:
    out: List[str] = []
    seen = set()

    def add(s: str):
        if s not in seen and len(out) < max_variants:
            seen.add(s)
            out.append(s)

    add(value)

    # Space obfuscation
    if " " in value:
        add(value.replace(" ", "/**/"))
        add(re.sub(r" +", "\t", value))
        add(value.replace(" ", "%20"))

    # Keyword mutation
    for kw in ["OR", "AND", "UNION", "SELECT", "WHERE"]:
        if re.search(rf"\b{kw}\b", value, re.I):
            add(re.sub(rf"\b{kw}\b", kw.capitalize(), value, flags=re.I))

    # URL encoding
    if "%" not in value[:8]:
        add(value.replace("'", "%27"))

    return out[:max_variants]


# ---------------------------------------------------------
# SQLiTester 11.0
# ---------------------------------------------------------
class SQLiTester(TesterBase):
    """Модуль тестування SQL‑ін'єкцій (11.0)."""

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
        threat_connector: Any | None = None,
    ):
        super().__init__("SQLi", base_url, param, base_value, payloads, output_callback)

        self.threat_connector = threat_connector

        # Timeout
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

        # Headers
        ua = getattr(settings, "DEFAULT_USER_AGENT", None) or settings.get(
            "http.default_user_agent", "XSS-Security-GUI/11.0"
        )
        base_hdr: Dict[str, str] = {"User-Agent": str(ua)}
        if headers:
            base_hdr.update(headers)
        if self.aggressive_headers:
            base_hdr.setdefault("Accept", "*/*")
            base_hdr.setdefault("Cache-Control", "no-cache")
            base_hdr.setdefault("Pragma", "no-cache")
        self.headers = base_hdr

        # Error indicators (DB fingerprinting)
        self.error_indicators = list(
            error_indicators
            or settings.SQLI_ERROR_INDICATORS
            or [
                "mysql",
                "postgres",
                "sqlite",
                "oracle",
                "mssql",
                "sql syntax",
                "syntax error",
                "unclosed quotation",
                "unexpected end of input",
                "invalid column",
                "sqlstate",
                "psql:",
                "ora-",
                "jdbc",
                "sqlite3.operationalerror",
            ]
        )

        # WAF indicators
        self.waf_indicators = list(
            waf_indicators
            or settings.SQLI_WAF_INDICATORS
            or [
                "waf",
                "blocked",
                "forbidden",
                "security",
                "mod_security",
                "cloudflare",
                "incapsula",
                "akamai",
                "perimeterx",
                "captcha",
                "rate limit",
            ]
        )

        # HTTP session
        self._http = requests.Session()
        proxies = settings.get("http.proxies")
        if proxies and isinstance(proxies, dict):
            self._http.proxies.update({k: v for k, v in proxies.items() if v})
        self.verify = bool(settings.get("http.verify_ssl", False))

    # ---------------------------------------------------------
    # HTTP-запрос
    # ---------------------------------------------------------
    def send_request(self, full_value: str) -> Union[requests.Response, Dict[str, Any]]:
        parsed = urlparse(self.base_url)
        if not _sqli_host_allowed(parsed.hostname):
            return {"status": "blocked", "reason": "domain-not-allowed"}

        values = _waf_sqli_variants(full_value, 6) if self.waf_evasion else [full_value]
        attempts: List[Tuple[str, str]] = [( "GET", v ) for v in values]

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

                if response.status_code in (403, 406) and len(attempts) > 1:
                    continue

                return response

            except requests.RequestException as e:
                last_exc = e
                continue

        if last_exc:
            return {"status": "blocked", "reason": str(last_exc)}

        return {"status": "blocked", "reason": "all-attempts-failed"}

    # ---------------------------------------------------------
    # Анализ ответа
    # ---------------------------------------------------------
    def _analyze_response(
        self,
        text: str,
        headers_lower: Dict[str, str],
        response,
    ) -> Dict[str, Any]:

        # Error-based SQLi
        body_hit = any(ind.lower() in text.lower() for ind in self.error_indicators)

        # WAF detection
        header_hit = any(
            any(w in hk or w in hv for w in self.waf_indicators)
            for hk, hv in headers_lower.items()
        )

        # Suspicious status codes
        suspicious_status = response.status_code in (500, 502, 503, 504)

        # Time-based SQLi (simple heuristic)
        slow = response.elapsed.total_seconds() > 3.5

        severity = self._assess_severity(body_hit, header_hit, suspicious_status, slow)

        raw_sample = response.text[:1500] if response.text else ""

        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "module": "SQLiTester",
            "category": "sqli_intel",
            "target": self.base_url,
            "http_status": response.status_code,
            "response_length": len(response.text or ""),
            "headers": dict(response.headers),
            "final_url": response.url,
            "body_hit": body_hit,
            "header_hit": header_hit,
            "slow": slow,
            "severity": severity,
            "raw": raw_sample,
        }

        # ThreatConnector інтеграція
        if self.threat_connector:
            try:
                self.threat_connector.add_artifact(result)
            except Exception:
                pass

        return result

    # ---------------------------------------------------------
    # Severity engine 11.0
    # ---------------------------------------------------------
    @staticmethod
    def _assess_severity(
        body_hit: bool,
        header_hit: bool,
        suspicious_status: bool,
        slow: bool,
    ) -> str:

        if body_hit:
            return "HIGH"

        if suspicious_status:
            return "HIGH"

        if header_hit:
            return "MEDIUM"

        if slow:
            return "MEDIUM"

        return "INFO"

    # ---------------------------------------------------------
    # Асинхронний запуск через ThreadWorker
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

        def on_success(result: Dict[str, Any]):
            if callback:
                safe_invoke(callback, result)

        def on_error(e: Exception):
            if callback:
                safe_invoke(callback, {"status": "error", "error": str(e)})

        run_in_thread(
            work_fn,
            name="SQLiTester",
            on_success=on_success,
            on_progress=None,
            on_error=on_error,
            on_finally=None,
        )

