# xss_security_gui/threat_analysis/ssrf_module.py
"""
SSRFTester (ULTRA Hybrid 6.5)
-----------------------------
• Проверяет параметры на наличие SSRF-уязвимостей
• Использует расширенные индикаторы (metadata, localhost, cloud endpoints)
• Интегрирован с settings.py и TesterBase
• Возвращает унифицированный результат для Threat Intel
"""

from __future__ import annotations

from ipaddress import ip_address
from datetime import datetime, timezone
from typing import Dict, Any, Callable, List, Optional
from urllib.parse import urljoin, urlsplit

import requests

from xss_security_gui.settings import settings
from xss_security_gui.threat_analysis.tester_base import TesterBase


_LOW_CONFIDENCE_BODY_INDICATORS = {
    "169.254.",
    "metadata",
    "ec2",
    "internal",
    "localhost",
    "127.0.0.1",
    "google.internal",
    "azure",
    "gcp",
    "aws",
    "openstack",
    "file://",
    "ftp://",
    "unix://",
}

_CONFIRMED_BODY_INDICATORS = (
    "ami-id",
    "instance-id",
    "iam/security-credentials",
    "root:x:0:0:",
    "daemon:x:1:1:",
    "metadata.google.internal/computeMetadata",
)


def _is_loopback_url(url: str) -> bool:
    try:
        hostname = urlsplit(url).hostname
        if not hostname:
            return False
        hostname = hostname.rstrip(".").lower()
        if hostname == "localhost" or hostname.endswith(".localhost"):
            return True
        return ip_address(hostname).is_loopback
    except ValueError:
        return False


class SSRFTester(TesterBase):
    """Модуль тестирования SSRF-уязвимостей."""

    MAX_REQUESTS = 20

    def __init__(
        self,
        base_url: str,
        param: str,
        base_value: str,
        payloads: List[str] | Dict[str, List[str]],
        output_callback: Callable[[Dict[str, Any]], None] | None = None,
        timeout: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        body_indicators: Optional[List[str]] = None,
        header_indicators: Optional[List[str]] = None,
        request_budget: RequestBudget | None = None,
    ):
        from xss_security_gui.auto_recon.scope import RequestBudget, normalize_http_url

        normalized_url = normalize_http_url(base_url)
        payload_categories = (
            payloads if isinstance(payloads, dict) else {"default": payloads}
        )
        super().__init__(
            "SSRF", normalized_url, param, base_value, payload_categories, output_callback
        )

        self.timeout = timeout or settings.REQUEST_TIMEOUT
        self.headers = headers or {"User-Agent": settings.DEFAULT_USER_AGENT}
        self.request_budget = request_budget or RequestBudget(self.MAX_REQUESTS)
        self._session = requests.Session()
        self.throttle_delay = max(self.throttle_delay, 0.5)

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
        from xss_security_gui.auto_recon.scope import (
            is_target_authorized,
            scoped_request,
        )

        if not is_target_authorized(self.base_url):
            return {
                "status": "blocked",
                "reason": "Target is outside ALLOW_REAL_RUN/ALLOWED_TARGETS",
            }

        try:
            return scoped_request(
                self._session,
                "GET",
                self.base_url,
                root_url=self.base_url,
                request_budget=self.request_budget,
                params={self.param: full_value},
                timeout=self.timeout,
                headers=self.headers,
            )
        except (requests.exceptions.RequestException, ValueError) as exc:
            return {"status": "blocked", "reason": str(exc)}

    def run(self) -> None:
        try:
            super().run()
        finally:
            self._session.close()

    # ---------------------------------------------------------
    # Анализ ответа (контракт TesterBase._analyze_response)
    # ---------------------------------------------------------
    def _analyze_response(
        self,
        text: str,
        headers_lower: Dict[str, str],
        response,
    ) -> Dict[str, Any]:
        # Broad words are useful hints, but are too common to confirm SSRF.
        body_matches = [
            indicator.lower()
            for indicator in self.body_indicators
            if indicator.lower() in text
        ]
        body_hit = any(
            indicator not in _LOW_CONFIDENCE_BODY_INDICATORS
            for indicator in body_matches
        ) or any(indicator in text for indicator in _CONFIRMED_BODY_INDICATORS)
        body_hint = bool(body_matches) and not body_hit

        header_matches = [
            indicator.lower()
            for indicator in self.header_indicators
            if any(
                indicator.lower() in name or indicator.lower() in value
                for name, value in headers_lower.items()
            )
        ]
        header_hit = bool(header_matches)
        suspicious_status = response.status_code in (500, 502, 503, 504)

        # Followed HTTP redirects can be observed here; internal server-side
        # fetches require out-of-band verification and cannot be inferred from this.
        redirected_to_local = False
        if response.history:
            for h in response.history:
                location = h.headers.get("Location", "")
                if _is_loopback_url(urljoin(h.url, location)):
                    redirected_to_local = True

        if _is_loopback_url(response.url):
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
            "body_hint": body_hint,
            "body_matches": body_matches,
            "header_hit": header_hit,
            "header_matches": header_matches,
            "redirected_to_local": redirected_to_local,
            "suspicious_status": suspicious_status,
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
        if body_hit or redirected_to_local:
            return "HIGH"
        return "INFO"