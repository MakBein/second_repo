# xss_security_gui/threat_analysis/xss_module.py
# ============================================================
# XSSTester 11.0 — context-aware, risk-aware, ThreatConnector-ready
# ============================================================

from __future__ import annotations
from datetime import datetime, timezone
from typing import Dict, Any, List, Callable, Optional

import requests

from xss_security_gui.threat_analysis.tester_base import TesterBase
from xss_security_gui.settings import settings

XSSCallback = Callable[[Dict[str, Any]], None]


class XSSTester(TesterBase):
    """
    XSSTester 11.0 — Combat Edition
    -------------------------------
    • ReflectionEngine 2.0 (точне визначення відображення payload)
    • ContextEngine 3.0 (JS, HTML, Attribute, URL, Inline Events, Dangerous Sinks)
    • SeverityEngine 11.0 (critical/high/medium/low/info)
    • ThreatConnector-friendly артефакти
    • Повна сумісність з TesterBase 11.0 (ретраї, троттлінг, stability-window)
    """

    def __init__(
        self,
        base_url: str,
        param: str,
        base_value: str,
        payloads: List[str],
        output_callback: Optional[XSSCallback] = None,
        timeout: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        super().__init__(
            "XSS",
            base_url,
            param,
            base_value,
            {"default": payloads},
            output_callback
        )

        self.timeout: int = timeout or int(settings.get("http.request_timeout", 7))

        default_ua = settings.get("http.default_user_agent", "XSS-Security-GUI/11.0")
        base_headers = {"User-Agent": default_ua}

        if headers:
            base_headers.update(headers)

        self.headers: Dict[str, str] = base_headers

    # ============================================================
    # HTTP-запрос
    # ============================================================
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
            return {"status": "blocked", "reason": str(e)}

    # ============================================================
    # Анализ ответа
    # ============================================================
    def _analyze_response(
        self,
        text: str,
        headers_lower: Dict[str, str],
        response,
    ) -> Dict[str, Any]:

        reflected = self._is_reflected(text, response.request.url)

        context_type, context_snippet = self._detect_context(text, reflected)

        severity = self._assess_severity(reflected, context_type)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "http_status": response.status_code,
            "response_length": len(text),
            "headers": dict(response.headers),
            "final_url": response.url,
            "reflected": reflected,
            "context_type": context_type,
            "context_snippet": context_snippet,
            "severity": severity,
        }

    # ============================================================
    # ReflectionEngine 2.0
    # ============================================================
    def _is_reflected(self, html: str, url: str) -> bool:
        """Перевіряє, чи відображено payload у HTML або URL."""
        p = self.base_value.lower()
        return p in html.lower() or p in url.lower()

    # ============================================================
    # ContextEngine 3.0
    # ============================================================
    def _detect_context(self, html: str, reflected: bool):
        if not reflected:
            return "Not Reflected", None

        lower = html.lower()
        p = self.base_value.lower()

        index = lower.find(p)
        snippet = None
        if index != -1:
            start = max(0, index - 80)
            end = min(len(html), index + len(p) + 80)
            snippet = html[start:end]

        # JS Context
        if "<script" in lower and p in lower:
            return "JS Context", snippet

        # Inline Event Handlers
        if any(ev in lower for ev in ("onerror=", "onclick=", "onload=", "onmouseover=", "onfocus=", "onblur=")):
            return "Inline Event Handler", snippet

        # Dangerous JS sinks
        if any(sink in lower for sink in ("eval(", "function(", "settimeout(", "setinterval(", "innerhtml", "outerhtml")):
            return "Dangerous JS Sink", snippet

        # Attribute Injection
        if f"=\"{p}\"" in lower or f"='{p}'" in lower:
            return "Attribute Injection", snippet

        # HTML Body
        if f">{p}<" in lower:
            return "HTML Body", snippet

        # URL Parameter
        if f"url={p}" in lower or f"href={p}" in lower:
            return "URL Parameter", snippet

        return "Unknown", snippet

    # ============================================================
    # SeverityEngine 11.0
    # ============================================================
    @staticmethod
    def _assess_severity(reflected: bool, context_type: str) -> str:
        if not reflected:
            return "INFO"

        if context_type in ("JS Context", "Dangerous JS Sink"):
            return "CRITICAL"

        if context_type in ("Inline Event Handler", "Attribute Injection"):
            return "HIGH"

        if context_type in ("HTML Body", "URL Parameter"):
            return "MEDIUM"

        return "LOW"

