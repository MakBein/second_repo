# xss_security_gui/threat_analysis/xss_module.py
"""
XSSTester (ULTRA Hybrid 6.5)
----------------------------
• Проверяет отражение XSS payload'ов
• Определяет контекст (HTML, JS, Attribute, URL)
• Работает через универсальный TesterBase
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import requests

from xss_security_gui.threat_analysis.tester_base import TesterBase
from xss_security_gui.settings import settings


class XSSTester(TesterBase):
    """Модуль тестирования XSS-инъекций."""

    def __init__(
        self,
        base_url: str,
        param: str,
        base_value: str,
        payloads: List[str],
        output_callback: Optional[callable] = None,
        timeout: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        # Оборачиваем payloads в категорию "default"
        super().__init__("XSS", base_url, param, base_value, {"default": payloads}, output_callback)

        # Таймаут
        self.timeout: int = timeout or int(settings.get("http.request_timeout", 7))

        # Заголовки
        default_ua = settings.get("http.default_user_agent", "XSS-Security-GUI/6.5")
        base_headers = {"User-Agent": default_ua}

        if headers:
            base_headers.update(headers)

        self.headers: Dict[str, str] = base_headers

    # ---------------------------------------------------------
    # HTTP-запрос (контракт TesterBase.send_request)
    # ---------------------------------------------------------
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

    # ---------------------------------------------------------
    # Анализ ответа (контракт TesterBase._analyze_response)
    # ---------------------------------------------------------
    def _analyze_response(
        self,
        text: str,
        headers_lower: Dict[str, str],
        response,
    ) -> Dict[str, Any]:

        # === Проверка отражения ===
        reflected = self._is_reflected(text, response.request.url)

        # === Контекст ===
        context_type, context_snippet = self._detect_context(text, reflected)

        # === Оценка риска ===
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

    # ---------------------------------------------------------
    # Вспомогательные методы
    # ---------------------------------------------------------
    def _is_reflected(self, html: str, url: str) -> bool:
        """Проверяет, отражён ли payload в HTML."""
        return self.base_value.lower() in html.lower() or self.base_value.lower() in url.lower()

    def _detect_context(self, html: str, reflected: bool):
        """Определяет контекст инъекции: HTML, JS, Attribute, URL."""
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

        # Контекст
        if "<script" in lower and p in lower:
            return "JS Context", snippet
        if f"=\"{p}\"" in lower or f"='{p}'" in lower:
            return "Attribute Injection", snippet
        if f">{p}<" in lower:
            return "HTML Body", snippet
        if f"url={p}" in lower or f"href={p}" in lower:
            return "URL Parameter", snippet

        return "Unknown", snippet

    @staticmethod
    def _assess_severity(reflected: bool, context_type: str) -> str:
        """Оценка риска по факту отражения и контексту."""
        if not reflected:
            return "INFO"
        if context_type in ("JS Context", "Attribute Injection"):
            return "HIGH"
        if context_type in ("HTML Body", "URL Parameter"):
            return "MEDIUM"
        return "LOW"