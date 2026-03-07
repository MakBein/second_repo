# xss_security_gui/threat_analysis/xss_module.py
"""
XSSTester (ULTRA Hybrid 6.5)
----------------------------
• Проверяет отражение XSS payload'ов
• Определяет контекст (HTML, JS, Attribute, URL)
• Использует гибридные настройки из settings.py
"""

from datetime import datetime
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
        super().__init__("XSS", base_url, param, base_value, {"default": payloads}, output_callback)

        # Таймаут из гибридных настроек (http.request_timeout) или fallback
        self.timeout: int = timeout or int(settings.get("http.request_timeout", 7))

        # User-Agent и заголовки из настроек
        default_ua = settings.get("http.default_user_agent", "XSS-Security-GUI/6.5")
        base_headers = {"User-Agent": default_ua}

        if headers:
            base_headers.update(headers)

        self.headers: Dict[str, str] = base_headers

    def _test_single(self, category: str, payload: str, full_value: str) -> Dict[str, Any]:
        """Тестирует один XSS payload."""
        try:
            r = requests.get(
                self.base_url,
                params={self.param: full_value},
                timeout=self.timeout,
                headers=self.headers,
                allow_redirects=True,
            )

            text = r.text
            reflected = payload.lower() in text.lower()

            # === Контекст отображения ===
            context_snippet = None
            index = text.lower().find(payload.lower())
            if index != -1:
                start = max(0, index - 80)
                end = min(len(text), index + len(payload) + 80)
                context_snippet = text[start:end]

            # === Тип контекста ===
            context_type = self._detect_context(text, payload)

            status = "reflected" if reflected else "not reflected"
            severity = self._assess_severity(reflected, context_type)

            result = self._format_result(
                category=category,
                payload=payload,
                severity=severity,
                details={
                    "timestamp": datetime.utcnow().isoformat(),
                    "status": status,
                    "http_status": r.status_code,
                    "response_length": len(text),
                    "context_type": context_type,
                    "context_snippet": context_snippet,
                    "headers": dict(r.headers),
                    "final_url": r.url,
                },
            )

            self.logger.debug(
                f"[XSSTester] {self.base_url} param={self.param} "
                f"payload={payload} status={status} context={context_type}"
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
            self.logger.error(f"[XSSTester] Ошибка при тестировании {self.base_url}: {e}")
            return result

    def _detect_context(self, html: str, payload: str) -> str:
        """Определяет контекст инъекции: HTML, JS, Attribute, URL."""
        lower = html.lower()
        p = payload.lower()

        if "<script" in lower and p in lower:
            return "JS Context"
        if f"=\"{p}\"" in lower or f"='{p}'" in lower:
            return "Attribute Injection"
        if f">{p}<" in lower:
            return "HTML Body"
        if f"url={p}" in lower or f"href={p}" in lower:
            return "URL Parameter"
        return "Unknown"

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