# xss_security_gui/threat_analysis/xss_module.py
import logging
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional

from xss_security_gui.threat_analysis.tester_base import TesterBase


class XSSTester(TesterBase):
    """
    Enterprise 6.0 XSS Tester
    -------------------------
    • Проверяет отражение XSS payload'ов
    • Определяет контекст (HTML, JS, Attribute, URL)
    • Возвращает унифицированный результат для Threat Intel
    """

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
        super().__init__("XSS", base_url, param, base_value, payloads, output_callback)
        self.timeout = timeout
        self.headers = headers or {"User-Agent": "XSS-Security-GUI/6.0"}

    def _test_single(self, category: str, payload: str, full_value: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat(),
            "module": "XSS",
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
            severity = "high" if reflected and context_type in ("JS Context", "Attribute Injection") else "info"

            result.update({
                "status": status,
                "severity": severity,
                "http_status": r.status_code,
                "response_length": len(text),
                "context_type": context_type,
                "context_snippet": context_snippet,
                "headers": dict(r.headers),
                "final_url": r.url
            })

            logging.debug(f"[XSSTester] {self.base_url} param={self.param} payload={payload} status={status}")
            return result

        except Exception as e:
            result.update({
                "status": "error",
                "severity": "error",
                "error": str(e),
                "response_length": 0
            })
            logging.error(f"[XSSTester] Ошибка при тестировании {self.base_url}: {e}")
            return result

    def _detect_context(self, html: str, payload: str) -> str:
        """
        Определяет контекст инъекции: HTML, JS, Attribute, URL.
        """
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