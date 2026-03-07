# xss_security_gui/threat_analysis/csrf_module.py
"""
CSRFTester (ULTRA Hybrid 6.5)
-----------------------------
• Проверяет наличие CSRF-защиты
• Анализирует заголовки и тело ответа
• Возвращает унифицированный результат для Threat Intel
"""

import requests
from datetime import datetime
from typing import Dict, Any

from xss_security_gui.threat_analysis.tester_base import TesterBase


class CSRFTester(TesterBase):
    """Модуль тестирования CSRF-защиты."""

    def __init__(self, base_url: str, param: str, base_value: str, payloads: Dict[str, list[str]], output_callback=None,
                 referer: str = "https://gazprombank.ru", origin: str = "https://gazprombank.ru"):
        super().__init__("CSRF", base_url, param, base_value, payloads, output_callback)
        self.referer = referer
        self.origin = origin

    def _test_single(self, category: str, payload: str, full_value: str) -> Dict[str, Any]:
        """Тестирует один CSRF payload."""
        try:
            headers = {
                "Referer": self.referer,
                "Origin": self.origin,
            }

            r = requests.get(
                self.base_url,
                params={self.param: full_value},
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
            )

            text = r.text.lower()
            hdr = {k.lower(): v.lower() for k, v in r.headers.items()}

            # === Индикаторы CSRF-уязвимости ===
            missing_samesite = "set-cookie" in hdr and "samesite" not in hdr.get("set-cookie", "")
            missing_csrf_header = "x-csrf-token" not in hdr
            missing_origin_check = r.status_code == 200 and "origin" not in hdr

            # === Подозрительные ключевые слова ===
            body_indicators = ["success", "done", "updated", "changed", "saved"]
            body_hit = any(x in text for x in body_indicators)

            # === Формирование severity ===
            severity = self._assess_severity(missing_samesite, missing_csrf_header, missing_origin_check, body_hit)

            result = self._format_result(
                category=category,
                payload=payload,
                severity=severity,
                details={
                    "timestamp": datetime.utcnow().isoformat(),
                    "http_status": r.status_code,
                    "response_length": len(r.text),
                    "headers": dict(r.headers),
                    "final_url": r.url,
                    "redirects": [h.url for h in r.history],
                    "body_hit": body_hit,
                },
            )

            self.logger.debug(f"[CSRFTester] {self.base_url} param={self.param} payload={payload} severity={severity}")
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
            self.logger.error(f"[CSRFTester] Ошибка при тестировании {self.base_url}: {e}")
            return result

    @staticmethod
    def _assess_severity(missing_samesite: bool, missing_csrf_header: bool, missing_origin_check: bool, body_hit: bool) -> str:
        """Оценка риска CSRF."""
        if missing_samesite or missing_csrf_header or body_hit:
            return "HIGH"
        if missing_origin_check:
            return "MEDIUM"
        return "LOW"