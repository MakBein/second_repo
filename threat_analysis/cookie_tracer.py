# xss_security_gui/threat_analysis/cookie_tracer.py
"""
CookieTracer
------------
Enterprise 6.0 Cookie Tracer:
• Анализирует утечки cookie в JS
• Проверяет наличие Secure/HttpOnly/SameSite флагов
• Возвращает унифицированный результат для Threat Intel
• Может работать в отдельном потоке для мониторинга
"""

import logging
import threading
from typing import Dict, Any, List


class CookieTracer:
    """Модуль анализа утечек и флагов cookie."""

    REQUIRED_FLAGS = ["secure", "httponly", "samesite"]

    def __init__(self, source_url: str = "unknown") -> None:
        self.source_url = source_url

    def run(self, page_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Запускает анализ cookies и JS.

        :param page_data: словарь с ключами "scripts" и "headers"
        :return: унифицированный результат анализа
        """
        js = "\n".join([s.get("content", "") for s in page_data.get("scripts", [])])
        leaks: List[str] = []

        # === JS утечки ===
        if "document.cookie" in js:
            leaks.append("❗ JS читает cookie напрямую")
        if "xhr.setrequestheader('cookie'" in js.lower():
            leaks.append("⚠️ Передача cookie через XHR")
        if ".send(" in js.lower() and "cookie" in js.lower():
            leaks.append("⚠️ Cookie передаются через XHR.send")

        # === Cookie флаги ===
        cookies = page_data.get("headers", {}).get("Set-Cookie", "")
        flags = [f.strip().lower() for f in cookies.split(";") if f]

        missing_flags = []
        if cookies:
            for flag in self.REQUIRED_FLAGS:
                if not any(flag in f for f in flags):
                    missing_flags.append(f"missing {flag.capitalize()}")

        severity = self._assess_severity(leaks, missing_flags)

        result = {
            "module": "CookieTracer",
            "target": self.source_url,
            "leaks": leaks,
            "cookie_flags": flags,
            "missing_flags": missing_flags,
            "severity": severity,
            "status": "success",
        }

        logging.info(f"[CookieTracer] {self.source_url} → {severity}")
        return result

    def run_in_thread(self, page_data: Dict[str, Any], callback: callable = None) -> threading.Thread:
        """
        Запускает CookieTracer в отдельном потоке.

        :param page_data: данные страницы
        :param callback: функция для обработки результата
        :return: объект Thread
        """
        def worker():
            try:
                result = self.run(page_data)
                if callback:
                    callback(result)
            except Exception as e:
                if callback:
                    callback({"status": "error", "error": str(e)})

        t = threading.Thread(target=worker, daemon=True, name="CookieTracerThread")
        t.start()
        return t

    @staticmethod
    def _assess_severity(leaks: List[str], missing_flags: List[str]) -> str:
        """Оценка риска по утечкам и отсутствующим флагам."""
        if leaks and missing_flags:
            return "HIGH"
        elif leaks or missing_flags:
            return "MEDIUM"
        return "LOW"