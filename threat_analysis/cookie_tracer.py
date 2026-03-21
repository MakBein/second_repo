# xss_security_gui/threat_analysis/cookie_tracer.py
"""
CookieTracer (ULTRA Hybrid 6.5)
-------------------------------
• Анализирует утечки cookie в JS
• Проверяет наличие Secure/HttpOnly/SameSite/Path/Domain флагов
• Определяет опасные передачи cookie (XHR, fetch, sendBeacon)
• Возвращает унифицированный результат для Threat Intel
• Может работать в отдельном потоке
"""

import logging
import threading
from typing import Dict, Any, List
import re


class CookieTracer:
    """Модуль анализа утечек и флагов cookie (уровень ZAP/Burp)."""

    REQUIRED_FLAGS = ["secure", "httponly", "samesite"]
    OPTIONAL_FLAGS = ["path", "domain", "max-age", "expires"]

    JS_LEAK_PATTERNS = [
        r"document\.cookie",
        r"xhr\.setrequestheader\s*\(\s*['\"]cookie",
        r"fetch\s*\(.*cookie",
        r"sendBeacon\s*\(.*cookie",
        r"navigator\.sendBeacon",
        r"postMessage\s*\(.*cookie",
        r"websocket",
    ]

    def __init__(self, source_url: str = "unknown", threat_tab=None) -> None:
        self.source_url = source_url
        self.threat_tab = threat_tab

    # ---------------------------------------------------------
    # Основной анализ
    # ---------------------------------------------------------
    def run(self, page_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Анализирует cookies и JS.

        :param page_data: словарь с ключами "scripts" и "headers"
        :return: унифицированный результат анализа
        """
        scripts = page_data.get("scripts", [])
        headers = page_data.get("headers", {})

        js_code = "\n".join([s.get("content", "") for s in scripts])
        leaks = self._detect_js_leaks(js_code)

        cookie_header = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")
        cookie_flags = self._parse_cookie_flags(cookie_header)
        missing_flags = self._detect_missing_flags(cookie_flags)

        severity = self._assess_severity(leaks, missing_flags)

        result = {
            "module": "CookieTracer",
            "target": self.source_url,
            "leaks": leaks,
            "cookie_flags": cookie_flags,
            "missing_flags": missing_flags,
            "severity": severity,
            "status": "success",
        }

        logging.info(f"[CookieTracer] {self.source_url} → {severity}")

        if self.threat_tab:
            self.threat_tab.add_threat({
                "type": "COOKIE",
                "url": self.source_url,
                "severity": severity,
                "leaks": leaks,
                "missing_flags": missing_flags,
                "flags": cookie_flags,
                "source": "CookieTracer",
            })

        return result

    # ---------------------------------------------------------
    # JS leak detection
    # ---------------------------------------------------------
    def _detect_js_leaks(self, js: str) -> List[str]:
        leaks = []
        lower = js.lower()

        for pattern in self.JS_LEAK_PATTERNS:
            if re.search(pattern, lower, re.IGNORECASE):
                leaks.append(f"JS leak detected: {pattern}")

        return leaks

    # ---------------------------------------------------------
    # Cookie flag parsing
    # ---------------------------------------------------------
    def _parse_cookie_flags(self, cookie_header: str) -> List[str]:
        if not cookie_header:
            return []

        parts = [p.strip().lower() for p in cookie_header.split(";") if p.strip()]
        return parts

    # ---------------------------------------------------------
    # Missing flags detection
    # ---------------------------------------------------------
    def _detect_missing_flags(self, flags: List[str]) -> List[str]:
        missing = []

        for flag in self.REQUIRED_FLAGS:
            if not any(flag in f for f in flags):
                missing.append(f"missing {flag.capitalize()}")

        return missing

    # ---------------------------------------------------------
    # Severity logic (уровень ZAP)
    # ---------------------------------------------------------
    def _assess_severity(self, leaks: List[str], missing_flags: List[str]) -> str:
        if leaks and missing_flags:
            return "HIGH"
        if leaks or missing_flags:
            return "MEDIUM"
        return "LOW"

    # ---------------------------------------------------------
    # Threaded execution
    # ---------------------------------------------------------
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