# xss_security_gui/threat_analysis/cookie_tracer.py

import logging
import threading
from typing import Dict, Any, List


class CookieTracer:
    """
    Enterprise 6.0 Cookie Tracer
    ----------------------------
    • Анализирует утечки cookie в JS
    • Проверяет наличие Secure/HttpOnly/SameSite флагов
    • Возвращает унифицированный результат для Threat Intel
    • Может работать в отдельном потоке для мониторинга
    """

    def __init__(self, source_url: str = "unknown"):
        self.source_url = source_url

    def run(self, page_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Запускает анализ cookies и JS.
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

        insecure_flags = []
        if cookies:
            if not any("secure" in f for f in flags):
                insecure_flags.append("missing Secure")
            if not any("httponly" in f for f in flags):
                insecure_flags.append("missing HttpOnly")
            if not any("samesite" in f for f in flags):
                insecure_flags.append("missing SameSite")

        result = {
            "module": "CookieTracer",
            "target": self.source_url,
            "leaks": leaks,
            "cookie_flags": flags,
            "missing_flags": insecure_flags,
            "status": "potential risk" if leaks or insecure_flags else "secure"
        }

        logging.info(f"[CookieTracer] {self.source_url} → {result['status']}")
        return result

    def run_in_thread(self, page_data: Dict[str, Any], callback: callable = None) -> threading.Thread:
        """
        Запускает CookieTracer в отдельном потоке.
        """
        def worker():
            result = self.run(page_data)
            if callback:
                callback(result)

        t = threading.Thread(target=worker, daemon=True, name="CookieTracerThread")
        t.start()
        return t