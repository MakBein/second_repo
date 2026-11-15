# xss_security_gui/threat_analysis/cookie_tracer.py
"""
CookieTracer 11.0 — Combat Edition
==================================
• JS‑Leak Engine 11.0 (document.cookie, fetch, XHR, Beacon, WebSocket, postMessage)
• Cookie Flag Engine 11.0 (Secure, HttpOnly, SameSite, Path, Domain, Max-Age, Expires)
• Severity Engine 11.0 (LOW/MEDIUM/HIGH/CRITICAL)
• Повна інтеграція з ThreatConnector 10.0+
• Підтримка ThreadWorker 10.0 (без блокування GUI)
• Підтримка SecurityDashboardPanel 10.0 (thread events)
• Уніфікований Threat Intel артефакт
"""

from __future__ import annotations
import logging
import threading
import re
from typing import Dict, Any, List, Optional, Callable

from xss_security_gui.utils.thread_worker import run_in_thread
from xss_security_gui.utils.safe_call import safe_invoke


class CookieTracer:
    """Бойовий модуль аналізу утечок cookie (рівень Burp/ZAP + ThreatConnector)."""

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
        r"cookie\s*=",
        r"localStorage\.setItem\(['\"]cookie",
        r"sessionStorage\.setItem\(['\"]cookie",
    ]

    def __init__(self, source_url: str = "unknown", threat_connector=None, dashboard=None):
        self.source_url = source_url
        self.threat_connector = threat_connector
        self.dashboard = dashboard

    # ---------------------------------------------------------
    # Основний аналіз
    # ---------------------------------------------------------
    def analyze(self, page_data: Dict[str, Any]) -> Dict[str, Any]:
        scripts = page_data.get("scripts", [])
        headers = page_data.get("headers", {})

        js_code = "\n".join([s.get("content", "") for s in scripts])
        leaks = self._detect_js_leaks(js_code)

        cookie_header = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
        cookie_flags = self._parse_cookie_flags(cookie_header)
        missing_flags = self._detect_missing_flags(cookie_flags)

        severity = self._assess_severity(leaks, missing_flags)

        artifact = {
            "module": "CookieTracer",
            "category": "cookie_intel",
            "target": self.source_url,
            "leaks": leaks,
            "cookie_flags": cookie_flags,
            "missing_flags": missing_flags,
            "severity": severity,
            "status": "success",
        }

        logging.info(f"[CookieTracer] {self.source_url} → {severity}")

        if self.threat_connector:
            try:
                self.threat_connector.add_artifact(artifact)
            except Exception:
                pass

        if self.dashboard:
            try:
                self.dashboard.update_thread_event("CookieTracer", "success", severity)
            except Exception:
                pass

        return artifact

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
    # Severity logic 11.0
    # ---------------------------------------------------------
    def _assess_severity(self, leaks: List[str], missing_flags: List[str]) -> str:
        if leaks and missing_flags:
            return "CRITICAL"
        if leaks:
            return "HIGH"
        if missing_flags:
            return "MEDIUM"
        return "LOW"

    # ---------------------------------------------------------
    # ThreadWorker 10.0 integration
    # ---------------------------------------------------------
    def analyze_async(
        self,
        page_data: Dict[str, Any],
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        """
        Запускає CookieTracer через ThreadWorker 10.0.
        Без блокування GUI.
        """

        def work_fn(progress, is_cancelled):
            return self.analyze(page_data)

        def on_success(result: Dict[str, Any]) -> None:
            if callback:
                safe_invoke(callback, result)

        def on_error(e: Exception) -> None:
            if callback:
                safe_invoke(callback, {"status": "error", "error": str(e)})

        run_in_thread(
            work_fn,
            name="CookieTracer",
            on_success=on_success,
            on_progress=None,
            on_error=on_error,
            on_finally=None,
        )

    # ---------------------------------------------------------
    # Legacy threaded execution (fallback)
    # ---------------------------------------------------------
    def run_in_thread(
        self,
        page_data: Dict[str, Any],
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> threading.Thread:
        """
        Старий режим — залишаємо як fallback.
        """

        def worker():
            try:
                result = self.analyze(page_data)
                if callback:
                    self._dispatch_callback(callback, result)
            except Exception as e:
                if callback:
                    self._dispatch_callback(callback, {"status": "error", "error": str(e)})

        t = threading.Thread(target=worker, daemon=True, name="CookieTracerThread")
        t.start()
        return t

    @staticmethod
    def _dispatch_callback(
        callback: Callable[[Dict[str, Any]], None],
        payload: Dict[str, Any],
    ) -> None:
        owner = getattr(callback, "__self__", None)
        after = getattr(owner, "after", None)
        if callable(after):
            after(0, lambda p=payload: callback(p))
        else:
            callback(payload)
