# xss_security_gui/threat_analysis/dom_events_module.py
"""
DOMEventMapper 11.0 — Combat Edition
====================================
• Розширений аналіз DOM‑подій у JS
• Виявлення небезпечних DOM‑синків (innerHTML, eval, write, insertAdjacentHTML, Function, setTimeout)
• Виявлення XSS‑синків (srcdoc, iframe, script injection)
• Виявлення SPA‑подій (Vue, React, Angular)
• Побудова карти подія → ризик → snippet → sinks
• Повністю ThreatConnector‑friendly артефакт
• Асинхронний запуск через ThreadWorker 10.0
• Без фризів, без падінь, без race‑conditions
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Callable

from xss_security_gui.utils.thread_worker import run_in_thread
from xss_security_gui.utils.safe_call import safe_invoke


class DOMEventMapper:
    """Бойовий модуль аналізу DOM‑подій та небезпечних JS‑конструкцій."""

    DEFAULT_EVENTS = [
        "click", "input", "submit", "mouseover", "keydown", "change",
        "keyup", "dblclick", "contextmenu", "touchstart", "touchend",
        "focus", "blur", "wheel", "scroll", "drag", "drop",
    ]

    DANGEROUS_SINKS = [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "document.writeln",
        "eval(",
        "Function(",
        "setTimeout(",
        "setInterval(",
        "srcdoc",
        "<iframe",
        "<script",
        "createElement('script'",
        "appendChild(script",
    ]

    SPA_PATTERNS = [
        "Vue.component",
        "new Vue",
        "ReactDOM.render",
        "useEffect(",
        "useState(",
        "angular.module",
        "ng-click",
        "ng-submit",
    ]

    def __init__(
        self,
        events: Optional[List[str]] = None,
        threat_connector: Any | None = None,
    ):
        self.events = events if events is not None else self.DEFAULT_EVENTS
        self.threat_connector = threat_connector

    # ---------------------------------------------------------
    # Основний аналіз
    # ---------------------------------------------------------
    def analyze(self, page_data: Dict[str, Any]) -> Dict[str, Any]:
        scripts = page_data.get("scripts", [])
        results: List[Dict[str, Any]] = []

        for script in scripts:
            code = script.get("content", "") or ""
            lower = code.lower()

            # === DOM Events ===
            for event_type in self.events:
                if event_type in lower:
                    sinks = self._find_sinks(code)
                    spa = self._find_spa(code)
                    risk = self._assess_risk(sinks, spa)

                    results.append({
                        "event": event_type,
                        "snippet": code[:300],
                        "sinks": sinks,
                        "spa": spa,
                        "risk": risk,
                    })

            # === Якщо немає подій, але є небезпечні синки ===
            sinks = self._find_sinks(code)
            spa = self._find_spa(code)
            if sinks or spa:
                results.append({
                    "event": None,
                    "snippet": code[:300],
                    "sinks": sinks,
                    "spa": spa,
                    "risk": self._assess_risk(sinks, spa),
                })

        artifact = {
            "module": "DOMEventMapper",
            "category": "dom_intel",
            "status": "success",
            "events_detected": len(results),
            "results": results,
        }

        # ThreatConnector інтеграція
        if self.threat_connector:
            try:
                self.threat_connector.add_artifact(artifact)
            except Exception:
                pass

        return artifact

    # ---------------------------------------------------------
    # Пошук небезпечних DOM‑синків
    # ---------------------------------------------------------
    def _find_sinks(self, code: str) -> List[str]:
        found = []
        lower = code.lower()

        for sink in self.DANGEROUS_SINKS:
            if sink.lower() in lower:
                found.append(sink)

        return found

    # ---------------------------------------------------------
    # Пошук SPA‑подій
    # ---------------------------------------------------------
    def _find_spa(self, code: str) -> List[str]:
        found = []
        lower = code.lower()

        for pattern in self.SPA_PATTERNS:
            if pattern.lower() in lower:
                found.append(pattern)

        return found

    # ---------------------------------------------------------
    # Оцінка ризику 11.0
    # ---------------------------------------------------------
    def _assess_risk(self, sinks: List[str], spa: List[str]) -> str:
        """
        Розширена логіка ризику:
        • CRITICAL — eval, Function, script injection, iframe injection
        • HIGH — innerHTML/outerHTML/insertAdjacentHTML + SPA
        • MEDIUM — innerHTML/outerHTML/insertAdjacentHTML без SPA
        • LOW — будь-які інші синки
        """

        sinks_lower = [s.lower() for s in sinks]

        # CRITICAL — прямі XSS‑синки
        if any(s in sinks_lower for s in ["eval(", "function(", "<script", "<iframe", "srcdoc"]):
            return "CRITICAL"

        # HIGH — DOM‑sink + SPA (реактивні фреймворки)
        if sinks and spa:
            return "HIGH"

        # MEDIUM — DOM‑sink без SPA
        if any(s in sinks_lower for s in ["innerhtml", "outerhtml", "insertadjacenthtml", "document.write"]):
            return "MEDIUM"

        # LOW — інші синки
        if sinks:
            return "LOW"

        return "LOW"

    # ---------------------------------------------------------
    # Асинхронний запуск через ThreadWorker
    # ---------------------------------------------------------
    def analyze_async(
        self,
        page_data: Dict[str, Any],
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:

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
            name="DOMEventMapper",
            on_success=on_success,
            on_progress=None,
            on_error=on_error,
            on_finally=None,
        )
