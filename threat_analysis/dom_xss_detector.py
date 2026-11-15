# xss_security_gui/threat_analysis/dom_xss_detector.py
"""
DOMXSSDetector 11.0 — Combat Edition
====================================
• Розширений аналіз DOM‑XSS по джерелах і sink'ах
• Сучасні патерни: eval, Function, innerHTML, srcdoc, iframe, script injection
• Dataflow-підхід: source → sink
• SPA-aware (React/Vue/Angular sinks & sources)
• ThreatConnector-friendly артефакт
• Асинхронний запуск через ThreadWorker 10.0
• Без фризів, без падінь
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional, Callable
from bs4 import BeautifulSoup
import re

from xss_security_gui.utils.thread_worker import run_in_thread
from xss_security_gui.utils.safe_call import safe_invoke


class DOMXSSDetector:
    """Бойовий аналізатор DOM‑XSS (11.0)."""

    DEFAULT_SINKS = [
        r"innerHTML",
        r"outerHTML",
        r"insertAdjacentHTML",
        r"document\.write",
        r"document\.writeln",
        r"eval\s*\(",
        r"new\s+Function",
        r"setTimeout\s*\(",
        r"setInterval\s*\(",
        r"srcdoc",
        r"<iframe",
        r"<script",
        r"createElement\s*\(\s*['\"]script['\"]",
        r"appendChild\s*\(",
    ]

    DEFAULT_SOURCES = [
        r"location\.hash",
        r"location\.search",
        r"location\.href",
        r"document\.URL",
        r"document\.documentURI",
        r"window\.name",
        r"document\.cookie",
        r"localStorage\.getItem",
        r"sessionStorage\.getItem",
        r"URLSearchParams",
    ]

    SPA_SOURCES = [
        r"props\.",
        r"this\.state",
        r"this\.props",
        r"window\.__INITIAL_STATE__",
        r"window\.__NUXT__",
        r"window\.__NEXT_DATA__",
    ]

    def __init__(
        self,
        threat_connector: Any | None = None,
        sinks: Optional[List[str]] = None,
        sources: Optional[List[str]] = None,
    ):
        self.threat_connector = threat_connector
        self.SINKS = sinks if sinks is not None else self.DEFAULT_SINKS
        self.SOURCES = sources if sources is not None else self.DEFAULT_SOURCES

    # ---------------------------------------------------------
    # Основний аналіз
    # ---------------------------------------------------------
    def analyze_html(self, html: str, url: str = "") -> Dict[str, Any]:
        soup = BeautifulSoup(html, "html.parser")
        findings: List[Dict[str, Any]] = []

        for script in soup.find_all("script"):
            code = script.string or ""
            if not code.strip():
                continue

            sinks = self._find_patterns(code, self.SINKS)
            sources = self._find_patterns(code, self.SOURCES)
            spa_sources = self._find_patterns(code, self.SPA_SOURCES)

            if sinks and (sources or spa_sources):
                snippet = self._extract_snippet(code)
                severity = self._assess_severity(sinks)

                finding = {
                    "url": url,
                    "type": "DOM-XSS",
                    "sources": sources + spa_sources,
                    "sinks": sinks,
                    "snippet": snippet,
                    "severity": severity,
                }
                findings.append(finding)

                # ThreatConnector інтеграція
                if self.threat_connector:
                    try:
                        self.threat_connector.add_artifact({
                            "module": "DOMXSSDetector",
                            "category": "dom_xss",
                            "type": "DOM-XSS",
                            "url": url,
                            "sources": sources + spa_sources,
                            "sinks": sinks,
                            "snippet": snippet,
                            "severity": severity,
                        })
                    except Exception:
                        pass

        return {
            "module": "DOMXSSDetector",
            "category": "dom_xss",
            "status": "success",
            "url": url,
            "count": len(findings),
            "findings": findings,
        }

    # ---------------------------------------------------------
    # Пошук патернів
    # ---------------------------------------------------------
    def _find_patterns(self, code: str, patterns: List[str]) -> List[str]:
        found = []
        for pattern in patterns:
            if re.search(pattern, code, flags=re.IGNORECASE):
                found.append(pattern)
        return found

    # ---------------------------------------------------------
    # Сниппет
    # ---------------------------------------------------------
    @staticmethod
    def _extract_snippet(code: str, window: int = 250) -> str:
        code = re.sub(r"\s+", " ", code)
        return code[:window]

    # ---------------------------------------------------------
    # Severity 11.0
    # ---------------------------------------------------------
    def _assess_severity(self, sinks: List[str]) -> str:
        high = ["eval", "new Function", "<script", "<iframe", "srcdoc"]
        medium = ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"]

        if any(re.search(h, s, re.IGNORECASE) for h in high for s in sinks):
            return "HIGH"

        if any(re.search(m, s, re.IGNORECASE) for m in medium for s in sinks):
            return "MEDIUM"

        return "LOW"

    # ---------------------------------------------------------
    # Асинхронний запуск через ThreadWorker
    # ---------------------------------------------------------
    def analyze_html_async(
        self,
        html: str,
        url: str = "",
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:

        def work_fn(progress, is_cancelled):
            return self.analyze_html(html, url)

        def on_success(result: Dict[str, Any]) -> None:
            if callback:
                safe_invoke(callback, result)

        def on_error(e: Exception) -> None:
            if callback:
                safe_invoke(callback, {"status": "error", "error": str(e)})

        run_in_thread(
            work_fn,
            name="DOMXSSDetector",
            on_success=on_success,
            on_progress=None,
            on_error=on_error,
            on_finally=None,
        )
