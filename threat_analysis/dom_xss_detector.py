# xss_security_gui/threat_analysis/dom_xss_detector.py
"""
DOMXSSDetector
--------------
Примитивный DOM-XSS детектор по паттернам sink'ов и source'ов.
"""

from typing import List, Dict, Any
from bs4 import BeautifulSoup
import re


class DOMXSSDetector:
    """Анализатор DOM-XSS по ключевым источникам и точкам внедрения."""

    DEFAULT_SINKS = [
        "innerHTML", "outerHTML", "insertAdjacentHTML",
        "document.write", "document.writeln",
        "eval(", "new Function", "setTimeout", "setInterval",
    ]

    DEFAULT_SOURCES = [
        "location.hash", "location.search", "location.href",
        "document.URL", "document.documentURI",
        "window.name",
    ]

    def __init__(self, threat_tab=None, sinks: List[str] | None = None, sources: List[str] | None = None):
        self.threat_tab = threat_tab
        self.SINKS = sinks if sinks is not None else self.DEFAULT_SINKS
        self.SOURCES = sources if sources is not None else self.DEFAULT_SOURCES

    def analyze_html(self, html: str, url: str = "") -> List[Dict[str, Any]]:
        """
        Анализирует HTML на наличие DOM-XSS паттернов.

        :param html: HTML-код страницы
        :param url: URL страницы
        :return: список найденных уязвимостей
        """
        soup = BeautifulSoup(html, "html.parser")
        findings: List[Dict[str, Any]] = []

        for script in soup.find_all("script"):
            code = script.string or ""
            code_lower = code.lower()

            sinks = [s for s in self.SINKS if s.lower() in code_lower]
            sources = [s for s in self.SOURCES if s.lower() in code_lower]

            if sinks and sources:
                snippet = self._extract_snippet(code)
                severity = self._assess_severity(code)

                finding = {
                    "url": url,
                    "type": "DOM-XSS",
                    "sinks": sinks,
                    "sources": sources,
                    "snippet": snippet,
                    "severity": severity,
                }
                findings.append(finding)

                if self.threat_tab:
                    self.threat_tab.add_threat({
                        "type": "DOM-XSS",
                        "url": url,
                        "snippet": snippet,
                        "sources": sources,
                        "sinks": sinks,
                        "severity": severity,
                        "source": "DOMXSSDetector",
                    })

        return findings

    @staticmethod
    def _extract_snippet(code: str, window: int = 200) -> str:
        """Очищает и возвращает сниппет кода."""
        code = re.sub(r"\s+", " ", code)
        return code[:window]

    @staticmethod
    def _assess_severity(code: str) -> str:
        """Простейшая оценка риска."""
        if "eval(" in code or "new Function" in code:
            return "HIGH"
        elif "innerHTML" in code or "document.write" in code:
            return "MEDIUM"
        return "LOW"