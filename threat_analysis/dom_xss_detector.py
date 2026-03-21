# xss_security_gui/threat_analysis/dom_xss_detector.py
"""
DOMXSSDetector (ULTRA Hybrid 6.5)
---------------------------------
• Анализ DOM-XSS по источникам и sink'ам
• Расширенные паттерны (eval, innerHTML, insertAdjacentHTML, write)
• Dataflow-подход: source → sink
• Threat Intel-friendly структура
"""

from typing import List, Dict, Any
from bs4 import BeautifulSoup
import re


class DOMXSSDetector:
    """Анализатор DOM-XSS по ключевым источникам и точкам внедрения."""

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
    ]

    DEFAULT_SOURCES = [
        r"location\.hash",
        r"location\.search",
        r"location\.href",
        r"document\.URL",
        r"document\.documentURI",
        r"window\.name",
        r"document\.cookie",
    ]

    def __init__(
        self,
        threat_tab=None,
        sinks: List[str] | None = None,
        sources: List[str] | None = None,
    ):
        self.threat_tab = threat_tab
        self.SINKS = sinks if sinks is not None else self.DEFAULT_SINKS
        self.SOURCES = sources if sources is not None else self.DEFAULT_SOURCES

    # ---------------------------------------------------------
    # Основной метод
    # ---------------------------------------------------------
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
            if not code.strip():
                continue

            sinks = self._find_patterns(code, self.SINKS)
            sources = self._find_patterns(code, self.SOURCES)

            if sinks and sources:
                snippet = self._extract_snippet(code)
                severity = self._assess_severity(sinks)

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

    # ---------------------------------------------------------
    # Поиск паттернов (RegExp)
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
    def _extract_snippet(code: str, window: int = 200) -> str:
        code = re.sub(r"\s+", " ", code)
        return code[:window]

    # ---------------------------------------------------------
    # Severity логика (уровень ZAP/Burp)
    # ---------------------------------------------------------
    def _assess_severity(self, sinks: List[str]) -> str:
        high = ["eval", "new Function"]
        medium = ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"]

        if any(re.search(h, s, re.IGNORECASE) for h in high for s in sinks):
            return "HIGH"

        if any(re.search(m, s, re.IGNORECASE) for m in medium for s in sinks):
            return "MEDIUM"

        return "LOW"