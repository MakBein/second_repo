# xss_security_gui/dom_xss_detector.py

from typing import List, Dict, Any
from bs4 import BeautifulSoup
import re


class DOMXSSDetector:
    """
    Примитивный DOM-XSS детектор по паттернам sink'ов и source'ов.
    """

    SINKS = [
        "innerHTML", "outerHTML", "insertAdjacentHTML",
        "document.write", "document.writeln",
        "eval(", "new Function", "setTimeout", "setInterval",
    ]

    SOURCES = [
        "location.hash", "location.search", "location.href",
        "document.URL", "document.documentURI",
        "window.name",
    ]

    def __init__(self, threat_tab=None):
        self.threat_tab = threat_tab

    def analyze_html(self, html: str, url: str = "") -> List[Dict[str, Any]]:
        soup = BeautifulSoup(html, "html.parser")
        findings: List[Dict[str, Any]] = []

        for script in soup.find_all("script"):
            code = script.string or ""
            code_lower = code.lower()

            has_sink = any(s.lower() in code_lower for s in self.SINKS)
            has_source = any(s.lower() in code_lower for s in self.SOURCES)

            if has_sink and has_source:
                snippet = self._extract_snippet(code)
                finding = {
                    "url": url,
                    "type": "DOM-XSS",
                    "sinks": [s for s in self.SINKS if s.lower() in code_lower],
                    "sources": [s for s in self.SOURCES if s.lower() in code_lower],
                    "snippet": snippet,
                    "severity": "high",
                }
                findings.append(finding)

                if self.threat_tab:
                    self.threat_tab.add_threat({
                        "type": "DOM-XSS",
                        "url": url,
                        "snippet": snippet,
                        "sources": finding["sources"],
                        "sinks": finding["sinks"],
                        "source": "DOMXSSDetector",
                    })

        return findings

    def _extract_snippet(self, code: str, window: int = 200) -> str:
        code = re.sub(r"\s+", " ", code)
        return code[:window]