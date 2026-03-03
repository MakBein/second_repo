# xss_security_gui/threat_analysis/csp_module.py
"""
CSPAnalyzer 2.1
---------------
Анализатор Content-Security-Policy:
• Полный парсинг директив
• Определение слабых мест
• Severity-оценка
• Threat Intel-friendly структура
"""

from typing import Dict, Any, List


class CSPAnalyzer:
    """Модуль анализа CSP-заголовков."""

    DEFAULT_WEAK_SOURCES = ["data:", "blob:", "*"]
    DEFAULT_DANGEROUS_FLAGS = ["'unsafe-inline'", "'unsafe-eval'"]

    def __init__(self, threat_tab=None, weak_sources: List[str] | None = None, dangerous_flags: List[str] | None = None):
        self.threat_tab = threat_tab
        self.WEAK_SOURCES = weak_sources if weak_sources is not None else self.DEFAULT_WEAK_SOURCES
        self.DANGEROUS_FLAGS = dangerous_flags if dangerous_flags is not None else self.DEFAULT_DANGEROUS_FLAGS

    # ---------------------------------------------------------
    # Основной метод
    # ---------------------------------------------------------
    def run(self, page_data: Dict[str, Any]) -> Dict[str, Any]:
        headers = page_data.get("headers", {})
        csp = headers.get("Content-Security-Policy", "")

        if not csp:
            result = {
                "status": "success",
                "present": False,
                "severity": "CRITICAL",
                "issues": ["CSP header missing"],
                "directives": {},
                "raw": "",
            }
            self._report(result)
            return result

        directives = self._parse_csp(csp)
        issues = self._analyze_directives(directives)
        severity = self._calculate_severity(issues)

        result = {
            "status": "success",
            "present": True,
            "severity": severity,
            "issues": issues,
            "directives": directives,
            "raw": csp,
        }

        self._report(result)
        return result

    # ---------------------------------------------------------
    # Парсинг CSP в dict
    # ---------------------------------------------------------
    def _parse_csp(self, header: str) -> Dict[str, List[str]]:
        directives: Dict[str, List[str]] = {}
        parts = [p.strip() for p in header.split(";") if p.strip()]

        for part in parts:
            tokens = part.split()
            if not tokens:
                continue
            name = tokens[0].lower()
            values = tokens[1:]
            directives[name] = values

        return directives

    # ---------------------------------------------------------
    # Анализ директив
    # ---------------------------------------------------------
    def _analyze_directives(self, directives: Dict[str, List[str]]) -> List[str]:
        issues = []
        script_src = directives.get("script-src") or directives.get("default-src") or []

        # Опасные флаги
        for flag in self.DANGEROUS_FLAGS:
            if flag in script_src:
                issues.append(f"DANGEROUS: {flag} detected")

        # Слабые источники
        for weak in self.WEAK_SOURCES:
            if weak in script_src:
                issues.append(f"WEAK_SOURCE: script-src contains {weak}")

        # Критичные отсутствующие директивы
        for required in ["script-src", "object-src", "base-uri", "frame-ancestors"]:
            if required not in directives:
                issues.append(f"MISSING: {required} directive missing")

        return issues

    # ---------------------------------------------------------
    # Severity логика
    # ---------------------------------------------------------
    def _calculate_severity(self, issues: List[str]) -> str:
        if not issues:
            return "STRONG"
        if any("DANGEROUS" in i for i in issues):
            return "HIGH"
        if any("WEAK_SOURCE" in i for i in issues):
            return "MEDIUM"
        if any("MISSING" in i for i in issues):
            return "MEDIUM"
        return "LOW"

    # ---------------------------------------------------------
    # Threat Intel интеграция
    # ---------------------------------------------------------
    def _report(self, result: Dict[str, Any]) -> None:
        if not self.threat_tab:
            return

        self.threat_tab.add_threat({
            "type": "CSP",
            "severity": result["severity"],
            "issues": result["issues"],
            "directives": result["directives"],
            "raw": result["raw"],
            "source": "CSPAnalyzer",
        })