# xss_security_gui/threat_analysis/csp_module.py

from typing import Dict, Any, List


class CSPAnalyzer:
    """
    CSPAnalyzer 2.0
    ----------------
    Покращений аналізатор Content-Security-Policy з:
    • повним парсингом директив
    • визначенням слабких місць
    • severity-оцінкою
    • Threat Intel-friendly структурою
    """

    WEAK_SOURCES = ["data:", "blob:", "*"]
    DANGEROUS_FLAGS = ["'unsafe-inline'", "'unsafe-eval'"]

    def __init__(self, threat_tab=None):
        self.threat_tab = threat_tab

    # ---------------------------------------------------------
    # Основний метод
    # ---------------------------------------------------------
    def run(self, page_data: Dict[str, Any]) -> Dict[str, Any]:
        headers = page_data.get("headers", {})
        csp = headers.get("Content-Security-Policy", "")

        if not csp:
            result = {
                "present": False,
                "severity": "critical",
                "issues": ["CSP header missing"],
                "directives": {},
                "raw": ""
            }
            self._report(result)
            return result

        directives = self._parse_csp(csp)
        issues = self._analyze_directives(directives)

        severity = self._calculate_severity(issues)

        result = {
            "present": True,
            "severity": severity,
            "issues": issues,
            "directives": directives,
            "raw": csp
        }

        self._report(result)
        return result

    # ---------------------------------------------------------
    # Парсинг CSP у dict
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
    # Аналіз директив
    # ---------------------------------------------------------
    def _analyze_directives(self, directives: Dict[str, List[str]]) -> List[str]:
        issues = []

        script_src = directives.get("script-src") or directives.get("default-src") or []

        # Небезпечні флаги
        for flag in self.DANGEROUS_FLAGS:
            if flag in script_src:
                issues.append(f"DANGEROUS: {flag} detected")

        # Нестабільні джерела
        for weak in self.WEAK_SOURCES:
            if weak in script_src:
                issues.append(f"WEAK_SOURCE: script-src contains {weak}")

        # Відсутність script-src
        if "script-src" not in directives:
            issues.append("MISSING: script-src directive missing")

        # Відсутність object-src (важливо для XSS)
        if "object-src" not in directives:
            issues.append("MISSING: object-src directive missing")

        # Відсутність base-uri
        if "base-uri" not in directives:
            issues.append("MISSING: base-uri directive missing")

        # Відсутність frame-ancestors
        if "frame-ancestors" not in directives:
            issues.append("MISSING: frame-ancestors directive missing")

        return issues

    # ---------------------------------------------------------
    # Severity логіка
    # ---------------------------------------------------------
    def _calculate_severity(self, issues: List[str]) -> str:
        if not issues:
            return "strong"

        if any("DANGEROUS" in i for i in issues):
            return "high"

        if any("WEAK_SOURCE" in i for i in issues):
            return "medium"

        if any("MISSING" in i for i in issues):
            return "medium"

        return "low"

    # ---------------------------------------------------------
    # Threat Intel інтеграція
    # ---------------------------------------------------------
    def _report(self, result: Dict[str, Any]):
        if not self.threat_tab:
            return

        self.threat_tab.add_threat({
            "type": "CSP",
            "severity": result["severity"],
            "issues": result["issues"],
            "directives": result["directives"],
            "raw": result["raw"],
            "source": "CSPAnalyzer"
        })