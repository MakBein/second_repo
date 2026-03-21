# xss_security_gui/threat_analysis/csp_module.py
"""
CSPAnalyzer (ULTRA Hybrid 6.5)
------------------------------
• Повний парсинг CSP (включно з nonce, hash, report-uri, report-to)
• Виявлення слабких місць у всіх ключових директивах
• Severity-оцінка у стилі ZAP / Mozilla Observatory
• Threat Intel-friendly структура
"""

from typing import Dict, Any, List


class CSPAnalyzer:
    """Поглиблений модуль аналізу CSP."""

    DEFAULT_WEAK_SOURCES = ["data:", "blob:", "*"]
    DEFAULT_DANGEROUS_FLAGS = ["'unsafe-inline'", "'unsafe-eval'"]
    REQUIRED_DIRECTIVES = [
        "default-src",
        "script-src",
        "object-src",
        "base-uri",
        "frame-ancestors",
    ]

    def __init__(
        self,
        threat_tab=None,
        weak_sources: List[str] | None = None,
        dangerous_flags: List[str] | None = None,
    ):
        self.threat_tab = threat_tab
        self.WEAK_SOURCES = weak_sources or self.DEFAULT_WEAK_SOURCES
        self.DANGEROUS_FLAGS = dangerous_flags or self.DEFAULT_DANGEROUS_FLAGS

    # ---------------------------------------------------------
    # Основний метод
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

        # === 1. Перевірка required-директив ===
        for required in self.REQUIRED_DIRECTIVES:
            if required not in directives:
                issues.append(f"MISSING: {required} directive missing")

        # === 2. Аналіз script-src ===
        script_src = directives.get("script-src") or directives.get("default-src") or []

        for flag in self.DANGEROUS_FLAGS:
            if flag in script_src:
                issues.append(f"DANGEROUS: {flag} detected")

        for weak in self.WEAK_SOURCES:
            if weak in script_src:
                issues.append(f"WEAK_SOURCE: script-src contains {weak}")

        # === 3. Аналіз object-src ===
        object_src = directives.get("object-src", [])
        if not object_src or object_src == ["*"]:
            issues.append("WEAK: object-src is missing or too permissive")

        # === 4. Аналіз base-uri ===
        base_uri = directives.get("base-uri", [])
        if not base_uri or "*" in base_uri:
            issues.append("WEAK: base-uri missing or wildcard")

        # === 5. Аналіз frame-ancestors ===
        frame_anc = directives.get("frame-ancestors", [])
        if not frame_anc or "*" in frame_anc:
            issues.append("WEAK: frame-ancestors missing or wildcard")

        # === 6. Mixed content ===
        if "upgrade-insecure-requests" not in directives:
            issues.append("MISSING: upgrade-insecure-requests")

        # === 7. Nonce/hash перевірка ===
        if not any("nonce-" in v or "sha256-" in v for v in script_src):
            issues.append("WEAK: no nonce/hash in script-src")

        # === 8. report-uri/report-to ===
        if "report-uri" not in directives and "report-to" not in directives:
            issues.append("INFO: no reporting endpoint configured")

        return issues

    # ---------------------------------------------------------
    # Severity логіка
    # ---------------------------------------------------------
    def _calculate_severity(self, issues: List[str]) -> str:
        if not issues:
            return "STRONG"
        if any("DANGEROUS" in i for i in issues):
            return "HIGH"
        if any("MISSING" in i for i in issues):
            return "HIGH"
        if any("WEAK" in i for i in issues):
            return "MEDIUM"
        return "LOW"

    # ---------------------------------------------------------
    # Threat Intel інтеграція
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