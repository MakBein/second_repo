# xss_security_gui/threat_analysis/csp_module.py
"""
CSPAnalyzer 11.0 — Combat Edition
=================================
• Повний парсинг CSP (nonce, hash, report-uri, report-to)
• Виявлення слабких місць у ключових директивах
• Severity-оцінка у стилі ZAP / Mozilla Observatory
• ThreatConnector / Threat Intel-friendly структура
• Підтримка асинхронного запуску (ThreadWorker 10.0)
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional, Callable

from xss_security_gui.utils.thread_worker import run_in_thread
from xss_security_gui.utils.safe_call import safe_invoke


class CSPAnalyzer:
    """Поглиблений модуль аналізу CSP (11.0, ThreatConnector-ready)."""

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
        threat_connector: Any | None = None,
        weak_sources: Optional[List[str]] = None,
        dangerous_flags: Optional[List[str]] = None,
    ):
        self.threat_connector = threat_connector
        self.WEAK_SOURCES = weak_sources or self.DEFAULT_WEAK_SOURCES
        self.DANGEROUS_FLAGS = dangerous_flags or self.DEFAULT_DANGEROUS_FLAGS

    # ---------------------------------------------------------
    # Основний метод
    # ---------------------------------------------------------
    def analyze(self, page_data: Dict[str, Any]) -> Dict[str, Any]:
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
                "category": "csp_intel",
                "module": "CSPAnalyzer",
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
            "category": "csp_intel",
            "module": "CSPAnalyzer",
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
        issues: List[str] = []

        # 1. Required директиви
        for required in self.REQUIRED_DIRECTIVES:
            if required not in directives:
                issues.append(f"MISSING: {required} directive missing")

        # 2. script-src / default-src
        script_src = directives.get("script-src") or directives.get("default-src") or []

        for flag in self.DANGEROUS_FLAGS:
            if flag in script_src:
                issues.append(f"DANGEROUS: {flag} detected")

        for weak in self.WEAK_SOURCES:
            if weak in script_src:
                issues.append(f"WEAK_SOURCE: script-src contains {weak}")

        # 3. object-src
        object_src = directives.get("object-src", [])
        if not object_src or object_src == ["*"]:
            issues.append("WEAK: object-src is missing or too permissive")

        # 4. base-uri
        base_uri = directives.get("base-uri", [])
        if not base_uri or "*" in base_uri:
            issues.append("WEAK: base-uri missing or wildcard")

        # 5. frame-ancestors
        frame_anc = directives.get("frame-ancestors", [])
        if not frame_anc or "*" in frame_anc:
            issues.append("WEAK: frame-ancestors missing or wildcard")

        # 6. Mixed content
        if "upgrade-insecure-requests" not in directives:
            issues.append("MISSING: upgrade-insecure-requests")

        # 7. nonce/hash
        if not any("nonce-" in v or "sha256-" in v or "sha384-" in v or "sha512-" in v for v in script_src):
            issues.append("WEAK: no nonce/hash in script-src")

        # 8. reporting
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
    # ThreatConnector інтеграція
    # ---------------------------------------------------------
    def _report(self, result: Dict[str, Any]) -> None:
        if not self.threat_connector:
            return

        try:
            self.threat_connector.add_artifact({
                "type": "CSP",
                "category": "csp_intel",
                "severity": result["severity"],
                "issues": result["issues"],
                "directives": result["directives"],
                "raw": result["raw"],
                "source": "CSPAnalyzer",
            })
        except Exception:
            pass

    # ---------------------------------------------------------
    # Async / ThreadWorker інтеграція
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
            name="CSPAnalyzer",
            on_success=on_success,
            on_progress=None,
            on_error=on_error,
            on_finally=None,
        )
