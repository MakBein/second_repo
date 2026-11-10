# xss_security_gui/auto_recon/analyzer.py
import logging
import time
import json
import os
from typing import List, Dict, Any, Callable, Optional

from xss_security_gui.threat_analysis.threat_connector import ThreatConnector
from xss_security_gui.threat_analysis.csp_module import CSPAnalyzer
from xss_security_gui.threat_analysis.dom_xss_detector import DOMXSSDetector
from xss_security_gui.threat_analysis.csrf_analyzer import CSRFAnalyzer
from xss_security_gui.threat_analysis.sqli_module import SQLiTester
from xss_security_gui.threat_analysis.ssrf_module import SSRFTester

from xss_security_gui.auto_recon.token_extractor import (
    extract_tokens,
    analyze_tokens,
    save_token_log,
)

from xss_security_gui import DIRS

log = logging.getLogger("AutoReconAnalyzerV2")


def analyze_page(html: str, url: str) -> dict:
    lower = html.lower()
    return {
        "url": url,
        "length": len(html),
        "has_script": "<script" in lower,
        "has_form": "<form" in lower,
        "keywords": [k for k in ["login", "password", "token", "auth"] if k in lower],
    }


def analyze_structure(html: str) -> dict:
    lower = html.lower()
    return {
        "tags": {
            "div": lower.count("<div"),
            "script": lower.count("<script"),
            "form": lower.count("<form"),
            "input": lower.count("<input"),
            "a": lower.count("<a "),
        }
    }


class AutoReconAnalyzerV2:
    """
    Enterprise 6.0 AutoRecon Analyzer (Red Team hardened)

    • Объединяет CSP, DOM-XSS, CSRF, SQLi, SSRF, Tokens, Headers
    • Каждому модулю даёт свой try/except (изолированные ошибки)
    • Логирует всё в NDJSON + ThreatConnector
    • Никогда не роняет вызывающий код (GUI / AutoRecon RT)
    """

    def __init__(self, threat_connector: ThreatConnector, active_testing: bool = False):
        self.connector = threat_connector
        self.active_testing = active_testing is True

        self.token_report: List[Dict[str, Any]] = []
        self.csrf_report: List[Dict[str, Any]] = []
        self.sqli_report: List[Dict[str, Any]] = []
        self.ssrf_report: List[Dict[str, Any]] = []
        self.dom_xss_report: List[Dict[str, Any]] = []
        self.csp_report: List[Dict[str, Any]] = []
        self.security_headers_report: List[Dict[str, Any]] = []
        self.page_report: List[Dict[str, Any]] = []
        self.structure_report: List[Dict[str, Any]] = []

        self.csp_analyzer = CSPAnalyzer(threat_tab=self.connector)
        self.dom_analyzer = DOMXSSDetector(threat_tab=self.connector)

        self.log_path = os.path.join(DIRS["logs"], "analysis_results.ndjson")
        os.makedirs(DIRS["logs"], exist_ok=True)

    def _log_ndjson(self, entry: dict) -> None:
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            log.error(f"[AutoReconAnalyzerV2] NDJSON log error: {e}", exc_info=True)

    def _safe_add_artifact(self, module: str, url: str, artifacts: List[Dict[str, Any]]) -> None:
        try:
            self.connector.add_artifact(module, url, artifacts)
        except Exception as e:
            log.error(f"[AutoReconAnalyzerV2] ThreatConnector error for {module}: {e}", exc_info=True)

    def analyze_security_headers(self, headers: dict) -> dict:
        return {
            "x_frame_options": headers.get("X-Frame-Options"),
            "x_content_type_options": headers.get("X-Content-Type-Options"),
            "referrer_policy": headers.get("Referrer-Policy"),
            "permissions_policy": headers.get("Permissions-Policy"),
            "strict_transport_security": headers.get("Strict-Transport-Security"),
        }

    def analyze(
        self,
        responses: List[Dict[str, Any]],
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        total_pages = len(responses)

        def report(status: str, url: str, index: int, **details: Any) -> None:
            if not progress_callback:
                return
            try:
                progress_callback(
                    {
                        "stage": "ANALYZING",
                        "status": status,
                        "details": {
                            "page": index,
                            "pages": total_pages,
                            "url": url,
                            **details,
                        },
                    }
                )
            except Exception as e:
                log.error(f"[AutoReconAnalyzerV2] Progress callback error: {e}", exc_info=True)

        for index, r in enumerate(responses, start=1):
            start = time.time()
            url = r.get("url", "")
            text = r.get("text", "") or ""
            headers = r.get("headers", {}) or {}

            report("page_started", url, index)
            result_entry: Dict[str, Any] = {"url": url, "ts": start}

            # 1. CSP
            report("module_started", url, index, module="CSP")
            try:
                csp_result = self.csp_analyzer.run({"headers": headers})
            except Exception as e:
                log.error(f"[AutoReconAnalyzerV2] CSP error for {url}: {e}", exc_info=True)
                csp_result = {"error": str(e)}
                report("module_error", url, index, module="CSP", error=str(e))
            self.csp_report.append({"url": url, **csp_result})
            result_entry["csp"] = csp_result
            report("module_complete", url, index, module="CSP")

            # 2. DOM-XSS
            report("module_started", url, index, module="DOM-XSS")
            try:
                dom_results = self.dom_analyzer.analyze_html(text, url)
            except Exception as e:
                log.error(f"[AutoReconAnalyzerV2] DOM-XSS error for {url}: {e}", exc_info=True)
                dom_results = []
                report("module_error", url, index, module="DOM-XSS", error=str(e))
            if dom_results:
                self.dom_xss_report.extend(dom_results)
                self._safe_add_artifact("DOM_XSS", url, dom_results)
            result_entry["dom_xss"] = dom_results
            report("module_complete", url, index, module="DOM-XSS", findings=len(dom_results))

            # 3. CSRF
            report("module_started", url, index, module="CSRF")
            try:
                csrf = CSRFAnalyzer(text)
                csrf_tokens = csrf.extract_tokens()
                csrf_headers = csrf.analyze_headers(headers)
                csrf_entry = {
                    "tokens": csrf_tokens,
                    "headers": csrf_headers,
                    "severity": "medium" if not csrf_tokens else "low",
                }
            except Exception as e:
                log.error(f"[AutoReconAnalyzerV2] CSRF error for {url}: {e}", exc_info=True)
                csrf_entry = {"error": str(e), "severity": "info"}
                report("module_error", url, index, module="CSRF", error=str(e))
            if csrf_entry.get("tokens") or csrf_entry.get("headers"):
                self.csrf_report.append({"url": url, **csrf_entry})
                self._safe_add_artifact("CSRF", url, [csrf_entry])
            result_entry["csrf"] = csrf_entry
            report("module_complete", url, index, module="CSRF")

            # 4. SQLi
            report("module_started", url, index, module="SQLi")
            if self.active_testing:
                try:
                    sqli = SQLiTester(url, "id", "1", ["' OR 1=1 --"], None)
                    sqli_result = sqli._test_single("AutoRecon", "' OR 1=1 --", "1' OR 1=1 --")
                except Exception as e:
                    log.error(f"[AutoReconAnalyzerV2] SQLi error for {url}: {e}", exc_info=True)
                    sqli_result = {"error": str(e), "severity": "info"}
                    report("module_error", url, index, module="SQLi", error=str(e))
            else:
                sqli_result = {"status": "skipped", "reason": "active_testing_not_confirmed"}
            self.sqli_report.append({"url": url, "results": [sqli_result]})
            if self.active_testing:
                self._safe_add_artifact("SQLi", url, [sqli_result])
            result_entry["sqli"] = sqli_result
            report(
                "module_complete",
                url,
                index,
                module="SQLi",
                probe_status=sqli_result.get("status", "complete"),
            )

            # 5. SSRF
            report("module_started", url, index, module="SSRF")
            if self.active_testing:
                try:
                    ssrf = SSRFTester(url, "url", "", ["http://127.0.0.1"], None)
                    ssrf_result = ssrf._test_single("AutoRecon", "http://127.0.0.1", "http://127.0.0.1")
                except Exception as e:
                    log.error(f"[AutoReconAnalyzerV2] SSRF error for {url}: {e}", exc_info=True)
                    ssrf_result = {"error": str(e), "severity": "info"}
                    report("module_error", url, index, module="SSRF", error=str(e))
            else:
                ssrf_result = {"status": "skipped", "reason": "active_testing_not_confirmed"}
            self.ssrf_report.append({"url": url, "results": [ssrf_result]})
            if self.active_testing:
                self._safe_add_artifact("SSRF", url, [ssrf_result])
            result_entry["ssrf"] = ssrf_result
            report(
                "module_complete",
                url,
                index,
                module="SSRF",
                probe_status=ssrf_result.get("status", "complete"),
            )

            # 6. Tokens
            report("module_started", url, index, module="Tokens")
            try:
                tokens = extract_tokens(headers, text)
                analyzed = analyze_tokens(tokens, expected_aud="default-aud")
            except Exception as e:
                log.error(f"[AutoReconAnalyzerV2] Tokens error for {url}: {e}", exc_info=True)
                analyzed = []
                report("module_error", url, index, module="Tokens", error=str(e))
            if analyzed:
                for t in analyzed:
                    t["linked_url"] = url
                self.token_report.extend(analyzed)
                self._safe_add_artifact("TOKENS", url, analyzed)
            result_entry["tokens"] = analyzed
            report("module_complete", url, index, module="Tokens", findings=len(analyzed))

            # 7. Security headers
            report("module_started", url, index, module="Security headers")
            try:
                sec_headers = self.analyze_security_headers(headers)
            except Exception as e:
                log.error(f"[AutoReconAnalyzerV2] Security headers error for {url}: {e}", exc_info=True)
                sec_headers = {"error": str(e)}
                report("module_error", url, index, module="Security headers", error=str(e))
            self.security_headers_report.append({"url": url, **sec_headers})
            result_entry["security_headers"] = sec_headers
            report("module_complete", url, index, module="Security headers")

            # 8. Page analysis
            report("module_started", url, index, module="Page analysis")
            try:
                page_info = analyze_page(text, url)
            except Exception as e:
                log.error(f"[AutoReconAnalyzerV2] Page analysis error for {url}: {e}", exc_info=True)
                page_info = {"url": url, "error": str(e)}
                report("module_error", url, index, module="Page analysis", error=str(e))
            self.page_report.append(page_info)
            result_entry["page"] = page_info
            report("module_complete", url, index, module="Page analysis")

            # 9. Structure analysis
            report("module_started", url, index, module="Structure analysis")
            try:
                struct_info = analyze_structure(text)
            except Exception as e:
                log.error(f"[AutoReconAnalyzerV2] Structure analysis error for {url}: {e}", exc_info=True)
                struct_info = {"error": str(e)}
                report("module_error", url, index, module="Structure analysis", error=str(e))
            self.structure_report.append({"url": url, **struct_info})
            result_entry["structure"] = struct_info
            report("module_complete", url, index, module="Structure analysis")

            # 10. NDJSON log
            result_entry["duration"] = time.time() - start
            self._log_ndjson(result_entry)
            report(
                "page_complete",
                url,
                index,
                duration_seconds=result_entry["duration"],
            )

        if self.token_report:
            try:
                save_token_log(self.token_report)
            except Exception as e:
                log.error(f"[AutoReconAnalyzerV2] Token log save error: {e}", exc_info=True)

        try:
            summary = self.connector.summary()
        except Exception as e:
            log.error(f"[AutoReconAnalyzerV2] ThreatConnector summary error: {e}", exc_info=True)
            summary = {"error": str(e)}

        return {
            "csp": self.csp_report,
            "dom_xss": self.dom_xss_report,
            "csrf": self.csrf_report,
            "sqli": self.sqli_report,
            "ssrf": self.ssrf_report,
            "tokens": self.token_report,
            "security_headers": self.security_headers_report,
            "page": self.page_report,
            "structure": self.structure_report,
            "threat_summary": summary,
        }


__all__ = [
    "AutoReconAnalyzerV2",
    "analyze_page",
    "analyze_structure",
]
