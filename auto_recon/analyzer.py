# xss_security_gui/auto_recon/analyzer.py

import logging
import time
import json
import os
from typing import List, Dict, Any

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


# ============================================================
#  Простые анализаторы структуры страницы
# ============================================================

def analyze_page(html: str, url: str) -> dict:
    lower = html.lower()
    return {
        "url": url,
        "length": len(html),
        "has_script": "<script" in lower,
        "has_form": "<form" in lower,
        "keywords": [
            k for k in ["login", "password", "token", "auth"]
            if k in lower
        ],
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


# ============================================================
#  AutoRecon Analyzer 6.0
# ============================================================

class AutoReconAnalyzerV2:
    """
    Enterprise 6.0 AutoRecon Analyzer

    • Объединяет все анализаторы (CSP, DOM-XSS, CSRF, SQLi, SSRF, Tokens, Headers)
    • Логирует результаты в NDJSON и ThreatConnector
    • Возвращает унифицированный отчёт
    """

    def __init__(self, threat_connector: ThreatConnector):
        self.connector = threat_connector

        # Собранные отчёты
        self.token_report: List[Dict[str, Any]] = []
        self.csrf_report: List[Dict[str, Any]] = []
        self.sqli_report: List[Dict[str, Any]] = []
        self.ssrf_report: List[Dict[str, Any]] = []
        self.dom_xss_report: List[Dict[str, Any]] = []
        self.csp_report: List[Dict[str, Any]] = []
        self.security_headers_report: List[Dict[str, Any]] = []
        self.page_report: List[Dict[str, Any]] = []
        self.structure_report: List[Dict[str, Any]] = []

        # Анализаторы
        self.csp_analyzer = CSPAnalyzer(threat_tab=self.connector)
        self.dom_analyzer = DOMXSSDetector(threat_tab=self.connector)

        # NDJSON лог
        self.log_path = os.path.join(DIRS["logs"], "analysis_results.ndjson")
        os.makedirs(DIRS["logs"], exist_ok=True)

    # --------------------------------------------------------

    def _log_ndjson(self, entry: dict):
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            logging.error(f"[AutoReconAnalyzerV2] NDJSON log error: {e}")

    # --------------------------------------------------------

    def analyze_security_headers(self, headers: dict) -> dict:
        return {
            "x_frame_options": headers.get("X-Frame-Options"),
            "x_content_type_options": headers.get("X-Content-Type-Options"),
            "referrer_policy": headers.get("Referrer-Policy"),
            "permissions_policy": headers.get("Permissions-Policy"),
            "strict_transport_security": headers.get("Strict-Transport-Security"),
        }

    # --------------------------------------------------------

    def analyze(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        for r in responses:
            start = time.time()
            url = r.get("url", "")
            text = r.get("text", "")
            headers = r.get("headers", {})

            result_entry = {"url": url, "ts": start}

            # 1. CSP
            csp_result = self.csp_analyzer.run({"headers": headers})
            self.csp_report.append({"url": url, **csp_result})
            result_entry["csp"] = csp_result

            # 2. DOM-XSS
            dom_results = self.dom_analyzer.analyze_html(text, url)
            if dom_results:
                self.dom_xss_report.extend(dom_results)
                self.connector.add_artifact("DOM_XSS", url, dom_results)
            result_entry["dom_xss"] = dom_results

            # 3. CSRF
            csrf = CSRFAnalyzer(text)
            csrf_tokens = csrf.extract_tokens()
            csrf_headers = csrf.analyze_headers(headers)
            csrf_entry = {
                "tokens": csrf_tokens,
                "headers": csrf_headers,
                "severity": "medium" if not csrf_tokens else "low",
            }
            if csrf_tokens or csrf_headers:
                self.csrf_report.append({"url": url, **csrf_entry})
                self.connector.add_artifact("CSRF", url, [csrf_entry])
            result_entry["csrf"] = csrf_entry

            # 4. SQLi
            sqli = SQLiTester(url, "id", "1", ["' OR 1=1 --"], None)
            sqli_result = sqli._test_single(
                "AutoRecon",
                "' OR 1=1 --",
                "1' OR 1=1 --",
            )
            self.sqli_report.append({"url": url, "results": [sqli_result]})
            self.connector.add_artifact("SQLi", url, [sqli_result])
            result_entry["sqli"] = sqli_result

            # 5. SSRF
            ssrf = SSRFTester(url, "url", "", ["http://127.0.0.1"], None)
            ssrf_result = ssrf._test_single(
                "AutoRecon",
                "http://127.0.0.1",
                "http://127.0.0.1",
            )
            self.ssrf_report.append({"url": url, "results": [ssrf_result]})
            self.connector.add_artifact("SSRF", url, [ssrf_result])
            result_entry["ssrf"] = ssrf_result

            # 6. Tokens
            tokens = extract_tokens(headers, text)
            analyzed = analyze_tokens(tokens, expected_aud="default-aud")
            if analyzed:
                for t in analyzed:
                    t["linked_url"] = url
                self.token_report.extend(analyzed)
                self.connector.add_artifact("TOKENS", url, analyzed)
            result_entry["tokens"] = analyzed

            # 7. Security headers
            sec_headers = self.analyze_security_headers(headers)
            self.security_headers_report.append({"url": url, **sec_headers})
            result_entry["security_headers"] = sec_headers

            # 8. Page analysis
            page_info = analyze_page(text, url)
            self.page_report.append(page_info)
            result_entry["page"] = page_info

            # 9. Structure analysis
            struct_info = analyze_structure(text)
            self.structure_report.append({"url": url, **struct_info})
            result_entry["structure"] = struct_info

            # 10. NDJSON log
            result_entry["duration"] = time.time() - start
            self._log_ndjson(result_entry)

        if self.token_report:
            save_token_log(self.token_report)

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
            "threat_summary": self.connector.summary(),
        }


# ============================================================
#  Публичный API модуля
# ============================================================

__all__ = [
    "AutoReconAnalyzerV2",
    "analyze_page",
    "analyze_structure",
]