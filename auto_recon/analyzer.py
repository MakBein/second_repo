# xss_security_gui/auto_recon/analyzer.py
import logging
import re
import time
import json
import os
import hashlib
from typing import List, Dict, Any, Optional

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
# ============================================================
#  Паттерны для извлечения секретов
# ============================================================
_SECRET_PATTERNS: Dict[str, str] = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token": r"xox[bpors]-[0-9a-zA-Z]{10,48}",
    "GitHub Token": r"gh[pousr]_[0-9a-zA-Z]{36}",
    "Private Key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "Generic Secret": r"(?i)(secret|password|passwd|api_key|apikey|token|access_token)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "Bearer Token": r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
    "Basic Auth": r"Basic\s+[A-Za-z0-9+/=]{10,}",
    "Stripe Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Mailgun Key": r"key-[0-9a-zA-Z]{32}",
    "Twilio SID": r"AC[a-z0-9]{32}",
    "SendGrid Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
}

_SENSITIVE_KEYWORDS = [
    "login", "password", "passwd", "token", "auth", "secret",
    "api_key", "apikey", "access_token", "session", "cookie",
    "admin", "debug", "trace", "internal", "private",
    "credit_card", "ssn", "oauth", "jwt", "bearer",
]


def analyze_page(html: str, url: str) -> dict:
    """Расширенный анализ содержимого страницы."""
    lower = html.lower()
    return {
        "url": url,
        "length": len(html),
        "has_script": "<script" in lower,
        "has_form": "<form" in lower,
        "has_iframe": "<iframe" in lower,
        "has_object": "<object" in lower,
        "has_embed": "<embed" in lower,
        "has_comments": "<!--" in lower,
        "keywords": [k for k in _SENSITIVE_KEYWORDS if k in lower],
        "content_hash": hashlib.md5(html.encode("utf-8", errors="ignore")).hexdigest(),
    }


def analyze_structure(html: str) -> dict:
    """Расширенный подсчёт HTML-тегов и атрибутов."""
    lower = html.lower()
    return {
        "tags": {
            "div": lower.count("<div"),
            "script": lower.count("<script"),
            "form": lower.count("<form"),
            "input": lower.count("<input"),
            "a": lower.count("<a "),
            "iframe": lower.count("<iframe"),
            "object": lower.count("<object"),
            "embed": lower.count("<embed"),
            "textarea": lower.count("<textarea"),
            "select": lower.count("<select"),
            "button": lower.count("<button"),
            "img": lower.count("<img"),
            "link": lower.count("<link"),
            "meta": lower.count("<meta"),
            "style": lower.count("<style"),
        },
        "event_handlers": len(re.findall(r'on\w+\s*=', lower)),
        "inline_scripts": len(re.findall(r'<script[^>]*>[^<]+</script>', lower)),
        "external_scripts": len(re.findall(r'<script[^>]+src\s*=', lower)),
        "hidden_inputs": len(re.findall(r'<input[^>]+type\s*=\s*["\']hidden', lower)),
        "comments": len(re.findall(r'<!--', lower)),
    }


def extract_secrets(html: str, url: str) -> List[Dict[str, Any]]:
    """Извлекает секреты и ключи из HTML/JS."""
    findings: List[Dict[str, Any]] = []
    for name, pattern in _SECRET_PATTERNS.items():
        for match in re.finditer(pattern, html):
            findings.append({
                "type": name,
                "value": match.group()[:120],
                "url": url,
                "severity": "critical" if "key" in name.lower() or "private" in name.lower() else "high",
            })
    return findings


def extract_emails(html: str) -> List[str]:
    """Извлекает email-адреса из HTML."""
    return list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html)))


def detect_technology(html: str, headers: dict) -> Dict[str, Any]:
    """Определяет технологии по HTML и заголовкам."""
    lower = html.lower()
    techs = []
    if "react" in lower or "__NEXT_DATA__" in html:
        techs.append("React/Next.js")
    if "ng-app" in lower or "ng-controller" in lower:
        techs.append("AngularJS")
    if "vue" in lower or "v-bind" in lower or "v-model" in lower:
        techs.append("Vue.js")
    if "jquery" in lower or "$.ajax" in html:
        techs.append("jQuery")
    if "wp-content" in lower or "wordpress" in lower:
        techs.append("WordPress")
    if "drupal" in lower:
        techs.append("Drupal")
    if "joomla" in lower:
        techs.append("Joomla")
    if "laravel" in lower or "csrf-token" in lower:
        techs.append("Laravel")
    if "django" in lower or "csrfmiddlewaretoken" in lower:
        techs.append("Django")
    if "bootstrap" in lower:
        techs.append("Bootstrap")

    server = headers.get("Server", headers.get("server", ""))
    powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))

    return {
        "frameworks": techs,
        "server": server,
        "powered_by": powered,
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
        self.secrets_report: List[Dict[str, Any]] = []
        self.tech_report: List[Dict[str, Any]] = []
        self.emails_report: List[Dict[str, Any]] = []

        # Анализаторы
        self.csp_analyzer = CSPAnalyzer(threat_tab=self.connector)
        self.dom_analyzer = DOMXSSDetector(threat_tab=self.connector)

        # NDJSON лог
        self.log_path = os.path.join(DIRS["logs"], "analysis_results.ndjson")
        os.makedirs(DIRS["logs"], exist_ok=True)

    def _log_ndjson(self, entry: dict):
        """Записывает результат анализа в NDJSON-лог."""
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            logging.error(f"[AutoReconAnalyzerV2] NDJSON log error: {e}")

    def analyze_security_headers(self, headers: dict) -> dict:
        """Расширенный анализ security-заголовков с оценкой рисков."""
        expected = {
            "X-Frame-Options": "clickjacking",
            "X-Content-Type-Options": "mime_sniffing",
            "Referrer-Policy": "referrer_leak",
            "Permissions-Policy": "feature_abuse",
            "Strict-Transport-Security": "no_hsts",
            "Content-Security-Policy": "no_csp",
            "X-XSS-Protection": "no_xss_filter",
            "Cache-Control": "caching_risk",
            "Cross-Origin-Opener-Policy": "no_coop",
            "Cross-Origin-Resource-Policy": "no_corp",
            "Cross-Origin-Embedder-Policy": "no_coep",
        }
        dangerous = {
            "Server": "server_exposed",
            "X-Powered-By": "tech_exposed",
            "X-AspNet-Version": "aspnet_exposed",
            "X-AspNetMvc-Version": "aspnet_mvc_exposed",
        }

        present = {}
        missing = []
        exposed = []
        for hdr, risk in expected.items():
            val = headers.get(hdr)
            if val:
                present[hdr] = val
            else:
                missing.append({"header": hdr, "risk": risk})

        for hdr, risk in dangerous.items():
            val = headers.get(hdr)
            if val:
                exposed.append({"header": hdr, "value": val, "risk": risk})

        score = max(0, 100 - len(missing) * 10 - len(exposed) * 5)
        severity = "critical" if score < 30 else "high" if score < 50 else "medium" if score < 70 else "low"

        return {
            "present": present,
            "missing": missing,
            "exposed": exposed,
            "score": score,
            "severity": severity,
        }

    def analyze(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Запускает полный анализ набора HTTP-ответов."""
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
            sqli_result = sqli._test_single("AutoRecon", "' OR 1=1 --", "1' OR 1=1 --")
            self.sqli_report.append({"url": url, "results": [sqli_result]})
            self.connector.add_artifact("SQLi", url, [sqli_result])
            result_entry["sqli"] = sqli_result

            # 5. SSRF
            ssrf = SSRFTester(url, "url", "", ["http://127.0.0.1"], None)
            ssrf_result = ssrf._test_single("AutoRecon", "http://127.0.0.1", "http://127.0.0.1")
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

            # 10. Secrets extraction
            secrets = extract_secrets(text, url)
            if secrets:
                self.secrets_report.extend(secrets)
                self.connector.add_artifact("SECRETS", url, secrets)
            result_entry["secrets"] = secrets

            # 11. Technology fingerprint
            tech = detect_technology(text, headers)
            self.tech_report.append({"url": url, **tech})
            result_entry["technology"] = tech

            # 12. Email extraction
            emails = extract_emails(text)
            if emails:
                self.emails_report.append({"url": url, "emails": emails})
            result_entry["emails"] = emails

            # 13. NDJSON log
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
            "secrets": self.secrets_report,
            "technology": self.tech_report,
            "emails": self.emails_report,
            "threat_summary": self.connector.summary(),
            "total_findings": (
                len(self.dom_xss_report) + len(self.csrf_report)
                + len(self.sqli_report) + len(self.ssrf_report)
                + len(self.secrets_report) + len(self.token_report)
            ),
        }


# ============================================================
#  Публичный API модуля
# ============================================================
__all__ = [
    "AutoReconAnalyzerV2",
    "analyze_page",
    "analyze_structure",
    "extract_secrets",
    "extract_emails",
    "detect_technology",
]