# xss_security_gui/threat_analysis/csrf_analyzer.py
"""
CSRFAnalyzer (ULTRA Hybrid 6.5)
-------------------------------
• Розширений пошук CSRF-токенів (input, meta, JS, hidden fields, SPA-фреймворки)
• Аналіз заголовків на наявність CSRF-захисту (SameSite, Secure, Origin/Referer policy)
• Уніфікований формат результатів (Threat Intel + TesterBase-сумісний)
• ZAP-рівень точності та структурованості
"""

import logging
from typing import Dict, Any, List
from bs4 import BeautifulSoup


class CSRFAnalyzer:
    """Поглиблений модуль аналізу CSRF-токенів та заголовків."""

    DEFAULT_KEYWORDS = ["csrf", "xsrf", "token", "auth", "secure"]

    def __init__(self, html: str, source_url: str = "unknown", keywords: List[str] | None = None):
        self.html = html or ""
        self.soup = BeautifulSoup(self.html, "html.parser")
        self.source_url = source_url
        self.keywords = keywords if keywords is not None else self.DEFAULT_KEYWORDS

    # ---------------------------------------------------------
    # Token Extraction
    # ---------------------------------------------------------
    def extract_tokens(self) -> List[Dict[str, Any]]:
        tokens: List[Dict[str, Any]] = []

        # === input-теги ===
        for input_tag in self.soup.find_all("input"):
            name = (input_tag.get("name") or "").lower()
            if any(k in name for k in self.keywords):
                tokens.append({
                    "type": "input",
                    "name": input_tag.get("name"),
                    "value": input_tag.get("value"),
                })

        # === hidden-поля ===
        for hidden in self.soup.find_all("input", {"type": "hidden"}):
            name = (hidden.get("name") or "").lower()
            if any(k in name for k in self.keywords):
                tokens.append({
                    "type": "hidden",
                    "name": hidden.get("name"),
                    "value": hidden.get("value"),
                })

        # === meta-теги ===
        for meta in self.soup.find_all("meta"):
            name = (meta.get("name") or "").lower()
            if any(k in name for k in self.keywords):
                tokens.append({
                    "type": "meta",
                    "name": meta.get("name"),
                    "value": meta.get("content"),
                })

        # === JS-токени ===
        for script in self.soup.find_all("script"):
            text = script.string or ""
            lower = text.lower()
            if any(k in lower for k in self.keywords):
                tokens.append({
                    "type": "js",
                    "snippet": lower[:200],
                })

        # === SPA-фреймворки (Angular, React, Vue) ===
        if "window.__initial_state__" in self.html.lower():
            tokens.append({
                "type": "spa",
                "snippet": "window.__INITIAL_STATE__ detected",
            })

        logging.debug(f"[CSRFAnalyzer] Found {len(tokens)} tokens on {self.source_url}")
        return tokens

    # ---------------------------------------------------------
    # Header Analysis
    # ---------------------------------------------------------
    def analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for k, v in headers.items():
            lk = k.lower()
            lv = v.lower()

            # CSRF headers
            if any(keyword in lk for keyword in self.keywords):
                issues.append({"header": k, "value": v, "info": "csrf-header-present"})

            # Origin / Referer policy
            if "origin" in lk or "referer" in lk:
                issues.append({"header": k, "value": v, "info": "origin-referer-present"})

            # CORS
            if "access-control" in lk:
                issues.append({"header": k, "value": v, "info": "cors-policy"})

            # SameSite cookie
            if "set-cookie" in lk:
                if "samesite" not in lv:
                    issues.append({"header": k, "value": v, "warning": "missing SameSite"})
                if "secure" not in lv:
                    issues.append({"header": k, "value": v, "warning": "missing Secure"})
                if "httponly" not in lv:
                    issues.append({"header": k, "value": v, "warning": "missing HttpOnly"})

        logging.debug(
            f"[CSRFAnalyzer] Checked {len(headers)} headers, found {len(issues)} potential issues"
        )
        return {"issues": issues, "headers_checked": len(headers)}

    # ---------------------------------------------------------
    # Full Analysis
    # ---------------------------------------------------------
    def run_analysis(self, headers: Dict[str, str]) -> Dict[str, Any]:
        tokens = self.extract_tokens()
        header_analysis = self.analyze_headers(headers)

        severity = self._assess_severity(tokens, header_analysis["issues"])

        result = {
            "module": "CSRF",
            "url": self.source_url,
            "severity": severity,
            "status": "secure" if severity == "SECURE" else "potential-risk",
            "details": {
                "tokens_found": tokens,
                "header_analysis": header_analysis,
                "token_count": len(tokens),
                "issue_count": len(header_analysis["issues"]),
            },
        }

        logging.info(
            f"[CSRFAnalyzer] Analysis complete: {result['status']} for {self.source_url}"
        )
        return result

    # ---------------------------------------------------------
    # Severity Assessment
    # ---------------------------------------------------------
    @staticmethod
    def _assess_severity(tokens: List[Dict[str, Any]], issues: List[Dict[str, Any]]) -> str:
        if not tokens and issues:
            return "HIGH"
        if tokens and issues:
            return "MEDIUM"
        if tokens and not issues:
            return "SECURE"
        return "LOW"