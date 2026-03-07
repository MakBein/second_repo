# xss_security_gui/threat_analysis/csrf_analyzer.py
"""
CSRFAnalyzer 6.1
----------------
• Извлекает CSRF-токены из HTML (input, meta, JS)
• Анализирует заголовки на наличие CSRF-защиты
• Возвращает унифицированный результат для Threat Intel
"""

import logging
from typing import Dict, Any, List
from bs4 import BeautifulSoup


class CSRFAnalyzer:
    """Модуль анализа CSRF-токенов и заголовков."""

    DEFAULT_KEYWORDS = ["csrf", "token"]

    def __init__(self, html: str, source_url: str = "unknown", keywords: List[str] | None = None):
        self.soup = BeautifulSoup(html, "html.parser")
        self.source_url = source_url
        self.keywords = keywords if keywords is not None else self.DEFAULT_KEYWORDS

    def extract_tokens(self) -> List[Dict[str, Any]]:
        """Извлекает CSRF-токены из HTML."""
        tokens: List[Dict[str, Any]] = []

        # === input-теги ===
        for input_tag in self.soup.find_all("input"):
            name = input_tag.get("name", "").lower()
            if any(k in name for k in self.keywords):
                tokens.append({
                    "type": "input",
                    "name": input_tag.get("name"),
                    "value": input_tag.get("value"),
                })

        # === meta-теги ===
        for meta in self.soup.find_all("meta"):
            name = meta.get("name", "").lower()
            if any(k in name for k in self.keywords):
                tokens.append({
                    "type": "meta",
                    "name": meta.get("name"),
                    "value": meta.get("content"),
                })

        # === JS-токены ===
        for script in self.soup.find_all("script"):
            if script.string:
                text = script.string.lower()
                if any(k in text for k in self.keywords):
                    tokens.append({
                        "type": "js",
                        "snippet": text[:200],
                    })

        logging.debug(f"[CSRFAnalyzer] Найдено {len(tokens)} токенов на {self.source_url}")
        return tokens

    def analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Анализирует заголовки на наличие CSRF-защиты."""
        issues: List[Dict[str, Any]] = []

        for k, v in headers.items():
            lk = k.lower()

            # CSRF headers
            if any(keyword in lk for keyword in self.keywords):
                issues.append({"header": k, "value": v})

            # Origin / Referer
            if "origin" in lk or "referer" in lk:
                issues.append({"header": k, "value": v})

            # CORS
            if "access-control" in lk:
                issues.append({"header": k, "value": v})

            # SameSite cookie
            if "set-cookie" in lk and "samesite" not in v.lower():
                issues.append({
                    "header": k,
                    "value": v,
                    "warning": "missing SameSite",
                })

        logging.debug(f"[CSRFAnalyzer] Проверено {len(headers)} заголовков, найдено {len(issues)} потенциальных проблем")
        return {"issues": issues, "headers_checked": len(headers)}

    def run_analysis(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Запускает полный анализ CSRF: токены + заголовки."""
        tokens = self.extract_tokens()
        header_analysis = self.analyze_headers(headers)

        severity = self._assess_severity(tokens, header_analysis["issues"])

        result = {
            "module": "CSRF",
            "target": self.source_url,
            "tokens_found": tokens,
            "header_analysis": header_analysis,
            "severity": severity,
            "status": "secure" if severity == "SECURE" else "potential CSRF risk",
        }

        logging.info(f"[CSRFAnalyzer] Анализ завершён: {result['status']} для {self.source_url}")
        return result

    @staticmethod
    def _assess_severity(tokens: List[Dict[str, Any]], issues: List[Dict[str, Any]]) -> str:
        """Оценка риска по наличию токенов и проблем в заголовках."""
        if not tokens and issues:
            return "HIGH"
        if tokens and issues:
            return "MEDIUM"
        if tokens and not issues:
            return "SECURE"
        return "LOW"