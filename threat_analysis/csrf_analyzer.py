# xss_security_gui/threat_analysis/csrf_analyzer.py
import logging
from typing import Dict, Any, List
from bs4 import BeautifulSoup


class CSRFAnalyzer:
    """
    Enterprise 6.0 CSRF Analyzer
    ----------------------------
    • Извлекает CSRF-токены из HTML (input, meta, JS)
    • Анализирует заголовки на наличие CSRF-защиты
    • Возвращает унифицированный результат для Threat Intel
    """

    def __init__(self, html: str, source_url: str = "unknown"):
        self.soup = BeautifulSoup(html, "html.parser")
        self.source_url = source_url

    def extract_tokens(self) -> List[Dict[str, Any]]:
        """
        Извлекает CSRF-токены из HTML.
        """
        tokens: List[Dict[str, Any]] = []

        # === input-теги ===
        for input_tag in self.soup.find_all("input"):
            name = input_tag.get("name", "").lower()
            if "csrf" in name or "token" in name:
                tokens.append({
                    "type": "input",
                    "name": input_tag.get("name"),
                    "value": input_tag.get("value")
                })

        # === meta-теги ===
        for meta in self.soup.find_all("meta"):
            name = meta.get("name", "").lower()
            if "csrf" in name or "token" in name:
                tokens.append({
                    "type": "meta",
                    "name": meta.get("name"),
                    "value": meta.get("content")
                })

        # === JS-токены ===
        for script in self.soup.find_all("script"):
            if script.string:
                text = script.string.lower()
                if "csrf" in text or "token" in text:
                    tokens.append({
                        "type": "js",
                        "snippet": text[:200]
                    })

        logging.debug(f"[CSRFAnalyzer] Найдено {len(tokens)} токенов на {self.source_url}")
        return tokens

    def analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Анализирует заголовки на наличие CSRF-защиты.
        """
        relevant: Dict[str, Any] = {
            "module": "CSRF",
            "target": self.source_url,
            "headers_checked": len(headers),
            "issues": []
        }

        for k, v in headers.items():
            lk = k.lower()

            # CSRF headers
            if "csrf" in lk:
                relevant["issues"].append({"header": k, "value": v})

            # Origin / Referer
            if "origin" in lk or "referer" in lk:
                relevant["issues"].append({"header": k, "value": v})

            # CORS
            if "access-control" in lk:
                relevant["issues"].append({"header": k, "value": v})

            # SameSite cookie
            if "set-cookie" in lk and "samesite" not in v.lower():
                relevant["issues"].append({
                    "header": k,
                    "value": v,
                    "warning": "missing SameSite"
                })

        logging.debug(f"[CSRFAnalyzer] Проверено {len(headers)} заголовков, найдено {len(relevant['issues'])} потенциальных проблем")
        return relevant

    def run_analysis(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Запускает полный анализ CSRF: токены + заголовки.
        Возвращает унифицированный результат для Threat Intel.
        """
        tokens = self.extract_tokens()
        header_analysis = self.analyze_headers(headers)

        result = {
            "module": "CSRF",
            "target": self.source_url,
            "tokens_found": tokens,
            "header_analysis": header_analysis,
            "status": "secure" if tokens and not header_analysis["issues"] else "potential CSRF risk"
        }

        logging.info(f"[CSRFAnalyzer] Анализ завершён: {result['status']} для {self.source_url}")
        return result