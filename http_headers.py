# xss_security_gui/http_headers.py

from typing import Dict, List


# ---------------------------------------------------------
# Aggressive header templates (розширювані)
# ---------------------------------------------------------
AGGRESSIVE_HEADER_TEMPLATES: Dict[str, str] = {
    # Classic reflection vectors
    "User-Agent": "{p}",
    "Referer": "{p}",
    "Cookie": "session={p}; token={p}",
    "Authorization": "Bearer {p}",

    # Proxy / Forwarding
    "X-Forwarded-For": "{p}",
    "X-Forwarded-Host": "{p}",
    "X-Forwarded-Proto": "{p}",
    "X-Real-IP": "{p}",
    "X-Client-IP": "{p}",
    "X-Remote-IP": "{p}",
    "X-Remote-Addr": "{p}",

    # Debug / Dev headers
    "X-Debug": "{p}",
    "X-Test": "{p}",
    "X-Trace": "{p}",
    "X-Request-ID": "{p}",
    "X-Correlation-ID": "{p}",

    # URL rewriting
    "X-Original-URL": "{p}",
    "X-Rewrite-URL": "{p}",
    "X-Rewrite-Path": "{p}",

    # Cloud / CDN
    "CF-Connecting-IP": "{p}",
    "CF-IPCountry": "{p}",
    "True-Client-IP": "{p}",
    "Fastly-Client-IP": "{p}",
    "X-Azure-Ref": "{p}",
    "X-Azure-FDID": "{p}",

    # API / Versioning
    "X-Api-Version": "{p}",
    "X-Client-Version": "{p}",
    "X-App-Version": "{p}",

    # Email / Account spoofing
    "X-Email": "{p}",
    "X-Account": "{p}",
    "X-User-ID": "{p}",
    "X-Session-ID": "{p}",
    "X-Customer-ID": "{p}",
    "X-Card-Number": "{p}",
    "X-Payment-Info": "{p}",

    # Search / Query injection
    "X-Search-Query": "{p}",
    "X-Query": "{p}",
    "X-Keyword": "{p}",

    # Smuggling / Obfuscation
    "X-HTTP-Method-Override": "{p}",
    "X-Method-Override": "{p}",
    "X-Original-Method": "{p}",
    "X-Override-URL": "{p}",

    # XSS-specific
    "X-XSS-Vector": "{p}",
    "X-Injection": "{p}",
    "X-Payload": "{p}",
    "X-Attack": "{p}",
}


# ---------------------------------------------------------
# Precompiled templates (для швидкості)
# ---------------------------------------------------------
_COMPILED = {k: v.replace("{p}", "%s") for k, v in AGGRESSIVE_HEADER_TEMPLATES.items()}


# ---------------------------------------------------------
# Main builder
# ---------------------------------------------------------
def build_aggressive_headers(
    payload: str,
    *,
    only_reflection: bool = False,
    minimal: bool = False,
    include: List[str] | None = None,
    exclude: List[str] | None = None,
) -> Dict[str, str]:
    """
    Генерує агресивні заголовки.

    Параметри:
        payload: str — значення для ін'єкції
        only_reflection: bool — тільки заголовки, які часто відображаються
        minimal: bool — мінімальний набір (10 найагресивніших)
        include: List[str] — whitelist заголовків
        exclude: List[str] — blacklist заголовків
    """

    payload = str(payload) if payload is not None else ""

    # Режим мінімального набору
    if minimal:
        keys = [
            "User-Agent", "Referer", "Cookie", "Authorization",
            "X-Forwarded-For", "X-Real-IP", "X-Debug",
            "X-Test", "X-XSS-Vector", "X-Injection"
        ]
    # Режим тільки відображуваних
    elif only_reflection:
        keys = [
            "User-Agent", "Referer", "Cookie",
            "X-Forwarded-For", "X-Real-IP",
            "X-XSS-Vector", "X-Injection"
        ]
    else:
        keys = list(_COMPILED.keys())

    # Фільтрація
    if include:
        keys = [k for k in keys if k in include]

    if exclude:
        keys = [k for k in keys if k not in exclude]

    # Генерація (дуже швидка, бо %s)
    return {k: _COMPILED[k] % payload for k in keys}