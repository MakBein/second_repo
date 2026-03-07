# xss_security_gui/http_headers.py

AGGRESSIVE_HEADER_TEMPLATES = {
    # --- Classic reflection vectors ---
    "User-Agent": "{p}",
    "Referer": "{p}",
    "Cookie": "session={p}; token={p}",
    "Authorization": "Bearer {p}",

    # --- Proxy / Forwarding ---
    "X-Forwarded-For": "{p}",
    "X-Forwarded-Host": "{p}",
    "X-Forwarded-Proto": "{p}",
    "X-Real-IP": "{p}",
    "X-Client-IP": "{p}",
    "X-Remote-IP": "{p}",
    "X-Remote-Addr": "{p}",

    # --- Debug / Dev headers ---
    "X-Debug": "{p}",
    "X-Test": "{p}",
    "X-Trace": "{p}",
    "X-Request-ID": "{p}",
    "X-Correlation-ID": "{p}",

    # --- URL rewriting ---
    "X-Original-URL": "{p}",
    "X-Rewrite-URL": "{p}",
    "X-Rewrite-Path": "{p}",

    # --- Cloud / CDN ---
    "CF-Connecting-IP": "{p}",
    "CF-IPCountry": "{p}",
    "True-Client-IP": "{p}",
    "Fastly-Client-IP": "{p}",
    "X-Azure-Ref": "{p}",
    "X-Azure-FDID": "{p}",

    # --- API / Versioning ---
    "X-Api-Version": "{p}",
    "X-Client-Version": "{p}",
    "X-App-Version": "{p}",

    # --- Email / Account spoofing ---
    "X-Email": "{p}",
    "X-Account": "{p}",
    "X-User-ID": "{p}",
    "X-Session-ID": "{p}",
    "X-Customer-ID": "{p}",
    "X-Card-Number": "{p}",
    "X-Payment-Info": "{p}",

    # --- Search / Query injection ---
    "X-Search-Query": "{p}",
    "X-Query": "{p}",
    "X-Keyword": "{p}",

    # --- Smuggling / Obfuscation ---
    "X-HTTP-Method-Override": "{p}",
    "X-Method-Override": "{p}",
    "X-Original-Method": "{p}",
    "X-Override-URL": "{p}",

    # --- XSS-specific ---
    "X-XSS-Vector": "{p}",
    "X-Injection": "{p}",
    "X-Payload": "{p}",
    "X-Attack": "{p}",
}


def build_aggressive_headers(payload: str) -> dict:
    """Генерирует агрессивные заголовки на основе шаблонов."""
    return {k: v.format(p=payload) for k, v in AGGRESSIVE_HEADER_TEMPLATES.items()}