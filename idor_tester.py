# xss_security_gui/idor_tester.py

import time
import hashlib
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional

from xss_security_gui.settings import settings


# ---------------------------------------------------------
# URL builder
# ---------------------------------------------------------
def build_url_with_param(url: str, param: str, value: str) -> str:
    """
    Формує новий URL з підміненою змінною параметра.
    Завжди повертає коректний URL.
    """
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)

    query[param] = [value]
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
# Hash helper
# ---------------------------------------------------------
def hash_response(text: str) -> str:
    """Повертає MD5-хеш відповіді."""
    return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()


# ---------------------------------------------------------
# Request sender
# ---------------------------------------------------------
def send_request(
    url: str,
    method: str,
    param: str,
    value: str,
    headers: Dict[str, str],
    timeout: int
):
    """
    Відправляє GET або POST запит.
    GET — параметр у URL.
    POST — параметр у form-data.
    """
    method = method.upper()

    if method == "GET":
        return requests.get(url, headers=headers, timeout=timeout)

    if method == "POST":
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return requests.post(
            base_url,
            headers=headers,
            data={param: value},
            timeout=timeout
        )

    raise ValueError(f"Unsupported method: {method}")


# ---------------------------------------------------------
# Main IDOR fuzzing engine
# ---------------------------------------------------------
def fuzz_id_parameter(
    url: str,
    param: str = "id",
    start: int = 1,
    stop: int = 10,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    delay: Optional[float] = None,
    timeout: Optional[int] = None,
    auth_token: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Основний IDOR‑фаззер.
    Повертає список результатів у форматі:
    {
        "url": str,
        "status": int | "ERR",
        "length": int,
        "hash": str | None,
        "differs": bool,
        "error": Optional[str]
    }
    """

    # -----------------------------
    # Валідація
    # -----------------------------
    if not url or not param:
        raise ValueError("URL і параметр повинні бути вказані")

    if start > stop:
        start, stop = stop, start

    # -----------------------------
    # Settings defaults
    # -----------------------------
    delay = delay if delay is not None else getattr(settings, "IDOR_DELAY", 0.5)
    timeout = timeout if timeout is not None else getattr(settings, "REQUEST_TIMEOUT", 10)

    # -----------------------------
    # Headers
    # -----------------------------
    if headers is None:
        headers = {
            "User-Agent": getattr(settings, "DEFAULT_USER_AGENT", "IDOR-Scanner")
        }

    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    # -----------------------------
    # Main logic
    # -----------------------------
    results: List[Dict[str, Any]] = []
    base_hash: Optional[str] = None
    base_length: Optional[int] = None

    for value in range(start, stop + 1):
        new_url = build_url_with_param(url, param, str(value))

        try:
            response = send_request(
                new_url,
                method,
                param,
                str(value),
                headers,
                timeout
            )

            text = response.text.strip()
            resp_hash = hash_response(text)
            resp_len = len(text)

            # Базовий відповідь
            if value == start:
                base_hash = resp_hash
                base_length = resp_len

            # Перевірка різниці
            differs = (resp_hash != base_hash) or (resp_len != base_length)

            results.append({
                "url": new_url,
                "status": response.status_code,
                "length": resp_len,
                "hash": resp_hash,
                "differs": differs
            })

        except Exception as e:
            results.append({
                "url": new_url,
                "status": "ERR",
                "length": 0,
                "hash": None,
                "differs": False,
                "error": str(e)
            })

        time.sleep(delay)

    return results


# ---------------------------------------------------------
# Test run
# ---------------------------------------------------------
if __name__ == "__main__":
    test_url = "https://example.com/profile?user_id=1"
    param = "user_id"

    res = fuzz_id_parameter(
        test_url,
        param=param,
        start=1,
        stop=5,
        method="GET",
        headers={"User-Agent": "Aleksandr-IDOR-Scanner"},
        auth_token=None
    )

    for r in sorted(res, key=lambda x: x["status"]):
        mark = "✅" if r["differs"] else "⚠️"
        print(f"{mark} {r['url']} | status={r['status']} | len={r['length']} | hash={r['hash']}")
        if "error" in r:
            print(f"   ❌ Error: {r['error']}")