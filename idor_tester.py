# xss_security_gui/idor_tester.py

import time
import hashlib
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from xss_security_gui.settings import settings


def build_url_with_param(url: str, param: str, value: str) -> str:
    """Формирует новый URL с подменённым параметром."""
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
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


def hash_response(text: str) -> str:
    """Возвращает MD5-хеш ответа."""
    return hashlib.md5(text.encode()).hexdigest()


def send_request(url: str, method: str, param: str, value: str, headers: dict, timeout: int):
    """Отправляет GET или POST запрос с подменённым параметром."""
    method = method.upper()

    if method == "GET":
        return requests.get(url, headers=headers, timeout=timeout)

    if method == "POST":
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return requests.post(base_url, headers=headers, data={param: value}, timeout=timeout)

    raise ValueError(f"Unsupported method: {method}")


def fuzz_id_parameter(
    url: str,
    param: str = "id",
    start: int = 1,
    stop: int = 10,
    method: str = "GET",
    headers: dict | None = None,
    delay: float | None = None,
    timeout: int | None = None,
    auth_token: str | None = None
):
    """
    Основной IDOR‑фаззер.
    Возвращает список результатов с информацией о различиях.
    """

    # -----------------------------
    # Валидация
    # -----------------------------
    if not url or not param:
        raise ValueError("URL и параметр должны быть указаны")

    if start > stop:
        start, stop = stop, start

    # -----------------------------
    # Настройки по умолчанию из settings.py
    # -----------------------------
    delay = delay if delay is not None else settings.IDOR_DELAY
    timeout = timeout if timeout is not None else settings.REQUEST_TIMEOUT

    # -----------------------------
    # Заголовки
    # -----------------------------
    if headers is None:
        headers = {
            "User-Agent": settings.DEFAULT_USER_AGENT
        }

    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    # -----------------------------
    # Основная логика
    # -----------------------------
    results = []
    base_hash = None
    base_length = None

    for value in range(start, stop + 1):
        try:
            # Формируем URL
            new_url = build_url_with_param(url, param, str(value))

            # Отправляем запрос
            response = send_request(new_url, method, param, str(value), headers, timeout)
            text = response.text.strip()

            # Хеш и длина
            resp_hash = hash_response(text)
            resp_len = len(text)

            # Базовый ответ
            if value == start:
                base_hash = resp_hash
                base_length = resp_len

            # Проверка различий
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


# -----------------------------
# Тестовый запуск
# -----------------------------
if __name__ == "__main__":
    test_url = "https://gazprombank.ru/"
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