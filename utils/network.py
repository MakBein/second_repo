# xss_security_gui/utils/network.py
"""
Network Utilities
-----------------
Обёртки для работы с requests:
• Ротация User-Agent
• Rate limiting через TokenBucket
• Retry-сессии с backoff
"""

import requests
import threading
import time
import hashlib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def rotating_user_agents() -> list[str]:
    """Возвращает список кастомных User-Agent для ротации."""
    return [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) XSSFuzz/2.0",
        "curl/8.0.1 (xss-audit)",
        "SecurityTest/1.1 (+test)",
    ]


def default_accepts() -> list[str]:
    """Возвращает список Accept-заголовков по умолчанию."""
    return [
        "*/*",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ]


# === TokenBucket для rate limiting ===
class TokenBucket:
    """Простейший rate limiter на основе токенов."""

    def __init__(self, rate_per_sec: float, burst: int | None = None, master: float = 1.0):
        self.master: float = float(master)
        self.rate: float = max(float(rate_per_sec), 0.01)
        self.capacity: int = burst if burst is not None else int(self.rate * 2)
        self.tokens: float = float(self.capacity)
        self.lock: threading.Lock = threading.Lock()
        self.last: float = time.time()

    def wait(self) -> None:
        """Ожидает, пока появится токен для запроса."""
        with self.lock:
            now: float = time.time()
            elapsed: float = now - self.last
            self.last = now

            # Пополнение токенов
            refill: float = elapsed * self.rate * self.master
            self.tokens = min(float(self.capacity), float(self.tokens + refill))

            if self.tokens < 1.0:
                needed: float = 1.0 - self.tokens
                sleep_time: float = needed / max(self.rate * self.master, 0.01)
                time.sleep(sleep_time)

                # Пересчёт после сна
                self.last = time.time()
                self.tokens = max(0.0, self.tokens)

            self.tokens -= 1.0

    def __repr__(self) -> str:
        return (f"<TokenBucket rate={self.rate:.2f} master={self.master:.2f} "
                f"tokens={self.tokens:.2f}/{self.capacity}>")

    @staticmethod
    def sha256_text(s: str) -> str:
        """SHA256-хеш строки."""
        return hashlib.sha256(s.encode(encoding="utf-8", errors="ignore")).hexdigest()


def create_retry_session(
    total: int = 7,
    backoff: float = 0.5,
    status_forcelist: tuple[int, ...] = (429, 500, 502, 503, 504),
    proxies: dict | None = None,
    headers: dict | None = None,
) -> requests.Session:
    """
    Создаёт requests.Session с автоматическим retry/backoff.
    """
    retry = Retry(
        total=total,
        connect=total,
        read=total,
        status=total,
        backoff_factor=backoff,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "PATCH"]),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)

    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.max_redirects = 5

    if proxies:
        session.proxies.update(proxies)

    # Заголовки по умолчанию
    base_headers = {
        "User-Agent": "XSS-Security-Scanner/1.0",
        "Accept": default_accepts()[0],
    }
    if headers:
        base_headers.update(headers)
    session.headers.update(base_headers)

    return session