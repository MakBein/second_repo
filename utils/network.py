# xss_security_gui/utils/network.py
# ============================================================
# Network Utilities 10.0 — async-ready, throttled, adaptive, threat-aware
# ============================================================

import asyncio
import hashlib
import random
import threading
import time
from typing import Optional, Dict, Any, Iterable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ============================================================
# User-Agent Engine 3.0 (threat-aware, stable)
# ============================================================

def rotating_user_agents(seed: Optional[str] = None) -> list[str]:
    """Возвращает стабильный список User-Agent с seed‑ротацией."""
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) XSSFuzz/10.0",
        "curl/8.3.0 (xss-audit; +threat-intel)",
        "SecurityTest/3.0 (+xss-security-gui)",
        "XSS-Scanner/10.0 (+https://example.com)",
    ]

    if seed:
        rnd = random.Random(hashlib.sha256(seed.encode()).hexdigest())
        rnd.shuffle(agents)
    else:
        random.shuffle(agents)

    return agents


def default_accepts() -> list[str]:
    return [
        "*/*",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ]


# ============================================================
# TokenBucket 10.0 — async-aware, monotonic-safe, GUI-friendly
# ============================================================

class TokenBucket:
    """
    TokenBucket 10.0:
    • Adaptive refill
    • No GUI blocking
    • Monotonic time
    • Thread-safe
    • Async-friendly (wait_async)
    """

    def __init__(self, rate_per_sec: float, burst: Optional[int] = None, master: float = 1.0):
        self.master = float(master)
        self.rate = max(float(rate_per_sec), 0.01)
        self.capacity = burst if burst is not None else int(self.rate * 2)
        self.tokens = float(self.capacity)
        self.lock = threading.Lock()
        self.last = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last
        self.last = now
        refill = elapsed * self.rate * self.master
        self.tokens = min(self.capacity, self.tokens + refill)

    def wait(self) -> None:
        """Синхронное ожидание токена без блокировки GUI."""
        with self.lock:
            self._refill()

            if self.tokens < 1.0:
                needed = 1.0 - self.tokens
                sleep_time = needed / max(self.rate * self.master, 0.01)
                time.sleep(min(sleep_time, 0.25))
                self.last = time.monotonic()
                self.tokens = max(0.0, self.tokens)

            self.tokens -= 1.0

    async def wait_async(self) -> None:
        """Асинхронное ожидание токена для async‑кода."""
        with self.lock:
            self._refill()

            if self.tokens < 1.0:
                needed = 1.0 - self.tokens
                sleep_time = needed / max(self.rate * self.master, 0.01)
                sleep_time = min(sleep_time, 0.25)
            else:
                sleep_time = 0.0

            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

            self.tokens -= 1.0

    @staticmethod
    def sha256_text(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8", "ignore")).hexdigest()

    def __repr__(self) -> str:
        return f"<TokenBucket10 rate={self.rate:.2f} tokens={self.tokens:.2f}/{self.capacity}>"


# ============================================================
# Retry Session 10.0 — adaptive backoff + safe timeouts + threat-aware
# ============================================================

def create_retry_session(
    total: int = 7,
    backoff: float = 0.5,
    status_forcelist: Iterable[int] = (429, 500, 502, 503, 504),
    proxies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
) -> requests.Session:
    """
    Создаёт requests.Session с:
    • adaptive retry/backoff
    • safe timeouts
    • UA rotation
    • thread-safe request wrapper
    """

    retry = Retry(
        total=total,
        connect=total,
        read=total,
        status=total,
        backoff_factor=backoff,
        status_forcelist=tuple(status_forcelist),
        allowed_methods=frozenset([
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "PATCH"
        ]),
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

    base_headers = {
        "User-Agent": rotating_user_agents(seed="network10")[0],
        "Accept": default_accepts()[0],
    }
    if headers:
        base_headers.update(headers)

    session.headers.update(base_headers)

    session.request = _wrap_request_with_timeout(session.request, timeout)

    return session


# ============================================================
# Internal: safe request wrapper
# ============================================================

def _wrap_request_with_timeout(original_request, timeout: float):
    """Гарантирует timeout и отсутствие зависаний."""
    def wrapped(method: str, url: str, **kwargs: Any):
        if "timeout" not in kwargs:
            kwargs["timeout"] = timeout
        return original_request(method, url, **kwargs)
    return wrapped


# ============================================================
# Async helper (for future async HTTP clients)
# ============================================================

async def async_sleep_backoff(base: float, factor: float, attempt: int) -> None:
    """Простой async backoff helper."""
    delay = base * (factor ** attempt)
    await asyncio.sleep(min(delay, 5.0))


