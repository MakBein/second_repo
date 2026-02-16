# xss_security_gui/utils/network.py
import requests, threading, time, hashlib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def rotating_user_agents():
    return [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) XSSFuzz/2.0",
        "curl/8.0.1 (xss-audit)",
        "SecurityTest/1.1 (+test)"
    ]

def default_accepts():
    return ["*/*", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"]

# === TokenBucket для rate limiting ===

class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int | None = None, master: float = 1.0):
        self.master: float = float(master)
        self.rate: float = max(float(rate_per_sec), 0.01)
        self.capacity: int = burst if burst is not None else int(self.rate * 2)
        self.tokens: float = float(self.capacity)
        self.lock: threading.Lock = threading.Lock()
        self.last: float = time.time()

    def wait(self) -> None:
        with self.lock:
            now: float = time.time()
            elapsed: float = now - self.last
            self.last = now

            refill: float = elapsed * self.rate * self.master
            self.tokens = min(float(self.capacity), float(self.tokens + refill))

            if self.tokens < 1.0:
                needed: float = 1.0 - self.tokens
                sleep_time: float = needed / max(self.rate * self.master, 0.01)
                time.sleep(sleep_time)
                self.tokens = 0.0

            self.tokens -= 1.0

    def __repr__(self) -> str:
        return (f"<TokenBucket rate={self.rate:.2f} master={self.master:.2f} "
                f"tokens={self.tokens:.2f}/{self.capacity}>")

    @staticmethod
    def sha256_text(s: str) -> str:
        return hashlib.sha256(s.encode(encoding="utf-8", errors="ignore")).hexdigest()

def create_retry_session(
    total=7,
    backoff=0.5,
    status_forcelist=(429, 500, 502, 503, 504),
    proxies=None,
    timeout=None
) -> requests.Session:
    retry = Retry(
        total=total,
        connect=total,
        read=total,
        status=total,
        backoff_factor=backoff,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "PATCH"]),
        raise_on_status=False,
        respect_retry_after_header=True
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.max_redirects = 5
    if proxies:
        session.proxies.update(proxies)
    if timeout:
        session.timeout = timeout  # если используешь кастомные обёртки
    session.headers.update({
        "User-Agent": "XSS-Security-Scanner/1.0"
    })
    return session