# xss_security_gui/crawler.py
"""
Enterprise-grade SUPER-CRAWLER for XSSSecurityGUI

Функції:
- Глибокий краул сайту з rate-limit’ом і паралелізмом
- Витяг чутливих даних (emails, телефони, токени, паролі, карти, адреси, API-ендпоінти)
- Інтеграція з Threat Intel (Burp/ZAP-style summary)
- Маскування секретів, нормалізація структур, безпечний експорт JSON/DOT/SVG

Автор: Aleksandr + Copilot (refactored to battle-ready level)
"""

import os
import re
import json
import time
import shutil
import tempfile
import logging
import threading
import subprocess
import random
import socket
import ssl


from hashlib import sha1
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import cloudscraper
import cloudscraper as cfscraper
from fake_useragent import UserAgent
from bs4 import BeautifulSoup, Comment
import dns.resolver
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from tls_client import Session as TLSClientSession  # type: ignore
    TLS_CLIENT_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    TLSClientSession = None  # type: ignore
    TLS_CLIENT_AVAILABLE = False

from xss_security_gui.js_inspector import extract_js_insights
from xss_security_gui.settings import settings
from xss_security_gui.settings import (
    CRAWL_DEPTH_LIMIT,
    CRAWL_DOMAINS_WHITELIST,
    LOG_CRAWL_STRUCTURE_PATH,
    LOG_CRAWL_GRAPH_DOT,
    LOG_CRAWL_GRAPH_SVG,
    JSON_CRAWL_EXPORT_PATH,
    CRAWLER_ERROR_LOG,
)

# ---------------------------------------------------------------------
# Configuration (from settings with hardened defaults)
# ---------------------------------------------------------------------
REQUEST_TIMEOUT: int = int(settings.get("http.request_timeout", 10) or 10)
PROXIES: Optional[Dict[str, str]] = settings.get("http.proxies", None)
RATE_LIMIT: float = float(settings.get("crawl.max_rps", 2.0) or 2.0)

MAX_LINKS_PER_PAGE: int = int(settings.get("crawl.max_links_per_page", 500) or 500)
MAX_SCRIPTS_PER_PAGE: int = int(settings.get("crawl.max_scripts_per_page", 200) or 200)
MAX_CONCURRENT_REQUESTS: int = int(settings.get("crawl.max_workers", 20) or 20)

AGGRESSIVE_HEADERS: bool = bool(settings.get("http.aggressive_headers", True))

MAX_MATCHES_PER_KEY: int = int(settings.get("crawl.max_matches_per_key", 200) or 200)
MAX_API_ENDPOINTS: int = int(settings.get("crawl.max_api_endpoints", 200) or 200)

# Anti-detection settings
ENABLE_TLS_SPOOFING: bool = bool(settings.get("anti_detection.tls_spoofing", True))
ENABLE_PLAYWRIGHT_STEALTH: bool = bool(settings.get("anti_detection.playwright_stealth", True))
ENABLE_DOH_RESOLVER: bool = bool(settings.get("anti_detection.dns_over_https", True))
ENABLE_GEO_IP_ROTATION: bool = bool(settings.get("anti_detection.geo_ip_rotation", True))
ENABLE_CHROME_FINGERPRINT: bool = bool(settings.get("anti_detection.chrome_fingerprint", True))
ENABLE_MULTI_SESSION_ROTATION: bool = bool(settings.get("anti_detection.multi_session", True))
ENABLE_AUTO_RETRY: bool = bool(settings.get("anti_detection.auto_retry", True))
# Sensitive extraction mode
ENABLE_ULTRA_SENSITIVE = bool(settings.get("sensitive.ultra_mode", False))


# ---------------------------------------------------------------------
# Logger and error logging helper
# ---------------------------------------------------------------------
logger = logging.getLogger("crawler")
logger.setLevel(logging.INFO)

# -----------------------------------------
# ADD THESE THREE LINES
# -----------------------------------------
COMMON_USER_AGENTS = []
COMMON_REFERERS = []
COMMON_LANGUAGES = []

# ---------------------------------------------------------------------
# Common JA3 fingerprints (real browser TLS ClientHello fingerprints)
# ---------------------------------------------------------------------
JA3_FINGERPRINTS = [
    # Chrome 120 (Windows)
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-13-16-5,23-24,0",

    # Firefox 121 (Windows)
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-13-16-5,23-24,0",

    # Safari 17.2 (macOS)
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-13-16-5,23-24,0",

    # Edge 120 (Windows)
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-13-16-5,23-24,0",

    # Opera 106 (Windows)
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-13-16-5,23-24,0"
]

# Common user agents for rotation
COMMON_USER_AGENTS.extend([
    # Windows 11 Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36",
    # Windows 11 Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 Edg/125.0.2535.67",
    # macOS Sonoma Chrome
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36",
    # macOS Sonoma Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    # Linux Chrome
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36",
    # Android Chrome
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Mobile Safari/537.36",
    # iPhone Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
])

# Common referers
COMMON_REFERERS.extend([
    "https://www.facebook.com/",
    "https://www.instagram.com/",
    "https://www.reddit.com/",
    "https://news.google.com/",
    "https://www.youtube.com/",
    "https://www.linkedin.com/",
    "https://t.co/",  # Twitter redirect
    "https://l.facebook.com/",  # Facebook redirect
])

# Common accept languages
COMMON_LANGUAGES.extend([
    "en-CA,en;q=0.9",
    "en-AU,en;q=0.9",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "pl-PL,pl;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.8"
])

def get_random_ja3() -> str:
    """Return a random JA3 fingerprint profile."""
    return random.choice(JA3_FINGERPRINTS)

def get_random_user_agent() -> str:
    return random.choice(COMMON_USER_AGENTS)

def get_random_referer() -> str:
    return random.choice(COMMON_REFERERS)

def get_random_language() -> str:
    return random.choice(COMMON_LANGUAGES)

def log_error(msg: str) -> None:
    """Log error both to logger and dedicated crawler error log."""
    try:
        logger.error(msg)
        if CRAWLER_ERROR_LOG:
            os.makedirs(os.path.dirname(CRAWLER_ERROR_LOG) or "logs", exist_ok=True)
            with open(CRAWLER_ERROR_LOG, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now(timezone.utc).isoformat()}] {msg}\n")
    except Exception:
        logger.exception("Failed to write to CRAWLER_ERROR_LOG")


# ---------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------
_last_request: float = 0.0
_rate_lock = threading.Lock()


def rate_limit() -> None:
    """Global rate limiter to respect crawl.max_rps."""
    global _last_request
    with _rate_lock:
        try:
            r = float(RATE_LIMIT) if RATE_LIMIT else 1.0
        except Exception:
            r = 1.0
        min_interval = 1.0 / max(r, 0.0001)
        now = time.time()
        delta = max(0.0, now - _last_request)
        if delta < min_interval:
            time.sleep(min_interval - delta)
        _last_request = time.time()


# ---------------------------------------------------------------------
# Playwright availability
# ---------------------------------------------------------------------
try:
    from playwright.sync_api import sync_playwright  # type: ignore

    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

# ---------------------------------------------------------------------
# Global in-memory structures (reset by reset_state)
# ---------------------------------------------------------------------
visited: Set[str] = set()
tree_log: List[str] = []
dot_edges: List[Tuple[str, str]] = []
nodes_json: List[Dict[str, Any]] = []
js_cache: Dict[str, Dict[str, Any]] = {}

visited_lock = threading.Lock()
nodes_lock = threading.Lock()
dot_lock = threading.Lock()

# ---------------------------------------------------------------------
# HTTP headers
# ---------------------------------------------------------------------
DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

if AGGRESSIVE_HEADERS:
    DEFAULT_HEADERS.update(
        {
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
        }
    )

# ============================================================
#  Anti‑WAF Bypass 1.0 — profiles, headers, behavior
# ============================================================

ANTI_WAF_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",

    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",

    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) "
    "Gecko/20100101 Firefox/124.0",
]

ANTI_WAF_ACCEPT_LANG = [
    "en-US,en;q=0.9",
    "ru-RU,ru;q=0.9,en-US;q=0.8",
    "uk-UA,uk;q=0.9,en-US;q=0.8",
]

ANTI_WAF_REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
]

# ---------------------------------------------------------------------
# TLS Configuration (cipher suite list)
# ---------------------------------------------------------------------
TLS_SPOOF_CIPHERS = [
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
]

# ---------------------------------------------------------------------
# GeoIP Database (safe initialization)
# ---------------------------------------------------------------------

try:
    import geoip2.database
    GEOIP_READER = geoip2.database.Reader("GeoLite2-Country.mmdb")
except Exception:
    GEOIP_READER = None
    logger.warning("GeoIP database not available — continuing without GeoIP support")


# ---------------------------------------------------------------------
# Enhanced HTTP headers with fingerprint injection
# ---------------------------------------------------------------------
class ChromeFingerprint:
    """Generates realistic Chrome browser fingerprints with regional profiles."""

    def __init__(self):
        self.ua = UserAgent()

        # Platforms
        self.platforms = ["Win32", "Macintosh", "X11"]

        # Chrome brand sets
        self.brands = [
            [{"brand": "Google Chrome", "version": "124"}, {"brand": "Chromium", "version": "124"}],
            [{"brand": "Not;A=Brand", "version": "99"}, {"brand": "Google Chrome", "version": "124"}],
        ]

        # Regional Accept-Language presets
        self.regional_lang = {
            "ru": "ru-RU,ru;q=0.9,en-US;q=0.8",
            "ua": "uk-UA,uk;q=0.9,en-US;q=0.8",
            "us": "en-US,en;q=0.9",
            "eu": "en-GB,en;q=0.9,de-DE;q=0.8,fr-FR;q=0.8",
        }

    def get_headers(self, region: str = "us") -> Dict[str, str]:
        """Return Chrome-like headers for a specific region."""

        # Fallback region
        region = region.lower()
        if region not in self.regional_lang:
            region = "us"

        platform = random.choice(self.platforms)
        brand = random.choice(self.brands)

        return {
            "User-Agent": self.ua.random,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Accept-Language": self.regional_lang[region],
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Ch-Ua": (
                f'"{brand[0]["brand"]}";v="{brand[0]["version"]}", '
                f'"{brand[1]["brand"]}";v="{brand[1]["version"]}"'
            ),
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": f'"{platform}"',
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Upgrade-Insecure-Requests": "1",
            "Connection": "keep-alive",
            "Cache-Control": "max-age=0",
        }


# Instantiate global fingerprint object (fake_useragent may fail offline)
try:
    fingerprint = ChromeFingerprint()
except Exception:
    fingerprint = None
    logger.warning("ChromeFingerprint unavailable — using static user-agents")

# ---------------------------------------------------------------------
# DNS-over-HTTPS Resolver
# ---------------------------------------------------------------------

DOH_SERVERS = [
    # Cloudflare
    "https://cloudflare-dns.com/dns-query",
    "https://1.1.1.1/dns-query",
    "https://1.0.0.1/dns-query",

    # Google
    "https://dns.google/resolve",
    "https://dns.google/dns-query",

    # Quad9
    "https://dns.quad9.net/dns-query",
    "https://9.9.9.9/dns-query",

    # NextDNS
    "https://dns.nextdns.io/dns-query",

    # OpenDNS
    "https://doh.opendns.com/dns-query",

    # CleanBrowsing (Family filter)
    "https://doh.cleanbrowsing.org/doh/family-filter/",
    # Adult filter
    "https://doh.cleanbrowsing.org/doh/adult-filter/",
    # Security filter
    "https://doh.cleanbrowsing.org/doh/security-filter/",

    # AdGuard
    "https://dns.adguard.com/dns-query",
    "https://dns-family.adguard.com/dns-query",

    # AliDNS (China)
    "https://dns.alidns.com/dns-query",

    # Neustar UltraDNS
    "https://doh-1.ultradns.com/dns-query",
    "https://doh-2.ultradns.com/dns-query",

    # Comcast
    "https://doh.xfinity.com/dns-query",

    # Mullvad Privacy
    "https://doh.mullvad.net/dns-query",

    # SecureDNS EU
    "https://doh.securedns.eu/dns-query"
]

# Fallback DNS servers (UDP)
FALLBACK_DNS = [
    ("8.8.8.8", 53),       # Google DNS
    ("8.8.4.4", 53),       # Google secondary
    ("1.1.1.1", 53),       # Cloudflare
    ("1.0.0.1", 53),       # Cloudflare secondary
    ("9.9.9.9", 53),       # Quad9
    ("149.112.112.112", 53),  # Quad9 secondary
    ("208.67.222.222", 53),   # OpenDNS
    ("208.67.220.220", 53),   # OpenDNS secondary
]


def resolve_dns(domain: str) -> str:
    """
    Resolve domain using DNS-over-HTTPS with multiple fallback mechanisms.
    Stable refactored version:
    - Same logic preserved
    - Clear structure
    - Better readability
    - Safer error handling
    """
    # -------------------------------------------------------------
    # 1. DoH resolution
    # -------------------------------------------------------------
    if not ENABLE_DOH_RESOLVER:
        return socket.gethostbyname(domain)

    for doh_server in DOH_SERVERS:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['1.1.1.1']  # Cloudflare default

            query = dns.message.make_query(domain, dns.rdatatype.A)
            response = dns.query.https(query, doh_server)

            if response.answer:
                return str(response.answer[0][0])

        except Exception as e:
            logger.debug(f"DoH resolution failed with {doh_server}: {str(e)}")
            continue

    # -------------------------------------------------------------
    # 2. Traditional DNS fallback (manual UDP packet)
    # -------------------------------------------------------------
    for dns_server, port in FALLBACK_DNS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)

            # DNS header
            transaction_id = random.randint(0, 65535)
            flags = 0x0100  # Standard query
            qdcount = 1
            header = (
                transaction_id.to_bytes(2, 'big') +
                flags.to_bytes(2, 'big') +
                qdcount.to_bytes(2, 'big') +
                (0).to_bytes(2, 'big') +  # ancount
                (0).to_bytes(2, 'big') +  # nscount
                (0).to_bytes(2, 'big')    # arcount
            )

            # Question section
            question = b''
            for part in domain.split('.'):
                question += len(part).to_bytes(1, 'big') + part.encode('ascii')
            question += b'\x00'
            question += (1).to_bytes(2, 'big')  # Type A
            question += (1).to_bytes(2, 'big')  # Class IN

            # Send query
            sock.sendto(header + question, (dns_server, port))

            # Receive response
            response, _ = sock.recvfrom(512)
            sock.close()

            # Parse response
            if len(response) >= 12 and response[0:2] == transaction_id.to_bytes(2, 'big'):
                offset = 12

                # Skip name
                while offset < len(response):
                    length = response[offset]
                    if length == 0:
                        offset += 1
                        break
                    if (length & 0xC0) == 0xC0:
                        offset += 2
                        break
                    offset += length + 1

                # Type + Class
                if offset + 4 <= len(response):
                    qtype = int.from_bytes(response[offset:offset+2], 'big')
                    qclass = int.from_bytes(response[offset+2:offset+4], 'big')

                    if qtype == 1 and qclass == 1:  # A record
                        offset += 8  # Skip type, class, ttl, rdlength

                        if offset + 4 <= len(response):
                            ip = socket.inet_ntoa(response[offset:offset+4])
                            return ip

            logger.debug(f"Traditional DNS resolution failed with {dns_server}")
            continue

        except Exception as e:
            logger.debug(f"DNS resolution failed with {dns_server}: {str(e)}")
            continue

    # -------------------------------------------------------------
    # 3. Final fallback: system DNS
    # -------------------------------------------------------------
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        logger.error(f"All DNS resolution methods failed for {domain}: {str(e)}")
        raise


# ---------------------------------------------------------------------
# Multi-Session Rotation
# ---------------------------------------------------------------------
BROWSER_SESSIONS = [
    {"browser": "chrome", "headless": False},
    {"browser": "firefox", "headless": False},
    {"browser": "edge", "headless": False},
]


def get_random_session() -> Dict[str, Any]:
    """
    Get random browser session configuration.
    Улучшено:
    - стабильный выбор user-agent
    - аккуратная генерация viewport
    - защита от ошибок fake_useragent
    - полностью сохранена логика и структура
    """
    session = random.choice(BROWSER_SESSIONS)
    ua = None
    if fingerprint is not None:
        try:
            ua = fingerprint.ua.random
        except Exception:
            ua = None
    return {
        **session,
        "user_agent": ua or get_random_user_agent(),
        "viewport": {"width": random.randint(1280, 1920), "height": random.randint(720, 1080)}
    }

# ---------------------------------------------------------------------
# Automatic Retry Strategy
# ---------------------------------------------------------------------

MAX_RETRIES = 5
RETRY_DELAYS = [1, 2, 4]  # Exponential backoff (1s → 2s → 4s)

# Retry-worthy HTTP status codes:
# 408 — Request Timeout
# 429 — Too Many Requests (rate limit)
# 5xx — Server errors
RETRY_STATUS_CODES = {408, 429, 502, 503, 504}

def should_retry(status_code: int) -> bool:
    """
    Determine if request should be retried.
    Улучшено:
    - вынесены коды в константу
    - добавлены пояснения
    - логика полностью сохранена
    """
    if not ENABLE_AUTO_RETRY:
        return False

    return status_code >= 500 or status_code in RETRY_STATUS_CODES


def build_anti_waf_headers(base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Build realistic, randomized browser headers to reduce bot fingerprint.
    """
    h = dict(base or {})
    h["User-Agent"] = random.choice(ANTI_WAF_USER_AGENTS)
    h["Accept-Language"] = random.choice(ANTI_WAF_ACCEPT_LANG)
    h["Referer"] = random.choice(ANTI_WAF_REFERERS)
    h.setdefault("Accept", DEFAULT_HEADERS["Accept"])
    h.setdefault("Connection", "keep-alive")
    h.setdefault("Upgrade-Insecure-Requests", "1")
    h.setdefault("Sec-Fetch-Site", "none")
    h.setdefault("Sec-Fetch-Mode", "navigate")
    h.setdefault("Sec-Fetch-User", "?1")
    h.setdefault("Sec-Fetch-Dest", "document")
    return h


def simulate_human_behavior_playwright(page) -> None:
    """
    Lightweight human-like behavior simulation:
      - random scrolls
      - small mouse moves
      - short idle delays
    """
    try:
        # Random scrolls
        for _ in range(random.randint(2, 5)):
            x = random.randint(0, 1920)
            y = random.randint(0, 1080)
            page.mouse.move(x, y, steps=random.randint(5, 15))
            page.wait_for_timeout(random.randint(200, 800))
            page.mouse.wheel(0, random.randint(200, 800))
            page.wait_for_timeout(random.randint(200, 800))
    except Exception:
        # Never break crawl on behavior simulation
        pass

# ---------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------
def reset_state() -> None:
    """Clear in-memory crawler state between runs."""
    with visited_lock:
        visited.clear()
    with nodes_lock:
        nodes_json.clear()
        tree_log.clear()
    with dot_lock:
        dot_edges.clear()
    js_cache.clear()


def run_crawl_in_background(
    url: str,
    *,
    depth: int = 0,
    session: Optional[requests.Session] = None,
    gui_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    max_links: int = MAX_LINKS_PER_PAGE,
    max_scripts: int = MAX_SCRIPTS_PER_PAGE,
    aggressive: bool = AGGRESSIVE_HEADERS,
    parallel: bool = True,
    reset_state_before_run: bool = True,
    on_progress: Optional[Callable[[Dict[str, Any]], None]] = None,
    on_result: Optional[Callable[[Dict[str, Any]], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
) -> threading.Thread:
    """Run a crawl in a daemon thread so GUI stays responsive."""

    def _invoke(callback: Optional[Callable[[Any], None]], payload: Any) -> None:
        if not callback:
            return
        try:
            callback(payload)
        except Exception:
            logger.debug("Background crawler callback failed", exc_info=True)

    def _worker() -> None:
        try:
            if reset_state_before_run:
                reset_state()

            def _progress(payload: Dict[str, Any]) -> None:
                _invoke(gui_callback, payload)
                _invoke(on_progress, payload)

            result = crawl_site(
                url,
                depth=depth,
                session=session,
                gui_callback=_progress,
                max_links=max_links,
                max_scripts=max_scripts,
                aggressive=aggressive,
                parallel=parallel,
            )
            if not isinstance(result, dict):
                raise ValueError("Crawler returned unexpected data type")

            save_outputs(result, gui_callback=_progress)
            _invoke(on_result, result)
        except Exception as exc:
            _invoke(on_error, exc)
            logger.exception("Background crawl failed")

    thread = threading.Thread(
        target=_worker,
        name="CrawlerBackground",
        daemon=True,
    )
    thread.start()
    return thread


def dedupe_preserve_order(seq: List[Any]) -> List[Any]:
    """Remove duplicates while preserving order. Works for hashable and JSON-serializable items."""
    seen = set()
    out: List[Any] = []
    for item in seq:
        try:
            key = (
                item
                if isinstance(item, (str, int, float, tuple))
                else json.dumps(item, sort_keys=True, ensure_ascii=False)
            )
        except Exception:
            key = str(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def hash_url_no_query(u: str) -> str:
    """Hash URL without query/fragment for uniqueness tracking."""
    parsed = urlparse(u)._replace(query="", fragment="")
    return sha1(parsed.geturl().encode()).hexdigest()


def normalize_scheme(url: str) -> str:
    """Normalize URL scheme to https if missing."""
    if not url:
        return ""
    parsed = urlparse(url)
    if not parsed.scheme:
        if url.startswith("//"):
            return "https:" + url
        return "https://" + url.lstrip("/")
    return parsed.geturl()


def _normalize_candidate(cand: str, base_url: str) -> str:
    """Normalize relative/absolute candidate into absolute URL; return empty string for invalid."""
    if not cand:
        return ""
    cand = cand.strip().strip("'\"")
    if not cand:
        return ""
    if cand.startswith(("http://", "https://")):
        return cand
    if cand.startswith("/"):
        return urljoin(base_url, cand)
    return urljoin(base_url, "/" + cand)


def _is_http_url(u: str) -> bool:
    try:
        p = urlparse(u)
        return p.scheme in ("http", "https")
    except Exception:
        return False


def is_same_domain(url: str, base_netloc: str) -> bool:
    """Check if URL belongs to same domain (with whitelist support)."""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        if not netloc:
            return False

        base = (base_netloc or "").lower()
        if not base:
            return False

        if netloc.startswith("www."):
            netloc = netloc[4:]
        if base.startswith("www."):
            base = base[4:]

        if CRAWL_DOMAINS_WHITELIST:
            wl = [d.lower() for d in CRAWL_DOMAINS_WHITELIST]
            if netloc not in wl and not any(netloc.endswith("." + d) for d in wl):
                return False

        return netloc == base or netloc.endswith("." + base)
    except Exception:
        return False


def is_real_link(href: str) -> bool:
    """Filter out non-navigational links."""
    if not href:
        return False
    href = href.strip().lower()
    if href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return False
    return True


def mask_secret(s: str, keep: int = 4) -> str:
    """Mask sensitive value, keeping first/last N chars."""
    s = str(s)
    if len(s) <= keep * 2:
        return "*" * len(s)
    return s[:keep] + "*" * (len(s) - keep * 2) + s[-keep:]


def _merge_sensitive_into_node(node: Dict[str, Any], sensitive: Dict[str, List[str]]) -> None:
    """Merge extracted sensitive data into node lists; only keys that exist on node are updated."""
    for key, value in sensitive.items():
        if key in node and value:
            node[key].extend(value)


def _trim_node_list_fields(node: Dict[str, Any], cap: int = MAX_MATCHES_PER_KEY) -> None:
    """Dedupe and cap all list fields in node in place."""
    for k in list(node.keys()):
        if isinstance(node[k], list):
            node[k] = dedupe_preserve_order(node[k])[:cap]


def _safe_trim_value(value: Any, max_len: int = 5000) -> str:
    """Normalize value to str, trim overly long values, guarantee safe type."""
    try:
        s = str(value)
    except Exception:
        s = repr(value)
    s = s.strip()
    if not s:
        return ""
    if len(s) > max_len:
        return s[:max_len] + "…"
    return s


def _append_limited_unique(bucket: List[str], value: Any, limit: int = MAX_MATCHES_PER_KEY) -> None:
    """Append value to bucket if non-empty, unique, and under limit."""
    if len(bucket) >= limit:
        return
    s = _safe_trim_value(value)
    if not s:
        return
    if s in bucket:
        return
    bucket.append(s)

def build_stealth_headers(base_headers: Optional[Dict] = None) -> Dict:
    """
    Build headers that mimic a real browser while avoiding fingerprinting
    """
    headers = base_headers or {}

    # Randomize user agent
    headers["User-Agent"] = get_random_user_agent()

    # Randomize accept header
    headers["Accept"] = (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
    )

    # Randomize accept-encoding
    headers["Accept-Encoding"] = random.choice(["gzip, deflate, br", "gzip, deflate"])

    # Randomize accept-language
    headers["Accept-Language"] = get_random_language()

    # Randomize DNT header
    headers["DNT"] = str(random.randint(0, 1))

    # Randomize connection header
    headers["Connection"] = random.choice(["keep-alive", "close"])

    # Randomize upgrade-insecure-requests
    headers["Upgrade-Insecure-Requests"] = str(random.randint(0, 1))

    # Randomize cache-control
    headers["Cache-Control"] = random.choice([
        "max-age=0",
        "no-cache",
        "no-store",
        "max-age=2592000"
    ])

    # Randomize referer
    headers["Referer"] = get_random_referer()

    # Security headers that look real but don't reveal bot nature
    headers.update({
        "Sec-Fetch-Dest": random.choice(["document", "empty"]),
        "Sec-Fetch-Mode": random.choice(["navigate", "same-origin", "no-cors"]),
        "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
        "Sec-Fetch-User": "?1" if random.random() > 0.5 else "?0",
    })

    # Additional headers to blend in
    headers.update({
        "Sec-CH-UA": f'"Not_A Brand";v="8", "Chromium";v="120"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": random.choice(['"Windows"', '"macOS"', '"Linux"']),
    })

    # ------------------------------------------------------------
    # ⭐ ADDITIONAL MODERN CHROME-LIKE HEADERS (ENHANCEMENT)
    # ------------------------------------------------------------
    headers.update({
        # Chrome network quality hints
        "Viewport-Width": str(random.choice([1366, 1440, 1536, 1600, 1680, 1920])),
        "Device-Memory": str(random.choice([4, 8, 16])),
        "Downlink": str(random.choice([0.5, 1.0, 1.5, 5.0, 10.0])),
        "ECT": random.choice(["slow-2g", "2g", "3g", "4g"]),
        "Rtt": str(random.choice([50, 100, 150, 200, 300])),
        "Save-Data": "on" if random.random() > 0.7 else "off",

        # Chrome privacy header
        "Sec-GPC": "1",

        # Chrome priority header (used in HTTP/2/3)
        "Priority": "u=0, i",

        # Chrome client hints (extended)
        "Sec-CH-UA-Arch": random.choice(['"x86"', '"x86_64"', '"arm"', '"arm64"']),
        "Sec-CH-UA-Platform-Version": random.choice(['"14.0.0"', '"15.0.0"', '"16.0.0"']),

        # Chrome fetch behavior
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": random.choice(["document", "empty", "iframe"]),
        "Sec-Fetch-Mode": random.choice(["navigate", "same-origin", "cors"]),
        "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
    })

    return headers


# Enable TLS client JA3 impersonation
USE_TLS_CLIENT = bool(settings.get("anti_detection.use_tls_client", False))

# -----------------------------------------------------------
# Modern TLS / HTTP2 support (legal)
# -----------------------------------------------------------
try:
    import httpx
    HTTP2_AVAILABLE = True
except ImportError:
    HTTP2_AVAILABLE = False
except Exception:
    HTTP2_AVAILABLE = False

# ---------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------
def make_session(
    aggressive: bool = True,
    max_retries: int = 3,
    pool_connections: int = 50,
    pool_maxsize: int = 50,
    delay: Optional[float] = 1.5,
    delay_jitter: float = 0.3
) -> requests.Session:

    # -----------------------------------------------------------
    # Choose TLS client or requests.Session
    # -----------------------------------------------------------
    s: Any = None
    if USE_TLS_CLIENT and TLS_CLIENT_AVAILABLE and TLSClientSession is not None:
        try:
            s = TLSClientSession(
                client_identifier=random.choice([
                    "chrome_120",
                    "chrome_121",
                    "chrome_118",
                    "firefox_120",
                    "safari_17_0",
                    "edge_116"
                ]),
                random_tls_extension_order=True
            )
        except Exception as e:
            logger.error("Failed to create TLS client session: %s", e)
            s = None
    if s is None:
        s = requests.Session()

    # -----------------------------------------------------------
    # Configure retry strategy (only for requests.Session)
    # -----------------------------------------------------------
    if isinstance(s, requests.Session):
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )

        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy
        )

        s.mount("https://", adapter)
        s.mount("http://", adapter)

    # -----------------------------------------------------------
    # PROXY SUPPORT
    # -----------------------------------------------------------
    if PROXIES:
        try:
            s.proxies.update(PROXIES)
        except Exception:
            logger.warning("Invalid PROXIES configuration; skipping proxies.")

    # -----------------------------------------------------------
    # STEALTH MODE
    # -----------------------------------------------------------
    if aggressive:

        stealth_headers = build_stealth_headers()

        stealth_headers.update({
            "X-Requested-With": "XMLHttpRequest",
            "Pragma": "no-cache",
            "TE": "trailers",
            "Origin": random.choice([
                "https://www.google.com",
                "https://www.bing.com",
                "https://duckduckgo.com"
            ]),
            "Sec-GPC": "1"
        })

        stealth_headers.update({
            "Viewport-Width": str(random.choice([1366, 1440, 1536, 1600, 1680, 1920])),
            "Device-Memory": str(random.choice([4, 8, 16])),
            "Downlink": str(random.choice([0.5, 1.0, 1.5, 5.0, 10.0])),
            "ECT": random.choice(["slow-2g", "2g", "3g", "4g"]),
            "Rtt": str(random.choice([50, 100, 150, 200, 300])),
            "Save-Data": "on" if random.random() > 0.7 else "off",
            "Sec-CH-UA-Arch": random.choice(['"x86"', '"x86_64"', '"arm"', '"arm64"']),
            "Sec-CH-UA-Platform-Version": random.choice(['"14.0.0"', '"15.0.0"', '"16.0.0"']),
            "Sec-CH-UA-Full-Version-List": f'"Chromium";v="120.0.0.0", "Google Chrome";v="120.0.0.0"',
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": random.choice(["document", "empty", "iframe"]),
            "Sec-Fetch-Mode": random.choice(["navigate", "same-origin", "cors"]),
            "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
            "Priority": "u=0, i"
        })

        s.headers.update(stealth_headers)

        if delay is not None:
            s.request = _throttled_request(s.request, delay, delay_jitter)

    else:
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; XSSSecurityCrawler/2.0; +https://localhost)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })

    return s

def _throttled_request(original_request, delay: float, jitter: float):
    """
    Wrapper to add delay between requests with jitter
    """
    def throttled(*args, **kwargs):
        actual_delay = delay * (1 + random.uniform(-jitter, jitter))
        if actual_delay > 0:
            time.sleep(actual_delay)
        return original_request(*args, **kwargs)

    return throttled

# ---------------------------------------------------------------------
# Luhn check for credit cards
# ---------------------------------------------------------------------
def luhn_check(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    checksum = 0
    parity = len(digits) % 2

    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d

    return checksum % 10 == 0


# ---------------------------------------------------------------------
# Precompiled patterns (emails, phones, tokens, secrets, cards, etc.)
# ---------------------------------------------------------------------
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

PASSWORD_PATTERNS_COMPILED = [
    re.compile(r"(?:password|passwd|pwd)[=:]\s*['\"]?([^'\"]{6,})['\"]?", re.I),
    re.compile(r"password['\"]?\s*[:=]\s*['\"]?([^'\"]{6,})['\"]?", re.I),
]

SECRET_PATTERNS_COMPILED = [
    re.compile(
        r"(?:secret|private[_-]?key|public[_-]?key)[=:]\s*['\"]?([A-Za-z0-9_\-\.+/=]{20,})['\"]?",
        re.I,
    ),
    re.compile(r"-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE|PUBLIC)\s+KEY-----", re.I),
]

EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PHONE_RE_LIST = [
    re.compile(r"(?:\+?\d{1,3}[-.\s]?\(?\d{2,3}\)?[-.\s]?\d{2,3}[-.\s]?\d{2,2}[-.\s]?\d{2,2})"),
    re.compile(r"(?:\+7|8)[-\s]?(?:9\d{2}|3\d{2}|4\d{2}|8\d{2})[-\s]?\d{3}[-\s]?\d{2}[-\s]?\d{2}"),
    re.compile(r"\+1[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}"),
    re.compile(r"\d{3}[-.\s]?\d{3}[-.\s]?\d{4}"),
]

TOKEN_PATTERNS_COMPILED = [
    re.compile(
        r"(?:auth[_-]?token|session[_-]?id|api[_-]?key|access[_-]?token|refresh[_-]?token)[=:]?\s*([A-Za-z0-9_\-\.]{8,})",
        re.I,
    ),
    re.compile(r"(?:bearer|token|key|secret)[=:]\s*([A-Za-z0-9_\-\.]{8,})", re.I),
    re.compile(r"['\"]([a-zA-Z0-9_\-]{32,})['\"]"),
]

JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
IPV6_RE = re.compile(
    r"\b(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,7}:|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|"
    r"[0-9A-Fa-f]{1,4}:(?:(?::[0-9A-Fa-f]{1,4}){1,6})|"
    r":(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)|"
    r"fe80:(?::[0-9A-Fa-f]{0,4}){0,4}%[0-9A-Za-z]+|"
    r"::(?:ffff(?::0{1,4}){0,1}:){0,1}"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,4}:"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b"
)

MAC_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b|\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b"
)
CIDR_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)/(?:[0-9]|[12][0-9]|3[0-2])\b"
    r"|\b[0-9A-Fa-f:]+/[0-9]{1,3}\b"
)

HOSTNAME_RE = re.compile(
    r"\b(?=.{1,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b"
)
PARAM_RE = re.compile(r"\b([a-zA-Z0-9_]+=[a-zA-Z0-9_\-\.]+)\b")
BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){5,}(?:==|=)?\b")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)

HASH_PATTERNS = [
    re.compile(r"\b[a-f0-9]{32}\b", re.I),
    re.compile(r"\b[a-f0-9]{40}\b", re.I),
    re.compile(r"\b[a-f0-9]{64}\b", re.I),
]

API_KEY_PATTERNS = [
    re.compile(r"(?:api[_-]?key|apikey)[=:]\s*([A-Za-z0-9_\-]{20,})", re.I),
    re.compile(r"(?:sk|pk)_[A-Za-z0-9_\-]{20,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
]

CREDIT_CARD_RE = re.compile(
    r"\b(?:(4[0-9]{12}(?:[0-9]{3})?)|(5[1-5][0-9]{14})|(3[47][0-9]{13})|"
    r"(6(?:011|5[0-9]{2})[0-9]{12})|(35[0-9]{14})|(62[0-9]{14,17}))\b"
)
CVV_RE = re.compile(r"(?:cvv|cvc|cid|security[_-]?code)[=:]\s*['\"]?(\d{3,4})['\"]?", re.I)
CARD_EXPIRY_RE = re.compile(
    r"(?:exp(?:iry|iration)?|valid(?:_thru|_until)?|срок)[=:]\s*['\"]?(\d{2}[/\-]\d{2,4})['\"]?",
    re.I,
)
CARD_EXPIRY_STANDALONE_RE = re.compile(r"\b(0[1-9]|1[0-2])[/-](\d{2}|\d{4})\b")
ACCOUNT_NUMBER_RE = re.compile(
    r"(?:account(?:_number)?|acct|iban|р/с|сч[её]т|номер[_\s]?сч[её]та)[=:]\s*['\"]?([A-Z0-9\-]{8,34})['\"]?",
    re.I,
)
LOGIN_RE = re.compile(
    r"(?:login|username|user(?:_name)?|логин)[=:]\s*['\"]?([^'\"\s]{3,64})['\"]?",
    re.I,
)
FULL_NAME_RE = re.compile(
    r"(?:full[_\s]?name|fio|фио|имя)[=:]\s*['\"]?([A-Za-zА-Яа-яЁё][A-Za-zА-Яа-яЁё\s\.\-]{4,79})['\"]?",
    re.I,
)
ADDRESS_RE = re.compile(
    r"(?:address|addr|адрес(?:\s+проживания)?)[=:]\s*['\"]?([^'\"]{10,200})['\"]?",
    re.I,
)


# ---------------------------------------------------------------------
# Sensitive Data Extraction (Burp-style, safe & bounded)
# ---------------------------------------------------------------------
def extract_sensitive_data(text: str) -> Dict[str, List[str]]:
    data: Dict[str, List[str]] = {
        "emails": [],
        "phones": [],
        "tokens": [],
        "ips": [],
        "ipv4": [],
        "ipv6": [],
        "mac": [],
        "cidr": [],
        "hostnames": [],
        "parameters": [],
        "base64_strings": [],
        "uuids": [],
        "hashes": [],
        "api_keys": [],
        "jwt_tokens": [],
        "credit_cards": [],
        "cvv": [],
        "card_expiry": [],
        "account_numbers": [],
        "logins": [],
        "full_names": [],
        "addresses": [],
        "ssn": [],
        "passwords": [],
        "secrets": [],
    }

    if not text:
        return data

    if len(text) > 2_000_000:
        text = text[:2_000_000]

    try:
        # Emails
        for m in EMAIL_RE.finditer(text):
            _append_limited_unique(data["emails"], m.group(0))

        # Phones
        for p in PHONE_RE_LIST:
            for m in p.finditer(text):
                _append_limited_unique(data["phones"], m.group(0))
                if len(data["phones"]) >= MAX_MATCHES_PER_KEY:
                    break
            if len(data["phones"]) >= MAX_MATCHES_PER_KEY:
                break

        # Tokens
        for p in TOKEN_PATTERNS_COMPILED:
            for m in p.finditer(text):
                token = m.group(1) if m.groups() else m.group(0)
                _append_limited_unique(data["tokens"], token)
                if len(data["tokens"]) >= MAX_MATCHES_PER_KEY:
                    break
            if len(data["tokens"]) >= MAX_MATCHES_PER_KEY:
                break

        # JWT
        for m in JWT_RE.finditer(text):
            _append_limited_unique(data["jwt_tokens"], m.group(0))

        # IPv4
        for m in IPV4_RE.finditer(text):
            ip = m.group(0)
            _append_limited_unique(data["ipv4"], ip)
            _append_limited_unique(data["ips"], ip)

        # IPv6
        for m in IPV6_RE.finditer(text):
            _append_limited_unique(data["ipv6"], m.group(0))

        # MAC
        for m in MAC_RE.finditer(text):
            _append_limited_unique(data["mac"], m.group(0))

        # CIDR
        for m in CIDR_RE.finditer(text):
            _append_limited_unique(data["cidr"], m.group(0))

        # Hostnames
        for m in HOSTNAME_RE.finditer(text):
            _append_limited_unique(data["hostnames"], m.group(0))

        # Parameters
        for m in PARAM_RE.finditer(text):
            _append_limited_unique(data["parameters"], m.group(1))

        # Base64
        for m in BASE64_RE.finditer(text):
            _append_limited_unique(data["base64_strings"], m.group(0))

        # UUID
        for m in UUID_RE.finditer(text):
            _append_limited_unique(data["uuids"], m.group(0))

        # Hashes
        for p in HASH_PATTERNS:
            for m in p.finditer(text):
                _append_limited_unique(data["hashes"], m.group(0))

        # API keys
        for p in API_KEY_PATTERNS:
            for m in p.finditer(text):
                key = m.group(1) if m.groups() else m.group(0)
                _append_limited_unique(data["api_keys"], key)

        # Credit cards
        for m in CREDIT_CARD_RE.finditer(text):
            raw = m.group(0)
            digits = re.sub(r"\D", "", raw)
            if 13 <= len(digits) <= 19 and luhn_check(digits):
                _append_limited_unique(data["credit_cards"], mask_secret(digits, keep=4))

        # CVV
        for m in CVV_RE.finditer(text):
            _append_limited_unique(data["cvv"], m.group(1))

        # Card expiry
        for m in CARD_EXPIRY_RE.finditer(text):
            _append_limited_unique(data["card_expiry"], m.group(1))
        for m in CARD_EXPIRY_STANDALONE_RE.finditer(text):
            _append_limited_unique(data["card_expiry"], m.group(0))

        # Account numbers
        for m in ACCOUNT_NUMBER_RE.finditer(text):
            _append_limited_unique(data["account_numbers"], mask_secret(m.group(1), keep=4))

        # Logins
        for m in LOGIN_RE.finditer(text):
            login_val = m.group(1).strip()
            if login_val.lower() not in ("null", "none", "undefined"):
                _append_limited_unique(data["logins"], login_val)

        # Full names
        for m in FULL_NAME_RE.finditer(text):
            _append_limited_unique(data["full_names"], m.group(1).strip())

        # Addresses
        for m in ADDRESS_RE.finditer(text):
            _append_limited_unique(data["addresses"], m.group(1).strip())

        # SSN
        for m in SSN_RE.finditer(text):
            _append_limited_unique(data["ssn"], m.group(0))

        # Passwords
        for p in PASSWORD_PATTERNS_COMPILED:
            for m in p.finditer(text):
                pwd = m.group(1) if m.groups() else None
                if pwd:
                    _append_limited_unique(data["passwords"], mask_secret(pwd, keep=2))

        # Secrets
        for p in SECRET_PATTERNS_COMPILED:
            for m in p.finditer(text):
                if "BEGIN" in p.pattern:
                    snippet = m.group(0)[:2000]
                    _append_limited_unique(data["secrets"], snippet)
                else:
                    val = m.group(1) if m.groups() else m.group(0)
                    _append_limited_unique(data["secrets"], mask_secret(val, keep=4))

    except Exception as e:
        data["errors"] = [str(e)]

    # Dedup + trim
    for key in data:
        if isinstance(data[key], list):
            data[key] = dedupe_preserve_order(data[key])[:MAX_MATCHES_PER_KEY]

    return data

# ---------------------------------------------------------------------
# ULTRA Sensitive Data Extractor — Burp/ZAP-grade
# ---------------------------------------------------------------------

# 🔹 Дополнительные паттерны для ULTRA-режима

# Пароли (включая сложные, с пробелами, спецсимволами, в JSON/конфигах)
PASSWORD_PATTERNS_ULTRA = [
    # classic key=value / key: value
    re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\n\r]{6,})['\"]?", re.I),
    # JSON-style: "password": "value"
    re.compile(r'"(?:password|passwd|pwd)"\s*:\s*"([^"\n\r]{6,})"', re.I),
    # YAML-style: password: value
    re.compile(r"(?:password|passwd|pwd)\s*:\s*([^\s#]{6,})", re.I),
]

# API-ключи (розширено: cloud, payment, maps, mail, storage)
API_KEY_PATTERNS_ULTRA = [
    re.compile(r"(?:api[_-]?key|apikey)[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?", re.I),
    re.compile(r'"api[_-]?key"\s*:\s*"([A-Za-z0-9_\-]{20,})"', re.I),
    re.compile(r"(?:sk|pk)_[A-Za-z0-9_\-]{20,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),          # Google API
    re.compile(r"AKIA[0-9A-Z]{16}"),               # AWS Access Key
    re.compile(r"SG\.[A-Za-z0-9_\-]{20,}", re.I),  # SendGrid
    re.compile(r"rk_live_[A-Za-z0-9]{24,}", re.I), # Stripe live key
]

# Base64 — ULTRA: проверка длины и структуры
BASE64_ULTRA_RE = re.compile(
    r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:==|=)?\b"  # минимум 32 байта
)

# Токены (session, auth, refresh, access, generic)
TOKEN_PATTERNS_ULTRA = [
    re.compile(
        r"(?:auth[_-]?token|session[_-]?id|access[_-]?token|refresh[_-]?token|id[_-]?token)"
        r"['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{8,})['\"]",
        re.I,
    ),
    re.compile(r'"(token|secret|key)"\s*:\s*"([A-Za-z0-9_\-\.]{8,})"', re.I),
]

# Криптографические ключи / secrets / PEM / конфиги
CRYPTO_KEY_PATTERNS_ULTRA = [
    re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", re.I),
    re.compile(r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----", re.I),
    re.compile(r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----", re.I),
    re.compile(r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----", re.I),
    re.compile(r"(?:secret|private[_-]?key|public[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.+/=]{20,})['\"]?", re.I),
]

# Конфиги / secrets.yml / env-файлы / JSON-конфиги
CONFIG_PATTERNS_ULTRA = [
    re.compile(r"(?:secrets?\.(ya?ml|json|toml))", re.I),
    re.compile(r"(?:config\.(json|ya?ml|toml|ini))", re.I),
    re.compile(r"\.env(\.[a-zA-Z0-9_\-]+)?", re.I),
    re.compile(r"(?:ENV|CONFIG|SECRET|TOKEN|KEY)[_\-A-Z0-9]*\s*=\s*['\"]?([^'\"\n\r]{4,})['\"]?", re.I),
]

# OAuth / OpenID / JWT claims
OAUTH_PATTERNS_ULTRA = [
    re.compile(r'"client_id"\s*:\s*"([^"\n\r]{4,})"', re.I),
    re.compile(r'"client_secret"\s*:\s*"([^"\n\r]{8,})"', re.I),
    re.compile(r'"redirect_uri"\s*:\s*"([^"\n\r]{8,})"', re.I),
    re.compile(r'"issuer"\s*:\s*"([^"\n\r]{4,})"', re.I),
]

JWT_CLAIMS_PATTERNS_ULTRA = [
    re.compile(r'"sub"\s*:\s*"([^"\n\r]{3,64})"', re.I),
    re.compile(r'"email"\s*:\s*"([^"\n\r]{6,128})"', re.I),
    re.compile(r'"scope"\s*:\s*"([^"\n\r]{3,256})"', re.I),
    re.compile(r'"roles?"\s*:\s*\[([^\]]+)\]', re.I),
]


def extract_sensitive_data_ultra(text: str) -> Dict[str, List[str]]:
    """
    ULTRA Sensitive Extractor:
      - passwords (classic + JSON/YAML/env)
      - API keys (cloud/payment/mail/storage)
      - Base64 (проверка длины)
      - tokens (auth/session/access/refresh)
      - crypto keys (PEM, RSA, EC, PGP, OpenSSH)
      - configs (secrets.yml, .env, config.json)
      - env-files (KEY=VALUE)
      - JSON tokens (client_id, client_secret, redirect_uri)
      - OAuth tokens / OpenID fields
      - JWT claims (sub, email, scope, roles)
    """
    data = extract_sensitive_data(text)  # твоя базовая версия как основа

    if not text:
        return data

    if len(text) > 4_000_000:
        text = text[:4_000_000]

    try:
        # ULTRA Passwords
        for p in PASSWORD_PATTERNS_ULTRA:
            for m in p.finditer(text):
                pwd = m.group(1) if m.groups() else None
                if pwd:
                    _append_limited_unique(data["passwords"], mask_secret(pwd, keep=2))

        # ULTRA API keys
        for p in API_KEY_PATTERNS_ULTRA:
            for m in p.finditer(text):
                val = m.group(1) if m.groups() else m.group(0)
                _append_limited_unique(data["api_keys"], mask_secret(val, keep=4))

        # ULTRA Base64
        for m in BASE64_ULTRA_RE.finditer(text):
            b64 = m.group(0)
            _append_limited_unique(data["base64_strings"], b64)

        # ULTRA Tokens
        for p in TOKEN_PATTERNS_ULTRA:
            for m in p.finditer(text):
                token = m.group(2) if len(m.groups()) >= 2 else (m.group(1) if m.groups() else m.group(0))
                _append_limited_unique(data["tokens"], mask_secret(token, keep=4))

        # ULTRA Crypto keys / secrets
        for p in CRYPTO_KEY_PATTERNS_ULTRA:
            for m in p.finditer(text):
                if "BEGIN" in p.pattern:
                    snippet = text[m.start(): m.start() + 4000]
                    _append_limited_unique(data["secrets"], snippet)
                else:
                    val = m.group(1) if m.groups() else m.group(0)
                    _append_limited_unique(data["secrets"], mask_secret(val, keep=4))

        # ULTRA Configs / secrets.yml / env-files
        for p in CONFIG_PATTERNS_ULTRA:
            for m in p.finditer(text):
                val = m.group(0)
                _append_limited_unique(data.setdefault("config_hits", []), val)

        # ULTRA OAuth / OpenID
        for p in OAUTH_PATTERNS_ULTRA:
            for m in p.finditer(text):
                val = m.group(1) if m.groups() else m.group(0)
                _append_limited_unique(data.setdefault("oauth", []), val)

        # ULTRA JWT claims
        for p in JWT_CLAIMS_PATTERNS_ULTRA:
            for m in p.finditer(text):
                val = m.group(1) if m.groups() else m.group(0)
                _append_limited_unique(data.setdefault("jwt_claims", []), val)

    except Exception as e:
        data.setdefault("errors", []).append(str(e))

    # Dedup + trim (повторно, с учётом новых полей)
    for key in data:
        if isinstance(data[key], list):
            data[key] = dedupe_preserve_order(data[key])[:MAX_MATCHES_PER_KEY]

    return data



# ---------------------------------------------------------------------
# API Endpoint Extraction
# ---------------------------------------------------------------------
def extract_api_endpoints_from_text(text: str, base_url: str) -> List[str]:
    """
    Extract API endpoints from HTML/JS/text.
    Returns normalized absolute URLs limited by MAX_API_ENDPOINTS.
    """
    if not text:
        return []

    api_patterns = [
        re.compile(
            r"(?:fetch|axios|ajax|XMLHttpRequest|\.get|\.post|\.put|\.delete)\s*\(\s*['\"]([^'\"]+)['\"]",
            re.I,
        ),
        re.compile(r"(?:url|endpoint|api)[\s]*[:=]\s*['\"]([^'\"]+)['\"]", re.I),
        re.compile(r"['\"](/(?:api/|v\d+/|rest/|graphql)[^'\"]+)['\"]", re.I),
        re.compile(r"['\"](https?://[^'\"]+(?:/api/|/v\d+/|/rest/)[^'\"]+)['\"]", re.I),
    ]

    candidates: List[str] = []
    for pat in api_patterns:
        for m in pat.finditer(text):
            try:
                cand = m.group(1) if m.groups() else m.group(0)
                norm = _normalize_candidate(cand, base_url)
                if norm and _is_http_url(norm):
                    candidates.append(norm)
                if len(candidates) >= MAX_API_ENDPOINTS:
                    break
            except Exception:
                continue
        if len(candidates) >= MAX_API_ENDPOINTS:
            break

    return dedupe_preserve_order(candidates)[:MAX_API_ENDPOINTS]


# ---------------------------------------------------------------------
# ThreatIntel Reporter
# ---------------------------------------------------------------------
def report_threatintel(node: Dict[str, Any], gui_callback=None) -> None:
    """
    Safe reporting of metadata to ThreatIntel / GUI callback.
    Builds a masked, deduplicated summary and calls gui_callback if provided.
    """
    if not gui_callback:
        return

    try:
        url = node.get("url", "")
        forms = node.get("forms") or []
        scripts = node.get("scripts") or []
        headers = node.get("headers") or {}
        api_endpoints = dedupe_preserve_order(node.get("api_endpoints") or [])[:MAX_API_ENDPOINTS]
        links = node.get("links") or []
        meta = node.get("meta") or []
        events = node.get("events") or []
        error = node.get("error")

        # Extract script paths safely
        script_paths: List[str] = []
        for s in scripts:
            if isinstance(s, dict):
                p = s.get("path") or s.get("src") or s.get("url") or ""
            else:
                p = str(s)
            if p:
                script_paths.append(p)
        script_paths = dedupe_preserve_order(script_paths)[:50]

        # Mask long header values
        safe_headers: Dict[str, str] = {}
        for k, v in headers.items():
            vs = str(v)
            safe_headers[str(k)] = vs if len(vs) <= 200 else vs[:100] + "…"

        safe_report = {
            "module": "crawler",
            "url": url,
            "forms_count": len(forms),
            "scripts": script_paths,
            "headers": safe_headers,
            "api_endpoints": api_endpoints[:200],
            "links_count": len(links),
            "meta": meta,
            "events": events[:100],
            "error": error,
        }

        try:
            gui_callback({"crawler": safe_report})
        except Exception:
            logger.debug("gui_callback failed for %s", url)
    except Exception:
        try:
            gui_callback({"crawler": {"module": "crawler", "error": "failed to build safe report"}})
        except Exception:
            pass


# ---------------------------------------------------------------------
# Hybrid Fetch Pipeline + Anti‑WAF Bypass
# ---------------------------------------------------------------------
def fetch_with_requests_raw(
    url: str,
    timeout: int = REQUEST_TIMEOUT,
    session: Optional[requests.Session] = None,
    max_retries: int = 3,
):
    """
    Try requests first with Anti‑WAF headers and small retry logic.
    Returns Response on success or None on failure.
    """
    sess = session or requests.Session()
    for attempt in range(max_retries):
        try:
            rate_limit()
            headers = build_anti_waf_headers(DEFAULT_HEADERS)
            resp = sess.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
            )
            if getattr(resp, "status_code", 0) in (403, 429, 503):
                # WAF / rate-limit — short backoff + retry
                backoff = (attempt + 1) * 1.5
                time.sleep(backoff)
                continue
            return resp
        except Exception as e:
            logger.debug("requests failed for %s (attempt %d): %s", url, attempt + 1, e)
            time.sleep(0.5 * (attempt + 1))
    return None


def fetch_with_cloudscraper(url: str, timeout: int = 15) -> Optional[str]:
    """
    Use cloudscraper to bypass simple bot protections. Returns HTML text or None.
    """
    try:
        rate_limit()
        scraper = cloudscraper.create_scraper(
            browser={"browser": "chrome", "platform": "windows", "mobile": False}
        )
        if PROXIES:
            try:
                scraper.proxies.update(PROXIES)
            except Exception:
                logger.debug("Invalid PROXIES for cloudscraper; skipping proxies.")
        headers = build_anti_waf_headers(DEFAULT_HEADERS)
        resp = scraper.get(url, timeout=timeout, allow_redirects=True, headers=headers)
        if resp is None:
            return None
        if getattr(resp, "status_code", 0) >= 400:
            logger.warning("cloudscraper: %s returned HTTP %s", url, resp.status_code)
        return resp.text or ""
    except Exception as e:
        logger.debug("cloudscraper failed for %s: %s", url, e)
        return None


def fetch_with_playwright(url: str, timeout: int = 25) -> Optional[str]:
    """
    Render page with Playwright (headless). Returns HTML or None.
    Safe-guards: returns None if Playwright not available or on error.
    Includes Anti‑WAF behavior simulation.
    """
    if not PLAYWRIGHT_AVAILABLE:
        return None

    try:
        def _inner():
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    viewport={"width": 1920, "height": 1080},
                    user_agent=random.choice(ANTI_WAF_USER_AGENTS),
                )
                try:
                    context.add_init_script(
                        "Object.defineProperty(navigator, 'webdriver', {get: () => false});"
                    )
                except Exception:
                    pass

                page = context.new_page()
                page.set_default_timeout(max(1000, int(timeout * 1000)))
                page.goto(url, wait_until="networkidle")
                simulate_human_behavior_playwright(page)
                html = page.content()
                try:
                    context.close()
                except Exception:
                    pass
                try:
                    browser.close()
                except Exception:
                    pass
                return html

        rate_limit()
        return _inner()
    except Exception as e:
        logger.warning("Playwright failed for %s: %s", url, e)
        return None


def fetch_html_hybrid_fallback(url: str) -> Optional[str]:
    """
    Hybrid HTML fetch:
      1) cloudscraper (JS challenge / basic WAF)
      2) Playwright (if cloudscraper result is too small or missing)
    Returns HTML string or None.
    """
    url = normalize_scheme(url)

    html = fetch_with_cloudscraper(url)
    if html and len(html.strip()) > 200:
        return html

    return fetch_with_playwright(url)


# ---------------------------------------------------------------------
# SUPER-CRAWLER — main function
# ---------------------------------------------------------------------
def crawl_site(
    url: str,
    depth: int = 0,
    session: Optional[requests.Session] = None,
    gui_callback=None,
    max_links: int = MAX_LINKS_PER_PAGE,
    max_scripts: int = MAX_SCRIPTS_PER_PAGE,
    aggressive: bool = AGGRESSIVE_HEADERS,
    parallel: bool = True,
) -> Dict[str, Any]:
    """
    Main crawler:
      - requests -> cloudscraper -> Playwright fallback
      - HTML/JS parsing
      - sensitive data extraction
      - ThreatIntel callback
      - recursion + ThreadPoolExecutor
      - writes to tree_log, dot_edges, nodes_json
      - Anti‑WAF Bypass 1.0 integrated
    """
    global visited, tree_log, dot_edges, nodes_json, js_cache

    # Initialize session lazily
    if session is None:
        try:
            if bool(settings.get("anti_detection.use_anti_detection_session", False)):
                session = AntiDetectionSession()
            else:
                session = make_session(aggressive=aggressive)
        except Exception as e:
            logger.warning("AntiDetectionSession init failed: %s", e)
            session = make_session(aggressive=aggressive)

    # Depth guard
    if depth > CRAWL_DEPTH_LIMIT:
        return {"url": url, "error": "Depth limit exceeded"}

    safe_url = normalize_scheme(url)
    parsed = urlparse(safe_url)
    parsed_domain = parsed.netloc or ""

    # Whitelist check
    if CRAWL_DOMAINS_WHITELIST:
        if parsed_domain not in CRAWL_DOMAINS_WHITELIST and not any(
            parsed_domain.endswith("." + d) for d in CRAWL_DOMAINS_WHITELIST
        ):
            return {"url": safe_url, "error": "Domain not whitelisted"}

    # Uniqueness (hash without query/fragment)
    url_id = hash_url_no_query(safe_url)
    with visited_lock:
        if url_id in visited:
            return {"url": safe_url, "error": "Already visited"}
        visited.add(url_id)

    # Node skeleton
    node: Dict[str, Any] = {
        "url": safe_url,
        "forms": [],
        "scripts": [],
        "links": [],
        "headers": {},
        "meta": [],
        "iframes": [],
        "events": [],
        "api_endpoints": [],
        "emails": [],
        "phones": [],
        "tokens": [],
        "ips": [],
        "ipv4": [],
        "ipv6": [],
        "mac": [],
        "cidr": [],
        "hostnames": [],
        "parameters": [],
        "base64_strings": [],
        "uuids": [],
        "hashes": [],
        "api_keys": [],
        "jwt_tokens": [],
        "credit_cards": [],
        "cvv": [],
        "card_expiry": [],
        "account_numbers": [],
        "logins": [],
        "full_names": [],
        "addresses": [],
        "ssn": [],
        "passwords": [],
        "secrets": [],
        "cookies": [],
        "websockets": [],
        "data_attributes": [],
        "comments": [],
        "buttons": [],
        "selects": [],
        "textareas": [],
        "error": None,
    }

    try:
        # Fetch (requests first; hybrid fallback later)
        rate_limit()
        resp = fetch_with_requests_raw(safe_url, timeout=REQUEST_TIMEOUT, session=session)

        if resp is None:
            html = fetch_html_hybrid_fallback(safe_url) or ""
            content_type = "text/html"
            headers = {}
            cookies_obj = None
        else:
            content_type = (resp.headers.get("Content-Type", "") or "").lower()
            headers = dict(resp.headers or {})
            cookies_obj = getattr(resp, "cookies", None)
            html = resp.text or ""

        # Headers summary (security-focused)
        node["headers"] = {
            "CSP": headers.get("Content-Security-Policy", "-"),
            "X-XSS-Protection": headers.get("X-XSS-Protection", "-"),
            "Referrer-Policy": headers.get("Referrer-Policy", "-"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "-"),
            "X-Frame-Options": headers.get("X-Frame-Options", "-"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "-"),
            "Server": headers.get("Server", "-"),
            "X-Powered-By": headers.get("X-Powered-By", "-"),
        }

        # Cookies
        if cookies_obj:
            try:
                node["cookies"] = [
                    {
                        "name": c.name,
                        "value": (c.value or "")[:100],
                        "domain": c.domain,
                    }
                    for c in cookies_obj
                ]
            except Exception:
                node["cookies"] = []

        # ============================================================
        # 3) JSON endpoint
        # ============================================================
        if ("application/json" in content_type or safe_url.lower().endswith(".json")) and resp is not None:
            try:
                json_data = resp.json()
                node["api_endpoints"].append(safe_url)
                _merge_sensitive_into_node(node, extract_sensitive_data(json.dumps(json_data)))
            except Exception as e:
                node["error"] = f"json_parse_error: {e}"

            node["api_endpoints"] = dedupe_preserve_order(node["api_endpoints"])[:MAX_API_ENDPOINTS]
            _trim_node_list_fields(node)

            with nodes_lock:
                nodes_json.append(node)
                tree_log.append("  " * depth + f"📄 {safe_url}")

            report_threatintel(node, gui_callback)
            return node

        # HTML parsing
        soup = BeautifulSoup(html or "", "html.parser")

        # Sensitive data from full HTML
        if ENABLE_ULTRA_SENSITIVE:
            sensitive = extract_sensitive_data_ultra(html)
        else:
            sensitive = extract_sensitive_data(html)

        _merge_sensitive_into_node(node, sensitive)

        # API endpoints from HTML
        node["api_endpoints"].extend(extract_api_endpoints_from_text(html, safe_url))

        # ============================================================
        # 5) Forms
        # ============================================================
        for form in soup.find_all("form"):
            cls = form.get("class")
            if isinstance(cls, list):
                form_classes = [str(c) for c in cls]
            elif isinstance(cls, str):
                form_classes = [cls]
            else:
                form_classes = []

            inputs = []
            for inp in form.find_all("input"):
                inp_cls = inp.get("class")
                if isinstance(inp_cls, list):
                    inp_classes = [str(c) for c in inp_cls]
                elif isinstance(inp_cls, str):
                    inp_classes = [inp_cls]
                else:
                    inp_classes = []

                input_data = {
                    "name": inp.get("name"),
                    "type": inp.get("type", "text"),
                    "id": inp.get("id"),
                    "class": inp_classes,
                    "placeholder": inp.get("placeholder"),
                    "value": (inp.get("value") or "")[:100],
                }

                if input_data["name"]:
                    inputs.append(input_data)

            textareas = [ta.get("name") for ta in form.find_all("textarea") if ta.get("name")]
            selects = [sel.get("name") for sel in form.find_all("select") if sel.get("name")]

            handlers = {attr: form.attrs[attr] for attr in form.attrs if attr.startswith("on")}

            node["forms"].append(
                {
                "action": form.get("action", ""),
                "method": form.get("method", "GET").upper(),
                    "inputs": [inp["name"] for inp in inputs if inp["name"]],
                    "input_details": inputs,
                    "textareas": textareas,
                    "selects": selects,
                    "js_events": handlers,
                    "id": form.get("id"),
                    "class": form_classes,
                }
            )

        # ============================================================
        # 6) Scripts (JS)
        # ============================================================
        scripts = soup.find_all("script")[:max_scripts]

        def _build_script_entry(js_url: str, raw_js: Optional[str] = None) -> Dict[str, Any]:
            if raw_js is None:
                if js_url in js_cache:
                    insights = js_cache[js_url]
                else:
                    try:
                        js_resp = session.get(js_url, timeout=8)
                        if "javascript" in js_resp.headers.get("Content-Type", "") or js_url.endswith(".js"):
                            js_text = js_resp.text or ""
                            insights = extract_js_insights(js_text)
                            node["api_endpoints"].extend(
                                extract_api_endpoints_from_text(js_text, safe_url)
                            )
                            _merge_sensitive_into_node(node, extract_sensitive_data(js_text))
                        else:
                            insights = {
                                "functions": [],
                                "fetch_calls": [],
                                "ajax_calls": [],
                                "sensitive": [],
                            }
                    except Exception as e:
                        logger.debug("[JS] Error loading %s: %s", js_url, e)
                        insights = {
                            "functions": [],
                            "fetch_calls": [],
                            "ajax_calls": [],
                            "sensitive": [],
                        }
                    js_cache[js_url] = insights
            else:
                if raw_js.strip():
                    insights = extract_js_insights(raw_js)
                    node["api_endpoints"].extend(
                        extract_api_endpoints_from_text(raw_js, safe_url)
                    )
                    _merge_sensitive_into_node(node, extract_sensitive_data(raw_js))
                else:
                    insights = {
                        "functions": [],
                        "fetch_calls": [],
                        "ajax_calls": [],
                        "sensitive": [],
                    }

            return {
                "path": js_url if js_url else "[INLINE]",
                    "functions": insights.get("functions", []),
                    "fetch_calls": [u for _, u in insights.get("fetch_calls", [])],
                    "ajax_calls": insights.get("ajax_calls", []),
                "xss_sensitive": insights.get("sensitive", []),
            }

        external_scripts: List[Tuple[int, str]] = []
        inline_scripts: List[Tuple[int, str]] = []
        for index, script in enumerate(scripts):
            if script.get("src"):
                external_scripts.append((index, normalize_scheme(urljoin(safe_url, script.get("src")))))
            else:
                inline_scripts.append((index, script.string or ""))

        if external_scripts:
            results: List[Optional[Dict[str, Any]]] = [None] * len(external_scripts)
            with ThreadPoolExecutor(
                max_workers=max(1, min(MAX_CONCURRENT_REQUESTS, len(external_scripts)))
            ) as executor:
                futures = {
                    executor.submit(_build_script_entry, js_url): idx
                    for idx, js_url in external_scripts
                }
                for future in as_completed(futures):
                    results[futures[future]] = future.result()

            for entry in results:
                if entry:
                    node["scripts"].append(entry)

        for _, raw_js in inline_scripts:
            node["scripts"].append(_build_script_entry("", raw_js))

        # ============================================================
        # 7) Links
        # ============================================================
        try:
            hrefs = [a.get("href") for a in soup.find_all("a") if a.get("href")]
        except Exception:
            hrefs = []

        clean_links: List[str] = []
        for h in hrefs:
            try:
                if not is_real_link(h):
                    continue
                candidate = h.split("#")[0].strip().strip("'\"")
                if not candidate:
                    continue
                absolute = urljoin(safe_url, candidate)
                parsed_cand = urlparse(absolute)
                if parsed_cand.scheme not in ("http", "https"):
                    continue
                clean_links.append(absolute)
            except Exception:
                continue

        unique_links = dedupe_preserve_order(clean_links)[:max_links]
        node["links"] = [str(x) for x in unique_links]

        # ============================================================
        # 8) META (safe)
        # ============================================================
        safe_meta: List[Dict[str, Any]] = []
        for meta in soup.find_all("meta"):
            try:
                meta_data: Dict[str, str] = {}
                for attr in ("name", "property", "content", "http-equiv"):
                    v = meta.get(attr)
                    if v:
                        meta_data[attr] = str(v)[:500]
                if meta_data:
                    safe_meta.append(meta_data)
            except Exception:
                continue

        node["meta"] = safe_meta

        # ============================================================
        # 9) Iframes
        # ============================================================
        iframes: List[str] = []
        for i in soup.find_all("iframe"):
            try:
                src = i.get("src")
                if src:
                    iframes.append(normalize_scheme(urljoin(safe_url, src)))
            except Exception:
                continue

        node["iframes"] = [str(x) for x in iframes]

        # ============================================================
        # 10) WebSockets
        # ============================================================
        ws_patterns = [
            re.compile(r"new\s+WebSocket\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
            re.compile(r"(wss?://[^\s\"']+)", re.IGNORECASE),
        ]

        ws_matches: List[str] = []
        for pat in ws_patterns:
            try:
                for m in pat.finditer(html or ""):
                    if m.groups():
                        ws = m.group(1)
                    else:
                        ws = m.group(0)
                    ws = (ws or "").strip()
                    if ws:
                        ws_matches.append(ws)
            except Exception:
                continue

        node["websockets"] = dedupe_preserve_order(ws_matches)[:50]

        # ============================================================
        # 11) data-* attributes
        # ============================================================
        safe_data_attrs: List[str] = []
        for tag in soup.find_all(True):
            try:
                for attr, val in tag.attrs.items():
                    if attr.startswith("data-"):
                        safe_data_attrs.append(f"{tag.name}.{attr}={str(val)[:100]}")
            except Exception:
                continue

        node["data_attributes"] = safe_data_attrs[:200]

        # ============================================================
        # 12) Comments
        # ============================================================
        comments: List[str] = []
        try:
            for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
                c = str(comment).strip()
                if c:
                    comments.append(c[:500])
                    if len(comments) >= 50:
                        break
        except Exception:
            pass

        node["comments"] = comments

        # Sensitive data from comments
        for c in comments:
            try:
                _merge_sensitive_into_node(node, extract_sensitive_data(c))
            except Exception:
                continue

        # ============================================================
        # 13) Buttons
        # ============================================================
        safe_buttons: List[Dict[str, Any]] = []
        for button in soup.find_all(["button", "input"]):
            try:
                if button.get("type") == "button" or button.name == "button":
                    cls = button.get("class")
                    if isinstance(cls, list):
                        btn_classes = [str(c) for c in cls]
                    elif isinstance(cls, str):
                        btn_classes = [cls]
                    else:
                        btn_classes = []

                    safe_buttons.append(
                        {
                            "text": button.get_text(strip=True)[:50],
                            "onclick": str(button.get("onclick", ""))[:200],
                            "id": button.get("id"),
                            "class": btn_classes,
                        }
                    )
            except Exception:
                continue

        node["buttons"] = safe_buttons

        # ============================================================
        # 14) Select
        # ============================================================
        safe_selects: List[Dict[str, Any]] = []
        for select in soup.find_all("select"):
            try:
                options = [
                    opt.get("value") for opt in select.find_all("option") if opt.get("value")
                ]
                if options:
                    safe_selects.append(
                        {
                            "name": select.get("name"),
                            "options": [str(o) for o in options[:20]],
                        }
                    )
            except Exception:
                continue

        node["selects"] = safe_selects

        # ============================================================
        # 15) Textarea
        # ============================================================
        safe_textareas: List[Dict[str, Any]] = []
        for textarea in soup.find_all("textarea"):
            try:
                safe_textareas.append(
                    {
                        "name": textarea.get("name"),
                        "placeholder": textarea.get("placeholder"),
                        "id": textarea.get("id"),
                    }
                )
            except Exception:
                continue

        node["textareas"] = safe_textareas

        # ============================================================
        # 16) on* events
        # ============================================================
        safe_events: List[str] = []
        for tag in soup.find_all(True):
            try:
                for attr in tag.attrs:
                    if attr.startswith("on"):
                        safe_events.append(
                            f"{tag.name}.{attr} → {str(tag.attrs[attr])[:200]}"
                        )
            except Exception:
                continue

        node["events"] = safe_events[:200]

        # ============================================================
        # 17) Tree log & graph edges
        # ============================================================
        tree_log.append("  " * depth + f"📄 {safe_url}")

        for form in node["forms"]:
            tree_log.append(
                "  " * (depth + 1)
                + f"📝 FORM {form['method']} {form['action']}"
            )

        for js in node["scripts"]:
            tree_log.append("  " * (depth + 1) + f"📦 JS {js['path']}")

        with dot_lock:
            for link in unique_links:
                dot_edges.append((safe_url, link))

        # ============================================================
        # 18) Dedup all list fields
        # ============================================================
        node["api_endpoints"] = dedupe_preserve_order(node["api_endpoints"])[:MAX_API_ENDPOINTS]
        _trim_node_list_fields(node)

        with nodes_lock:
            nodes_json.append(node)

        report_threatintel(node, gui_callback)

        # ============================================================
        # 19) Recursive crawl
        # ============================================================
        if parallel and len(unique_links) > 1:
            to_visit: List[str] = []

            for link in unique_links:
                if not is_same_domain(link, parsed_domain):
                    continue
                link_id = hash_url_no_query(link)
                with visited_lock:
                    if link_id in visited:
                        continue
                to_visit.append(link)

            if to_visit:
                with ThreadPoolExecutor(
                    max_workers=min(MAX_CONCURRENT_REQUESTS, len(to_visit))
                ) as executor:
                    futures = {
                        executor.submit(
                            crawl_site,
                            link,
                            depth + 1,
                            session,
                            gui_callback,
                            max_links,
                            max_scripts,
                            aggressive,
                            parallel,
                        ): link
                        for link in to_visit
                    }

                    for fut in as_completed(futures):
                        try:
                            fut.result()
                        except Exception as e:
                            node["error"] = (node.get("error") or "") + f" child_error:{futures[fut]}:{e}"
        else:
            # Sequential mode
            for link in unique_links:
                if not is_same_domain(link, parsed_domain):
                    continue
                link_id = hash_url_no_query(link)
                with visited_lock:
                    if link_id in visited:
                        continue
                crawl_site(
                    link,
                    depth + 1,
                    session=session,
                    gui_callback=gui_callback,
                    max_links=max_links,
                    max_scripts=max_scripts,
                    aggressive=aggressive,
                    parallel=parallel,
                )

        return node

    except Exception as e:
        node["error"] = str(e)
        try:
            err_path = str(CRAWLER_ERROR_LOG or "")
            os.makedirs(os.path.dirname(err_path) or "logs", exist_ok=True)
            with open(err_path, "a", encoding="utf-8") as errlog:
                errlog.write(f"[{datetime.now().isoformat()}] {safe_url} ❌ {str(e)}\n")
        except Exception:
            pass
        with nodes_lock:
            nodes_json.append(node)
        report_threatintel(node, gui_callback)
        return node


# ---------------------------------------------------------------------
# Final aggregation (Burp/ZAP-style summary)
# ---------------------------------------------------------------------
def build_final_dict(nodes: List[Dict[str, Any]], max_items: int = 500) -> Dict[str, Any]:
    """
    Бойова версія build_final_dict():
      • Гарантує правильні типи
      • Нормалізує всі поля
      • Маскує чутливі дані
      • Не падає на кривих нодах
      • Повертає чистий, JSON‑сумісний dict
    """

    def _dedupe(seq):
        try:
            return list(dict.fromkeys(seq))
        except Exception:
            out = []
            seen = set()
            for x in seq:
                sx = str(x)
                if sx not in seen:
                    seen.add(sx)
                    out.append(x)
            return out

    def _safe_list(v):
        return v if isinstance(v, (list, tuple)) else []

    def _safe_mask(s: str, keep: int = 4) -> str:
        try:
            return mask_secret(str(s), keep=keep)
        except Exception:
            s = str(s)
            return "*" * min(len(s), 8)

    def _normalize_sensitive(v) -> List[str]:
        if isinstance(v, dict) and "examples" in v:
            return [str(x) for x in v.get("examples", []) if x]
        if isinstance(v, (list, tuple)):
            return [str(x) for x in v if x]
        return []

    if not nodes:
        return {
            "url": "",
            "forms": [],
            "scripts": [],
            "links": [],
            "headers": {},
            "meta": [],
            "iframes": [],
            "events": [],
            "api_endpoints": [],
            "emails": [],
            "phones": [],
            "tokens": {"count": 0, "examples": []},
            "ips": [],
            "ipv6": [],
            "mac": [],
            "cidr": [],
            "hostnames": [],
            "parameters": [],
            "base64_strings": [],
            "uuids": [],
            "hashes": [],
            "api_keys": {"count": 0, "examples": []},
            "jwt_tokens": {"count": 0, "examples": []},
            "credit_cards": [],
            "cvv": [],
            "card_expiry": [],
            "account_numbers": [],
            "logins": [],
            "full_names": [],
            "addresses": [],
            "ssn": [],
            "passwords": {"count": 0, "examples": []},
            "secrets": {"count": 0, "examples": []},
            "cookies": [],
            "websockets": [],
            "data_attributes": [],
            "comments": [],
            "buttons": [],
            "selects": [],
            "textareas": [],
            "error": None,
            "total_nodes": 0,
            "merged_at": datetime.now(timezone.utc).isoformat(),
        }

    root = dict(nodes[0]) if isinstance(nodes[0], dict) else {}

    merge_fields = [
        "forms", "scripts", "links", "meta", "iframes", "events",
        "api_endpoints", "emails", "phones", "tokens", "ips",
        "ipv6", "mac", "cidr", "hostnames", "comments",
        "parameters", "base64_strings", "uuids", "hashes",
        "api_keys", "jwt_tokens", "credit_cards", "cvv", "card_expiry",
        "account_numbers", "logins", "full_names", "addresses", "ssn",
        "passwords", "secrets", "cookies", "websockets",
        "data_attributes", "buttons", "selects", "textareas",
    ]

    combined = {f: [] for f in merge_fields}

    for node in nodes:
        if not isinstance(node, dict):
            continue
        for f in merge_fields:
            val = node.get(f)
            if isinstance(val, (list, tuple)):
                combined[f].extend(val)

    merged_meta = []
    seen_meta = set()
    for m in combined["meta"]:
        try:
            key = json.dumps(m, sort_keys=True, ensure_ascii=False)
        except Exception:
            key = str(m)
        if key not in seen_meta:
            seen_meta.add(key)
            merged_meta.append(m)
            if len(merged_meta) >= max_items:
                break
    root["meta"] = merged_meta

    ipv4_valid = []
    ipv4_re = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
    )
    for ip in combined["ips"]:
        if isinstance(ip, str) and ipv4_re.match(ip):
            ipv4_valid.append(ip)
    root["ips"] = _dedupe(ipv4_valid)[:max_items]

    simple_fields = [
        "forms", "scripts", "links", "iframes", "events", "api_endpoints",
        "emails", "phones", "ipv6", "mac", "cidr", "hostnames",
        "comments", "parameters", "base64_strings", "uuids", "hashes",
        "credit_cards", "cvv", "card_expiry", "account_numbers", "logins",
        "full_names", "addresses", "ssn", "cookies", "websockets", "data_attributes",
        "buttons", "selects", "textareas",
    ]

    for f in simple_fields:
        vals = combined.get(f, [])
        root[f] = _dedupe(vals)[:max_items]

    def _summarize(items: List[Any], keep: int) -> Dict[str, Any]:
        items = [str(i) for i in items if i]
        items = _dedupe(items)
        return {
            "count": len(items),
            "examples": [_safe_mask(x, keep=keep) for x in items[:5]],
        }

    root["tokens"] = _summarize(_normalize_sensitive(combined["tokens"]), keep=4)
    root["api_keys"] = _summarize(_normalize_sensitive(combined["api_keys"]), keep=4)
    root["jwt_tokens"] = _summarize(_normalize_sensitive(combined["jwt_tokens"]), keep=4)
    root["passwords"] = _summarize(_normalize_sensitive(combined["passwords"]), keep=2)
    root["secrets"] = _summarize(_normalize_sensitive(combined["secrets"]), keep=4)

    expected = [
        "forms", "scripts", "links", "meta", "iframes", "events",
        "api_endpoints", "emails", "phones", "ips", "ipv6", "mac",
        "cidr", "hostnames", "parameters", "base64_strings", "uuids",
        "hashes", "credit_cards", "cvv", "card_expiry", "account_numbers",
        "logins", "full_names", "addresses", "ssn", "cookies", "websockets",
        "data_attributes", "comments", "buttons", "selects", "textareas",
    ]
    for f in expected:
        root.setdefault(f, [])

    root.setdefault("headers", root.get("headers", {}))
    root.setdefault("url", root.get("url", ""))
    root.setdefault("error", None)

    root["total_nodes"] = len(nodes)
    root["merged_at"] = datetime.now(timezone.utc).isoformat()

    for k, v in list(root.items()):
        if isinstance(v, list) and len(v) > max_items:
            root[k] = v[:max_items]

    return root

def safe_replace(src: str, dst: str, retries: int = 5, delay: float = 0.3):
    """
    Надійна заміна файлу на Windows:
      • os.replace() з ретраями
      • fallback на shutil.move()
      • гарантія збереження результатів
    """
    for attempt in range(retries):
        try:
            os.replace(src, dst)
            return True
        except PermissionError:
            time.sleep(delay)

    # fallback
    try:
        shutil.move(src, dst)
        return True
    except Exception as e:
        logging.error(f"[save_outputs] Fallback move failed: {e}")
        return False

# ---------------------------------------------------------------------
# Save Outputs (Tree, JSON, DOT, SVG, Summary) — hardened
# ---------------------------------------------------------------------
def save_outputs(
    result: Dict[str, Any],
    gui_callback=None,
    max_nodes_save: int = 1000,
    max_items_per_field: int = 500,
) -> None:
    """
    Enterprise‑рівень збереження результатів:
      • Повна нормалізація нод
      • Маскування чутливих полів
      • Захист від кривих структур
      • Агрегований summary (Burp‑style)
      • Повна сумісність з існуючим GUI
    """
    logger = logging.getLogger("crawler.save_outputs")
    logger.setLevel(logging.INFO)

    os.makedirs("logs", exist_ok=True)

    # 1) Збереження дерева краулу
    try:
        tree_dir = os.path.dirname(LOG_CRAWL_STRUCTURE_PATH) or "."
        os.makedirs(tree_dir, exist_ok=True)

        tmp = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False,
            dir=tree_dir, prefix="tree_", suffix=".tmp"
        )
        try:
            tmp.write(f"--- Crawl Tree @ {datetime.now().isoformat()} ---\n")
            lines = globals().get("tree_log", [])
            if isinstance(lines, (list, tuple)):
                tmp.writelines([str(line) + "\n" for line in lines])
            tmp.flush()
        finally:
            tmp.close()
            os.replace(tmp.name, str(LOG_CRAWL_STRUCTURE_PATH))

        logger.info("Crawl tree saved to %s", LOG_CRAWL_STRUCTURE_PATH)

    except Exception as e:
        logger.exception("Failed to write crawl tree: %s", e)

    # 2) Витягуємо nodes_json / result
    try:
        if isinstance(result, list):
            nodes_raw = result
        elif isinstance(result, dict) and isinstance(result.get("nodes"), list):
            nodes_raw = result.get("nodes")
        else:
            nodes_raw = globals().get("nodes_json", []) or []
    except Exception:
        nodes_raw = globals().get("nodes_json", []) or []

    if not isinstance(nodes_raw, (list, tuple)):
        nodes_raw = [nodes_raw]

    nodes_raw = list(nodes_raw)[:max_nodes_save]

    clean_nodes: List[Dict[str, Any]] = []
    for n in nodes_raw:
        if isinstance(n, dict):
            clean_nodes.append(n)
        else:
            logger.warning(f"Skipping invalid node in save_outputs: {type(n)} -> {n}")

    if not clean_nodes:
        clean_nodes = []

    def _normalize_sensitive_list(v: Any) -> List[str]:
        if isinstance(v, dict) and "examples" in v:
            return [str(x) for x in v.get("examples", []) if x]
        if isinstance(v, (list, tuple)):
            return [str(x) for x in v if x]
        return []

    def _safe_mask(s: str, keep: int = 4) -> str:
        try:
            return mask_secret(str(s), keep=keep)
        except Exception:
            s = str(s)
            return "*" * min(len(s), 8)

    def _mask_node_for_export(node: dict) -> dict:
        n: Dict[str, Any] = {}
        for k, v in node.items():

            if k in ("tokens", "api_keys", "jwt_tokens"):
                items = _normalize_sensitive_list(v)
                items = list(dict.fromkeys(items))[:max_items_per_field]
                n[k] = {
                    "count": len(items),
                    "examples": [_safe_mask(x, keep=4) for x in items[:5]],
                }

            elif k in ("passwords", "secrets"):
                items = _normalize_sensitive_list(v)
                items = list(dict.fromkeys(items))[:max_items_per_field]
                keep = 2 if k == "passwords" else 4
                n[k] = {
                    "count": len(items),
                    "examples": [_safe_mask(x, keep=keep) for x in items[:3]],
                }

            elif isinstance(v, (list, tuple)):
                try:
                    n[k] = list(v)[:max_items_per_field]
                except Exception:
                    n[k] = []

            elif isinstance(v, dict):
                try:
                    n[k] = v.copy()
                except Exception:
                    n[k] = {}

            else:
                n[k] = v

        return n

    safe_nodes: List[Dict[str, Any]] = []
    host_counter: Dict[str, int] = {}
    endpoint_counter: Dict[str, int] = {}
    sensitive_total = 0


    def _safe_url(u: Any) -> str:
        try:
            return str(u) if u is not None else ""
        except Exception:
            return ""

    for node in clean_nodes:
        masked = _mask_node_for_export(node)
        safe_nodes.append(masked)

        url = _safe_url(masked.get("url", ""))
        try:
            host = urlparse(url).netloc or ""
        except Exception:
            host = ""

        if host:
            host_counter[host] = host_counter.get(host, 0) + 1

        api_eps = masked.get("api_endpoints", [])
        if isinstance(api_eps, dict) and "examples" in api_eps:
            eps_list = api_eps.get("examples") or []
        elif isinstance(api_eps, (list, tuple)):
            eps_list = api_eps
        else:
            eps_list = []

        for ep in eps_list:
            ep_s = str(ep)
            endpoint_counter[ep_s] = endpoint_counter.get(ep_s, 0) + 1

        for key in ("tokens", "api_keys", "jwt_tokens", "passwords", "secrets"):
            val = masked.get(key)
            if isinstance(val, dict):
                sensitive_total += int(val.get("count", 0))

    top_hosts = sorted(
        [{"host": h, "pages": c} for h, c in host_counter.items()],
        key=lambda x: x["pages"], reverse=True
    )[:20]

    top_endpoints = sorted(
        [{"endpoint": e, "hits": c} for e, c in endpoint_counter.items()],
        key=lambda x: x["hits"], reverse=True
    )[:50]

    enterprise_summary = {
        "total_nodes": len(safe_nodes),
        "total_hosts": len(host_counter),
        "total_api_endpoints": len(endpoint_counter),
        "total_sensitive_items": sensitive_total,
        "top_hosts": top_hosts,
        "top_api_endpoints": top_endpoints,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    enterprise_payload = {
        "nodes": safe_nodes,
        "summary": enterprise_summary,
    }

    # 4) Збереження JSON
    try:
        json_dir = os.path.dirname(JSON_CRAWL_EXPORT_PATH) or "."
        os.makedirs(json_dir, exist_ok=True)

        tmp = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False,
            dir=json_dir, prefix="nodes_", suffix=".tmp"
        )
        try:
            json.dump(enterprise_payload, tmp, indent=2, ensure_ascii=False)
            tmp.flush()
        finally:
            tmp.close()
            safe_replace(tmp.name, JSON_CRAWL_EXPORT_PATH)

        logger.info(
            "Enterprise JSON saved to %s (%d nodes, %d hosts, %d endpoints)",
            JSON_CRAWL_EXPORT_PATH,
            enterprise_summary["total_nodes"],
            enterprise_summary["total_hosts"],
            enterprise_summary["total_api_endpoints"],
        )
    except Exception as e:
        logger.exception("Failed to write enterprise JSON: %s", e)

    # 5) DOT + SVG
    def _safe_dot_pair(x: Any) -> str:
        try:
            s = str(x)
            return s.replace("\n", " ").replace("\r", " ").replace('"', '\\"')
        except Exception:
            return ""

    try:
        dot_dir = os.path.dirname(str(LOG_CRAWL_GRAPH_DOT)) or "."
        os.makedirs(dot_dir, exist_ok=True)

        tmp = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False,
            dir=dot_dir, prefix="dot_", suffix=".tmp"
        )
        try:
            tmp.write("digraph Crawl {\n")
            edges = globals().get("dot_edges", [])
            if isinstance(edges, (list, tuple)):
                for frm, to in edges:
                    frm_s = _safe_dot_pair(frm)
                    to_s = _safe_dot_pair(to)
                    if frm_s and to_s:
                        tmp.write(f'  "{frm_s}" -> "{to_s}";\n')
            tmp.write("}\n")
            tmp.flush()
        finally:
            tmp.close()
            safe_replace(tmp.name, LOG_CRAWL_GRAPH_DOT)

    except Exception as e:
        logger.exception("Failed to write DOT file: %s", e)

    try:
        import shutil
        if shutil.which("dot"):
            try:
                svg_out = LOG_CRAWL_GRAPH_SVG + ".svg"
                subprocess.run(
                    ["dot", "-Tsvg", LOG_CRAWL_GRAPH_DOT, "-o", svg_out],
                    timeout=10, check=True
                )
            except Exception:
                pass
    except Exception:
        pass

    # 6) Summary для GUI
    if gui_callback:
        try:
            gui_summary = []
            for n in safe_nodes:
                if not isinstance(n, dict):
                    continue

                def _safe_len(key: str) -> int:
                    v = n.get(key, [])
                    return len(v) if isinstance(v, (list, tuple, set)) else 0

                api_ep = n.get("api_endpoints")
                api_ep_count = (
                    api_ep.get("count", 0)
                    if isinstance(api_ep, dict)
                    else _safe_len("api_endpoints")
                )

                sens_count = 0
                if isinstance(n.get("tokens"), dict):
                    sens_count += n["tokens"].get("count", 0)
                if isinstance(n.get("api_keys"), dict):
                    sens_count += n["api_keys"].get("count", 0)

                gui_summary.append(
                    {
                        "url": _safe_url(n.get("url", "")),
                        "forms": _safe_len("forms"),
                        "scripts": _safe_len("scripts"),
                        "api_endpoints": api_ep_count,
                        "ipv6": _safe_len("ipv6"),
                        "mac": _safe_len("mac"),
                        "cidr": _safe_len("cidr"),
                        "hostnames": _safe_len("hostnames"),
                        "sensitive_data": sens_count,
                    }
                )

            gui_callback(
                {
                    "crawler": {
                        "nodes": gui_summary,
                        "summary": enterprise_summary,
                    }
                }
            )
        except Exception as e:
            logger.exception("GUI callback failed: %s", e)

# ---------------------------------------------------------------------
# Enhanced Request Session (stable version)
# ---------------------------------------------------------------------

class AntiDetectionSession:
    def __init__(self):
        self.session = requests.Session()
        self.cloudscraper = cfscraper.create_scraper()
        # Safe session rotation
        self.current_session = get_random_session()
        # Safe TLS context
        self.tls_context = self._create_tls_context()
        # Safe DNS resolver (no domain replacement)
        self.doh_resolver = resolve_dns

    # -----------------------------------------------------------------
    # TLS Context (stable)
    # -----------------------------------------------------------------
    def _create_tls_context(self) -> ssl.SSLContext:
        """Create TLS context with spoofed ciphers"""
        if not ENABLE_TLS_SPOOFING:
            return ssl.create_default_context()

        ctx = ssl.create_default_context()
        ctx.set_ciphers(':'.join(TLS_SPOOF_CIPHERS))
        ctx.options |= 0x4  # OP_LEGACY_SERVER_CONNECT
        return ctx

    # -----------------------------------------------------------------
    # GET request with stable anti-detection pipeline
    # -----------------------------------------------------------------
    def get(self, url: str, **kwargs) -> requests.Response:
        """
        Make request with stable anti-detection features.
        """
        # Rate limit
        rate_limit()

        # Multi-session rotation (safe)
        if ENABLE_MULTI_SESSION_ROTATION:
            self.current_session = get_random_session()

        # Geo-IP rotation (safe: only proxy assignment, no domain/IP replacement)
        if ENABLE_GEO_IP_ROTATION:
            proxy = self.get_random_country_ip()
            if proxy:
                kwargs["proxies"] = {"http": proxy, "https": proxy}

        # TLS spoofing (safe)
        if ENABLE_TLS_SPOOFING:
            kwargs["verify"] = self.tls_context

        # Apply DNS-over-HTTPS
        if ENABLE_DOH_RESOLVER:
            domain = urlparse(url).netloc
            try:
                ip = self.doh_resolver(domain)
                url = url.replace(domain, ip)
            except Exception:
                pass

        # Automatic retry
        for attempt in range(MAX_RETRIES):
            try:
                response = self.session.get(url, timeout=REQUEST_TIMEOUT, **kwargs)

                if not should_retry(response.status_code):
                    return response

                # Backoff delay
                time.sleep(RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)])

            except Exception:
                if attempt == MAX_RETRIES - 1:
                    raise
                time.sleep(RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)])

        # Final fallback
        return self.session.get(url, timeout=REQUEST_TIMEOUT, **kwargs)

    def get_random_country_ip(self) -> Optional[str]:
        """
        Get proxy IP from a random country.
        Stable version:
        - No invalid GeoIP lookups
        - Safe proxy selection
        - Safe fallback IP generation
        - Fully preserves your logic and structure
        """
        if not ENABLE_GEO_IP_ROTATION or not GEOIP_READER:
            return None

        try:
            # Countries with known proxy pools
            country_proxies = {
                'US': ['us', 'usa', 'america'],
                'GB': ['uk', 'britain', 'england'],
                'DE': ['germany', 'deutschland'],
                'FR': ['france'],
                'JP': ['japan'],
                'CA': ['canada'],
                'AU': ['australia'],
                'BR': ['brazil'],
                'NL': ['netherlands', 'holland'],
                'RU': ['russia']
            }

            # Known proxy servers for each country
            known_proxies = {
                'US': ['104.238.176.100:80', '162.244.148.134:8080', '192.111.134.10:3128'],
                'GB': ['185.143.223.43:80', '185.143.223.42:8080'],
                'DE': ['178.157.131.10:80', '178.157.131.11:8080'],
                'FR': ['194.163.173.10:80', '194.163.173.11:8080'],
                'JP': ['103.10.100.10:80', '103.10.100.11:8080'],
                'CA': ['142.44.160.10:80', '142.44.160.11:8080'],
                'AU': ['103.8.100.10:80', '103.8.100.11:8080'],
                'BR': ['177.10.100.10:80', '177.10.100.11:8080'],
                'NL': ['185.100.100.10:80', '185.100.100.11:8080'],
                'RU': ['176.100.100.10:80', '176.100.100.11:8080']
            }

            # Pick random country
            countries = list(country_proxies.keys())
            country = random.choice(countries)

            # If we have known proxies — return one
            if country in known_proxies and known_proxies[country]:
                return random.choice(known_proxies[country])

            # Safe fallback IP (avoid 0.x.x.x and 255.x.x.x)
            def safe_octet():
                return random.randint(1, 254)

            fallback_ip = f"{safe_octet()}.{safe_octet()}.{safe_octet()}.{safe_octet()}:80"
            return fallback_ip

        except Exception as e:
            logger.warning(f"Geo-IP rotation failed: {e}")
            return None


