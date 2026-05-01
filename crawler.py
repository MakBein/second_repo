# xss_security_gui/crawler.py
import os
import json
import re
import time
import threading
import logging
import tempfile
import subprocess
from urllib.parse import urljoin, urlparse
from hashlib import sha1
from datetime import datetime, timezone
from typing import List, Dict, Any, Set, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import cloudscraper
from bs4 import BeautifulSoup, Comment

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
# Configuration (from settings with sensible defaults)
# ---------------------------------------------------------------------
REQUEST_TIMEOUT: int = settings.get("http.request_timeout", 10)
PROXIES: Optional[Dict[str, str]] = settings.get("http.proxies", None)
RATE_LIMIT: float = float(settings.get("crawl.max_rps", 2.0) or 2.0)

# internal rate-limit state
_last_request: float = 0.0
_rate_lock = threading.Lock()

# ---------------------------------------------------------------------
# Logger and error logging helper
# ---------------------------------------------------------------------
logger = logging.getLogger("crawler")
logger.setLevel(logging.INFO)


def log_error(msg: str) -> None:
    try:
        logger.error(msg)
        if CRAWLER_ERROR_LOG:
            os.makedirs(os.path.dirname(CRAWLER_ERROR_LOG) or "logs", exist_ok=True)
            with open(CRAWLER_ERROR_LOG, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.utcnow().isoformat()}] {msg}\n")
    except Exception:
        logger.exception("Failed to write to CRAWLER_ERROR_LOG")

# ---------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------
def rate_limit() -> None:
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


# Try Playwright but don't break if it's not installed
try:
    from playwright.sync_api import sync_playwright  # type: ignore

    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

# Global in-memory structures (reset by reset_state)

visited: Set[str] = set()
tree_log: List[str] = []
dot_edges: List[tuple] = []
nodes_json: List[Dict[str, Any]] = []
js_cache: Dict[str, Dict] = {}

visited_lock = threading.Lock()
nodes_lock = threading.Lock()
dot_lock = threading.Lock()


# Aggressive defaults (can be overridden via settings)

MAX_LINKS_PER_PAGE: int = int(settings.get("crawl.max_links_per_page", 500))
MAX_SCRIPTS_PER_PAGE: int = int(settings.get("crawl.max_scripts_per_page", 200))
MAX_CONCURRENT_REQUESTS: int = int(settings.get("crawl.max_workers", 20))
AGGRESSIVE_HEADERS: bool = bool(settings.get("http.aggressive_headers", True))

MAX_MATCHES_PER_KEY: int = int(settings.get("crawl.max_matches_per_key", 200))
MAX_API_ENDPOINTS: int = int(settings.get("crawl.max_api_endpoints", 200))


# --- HTTP / Browser emulation ---

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

if AGGRESSIVE_HEADERS:
    DEFAULT_HEADERS.update({
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
    })

# Utilities

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



def dedupe_preserve_order(seq: List[Any]) -> List[Any]:
    """Remove duplicates while preserving order. Works for hashable and JSON-serializable items."""
    seen = set()
    out: List[Any] = []
    for item in seq:
        try:
            key = item if isinstance(item, (str, int, float, tuple)) else json.dumps(item, sort_keys=True, ensure_ascii=False)
        except Exception:
            key = str(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out



def _normalize_candidate(cand: str, base_url: str) -> str:
    """Normalize relative/absolute candidate into absolute URL; return empty string for invalid."""
    if not cand:
        return ""
    cand = cand.strip().strip('\'"')
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

def safe_list(v):
    return v if isinstance(v, (list, tuple)) else []

def mask_secret(s: str, keep: int = 4) -> str:
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


# Helpers

def hash_url_no_query(u: str) -> str:
    parsed = urlparse(u)._replace(query="", fragment="")
    return sha1(parsed.geturl().encode()).hexdigest()

def normalize_scheme(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    if not parsed.scheme:
        # якщо це вже щось типу //host/path
        if url.startswith("//"):
            return "https:" + url
        return "https://" + url.lstrip("/")
    return parsed.geturl()


def is_same_domain(url: str, base_netloc: str) -> bool:
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
    if not href:
        return False
    href = href.strip().lower()
    if href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return False
    return True

def make_session(aggressive: bool = True) -> requests.Session:
    """Создание сессии с агрессивными заголовками для максимального сбора данных"""
    s = requests.Session()

    if PROXIES:
        s.proxies.update(PROXIES)

    if aggressive:
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 XSSSecurityCrawler/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
            "Referer": "https://www.google.com/",
        })
    else:
        s.headers.update({
            "User-Agent": "XSSSecurityCrawler/2.0 (+https://localhost)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
    return s

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

# Precompiled patterns
# SSN, PASSWORD и SECRET
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
PASSWORD_PATTERNS_COMPILED = [
    re.compile(r"(?:password|passwd|pwd)[=:]\s*['\"]?([^'\"]{6,})['\"]?", re.I),
    re.compile(r"password['\"]?\s*[:=]\s*['\"]?([^'\"]{6,})['\"]?", re.I),
]
SECRET_PATTERNS_COMPILED = [
    re.compile(r"(?:secret|private[_-]?key|public[_-]?key)[=:]\s*['\"]?([A-Za-z0-9_\-\.+/=]{20,})['\"]?", re.I),
    re.compile(r"-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE|PUBLIC)\s+KEY-----", re.I),
]

EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PHONE_RE_LIST = [
    re.compile(r"(?:\+?\d{1,3}[-.\s]?\(?\d{2,3}\)?[-.\s]?\d{2,3}[-.\s]?\d{2,2}[-.\s]?\d{2,2})"),
    re.compile(r"(?:\+7|8)[-\s]?(?:9\d{2}|3\d{2}|4\d{2}|8\d{2})[-\s]?\d{3}[-\s]?\d{2}[-\s]?\d{2}"),
    re.compile(r"\+1[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}"),
    re.compile(r"\d{3}[-.\s]?\d{3}[-.\s]?\d{4}")
]

TOKEN_PATTERNS_COMPILED = [
    re.compile(r"(?:auth[_-]?token|session[_-]?id|api[_-]?key|access[_-]?token|refresh[_-]?token)[=:]?\s*([A-Za-z0-9_\-\.]{8,})", re.I),
    re.compile(r"(?:bearer|token|key|secret)[=:]\s*([A-Za-z0-9_\-\.]{8,})", re.I),
    re.compile(r"['\"]([a-zA-Z0-9_\-]{32,})['\"]"),
]


JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
# IPv6 pattern kept complex; use findall but limit results
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

MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b|\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b")
CIDR_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)/(?:[0-9]|[12][0-9]|3[0-2])\b"
    r"|\b[0-9A-Fa-f:]+/[0-9]{1,3}\b"
)


HOSTNAME_RE = re.compile(r"\b(?=.{1,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b")
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
    re.compile(r"AKIA[0-9A-Z]{16}")
]
CREDIT_CARD_RE = re.compile(
    r"\b(?:(4[0-9]{12}(?:[0-9]{3})?)|(5[1-5][0-9]{14})|(3[47][0-9]{13})|"
    r"(6(?:011|5[0-9]{2})[0-9]{12})|(35[0-9]{14})|(62[0-9]{14,17}))\b"
)


# ============================================================
#  Sensitive Data Extraction (Burp-style, safe & bounded)
# ============================================================

def _safe_trim_value(value: Any, max_len: int = 5000) -> str:
    """Нормалізує значення до str, обрізає надто довгі, гарантує безпечний тип."""
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


def _append_limited_unique(
    bucket: List[str],
    value: Any,
    limit: int = MAX_MATCHES_PER_KEY,
) -> None:
    """Додає значення в список, якщо воно не пусте, ще не зустрічалось і не перевищено ліміт."""
    if len(bucket) >= limit:
        return
    s = _safe_trim_value(value)
    if not s:
        return
    if s in bucket:
        return
    bucket.append(s)


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
                _append_limited_unique(data["credit_cards"], digits)

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

    # Дедуплікація + обрізання
    for key in data:
        if isinstance(data[key], list):
            data[key] = dedupe_preserve_order(data[key])[:MAX_MATCHES_PER_KEY]

    return data

# ============================================================
#  API Endpoint Extraction
# ============================================================

def extract_api_endpoints_from_text(text: str, base_url: str) -> List[str]:
    """
    Extract API endpoints from HTML/JS/text.
    Returns normalized absolute URLs limited by MAX_API_ENDPOINTS.
    """

    if not text:
        return []

    api_patterns = [
        re.compile(r"(?:fetch|axios|ajax|XMLHttpRequest|\.get|\.post|\.put|\.delete)\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
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


# ============================================================
#  ThreatIntel Reporter
# ============================================================

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


# ============================================================
#  Hybrid Fetch Pipeline
# ============================================================

def fetch_with_requests_raw(url: str, timeout: int = REQUEST_TIMEOUT, session: Optional[requests.Session] = None):
    """
    Try requests first. Returns Response on success or None on failure.
    Uses DEFAULT_HEADERS and optional session.
    """
    sess = session or requests.Session()
    try:
        rate_limit()
        return sess.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
    except Exception as e:
        logger.debug("requests failed for %s: %s", url, e)
        return None



def fetch_with_cloudscraper(url: str, timeout: int = 15) -> Optional[str]:
    """
    Use cloudscraper to bypass simple bot protections. Returns HTML text or None.
    """
    try:
        rate_limit()
        scraper = cloudscraper.create_scraper(browser={"browser": "chrome", "platform": "windows", "mobile": False})
        if PROXIES:
            try:
                scraper.proxies.update(PROXIES)
            except Exception:
                logger.debug("Invalid PROXIES for cloudscraper; skipping proxies.")
        resp = scraper.get(url, timeout=timeout, allow_redirects=True)
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
    """
    if not PLAYWRIGHT_AVAILABLE:
        return None

    try:
        def _inner():
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    viewport={"width": 1920, "height": 1080},
                    user_agent=DEFAULT_HEADERS.get("User-Agent"),
                )
                try:
                    context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => false});")
                except Exception:
                    pass

                page = context.new_page()
                page.set_default_timeout(max(1000, int(timeout * 1000)))
                page.goto(url, wait_until="networkidle")
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
      1) cloudscraper
      2) Playwright (if cloudscraper result is too small or missing)
    Returns HTML string or None.
    """
    url = normalize_scheme(url)

    html = fetch_with_cloudscraper(url)
    if html and len(html.strip()) > 200:
        return html

    return fetch_with_playwright(url)


# ============================================================
#  SUPER-CRAWLER — головна функція
# ============================================================

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
    Logic preserved; code cleaned and hardened.
    """
    global visited, tree_log, dot_edges, nodes_json, js_cache

    # Initialize session lazily
    if session is None:
        session = make_session(aggressive=aggressive)

    # Depth guard
    if depth > CRAWL_DEPTH_LIMIT:
        return {"url": url, "error": "Depth limit exceeded"}

    safe_url = normalize_scheme(url)
    parsed = urlparse(safe_url)
    parsed_domain = parsed.netloc or ""

    # Whitelist check
    if CRAWL_DOMAINS_WHITELIST:
        if parsed_domain not in CRAWL_DOMAINS_WHITELIST and not any(parsed_domain.endswith("." + d) for d in CRAWL_DOMAINS_WHITELIST):
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

        # Headers summary
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
                node["cookies"] = [{"name": c.name, "value": (c.value or "")[:100], "domain": c.domain} for c in
                                   cookies_obj]
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
        _merge_sensitive_into_node(node, extract_sensitive_data(html))

        # API endpoints from HTML
        node["api_endpoints"].extend(extract_api_endpoints_from_text(html, safe_url))

        # ============================================================
        # 5) Форми
        # ============================================================

        for form in soup.find_all("form"):

            # --- normalize class attribute ---
            cls = form.get("class")
            if isinstance(cls, list):
                form_classes = [str(c) for c in cls]
            elif isinstance(cls, str):
                form_classes = [cls]
            else:
                form_classes = []

            inputs = []
            for inp in form.find_all("input"):

                # normalize input class
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

            handlers = {
                attr: form.attrs[attr]
                for attr in form.attrs
                if attr.startswith("on")
            }

            node["forms"].append({
                "action": form.get("action", ""),
                "method": form.get("method", "GET").upper(),
                "inputs": [inp["name"] for inp in inputs if inp["name"]],
                "input_details": inputs,
                "textareas": textareas,
                "selects": selects,
                "js_events": handlers,
                "id": form.get("id"),
                "class": form_classes,
            })

        # ============================================================
        # 6) Скрипти (JS)
        # ============================================================

        scripts = soup.find_all("script")[:max_scripts]

        for script in scripts:
            if script.get("src"):
                js_url = normalize_scheme(urljoin(safe_url, script.get("src")))

                if js_url in js_cache:
                    insights = js_cache[js_url]
                else:
                    try:
                        js_resp = session.get(js_url, timeout=8)
                        if "javascript" in js_resp.headers.get("Content-Type", "") or js_url.endswith(".js"):
                            js_text = js_resp.text or ""
                            insights = extract_js_insights(js_text)

                            # API endpoints з JS
                            node["api_endpoints"].extend(
                                extract_api_endpoints_from_text(js_text, safe_url)
                            )

                            # Sensitive data з JS
                            _merge_sensitive_into_node(node, extract_sensitive_data(js_text))
                        else:
                            insights = {"functions": [], "fetch_calls": [], "ajax_calls": [], "sensitive": []}

                    except Exception as e:
                        print(f"[JS] ❌ Error loading {js_url}: {e}")
                        insights = {"functions": [], "fetch_calls": [], "ajax_calls": [], "sensitive": []}

                    js_cache[js_url] = insights

                node["scripts"].append({
                    "path": js_url,
                    "functions": insights.get("functions", []),
                    "fetch_calls": [u for _, u in insights.get("fetch_calls", [])],
                    "ajax_calls": insights.get("ajax_calls", []),
                    "xss_sensitive": insights.get("sensitive", []),
                })

            else:
                # INLINE JS
                js = script.string or ""
                if js.strip():
                    insights = extract_js_insights(js)
                    node["api_endpoints"].extend(
                        extract_api_endpoints_from_text(js, safe_url)
                    )

                    _merge_sensitive_into_node(node, extract_sensitive_data(js))
                else:
                    insights = {"functions": [], "fetch_calls": [], "ajax_calls": [], "sensitive": []}

                node["scripts"].append({
                    "path": "[INLINE]",
                    "functions": insights.get("functions", []),
                    "fetch_calls": [u for _, u in insights.get("fetch_calls", [])],
                    "ajax_calls": insights.get("ajax_calls", []),
                    "xss_sensitive": insights.get("sensitive", []),
                })

        # ============================================================
        # 7) Посилання
        # ============================================================

        hrefs = []
        try:
            hrefs = [a.get("href") for a in soup.find_all("a") if a.get("href")]
        except Exception:
            hrefs = []

        clean_links = []
        for h in hrefs:
            try:
                if not is_real_link(h):
                    continue
                candidate = h.split("#")[0].strip().strip('\'"')
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
        # 8) META (повністю безпечна версія)
        # ============================================================

        safe_meta = []
        for meta in soup.find_all("meta"):
            try:
                meta_data = {}
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

        iframes = []
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
                    # Якщо є групи – беремо першу, інакше весь матч
                    if m.groups():
                        ws = m.group(1)
                    else:
                        ws = m.group(0)
                    ws = (ws or "").strip()
                    if ws:
                        ws_matches.append(ws)
            except Exception:
                # Не валимо весь crawl через один кривий патерн
                continue

        node["websockets"] = dedupe_preserve_order(ws_matches)[:50]

        # ============================================================
        # 11) data-* атрибути
        # ============================================================

        safe_data_attrs = []
        for tag in soup.find_all(True):
            try:
                for attr, val in tag.attrs.items():
                    if attr.startswith("data-"):
                        safe_data_attrs.append(
                            f"{tag.name}.{attr}={str(val)[:100]}"
                        )
            except Exception:
                continue

        node["data_attributes"] = safe_data_attrs[:200]

        # ============================================================
        # 12) Коментарі
        # ============================================================

        comments = []
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

        # Sensitive data з коментарів
        for c in comments:
            try:
                _merge_sensitive_into_node(node, extract_sensitive_data(c))
            except Exception:
                continue

        # ============================================================
        # 13) Кнопки
        # ============================================================

        safe_buttons = []

        for button in soup.find_all(["button", "input"]):
            try:
                # Визначаємо, чи це кнопка
                if button.get("type") == "button" or button.name == "button":

                    # --- normalize class attribute ---
                    cls = button.get("class")
                    if isinstance(cls, list):
                        btn_classes = [str(c) for c in cls]
                    elif isinstance(cls, str):
                        btn_classes = [cls]
                    else:
                        btn_classes = []

                    safe_buttons.append({
                        "text": button.get_text(strip=True)[:50],
                        "onclick": str(button.get("onclick", ""))[:200],
                        "id": button.get("id"),
                        "class": btn_classes,
                    })

            except Exception:
                continue

        node["buttons"] = safe_buttons

        # ============================================================
        # 14) Select
        # ============================================================

        safe_selects = []
        for select in soup.find_all("select"):
            try:
                options = [
                    opt.get("value")
                    for opt in select.find_all("option")
                    if opt.get("value")
                ]
                if options:
                    safe_selects.append({
                        "name": select.get("name"),
                        "options": [str(o) for o in options[:20]],
                    })
            except Exception:
                continue

        node["selects"] = safe_selects

        # ============================================================
        # 15) Textarea
        # ============================================================

        safe_textareas = []
        for textarea in soup.find_all("textarea"):
            try:
                safe_textareas.append({
                    "name": textarea.get("name"),
                    "placeholder": textarea.get("placeholder"),
                    "id": textarea.get("id"),
                })
            except Exception:
                continue

        node["textareas"] = safe_textareas

        # ============================================================
        # 16) on* events
        # ============================================================

        safe_events = []
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
        # 17) Логи дерева та графа
        # ============================================================

        tree_log.append("  " * depth + f"📄 {safe_url}")

        for form in node["forms"]:
            tree_log.append("  " * (depth + 1) + f"📝 FORM {form['method']} {form['action']}")

        for js in node["scripts"]:
            tree_log.append("  " * (depth + 1) + f"📦 JS {js['path']}")

        with dot_lock:
            for link in unique_links:
                dot_edges.append((safe_url, link))

        # ============================================================
        # 18) Дедуплікація всіх полів
        # ============================================================

        node["api_endpoints"] = dedupe_preserve_order(node["api_endpoints"])[:MAX_API_ENDPOINTS]
        _trim_node_list_fields(node)

        with nodes_lock:
            nodes_json.append(node)

        report_threatintel(node, gui_callback)

        # ============================================================
        # 19) Рекурсивний обхід посилань
        # ============================================================

        if parallel and len(unique_links) > 1:
            to_visit = []

            for link in unique_links:
                if not is_same_domain(link, parsed_domain):
                    continue
                link_id = hash_url_no_query(link)
                with visited_lock:
                    if link_id in visited:
                        continue
                to_visit.append(link)

            if to_visit:
                with ThreadPoolExecutor(max_workers=min(MAX_CONCURRENT_REQUESTS, len(to_visit))) as executor:
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
            # Послідовний режим
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
            os.makedirs(os.path.dirname(CRAWLER_ERROR_LOG) or "logs", exist_ok=True)
            with open(CRAWLER_ERROR_LOG, "a", encoding="utf-8") as errlog:
                errlog.write(f"[{datetime.now().isoformat()}] {safe_url} ❌ {str(e)}\n")
        except Exception:
            pass
        with nodes_lock:
            nodes_json.append(node)
        report_threatintel(node, gui_callback)
        return node


def build_final_dict(nodes: List[Dict[str, Any]], max_items: int = 500) -> Dict[str, Any]:
    """
    Бойова версія build_final_dict():
      • Гарантує правильні типи
      • Нормалізує всі поля
      • Маскує чутливі дані
      • Не падає на кривих нодах
      • Повертає чистий, JSON‑сумісний dict
    """

    # -----------------------------
    # 0) Захисні утиліти
    # -----------------------------
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
        """
        Приводить чутливі поля до списку строк.
        Підтримує:
          - list/tuple
          - dict {"count":..., "examples":[...]}
        """
        if isinstance(v, dict) and "examples" in v:
            return [str(x) for x in v.get("examples", []) if x]
        if isinstance(v, (list, tuple)):
            return [str(x) for x in v if x]
        return []

    # -----------------------------
    # 1) Якщо немає нод — повертаємо порожній шаблон
    # -----------------------------
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

    # -----------------------------
    # 2) Root — копія першої ноди, але нормалізована
    # -----------------------------
    root = dict(nodes[0]) if isinstance(nodes[0], dict) else {}

    # -----------------------------
    # 3) Поля, які треба зливати
    # -----------------------------
    merge_fields = [
        "forms", "scripts", "links", "meta", "iframes", "events",
        "api_endpoints", "emails", "phones", "tokens", "ips",
        "ipv6", "mac", "cidr", "hostnames", "comments",
        "parameters", "base64_strings", "uuids", "hashes",
        "api_keys", "jwt_tokens", "credit_cards", "ssn",
        "passwords", "secrets", "cookies", "websockets",
        "data_attributes", "buttons", "selects", "textareas",
    ]

    combined = {f: [] for f in merge_fields}

    # -----------------------------
    # 4) Збір усіх значень
    # -----------------------------
    for node in nodes:
        if not isinstance(node, dict):
            continue
        for f in merge_fields:
            val = node.get(f)
            if isinstance(val, (list, tuple)):
                combined[f].extend(val)

    # -----------------------------
    # 5) META — унікальні dict
    # -----------------------------
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

    # -----------------------------
    # 6) IPv4 — тільки валідні
    # -----------------------------
    ipv4_valid = []
    ipv4_re = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
    )
    for ip in combined["ips"]:
        if isinstance(ip, str) and ipv4_re.match(ip):
            ipv4_valid.append(ip)
    root["ips"] = _dedupe(ipv4_valid)[:max_items]

    # -----------------------------
    # 7) Простi спискові поля
    # -----------------------------
    simple_fields = [
        "forms", "scripts", "links", "iframes", "events", "api_endpoints",
        "emails", "phones", "ipv6", "mac", "cidr", "hostnames",
        "comments", "parameters", "base64_strings", "uuids", "hashes",
        "credit_cards", "ssn", "cookies", "websockets", "data_attributes",
        "buttons", "selects", "textareas",
    ]

    for f in simple_fields:
        vals = combined.get(f, [])
        root[f] = _dedupe(vals)[:max_items]

    # -----------------------------
    # 8) Чутливі поля (уніфікований формат)
    # -----------------------------
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

    # -----------------------------
    # 9) Гарантуємо наявність усіх полів
    # -----------------------------
    expected = [
        "forms", "scripts", "links", "meta", "iframes", "events",
        "api_endpoints", "emails", "phones", "ips", "ipv6", "mac",
        "cidr", "hostnames", "parameters", "base64_strings", "uuids",
        "hashes", "credit_cards", "ssn", "cookies", "websockets",
        "data_attributes", "comments", "buttons", "selects", "textareas",
    ]
    for f in expected:
        root.setdefault(f, [])

    root.setdefault("headers", root.get("headers", {}))
    root.setdefault("url", root.get("url", ""))
    root.setdefault("error", None)

    # -----------------------------
    # 10) Фінальні метадані
    # -----------------------------
    root["total_nodes"] = len(nodes)
    root["merged_at"] = datetime.now(timezone.utc).isoformat(),

    # -----------------------------
    # 11) Обрізаємо надто великі списки
    # -----------------------------
    for k, v in list(root.items()):
        if isinstance(v, list) and len(v) > max_items:
            root[k] = v[:max_items]

    return root

# ============================================================
#  Save Outputs (Tree, JSON, DOT, SVG, Summary) — HARDENED
# ============================================================

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

    # ============================================================
    # 1) Збереження дерева краулу
    # ============================================================
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
            os.replace(tmp.name, LOG_CRAWL_STRUCTURE_PATH)

        logger.info("Crawl tree saved to %s", LOG_CRAWL_STRUCTURE_PATH)

    except Exception as e:
        logger.exception("Failed to write crawl tree: %s", e)

    # ============================================================
    # 2) Витягуємо nodes_json / result
    # ============================================================
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

    # ============================================================
    # 2.1 Жорстка нормалізація — тільки dict
    # ============================================================
    clean_nodes: List[Dict[str, Any]] = []
    for n in nodes_raw:
        if isinstance(n, dict):
            clean_nodes.append(n)
        else:
            logger.warning(f"Skipping invalid node in save_outputs: {type(n)} -> {n}")

    if not clean_nodes:
        clean_nodes = []

    # ============================================================
    # 2.2 Утиліти
    # ============================================================
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

            # Чутливі поля
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

            # Списки
            elif isinstance(v, (list, tuple)):
                try:
                    n[k] = list(v)[:max_items_per_field]
                except Exception:
                    n[k] = []

            # dict
            elif isinstance(v, dict):
                try:
                    n[k] = v.copy()
                except Exception:
                    n[k] = {}

            # Примітиви
            else:
                n[k] = v

        return n

    # ============================================================
    # 3) Формуємо enterprise‑структуру
    # ============================================================
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

        # API endpoints
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

        # Sensitive
        for key in ("tokens", "api_keys", "jwt_tokens", "passwords", "secrets"):
            val = masked.get(key)
            if isinstance(val, dict):
                sensitive_total += int(val.get("count", 0))

    # Топ‑хости / ендпоінти
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

    # ============================================================
    # 4) Збереження JSON
    # ============================================================
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
            os.replace(tmp.name, JSON_CRAWL_EXPORT_PATH)

        logger.info(
            "Enterprise JSON saved to %s (%d nodes, %d hosts, %d endpoints)",
            JSON_CRAWL_EXPORT_PATH,
            enterprise_summary["total_nodes"],
            enterprise_summary["total_hosts"],
            enterprise_summary["total_api_endpoints"],
        )
    except Exception as e:
        logger.exception("Failed to write enterprise JSON: %s", e)

    # ============================================================
    # 5) DOT + SVG (без зміни логіки)
    # ============================================================
    def _safe_dot_pair(x: Any) -> str:
        try:
            s = str(x)
            return s.replace("\n", " ").replace("\r", " ").replace('"', '\\"')
        except Exception:
            return ""

    try:
        dot_dir = os.path.dirname(LOG_CRAWL_GRAPH_DOT) or "."
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
            os.replace(tmp.name, LOG_CRAWL_GRAPH_DOT)

    except Exception as e:
        logger.exception("Failed to write DOT file: %s", e)

    # SVG
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

    # ============================================================
    # 6) Summary для GUI (повністю сумісний)
    # ============================================================
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

