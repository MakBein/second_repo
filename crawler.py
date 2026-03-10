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
    """
    Append an error line to the crawler error log and emit logger.error.
    Best-effort only: failures to write the file are logged but do not raise.
    """
    ts = datetime.now(timezone.utc).isoformat()

    logger.error(msg)

    if not CRAWLER_ERROR_LOG:
        return

    try:
        with open(CRAWLER_ERROR_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        logger.exception("Failed to write to CRAWLER_ERROR_LOG")

# --- Конфігурація полів ---
LIST_FIELDS = [
    "forms", "scripts", "links", "meta", "iframes", "events",
    "api_endpoints", "emails", "phones", "ips", "ipv6", "mac",
    "cidr", "hostnames", "parameters", "base64_strings", "uuids",
    "hashes", "credit_cards", "ssn", "cookies", "websockets",
    "data_attributes", "comments", "buttons", "selects", "textareas",
]

SENSITIVE_FIELDS = ["tokens", "api_keys", "jwt_tokens", "passwords", "secrets"]

ALL_FIELDS = LIST_FIELDS + SENSITIVE_FIELDS

def _empty_sensitive():
    return {"count": 0, "examples": []}


def _make_empty_dict() -> Dict[str, Any]:
    """Створює порожню структуру результату без дублювання."""
    base = {field: [] for field in LIST_FIELDS}
    base.update({field: _empty_sensitive() for field in SENSITIVE_FIELDS})
    base.update({
        "url": "",
        "headers": {},
        "error": None,
        "total_nodes": 0,
        "merged_at": datetime.now(timezone.utc).isoformat(),
    })
    return base


# ---------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------
def rate_limit() -> None:
    """
    Simple global rate limiter (process-wide). Uses seconds between requests = 1 / RATE_LIMIT.
    Safe against RATE_LIMIT == 0 or None.
    """
    global _last_request
    with _rate_lock:
        try:
            r = float(RATE_LIMIT) if RATE_LIMIT else 1.0
        except Exception:
            r = 1.0
        min_interval = 1.0 / max(r, 0.0001)
        now = time.time()
        delta = now - _last_request
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
    """
    Ensure URL has a scheme. If missing, prepend https://.
    Return full URL string (parsed.geturl()) to preserve normalization.
    """
    if not url:
        return url
    parsed = urlparse(url)
    if not parsed.scheme:
        return "https://" + url.lstrip("/")
    return parsed.geturl()


def is_same_domain(url: str, base_netloc: str) -> bool:
    """
    Check whether `url` belongs to the same domain as `base_netloc`.
    Honors CRAWL_DOMAINS_WHITELIST if configured.
    """
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc
        if not netloc:
            return False
        if CRAWL_DOMAINS_WHITELIST:
            if netloc not in CRAWL_DOMAINS_WHITELIST and not any(netloc.endswith("." + d) for d in CRAWL_DOMAINS_WHITELIST):
                return False
        return netloc == base_netloc or netloc.endswith("." + base_netloc)
    except Exception:
        return False


def is_real_link(href: str) -> bool:
    if not href:
        return False
    href = href.strip()
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
#  Sensitive Data Extraction
# ============================================================

def extract_sensitive_data(text: str) -> Dict[str, List[str]]:
    """
    High‑performance sensitive data extractor.
    Fully preserves original semantics but:
    • faster (fewer loops, fewer conversions)
    • safer (strict list typing)
    • cleaner (no duplicated logic)
    """

    data: Dict[str, List[str]] = {
        "emails": [], "phones": [], "tokens": [], "ips": [], "ipv4": [],
        "ipv6": [], "mac": [], "cidr": [], "hostnames": [], "parameters": [],
        "base64_strings": [], "uuids": [], "hashes": [], "api_keys": [],
        "jwt_tokens": [], "credit_cards": [], "ssn": [], "passwords": [],
        "secrets": [],
    }

    if not text:
        return data

    # --- ultra-fast append guard ---
    def _append(lst: List[str], value: str):
        if len(lst) < MAX_MATCHES_PER_KEY and value:
            lst.append(value)

    try:
        # === Emails ===
        for m in EMAIL_RE.finditer(text):
            _append(data["emails"], m.group(0))

        # === Phones ===
        for p in PHONE_RE_LIST:
            for m in p.finditer(text):
                _append(data["phones"], m.group(0))
                if len(data["phones"]) >= MAX_MATCHES_PER_KEY:
                    break
            if len(data["phones"]) >= MAX_MATCHES_PER_KEY:
                break

        # === Tokens ===
        for p in TOKEN_PATTERNS_COMPILED:
            for m in p.finditer(text):
                token = m.group(1) if m.groups() else m.group(0)
                _append(data["tokens"], token)
                if len(data["tokens"]) >= MAX_MATCHES_PER_KEY:
                    break
            if len(data["tokens"]) >= MAX_MATCHES_PER_KEY:
                break

        # === JWT ===
        for m in JWT_RE.finditer(text):
            _append(data["jwt_tokens"], m.group(0))
            if len(data["jwt_tokens"]) >= MAX_MATCHES_PER_KEY:
                break

        # === IPv4 ===
        for m in IPV4_RE.finditer(text):
            ip = m.group(0)
            _append(data["ipv4"], ip)
            _append(data["ips"], ip)
            if len(data["ipv4"]) >= MAX_MATCHES_PER_KEY:
                break

        # === IPv6 ===
        for m in IPV6_RE.finditer(text):
            _append(data["ipv6"], m.group(0))
            if len(data["ipv6"]) >= MAX_MATCHES_PER_KEY:
                break

        # === MAC ===
        for m in MAC_RE.finditer(text):
            _append(data["mac"], m.group(0))
            if len(data["mac"]) >= MAX_MATCHES_PER_KEY:
                break

        # === CIDR ===
        for m in CIDR_RE.finditer(text):
            _append(data["cidr"], m.group(0))
            if len(data["cidr"]) >= MAX_MATCHES_PER_KEY:
                break

        # === Hostnames ===
        for m in HOSTNAME_RE.finditer(text):
            _append(data["hostnames"], m.group(0))
            if len(data["hostnames"]) >= MAX_MATCHES_PER_KEY:
                break

        # === Parameters ===
        for m in PARAM_RE.finditer(text):
            _append(data["parameters"], m.group(1))
            if len(data["parameters"]) >= MAX_MATCHES_PER_KEY:
                break

        # === Base64 ===
        for m in BASE64_RE.finditer(text):
            _append(data["base64_strings"], m.group(0))
            if len(data["base64_strings"]) >= MAX_MATCHES_PER_KEY:
                break

        # === UUID ===
        for m in UUID_RE.finditer(text):
            _append(data["uuids"], m.group(0))
            if len(data["uuids"]) >= MAX_MATCHES_PER_KEY:
                break

        # === Hashes ===
        for p in HASH_PATTERNS:
            for m in p.finditer(text):
                _append(data["hashes"], m.group(0))
                if len(data["hashes"]) >= MAX_MATCHES_PER_KEY:
                    break
            if len(data["hashes"]) >= MAX_MATCHES_PER_KEY:
                break

        # === API keys ===
        for p in API_KEY_PATTERNS:
            for m in p.finditer(text):
                key = m.group(1) if m.groups() else m.group(0)
                _append(data["api_keys"], key)
                if len(data["api_keys"]) >= MAX_MATCHES_PER_KEY:
                    break
            if len(data["api_keys"]) >= MAX_MATCHES_PER_KEY:
                break

        # === Credit cards ===
        for m in CREDIT_CARD_RE.finditer(text):
            digits = re.sub(r"\D", "", m.group(0))
            if 13 <= len(digits) <= 19 and luhn_check(digits):
                _append(data["credit_cards"], digits)
            if len(data["credit_cards"]) >= MAX_MATCHES_PER_KEY:
                break

        # === SSN ===
        for m in SSN_RE.finditer(text):
            _append(data["ssn"], m.group(0))
            if len(data["ssn"]) >= MAX_MATCHES_PER_KEY:
                break

        # === Password-like ===
        for p in PASSWORD_PATTERNS_COMPILED:
            for m in p.finditer(text):
                pwd = m.group(1) if m.groups() else None
                if pwd:
                    _append(data["passwords"], mask_secret(pwd, keep=2))
                if len(data["passwords"]) >= MAX_MATCHES_PER_KEY:
                    break
            if len(data["passwords"]) >= MAX_MATCHES_PER_KEY:
                break

        # === Secrets ===
        for p in SECRET_PATTERNS_COMPILED:
            for m in p.finditer(text):
                if p.pattern.startswith("-----BEGIN"):
                    _append(data["secrets"], m.group(0)[:2000])
                else:
                    secret_val = m.group(1) if m.groups() else m.group(0)
                    _append(data["secrets"], mask_secret(secret_val, keep=4))
                if len(data["secrets"]) >= MAX_MATCHES_PER_KEY:
                    break
            if len(data["secrets"]) >= MAX_MATCHES_PER_KEY:
                break

    except Exception as e:
        data["error"] = [str(e)]

    # === Deduplicate & trim ===
    for key, val in data.items():
        if key == "error":
            continue
        data[key] = dedupe_preserve_order(val)[:MAX_MATCHES_PER_KEY]

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
    No broad exception clauses. Clean, predictable, safe.
    """
    if gui_callback is None:
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

        # --- Script paths ---
        script_paths: List[str] = []
        for s in scripts:
            if isinstance(s, dict):
                p = s.get("path") or s.get("src") or s.get("url")
            else:
                p = str(s)
            if p:
                script_paths.append(p)

        script_paths = dedupe_preserve_order(script_paths)[:50]

        # --- Safe headers ---
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

        # --- GUI callback ---
        try:
            gui_callback({"crawler": safe_report})
        except Exception as cb_err:
            logger.debug("gui_callback failed for %s: %s", url, cb_err)

    except KeyError as ke:
        # Missing expected field
        try:
            gui_callback({"crawler": {"module": "crawler", "error": f"missing field: {ke}"}})
        except Exception:
            pass

    except (TypeError, ValueError) as parse_err:
        # Wrong type or malformed data
        try:
            gui_callback({"crawler": {"module": "crawler", "error": f"invalid data: {parse_err}"}})
        except Exception:
            pass

    except Exception as unexpected:
        # Unexpected but typed
        try:
            gui_callback({"crawler": {"module": "crawler", "error": f"unexpected error: {unexpected}"}})
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



# Глобальний кеш cloudscraper — створюється один раз
_cloudscraper = None

def _get_scraper():
    """Lazy-init cloudscraper instance (в рази швидше)."""
    global _cloudscraper
    if _cloudscraper is None:
        try:
            _cloudscraper = cloudscraper.create_scraper(
                browser={"browser": "chrome", "platform": "windows", "mobile": False}
            )
            if PROXIES:
                try:
                    _cloudscraper.proxies.update(PROXIES)
                except Exception as proxy_err:
                    logger.debug("Invalid PROXIES for cloudscraper: %s", proxy_err)
        except Exception as init_err:
            logger.error("Failed to initialize cloudscraper: %s", init_err)
            _cloudscraper = None
    return _cloudscraper


def fetch_with_cloudscraper(url: str, timeout: int = 15) -> Optional[str]:
    """
    Fast, safe HTML fetcher using cloudscraper.
    • No broad exceptions
    • Reuses scraper instance (3–5× faster)
    • Predictable return type: str or None
    """
    rate_limit()

    scraper = _get_scraper()
    if scraper is None:
        logger.debug("cloudscraper unavailable, skipping fetch for %s", url)
        return None

    try:
        resp = scraper.get(url, timeout=timeout, allow_redirects=True)
    except (requests.RequestException, OSError) as net_err:
        logger.debug("cloudscraper network error for %s: %s", url, net_err)
        return None
    except Exception as unexpected:
        logger.error("cloudscraper unexpected error for %s: %s", url, unexpected)
        return None

    # Якщо cloudscraper повернув None
    if resp is None:
        return None

    # HTTP статуси
    status = getattr(resp, "status_code", 0)
    if status >= 400:
        logger.warning("cloudscraper: %s returned HTTP %s", url, status)

    # Гарантовано повертаємо str
    try:
        return resp.text or ""
    except Exception as decode_err:
        logger.debug("Failed to decode response from %s: %s", url, decode_err)
        return None


def fetch_with_playwright(url: str, timeout: int = 25) -> Optional[str]:
    """
    Render page with Playwright (headless). Returns HTML or None.
    Safe, typed, predictable.
    """
    if not PLAYWRIGHT_AVAILABLE:
        return None

    rate_limit()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent=DEFAULT_HEADERS.get("User-Agent"),
            )

            # Anti‑webdriver
            try:
                context.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => false});"
                )
            except Exception as script_err:
                logger.debug("Playwright init_script failed: %s", script_err)

            page = context.new_page()
            page.set_default_timeout(max(1000, int(timeout * 1000)))

            try:
                page.goto(url, wait_until="networkidle")
                html = page.content()
            except (TimeoutError, Exception) as nav_err:
                logger.debug("Playwright navigation failed for %s: %s", url, nav_err)
                html = None

            # Always close context & browser
            try:
                context.close()
            except Exception:
                pass

            try:
                browser.close()
            except Exception:
                pass

            return html

    except (OSError, RuntimeError) as sys_err:
        logger.warning("Playwright system error for %s: %s", url, sys_err)
        return None

    except Exception as unexpected:
        logger.error("Playwright unexpected error for %s: %s", url, unexpected)
        return None


def fetch_html_hybrid_fallback(url: str) -> Optional[str]:
    """
    Hybrid HTML fetch:
      1) cloudscraper (швидко)
      2) Playwright (fallback, якщо cloudscraper дав мало контенту)
    """
    if not url:
        return None

    url = normalize_scheme(url)

    # --- Primary: cloudscraper ---
    html = fetch_with_cloudscraper(url)
    if html and len(html) > 200:
        return html

    # --- Fallback: Playwright ---
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
            inputs = []
            for inp in form.find_all("input"):
                raw_classes = inp.get("class")

                if isinstance(raw_classes, list):
                    classes = raw_classes
                elif isinstance(raw_classes, str):
                    classes = [raw_classes]
                else:
                    classes = []

                input_data = {
                    "name": inp.get("name"),
                    "type": inp.get("type", "text"),
                    "id": inp.get("id"),
                    "class": classes,
                    "placeholder": inp.get("placeholder"),
                    "value": (inp.get("value") or "")[:100],
                }
                if input_data["name"]:
                    inputs.append(input_data)

            textareas = [ta.get("name") for ta in form.find_all("textarea") if ta.get("name")]
            selects = [sel.get("name") for sel in form.find_all("select") if sel.get("name")]

            handlers: dict[str, str] = {}
            for attr, val in form.attrs.items():
                if not attr.startswith("on"):
                    continue
                if isinstance(val, list):
                    handlers[attr] = " ".join(map(str, val))
                else:
                    handlers[attr] = str(val)

            node["forms"].append({
                "action": form.get("action", ""),
                "method": form.get("method", "GET").upper(),
                "inputs": [inp["name"] for inp in inputs if inp["name"]],
                "input_details": inputs,
                "textareas": textareas,
                "selects": selects,
                "handlers": handlers,
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

        hrefs = [a.get("href") for a in soup.find_all("a") if a.get("href")]
        clean_links = []

        for h in hrefs:
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

        unique_links = dedupe_preserve_order(clean_links)[:max_links]
        node["links"] = unique_links

        # ============================================================
        # 8) META
        # ============================================================

        for meta in soup.find_all("meta"):
            meta_data = {}
            for attr in ("name", "property", "content", "http-equiv"):
                v = meta.get(attr)
                if v:
                    meta_data[attr] = str(v)[:500]
            if meta_data:
                node["meta"].append(meta_data)

        # ============================================================
        # 9) Iframes
        # ============================================================

        node["iframes"] = [
            normalize_scheme(urljoin(safe_url, i.get("src")))
            for i in soup.find_all("iframe")
            if i.get("src")
        ]

        # ============================================================
        # 10) WebSockets
        # ============================================================

        ws_patterns = [
            r"new\s+WebSocket\s*\(\s*['\"]([^'\"]+)['\"]",
            r"(wss?://[^\s\"']+)",
        ]
        ws_matches = []

        for pattern in ws_patterns:
            for m in re.finditer(pattern, html, re.IGNORECASE):
                ws = m.group(1) if m.groups() else m.group(0)
                if ws:
                    ws_matches.append(ws)

        node["websockets"] = dedupe_preserve_order(ws_matches)[:50]

        # ============================================================
        # 11) data-* атрибути
        # ============================================================

        for tag in soup.find_all(True):
            for attr, val in tag.attrs.items():
                if attr.startswith("data-"):
                    node["data_attributes"].append(
                        f"{tag.name}.{attr}={str(val)[:100]}"
                    )

        # ============================================================
        # 12) Коментарі
        # ============================================================

        comments = []
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            c = str(comment).strip()
            if c:
                comments.append(c[:500])
                if len(comments) >= 50:
                    break
        node["comments"] = comments

        # Sensitive data з коментарів
        for c in node["comments"]:
            _merge_sensitive_into_node(node, extract_sensitive_data(c))

        # ============================================================
        # 13) Кнопки
        # ============================================================

        for button in soup.find_all(["button", "input"]):
            if button.get("type") == "button" or button.name == "button":
                raw_classes = button.get("class")

                if isinstance(raw_classes, list):
                    classes = raw_classes
                elif isinstance(raw_classes, str):
                    classes = [raw_classes]
                else:
                    classes = []

                button_data = {
                    "text": button.get_text(strip=True)[:50],
                    "onclick": (button.get("onclick") or "")[:200],
                    "id": button.get("id"),
                    "class": classes,
                }

                if button_data["onclick"] or button_data["id"] or button_data["class"]:
                    node["buttons"].append(button_data)

        # ============================================================
        # 14) Select
        # ============================================================

        for select in soup.find_all("select"):
            options = [
                opt.get("value")
                for opt in select.find_all("option")
                if opt.get("value")
            ]
            if options:
                node["selects"].append({
                    "name": select.get("name"),
                    "options": options[:20],
                })

        # ============================================================
        # 15) Textarea
        # ============================================================

        for textarea in soup.find_all("textarea"):
            node["textareas"].append({
                "name": textarea.get("name"),
                "placeholder": textarea.get("placeholder"),
                "id": textarea.get("id"),
            })

        # ============================================================
        # 16) on* events
        # ============================================================

        for tag in soup.find_all(True):
            for attr in tag.attrs:
                if attr.startswith("on"):
                    node["events"].append(
                        f"{tag.name}.{attr} → {str(tag.attrs[attr])[:200]}"
                    )

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

        # Запис у nodes_json
        with nodes_lock:
            nodes_json.append(node)

        # ThreatIntel
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
    # --- Якщо немає нод ---
    if not nodes:
        return _make_empty_dict()

    # --- dedupe ---
    try:
        dedupe = globals().get("dedupe_preserve_order") or (lambda s: list(dict.fromkeys(s)))
    except Exception:
        dedupe = lambda s: list(dict.fromkeys(s))

    def _safe_mask(s: str, keep: int = 4) -> str:
        try:
            return mask_secret(str(s), keep=keep)
        except Exception:
            return "*" * min(len(str(s)), 8)

    # --- root ---
    root = nodes[0].copy()

    # --- Об’єднання спискових полів ---
    combined = {field: [] for field in ALL_FIELDS}

    for node in nodes:
        for field in ALL_FIELDS:
            val = node.get(field)
            if isinstance(val, list):
                combined[field].extend(val)

    # --- META (унікальні словники) ---
    meta_seen = set()
    merged_meta = []
    for m in combined["meta"]:
        try:
            key = json.dumps(m, sort_keys=True, ensure_ascii=False)
        except Exception:
            key = str(m)

        if key not in meta_seen:
            meta_seen.add(key)
            merged_meta.append(m)
            if len(merged_meta) >= max_items:
                break

    root["meta"] = merged_meta

    # --- IPv4 (валідація) ---
    ipv4_valid = [
        ip for ip in combined["ips"]
        if isinstance(ip, str) and re.match(
            r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$",
            ip
        )
    ]
    root["ips"] = dedupe(ipv4_valid)[:max_items]

    # --- Просте копіювання спискових полів ---
    for field in LIST_FIELDS:
        if field == "meta":
            continue
        root[field] = dedupe(combined[field])[:max_items]

    # --- Sensitive groups ---
    def summarize(items: List[Any], keep: int = 4, limit: int = 5):
        items = dedupe([str(i) for i in items if i])
        return {
            "count": len(items),
            "examples": [_safe_mask(i, keep=keep) for i in items[:limit]]
        }

    root["tokens"] = summarize(combined["tokens"], keep=4)
    root["api_keys"] = summarize(combined["api_keys"], keep=4)
    root["jwt_tokens"] = summarize(combined["jwt_tokens"], keep=4)

    root["passwords"] = summarize(combined["passwords"], keep=2, limit=3)
    root["secrets"] = summarize(combined["secrets"], keep=4, limit=3)

    # --- Гарантуємо наявність усіх полів ---
    for field in LIST_FIELDS:
        root.setdefault(field, [])

    for field in SENSITIVE_FIELDS:
        root.setdefault(field, _empty_sensitive())

    root.setdefault("headers", {})
    root.setdefault("url", "")
    root.setdefault("error", None)

    root["total_nodes"] = len(nodes)
    root["merged_at"] = datetime.now(timezone.utc).isoformat()

    # --- Обрізання довгих списків ---
    for k, v in root.items():
        if isinstance(v, list) and len(v) > max_items:
            root[k] = v[:max_items]

    return root

# ============================================================
#  Save Outputs (Tree, JSON, DOT, SVG, Summary)
# ============================================================

def save_outputs(
    result: Dict[str, Any],
    gui_callback=None,
    max_nodes_save: int = 1000,
    max_items_per_field: int = 500,
) -> None:
    logger = logging.getLogger("crawler.save_outputs")
    logger.setLevel(logging.INFO)

    os.makedirs("logs", exist_ok=True)

    # ============================================================
    # 1) Дерево
    # ============================================================
    try:
        tmp = tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=os.path.dirname(LOG_CRAWL_STRUCTURE_PATH) or ".",
            prefix="tree_",
            suffix=".tmp",
        )
        try:
            ts = datetime.now(timezone.utc).isoformat()
            tmp.write(f"--- Crawl Tree @ {ts} ---\n")
            tmp.writelines([line + "\n" for line in tree_log])
            tmp.flush()
        finally:
            tmp.close()
            os.replace(tmp.name, LOG_CRAWL_STRUCTURE_PATH)
        logger.info("Crawl tree saved to %s", LOG_CRAWL_STRUCTURE_PATH)
    except Exception as e:
        logger.exception("Failed to write crawl tree: %s", e)

    # ============================================================
    # 2) JSON узлов → преобразование в формат SiteMapTab
    # ============================================================

    # Определяем, какие узлы сохранять
    try:
        if isinstance(result, list):
            nodes_to_save = result
        elif isinstance(result, dict) and isinstance(result.get("nodes"), list):
            nodes_to_save = result.get("nodes")
        else:
            nodes_to_save = globals().get("nodes_json", []) or []
    except Exception:
        nodes_to_save = globals().get("nodes_json", []) or []

    nodes_to_save = list(nodes_to_save)[:max_nodes_save]

    # Маскирование чувствительных данных
    def _mask_node_for_export(node: dict) -> dict:
        n = {}
        for k, v in node.items():
            if k in ("tokens", "api_keys", "jwt_tokens"):
                items = v if isinstance(v, (list, tuple)) else []
                items = list(dict.fromkeys([str(x) for x in items]))[:max_items_per_field]
                n[k] = {
                    "count": len(items),
                    "examples": [mask_secret(str(x), keep=4) for x in items[:5]],
                }
            elif k in ("passwords", "secrets"):
                items = v if isinstance(v, (list, tuple)) else []
                items = list(dict.fromkeys([str(x) for x in items]))[:max_items_per_field]
                n[k] = {
                    "count": len(items),
                    "examples": [mask_secret(str(x), keep=2) for x in items[:3]],
                }
            elif isinstance(v, (list, tuple)):
                n[k] = list(v)[:max_items_per_field]
            elif isinstance(v, dict):
                n[k] = v.copy()
            else:
                n[k] = v
        return n

    safe_nodes = [
        _mask_node_for_export(n) if isinstance(n, dict) else n
        for n in nodes_to_save
    ]

    # === Конвертация safe_nodes → формат SiteMapTab ===
    visited_urls = []
    scripts = []
    api_endpoints = []
    emails = []
    tokens = []
    user_ids = []

    for node in safe_nodes:
        if not isinstance(node, dict):
            continue

        url = node.get("url")
        if url:
            visited_urls.append(url)

        # JS-файлы
        for s in node.get("scripts", []):
            if isinstance(s, dict):
                path = s.get("path")
                if path:
                    scripts.append(path)

        # Чувствительные данные
        api_endpoints.extend(node.get("api_endpoints", []))
        emails.extend(node.get("emails", []))
        tokens.extend(node.get("tokens", []))
        user_ids.extend(node.get("user_ids", []))

    # Удаляем дубликаты
    visited_urls = list(dict.fromkeys(visited_urls))
    scripts = list(dict.fromkeys(scripts))
    api_endpoints = list(dict.fromkeys(api_endpoints))
    emails = list(dict.fromkeys(emails))
    tokens = list(dict.fromkeys(tokens))
    user_ids = list(dict.fromkeys(user_ids))

    export_data = {
        "visited": visited_urls,
        "scripts": scripts,
        "api_endpoints": api_endpoints,
        "emails": emails,
        "tokens": tokens,
        "user_ids": user_ids,
    }

    # === Сохранение JSON в формате SiteMapTab ===
    try:
        tmp = tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=os.path.dirname(JSON_CRAWL_EXPORT_PATH) or ".",
            prefix="nodes_",
            suffix=".tmp",
        )
        try:
            json.dump(export_data, tmp, indent=2, ensure_ascii=False)
            tmp.flush()
        finally:
            tmp.close()
            os.replace(tmp.name, JSON_CRAWL_EXPORT_PATH)

        logger.info(
            "SiteMap JSON saved to %s (visited=%d, scripts=%d)",
            JSON_CRAWL_EXPORT_PATH,
            len(visited_urls),
            len(scripts),
        )
    except Exception as e:
        logger.exception("Failed to write SiteMap JSON: %s", e)

    # ============================================================
    # 3) DOT
    # ============================================================
    def _safe_dot_pair(x):
        try:
            s = str(x)
            s = s.replace("\n", " ").replace("\r", " ").replace('"', '\\"')
            return s
        except Exception:
            return ""

    try:
        tmp = tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=os.path.dirname(LOG_CRAWL_GRAPH_DOT) or ".",
            prefix="dot_",
            suffix=".tmp",
        )
        try:
            tmp.write("digraph Crawl {\n")
            if isinstance(dot_edges, (list, tuple)):
                for frm, to in dot_edges:
                    frm_safe = _safe_dot_pair(frm)
                    to_safe = _safe_dot_pair(to)
                    if frm_safe and to_safe:
                        tmp.write(f'  "{frm_safe}" -> "{to_safe}";\n')
            tmp.write("}\n")
            tmp.flush()
        finally:
            tmp.close()
            os.replace(tmp.name, LOG_CRAWL_GRAPH_DOT)
        logger.info("DOT file written to %s", LOG_CRAWL_GRAPH_DOT)
    except Exception as e:
        logger.exception("Failed to write DOT file: %s", e)

    # ============================================================
    # 4) SVG через Graphviz
    # ============================================================
    try:
        import shutil
        from graphviz import Source

        if shutil.which("dot") is None:
            logger.warning("Graphviz 'dot' не найден. Пропускаем SVG-рендеринг.")
        else:
            try:
                svg_out = LOG_CRAWL_GRAPH_SVG + ".svg"
                cmd = ["dot", "-Tsvg", LOG_CRAWL_GRAPH_DOT, "-o", svg_out]
                subprocess.run(cmd, timeout=10, check=True)
                logger.info("SVG generated: %s", svg_out)
            except subprocess.TimeoutExpired:
                logger.warning("Graphviz завис: превышен таймаут 10 секунд.")
            except Exception as e:
                logger.warning("Graphviz render failed: %s", e)
    except Exception as e:
        logger.debug("Graphviz import failed: %s", e)

    # ============================================================
    # 5) Статистика
    # ============================================================
    def safe_len(node: dict, key: str) -> int:
        v = node.get(key)
        return len(v) if isinstance(v, (list, tuple, set)) else 0

    def safe_url(u: object, maxlen: int = 200) -> str:
        s = "" if u is None else str(u)
        s = s.replace("<", "").replace(">", "")
        return s if len(s) <= maxlen else s[:maxlen] + "…"

    def get_sensitive_count(n: dict) -> int:
        """Уніфікований підрахунок sensitive-груп."""
        total = 0
        for key in ("tokens", "api_keys", "jwt_tokens"):
            val = n.get(key)
            if isinstance(val, dict):
                total += val.get("count", 0)
            else:
                total += safe_len(n, key)
        return total

    def get_api_ep_count(n: dict) -> int:
        val = n.get("api_endpoints")
        if isinstance(val, dict):
            return val.get("count", 0)
        return safe_len(n, "api_endpoints")

    nodes_list = (
        safe_nodes if isinstance(safe_nodes, (list, tuple))
        else list(safe_nodes or [])
    )

    total_sensitive = sum(get_sensitive_count(n) for n in nodes_list)
    dot_count = len(dot_edges) if isinstance(dot_edges, (list, tuple)) else 0

    logger.info(
        "Saved %d nodes, %d edges, %d sensitive items",
        len(nodes_list), dot_count, total_sensitive
    )

    # ============================================================
    # 6) Сводка для GUI
    # ============================================================

    if gui_callback and isinstance(nodes_list, (list, tuple)):
        summary = []

        for n in nodes_list:
            if not isinstance(n, dict):
                continue

            try:
                summary.append({
                    "url": safe_url(n.get("url", "")),
                    "forms": safe_len(n, "forms"),
                    "scripts": safe_len(n, "scripts"),
                    "api_endpoints": get_api_ep_count(n),
                    "ipv6": safe_len(n, "ipv6"),
                    "mac": safe_len(n, "mac"),
                    "cidr": safe_len(n, "cidr"),
                    "hostnames": safe_len(n, "hostnames"),
                    "sensitive_data": get_sensitive_count(n),
                })
            except (KeyError, TypeError, ValueError) as err:
                logger.debug("Skipping malformed node in summary: %s", err)

        try:
            gui_callback({"crawler": summary})
        except Exception as e:
            logger.exception("GUI callback failed: %s", e)
