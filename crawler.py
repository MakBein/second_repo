# xss_security_gui/crawler.py

import os
import json
import re
import threading
import logging
import tempfile
import subprocess
from urllib.parse import urljoin, urlparse
from hashlib import sha1
from datetime import datetime
from typing import List, Dict, Any, Set, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import cloudscraper
from bs4 import BeautifulSoup, Comment

from xss_security_gui.js_inspector import extract_js_insights
from xss_security_gui.settings import (
    CRAWL_DEPTH_LIMIT,
    CRAWL_DOMAINS_WHITELIST,
    CRAWLER_ERROR_LOG as SETTINGS_CRAWLER_ERROR_LOG,
)

# === Универсальные пути внутри пакета ===
BASE_DIR = os.path.dirname(__file__)
LOGS_DIR = os.path.join(BASE_DIR, "logs")

LOG_CRAWL_STRUCTURE_PATH = os.path.join(LOGS_DIR, "crawl_structure.log")
LOG_CRAWL_GRAPH_DOT = os.path.join(LOGS_DIR, "crawl_graph.dot")
LOG_CRAWL_GRAPH_SVG = os.path.join(LOGS_DIR, "crawl_graph.svg")
JSON_CRAWL_EXPORT_PATH = os.path.join(LOGS_DIR, "crawl_export.json")
CRAWLER_ERROR_LOG = SETTINGS_CRAWLER_ERROR_LOG or os.path.join(LOGS_DIR, "crawler_errors.log")

os.makedirs(LOGS_DIR, exist_ok=True)

# Попробуем Playwright, но не ломаем модуль, если его нет
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger("crawler")
logger.setLevel(logging.INFO)

# Глобальные структуры
visited: Set[str] = set()              # SHA1 хэш URL без query/fragment
tree_log: List[str] = []               # человекочитаемое дерево обхода
dot_edges: List[Tuple[str, str]] = []  # рёбра графа (from → to)
nodes_json: List[Dict[str, Any]] = []  # описание узлов
js_cache: Dict[str, Dict] = {}         # кэш JS: url → insights

visited_lock = threading.Lock()
nodes_lock = threading.Lock()
dot_lock = threading.Lock()

# Агрессивные настройки
MAX_LINKS_PER_PAGE = 500
MAX_SCRIPTS_PER_PAGE = 200
MAX_CONCURRENT_REQUESTS = 20
AGGRESSIVE_HEADERS = True

# Ограничения для извлечения чувствительных данных
MAX_MATCHES_PER_KEY = 200
MAX_API_ENDPOINTS = 200

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
    DEFAULT_HEADERS.update(
        {
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
        }
    )


# === УТИЛИТЫ ===

def dedupe_preserve_order(seq):
    seen = set()
    out = []
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


def _normalize_candidate(cand: str, base_url: str) -> str:
    cand = cand.strip().strip("'\"")
    if not cand:
        return ""
    if cand.startswith("http://") or cand.startswith("https://"):
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


# === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===

def hash_url_no_query(u: str) -> str:
    parsed = urlparse(u)._replace(query="", fragment="")
    return sha1(parsed.geturl().encode()).hexdigest()


def normalize_scheme(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        return "https://" + url.lstrip("/")
    return url


def is_same_domain(url: str, base_netloc: str) -> bool:
    parsed = urlparse(url)
    if not parsed.netloc:
        return False
    if CRAWL_DOMAINS_WHITELIST:
        if not any(whitelisted in parsed.netloc for whitelisted in CRAWL_DOMAINS_WHITELIST):
            return False
    return parsed.netloc == base_netloc or parsed.netloc.endswith("." + base_netloc)


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
    if aggressive:
        s.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36 XSSSecurityCrawler/2.0"
                ),
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,image/apng,*/*;q=0.8"
                ),
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
            }
        )
    else:
        s.headers.update(
            {
                "User-Agent": "XSSSecurityCrawler/2.0 (+https://localhost)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )
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


# === ПРЕКОМПИЛИРОВАННЫЕ ПАТТЕРНЫ ===

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
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)/(?:[0-9]|[12][0-9]|3[0-2])\b"
    r"|\b[0-9A-Fa-f:]+/[0-9]{1,3}\b"
)
HOSTNAME_RE = re.compile(
    r"\b(?=.{1,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b"
)
PARAM_RE = re.compile(r"\b([a-zA-Z0-9_]+=[a-zA-Z0-9_\-\.]+)\b")
BASE64_RE = re.compile(
    r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
)
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)
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
    r"\b(?:(4[0-9]{12}(?:[0-9]{3})?)|(5[1-5][0-9]{14})|(3[47][0-9]{13})|(6(?:011|5[0-9]{2})[0-9]{12})|(35[0-9]{14})|(62[0-9]{14,17}))\b"
)


# === Извлечение чувствительных данных ===

def extract_sensitive_data(text: str) -> Dict[str, List[str]]:
    """
    Агрессивное извлечение чувствительных данных из текста.
    Возвращает словарь со списками; результаты дедуплицируются и ограничиваются.
    """
    data = {
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

    try:
        # EMAIL
        data["emails"].extend(m.group(0) for m in EMAIL_RE.finditer(text))

        # PHONES
        for p in PHONE_RE_LIST:
            for m in p.finditer(text):
                data["phones"].append(m.group(0))
                if len(data["phones"]) >= MAX_MATCHES_PER_KEY:
                    break
            if len(data["phones"]) >= MAX_MATCHES_PER_KEY:
                break

        # TOKENS
        for p in TOKEN_PATTERNS_COMPILED:
            for m in p.finditer(text):
                token = m.group(1) if m.groups() else m.group(0)
                data["tokens"].append(token)
                if len(data["tokens"]) >= MAX_MATCHES_PER_KEY:
                    break
            if len(data["tokens"]) >= MAX_MATCHES_PER_KEY:
                break

        # JWT
        for m in JWT_RE.finditer(text):
            data["jwt_tokens"].append(m.group(0))
            if len(data["jwt_tokens"]) >= MAX_MATCHES_PER_KEY:
                break

        # IPv4
        for m in IPV4_RE.finditer(text):
            ip = m.group(0)
            data["ipv4"].append(ip)
            data["ips"].append(ip)
            if len(data["ipv4"]) >= MAX_MATCHES_PER_KEY:
                break

        # IPv6
        for m in IPV6_RE.finditer(text):
            ip6 = m.group(0)
            data["ipv6"].append(ip6)
            data["ips"].append(ip6)
            if len(data["ipv6"]) >= MAX_MATCHES_PER_KEY:
                break

        # MAC
        for m in MAC_RE.finditer(text):
            data["mac"].append(m.group(0))
            if len(data["mac"]) >= MAX_MATCHES_PER_KEY:
                break

        # CIDR
        for m in CIDR_RE.finditer(text):
            data["cidr"].append(m.group(0))
            if len(data["cidr"]) >= MAX_MATCHES_PER_KEY:
                break

        # HOSTNAMES
        for m in HOSTNAME_RE.finditer(text):
            data["hostnames"].append(m.group(0))
            if len(data["hostnames"]) >= MAX_MATCHES_PER_KEY:
                break

        # PARAMETERS
        for m in PARAM_RE.finditer(text):
            data["parameters"].append(m.group(1))
            if len(data["parameters"]) >= MAX_MATCHES_PER_KEY:
                break

        # BASE64
        for m in BASE64_RE.finditer(text):
            data["base64_strings"].append(m.group(0))
            if len(data["base64_strings"]) >= MAX_MATCHES_PER_KEY:
                break

        # UUID
        for m in UUID_RE.finditer(text):
            data["uuids"].append(m.group(0))
            if len(data["uuids"]) >= MAX_MATCHES_PER_KEY:
                break

        # HASHES
        for p in HASH_PATTERNS:
            for m in p.finditer(text):
                data["hashes"].append(m.group(0))
                if len(data["hashes"]) >= MAX_MATCHES_PER_KEY:
                    break
            if len(data["hashes"]) >= MAX_MATCHES_PER_KEY:
                break

        # API KEYS
        for p in API_KEY_PATTERNS:
            for m in p.finditer(text):
                key = m.group(1) if m.groups() else m.group(0)
                data["api_keys"].append(key)
                if len(data["api_keys"]) >= MAX_MATCHES_PER_KEY:
                    break
            if len(data["api_keys"]) >= MAX_MATCHES_PER_KEY:
                break

        # CREDIT CARDS
        raw_cards = []
        for m in CREDIT_CARD_RE.finditer(text):
            raw_cards.append(m.group(0))
            if len(raw_cards) >= MAX_MATCHES_PER_KEY:
                break

        valid_cards = []
        for card in raw_cards:
            digits = re.sub(r"\D", "", card)
            if 13 <= len(digits) <= 19 and luhn_check(digits):
                valid_cards.append(digits)

        data["credit_cards"].extend(valid_cards)

        # SSN
        for m in SSN_RE.finditer(text):
            data["ssn"].append(m.group(0))
            if len(data["ssn"]) >= MAX_MATCHES_PER_KEY:
                break

        # PASSWORDS (masked)
        for p in PASSWORD_PATTERNS_COMPILED:
            for m in p.finditer(text):
                pwd = m.group(1)
                if pwd:
                    data["passwords"].append(mask_secret(pwd, keep=2))
                if len(data["passwords"]) >= MAX_MATCHES_PER_KEY:
                    break
            if len(data["passwords"]) >= MAX_MATCHES_PER_KEY:
                break

        # SECRETS
        for p in SECRET_PATTERNS_COMPILED:
            for m in p.finditer(text):
                if p.pattern.startswith("-----BEGIN"):
                    data["secrets"].append(m.group(0))
                else:
                    secret_val = m.group(1) if m.groups() else m.group(0)
                    data["secrets"].append(mask_secret(secret_val, keep=4))
                if len(data["secrets"]) >= MAX_MATCHES_PER_KEY:
                    break
            if len(data["secrets"]) >= MAX_MATCHES_PER_KEY:
                break

    except Exception:
        pass

    for key in data:
        if isinstance(data[key], list):
            data[key] = list(dict.fromkeys(data[key]))[:MAX_MATCHES_PER_KEY]

    return data


# === Извлечение API endpoints ===

def extract_api_endpoints_from_text(text: str, base_url: str) -> List[str]:
    """
    ULTRA 6.x API Endpoint Extractor
    --------------------------------
    • Распознаёт API-вызовы всех HTTP-методов:
      GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT
    • Поддерживает fetch/axios/XHR
    • Поддерживает относительные и абсолютные пути
    • Поддерживает REST/v1/v2/graphql
    • Дедупликация + нормализация
    """
    if not text:
        return []

    http_methods = r"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)"

    api_patterns = [
        re.compile(rf"fetch\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
        re.compile(rf"axios\.(?:{http_methods})\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
        re.compile(r"url\s*:\s*['\"]([^'\"]+)['\"]", re.I),
        re.compile(rf"open\s*\(\s*['\"]{http_methods}['\"]\s*,\s*['\"]([^'\"]+)['\"]", re.I),
        re.compile(rf"method\s*:\s*['\"]{http_methods}['\"].*?url\s*:\s*['\"]([^'\"]+)['\"]", re.I),
        re.compile(r"['\"](/(?:api/|v\d+/|rest/|graphql)[^'\"]+)['\"]", re.I),
        re.compile(r"['\"](https?://[^'\"]+(?:/api/|/v\d+/|/rest/)[^'\"]+)['\"]", re.I),
        re.compile(rf"{http_methods}\s+(/[^ \n]+)", re.I),
        re.compile(rf"{http_methods}\s+(https?://[^ \n]+)", re.I),
    ]

    candidates: List[str] = []

    for pat in api_patterns:
        try:
            for m in pat.finditer(text):
                if m.groups():
                    cand = m.group(m.lastindex)
                else:
                    cand = m.group(0)

                if not cand:
                    continue

                norm = _normalize_candidate(cand, base_url)
                if norm and _is_http_url(norm):
                    candidates.append(norm)

                if len(candidates) >= MAX_API_ENDPOINTS:
                    break
        except Exception as e:
            logger.warning("[APIExtractor] Ошибка в паттерне %s: %s", pat, e)

    return dedupe_preserve_order(candidates)[:MAX_API_ENDPOINTS]


# === Threat Intel report ===

def report_threatintel(node: dict, gui_callback=None):
    """Безопасная передача метаданных узла в Threat Intel"""
    if not gui_callback:
        return

    try:
        url = node.get("url", "")
        forms = node.get("forms") or []
        scripts = node.get("scripts") or []
        headers = node.get("headers") or {}
        api_endpoints = node.get("api_endpoints") or []
        links = node.get("links") or []
        meta = node.get("meta") or {}
        events = node.get("events") or []
        error = node.get("error", None)

        script_paths = []
        for s in scripts:
            if isinstance(s, dict):
                p = s.get("path") or s.get("src") or s.get("url") or ""
            else:
                p = str(s)
            if p:
                script_paths.append(p)
        script_paths = dedupe_preserve_order(script_paths)[:50]

        safe_headers = {}
        for k, v in headers.items():
            try:
                vs = str(v)
                safe_headers[str(k)] = vs if len(vs) <= 200 else vs[:100] + "…"
            except Exception:
                safe_headers[str(k)] = ""

        page_class = node.get("page_class", "other")
        page_class_score = node.get("page_class_score", 0.0)

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
            pass

    except Exception:
        try:
            gui_callback({"crawler": {"module": "crawler", "error": "failed to build safe report"}})
        except Exception:
            pass


# --- Hybrid fetch: requests → cloudscraper → Playwright ---

def fetch_with_requests_raw(
    url: str, timeout: int = 10, session: Optional[requests.Session] = None
) -> Optional[requests.Response]:
    try:
        sess = session or requests.Session()
        resp = sess.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        return resp
    except Exception as e:
        logger.warning("requests failed for %s: %s", url, e)
        return None


def fetch_with_cloudscraper(url: str, timeout: int = 15) -> Optional[str]:
    try:
        scraper = cloudscraper.create_scraper(
            browser={"browser": "chrome", "platform": "windows", "mobile": False}
        )
        resp = scraper.get(url, timeout=timeout, allow_redirects=True)
        if resp.status_code >= 400:
            logger.warning("cloudscraper: %s returned HTTP %s", url, resp.status_code)
        return resp.text or ""
    except Exception as e:
        logger.warning("cloudscraper failed for %s: %s", url, e)
        return None


def fetch_with_playwright(url: str, timeout: int = 25) -> Optional[str]:
    if not PLAYWRIGHT_AVAILABLE:
        return None

    try:
        def _inner() -> Optional[str]:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    viewport={"width": 1920, "height": 1080},
                    user_agent=DEFAULT_HEADERS["User-Agent"],
                )
                context.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => false});"
                )

                page = context.new_page()
                page.set_default_timeout(timeout * 1000)

                page.goto(url, wait_until="networkidle")
                html = page.content()

                context.close()
                browser.close()
                return html

        return _inner()
    except Exception as e:
        logger.warning("Playwright failed for %s: %s", url, e)
        return None


def fetch_html_hybrid_fallback(url: str) -> Optional[str]:
    url = normalize_scheme(url)

    html = fetch_with_cloudscraper(url)
    if html and len(html.strip()) > 200:
        return html

    html = fetch_with_playwright(url)
    return html

# === SUPER-CRAWLER ===

def crawl_site(
    url: str,
    depth: int = 0,
    session: requests.Session | None = None,
    gui_callback=None,
    max_links: int = MAX_LINKS_PER_PAGE,
    max_scripts: int = MAX_SCRIPTS_PER_PAGE,
    aggressive: bool = AGGRESSIVE_HEADERS,
    parallel: bool = True,
):
    """
    Единый супер-краулер:
      - основа: requests Session
      - fallback: cloudscraper / Playwright для сложных/JS страниц
      - расширенный парсинг HTML/JS + чувствительные данные
      - ThreatIntel репорты
      - дерево, DOT, параллельный обход
    """
    global visited, tree_log, dot_edges, nodes_json, js_cache
    global visited_lock, nodes_lock, dot_lock

    # Инициализация глобальных локов
    if "visited_lock" not in globals():
        visited_lock = threading.Lock()
        nodes_lock = threading.Lock()
        dot_lock = threading.Lock()

    # Сброс глобальных структур при корневом вызове
    if depth == 0:
        with visited_lock:
            visited.clear()
        with nodes_lock:
            nodes_json.clear()
            tree_log.clear()
            dot_edges.clear()
            js_cache.clear()

    if session is None:
        session = make_session(aggressive=aggressive)

    if depth > CRAWL_DEPTH_LIMIT:
        return {"url": url, "error": "Depth limit exceeded"}

    safe_url = normalize_scheme(url)
    parsed = urlparse(safe_url)
    parsed_domain = parsed.netloc

    if CRAWL_DOMAINS_WHITELIST and not any(
        domain in parsed_domain for domain in CRAWL_DOMAINS_WHITELIST
    ):
        return {"url": safe_url, "error": "Domain not whitelisted"}

    url_id = hash_url_no_query(safe_url)
    with visited_lock:
        if url_id in visited:
            return {"url": safe_url, "error": "Already visited"}
        visited.add(url_id)

    node = {
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
        # 1) основной запрос через session
        r = fetch_with_requests_raw(safe_url, timeout=10, session=session)

        if r is None:
            # 2) fallback – только HTML (Cloudflare/JS), без заголовков/куков
            html = fetch_html_hybrid_fallback(safe_url) or ""
            content_type = "text/html"
            headers = {}
            cookies_obj = None
        else:
            content_type = r.headers.get("Content-Type", "")
            headers = r.headers
            cookies_obj = r.cookies
            if (
                "text/html" in content_type
                or "application/json" in content_type
                or safe_url.endswith(".json")
            ):
                html = r.text or ""
            else:
                html = r.text or ""

        # Заголовки (без полного Set-Cookie)
        node["headers"] = {
            "CSP": headers.get("Content-Security-Policy", "-") if headers else "-",
            "X-XSS-Protection": headers.get("X-XSS-Protection", "-") if headers else "-",
            "Referrer-Policy": headers.get("Referrer-Policy", "-") if headers else "-",
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "-") if headers else "-",
            "X-Frame-Options": headers.get("X-Frame-Options", "-") if headers else "-",
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "-") if headers else "-",
            "Server": headers.get("Server", "-") if headers else "-",
            "X-Powered-By": headers.get("X-Powered-By", "-") if headers else "-",
        }

        # Cookies
        if cookies_obj:
            node["cookies"] = [
                {"name": c.name, "value": (c.value or "")[:100], "domain": c.domain}
                for c in cookies_obj
            ]

        # JSON endpoint
        if ("application/json" in content_type or safe_url.endswith(".json")) and r is not None:
            try:
                json_data = r.json()
                node["api_endpoints"].append(safe_url)
                json_text = json.dumps(json_data)
                sensitive = extract_sensitive_data(json_text)
                for key, value in sensitive.items():
                    if key in node and value:
                        node[key].extend(value)
            except Exception as e:
                node["error"] = f"json_parse_error: {e}"

            node["api_endpoints"] = dedupe_preserve_order(node["api_endpoints"])[:MAX_API_ENDPOINTS]

            for k in node:
                if isinstance(node[k], list):
                    node[k] = dedupe_preserve_order(node[k])[:MAX_MATCHES_PER_KEY]

            with nodes_lock:
                nodes_json.append(node)
                tree_log.append("  " * depth + f"📄 {safe_url}")

            report_threatintel(node, gui_callback)
            return node

        # HTML разбор
        soup = BeautifulSoup(html or "", "html.parser")

        # META
        for m in soup.find_all("meta"):
            node["meta"].append(str(m)[:500])

        # FORMS
        for form in soup.find_all("form"):
            form_desc = {
                "action": _normalize_candidate(form.get("action", ""), safe_url),
                "method": (form.get("method") or "GET").upper(),
                "inputs": [],
            }
            for inp in form.find_all(["input", "textarea", "select"]):
                form_desc["inputs"].append({
                    "name": inp.get("name"),
                    "type": inp.get("type"),
                })
            node["forms"].append(form_desc)

        # BUTTONS / SELECTS / TEXTAREAS
        node["buttons"] = [btn.get("name") or btn.get("id") or "" for btn in soup.find_all("button")]
        node["selects"] = [sel.get("name") or sel.get("id") or "" for sel in soup.find_all("select")]
        node["textareas"] = [ta.get("name") or ta.get("id") or "" for ta in soup.find_all("textarea")]

        # LINKS
        links: List[str] = []
        for a in soup.find_all("a", href=True):
            href = a.get("href", "").strip()
            if not is_real_link(href):
                continue
            full = _normalize_candidate(href, safe_url)
            if not _is_http_url(full):
                continue
            if not is_same_domain(full, parsed_domain):
                continue
            links.append(full)

        links = dedupe_preserve_order(links)[:max_links]
        node["links"] = links

        # IFRAMES
        for iframe in soup.find_all("iframe", src=True):
            src = _normalize_candidate(iframe.get("src", ""), safe_url)
            if _is_http_url(src):
                node["iframes"].append(src)

        # COMMENTS
        for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
            node["comments"].append(str(c)[:500])

        # SCRIPTS
        scripts_info = []
        script_tags = soup.find_all("script")[:max_scripts]
        for s_tag in script_tags:
            src = s_tag.get("src")
            if src:
                full_src = _normalize_candidate(src, safe_url)
                scripts_info.append({"src": full_src, "inline": False})
            else:
                code = s_tag.string or ""
                scripts_info.append({"src": None, "inline": True, "code": code[:2000]})
        node["scripts"] = scripts_info

        # JS-инсайты (если есть кэш)
        try:
            js_insights = extract_js_insights(safe_url, html, scripts_info, js_cache)
            for key, value in js_insights.items():
                if key in node and isinstance(value, list):
                    node[key].extend(value)
        except Exception:
            pass

        # Чувствительные данные из HTML
        try:
            sensitive = extract_sensitive_data(html)
            for key, value in sensitive.items():
                if key in node and value:
                    node[key].extend(value)
        except Exception:
            pass

            # Ограничения и дедупликация
        for k in node:
            if isinstance(node[k], list):
                node[k] = dedupe_preserve_order(node[k])[:MAX_MATCHES_PER_KEY]

        with nodes_lock:
            nodes_json.append(node)
            tree_log.append("  " * depth + f"📄 {safe_url}")

        report_threatintel(node, gui_callback)

        # Параллельный обход дочерних ссылок
        child_results = []
        if depth < CRAWL_DEPTH_LIMIT and links:
            if parallel:

                def _crawl_child(child_url: str):
                    try:
                        return crawl_site(
                            child_url,
                            depth=depth + 1,
                            session=session,
                            gui_callback=gui_callback,
                            max_links=max_links,
                            max_scripts=max_scripts,
                            aggressive=aggressive,
                            parallel=False,  # не плодим вложенные пулы
                        )
                    except Exception:
                        return None

                with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_REQUESTS) as executor:
                    futures = {executor.submit(_crawl_child, u): u for u in links}
                    for fut in as_completed(futures):
                        res = fut.result()
                        if isinstance(res, dict):
                            child_results.append(res)
            else:
                for child_url in links:
                    try:
                        res = crawl_site(
                            child_url,
                            depth=depth + 1,
                            session=session,
                            gui_callback=gui_callback,
                            max_links=max_links,
                            max_scripts=max_scripts,
                            aggressive=aggressive,
                            parallel=False,
                        )
                        if isinstance(res, dict):
                            child_results.append(res)
                    except Exception:
                        continue

        # Если это корневой вызов — возвращаем сводку по всем узлам
        if depth == 0:
            with nodes_lock:
                all_nodes = list(nodes_json)
            pages = [n.get("url") for n in all_nodes if isinstance(n, dict)]
            return all_nodes, pages

        return node

    except Exception as e:
        node["error"] = f"{type(e).__name__}: {e}"
        with nodes_lock:
            nodes_json.append(node)
            tree_log.append("  " * depth + f"❌ {safe_url} ({e})")
        report_threatintel(node, gui_callback)
        return node


def build_final_dict(nodes: List[Dict[str, Any]], max_items: int = 500) -> Dict[str, Any]:
    try:
        dedupe = globals().get("dedupe_preserve_order", None) or (lambda s: list(dict.fromkeys(s)))
    except Exception:
        dedupe = lambda s: list(dict.fromkeys(s))

    def _mask(s: str, keep: int = 4) -> str:
        mask_fn = globals().get("mask_secret", None)
        if callable(mask_fn):
            try:
                return mask_fn(s, keep=keep)
            except Exception:
                pass
        s = str(s)
        if len(s) <= keep * 2:
            return "*" * len(s)
        return s[:keep] + "*" * (len(s) - keep * 2) + s[-keep:]

    if not nodes:
        empty = {
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
            "merged_at": datetime.utcnow().isoformat(),
        }
        return empty

    root = nodes[0].copy()

    merge_list_fields = [
        "forms", "scripts", "links", "meta", "iframes", "events",
        "api_endpoints", "emails", "phones", "tokens", "ips",
        "ipv6", "mac", "cidr", "hostnames", "comments",
        "parameters", "base64_strings", "uuids", "hashes",
        "api_keys", "jwt_tokens", "credit_cards", "ssn",
        "passwords", "secrets", "cookies", "websockets",
        "data_attributes", "buttons", "selects", "textareas",
    ]

    combined_map: Dict[str, List[Any]] = {f: [] for f in merge_list_fields}
    for node in nodes:
        for field in merge_list_fields:
            val = node.get(field, [])
            if isinstance(val, list):
                combined_map[field].extend(val)

    metas = combined_map.get("meta", [])
    meta_seen = set()
    merged_meta = []
    for m in metas:
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

    ips = [
        ip
        for ip in combined_map.get("ips", [])
        if isinstance(ip, str)
        and re.match(
            r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$",
            ip,
        )
    ]
    root["ips"] = dedupe(ips)[:max_items]

    simple_fields = [
        "forms", "scripts", "links", "iframes", "events", "api_endpoints",
        "emails", "phones", "ipv6", "mac", "cidr", "hostnames",
        "comments", "parameters", "base64_strings", "uuids", "hashes",
        "credit_cards", "ssn", "cookies", "websockets", "data_attributes",
        "buttons", "selects", "textareas",
    ]
    for f in simple_fields:
        vals = combined_map.get(f, [])
        root[f] = dedupe(vals)[:max_items]

    def _summarize_sensitive(items: List[Any], example_limit: int = 5):
        items = [str(i) for i in items if i]
        items = dedupe(items)
        count = len(items)
        examples = [_mask(it) for it in items[:example_limit]]
        return {"count": count, "examples": examples}

    root["tokens"] = _summarize_sensitive(combined_map.get("tokens", []))
    root["api_keys"] = _summarize_sensitive(combined_map.get("api_keys", []))
    root["jwt_tokens"] = _summarize_sensitive(combined_map.get("jwt_tokens", []))

    root["passwords"] = {
        "count": len(dedupe(combined_map.get("passwords", []))),
        "examples": [_mask(x, keep=2) for x in dedupe(combined_map.get("passwords", []))[:3]],
    }
    root["secrets"] = {
        "count": len(dedupe(combined_map.get("secrets", []))),
        "examples": [_mask(x, keep=4) for x in dedupe(combined_map.get("secrets", []))[:3]],
    }

    expected_list_fields = [
        "forms", "scripts", "links", "meta", "iframes", "events",
        "api_endpoints", "emails", "phones", "tokens", "ips",
        "ipv6", "mac", "cidr", "hostnames", "parameters",
        "base64_strings", "uuids", "hashes", "api_keys", "jwt_tokens",
        "credit_cards", "ssn", "passwords", "secrets", "cookies",
        "websockets", "data_attributes", "comments", "buttons",
        "selects", "textareas",
    ]
    for field in expected_list_fields:
        if field in ("tokens", "api_keys", "jwt_tokens", "passwords", "secrets"):
            root.setdefault(field, {"count": 0, "examples": []})
        else:
            root.setdefault(field, [])

    root.setdefault("headers", root.get("headers", {}))
    root.setdefault("url", root.get("url", ""))
    root.setdefault("error", None)

    root["total_nodes"] = len(nodes)
    root["merged_at"] = datetime.utcnow().isoformat()

    for k, v in list(root.items()):
        if isinstance(v, list) and len(v) > max_items:
            root[k] = v[:max_items]

    return root


def save_outputs(result: Dict[str, Any], gui_callback=None, max_nodes_save: int = 1000, max_items_per_field: int = 500) -> None:
    logger = logging.getLogger("crawler.save_outputs")
    logger.setLevel(logging.INFO)

    os.makedirs("logs", exist_ok=True)

    # 1) дерево
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
            tmp.write(f"--- Crawl Tree @ {datetime.now().isoformat()} ---\n")
            tmp.writelines([line + "\n" for line in tree_log])
            tmp.flush()
        finally:
            tmp.close()
            os.replace(tmp.name, LOG_CRAWL_STRUCTURE_PATH)
        logger.info("Crawl tree saved to %s", LOG_CRAWL_STRUCTURE_PATH)
    except Exception as e:
        logger.exception("Failed to write crawl tree: %s", e)

    # 2) JSON узлов
    safe_nodes = []

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

    try:
        safe_nodes = [_mask_node_for_export(n) if isinstance(n, dict) else n for n in nodes_to_save]
        tmp = tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=os.path.dirname(JSON_CRAWL_EXPORT_PATH) or ".",
            prefix="nodes_",
            suffix=".tmp",
        )
        try:
            json.dump(safe_nodes, tmp, indent=2, ensure_ascii=False)
            tmp.flush()
        finally:
            tmp.close()
            os.replace(tmp.name, JSON_CRAWL_EXPORT_PATH)
        logger.info("Nodes JSON saved to %s (%d nodes)", JSON_CRAWL_EXPORT_PATH, len(safe_nodes))
    except Exception as e:
        logger.exception("Failed to write nodes JSON: %s", e)

    # 3) DOT
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
                for pair in dot_edges:
                    try:
                        frm, to = pair
                        frm_safe = _safe_dot_pair(frm)
                        to_safe = _safe_dot_pair(to)
                        if frm_safe and to_safe:
                            tmp.write(f'  "{frm_safe}" -> "{to_safe}";\n')
                    except Exception:
                        continue
            tmp.write("}\n")
            tmp.flush()
        finally:
            tmp.close()
            os.replace(tmp.name, LOG_CRAWL_GRAPH_DOT)
        logger.info("DOT file written to %s", LOG_CRAWL_GRAPH_DOT)
    except Exception as e:
        logger.exception("Failed to write DOT file: %s", e)

    # 4) SVG через Graphviz
    try:
        import shutil
        from graphviz import Source  # для совместимости

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

    # 5) статистика
    def safe_len(node: dict, key: str) -> int:
        try:
            v = node.get(key, [])
        except Exception:
            return 0
        return len(v) if isinstance(v, (list, tuple, set)) else 0

    def safe_url(u: object, maxlen: int = 200) -> str:
        s = str(u) if u is not None else ""
        s = s.replace("<", "").replace(">", "")
        return s if len(s) <= maxlen else s[:maxlen] + "…"

    nodes_list = safe_nodes if isinstance(safe_nodes, (list, tuple)) else list(safe_nodes or [])
    total_sensitive = sum(
        (n.get("tokens", {}).get("count", 0) if isinstance(n.get("tokens"), dict) else safe_len(n, "tokens"))
        + (n.get("api_keys", {}).get("count", 0) if isinstance(n.get("api_keys"), dict) else safe_len(n, "api_keys"))
        + (n.get("jwt_tokens", {}).get("count", 0) if isinstance(n.get("jwt_tokens"), dict) else safe_len(n, "jwt_tokens"))
        for n in nodes_list
    )
    dot_count = len(dot_edges) if isinstance(dot_edges, (list, tuple)) else 0

    logger.info("Saved %d nodes, %d edges, %d sensitive items", len(nodes_list), dot_count, total_sensitive)

    # 6) сводка для GUI
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
                    "api_endpoints": (
                        n.get("api_endpoints", []) and (
                            n.get("api_endpoints").get("count")
                            if isinstance(n.get("api_endpoints"), dict)
                            else safe_len(n, "api_endpoints")
                        )
                    ),
                    "ipv6": safe_len(n, "ipv6"),
                    "mac": safe_len(n, "mac"),
                    "cidr": safe_len(n, "cidr"),
                    "hostnames": safe_len(n, "hostnames"),
                    "sensitive_data": (
                        (n.get("tokens", {}).get("count", 0) if isinstance(n.get("tokens"), dict) else safe_len(n, "tokens"))
                        + (n.get("api_keys", {}).get("count", 0) if isinstance(n.get("api_keys"), dict) else safe_len(n, "api_keys"))
                    ),
                })
            except Exception:
                continue
        try:
            gui_callback({"crawler": summary})
        except Exception as e:
            logger.exception("GUI callback failed: %s", e)