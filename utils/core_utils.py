# xss_security_gui/utils/core_utils.py
# ============================================================
# CoreUtils 9.0 — safe, strict, canonical, threat‑aware
# ============================================================

from datetime import datetime, timezone
import traceback
import os
import urllib.parse
from hashlib import sha1, sha256, md5


# ============================================================
# URL Engine 9.0
# ============================================================

def normalize_url(url: str) -> str:
    """Приводить URL к безопасному каноническому виду."""
    if not isinstance(url, str):
        return ""

    url = url.strip()
    if not url:
        return ""

    # Пробуем распарсить
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return ""

    # Добавляем схему, если отсутствует
    if not parsed.scheme:
        url = "https://" + url
        parsed = urllib.parse.urlparse(url)

    # Убираем пробелы и мусор
    url = parsed.geturl().strip()

    return url


def canonical_url(url: str) -> str:
    """Возвращает канонический URL без query/fragment."""
    try:
        parsed = urllib.parse.urlparse(url)
        parsed = parsed._replace(query="", fragment="")
        return parsed.geturl()
    except Exception:
        return url


def hash_url(url: str, algo: str = "sha1") -> str:
    """Хеширует канонизированный URL."""
    try:
        canonical = canonical_url(url).encode()
    except Exception:
        canonical = str(url).encode()

    if algo == "sha256":
        return sha256(canonical).hexdigest()
    elif algo == "md5":
        return md5(canonical).hexdigest()
    return sha1(canonical).hexdigest()


def url_fingerprint(url: str, keep_query_keys=None, algo: str = "sha1") -> str:
    """Создаёт хеш URL с сохранением ключевых query-параметров."""
    try:
        parsed = urllib.parse.urlparse(url)
        query = parsed.query

        if keep_query_keys:
            query_dict = urllib.parse.parse_qs(query)
            filtered = {k: query_dict[k] for k in keep_query_keys if k in query_dict}
            query_str = urllib.parse.urlencode(filtered, doseq=True)
        else:
            query_str = ""

        canonical = parsed._replace(query=query_str, fragment="")
        return hash_url(canonical.geturl(), algo=algo)
    except Exception:
        return hash_url(url, algo=algo)


def is_valid_url(url: str) -> bool:
    """Проверяет корректность http/https URL."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


# ============================================================
# Crawl Engine 9.0
# ============================================================

def safe_crawl_site(domain: str, retries: int = 3, timeout: int = 5):
    """
    Безопасный краулер с retry и логированием.
    Никогда не валит GUI.
    """
    import requests
    from time import sleep

    domain = normalize_url(domain)
    domain_hash = hash_url(domain)

    for attempt in range(retries):
        try:
            if not is_valid_url(domain):
                raise ValueError(f"Invalid URL: {domain}")

            response = requests.get(domain, timeout=timeout)

            if response.ok:
                return {"status": "success", "content": response.text}

            return {
                "status": "error",
                "code": response.status_code,
                "reason": response.reason,
            }

        except Exception as e:
            log_error(domain_hash, e)
            sleep(1)

    return {
        "status": "failure",
        "reason": "Max retries exceeded",
        "target": domain,
    }


# ============================================================
# Logging Engine 9.0
# ============================================================

def log_xss_flood(url: str, status: str):
    """Логирует XSS flood-атаки."""
    try:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        os.makedirs("logs", exist_ok=True)
        with open("logs/xss_flood_log.txt", "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] [{status}] {url}\n")
    except Exception:
        pass


def log_error(domain: str, error: Exception):
    """Лог ошибок — никогда не падает."""
    try:
        os.makedirs("xss_security_gui", exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        path = "xss_security_gui/error_log.txt"

        with open(path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] 🌐 {domain} — {type(error).__name__}: {str(error)}\n")
            f.write(traceback.format_exc() + "\n")
    except Exception:
        pass


# ============================================================
# Data Analysis Engine 9.0
# ============================================================

def contains_sensitive(data, keys) -> bool:
    """Проверяет наличие чувствительных ключей в любой структуре."""
    try:
        keys = {k.lower() for k in keys}

        if isinstance(data, dict):
            for k, v in data.items():
                if k.lower() in keys:
                    return True
                if contains_sensitive(v, keys):
                    return True

        elif isinstance(data, list):
            for item in data:
                if contains_sensitive(item, keys):
                    return True

        return False
    except Exception:
        return False


def flatten_dict(d: dict, parent_key: str = "", sep: str = ".") -> dict:
    """Разворачивает вложенные словари в плоский вид."""
    items = {}
    try:
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.update(flatten_dict(v, new_key, sep=sep))
            else:
                items[new_key] = v
    except Exception:
        pass
    return items


def safe_get(d: dict, path: str, default=None):
    """Безопасно извлекает значение по пути 'a.b.c'."""
    try:
        keys = path.split(".")
        for k in keys:
            if isinstance(d, dict) and k in d:
                d = d[k]
            else:
                return default
        return d
    except Exception:
        return default

