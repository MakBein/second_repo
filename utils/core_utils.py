# xss_security_gui/utils/core_utils.py
import datetime
import traceback
import os
import urllib.parse
from hashlib import sha1


def normalize_url(url: str) -> str:
    """Приводит URL к стандартному виду."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url  # HTTPS предпочтительнее
    return url


def hash_url(url: str) -> str:
    """SHA1-хеш канонизированного URL (без query/fragment)."""
    parsed = urllib.parse.urlparse(url)._replace(query="", fragment="")
    return sha1(parsed.geturl().encode()).hexdigest()


def url_fingerprint(url, keep_query_keys=None):
    """Создаёт хеш URL с сохранением ключевых query-параметров."""
    parsed = urllib.parse.urlparse(url)
    query = parsed.query

    if keep_query_keys:
        query_dict = urllib.parse.parse_qs(query)
        filtered_query = {
            k: query_dict[k] for k in keep_query_keys if k in query_dict
        }
        query_str = urllib.parse.urlencode(filtered_query, doseq=True)
    else:
        query_str = ""

    canonical = parsed._replace(query=query_str, fragment="")
    return sha1(canonical.geturl().encode()).hexdigest()


def is_valid_url(url: str) -> bool:
    """Проверяет, что строка является корректным http/https URL."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in ("http", "https") and parsed.netloc != ""
    except Exception:
        return False


def safe_crawl_site(domain, retries=3):
    """
    Безопасный краулер с повторами и логированием.
    Делает запрос на реальный URL, а не на SHA1-хеш.
    """
    import requests
    from time import sleep

    domain = normalize_url(domain)
    domain_hash = hash_url(domain)

    for attempt in range(retries):
        try:
            if not is_valid_url(domain):
                raise ValueError(f"Invalid URL: {domain}")

            response = requests.get(domain, timeout=5)

            if response.ok:
                return {"status": "success", "content": response.text}
            else:
                return {
                    "status": "error",
                    "code": response.status_code,
                    "reason": response.reason
                }

        except Exception as e:
            log_error(domain_hash, e)
            sleep(1)

    return {
        "status": "failure",
        "reason": "Max retries exceeded",
        "target": domain
    }


def log_xss_flood(url, status):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    os.makedirs("logs", exist_ok=True)
    with open("logs/xss_flood_log.txt", "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] [{status}] {url}\n")


def log_error(domain, error):
    """Лог ошибок с автосозданием директории."""
    os.makedirs("xss_security_gui", exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    path = "xss_security_gui/error_log.txt"

    with open(path, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] 🌐 {domain} — {type(error).__name__}: {str(error)}\n")
        f.write(traceback.format_exc() + "\n")


def contains_sensitive(data, keys):
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
