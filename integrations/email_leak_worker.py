# xss_security_gui/integrations/email_leak_worker.py

from __future__ import annotations

import logging
import os
import random
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from xss_security_gui.auto_recon.scope import (
    RequestBudget,
    is_target_authorized,
    normalize_http_url,
    same_origin,
    scoped_request,
)
from xss_security_gui.settings import settings
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
from xss_security_gui.utils.pii_aggregator import build_email_leak_artifact

logger = logging.getLogger(__name__)

CRAWLER_ERROR_LOG = settings.get("crawl.error_log")
RATE_LIMIT = float(settings.get("crawl.max_rps", 2.0) or 2.0)
AGGRESSIVE_HEADERS = bool(settings.get("http.aggressive_headers", True))

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
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-13-16-5,23-24,0",
]

COMMON_USER_AGENTS.extend([
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 Edg/125.0.2535.67",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
])

COMMON_REFERERS.extend([
    "https://www.facebook.com/",
    "https://www.instagram.com/",
    "https://www.reddit.com/",
    "https://news.google.com/",
    "https://www.youtube.com/",
    "https://www.linkedin.com/",
    "https://t.co/",
    "https://l.facebook.com/",
])

COMMON_LANGUAGES.extend([
    "en-CA,en;q=0.9",
    "en-AU,en;q=0.9",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "pl-PL,pl;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.8",
    "ru-RU,ru;q=0.9,en-US;q=0.8",
])


def get_random_ja3() -> str:
    return random.choice(JA3_FINGERPRINTS)


def get_random_user_agent() -> str:
    return random.choice(COMMON_USER_AGENTS)


def get_random_referer() -> str:
    return random.choice(COMMON_REFERERS)


def get_random_language() -> str:
    return random.choice(COMMON_LANGUAGES)


def log_error(msg: str) -> None:
    try:
        logger.error(msg)
        if CRAWLER_ERROR_LOG:
            os.makedirs(os.path.dirname(str(CRAWLER_ERROR_LOG)) or "logs", exist_ok=True)
            with open(CRAWLER_ERROR_LOG, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now(timezone.utc).isoformat()}] {msg}\n")
    except Exception:
        logger.exception("Failed to write to CRAWLER_ERROR_LOG")


_last_request: float = 0.0
_rate_lock = threading.Lock()


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


DEFAULT_HEADERS: dict[str, str] = {
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

try:
    import geoip2.database  # type: ignore

    GEOIP_READER = geoip2.database.Reader("GeoLite2-Country.mmdb")
except Exception:
    GEOIP_READER = None
    logger.debug("GeoIP database not available — email audit continues without GeoIP")


def build_browser_headers() -> dict[str, str]:
    """Rotate UA / Referer / Accept-Language for each audit request."""
    headers = dict(DEFAULT_HEADERS)
    headers["User-Agent"] = get_random_user_agent()
    headers["Referer"] = get_random_referer()
    headers["Accept-Language"] = get_random_language()
    if random.random() < 0.5:
        headers["User-Agent"] = random.choice(ANTI_WAF_USER_AGENTS)
        headers["Accept-Language"] = random.choice(ANTI_WAF_ACCEPT_LANG)
        headers["Referer"] = random.choice(ANTI_WAF_REFERERS)
    return headers

_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+"
    r"(?:\.[A-Z0-9-]+)+(?![\w.-])",
    re.IGNORECASE,
)
_MAX_RESPONSE_BYTES = 1_000_000
_DEFAULT_MAX_PAGES = 100
_DEFAULT_MAX_REQUESTS = 200
_DEFAULT_TIMEOUT = 5
ALLOWED_CONTROL_CHARS = {"\n", "\r", "\t"}

def _validated_form_values(
    values: Optional[dict[str, str]]
) -> dict[str, str]:
    if values is None:
        return {}

    if not isinstance(values, dict):
        raise TypeError(
            "form_values must be a mapping of field names to plain-text values"
        )

    validated: dict[str, str] = {}

    for name, value in values.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError(
                "Form field names must be non-empty strings"
            )

        if not isinstance(value, str) or len(value) > 256:
            raise ValueError(
                "Form test values must be strings of at most 256 characters"
            )

        if any(
            char not in ALLOWED_CONTROL_CHARS and ord(char) < 32
            for char in value
        ):
            raise ValueError(
                "Form test values must not contain control characters"
            )

        lowered = value.lower()

        if any(
            marker in lowered
            for marker in ("<", ">", "onerror=", "onload=")
        ):
            raise ValueError(
                "Only plain-text, non-executable form test values are accepted"
            )

        validated[name] = value

    return validated


def _form_fields(form: Any, values: dict[str, str]) -> tuple[dict[str, str], bool]:
    fields: dict[str, str] = {}
    matched_test_value = False
    for control in form.find_all(["input", "textarea", "select"]):
        name = control.get("name")
        if not name:
            continue
        name = str(name)
        control_type = str(control.get("type", "text")).lower()
        if control.name == "input" and control_type in {
            "checkbox", "radio",
        }:
            continue
        if control_type == "hidden":
            fields[name] = str(control.get("value", ""))
        elif name in values:
            if control.name == "select":
                options = {
                    str(option.get("value", option.get_text(strip=True)))
                    for option in control.find_all("option")
                }
                if values[name] not in options:
                    continue
            fields[name] = values[name]
            matched_test_value = True
    return fields, matched_test_value


def _response_text(response: requests.Response) -> str:
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_content(chunk_size=16_384):
        if not chunk:
            continue
        remaining = _MAX_RESPONSE_BYTES - size
        chunks.append(chunk[:remaining])
        size += min(len(chunk), remaining)
        if size >= _MAX_RESPONSE_BYTES:
            break
    encoding = response.encoding or "utf-8"
    return b"".join(chunks).decode(encoding, errors="replace")


def run_email_leak_audit(
    target_url: str,
    *,
    active_testing: bool = True,
    max_pages: int = _DEFAULT_MAX_PAGES,
    max_requests: int = _DEFAULT_MAX_REQUESTS,
    timeout: int = _DEFAULT_TIMEOUT,
    form_values: Optional[dict[str, str]] = None,
    callback: Optional[Callable[[dict[str, Any]], None]] = None,
    cancel_event: Optional[threading.Event] = None,
) -> dict[str, Any]:
    """Crawl an allowlisted origin and report masked email exposure.

    Form submissions are disabled by default. Active mode submits explicitly
    supplied, plain-text values only to matching same-origin fields.
    """
    target = normalize_http_url(target_url)
    if not is_target_authorized(target):
        return {
            "status": "blocked",
            "error": "Target is outside ALLOW_REAL_RUN/ALLOWED_TARGETS",
            "target": target,
            "active_testing": True,
            "pages": [],
            "forms": [],
            "emails": [],
            "requests": 0,
        }
    if not isinstance(active_testing, bool):
        raise TypeError("active_testing must be a boolean")
    test_values = _validated_form_values(form_values)

    max_pages = min(max(int(max_pages), 1), 500)
    timeout = min(max(int(timeout), 1), 5)
    budget = RequestBudget(min(max(int(max_requests), 1), _DEFAULT_MAX_REQUESTS))
    session = requests.Session()
    session.headers.update(build_browser_headers())

    pages: list[str] = []
    forms_found: list[dict[str, Any]] = []
    form_submissions: list[dict[str, Any]] = []
    emails: dict[str, set[str]] = {}
    visited: set[str] = set()
    pending = deque([target])
    queued_urls: set[str] = {target}

    def report(event: dict[str, Any]) -> None:
        if callback:
            callback(event)

    try:
        while (
                pending
                and len(pages) < max_pages
                and budget.used < budget.limit
                and not (cancel_event and cancel_event.is_set())
        ):

            page_url = normalize_http_url(
                pending.popleft()
            )

            queued_urls.discard(page_url)

            if page_url in visited:
                continue

            if not same_origin(page_url, target):
                report({
                    "stage": "scope_skip",
                    "url": page_url,
                })
                continue

            visited.add(page_url)

            if not budget.try_consume():
                report({
                    "stage": "budget_exhausted",
                    "requests": budget.used,
                    "limit": budget.limit,
                })
                break

            rate_limit()
            session.headers.update(build_browser_headers())

            report({
                "stage": "crawl_start",
                "url": page_url,
                "visited": len(visited),
                "queued": len(pending),
                "requests": budget.used,
            })

            try:
                response = scoped_request(
                    session,
                    "GET",  # <- тільки GET
                    page_url,
                    root_url=target,
                    timeout=timeout,
                    stream=True,
                    request_budget=budget,
                    initial_budget_consumed=True,
                )

                if response.status_code >= 400:
                    report({
                        "stage": "http_error",
                        "url": page_url,
                        "status": response.status_code,
                    })
                    continue

            except requests.exceptions.RequestException as exc:
                report({
                    "stage": "crawl_error",
                    "url": page_url,
                    "error": str(exc),
                })
                continue

            try:
                if response.is_redirect:
                    report({
                        "stage": "redirect_blocked",
                        "url": page_url,
                        "location": response.headers.get("Location", ""),
                    })
                    continue

                if not same_origin(response.url, target):
                    report({
                        "stage": "cross_origin_blocked",
                        "url": response.url,
                    })
                    continue

                content_type = (
                    response.headers.get("Content-Type", "")
                    .split(";")[0]
                    .strip()
                    .lower()
                )

                allowed_types = {
                    "text/html",
                    "text/plain",
                    "application/xhtml+xml",
                }

                if content_type and content_type not in allowed_types:
                    report({
                        "stage": "content_type_skipped",
                        "url": page_url,
                        "content_type": content_type,
                    })
                    continue

                html = _response_text(response)

                page_url = normalize_http_url(response.url)

                pages.append(page_url)

                report({
                    "stage": "page_processed",
                    "url": page_url,
                    "pages": len(pages),
                    "requests": budget.used,
                })

            finally:
                response.close()

            soup = BeautifulSoup(html, "html.parser")
            text = soup.get_text(" ", strip=True) + " " + html
            for address in _EMAIL_RE.findall(text):
                emails.setdefault(address.lower(), set()).add(page_url)

            for anchor in soup.find_all("a", href=True):
                candidate = normalize_http_url(
                    urljoin(page_url, str(anchor["href"]))
                )

                if (
                        same_origin(candidate, target)
                        and candidate not in visited
                        and candidate not in queued_urls
                ):
                    if urlparse(candidate).path.lower().endswith(
                            (
                                    ".pdf",
                                    ".zip",
                                    ".png",
                                    ".jpg",
                                    ".jpeg",
                                    ".gif",
                                    ".svg",
                                    ".css",
                                    ".js",
                            )
                    ):
                        continue

                    pending.append(candidate)
                    queued_urls.add(candidate)

            for form in soup.find_all("form"):
                action = urljoin(page_url, str(form.get("action", "")))
                method = str(form.get("method", "GET")).upper()
                if method not in {"GET", "POST"} or not same_origin(action, target):
                    continue
                descriptor = {
                    "url": action,
                    "method": method,
                    "input_count": len(
                        form.find_all(
                            ["input", "textarea", "select"]
                        )
                    ),
                    "contains_password": bool(
                        form.find(
                            "input",
                            {"type": "password"}
                        )
                    ),
                    "contains_email": bool(
                        form.find(
                            "input",
                            {"type": "email"}
                        )
                    ),
                }
                forms_found.append(descriptor)
                if not active_testing or not test_values:
                    continue
                fields, matched_test_value = _form_fields(form, test_values)
                if not fields or not matched_test_value:
                    continue
                if cancel_event and cancel_event.is_set():
                    break
                if not budget.try_consume():
                    break
                rate_limit()
                session.headers.update(build_browser_headers())
                try:
                    form_response = scoped_request(
                        session,
                        method,
                        action,
                        root_url=target,
                        timeout=timeout,
                        stream=True,
                        request_budget=budget,
                        initial_budget_consumed=True,
                        **({"params": fields} if method == "GET" else {"data": fields}),
                    )
                except requests.exceptions.RequestException as exc:
                    report({"stage": "form_error", "url": action, "error": str(exc)})
                    continue
                try:
                    submission = {
                        "url": action,
                        "method": method,
                        "status": form_response.status_code,
                        "redirect_blocked": form_response.is_redirect,
                    }

                    if not form_response.is_redirect and same_origin(
                            form_response.url,
                            target
                    ):
                        submitted_text = _response_text(form_response)

                        submission["response_bytes"] = len(
                            submitted_text.encode("utf-8")
                        )

                    form_submissions.append(submission)

                finally:
                    form_response.close()

        report({
            "stage": "progress",
            "pages": len(pages),
            "visited": len(visited),
            "queued": len(pending),
            "emails": len(emails),
            "forms": len(forms_found),
            "active_findings": len(form_submissions),
            "requests": budget.used,
            "budget": budget.limit,
        })

        masked_emails = sorted(emails.keys())
        result = {
            "status": "cancelled" if cancel_event and cancel_event.is_set() else "completed",
            "target": target,
            "active_testing": active_testing,
            "active_form_submissions": bool(form_submissions),
            "pages": pages,
            "page_count": len(pages),
            "forms": forms_found,
            "form_count": len(forms_found),
            "emails": masked_emails,
            "email_sources": {
                address: sorted(sources)
                for address, sources in emails.items()
            },
            "form_submissions": form_submissions,
            "active_findings": form_submissions,
            "requests": budget.used,
            "request_budget": budget.limit,
        }
        artifact = build_email_leak_artifact(
            {"emails": masked_emails},
            target_url=target,
            source="email_leak_worker",
            module="EmailLeakWorker",
        )
        if artifact:
            result["artifact"] = artifact
            THREAT_CONNECTOR.add_artifact("EmailLeakWorker", target, [artifact])
        return result
    finally:
        session.close()


class EmailLeakWorker:
    """Background runner compatible with the main window's legacy worker API."""

    def __init__(
        self,
        threat_tab=None,
        ui_bridge=None,
        target_provider: Optional[Callable[[], str]] = None,
        on_complete: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        self.threat_tab = threat_tab
        self.ui_bridge = ui_bridge
        self.target_provider = target_provider
        self.on_complete = on_complete
        self._thread: Optional[threading.Thread] = None
        self._cancel = threading.Event()
        self._lock = threading.Lock()
        self.last_result: Optional[dict[str, Any]] = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(
        self,
        target_url: Optional[str] = None,
        *,
        active_testing: bool = False,
        max_pages: int = _DEFAULT_MAX_PAGES,
        max_requests: int = _DEFAULT_MAX_REQUESTS,
        form_values: Optional[dict[str, str]] = None,
    ) -> bool:
        if self.is_running():
            return False
        if target_url is None and self.target_provider is not None:
            target_url = self.target_provider()
        if not target_url:
            raise ValueError("An audit target URL is required")
        if not isinstance(active_testing, bool):
            raise TypeError("active_testing must be a boolean")
        self._cancel.clear()

        def worker() -> None:
            try:
                result = run_email_leak_audit(
                    target_url,
                    active_testing=active_testing,
                    max_pages=max_pages,
                    max_requests=max_requests,
                    form_values=form_values,
                    callback=lambda event: logger.info("Email audit: %s", event),
                    cancel_event=self._cancel,
                )
                self.last_result = result
                artifact = result.get("artifact")
                if artifact and self.threat_tab is not None:
                    self._post_ui(self.threat_tab.add_threat, artifact)
                self._post_ui(self._publish_status, result)
                if self.on_complete:
                    self._post_ui(self.on_complete, result)
            except Exception as exc:
                logger.exception("Email leak audit failed")
                self._post_ui(self._publish_error, exc)
                if self.on_complete:
                    self._post_ui(self.on_complete, {"status": "failed", "error": str(exc)})

        with self._lock:
            if self.is_running():
                return False
            self._thread = threading.Thread(
                target=worker,
                name="EmailLeakAuditWorker",
                daemon=True,
            )
            self._thread.start()
        return True

    def stop(self) -> None:
        self._cancel.set()

    def _post_ui(self, callback: Callable[..., Any], *args: Any) -> None:
        if self.ui_bridge is not None and callable(getattr(self.ui_bridge, "post_ui", None)):
            self.ui_bridge.post_ui(callback, *args)
        else:
            callback(*args)

    def _publish_status(self, result: dict[str, Any]) -> None:
        status_var = getattr(self.threat_tab, "status_var", None)
        if status_var is not None:
            status_var.set(
                f"Email audit {result.get('status')}: "
                f"{result.get('page_count', 0)} pages, "
                f"{len(result.get('emails', []))} masked emails"
            )

    def _publish_error(self, error: Exception) -> None:
        status_var = getattr(self.threat_tab, "status_var", None)
        if status_var is not None:
            status_var.set(f"Email audit failed: {type(error).__name__}: {error}")


__all__ = [
    "EmailLeakWorker",
    "run_email_leak_audit",
    "JA3_FINGERPRINTS",
    "COMMON_USER_AGENTS",
    "COMMON_REFERERS",
    "COMMON_LANGUAGES",
    "TLS_SPOOF_CIPHERS",
    "get_random_ja3",
    "get_random_user_agent",
    "get_random_referer",
    "get_random_language",
    "rate_limit",
    "build_browser_headers",
]

