"""Fail-closed URL scope policy shared by AutoRecon stages."""

from __future__ import annotations

import threading
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from xss_security_gui.settings import settings


class RequestBudget:
    """Thread-safe cap shared by all active probes in one AutoRecon run."""

    def __init__(self, limit: int):
        self.limit = min(max(0, int(limit)), 200)
        self.used = 0
        self._lock = threading.Lock()

    def try_consume(self) -> bool:
        with self._lock:
            if self.used >= self.limit:
                return False
            self.used += 1
            return True


class RequestBudgetExceeded(requests.exceptions.RequestException):
    """Raised before a network hop when an active audit reaches its request cap."""


def normalize_http_url(value: str) -> str:
    target = value.strip()
    if not target:
        raise ValueError("Target URL must not be empty")
    if "://" not in target:
        target = "https://" + target

    parsed = urlparse(target)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be an absolute HTTP or HTTPS URL")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in target URLs are not allowed")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Target URL has an invalid port") from exc

    return parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        fragment="",
    ).geturl()


def _host_entry(value: str) -> str:
    entry = value.strip().lower()
    if "://" in entry:
        parsed = urlparse(entry)
        return (parsed.hostname or "").rstrip(".")
    return entry.rstrip(".")


def is_target_authorized(url: str) -> bool:
    """Return true only when real runs are enabled and the hostname is allowlisted."""
    if not getattr(settings, "ALLOW_REAL_RUN", False):
        return False
    try:
        hostname = (urlparse(normalize_http_url(url)).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    allowlist = getattr(settings, "ALLOWED_TARGETS", ())
    if not isinstance(allowlist, (list, tuple, set, frozenset)):
        return False

    for raw_entry in allowlist:
        entry = _host_entry(str(raw_entry))
        if entry.startswith("*."):
            suffix = entry[2:]
            if hostname.endswith("." + suffix):
                return True
        elif hostname == entry:
            return True
    return False


def same_origin(url: str, root_url: str) -> bool:
    """Compare scheme, normalized hostname, and effective port."""
    try:
        candidate = urlparse(normalize_http_url(url))
        root = urlparse(normalize_http_url(root_url))
    except ValueError:
        return False

    def origin(parsed):
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return parsed.scheme, (parsed.hostname or "").lower().rstrip("."), port

    return origin(candidate) == origin(root)


def scoped_request(
    requester: Any,
    method: str,
    url: str,
    *,
    root_url: str,
    max_redirects: int = 5,
    request_budget: RequestBudget | None = None,
    initial_budget_consumed: bool = False,
    **kwargs: Any,
) -> requests.Response:
    """Issue a request and follow only authorized same-origin redirects."""
    method = method.upper()
    if method not in {"GET", "POST"}:
        raise ValueError("Only GET and POST are allowed by AutoRecon")
    if not is_target_authorized(url) or not same_origin(url, root_url):
        raise requests.exceptions.InvalidURL("Request target is outside the authorized origin")

    current_url = normalize_http_url(url)
    current_method = method
    request_kwargs = dict(kwargs)

    for redirect_count in range(max_redirects + 1):
        if request_budget and not (
            redirect_count == 0 and initial_budget_consumed
        ):
            if not request_budget.try_consume():
                raise RequestBudgetExceeded("Active request budget exhausted")
        response = requester.request(
            current_method,
            current_url,
            allow_redirects=True,
            **request_kwargs,
        )
        request_kwargs.pop("params", None)
        if not response.is_redirect:
            return response

        location = response.headers.get("Location")
        if not location:
            return response
        next_url = urljoin(response.url, location)
        if not is_target_authorized(next_url) or not same_origin(next_url, root_url):
            response.close()
            return response
        if redirect_count == max_redirects:
            response.close()
            raise requests.exceptions.TooManyRedirects(
                f"More than {max_redirects} same-origin redirects"
            )

        status = response.status_code
        response.close()
        if status == 303 or (status in {301, 302} and current_method == "POST"):
            current_method = "GET"
            request_kwargs.pop("data", None)
            request_kwargs.pop("json", None)
            request_kwargs.pop("files", None)
            headers = dict(request_kwargs.get("headers") or {})
            for name in list(headers):
                if name.lower() in {"content-length", "content-type"}:
                    headers.pop(name)
            if headers:
                request_kwargs["headers"] = headers
        current_url = normalize_http_url(next_url)

    raise requests.exceptions.TooManyRedirects("Redirect limit exceeded")


__all__ = [
    "RequestBudget",
    "RequestBudgetExceeded",
    "is_target_authorized",
    "normalize_http_url",
    "same_origin",
    "scoped_request",
]
