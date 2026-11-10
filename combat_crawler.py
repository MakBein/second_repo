"""Bounded passive discovery and allowlist-gated form audit for the Combat Results GUI."""

from __future__ import annotations

import json
import logging
import queue
import time
import uuid
from collections import Counter, deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urldefrag, urljoin, urlparse

import requests

from xss_security_gui.settings import LOG_DIR, settings

_logger = logging.getLogger(__name__)
_MAX_RESPONSE_BYTES = 1_000_000
_MAX_LINKS_PER_PAGE = 200
_MAX_PAGES_LIMIT = 100
_MAX_ACTIVE_REQUESTS = 50


class _PageParser(HTMLParser):
    """Extract navigation links and form metadata without executing page content."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None
        self._inside_textarea = False
        self._textarea_value = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "a":
            href = attributes.get("href")
            if href:
                self.links.append(href)
        elif tag == "form":
            self._current_form = {
                "action": attributes.get("action") or "",
                "method": (attributes.get("method") or "get").lower(),
                "password_field": False,
                "unsupported_field": False,
                "fields": [],
            }
            self.forms.append(self._current_form)
        elif tag == "input" and self._current_form is not None:
            field_type = (attributes.get("type") or "text").lower()
            field_name = attributes.get("name") or ""
            if field_type == "password":
                self._current_form["password_field"] = True
            if field_type in ("file", "image"):
                self._current_form["unsupported_field"] = True
            if field_name and field_type not in ("submit", "button", "reset", "image", "file"):
                self._current_form["fields"].append(
                    {
                        "name": field_name,
                        "type": field_type,
                        "value": attributes.get("value") or "",
                    }
                )
        elif tag == "textarea" and self._current_form is not None:
            field_name = attributes.get("name") or ""
            self._inside_textarea = bool(field_name)
            self._textarea_value = ""
            if field_name:
                self._current_form["fields"].append(
                    {"name": field_name, "type": "textarea", "value": ""}
                )

    def handle_endtag(self, tag: str) -> None:
        if tag == "textarea" and self._inside_textarea and self._current_form is not None:
            for field in reversed(self._current_form["fields"]):
                if field["type"] == "textarea" and not field["value"]:
                    field["value"] = self._textarea_value
                    break
            self._inside_textarea = False
            self._textarea_value = ""
        if tag == "form":
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._inside_textarea:
            self._textarea_value += data


def _normalized_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Target URL must not be empty")
    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Target must be an absolute HTTP or HTTPS URL")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in target URLs are not supported")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Target URL contains an invalid port") from exc

    return urldefrag(parsed._replace(fragment="").geturl())[0]


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


def is_active_target_allowed(url: str) -> bool:
    """Fail closed unless real requests are enabled and the hostname is allowlisted."""
    if not getattr(settings, "ALLOW_REAL_RUN", False):
        return False

    hostname = (urlparse(url).hostname or "").lower().rstrip(".")
    if not hostname:
        return False

    allowed_hosts = getattr(settings, "ALLOWED_TARGETS", [])
    if not isinstance(allowed_hosts, (list, tuple, set)):
        return False
    for entry in allowed_hosts:
        allowed = str(entry).strip().lower().rstrip(".")
        if "://" in allowed:
            allowed = (urlparse(allowed).hostname or "").lower().rstrip(".")
        if allowed.startswith("*."):
            suffix = allowed[2:]
            if hostname.endswith("." + suffix):
                return True
        elif hostname == allowed:
            return True
    return False


def _bounded_get(
    session: requests.Session,
    url: str,
    deadline: float,
) -> tuple[str, int, dict[str, str], str]:
    """Fetch a page with same-origin redirect checks and a capped response body."""
    requested_url = url
    for _ in range(4):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Combat crawl time budget exhausted")

        response = session.get(
            requested_url,
            allow_redirects=True,
            stream=True,
            timeout=(min(5.0, remaining), min(8.0, remaining)),
        )
        try:
            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                if not location:
                    return requested_url, response.status_code, dict(response.headers), ""
                redirected_url = urljoin(requested_url, location)
                if _origin(redirected_url) != _origin(url):
                    raise ValueError("Cross-origin redirect blocked")
                requested_url = redirected_url
                continue

            body = _read_response_body(response, deadline)
            return (
                response.url or requested_url,
                response.status_code,
                dict(response.headers),
                body,
            )
        finally:
            response.close()

    raise requests.TooManyRedirects("Too many same-origin redirects")


def _read_response_body(response: requests.Response, deadline: float) -> str:
    chunks: list[bytes] = []
    content_size = 0
    for chunk in response.iter_content(chunk_size=16_384):
        if time.monotonic() >= deadline:
            raise TimeoutError("Combat crawl time budget exhausted")
        if not chunk:
            continue
        remaining_bytes = _MAX_RESPONSE_BYTES - content_size
        chunks.append(chunk[:remaining_bytes])
        content_size += min(len(chunk), remaining_bytes)
        if content_size >= _MAX_RESPONSE_BYTES:
            break

    encoding = response.encoding or "utf-8"
    try:
        return b"".join(chunks).decode(encoding, errors="replace")
    except LookupError:
        return b"".join(chunks).decode("utf-8", errors="replace")


def _collect_page_findings(
    url: str,
    status_code: int,
    headers: dict[str, str],
    parser: _PageParser,
) -> list[dict[str, str]]:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    findings: list[dict[str, str]] = []

    def add(severity: str, category: str, description: str, evidence: str) -> None:
        findings.append(
            {
                "severity": severity,
                "category": category,
                "url": url,
                "description": description,
                "evidence": evidence[:300],
                "status_code": str(status_code),
            }
        )

    if not normalized_headers.get("content-security-policy"):
        add("medium", "missing_csp", "Content-Security-Policy header is absent", "")
    if urlparse(url).scheme == "https" and not normalized_headers.get(
        "strict-transport-security"
    ):
        add("medium", "missing_hsts", "Strict-Transport-Security header is absent", "")
    if not normalized_headers.get("x-content-type-options"):
        add(
            "low",
            "missing_nosniff",
            "X-Content-Type-Options header is absent",
            "",
        )

    csp = normalized_headers.get("content-security-policy", "").lower()
    if not normalized_headers.get("x-frame-options") and "frame-ancestors" not in csp:
        add(
            "low",
            "missing_frame_protection",
            "No X-Frame-Options or CSP frame-ancestors directive was found",
            "",
        )

    server = normalized_headers.get("server")
    if server:
        add("info", "server_banner", "Server response header is exposed", server)

    if urlparse(url).scheme == "http":
        for form in parser.forms:
            if form["password_field"]:
                add(
                    "high",
                    "password_form_over_http",
                    "A password form is served over unencrypted HTTP",
                    str(form["action"]),
                )
                break

    return findings


def run_combat_crawl(
    target_url: str,
    result_queue: queue.Queue | None = None,
    progress_callback: Callable[[str, int], None] | None = None,
    *,
    max_pages: int = 20,
    timeout: float = 60.0,
    active_testing: bool = False,
) -> dict[str, Any]:
    """Run a bounded audit and return a JSON-serializable report.

    Discovery GET requests are restricted to the target's origin. Optional active
    tests submit a non-executable reflection canary only to explicitly allowlisted
    targets; password and file-upload forms are never submitted.
    """
    target = _normalized_url(target_url)
    if not 1 <= max_pages <= _MAX_PAGES_LIMIT:
        raise ValueError(f"max_pages must be between 1 and {_MAX_PAGES_LIMIT}")
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    active_enabled = active_testing and is_active_target_allowed(target)

    started_at = datetime.now(timezone.utc)
    deadline = time.monotonic() + timeout
    pending = deque([target])
    queued = {target}
    pages: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []
    active_tests: list[dict[str, Any]] = []
    active_request_count = 0

    def emit(event_type: str, data: dict[str, Any]) -> None:
        event = {
            "type": event_type,
            "data": {"target": target, **data},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if result_queue is not None:
            result_queue.put(event)

    def report_progress(message: str, percent: int) -> None:
        if progress_callback is not None:
            progress_callback(message, max(0, min(100, percent)))

    emit("crawl_started", {"status": "started"})
    if active_testing and not active_enabled:
        _logger.warning("Active checks disabled: target is not explicitly allowlisted: %s", target)
    report_progress(f"Пассивный аудит: {target}", 0)
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "XSS-Security-GUI-Passive-Auditor/1.0",
            "Accept": "text/html,application/xhtml+xml",
        }
    )

    try:
        while pending and len(pages) < max_pages and time.monotonic() < deadline:
            page_url = pending.popleft()
            try:
                final_url, status_code, headers, body = _bounded_get(
                    session, page_url, deadline
                )
                if _origin(final_url) != _origin(target):
                    raise ValueError("Cross-origin response blocked")

                content_type = next(
                    (
                        value
                        for key, value in headers.items()
                        if key.lower() == "content-type"
                    ),
                    "",
                )
                parser = _PageParser()
                if "html" in content_type.lower() or not content_type:
                    parser.feed(body)

                page_findings = _collect_page_findings(
                    final_url, status_code, headers, parser
                )
                findings.extend(page_findings)
                pages.append(
                    {
                        "url": final_url,
                        "status_code": status_code,
                        "content_type": content_type,
                        "bytes_read": len(body.encode("utf-8")),
                        "links_found": len(parser.links),
                        "forms_found": len(parser.forms),
                        "findings_count": len(page_findings),
                    }
                )

                if active_enabled and active_request_count < _MAX_ACTIVE_REQUESTS:
                    for form in parser.forms:
                        action_url = urljoin(final_url, form["action"] or final_url)
                        method = form["method"]
                        eligible_fields = [
                            field
                            for field in form["fields"]
                            if field["type"]
                            in ("text", "search", "email", "url", "tel", "number", "textarea")
                        ]
                        if (
                            method not in ("get", "post")
                            or form["password_field"]
                            or form["unsupported_field"]
                            or not eligible_fields
                            or _origin(action_url) != _origin(target)
                            or not is_active_target_allowed(action_url)
                        ):
                            continue

                        marker = f"xss-audit-{uuid.uuid4().hex}"
                        canary = f'\"><xss-audit-{marker}>'
                        values = [
                            (
                                field["name"],
                                canary if field in eligible_fields else field["value"],
                            )
                            for field in form["fields"]
                        ]
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or active_request_count >= _MAX_ACTIVE_REQUESTS:
                            break
                        try:
                            if method == "get":
                                response = session.get(
                                    action_url,
                                    params=values,
                                    allow_redirects=True,
                                    stream=True,
                                    timeout=(min(5.0, remaining), min(8.0, remaining)),
                                )
                            else:
                                response = session.post(
                                    action_url,
                                    data=values,
                                    allow_redirects=True,
                                    stream=True,
                                    timeout=(min(5.0, remaining), min(8.0, remaining)),
                                )
                            active_request_count += 1
                            try:
                                active_body = _read_response_body(response, deadline)
                                reflected = marker in active_body
                                active_tests.append(
                                    {
                                        "url": action_url,
                                        "method": method.upper(),
                                        "status_code": response.status_code,
                                        "result": (
                                            "canary_reflected"
                                            if reflected
                                            else "not_reflected"
                                        ),
                                        "forms_submitted": True,
                                    }
                                )
                                if reflected:
                                    findings.append(
                                        {
                                            "severity": "medium",
                                            "category": "reflected_input_candidate",
                                            "url": action_url,
                                            "description": (
                                                "Active canary was reflected in the response; "
                                                "manual context validation is required"
                                            ),
                                            "evidence": marker,
                                            "status_code": str(response.status_code),
                                        }
                                    )
                            finally:
                                response.close()
                        except (requests.RequestException, TimeoutError) as exc:
                            active_tests.append(
                                {
                                    "url": action_url,
                                    "method": method.upper(),
                                    "result": "request_error",
                                    "error": f"{type(exc).__name__}: {exc}",
                                    "forms_submitted": True,
                                }
                            )
                            _logger.warning("Active form check failed for %s: %s", action_url, exc)

                for href in parser.links[:_MAX_LINKS_PER_PAGE]:
                    candidate = urldefrag(urljoin(final_url, href))[0]
                    parsed = urlparse(candidate)
                    if (
                        parsed.scheme in ("http", "https")
                        and _origin(candidate) == _origin(target)
                        and candidate not in queued
                    ):
                        queued.add(candidate)
                        pending.append(candidate)
            except (requests.RequestException, TimeoutError, ValueError) as exc:
                errors.append(
                    {
                        "url": page_url,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                _logger.warning("Passive audit failed for %s: %s", page_url, exc)

            percent = int(80 * len(pages) / max_pages) if max_pages else 80
            report_progress(f"Проверено страниц: {len(pages)}", percent)
    finally:
        session.close()

    emit("crawl_complete", {"pages_crawled": len(pages), "errors": len(errors)})
    report_progress("Краулинг завершен; анализ результатов", 85)
    crawl_truncated = bool(pending)

    counts = Counter(item["severity"] for item in findings)
    summary = {
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
        "total_vulnerable": sum(
            1 for item in findings if item["severity"] in ("critical", "high", "medium")
        ),
        "critical_severity": counts.get("critical", 0),
    }
    emit(
        "analysis_complete",
        {"pages_crawled": len(pages), "findings": len(findings), "summary": summary},
    )
    report_progress(
        "Анализ завершен; активные проверки: "
        + ("выполнены в пределах allowlist" if active_enabled else "не выполнялись"),
        95,
    )
    emit(
        "attacks_complete",
        {
            "active_tests_run": 0,
            "total_vulnerable": summary["total_vulnerable"],
            "critical_severity": summary["critical_severity"],
            "summary": summary,
        },
    )

    finished_at = datetime.now(timezone.utc)
    report: dict[str, Any] = {
        "status": (
            "complete"
            if pages and not errors and not crawl_truncated
            else "partial"
            if pages
            else "error"
        ),
        "target": target,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
        "scope": {
            "origin": target,
            "max_pages": max_pages,
            "active_testing_requested": active_testing,
            "active_testing_allowed": active_enabled,
            "active_tests_run": bool(active_tests),
            "active_requests": active_request_count,
            "forms_submitted": any(item.get("forms_submitted") for item in active_tests),
        },
        "pages": pages,
        "crawl_truncated": crawl_truncated,
        "findings": findings,
        "active_tests": active_tests,
        "errors": errors,
        "vulnerability_summary": summary,
    }

    report_dir = Path(LOG_DIR) / "combat_reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"combat_report_{started_at.strftime('%Y%m%d_%H%M%S_%f')}.json"
    temporary_path = report_path.with_suffix(".json.tmp")
    report["report_path"] = str(report_path)
    try:
        temporary_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        temporary_path.replace(report_path)
    except OSError:
        temporary_path.unlink(missing_ok=True)
        raise

    emit("report_saved", {"report_path": str(report_path)})
    emit("combat_complete", report)
    report_progress(f"Отчет сохранен: {report_path}", 100)
    return report


class CombatCrawler:
    """Compatibility adapter for the live watcher; runs passive audits only."""

    def __init__(
        self,
        target_url: str,
        result_queue: queue.Queue | None = None,
        progress_callback: Callable[[], None] | None = None,
    ) -> None:
        self.target_url = target_url
        self.result_queue = result_queue
        self.progress_callback = progress_callback

    def run_full_combat_cycle(self) -> dict[str, Any]:
        def update_watcher_status(_message: str, _percent: int) -> None:
            if self.progress_callback is not None:
                self.progress_callback()

        return run_combat_crawl(
            target_url=self.target_url,
            result_queue=self.result_queue,
            progress_callback=update_watcher_status,
            active_testing=True,
        )
