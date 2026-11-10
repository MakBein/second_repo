# xss_security_gui/auto_recon/scanner.py

# === Стандартная библиотека ===
from pathlib import Path
import datetime
import json
import logging
import re
import os
import secrets
import threading
from collections import deque
from typing import Optional, List, Dict, Any, Callable
from urllib.parse import urljoin, urldefrag

# === Внешние библиотеки ===
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup

# === Локальные утилиты ===
from xss_security_gui.auto_recon.scope import (
    RequestBudget,
    is_target_authorized,
    normalize_http_url,
    RequestBudgetExceeded,
    same_origin,
    scoped_request,
)
from xss_security_gui.settings import LOG_DIR

# === Локальные модули ===
from xss_security_gui.xss_detector import XSSDetector
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


# ============================================================
#  Устойчивый HTTP-сессия
# ============================================================

def create_retry_session(
    total: int = 3,
    backoff_factor: float = 0.5,
    status_forcelist: tuple = (429, 500, 502, 503, 504),
) -> requests.Session:
    """
    Создаёт HTTP-сессию без повторных запросов, чтобы сетевой бюджет был точным.

    Args:
        total, backoff_factor, status_forcelist: retained for API compatibility.
    """
    retry = Retry(
        total=0,
        connect=0,
        read=0,
        status=0,
        backoff_factor=0,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(["GET"]),
        raise_on_status=False,
        respect_retry_after_header=False,
    )

    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _read_bounded_response(response: requests.Response, max_bytes: int) -> str:
    if not callable(getattr(response, "iter_content", None)):
        return str(getattr(response, "text", ""))[:max_bytes]
    chunks: list[bytes] = []
    byte_count = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        remaining = max_bytes - byte_count
        chunks.append(chunk[:remaining])
        byte_count += min(len(chunk), remaining)
        if byte_count >= max_bytes:
            break
    return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")


def _safe_response_excerpt(html: str, limit: int = 2000) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for field in soup.find_all(["input", "textarea"]):
        name = str(field.get("name") or "").lower()
        field_type = str(field.get("type") or "").lower()
        if field_type in {"password", "file"} or any(
            marker in name
            for marker in ("password", "passwd", "secret", "token", "cookie", "auth")
        ):
            field.attrs.pop("value", None)
            field.clear()
    return str(soup)[:limit]


# ============================================================
#  Основной сканер эндпоинтов
# ============================================================

class EndpointScanner:
    """
    AutoRecon EndpointScanner 2.0

    • Сканирует страницы, формы, JS и XHR
    • Интегрируется с ThreatConnector
    • Поддерживает XSS-сканирование
    """

    def __init__(
        self,
        target_url: str,
        gui_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        opsec_mode: str = "standard",
        timeout: int = 5,
        active_request_budget: Optional[RequestBudget] = None,
        active_testing: bool = False,
        max_pages: int = 100,
        max_response_bytes: int = 1024 * 1024,
    ):
        self.session = create_retry_session()
        self.target = normalize_http_url(target_url)
        self.authorized = is_target_authorized(self.target)
        self.timeout = min(max(timeout, 1), 5)
        self.active_request_budget = active_request_budget or RequestBudget(200)
        self.active_testing = active_testing is True
        self.max_pages = min(max(int(max_pages), 1), 100)
        self.max_response_bytes = min(max(int(max_response_bytes), 1024), 1024 * 1024)
        self.headers = {"User-Agent": "AutoReconScanner/2.0"}
        self.endpoints: List[Dict[str, Any]] = []
        self.gui_callback = gui_callback
        self.opsec_mode = opsec_mode or "standard"
        self.detector = XSSDetector()

    @staticmethod
    def _timestamp() -> str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Consume the shared request budget and follow only in-scope redirects."""
        if not is_target_authorized(url) or not same_origin(url, self.target):
            raise requests.exceptions.InvalidURL("Request URL is outside the authorized origin")
        if not self.active_request_budget.try_consume():
            raise RequestBudgetExceeded("AutoRecon request budget exhausted")
        kwargs.setdefault("stream", True)
        return scoped_request(
            self.session,
            method,
            url,
            root_url=self.target,
            timeout=self.timeout,
            request_budget=self.active_request_budget,
            initial_budget_consumed=True,
            **kwargs,
        )

    def _read_response(self, response: requests.Response) -> str:
        """Read at most the configured response cap, including compressed bodies."""
        return _read_bounded_response(response, self.max_response_bytes)

    @staticmethod
    def _safe_headers(headers: Any) -> Dict[str, str]:
        hidden = {"authorization", "proxy-authorization", "cookie", "set-cookie"}
        return {
            str(key): ("[redacted]" if str(key).lower() in hidden else str(value))
            for key, value in dict(headers or {}).items()
        }

    @staticmethod
    def _sensitive_field(name: str, field_type: str = "") -> bool:
        key = f"{name} {field_type}".lower().replace("-", "_")
        return field_type.lower() in {"password", "file"} or any(
            marker in key
            for marker in ("password", "passwd", "secret", "token", "cookie", "auth")
        )

    @staticmethod
    def _canary() -> str:
        return f"AUTORECON-CANARY-{secrets.token_hex(8)}"

    @staticmethod
    def _response_excerpt(html: str, limit: int = 2000) -> str:
        return _safe_response_excerpt(html, limit)

    # --------------------------------------------------------
    # Вспомогательный метод: отправка событий в GUI
    # --------------------------------------------------------

    def _report_gui(self, message: Dict[str, Any]):
        if self.gui_callback:
            try:
                self.gui_callback(message)
            except Exception as e:
                logging.error(f"[EndpointScanner] GUI callback error: {e}", exc_info=True)

    # --------------------------------------------------------
    # Основной сбор эндпоинтов
    # --------------------------------------------------------

    def scan(self) -> List[Dict[str, Any]]:
        """Crawl same-origin pages and discover forms, scripts, and API endpoints."""
        if not self.authorized:
            self._report_gui(
                {
                    "status": "blocked",
                    "error": "Target blocked by ALLOW_REAL_RUN/ALLOWED_TARGETS",
                }
            )
            return []
        pending = deque([self.target])
        queued = {self.target}
        visited: set[str] = set()
        discovered: list[Dict[str, Any]] = []
        scripts: set[str] = set()
        pages_read = 0

        while pending and pages_read < self.max_pages:
            page_url = pending.popleft()
            if page_url in visited:
                continue
            visited.add(page_url)
            response: Optional[requests.Response] = None
            try:
                response = self._request(
                    "GET",
                    page_url,
                    headers=self.headers,
                )
                if response.is_redirect or not same_origin(response.url, self.target):
                    self._report_gui(
                        {"status": "blocked", "url": page_url, "reason": "redirect_scope"}
                    )
                    continue
                response.raise_for_status()
                content_type = response.headers.get("Content-Type", "").lower()
                if content_type and not any(
                    media_type in content_type
                    for media_type in ("text/html", "application/xhtml+xml")
                ):
                    continue
                html = self._read_response(response)
                page_url = response.url
                pages_read += 1
                soup = BeautifulSoup(html, "html.parser")
                discovered.append(
                    {
                        "url": page_url,
                        "method": "GET",
                        "params": {},
                        "source": "page",
                        "status": response.status_code,
                        "headers": self._safe_headers(response.request.headers),
                        "response_headers": self._safe_headers(response.headers),
                        "full_response": self._response_excerpt(html),
                        "timestamp": self._timestamp(),
                    }
                )
                discovered.extend(self.extract_forms(soup, page_url))
                scripts.update(self.extract_js_links(soup, page_url))

                for anchor in soup.find_all("a", href=True):
                    candidate = urljoin(page_url, str(anchor.get("href", "")))
                    candidate, _fragment = urldefrag(candidate)
                    if (
                        candidate
                        and same_origin(candidate, self.target)
                        and candidate not in queued
                    ):
                        queued.add(candidate)
                        pending.append(candidate)
            except RequestBudgetExceeded as exc:
                self._report_gui({"status": "limited", "reason": str(exc)})
                break
            except requests.exceptions.RequestException as exc:
                self._report_gui({"warning": f"Failed to fetch page {page_url}: {exc}"})
                logging.warning("[EndpointScanner] Failed to fetch %s: %s", page_url, exc)
            finally:
                if response is not None:
                    response.close()

        discovered.extend(self.extract_xhr(sorted(scripts)))
        self.endpoints = self._deduplicate_endpoints(discovered)
        self._report_gui({"info": f"Discovered {len(self.endpoints)} endpoints"})

        # Отправляем артефакты в ThreatConnector
        try:
            if self.endpoints:
                THREAT_CONNECTOR.add_artifact(
                    "EndpointScanner",
                    self.target,
                    self.endpoints,
                )
        except Exception as e:
            logging.error(f"[EndpointScanner] ThreatConnector error: {e}", exc_info=True)

        return self.endpoints

    @staticmethod
    def _deduplicate_endpoints(
        endpoints: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        unique: dict[tuple[str, str, str], Dict[str, Any]] = {}
        for endpoint in endpoints:
            key = (
                str(endpoint.get("url", "")),
                str(endpoint.get("method", "GET")).upper(),
                str(endpoint.get("source", "")),
            )
            unique.setdefault(key, endpoint)
        return list(unique.values())

    # --------------------------------------------------------
    # Формы
    # --------------------------------------------------------

    def extract_forms(
        self,
        soup: BeautifulSoup,
        page_url: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Извлекает HTML-формы и превращает их в эндпоинты."""
        result: List[Dict[str, Any]] = []
        source_url = page_url or self.target

        for form in soup.find_all("form"):
            action = urljoin(source_url, form.get("action", ""))
            if not same_origin(action, self.target):
                continue
            method = form.get("method", "GET").upper()
            if method not in {"GET", "POST"}:
                continue

            fields = []
            params: Dict[str, str] = {}
            for field in form.find_all(["input", "textarea", "select", "button"]):
                name = str(field.get("name") or "").strip()
                if not name:
                    continue
                field_type = str(field.get("type") or (
                    "textarea" if field.name == "textarea" else
                    "select" if field.name == "select" else "text"
                )).lower()
                fields.append({"name": name, "type": field_type})
                if not self._sensitive_field(name, field_type):
                    params.setdefault(name, "")

            result.append({
                "url": action,
                "method": method,
                "params": params,
                "fields": fields,
                "page_url": source_url,
                "source": "form",
                "status": None,
                "headers": dict(self.headers),
                "response_headers": {},
                "timestamp": self._timestamp(),
            })

        return result

    # --------------------------------------------------------
    # JS-файлы
    # --------------------------------------------------------

    def extract_js_links(
        self,
        soup: BeautifulSoup,
        page_url: Optional[str] = None,
    ) -> List[str]:
        """Возвращает список абсолютных ссылок на JS-файлы."""
        source_url = page_url or self.target
        return [
            urljoin(source_url, s["src"])
            for s in soup.find_all("script", src=True)
            if same_origin(urljoin(source_url, s["src"]), self.target)
        ]

    # --------------------------------------------------------
    # XHR / fetch / ajax
    # --------------------------------------------------------

    def extract_xhr(self, js_links: List[str]) -> List[Dict[str, Any]]:
        """
        Ищет в JS-файлах вызовы fetch/xhr/ajax и строит эндпоинты.
        """
        api_patterns: List[Dict[str, Any]] = []
        xhr_regex = re.compile(
            r"(fetch|xhr|ajax)\s*\(\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE,
        )

        for js_url in js_links:
            if not same_origin(js_url, self.target):
                continue
            try:
                resp = self._request("GET", js_url, headers=self.headers)
                if resp.is_redirect or not same_origin(resp.url, self.target):
                    resp.close()
                    continue
                js_text = self._read_response(resp)
                found = xhr_regex.findall(js_text)

                for _, url in found:
                    full_url = urljoin(self.target, url)
                    if not same_origin(full_url, self.target):
                        continue
                    api_patterns.append({
                        "url": full_url,
                        "method": "GET",
                        "params": {},
                        "source": "js",
                        "status": resp.status_code,
                        "headers": self._safe_headers(resp.request.headers),
                        "response_headers": self._safe_headers(resp.headers),
                        "timestamp": self._timestamp(),
                    })
                resp.close()

            except RequestBudgetExceeded as e:
                self._report_gui({"status": "limited", "reason": str(e)})
                break
            except requests.exceptions.RequestException as e:
                self._report_gui({"warning": f"Failed to fetch JS {js_url}: {e}"})
                logging.warning(f"[EndpointScanner] Failed to fetch JS {js_url}: {e}")

        return api_patterns

    # --------------------------------------------------------
    # XSS-сканирование эндпоинтов
    # --------------------------------------------------------

    def scan_xss_on_endpoints(
        self,
        payload: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Check same-origin GET/POST forms with a non-executable reflection canary.

        Password/file and credential/token forms are never submitted. Supplying a
        custom canary is supported for correlation, but executable markup is not.
        """
        results: List[Dict[str, Any]] = []
        if not self.active_testing:
            self._report_gui({"status": "skipped", "reason": "active_testing_not_confirmed"})
            return results
        if not self.authorized:
            self._report_gui(
                {"status": "blocked", "reason": "target_not_authorized"}
            )
            return results
        canary = payload or self._canary()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", canary):
            raise ValueError("Only inert alphanumeric reflection canaries are accepted")

        for ep in self.endpoints:
            method = str(ep.get("method", "GET")).upper()
            if method not in {"GET", "POST"}:
                continue
            if ep.get("source") not in {"form"}:
                continue
            fields = ep.get("fields", [])
            if not isinstance(fields, list) or any(
                isinstance(field, dict)
                and self._sensitive_field(
                    str(field.get("name") or ""),
                    str(field.get("type") or ""),
                )
                for field in fields
            ):
                self._report_gui(
                    {
                        "status": "skipped",
                        "reason": "sensitive_form_fields",
                        "url": ep.get("url"),
                    }
                )
                continue
            params = ep.get("params")
            if not isinstance(params, dict):
                continue
            safe_names = [
                str(name)
                for name in params
                if isinstance(name, str) and not self._sensitive_field(name)
            ]
            if not safe_names:
                continue
            test_params = dict.fromkeys(params, "")
            test_params[safe_names[0]] = canary

            response: Optional[requests.Response] = None
            try:
                endpoint_url = normalize_http_url(str(ep.get("url") or ""))
                if not same_origin(endpoint_url, self.target):
                    continue
                request_kwargs = (
                    {"params": test_params}
                    if method == "GET"
                    else {"data": test_params}
                )
                response = self._request(
                    method,
                    endpoint_url,
                    headers=self.headers,
                    **request_kwargs,
                )
                if response.is_redirect or not same_origin(response.url, self.target):
                    response.close()
                    continue
                html = self._read_response(response)
                reflected = canary in html
                context = (
                    self.detector.detect_xss_context(html, canary)
                    if reflected
                    else "Not reflected"
                )

                result: Dict[str, Any] = {
                    "url": response.url,
                    "request_url": endpoint_url,
                    "status": response.status_code,
                    "method": method,
                    "payload": canary,
                    "context": (
                        f"Input reflected (canary only): {context}"
                        if reflected
                        else "Not reflected"
                    ),
                    "category": "input_reflection" if reflected else "none",
                    "source": "form_canary",
                    "full_response": self._response_excerpt(html),
                    "headers": self._safe_headers(response.request.headers),
                    "response_headers": self._safe_headers(response.headers),
                    "timestamp": self._timestamp(),
                    "reflected": reflected,
                    "finding_type": "reflection_only",
                    "vulnerable": False,
                }

                results.append(result)
                self._report_gui(result)

                try:
                    THREAT_CONNECTOR.add_artifact("XSSScanner", response.url, [result])
                except Exception as e:
                    logging.error(f"[EndpointScanner] ThreatConnector XSS error: {e}", exc_info=True)
            except RequestBudgetExceeded as e:
                self._report_gui({"status": "limited", "reason": str(e)})
                break
            except requests.exceptions.RequestException as e:
                error_result = {
                    "url": ep.get("url"),
                    "error": str(e),
                    "source": ep.get("source", "unknown"),
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                }
                results.append(error_result)
                self._report_gui(error_result)
                logging.error(f"[EndpointScanner] XSS scan error for {ep.get('url')}: {e}")
            finally:
                if response is not None:
                    response.close()

        return results

    def fuzz_xss_parameters(
            self,
            base_params: Optional[Dict[str, Any]] = None,
            method: str = "GET",
    ) -> List[Dict[str, Any]]:
        """
        REAL XSS fuzzing (variant 4):
        - Uses real XSS payloads (not canaries)
        - Loads additional payloads from real_payloads.txt
        - Detects reflection AND execution context
        - Marks vulnerable=True only when execution is possible
        """
        results: List[Dict[str, Any]] = []

        # Active testing required
        if not self.active_testing:
            self._report_gui({"status": "skipped", "reason": "active_testing_not_confirmed"})
            return results

        # Target must be authorized
        if not self.authorized:
            self._report_gui({"status": "blocked", "reason": "target_not_authorized"})
            return results

        method = method.upper()
        if method not in {"GET", "POST"}:
            raise ValueError("Only GET and POST are supported")

        base_params = base_params or {}
        if not isinstance(base_params, dict):
            raise TypeError("base_params must be a dictionary")

        # Filter out sensitive fields
        safe_params = {
            str(name): value
            for name, value in base_params.items()
            if isinstance(name, str)
               and name
               and not self._sensitive_field(name)
        }

        if not safe_params:
            return results

        # BUILT-IN REAL XSS PAYLOADS
        builtin_payloads = [
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '"><svg onload=alert(1)>',
            '"><iframe src=javascript:alert(1)>',
            "';alert(1);//",
            "\"><body onload=alert(1)>",
            "<script>alert(1)</script>",
            "javascript:alert(1)",
        ]

        # LOAD EXTERNAL PAYLOADS FROM FILE
        external_payloads = []
        try:
            payload_file = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                "auto_recon",
                "target",
                "real_payloads.txt"
            )

            with open(payload_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        external_payloads.append(line)
        except Exception as e:
            logging.error(f"[XSSFuzzer] Failed to load external payloads: {e}", exc_info=True)

        # MERGE PAYLOADS
        xss_payloads = builtin_payloads + external_payloads

        # MAIN LOOP — test each parameter with each payload
        for name in safe_params:
            for payload in xss_payloads:

                params = dict(safe_params)
                params[name] = payload

                response: Optional[requests.Response] = None

                try:
                    request_kwargs = {"params": params} if method == "GET" else {"data": params}

                    response = self._request(
                        method,
                        self.target,
                        headers=self.headers,
                        **request_kwargs,
                    )

                    # Redirects or cross-origin responses are ignored
                    if response.is_redirect or not same_origin(response.url, self.target):
                        response.close()
                        continue

                    html = self._read_response(response)

                    # Reflection detection
                    reflected = payload in html

                    # Context detection
                    if reflected:
                        context = self.detector.detect_xss_context(html, payload)
                    else:
                        context = "Not reflected"

                    # Execution detection
                    executable_contexts = {
                        "JS Context",
                        "Attribute Injection",
                        "HTML Body",
                        "URL Parameter",
                    }

                    vulnerable = reflected and context in executable_contexts

                    result = {
                        "module": "XSSFuzzer",
                        "url": response.url,
                        "request_url": self.target,
                        "status": response.status_code,
                        "method": method,
                        "parameter": name,
                        "payload": payload,
                        "context": context,
                        "category": "xss" if vulnerable else ("input_reflection" if reflected else "none"),
                        "source": "xss_real_payloads",
                        "full_response": self._response_excerpt(html),
                        "headers": self._safe_headers(response.request.headers),
                        "response_headers": self._safe_headers(response.headers),
                        "response_length": len(html),
                        "timestamp": self._timestamp(),
                        "reflected": reflected,
                        "finding_type": "xss_executable" if vulnerable else (
                            "xss_reflection" if reflected else "none"
                        ),
                        "vulnerable": vulnerable,
                        "severity": "high" if vulnerable else ("medium" if reflected else "info"),
                    }

                    results.append(result)
                    self._report_gui(result)

                    try:
                        THREAT_CONNECTOR.add_artifact("XSSFuzzer", result["url"], [result])
                    except Exception as e:
                        logging.error(f"[XSSFuzzer] ThreatConnector error: {e}", exc_info=True)

                except RequestBudgetExceeded as e:
                    self._report_gui({"status": "limited", "reason": str(e)})
                    break

                except requests.exceptions.RequestException as e:
                    error_result = {
                        "module": "XSSFuzzer",
                        "url": self.target,
                        "error": str(e),
                        "source": "xss_real_payloads",
                        "timestamp": self._timestamp(),
                        "severity": "error",
                        "vulnerable": False,
                    }

                    results.append(error_result)
                    self._report_gui(error_result)

                    try:
                        THREAT_CONNECTOR.add_artifact("XSSFuzzer", error_result["url"], [error_result])
                    except Exception as e2:
                        logging.error(f"[XSSFuzzer] ThreatConnector error: {e2}", exc_info=True)

                finally:
                    if response is not None:
                        response.close()

        return results

# ============================================================
#  Вспомогательные функции
# ============================================================

def extract_context(payload: str, html: str, context: int = 50) -> Optional[tuple[str, int]]:
    """Возвращает фрагмент HTML вокруг payload."""
    if not payload or not html:
        return None

    index = html.find(payload)
    if index == -1:
        return None

    start = max(0, index - context)
    end = min(len(html), index + len(payload) + context)
    return html[start:end], index


def categorize_reflection(payload: str, html: str) -> str:
    """Определяет категорию отражения payload."""
    snippet, _ = extract_context(payload, html, context=100) or (None, None)
    if not snippet:
        return "unknown"

    if re.search(r"<[^>]+{}[^>]*>".format(re.escape(payload)), snippet):
        return "🔤 Reflected HTML"

    if re.search(r'["\']{}["\']'.format(re.escape(payload)), snippet):
        return "📜 Reflected JS"

    if re.search(r'\s+\w+=["\']{}["\']'.format(re.escape(payload)), snippet):
        return "🧬 Attribute Injection"

    return "raw"


def suggest_payload_by_category(category: str) -> str:
    """Возвращает подходящий payload для категории отражения."""
    mapping = {
        "🔤 Reflected HTML": "<script>alert(1)</script>",
        "🧬 Attribute Injection": '" onerror="alert(1)',
        "📜 Reflected JS": '";alert(1)//',
        "raw": "<img src=x onerror=alert(1)>",
    }
    return mapping.get(category, "<img src=x onerror=alert(1)>")


def scan_url(
    url: str,
    request_budget: Optional[RequestBudget] = None,
    max_response_bytes: int = 1024 * 1024,
) -> Dict[str, Any]:
    """Минимальный сканер одного URL."""
    budget = request_budget or RequestBudget(200)
    response: Optional[requests.Response] = None
    session = create_retry_session()
    try:
        normalized_url = normalize_http_url(url)
        if not is_target_authorized(normalized_url):
            return {
                "module": "URLScanner",
                "url": url,
                "text": "",
                "headers": {},
                "status": "blocked",
                "error": "Target is outside ALLOW_REAL_RUN/ALLOWED_TARGETS",
                "source": "scan_url",
                "timestamp": datetime.datetime.utcnow().isoformat(),
            }
        if not budget.try_consume():
            raise RequestBudgetExceeded("AutoRecon request budget exhausted")
        response = scoped_request(
            session,
            "GET",
            normalized_url,
            root_url=normalized_url,
            timeout=5,
            stream=True,
            request_budget=budget,
            initial_budget_consumed=True,
        )
        if response.is_redirect or not same_origin(response.url, normalized_url):
            return {
                "module": "URLScanner",
                "url": url,
                "text": "",
                "headers": {},
                "status": "blocked",
                "error": "Redirect target is outside the authorized origin",
                "source": "scan_url",
                "timestamp": datetime.datetime.utcnow().isoformat(),
            }
        response.raise_for_status()
        text = _read_bounded_response(
            response,
            min(max(int(max_response_bytes), 1024), 1024 * 1024),
        )
        return {
            "module": "URLScanner",
            "url": response.url,
            "text": _safe_response_excerpt(text),
            "headers": EndpointScanner._safe_headers(response.headers),
            "status": response.status_code,
            "source": "scan_url",
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
    except (requests.exceptions.RequestException, ValueError, TypeError) as e:
        return {
            "module": "URLScanner",
            "url": url,
            "text": "",
            "headers": {},
            "status": "error",
            "error": str(e),
            "source": "scan_url",
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
    finally:
        if response is not None:
            response.close()
        session.close()


def scan_multiple(
    urls: List[str],
    max_requests: int = 200,
    max_response_bytes: int = 1024 * 1024,
) -> List[Dict[str, Any]]:
    """Scan authorized URLs with one shared request and response-size budget."""
    budget = RequestBudget(min(max(int(max_requests), 0), 200))
    results = []
    for url in urls:
        if budget.used >= budget.limit:
            break
        results.append(
            scan_url(
                url,
                request_budget=budget,
                max_response_bytes=max_response_bytes,
            )
        )
    return results

# ============================================================
#  NDJSON логирование XSS
# ============================================================

LOG_DIR: Path = LOG_DIR / "xss"
LOG_FILE: Path = LOG_DIR / "reflected_responses.json"

LOG_DIR.mkdir(parents=True, exist_ok=True)
_write_lock = threading.Lock()


def rotate_if_big(path: Path, max_mb: int = 20) -> None:
    """Ротирует файл, если он превышает max_mb мегабайт."""
    try:
        if not path.exists():
            return

        size = path.stat().st_size
        if size <= max_mb * 1024 * 1024:
            return

        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup = path.with_suffix(path.suffix + f".{ts}.bak")
        path.rename(backup)

        logging.info(f"[NDJSON] Лог ротирован: {path} → {backup}")
    except Exception as e:
        logging.error(f"[NDJSON] Ошибка ротации файла {path}: {e}", exc_info=True)


def validate_result(result: Dict[str, Any]) -> bool:
    """Минимальная валидация структуры XSS-артефакта."""
    required = {"url", "category", "context"}
    missing = required - result.keys()

    if missing:
        logging.warning(f"[NDJSON] Пропущены обязательные поля: {missing}")
        return False
    return True


def save_reflected_response(result: Dict[str, Any]) -> None:
    """Сохраняет XSS-отражение в NDJSON-файл."""
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        result.setdefault("_ts", datetime.datetime.utcnow().isoformat())

        if not validate_result(result):
            return

        rotate_if_big(LOG_FILE)

        with _write_lock:
            with LOG_FILE.open("a", encoding="utf-8") as f:
                f.write(json.dumps(result, ensure_ascii=False) + "\n")

        logging.info(f"[NDJSON] Сохранён артефакт: {result.get('url')} [{result.get('category')}]")
    except Exception as e:
        logging.error(f"[NDJSON] Ошибка записи артефакта: {e}", exc_info=True)


def load_reflected_responses(path: Path = LOG_FILE) -> List[Dict[str, Any]]:
    """Загружает NDJSON-файл и возвращает список артефактов."""
    results: List[Dict[str, Any]] = []

    if not path.exists():
        logging.warning(f"[NDJSON] Файл не найден: {path}")
        return results

    try:
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError as e:
                    logging.warning(f"[NDJSON] Ошибка JSON в строке: {e}")
    except Exception as e:
        logging.error(f"[NDJSON] Ошибка чтения файла {path}: {e}", exc_info=True)

    logging.info(f"[NDJSON] Загружено {len(results)} артефактов из {path}")
    return results



if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler("logs/xss_ndjson.log", encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )

    responses = load_reflected_responses()
    print(f"Загружено {len(responses)} результатов")

    for r in responses[:3]:
        print(r.get("url"), r.get("category"), r.get("context"))
