import os
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from xss_security_gui.payload_mutator import mutate_payload
from xss_security_gui.xss_detector import XSSDetector
from xss_security_gui.utils.core_utils import normalize_url
from xss_security_gui.http_headers import build_aggressive_headers

logger = logging.getLogger(__name__)

# Константы
DEFAULT_TIMEOUT = 4.0
DEFAULT_MAX_WORKERS = 20
SNIPPET_MAX_LENGTH = 300
SNIPPET_CONTEXT_WINDOW = 40
MAX_RESPONSE_SIZE = 10000

# Разрешённые HTTP-методы
ALLOWED_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
    "TRACE",
}

# Агрессивные payload'ы
AGGRESSIVE_PAYLOADS = [
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "{{7*7}}",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
]


def load_payloads(path: str = "payloads/xss.txt") -> List[str]:
    default = ["<script>alert(1)</script>"]
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    return default


def report_threatintel(
    data: Dict[str, Any],
    gui_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> None:
    if not gui_callback:
        return

    safe_report = {
        "module": "form_fuzzer",
        "url": data.get("url"),
        "method": data.get("method"),
        "payload": data.get("payload"),
        "status": data.get("status"),
        "vulnerable": data.get("vulnerable"),
        "category": data.get("category"),
        "snippet": data.get("snippet"),
        "error": data.get("error"),
    }
    gui_callback({"form_fuzzer": safe_report})


def create_aggressive_headers(payload: str) -> Dict[str, str]:
    return {
        "User-Agent": payload,
        "Referer": payload,
        "X-Forwarded-For": payload,
        "X-Requested-With": payload,
        "X-Api-Version": payload,
        "X-Original-URL": payload,
        "X-Rewrite-URL": payload,
        "X-Email": payload,
        "X-Account": payload,
        "X-Customer-ID": payload,
        "X-User-ID": payload,
        "X-Session-ID": payload,
        "X-Card-Number": payload,
        "X-Payment-Info": payload,
        "X-Search-Query": payload,
        "X-Debug": payload,
        "X-Test": payload,
        "Authorization": f"Bearer {payload}",
        "Cookie": f"session={payload}; token={payload}",
        "X-XSS-Vector": payload,
    }


def _truncate_response(text: str) -> str:
    if len(text) <= MAX_RESPONSE_SIZE:
        return text
    return text[:MAX_RESPONSE_SIZE] + f"\n...[Обрезано {len(text) - MAX_RESPONSE_SIZE} символов]"


def _build_error_result(
    url: str,
    method: str,
    inputs: List[str],
    payload: str,
    category: str,
    error: str,
) -> Dict[str, Any]:
    return {
        "url": url,
        "method": method,
        "inputs": inputs,
        "payload": payload,
        "status": None,
        "vulnerable": False,
        "error": error,
        "category": category,
        "snippet": "",
    }


def _send_request(
    url: str,
    method: str,
    data: Dict[str, Any],
    headers: Dict[str, str],
    timeout: float,
) -> requests.Response:
    """
    Универсальная отправка HTTP-запроса для любого метода.
    Для методов без тела (HEAD, OPTIONS, TRACE) данные передаются как params.
    """
    method_upper = method.upper()

    if method_upper not in ALLOWED_METHODS:
        raise ValueError(f"HTTP метод {method_upper} не поддерживается")

    # Методы, которые обычно используют тело запроса
    methods_with_body = {"POST", "PUT", "PATCH", "DELETE"}

    if method_upper in methods_with_body:
        return requests.request(
            method=method_upper,
            url=url,
            data=data,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
        )
    else:
        # GET, HEAD, OPTIONS, TRACE — параметры в query string
        return requests.request(
            method=method_upper,
            url=url,
            params=data,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
        )


def fuzz_payload(
    action_url: str,
    method: str,
    inputs: List[str],
    payload: str,
    gui_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    if not inputs:
        logger.warning(f"[FormFuzz] Пустой список inputs для {action_url}")
        result = _build_error_result(
            url=action_url,
            method=method,
            inputs=inputs,
            payload=payload,
            category="Error",
            error="Пустой список inputs",
        )
        report_threatintel(result, gui_callback)
        return result

    method_upper = method.upper()

    # Подготовка данных
    data = {key: payload for key in inputs}
    headers = build_aggressive_headers(payload)

    # Нормализация URL
    try:
        normalized_url = normalize_url(action_url)
    except Exception as e:
        result = _build_error_result(
            url=action_url,
            method=method_upper,
            inputs=inputs,
            payload=payload,
            category="URLNormalizeError",
            error=str(e),
        )
        report_threatintel(result, gui_callback)
        return result

    # Отправка запроса
    try:
        r = _send_request(
            url=normalized_url,
            method=method_upper,
            data=data,
            headers=headers,
            timeout=timeout,
        )

        status = r.status_code
        response_text = _truncate_response(r.text)
        reflected = payload in response_text

        result: Dict[str, Any] = {
            "url": normalized_url,
            "method": method_upper,
            "inputs": inputs,
            "payload": payload,
            "status": status,
            "vulnerable": reflected,
            "category": None,
            "snippet": "",
            "response": response_text,
            "error": None,
        }

        if reflected:
            detector = XSSDetector()
            ctx = detector.detect_xss_context(response_text, payload)
            inline_hits = detector.scan_inline_js_for_payload(response_text, payload)

            category = ctx or (inline_hits[0][0] if inline_hits else "Reflected HTML")

            if inline_hits:
                snippet = inline_hits[0][1]
            else:
                pos = response_text.find(payload)
                start = max(0, pos - SNIPPET_CONTEXT_WINDOW)
                end = pos + len(payload) + SNIPPET_CONTEXT_WINDOW
                snippet = response_text[start:end]

            result["category"] = category
            result["snippet"] = snippet.strip()[:SNIPPET_MAX_LENGTH]

            os.makedirs("logs", exist_ok=True)
            with open("logs/form_fuzz_hits.log", "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now()}] {category} XSS in {method_upper} → {normalized_url}\n")
                f.write(f"Inputs: {inputs}\nPayload: {payload}\nStatus: {status}\n")
                f.write(f"Snippet: {result['snippet']}\n\n")

            logger.warning(f"[Fuzz] {method_upper} {normalized_url} → ⚠️ {category} XSS [{status}]")
        else:
            logger.debug(f"[Fuzz] {method_upper} {normalized_url} → ✓ [{status}]")

        report_threatintel(result, gui_callback)
        return result

    except requests.Timeout as e:
        result = _build_error_result(
            url=action_url,
            method=method_upper,
            inputs=inputs,
            payload=payload,
            category="Timeout",
            error=str(e),
        )
        report_threatintel(result, gui_callback)
        return result

    except requests.RequestException as e:
        result = _build_error_result(
            url=action_url,
            method=method_upper,
            inputs=inputs,
            payload=payload,
            category="NetworkError",
            error=str(e),
        )
        report_threatintel(result, gui_callback)
        return result

    except Exception as e:
        result = _build_error_result(
            url=action_url,
            method=method_upper,
            inputs=inputs,
            payload=payload,
            category="UnexpectedError",
            error=str(e),
        )
        report_threatintel(result, gui_callback)
        return result


def fuzz_form(
    action_url: str,
    method: str,
    inputs: List[str],
    base_payloads: Optional[List[str]] = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
    gui_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    allowlist: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    if not inputs:
        raise ValueError("inputs не может быть пустым")

    if not action_url:
        raise ValueError("action_url не может быть пустым")

    method_upper = method.upper()
    if method_upper not in ALLOWED_METHODS:
        raise ValueError(f"HTTP метод {method_upper} не поддерживается")

    if allowlist and not any(action_url.startswith(prefix) for prefix in allowlist):
        raise ValueError(f"URL {action_url} не находится в allowlist")

    action_url = normalize_url(action_url)

    base_payloads = base_payloads or load_payloads()
    results: List[Dict[str, Any]] = []

    mutated_variants: List[str] = []
    seen: set[str] = set()

    for base in base_payloads:
        for variant in mutate_payload(base):
            if variant not in seen:
                seen.add(variant)
                mutated_variants.append(variant)

    for agg_payload in AGGRESSIVE_PAYLOADS:
        if agg_payload not in seen:
            seen.add(agg_payload)
            mutated_variants.append(agg_payload)

    logger.info(f"[FormFuzz] Запуск фуззинга {action_url} с {len(mutated_variants)} payload'ами ({method_upper})")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(
                fuzz_payload,
                action_url,
                method_upper,
                inputs,
                p,
                gui_callback,
                timeout,
            )
            for p in mutated_variants
        ]

        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                logger.error(f"[FormFuzz] Ошибка в потоке: {e}")
                results.append(
                    {
                        "url": action_url,
                        "method": method_upper,
                        "inputs": inputs,
                        "payload": "unknown",
                        "status": None,
                        "vulnerable": False,
                        "error": f"ThreadError: {str(e)}",
                        "category": "Error",
                        "snippet": "",
                    }
                )

    logger.info(f"[FormFuzz] Фуззинг завершён: {len(results)} результатов для {method_upper} {action_url}")
    return results