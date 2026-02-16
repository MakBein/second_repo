# xss_security_gui/form_fuzzer.py

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


def report_threatintel(data: Dict[str, Any], gui_callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
    """
    Безопасная передача отчёта в Threat Intel.
    Передаём только метаданные: url, метод, payload, статус, категория, сниппет.
    """
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

    # ----------------------------
    # Подготовка данных
    # ----------------------------
    data = {key: payload for key in inputs}
    headers = build_aggressive_headers(payload)
    method_upper = method.upper()

    # ----------------------------
    # Нормализация URL
    # ----------------------------
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

    # ----------------------------
    # Отправка запроса
    # ----------------------------
    try:
        if method_upper == "POST":
            r = requests.post(
                normalized_url,
                data=data,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
            )
        else:
            r = requests.get(
                normalized_url,
                params=data,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
            )

        status = r.status_code
        response_text = _truncate_response(r.text)
        reflected = payload in response_text

        result = {
            "url": normalized_url,
            "method": method_upper,
            "inputs": inputs,
            "payload": payload,
            "status": status,
            "vulnerable": reflected,
            "category": None,
            "snippet": "",
            "response": response_text,
        }

        # ----------------------------
        # Анализ отражения
        # ----------------------------
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

            # Логирование
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

    # ----------------------------
    # Обработка ошибок
    # ----------------------------
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
    allowlist: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Запуск многопоточного фуззинга формы.

    Args:
        action_url: URL формы для тестирования
        method: HTTP метод (GET/POST)
        inputs: Список имён полей формы
        base_payloads: Базовые payload'ы (если None, загружаются из файла)
        max_workers: Максимальное количество потоков
        gui_callback: Опциональный callback для GUI
        timeout: Таймаут запросов в секундах
        allowlist: Список разрешённых префиксов URL (если None, проверка пропускается)

    Returns:
        Список результатов тестирования

    Raises:
        ValueError: Если URL не в allowlist или inputs пустой
    """
    # Валидация входных данных
    if not inputs:
        raise ValueError("inputs не может быть пустым")

    if not action_url:
        raise ValueError("action_url не может быть пустым")

    # Проверка allowlist
    if allowlist:
        if not any(action_url.startswith(prefix) for prefix in allowlist):
            raise ValueError(f"URL {action_url} не находится в allowlist")

    # Нормализация URL
    action_url = normalize_url(action_url)

    base_payloads = base_payloads or load_payloads()
    results = []

    # Расширяем мутации и добавляем агрессивные варианты
    # Используем list для сохранения порядка, но убираем дубликаты
    mutated_variants = []
    seen = set()

    for base in base_payloads:
        for variant in mutate_payload(base):
            if variant not in seen:
                seen.add(variant)
                mutated_variants.append(variant)

        # Добавляем агрессивные payload'ы
        for agg_payload in AGGRESSIVE_PAYLOADS:
            if agg_payload not in seen:
                seen.add(agg_payload)
                mutated_variants.append(agg_payload)

    logger.info(f"[FormFuzz] Запуск фуззинга {action_url} с {len(mutated_variants)} payload'ами")

    # Многопоточный запуск с обработкой исключений
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(fuzz_payload, action_url, method, inputs, p, gui_callback, timeout)
            for p in mutated_variants
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

    logger.info(f"[FormFuzz] Фуззинг завершён: {len(results)} результатов")
    return results