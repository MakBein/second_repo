# xss_security_gui/auto_modules/auto_modules.py
"""
Ultra auto-attack primitives: реальные HTTP-запросы через Session,
настройки из settings, ретраи, корректная сборка URL, безопасное логирование.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlparse, urlunparse

import requests

from xss_security_gui.net_utils import session_request_safe
from xss_security_gui.auto_modules.module_families import MODULE_FAMILIES
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR, ThreatConnector
from xss_security_gui.threat_data_loader import ThreatRisk

import logging
logger = logging.getLogger(__name__)


LogFunc = Callable[[str, str], None]

_WAF_HINTS = (
    "blocked",
    "forbidden",
    "access denied",
    "waf",
    "cloudflare",
    "captcha",
    "rate limit",
    "too many requests",
    "security policy",
    "request rejected",
    "mod_security",
    "akamai",
    "perimeterx",
)

_SENSITIVE_BODY_HINTS = (
    "admin",
    "root",
    "token",
    "jwt",
    "bearer",
    "password",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "private_key",
)

_DOM_RISK = (
    "innerhtml",
    "document.write",
    "location.hash",
    "eval(",
    "settimeout(",
    "dangerouslysetinnerhtml",
    "v-html",
    "ng-bind-html",
)


def _load_ultra_config() -> Dict[str, Any]:
    try:
        from xss_security_gui import settings as app_settings

        st = app_settings.settings
        delay = st.get("attack.auto_module_delay")
        if delay is None:
            delay = st.get("idor.delay", 0.35)
        return {
            "timeout": float(st.get("http.request_timeout", 10) or 10),
            "ua": str(st.get("http.default_user_agent", "XSS-Security-GUI-AutoAttack/Ultra")),
            "verify": bool(st.get("http.verify_ssl", False)),
            "delay": float(delay or 0.35),
            "max_body_sample": int(st.get("attack.max_body_sample", 400_000) or 400_000),
            "retries": int(st.get("attack.request_retries", 2) or 2),
            "proxies": st.get("http.proxies"),
            "max_endpoints_per_run": int(st.get("attack.max_auto_endpoints", 500) or 500),
            "max_token_attempts": int(st.get("attack.max_token_attempts", 80) or 80),
            "max_auth_headers": int(st.get("attack.max_auth_header_variants", 3) or 3),
        }
    except Exception:
        return {
            "timeout": 10.0,
            "ua": "XSS-Security-GUI-AutoAttack/Ultra",
            "verify": False,
            "delay": 0.35,
            "max_body_sample": 400_000,
            "retries": 2,
            "proxies": None,
            "max_endpoints_per_run": 500,
            "max_token_attempts": 80,
            "max_auth_headers": 3,
        }


def _safe_log(log: Optional[LogFunc], msg: str, level: str = "info") -> None:
    if log:
        try:
            log(msg, level)
        except Exception:
            pass


def _pace(cfg: Dict[str, Any]) -> None:
    d = float(cfg.get("delay", 0) or 0)
    if d > 0:
        time.sleep(d)


def _mask_secret(s: str, keep: int = 4) -> str:
    s = str(s)
    if len(s) <= keep * 2:
        return "***"
    return s[:keep] + "…" + s[-2:]


def _normalize_url(base_url: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    base = base_url.rstrip("/") + "/"
    return urljoin(base, path.lstrip("/"))


def _merge_query_params(base: str, new_params: Dict[str, Any]) -> str:
    p = urlparse(base)
    existing = parse_qs(p.query, keep_blank_values=True)
    for k, v in new_params.items():
        existing[str(k)] = [str(v)]
    pairs = []
    for key, vals in existing.items():
        for val in vals:
            pairs.append((key, val))
    new_query = urlencode(pairs, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))


def _sample_body(text: str, max_len: int) -> str:
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "\n…[truncated]"


def _classify_severity(
    status: int,
    reflected: bool = False,
    error: bool = False,
    waf_like: bool = False,
) -> str:
    if error:
        return "error"
    if waf_like:
        return "medium"
    if reflected:
        return "critical"
    if status >= 500:
        return "high"
    if status >= 400:
        return "medium"
    return "info"


def _waf_like(body: str) -> bool:
    low = (body or "").lower()
    return any(h in low for h in _WAF_HINTS)


def _sensitive_body(body: str) -> bool:
    low = (body or "").lower()
    return any(h in low for h in _SENSITIVE_BODY_HINTS)


def _extract_json(body: str) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def _looks_like_graphql(endpoint: str, body: str, resp_headers: Dict[str, str]) -> bool:
    if "graphql" in endpoint.lower():
        return True
    ct = (resp_headers.get("Content-Type") or "").lower()
    if "application/graphql" in ct or "graphql" in ct:
        return True
    if any(k in body for k in ("query", "mutation")) and "{" in body and "}" in body:
        return True
    return False


def _default_headers(cfg: Dict[str, Any]) -> Dict[str, str]:
    return {
        "User-Agent": cfg["ua"],
        "Accept": "text/html,application/json,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }


def _request_get(
    session: requests.Session,
    url: str,
    headers: Optional[Dict[str, str]],
    cfg: Dict[str, Any],
    log: Optional[LogFunc],
) -> Tuple[Optional[requests.Response], Optional[str]]:
    hdr = _default_headers(cfg)
    if headers:
        hdr.update(headers)
    resp, err = session_request_safe(
        session,
        "GET",
        url,
        headers=hdr,
        timeout=cfg["timeout"],
        verify=cfg["verify"],
        proxies=cfg["proxies"] if cfg.get("proxies") else None,
        retries=int(cfg["retries"]),
    )
    if err:
        _safe_log(log, f"[HTTP] GET fail {url[:120]}… → {err}", "debug")
    return resp, err


# ============================================================
#  API Endpoints (Ultra)
# ============================================================
def attack_api_endpoints(
    session: requests.Session,
    base_url: str,
    endpoints: List[str],
    headers_list: List[Dict[str, str]],
    log: Optional[LogFunc] = None,
) -> Dict[str, Any]:
    cfg = _load_ultra_config()
    cap = int(cfg["max_endpoints_per_run"])
    endpoints = list(endpoints)[:cap]
    if not headers_list:
        headers_list = [{}]

    module_name = "API Endpoints"
    meta = MODULE_FAMILIES.get(module_name, {})

    results: List[Dict[str, Any]] = []

    try:
        for ep in endpoints:
            url = _normalize_url(base_url, str(ep))
            for hdr in headers_list:
                _safe_log(log, f"[API] GET {url}", "debug")
                r, err = _request_get(session, url, hdr, cfg, log)
                _pace(cfg)

                if r is None:
                    results.append(
                        {
                            "endpoint": url,
                            "headers_used": hdr,
                            "error": err or "request_failed",
                            "severity": "error",
                        }
                    )
                    continue

                body = _sample_body(r.text or "", cfg["max_body_sample"])
                json_body = _extract_json(body)
                rh = dict(r.headers)
                is_graphql = _looks_like_graphql(url, body, rh)
                waf = _waf_like(body)

                results.append(
                    {
                        "endpoint": url,
                        "status": r.status_code,
                        "headers_used": hdr,
                        "content_type": r.headers.get("Content-Type", ""),
                        "length": len(r.text or ""),
                        "is_graphql": is_graphql,
                        "json_detected": json_body is not None,
                        "waf_or_block_page": waf,
                        "redirected": len(r.history) > 0,
                        "final_url": r.url,
                        "severity": _classify_severity(r.status_code, waf_like=waf),
                    }
                )

        return {
            "status": "ok",
            "count": len(results),
            "items": results,
            "family": meta.get("family", "-"),
            "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }

    except Exception as e:
        return {
            "status": "error",
            "count": 0,
            "items": [],
            "error": str(e),
            "family": meta.get("family", "-"),
            "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }


def _auth_header_variants(token: str, max_variants: int) -> List[Dict[str, str]]:
    t = token.strip()
    if not t:
        return []
    auth_raw = t if t.lower().startswith("bearer ") else f"Bearer {t}"
    variants: List[Dict[str, str]] = [
        {"Authorization": auth_raw},
        {"Authorization": f"Token {t}"},
        {"X-API-Key": t},
        {"X-Auth-Token": t},
    ]
    out: List[Dict[str, str]] = []
    seen = set()
    for h in variants:
        key = tuple(sorted(h.items()))
        if key not in seen:
            seen.add(key)
            out.append(h)
        if len(out) >= max_variants:
            break
    return out


# ============================================================
#  Token probing (Ultra) — используется AttackEngine
# ============================================================
def brute_force_tokens(
    session: requests.Session,
    base_url: str,
    tokens: List[str],
    log: Optional[LogFunc] = None,
) -> Dict[str, Any]:

    module_name = "Token Brute Force"
    meta = MODULE_FAMILIES.get(module_name, {})

    cfg = _load_ultra_config()
    max_attempts = int(cfg["max_token_attempts"])
    max_hdr = int(cfg["max_auth_headers"])

    results: List[Dict[str, Any]] = []
    attempt_no = 0

    try:
        for token in tokens:
            if attempt_no >= max_attempts:
                _safe_log(log, f"[TOKENS] лимит попыток {max_attempts}", "warn")
                break

            for hdr in _auth_header_variants(str(token), max_hdr):
                if attempt_no >= max_attempts:
                    break

                masked = _mask_secret(str(token))
                _safe_log(log, f"[TOKENS] GET {base_url} auth={hdr.keys()} token={masked}", "debug")

                r, err = _request_get(session, base_url, hdr, cfg, log)
                _pace(cfg)
                attempt_no += 1

                if r is None:
                    results.append({
                        "token_preview": masked,
                        "auth_headers": list(hdr.keys()),
                        "error": err or "request_failed",
                        "severity": "error",
                    })
                    continue

                body = _sample_body(r.text or "", cfg["max_body_sample"])
                suspicious = _sensitive_body(body)
                waf = _waf_like(body)
                status_shift = r.status_code not in (401, 403)

                results.append({
                    "token_preview": masked,
                    "auth_headers": list(hdr.keys()),
                    "status": r.status_code,
                    "length": len(r.text or ""),
                    "suspicious": suspicious,
                    "waf_or_block_page": waf,
                    "not_unauthorized": status_shift,
                    "severity": _classify_severity(
                        r.status_code,
                        reflected=False,
                        error=False,
                        waf_like=waf,
                    ),
                })

        return {
            "status": "ok",
            "count": len(results),
            "items": results,
            "family": meta.get("family", "-"),
            "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }

    except Exception as e:
        return {
            "status": "error",
            "count": 0,
            "items": [],
            "error": str(e),
            "family": meta.get("family", "-"),
            "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }


# ============================================================
#  Parameters (Ultra)
# ============================================================
def attack_parameters(
    session: requests.Session,
    base_url: str,
    parameters: List[str],
    log: Optional[LogFunc] = None,
) -> Dict[str, Any]:

    module_name = "Parameters Discovery"
    meta = MODULE_FAMILIES.get(module_name, {})

    cfg = _load_ultra_config()
    probe = "xss_auto_probe_ultra"
    results: List[Dict[str, Any]] = []

    try:
        for param in parameters:
            pname = str(param).strip()
            if not pname:
                continue

            url = _merge_query_params(base_url, {pname: probe})
            _safe_log(log, f"[PARAM] GET {url[:200]}", "debug")

            r, err = _request_get(session, url, None, cfg, log)
            _pace(cfg)

            if r is None:
                results.append({
                    "parameter": pname,
                    "url": url,
                    "error": err or "request_failed",
                    "severity": "error",
                })
                continue

            body = r.text or ""
            reflected = probe in body

            enc = quote(probe, safe="")
            encoded_hit = enc in body or ("+" in enc and enc.replace("+", "%20") in body)

            waf = _waf_like(body)

            results.append({
                "parameter": pname,
                "url": url,
                "status": r.status_code,
                "reflected": reflected or encoded_hit,
                "length": len(body),
                "waf_or_block_page": waf,
                "severity": _classify_severity(
                    r.status_code,
                    reflected=reflected,
                    waf_like=waf
                ),
            })

        return {
            "status": "ok",
            "count": len(results),
            "items": results,
            "family": meta.get("family", "-"),
            "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }

    except Exception as e:
        return {
            "status": "error",
            "count": 0,
            "items": [],
            "error": str(e),
            "family": meta.get("family", "-"),
            "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }


# ============================================================
#  User IDs (Ultra)
# ============================================================
def attack_user_ids(
    session: requests.Session,
    base_url: str,
    user_ids: List[Any],
    log: Optional[LogFunc] = None,
) -> Dict[str, Any]:

    module_name = "User IDs Enumeration"
    meta = MODULE_FAMILIES.get(module_name, {})

    cfg = _load_ultra_config()

    try:
        from xss_security_gui import settings as app_settings
        extra = app_settings.settings.get("attack.user_id_param_names")
        if isinstance(extra, (list, tuple)) and extra:
            id_param_names = tuple(str(x) for x in extra)
        else:
            id_param_names = ("id", "user_id")
    except Exception:
        id_param_names = ("id", "user_id")

    results: List[Dict[str, Any]] = []

    try:
        for uid in user_ids:
            for pname in id_param_names:
                url = _merge_query_params(base_url, {pname: str(uid)})
                _safe_log(log, f"[USER] GET {url[:200]}", "debug")

                r, err = _request_get(session, url, None, cfg, log)
                _pace(cfg)

                if r is None:
                    results.append({
                        "user_id": uid,
                        "param": pname,
                        "url": url,
                        "error": err or "request_failed",
                        "severity": "error",
                    })
                    continue

                body = r.text or ""
                leaked_email = bool(
                    re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", body)
                )
                diff_status = r.status_code == 200 and len(body) > 200
                waf = _waf_like(body)

                results.append({
                    "user_id": uid,
                    "param": pname,
                    "url": url,
                    "status": r.status_code,
                    "length": len(body),
                    "leaked_email": leaked_email,
                    "substantial_body": diff_status,
                    "waf_or_block_page": waf,
                    "severity": _classify_severity(r.status_code, waf_like=waf),
                })

        return {
            "status": "ok",
            "count": len(results),
            "items": results,
            "family": meta.get("family", "-"),
            "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }

    except Exception as e:
        return {
            "status": "error",
            "count": 0,
            "items": [],
            "error": str(e),
            "family": meta.get("family", "-"),
            "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }


# ============================================================
#  XSS Targets (Ultra)
# ============================================================
def attack_xss_targets(
    session: requests.Session,
    base_url: str,
    targets: List[Any],
    log: Optional[LogFunc] = None,
) -> Dict[str, Any]:

    module_name = "XSS Targets"
    meta = MODULE_FAMILIES.get(module_name, {})

    cfg = _load_ultra_config()
    results: List[Dict[str, Any]] = []

    try:
        for t in targets:
            if isinstance(t, dict):
                url = t.get("url") or base_url
                payload = t.get("payload") or t.get("raw_payload") or "xss_test_ultra"
                context = t.get("context") or "generic"
                param_name = t.get("param") or t.get("parameter") or "x"
            else:
                url = base_url
                payload = str(t)
                context = "generic"
                param_name = "x"

            full_url = _merge_query_params(str(url), {str(param_name): str(payload)})
            _safe_log(log, f"[XSS] GET ctx={context} url={full_url[:180]}…", "debug")

            r, err = _request_get(session, full_url, None, cfg, log)
            _pace(cfg)

            if r is None:
                results.append({
                    "url": full_url,
                    "base_url": url,
                    "payload": payload,
                    "param": param_name,
                    "context": context,
                    "error": err or "request_failed",
                    "severity": "error",
                })
                continue

            body = r.text or ""
            reflected = str(payload) in body
            dom_suspicious = any(k in body.lower() for k in _DOM_RISK)
            waf = _waf_like(body)

            results.append({
                "url": full_url,
                "base_url": url,
                "payload": payload,
                "param": param_name,
                "context": context,
                "status": r.status_code,
                "reflected": reflected,
                "length": len(body),
                "dom_suspicious": dom_suspicious,
                "waf_or_block_page": waf,
                "severity": _classify_severity(
                    r.status_code,
                    reflected=reflected,
                    waf_like=waf
                ),
            })

        return {
            "status": "ok",
            "count": len(results),
            "items": results,
            "family": meta.get("family", "-"),
            "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }

    except Exception as e:
        return {
            "status": "error",
            "count": 0,
            "items": [],
            "error": str(e),
            "family": meta.get("family", "-"),
            "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }


# ============================================================
#  Forms & Inputs (Ultra) — генерация тестовых данных для форм
# ============================================================
def attack_forms_inputs(
    session: requests.Session,
    base_url: str,
    forms_data: List[Dict[str, Any]],
    log: Optional[LogFunc] = None,
) -> Dict[str, Any]:

    module_name = "Forms & Inputs"
    meta = MODULE_FAMILIES.get(module_name, {})

    cfg = _load_ultra_config()

    try:
        from xss_security_gui.data_generator import generate_form_data

        results: List[Dict[str, Any]] = []

        for form_info in forms_data:
            if isinstance(form_info, dict):
                form_url = form_info.get("url", base_url)
                fields = form_info.get("fields", [])
                method = form_info.get("method", "POST").upper()
            else:
                form_url = base_url
                fields = []
                method = "POST"

            if not fields:
                # Если поля не указаны, генерируем стандартный набор
                fields = ["name", "email", "password", "phone", "address", "credit_card"]

            # Генерируем тестовые данные для формы
            test_data_list = generate_form_data(fields, count=5)

            for test_data in test_data_list:
                # Отправляем тестовые данные на форму
                try:
                    if method == "POST":
                        response = session.post(form_url, data=test_data, timeout=cfg["timeout"])
                    else:
                        # Для GET добавляем параметры в URL
                        params_url = _merge_query_params(form_url, test_data)
                        response = session.get(params_url, timeout=cfg["timeout"])

                    _pace(cfg)

                    body = _sample_body(response.text or "", cfg["max_body_sample"])
                    waf = _waf_like(body)

                    # Проверяем, отражаются ли данные в ответе (потенциальная XSS)
                    reflected_fields = []
                    for field, value in test_data.items():
                        if str(value) in body:
                            reflected_fields.append(field)

                    results.append({
                        "form_url": form_url,
                        "method": method,
                        "test_data": test_data,
                        "status": response.status_code,
                        "length": len(response.text or ""),
                        "reflected_fields": reflected_fields,
                        "waf_or_block_page": waf,
                        "severity": _classify_severity(
                            response.status_code,
                            reflected=bool(reflected_fields),
                            waf_like=waf
                        ),
                    })

                except Exception as e:
                    results.append({
                        "form_url": form_url,
                        "method": method,
                        "test_data": test_data,
                        "error": str(e),
                        "severity": "error",
                    })

        return {
            "status": "ok",
            "count": len(results),
            "items": results,
            "family": meta.get("family", "-"),
            "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }

    except Exception as e:
        return {
            "status": "error",
            "count": 0,
            "items": [],
            "error": str(e),
            "family": meta.get("family", "-"),
            "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }

# ============================================================
#  CORS Misconfiguration Check (Ultra)
# ============================================================
def attack_cors(
    session: requests.Session,
    base_url: str,
    endpoints: List[str],
    log: Optional[LogFunc] = None,
) -> Dict[str, Any]:
    module_name = "CORS Misconfiguration"
    meta = MODULE_FAMILIES.get(module_name, {})
    cfg = _load_ultra_config()
    results: List[Dict[str, Any]] = []

    evil_origins = [
        "https://evil.com",
        "https://attacker.example.com",
        "null",
        base_url.rstrip("/") + ".evil.com",
    ]

    try:
        test_urls = [base_url] + [_normalize_url(base_url, ep) for ep in (endpoints or [])[:20]]
        for url in test_urls:
            for origin in evil_origins:
                hdr = _default_headers(cfg)
                hdr["Origin"] = origin
                r, err = _request_get(session, url, hdr, cfg, log)
                _pace(cfg)

                if r is None:
                    results.append({
                        "url": url, "origin": origin,
                        "error": err or "request_failed", "severity": "error",
                    })
                    continue

                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
                misconfigured = False
                details = []

                if acao == "*":
                    misconfigured = True
                    details.append("wildcard_acao")
                if acao == origin and origin != base_url:
                    misconfigured = True
                    details.append("origin_reflected")
                if acac == "true" and acao != "":
                    misconfigured = True
                    details.append("credentials_with_acao")
                if acao == "null":
                    misconfigured = True
                    details.append("null_origin_allowed")

                results.append({
                    "url": url, "origin": origin,
                    "acao": acao, "acac": acac,
                    "misconfigured": misconfigured,
                    "details": details,
                    "status": r.status_code,
                    "severity": "critical" if misconfigured and acac == "true" else
                                "high" if misconfigured else "info",
                })

        return {
            "status": "ok", "count": len(results), "items": results,
            "family": meta.get("family", "-"), "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }
    except Exception as e:
        return {
            "status": "error", "count": 0, "items": [], "error": str(e),
            "family": meta.get("family", "-"), "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }


# ============================================================
#  Security Headers Audit (Ultra)
# ============================================================
_EXPECTED_HEADERS = {
    "Strict-Transport-Security": "HSTS missing — no forced HTTPS",
    "X-Content-Type-Options": "X-Content-Type-Options missing — MIME sniffing possible",
    "X-Frame-Options": "X-Frame-Options missing — clickjacking possible",
    "Content-Security-Policy": "CSP missing — XSS risk elevated",
    "X-XSS-Protection": "X-XSS-Protection missing (legacy but useful)",
    "Referrer-Policy": "Referrer-Policy missing — referrer leakage",
    "Permissions-Policy": "Permissions-Policy missing — feature abuse possible",
    "Cache-Control": "Cache-Control missing — sensitive data caching",
}

_DANGEROUS_HEADERS = {
    "Server": "Server header exposes technology",
    "X-Powered-By": "X-Powered-By exposes framework",
    "X-AspNet-Version": "ASP.NET version exposed",
    "X-AspNetMvc-Version": "ASP.NET MVC version exposed",
}


def attack_security_headers(
    session: requests.Session,
    base_url: str,
    endpoints: List[str],
    log: Optional[LogFunc] = None,
) -> Dict[str, Any]:
    module_name = "Security Headers Audit"
    meta = MODULE_FAMILIES.get(module_name, {})
    cfg = _load_ultra_config()
    results: List[Dict[str, Any]] = []

    try:
        test_urls = [base_url] + [_normalize_url(base_url, ep) for ep in (endpoints or [])[:10]]
        for url in test_urls:
            r, err = _request_get(session, url, None, cfg, log)
            _pace(cfg)

            if r is None:
                results.append({
                    "url": url, "error": err or "request_failed", "severity": "error",
                })
                continue

            rh = {k.lower(): v for k, v in r.headers.items()}
            missing = []
            for hdr_name, desc in _EXPECTED_HEADERS.items():
                if hdr_name.lower() not in rh:
                    missing.append({"header": hdr_name, "issue": desc})

            exposed = []
            for hdr_name, desc in _DANGEROUS_HEADERS.items():
                val = rh.get(hdr_name.lower())
                if val:
                    exposed.append({"header": hdr_name, "value": val, "issue": desc})

            sev = "info"
            if len(missing) >= 4:
                sev = "high"
            elif len(missing) >= 2:
                sev = "medium"
            if exposed:
                sev = max(sev, "medium", key=lambda x: ["info", "medium", "high", "critical"].index(x))

            results.append({
                "url": url, "status": r.status_code,
                "missing_headers": missing, "exposed_headers": exposed,
                "missing_count": len(missing), "exposed_count": len(exposed),
                "severity": sev,
            })

        return {
            "status": "ok", "count": len(results), "items": results,
            "family": meta.get("family", "-"), "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }
    except Exception as e:
        return {
            "status": "error", "count": 0, "items": [], "error": str(e),
            "family": meta.get("family", "-"), "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }


# ============================================================
#  Open Redirect Check (Ultra)
# ============================================================
_REDIRECT_PARAMS = ("url", "redirect", "next", "return", "returnUrl", "redirect_uri",
                     "continue", "dest", "destination", "redir", "target", "go", "out",
                     "view", "ref", "callback")

_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%00.target.com",
    "https://evil.com%2F%2F",
    "////evil.com",
    "https:evil.com",
]


def attack_open_redirect(
    session: requests.Session,
    base_url: str,
    log: Optional[LogFunc] = None,
) -> Dict[str, Any]:
    module_name = "Open Redirect"
    meta = MODULE_FAMILIES.get(module_name, {})
    cfg = _load_ultra_config()
    results: List[Dict[str, Any]] = []

    try:
        for param in _REDIRECT_PARAMS:
            for payload in _REDIRECT_PAYLOADS:
                url = _merge_query_params(base_url, {param: payload})
                _safe_log(log, f"[REDIRECT] GET {url[:200]}", "debug")

                r, err = _request_get(session, url, None, cfg, log)
                _pace(cfg)

                if r is None:
                    results.append({
                        "param": param, "payload": payload, "url": url,
                        "error": err or "request_failed", "severity": "error",
                    })
                    continue

                redirected_to_evil = False
                if r.history:
                    for hist_resp in r.history:
                        loc = hist_resp.headers.get("Location", "")
                        if "evil.com" in loc:
                            redirected_to_evil = True
                            break
                if "evil.com" in r.url:
                    redirected_to_evil = True

                results.append({
                    "param": param, "payload": payload, "url": url,
                    "status": r.status_code,
                    "final_url": r.url,
                    "redirected": len(r.history) > 0,
                    "open_redirect": redirected_to_evil,
                    "severity": "high" if redirected_to_evil else "info",
                })

                if redirected_to_evil:
                    break

        return {
            "status": "ok", "count": len(results), "items": results,
            "family": meta.get("family", "-"), "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }
    except Exception as e:
        return {
            "status": "error", "count": 0, "items": [], "error": str(e),
            "family": meta.get("family", "-"), "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }


# ============================================================
#  CRLF Injection Check (Ultra)
# ============================================================
_CRLF_PAYLOADS = [
    "%0d%0aX-Injected: true",
    "%0aX-Injected: true",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "\\r\\nX-Injected: true",
    "%E5%98%8A%E5%98%8DX-Injected: true",
]


def attack_crlf(
    session: requests.Session,
    base_url: str,
    log: Optional[LogFunc] = None,
) -> Dict[str, Any]:
    module_name = "CRLF Injection"
    meta = MODULE_FAMILIES.get(module_name, {})
    cfg = _load_ultra_config()
    results: List[Dict[str, Any]] = []

    try:
        for payload in _CRLF_PAYLOADS:
            url = base_url.rstrip("/") + "/" + payload
            _safe_log(log, f"[CRLF] GET {url[:200]}", "debug")

            r, err = _request_get(session, url, None, cfg, log)
            _pace(cfg)

            if r is None:
                results.append({
                    "payload": payload, "url": url,
                    "error": err or "request_failed", "severity": "error",
                })
                continue

            injected = "X-Injected" in str(r.headers)
            body_injected = "<script>alert(1)</script>" in (r.text or "")

            results.append({
                "payload": payload, "url": url,
                "status": r.status_code,
                "header_injected": injected,
                "body_injected": body_injected,
                "severity": "critical" if injected or body_injected else "info",
            })

        return {
            "status": "ok", "count": len(results), "items": results,
            "family": meta.get("family", "-"), "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }
    except Exception as e:
        return {
            "status": "error", "count": 0, "items": [], "error": str(e),
            "family": meta.get("family", "-"), "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }


# ============================================================
#  HTTP Method Tampering (Ultra)
# ============================================================
_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]


def attack_http_methods(
    session: requests.Session,
    base_url: str,
    endpoints: List[str],
    log: Optional[LogFunc] = None,
) -> Dict[str, Any]:
    module_name = "HTTP Method Tampering"
    meta = MODULE_FAMILIES.get(module_name, {})
    cfg = _load_ultra_config()
    results: List[Dict[str, Any]] = []

    try:
        test_urls = [base_url] + [_normalize_url(base_url, ep) for ep in (endpoints or [])[:15]]
        for url in test_urls:
            method_results = {}
            for method in _HTTP_METHODS:
                try:
                    hdr = _default_headers(cfg)
                    r = session.request(
                        method, url, headers=hdr,
                        timeout=cfg["timeout"], verify=cfg["verify"],
                        allow_redirects=True,
                    )
                    method_results[method] = r.status_code
                    _pace(cfg)
                except Exception:
                    method_results[method] = -1

            trace_ok = method_results.get("TRACE", -1) == 200
            options_resp = method_results.get("OPTIONS", -1)
            unexpected_200 = [m for m, s in method_results.items()
                              if s == 200 and m not in ("GET", "HEAD", "OPTIONS")]

            sev = "info"
            if trace_ok:
                sev = "high"
            elif unexpected_200:
                sev = "medium"

            results.append({
                "url": url,
                "method_responses": method_results,
                "trace_enabled": trace_ok,
                "unexpected_200_methods": unexpected_200,
                "severity": sev,
            })

        return {
            "status": "ok", "count": len(results), "items": results,
            "family": meta.get("family", "-"), "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }
    except Exception as e:
        return {
            "status": "error", "count": 0, "items": [], "error": str(e),
            "family": meta.get("family", "-"), "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }


# ============================================================
#  Technology Fingerprint (Ultra)
# ============================================================
_TECH_PATTERNS = {
    "Apache": re.compile(r"Apache[/ ]?([\d.]+)?", re.I),
    "Nginx": re.compile(r"nginx[/ ]?([\d.]+)?", re.I),
    "IIS": re.compile(r"Microsoft-IIS[/ ]?([\d.]+)?", re.I),
    "PHP": re.compile(r"PHP[/ ]?([\d.]+)?", re.I),
    "ASP.NET": re.compile(r"ASP\.NET|X-AspNet", re.I),
    "Express": re.compile(r"Express", re.I),
    "Django": re.compile(r"django|csrfmiddlewaretoken", re.I),
    "Rails": re.compile(r"X-Runtime|X-Request-Id.*rails", re.I),
    "Spring": re.compile(r"X-Application-Context|Whitelabel Error", re.I),
    "Cloudflare": re.compile(r"cloudflare|cf-ray", re.I),
    "AWS": re.compile(r"x-amz-|AmazonS3|awselb", re.I),
    "WordPress": re.compile(r"wp-content|wp-includes|wordpress", re.I),
    "jQuery": re.compile(r"jquery[.-]?([\d.]+)?\.(?:min\.)?js", re.I),
    "React": re.compile(r"__NEXT_DATA__|_react|reactroot", re.I),
    "Vue.js": re.compile(r"v-cloak|vue\.(?:min\.)?js|__vue__", re.I),
    "Angular": re.compile(r"ng-version|ng-app|angular", re.I),
}


def attack_fingerprint(
    session: requests.Session,
    base_url: str,
    log: Optional[LogFunc] = None,
) -> Dict[str, Any]:
    module_name = "Technology Fingerprint"
    meta = MODULE_FAMILIES.get(module_name, {})
    cfg = _load_ultra_config()
    results: List[Dict[str, Any]] = []

    try:
        r, err = _request_get(session, base_url, None, cfg, log)
        if r is None:
            return {
                "status": "error", "count": 0, "items": [],
                "error": err or "request_failed",
                "family": meta.get("family", "-"), "risk": meta.get("risk", "-"),
                "tags": meta.get("tags", []),
            }

        headers_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body = _sample_body(r.text or "", cfg["max_body_sample"])
        combined = headers_str + "\n" + body

        detected: List[Dict[str, str]] = []
        for tech, pattern in _TECH_PATTERNS.items():
            m = pattern.search(combined)
            if m:
                version = m.group(1) if m.lastindex and m.group(1) else "unknown"
                detected.append({"technology": tech, "version": version})

        results.append({
            "url": base_url,
            "status": r.status_code,
            "technologies": detected,
            "tech_count": len(detected),
            "severity": "medium" if len(detected) >= 3 else "info",
        })

        return {
            "status": "ok", "count": len(results), "items": results,
            "family": meta.get("family", "-"), "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }
    except Exception as e:
        return {
            "status": "error", "count": 0, "items": [], "error": str(e),
            "family": meta.get("family", "-"), "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }


# ============================================================
#  Path Traversal Check (Ultra)
# ============================================================
_PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "....\\\\....\\\\....\\\\windows\\\\win.ini",
]

_PATH_TRAVERSAL_INDICATORS = (
    "root:", "[extensions]", "[fonts]", "daemon:", "bin/bash",
    "nobody:", "[boot loader]",
)


def attack_path_traversal(
    session: requests.Session,
    base_url: str,
    parameters: List[str],
    log: Optional[LogFunc] = None,
) -> Dict[str, Any]:
    module_name = "Path Traversal"
    meta = MODULE_FAMILIES.get(module_name, {})
    cfg = _load_ultra_config()
    results: List[Dict[str, Any]] = []

    if not parameters:
        parameters = ["file", "path", "page", "doc", "folder", "dir", "template", "include"]

    try:
        for param in parameters[:10]:
            for payload in _PATH_TRAVERSAL_PAYLOADS:
                url = _merge_query_params(base_url, {param: payload})
                _safe_log(log, f"[LFI] GET {url[:200]}", "debug")

                r, err = _request_get(session, url, None, cfg, log)
                _pace(cfg)

                if r is None:
                    results.append({
                        "param": param, "payload": payload, "url": url,
                        "error": err or "request_failed", "severity": "error",
                    })
                    continue

                body = r.text or ""
                traversal_found = any(ind in body for ind in _PATH_TRAVERSAL_INDICATORS)

                results.append({
                    "param": param, "payload": payload, "url": url,
                    "status": r.status_code,
                    "traversal_found": traversal_found,
                    "length": len(body),
                    "severity": "critical" if traversal_found else "info",
                })

                if traversal_found:
                    break

        return {
            "status": "ok", "count": len(results), "items": results,
            "family": meta.get("family", "-"), "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }
    except Exception as e:
        return {
            "status": "error", "count": 0, "items": [], "error": str(e),
            "family": meta.get("family", "-"), "risk": meta.get("risk", "-"),
            "tags": meta.get("tags", []),
        }


class AutoModulesEngine:
    """
    AutoModules 13.0 ULTRA‑MODE (GOD‑ENGINE):

    - Обгортає примітиви attack_api_endpoints / brute_force_tokens / attack_parameters / attack_user_ids /
      attack_xss_targets / attack_forms_inputs
    - Дає:
        * unified result schema
        * risk scoring + severity normalization
        * entropy + heatmap
        * ML‑hooks
        * ThreatConnector ingestion
        * event‑stream (on_event)
    """

    def __init__(
        self,
        connector: Optional[ThreatConnector] = None,
        on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        debug_telemetry: bool = False,
    ) -> None:
        self.connector: ThreatConnector = connector or THREAT_CONNECTOR
        self.on_event = on_event
        self.debug_telemetry = debug_telemetry
        self.heatmap: Dict[str, int] = {}
        self.last_ml_prediction: Optional[Any] = None

    def _log_debug(self, msg: str) -> None:
        if self.debug_telemetry:
            logger.info(f"[AutoModulesEngine] {msg}")

    # -----------------------------
    #  Unified ingestion
    # -----------------------------
    def _ingest_result(
        self,
        module_name: str,
        raw_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Приводить результат примітиву до unified schema + додає risk / severity / entropy.
        """
        items = raw_result.get("items") or []
        family = raw_result.get("family") or MODULE_FAMILIES.get(module_name, {}).get("family", module_name)
        base_risk = raw_result.get("risk") or MODULE_FAMILIES.get(module_name, {}).get("risk", "info")
        tags = raw_result.get("tags") or MODULE_FAMILIES.get(module_name, {}).get("tags", [])

        # Heatmap counters
        self.heatmap.setdefault(module_name, 0)
        self.heatmap[module_name] += len(items)

        # Normalize each item
        normalized_items: List[Dict[str, Any]] = []
        for it in items:
            sev_raw = it.get("severity") or base_risk
            sev_norm = ThreatRisk.normalize(sev_raw)
            it["severity"] = sev_norm
            normalized_items.append(it)

        # Entropy (простий: по JSON)
        entropy_val = 0.0
        try:
            import math
            blob = json.dumps(normalized_items, ensure_ascii=False)
            freq: Dict[str, int] = {}
            for c in blob:
                freq[c] = freq.get(c, 0) + 1
            total = len(blob) or 1
            entropy_val = round(
                -sum((f / total) * math.log2(f / total) for f in freq.values()),
                3,
            )
        except Exception:
            entropy_val = 0.0

        unified = {
            "module": module_name,
            "family": family,
            "risk": base_risk,
            "tags": tags,
            "status": raw_result.get("status", "ok"),
            "count": len(normalized_items),
            "items": normalized_items,
            "entropy": entropy_val,
        }

        # ThreatConnector ingestion
        try:
            self.connector.ingest_artifact(
                {
                    "module": module_name,
                    "family": family,
                    "result": unified,
                }
            )
        except Exception:
            logger.exception("[AutoModulesEngine] ThreatConnector ingest error")

        # Event‑stream
        cb = self.on_event
        if callable(cb):
            try:
                cb("auto_module_result_ultra", unified)
            except Exception:
                logger.exception("[AutoModulesEngine] on_event callback error")

        self._log_debug(
            f"{module_name}: items={unified['count']} risk={unified['risk']} entropy={unified['entropy']}"
        )
        return unified

    # -----------------------------
    #  ML‑hook (optional)
    # -----------------------------
    def _ml_classify(self, summary: Dict[str, Any]) -> None:
        try:
            from xss_security_gui.ai_core.nn_model import nn_model_predict
            pred = nn_model_predict(summary)
            self.last_ml_prediction = pred

            cb = self.on_event
            if callable(cb):
                cb("auto_modules_ml_ultra", {
                    "prediction": pred,
                    "summary": summary
                })

        except Exception:
            self.last_ml_prediction = None

    # -----------------------------
    #  Public ULTRA‑MODE wrappers
    # -----------------------------
    def run_api_endpoints(
        self,
        session: requests.Session,
        base_url: str,
        endpoints: List[str],
        headers_list: List[Dict[str, str]],
        log: Optional[LogFunc] = None,
    ) -> Dict[str, Any]:
        raw = attack_api_endpoints(session, base_url, endpoints, headers_list, log)
        return self._ingest_result("API Endpoints", raw)

    def run_token_bruteforce(
        self,
        session: requests.Session,
        base_url: str,
        tokens: List[str],
        log: Optional[LogFunc] = None,
    ) -> Dict[str, Any]:
        raw = brute_force_tokens(session, base_url, tokens, log)
        return self._ingest_result("Token Brute Force", raw)

    def run_parameters(
        self,
        session: requests.Session,
        base_url: str,
        parameters: List[str],
        log: Optional[LogFunc] = None,
    ) -> Dict[str, Any]:
        raw = attack_parameters(session, base_url, parameters, log)
        return self._ingest_result("Parameters Discovery", raw)

    def run_user_ids(
        self,
        session: requests.Session,
        base_url: str,
        user_ids: List[Any],
        log: Optional[LogFunc] = None,
    ) -> Dict[str, Any]:
        raw = attack_user_ids(session, base_url, user_ids, log)
        return self._ingest_result("User IDs Enumeration", raw)

    def run_xss_targets(
        self,
        session: requests.Session,
        base_url: str,
        targets: List[Any],
        log: Optional[LogFunc] = None,
    ) -> Dict[str, Any]:
        raw = attack_xss_targets(session, base_url, targets, log)
        return self._ingest_result("XSS Targets", raw)

    def run_forms_inputs(
        self,
        session: requests.Session,
        base_url: str,
        forms_data: List[Dict[str, Any]],
        log: Optional[LogFunc] = None,
    ) -> Dict[str, Any]:
        raw = attack_forms_inputs(session, base_url, forms_data, log)
        return self._ingest_result("Forms & Inputs", raw)

    def run_cors(
        self,
        session: requests.Session,
        base_url: str,
        endpoints: List[str],
        log: Optional[LogFunc] = None,
    ) -> Dict[str, Any]:
        raw = attack_cors(session, base_url, endpoints, log)
        return self._ingest_result("CORS Misconfiguration", raw)

    def run_security_headers(
        self,
        session: requests.Session,
        base_url: str,
        endpoints: List[str],
        log: Optional[LogFunc] = None,
    ) -> Dict[str, Any]:
        raw = attack_security_headers(session, base_url, endpoints, log)
        return self._ingest_result("Security Headers Audit", raw)

    def run_open_redirect(
        self,
        session: requests.Session,
        base_url: str,
        log: Optional[LogFunc] = None,
    ) -> Dict[str, Any]:
        raw = attack_open_redirect(session, base_url, log)
        return self._ingest_result("Open Redirect", raw)

    def run_crlf(
        self,
        session: requests.Session,
        base_url: str,
        log: Optional[LogFunc] = None,
    ) -> Dict[str, Any]:
        raw = attack_crlf(session, base_url, log)
        return self._ingest_result("CRLF Injection", raw)

    def run_http_methods(
        self,
        session: requests.Session,
        base_url: str,
        endpoints: List[str],
        log: Optional[LogFunc] = None,
    ) -> Dict[str, Any]:
        raw = attack_http_methods(session, base_url, endpoints, log)
        return self._ingest_result("HTTP Method Tampering", raw)

    def run_fingerprint(
        self,
        session: requests.Session,
        base_url: str,
        log: Optional[LogFunc] = None,
    ) -> Dict[str, Any]:
        raw = attack_fingerprint(session, base_url, log)
        return self._ingest_result("Technology Fingerprint", raw)

    def run_path_traversal(
        self,
        session: requests.Session,
        base_url: str,
        parameters: List[str],
        log: Optional[LogFunc] = None,
    ) -> Dict[str, Any]:
        raw = attack_path_traversal(session, base_url, parameters, log)
        return self._ingest_result("Path Traversal", raw)

    # -----------------------------
    #  Run ALL modules (full scan)
    # -----------------------------
    def run_full_scan(
        self,
        session: requests.Session,
        base_url: str,
        endpoints: List[str] | None = None,
        parameters: List[str] | None = None,
        tokens: List[str] | None = None,
        user_ids: List[Any] | None = None,
        xss_targets: List[Any] | None = None,
        forms_data: List[Dict[str, Any]] | None = None,
        headers_list: List[Dict[str, str]] | None = None,
        log: Optional[LogFunc] = None,
        selected_modules: List[str] | None = None,
        cancel_flag: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """
        Запускает все (или выбранные) модули последовательно.
        cancel_flag — callable, возвращающий True если нужно прервать.
        """
        endpoints = endpoints or []
        parameters = parameters or []
        tokens = tokens or []
        user_ids = user_ids or []
        xss_targets = xss_targets or []
        forms_data = forms_data or []
        headers_list = headers_list or [{}]

        all_modules = {
            "Technology Fingerprint": lambda: self.run_fingerprint(session, base_url, log),
            "Security Headers Audit": lambda: self.run_security_headers(session, base_url, endpoints, log),
            "CORS Misconfiguration": lambda: self.run_cors(session, base_url, endpoints, log),
            "HTTP Method Tampering": lambda: self.run_http_methods(session, base_url, endpoints, log),
            "API Endpoints": lambda: self.run_api_endpoints(session, base_url, endpoints, headers_list, log),
            "Parameters Discovery": lambda: self.run_parameters(session, base_url, parameters, log),
            "XSS Targets": lambda: self.run_xss_targets(session, base_url, xss_targets, log),
            "Path Traversal": lambda: self.run_path_traversal(session, base_url, parameters, log),
            "Open Redirect": lambda: self.run_open_redirect(session, base_url, log),
            "CRLF Injection": lambda: self.run_crlf(session, base_url, log),
            "Token Brute Force": lambda: self.run_token_bruteforce(session, base_url, tokens, log),
            "User IDs Enumeration": lambda: self.run_user_ids(session, base_url, user_ids, log),
            "Forms & Inputs": lambda: self.run_forms_inputs(session, base_url, forms_data, log),
        }

        if selected_modules:
            modules_to_run = {k: v for k, v in all_modules.items() if k in selected_modules}
        else:
            modules_to_run = all_modules

        scan_results: Dict[str, Any] = {}
        total = len(modules_to_run)
        done = 0

        for name, runner in modules_to_run.items():
            if cancel_flag and cancel_flag():
                _safe_log(log, f"[SCAN] Отменено на модуле {name}", "warn")
                break
            try:
                _safe_log(log, f"[SCAN] ▶ {name} ({done+1}/{total})", "info")
                scan_results[name] = runner()
            except Exception as e:
                scan_results[name] = {"status": "error", "error": str(e), "items": []}
                _safe_log(log, f"[SCAN] ❌ {name}: {e}", "error")
            done += 1

        return {
            "status": "ok",
            "modules_run": done,
            "modules_total": total,
            "results": scan_results,
            "summary": self.build_summary(),
        }

    # -----------------------------
    #  ULTRA‑MODE summary + heatmap
    # -----------------------------
    def build_summary(self) -> Dict[str, Any]:
        """
        Повертає ULTRA‑MODE summary по всіх запусках AutoModulesEngine.
        """
        summary = {
            "heatmap": dict(self.heatmap),
            "ml_prediction": self.last_ml_prediction or "unavailable",
        }

        # ML‑hook
        self._ml_classify(summary)

        # Event‑stream
        cb = self.on_event
        if callable(cb):
            try:
                cb("auto_modules_summary_ultra", summary)
            except Exception:
                logger.exception("[AutoModulesEngine] on_event summary callback error")

        return summary
