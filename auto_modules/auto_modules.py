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
