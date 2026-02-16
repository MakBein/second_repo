# xss_security_gui/auto_modules.py
import json
import re
from typing import Any, Dict, List, Callable, Optional
import requests
from urllib.parse import urlencode, urljoin


LogFunc = Callable[[str, str], None]


# ============================================================
#  ВСПОМОГАТЕЛЬНЫЕ УТИЛИТЫ 5.0
# ============================================================

def _safe_log(log: Optional[LogFunc], msg: str, level: str = "info") -> None:
    if log:
        try:
            log(msg, level)
        except Exception:
            pass


def _normalize_url(base_url: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _classify_severity(status: int, reflected: bool = False, error: bool = False) -> str:
    if error:
        return "error"
    if reflected:
        return "critical"
    if status >= 500:
        return "high"
    if status >= 400:
        return "medium"
    return "info"


def _extract_json(body: str) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def _looks_like_graphql(endpoint: str, body: str, headers: Dict[str, str]) -> bool:
    if "graphql" in endpoint.lower():
        return True
    if "application/graphql" in headers.get("Content-Type", "").lower():
        return True
    if any(k in body for k in ("query", "mutation")) and "{" in body and "}" in body:
        return True
    return False


# ============================================================
#  API ENDPOINT ATTACK 5.0
# ============================================================

def attack_api_endpoints(
    session: requests.Session,
    base_url: str,
    endpoints: List[str],
    headers_list: List[Dict[str, str]],
    log: Optional[LogFunc] = None,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for ep in endpoints:
        url = _normalize_url(base_url, ep)

        for hdr in headers_list:
            try:
                _safe_log(log, f"[API] → {url} headers={hdr}", "debug")
                r = session.get(url, headers=hdr, timeout=10, verify=False)

                body = r.text or ""
                json_body = _extract_json(body)

                is_graphql = _looks_like_graphql(url, body, dict(r.headers))

                res = {
                    "endpoint": url,
                    "status": r.status_code,
                    "headers_used": hdr,
                    "content_type": r.headers.get("Content-Type", ""),
                    "length": len(body),
                    "is_graphql": is_graphql,
                    "json_detected": json_body is not None,
                }
                res["severity"] = _classify_severity(r.status_code)

                results.append(res)

            except Exception as e:
                _safe_log(log, f"[API] ❌ {url}: {e}", "warn")
                results.append({
                    "endpoint": url,
                    "error": str(e),
                    "severity": "error",
                })

    return results


# ============================================================
#  TOKEN BRUTE FORCE 5.0
# ============================================================

def brute_force_tokens(
    session: requests.Session,
    base_url: str,
    tokens: List[str],
    log: Optional[LogFunc] = None,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for token in tokens:
        headers = {"Authorization": f"Bearer {token}"}
        try:
            _safe_log(log, f"[TOKENS] → {base_url} token={token}", "debug")
            r = session.get(base_url, headers=headers, timeout=10, verify=False)

            body = r.text or ""
            suspicious = any(k in body.lower() for k in ("admin", "root", "token", "jwt"))

            res = {
                "token": token,
                "status": r.status_code,
                "length": len(body),
                "suspicious": suspicious,
            }
            res["severity"] = _classify_severity(r.status_code)

            results.append(res)

        except Exception as e:
            _safe_log(log, f"[TOKENS] ❌ {base_url} token={token}: {e}", "warn")
            results.append({
                "token": token,
                "error": str(e),
                "severity": "error",
            })

    return results


# ============================================================
#  PARAMETER ATTACK 5.0
# ============================================================

def attack_parameters(
    session: requests.Session,
    base_url: str,
    parameters: List[str],
    log: Optional[LogFunc] = None,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for param in parameters:
        try:
            url = base_url + "?" + urlencode({param: "xss_test"})
            _safe_log(log, f"[PARAM] → {url}", "debug")
            r = session.get(url, timeout=10, verify=False)

            body = r.text or ""
            reflected = "xss_test" in body

            res = {
                "parameter": param,
                "url": url,
                "status": r.status_code,
                "reflected": reflected,
                "length": len(body),
            }
            res["severity"] = _classify_severity(r.status_code, reflected=reflected)

            results.append(res)

        except Exception as e:
            _safe_log(log, f"[PARAM] ❌ {base_url} param={param}: {e}", "warn")
            results.append({
                "parameter": param,
                "error": str(e),
                "severity": "error",
            })

    return results


# ============================================================
#  USER ID ENUMERATION 5.0
# ============================================================

def attack_user_ids(
    session: requests.Session,
    base_url: str,
    user_ids: List[Any],
    log: Optional[LogFunc] = None,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for uid in user_ids:
        try:
            url = base_url + "?" + urlencode({"id": uid})
            _safe_log(log, f"[USER] → {url}", "debug")
            r = session.get(url, timeout=10, verify=False)

            body = r.text or ""
            leaked_email = bool(re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", body))

            res = {
                "user_id": uid,
                "url": url,
                "status": r.status_code,
                "length": len(body),
                "leaked_email": leaked_email,
            }
            res["severity"] = _classify_severity(r.status_code)

            results.append(res)

        except Exception as e:
            _safe_log(log, f"[USER] ❌ {base_url} id={uid}: {e}", "warn")
            results.append({
                "user_id": uid,
                "error": str(e),
                "severity": "error",
            })

    return results


# ============================================================
#  XSS TARGET ATTACK 5.0
# ============================================================

def attack_xss_targets(
    session: requests.Session,
    base_url: str,
    targets: List[Any],
    log: Optional[LogFunc] = None,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for t in targets:
        if isinstance(t, dict):
            url = t.get("url") or base_url
            payload = t.get("payload") or t.get("raw_payload") or "xss_test"
            context = t.get("context") or "generic"
        else:
            url = base_url
            payload = str(t)
            context = "generic"

        try:
            full_url = url + "?" + urlencode({"x": payload})
            _safe_log(log, f"[XSS] → {full_url} ctx={context}", "debug")
            r = session.get(full_url, timeout=10, verify=False)

            body = r.text or ""
            reflected = payload in body

            dom_suspicious = any(
                k in body.lower()
                for k in ("innerhtml", "document.write", "location.hash", "eval(", "settimeout(")
            )

            res = {
                "url": full_url,
                "base_url": url,
                "payload": payload,
                "context": context,
                "status": r.status_code,
                "reflected": reflected,
                "length": len(body),
                "dom_suspicious": dom_suspicious,
            }
            res["severity"] = _classify_severity(r.status_code, reflected=reflected)

            results.append(res)

        except Exception as e:
            _safe_log(log, f"[XSS] ❌ {url} payload={payload}: {e}", "warn")
            results.append({
                "url": url,
                "payload": payload,
                "context": context,
                "error": str(e),
                "severity": "error",
            })

    return results