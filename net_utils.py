# xss_security_gui/net_utils.py
"""Общие безопасные HTTP-утилиты для GUI, auto_modules и движка атак."""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional, Tuple

import requests

LogFn = Optional[Callable[[str, str], None]]


def _safe_request(
    method: str,
    url: str,
    headers: dict = None,
    params: dict = None,
    data: Any = None,
    timeout: int = 10,
) -> dict:
    """Универсальная безопасная обёртка для HTTP-запросов (без Session)."""
    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            params=params,
            data=data,
            timeout=timeout,
        )
        resp.raise_for_status()
        return {"status": "ok", "code": resp.status_code, "text": resp.text}
    except requests.RequestException as e:
        return {"status": "error", "error": str(e)}


def session_request_safe(
    session: requests.Session,
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
    verify: bool = False,
    allow_redirects: bool = True,
    proxies: Optional[Dict[str, str]] = None,
    retries: int = 0,
    retry_backoff: float = 0.35,
) -> Tuple[Optional[requests.Response], Optional[str]]:
    """
    Запрос через Session с ретраями. Не бросает исключения наружу.
    Возвращает (response, error_message). error_message заполнен при полном провале.
    """
    merged_headers: Dict[str, str] = {}
    if session.headers:
        merged_headers.update(dict(session.headers))
    if headers:
        merged_headers.update(headers)

    last_err: Optional[str] = None
    attempts = max(0, int(retries)) + 1
    for attempt in range(attempts):
        try:
            kwargs: Dict[str, Any] = {
                "headers": merged_headers or None,
                "timeout": timeout,
                "verify": verify,
                "allow_redirects": allow_redirects,
            }
            if proxies:
                kwargs["proxies"] = proxies
            resp = session.request(method.upper(), url, **kwargs)
            return resp, None
        except requests.RequestException as e:
            last_err = f"{type(e).__name__}: {e}"
            if attempt + 1 < attempts:
                time.sleep(retry_backoff * (attempt + 1))
    return None, last_err or "request_failed"
