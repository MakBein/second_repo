# xss_security_gui/net_utils.py

import requests
from typing import Any

def _safe_request(
    method: str,
    url: str,
    headers: dict = None,
    params: dict = None,
    data: Any = None,
    timeout: int = 10
) -> dict:
    """Универсальная безопасная обёртка для HTTP-запросов."""
    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            params=params,
            data=data,
            timeout=timeout
        )
        resp.raise_for_status()
        return {"status": "ok", "code": resp.status_code, "text": resp.text}
    except requests.RequestException as e:
        return {"status": "error", "error": str(e)}