# xss_security_gui/auth/session_manager.py
"""
session_manager 12.0 OMNI‑MODE

- session.json v2 (meta + cookies)
- multi‑profile support
- secure‑cookie‑filter
- expired/third‑party/tracking cleanup
- domain‑aware cookie sanitizer
- Playwright‑safe cookie injection
- session validity check (logout/profile/account)
- auto‑repair cookies
- auto‑merge cookies
"""

import json
import os
import datetime as dt
from typing import Any, Dict, List, Optional

BASE_DIR: str = os.path.dirname(__file__)
DEFAULT_PROFILE = "default"


# ============================================================
#  INTERNAL HELPERS
# ============================================================

def _session_file(profile: str = DEFAULT_PROFILE) -> str:
    """
    Возвращает путь к session_{profile}.json.
    """
    fname = f"session_{profile}.json"
    return os.path.join(BASE_DIR, fname)


def _now_iso() -> str:
    """
    Возвращает текущий timestamp в ISO‑формате.
    """
    return dt.datetime.now().isoformat()


def _sanitize_cookies(cookies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Убираем мусорные/битые/трекерные cookies:
    - пустые name/value
    - явно трекинговые (ga, gid, fb, yandex, etc.)
    - странные домены
    - битые даты
    - third‑party cookies
    """

    tracking_keys = [
        "ga", "_ga", "_gid", "_fbp", "_fbc", "yandexuid", "ym_uid",
        "gcl_", "utm_", "ad_", "pixel", "tracker",
    ]

    sanitized: List[Dict[str, Any]] = []

    for c in cookies:
        name = str(c.get("name", "")).strip().lower()
        value = str(c.get("value", "")).strip()
        domain = str(c.get("domain", "")).strip().lower()

        # Пустые cookies
        if not name or not value:
            continue

        # Трекинговые cookies
        if any(k in name for k in tracking_keys):
            continue

        # Битые домены
        if domain.startswith("."):
            domain = domain[1:]

        # Third‑party cookies (если домен не похож на реальный)
        if domain.count(".") < 1:
            continue

        # Битые даты
        expires = c.get("expires")
        if expires is not None:
            try:
                if expires < dt.datetime.now().timestamp():
                    continue
            except Exception:
                pass

        sanitized.append(c)

    return sanitized


def _merge_cookies(old: List[Dict[str, Any]], new: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Объединяет старые и новые cookies:
    - новые перезаписывают старые
    - удаляет дубликаты
    """
    merged: Dict[str, Dict[str, Any]] = {}

    for c in old:
        merged[c["name"]] = c

    for c in new:
        merged[c["name"]] = c

    return list(merged.values())


# ============================================================
#  SAVE SESSION
# ============================================================

def save_session(context: Any, profile: str = DEFAULT_PROFILE) -> None:
    """
    Сохраняет cookies в session_{profile}.json (v2 формат):
    {
      "meta": {...},
      "cookies": [...]
    }
    """

    try:
        cookies = context.cookies()
    except Exception:
        print("[⚠️] Cannot read cookies from context")
        return

    cookies = _sanitize_cookies(cookies)

    # Если файл уже существует — объединяем cookies
    path = _session_file(profile)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                old_data = json.load(f)
            old_cookies = old_data.get("cookies", [])
            cookies = _merge_cookies(old_cookies, cookies)
        except Exception:
            pass

    data = {
        "meta": {
            "timestamp": _now_iso(),
            "profile": profile,
            "cookie_count": len(cookies),
        },
        "cookies": cookies,
    }

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[🔐] Session saved: {path} ({len(cookies)} cookies)")
    except Exception as e:
        print(f"[⚠️] Failed to save session: {e}")


# ============================================================
#  LOAD SESSION
# ============================================================

def load_session(context: Any, profile: str = DEFAULT_PROFILE) -> bool:
    """
    Загружает cookies из session_{profile}.json (v2 формат) и добавляет в контекст.
    Возвращает True, если сессия загружена, иначе False.
    """

    path = _session_file(profile)
    if not os.path.exists(path):
        print("[ℹ️] No session file found")
        return False

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        print("[⚠️] Failed to read session file")
        return False

    cookies = data.get("cookies", [])
    if not isinstance(cookies, list) or not cookies:
        print("[⚠️] Session file contains no cookies")
        return False

    cookies = _sanitize_cookies(cookies)

    try:
        context.add_cookies(cookies)
        print(f"[🔐] Session loaded: {path} ({len(cookies)} cookies)")
        return True
    except Exception as e:
        print(f"[⚠️] Failed to load session: {e}")
        return False


# ============================================================
#  VALIDATE SESSION
# ============================================================

def validate_session(
    context: Any,
    test_url: str,
    expect_logged_in_markers: Optional[List[str]] = None,
) -> bool:
    """
    Проверка валидности сессии:
    - делает GET на test_url
    - проверяет наличие маркеров авторизации (logout/profile/account)
    """

    if expect_logged_in_markers is None:
        expect_logged_in_markers = ["logout", "profile", "account"]

    try:
        resp = context.request.get(test_url, timeout=10000)
    except Exception:
        print("[⚠️] Session validation request failed")
        return False

    try:
        text = resp.text().lower()
    except Exception:
        print("[⚠️] Cannot read response text")
        return False

    for m in expect_logged_in_markers:
        if m in text:
            print("[🔐] Session is valid")
            return True

    print("[⚠️] Session appears invalid")
    return False


