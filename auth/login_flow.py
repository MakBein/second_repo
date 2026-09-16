# xss_security_gui/auth/login_flow.py
"""Combat-grade login flow for red-team style automation.

This module executes a realistic login sequence with:
- session restore
- login URL discovery
- AI-driven + DOM fallback login detection
- credential rotation
- multi-strategy form submission
- AJAX / SPA / OAuth / PKCE detection
- session persistence and structured success checks
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from xss_security_gui.auth.session_manager import load_session, save_session
from xss_security_gui.auth.login_detectors import (
    detect_login_form_ai,
    detect_login_form_without_form,
    detect_ajax_login,
    detect_oauth,
)


_DEFAULT_CREDENTIAL_SETS = [
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "Admin123!"),
    ("admin", "Password1"),
    ("user", "password"),
    ("root", "toor"),
    ("test", "test123"),
    ("demo", "demo123"),
    ("manager", "manager123"),
]


def _safe_page_call(page: Any, fn_name: str, *args: Any, default: Any = None) -> Any:
    try:
        return getattr(page, fn_name)(*args)
    except Exception:
        return default


def _iter_credentials(login_config: Dict[str, Any]) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []

    explicit = login_config.get("credentials")
    if isinstance(explicit, list):
        for item in explicit:
            if isinstance(item, dict):
                username = str(item.get("username") or "").strip()
                password = str(item.get("password") or "").strip()
                if username and password:
                    pairs.append((username, password))
            elif isinstance(item, (tuple, list)) and len(item) >= 2:
                username, password = item[:2]
                if username and password:
                    pairs.append((str(username), str(password)))

    username = str(login_config.get("username") or "").strip()
    password = str(login_config.get("password") or "").strip()
    if username and password:
        pairs.append((username, password))

    for user, pwd in _DEFAULT_CREDENTIAL_SETS:
        if not any(existing[0] == user and existing[1] == pwd for existing in pairs):
            pairs.append((user, pwd))

    seen = set()
    unique: List[Tuple[str, str]] = []
    for user, pwd in pairs:
        key = (user.lower(), pwd.lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append((user, pwd))
    return unique


def _candidate_login_urls(page: Any, login_config: Dict[str, Any]) -> List[str]:
    urls: List[str] = []
    seen = set()

    for value in (
        login_config.get("url"),
        login_config.get("login_url"),
        login_config.get("target_url"),
        login_config.get("base_url"),
        getattr(page, "url", None),
    ):
        if value and isinstance(value, str):
            clean = value.strip()
            if clean and clean not in seen:
                urls.append(clean)
                seen.add(clean)

    try:
        page_html = (page.content() or "")
    except Exception:
        page_html = ""

    for pattern in (
        r"https?://[^\s\"'<>]+(?:/login|/signin|/auth|/account|/portal)[^\s\"'<>]*",
        r"(?:href|src|action)=[\"']([^\"']+(?:login|signin|auth|account)[^\"']*)[\"']",
    ):
        for match in re.findall(pattern, page_html, flags=re.IGNORECASE):
            if match.startswith("/"):
                base = getattr(page, "url", "") or login_config.get("base_url") or ""
                if base:
                    match = base.rstrip("/") + match
            if match and match not in seen:
                urls.append(match)
                seen.add(match)

    return urls


def _is_successful_login(page: Any, login_url: str, original_url: str) -> bool:
    try:
        cookies = page.context.cookies() if hasattr(page, "context") else []
        html = (page.content() or "").lower()
        url = (page.url or "").lower()

        markers = [
            url != original_url.lower(),
            any("session" in str(c.get("name", "")).lower() for c in cookies),
            any(token in html for token in ["logout", "profile", "account", "dashboard", "welcome", "my account", "sign out"]),
            "jwt" in html,
            "bearer " in html,
            "token" in html,
            "auth" in url,
        ]
        return any(markers)
    except Exception:
        return False


def _apply_credentials(page: Any, username_selector: Optional[str], password_selector: Optional[str], username: str, password: str) -> bool:
    if username_selector:
        try:
            if page.query_selector(username_selector):
                page.fill(username_selector, username)
        except Exception:
            pass

    if not password_selector:
        return False

    try:
        if page.query_selector(password_selector):
            page.fill(password_selector, password)
            return True
    except Exception:
        pass
    return False


def _submit_form(page: Any, username_selector: Optional[str], password_selector: Optional[str], submit_selector: Optional[str]) -> bool:
    actions = []
    if submit_selector and submit_selector.strip():
        actions.append(("selector", submit_selector))
    actions.extend([
        ("pass-enter", password_selector),
        ("form-submit", "document.forms[0].submit();"),
        ("fallback-click", "document.querySelector('input[type=\"submit\"]')?.click()"),
        ("fallback-press", password_selector),
    ])

    for kind, value in actions:
        try:
            if kind == "selector":
                if page.query_selector(value):
                    page.click(value)
                    return True
            elif kind == "pass-enter":
                if value and page.query_selector(value):
                    page.press(value, "Enter")
                    return True
            elif kind == "form-submit":
                page.evaluate(value)
                return True
            elif kind == "fallback-click":
                page.evaluate(value)
                return True
            elif kind == "fallback-press":
                if value and page.query_selector(value):
                    page.press(value, "Tab")
                    page.keyboard.press("Enter")
                    return True
        except Exception:
            continue

    return False


def _build_login_summary(success: bool, login_url: str, tested_credentials: List[Tuple[str, str]], details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "success": success,
        "login_url": login_url,
        "tested_credentials": [{"username": u, "password": p} for u, p in tested_credentials],
    }
    if details:
        payload.update(details)
    return payload


def perform_login(page, login_config: dict) -> Dict[str, Any]:
    """Execute a realistic login flow for Playwright-powered pages.

    Returns a structured dict with success status and diagnostics.
    """
    config = dict(login_config or {})
    summary: Dict[str, Any] = {
        "success": False,
        "login_url": config.get("url") or config.get("login_url") or "",
        "tested_credentials": [],
        "details": {},
    }

    try:
        if page is None:
            summary["details"]["error"] = "page is missing"
            return summary

        try:
            if load_session(page.context):
                print("[🔄] Session restored — validating current auth state.")
                page.reload()
                page.wait_for_timeout(1200)
                if _is_successful_login(page, config.get("url") or "", getattr(page, "url", "") or ""):
                    save_session(page.context)
                    summary["success"] = True
                    summary["details"]["reason"] = "session_restored"
                    return summary
        except Exception:
            print("[⚠️] Failed to restore session — continuing without it.")

        login_candidates = _candidate_login_urls(page, config)
        login_url = config.get("url") or config.get("login_url")
        if not login_url and login_candidates:
            login_url = login_candidates[0]

        if not login_url:
            summary["details"]["error"] = "login URL not configured"
            print("[ℹ️] Login URL absent — skipping login flow.")
            return summary

        original_url = getattr(page, "url", "") or login_url
        try:
            page.goto(login_url, timeout=25000)
            page.wait_for_timeout(1200)
        except Exception as exc:
            summary["details"]["error"] = f"goto failed: {exc}"
            print(f"[⚠️] Failed to open login URL: {exc}")
            return summary

        form_info = detect_login_form_ai(page) or detect_login_form_without_form(page)
        if not form_info:
            print("[ℹ️] Login form not auto-detected. Trying fallback selectors.")
            form_info = {
                "username": "input[name*='user' i], input[name*='login' i], input[type='email'], input[autocomplete='username']",
                "password": "input[type='password'], input[name*='pass' i]",
                "submit": "button[type='submit'], input[type='submit'], button:has-text('login'), button:has-text('sign in')",
            }

        user_sel = form_info.get("username")
        pass_sel = form_info.get("password")
        submit_sel = form_info.get("submit")

        if not pass_sel:
            summary["details"]["error"] = "password field not found"
            print("[⚠️] Password field not found — aborting login flow.")
            return summary

        credential_pairs = _iter_credentials(config)
        tested: List[Tuple[str, str]] = []

        for username, password in credential_pairs:
            tested.append((username, password))
            print(f"[🧪] Trying login attempt for user={username!r}")

            try:
                if user_sel:
                    _safe_page_call(page, "fill", user_sel, username)
                if not _apply_credentials(page, user_sel, pass_sel, username, password):
                    print("[⚠️] Password field not writable — aborting attempt.")
                    break

                if not _submit_form(page, user_sel, pass_sel, submit_sel):
                    print("[ℹ️] Submit by standard strategy failed — trying JS fallback.")
                    try:
                        page.evaluate("document.querySelectorAll('form').length && document.querySelectorAll('form')[0].submit();")
                    except Exception:
                        pass

                page.wait_for_timeout(1600)

                if _is_successful_login(page, login_url, original_url):
                    print("[🔐] Login success confirmed.")
                    save_session(page.context)
                    summary["success"] = True
                    summary["login_url"] = login_url
                    summary["tested_credentials"] = [{"username": u, "password": p} for u, p in tested]
                    summary["details"] = {
                        "reason": "successful_login",
                        "detected_form": form_info,
                        "url_after_login": page.url,
                    }
                    return summary

                try:
                    if detect_ajax_login(page, original_url, page.context.cookies(), page.content()):
                        print("[✔️] AJAX login flow detected.")
                except Exception:
                    pass

                try:
                    html = (page.content() or "").lower()
                    oauth = detect_oauth(html)
                    if oauth:
                        print(f"[ℹ️] OAuth/SSO provider detected: {oauth}")
                    if "code_challenge" in html or "code_verifier" in html:
                        print("[ℹ️] PKCE flow detected.")
                except Exception:
                    pass

                try:
                    ls = page.evaluate("() => JSON.stringify(window.localStorage)") or ""
                    ss = page.evaluate("() => JSON.stringify(window.sessionStorage)") or ""
                    if "refresh" in (ls + ss).lower() or "token" in (ls + ss).lower():
                        print("[ℹ️] Refresh-token or silent auth artifacts detected.")
                except Exception:
                    pass

                try:
                    page.reload()
                    page.wait_for_timeout(800)
                except Exception:
                    pass

            except Exception as exc:
                print(f"[⚠️] Attempt failed for {username}: {exc}")
                continue

        summary["tested_credentials"] = [{"username": u, "password": p} for u, p in tested]
        summary["details"] = {
            "reason": "login_not_confirmed",
            "detected_form": form_info,
            "page_url": getattr(page, "url", ""),
        }
        print("[⚠️] Login flow did not confirm successful authentication.")
        return summary

    except Exception as exc:
        summary["details"] = {"error": f"login_flow crash: {exc}"}
        print(f"[❌] Error in login_flow: {exc}")
        return summary
