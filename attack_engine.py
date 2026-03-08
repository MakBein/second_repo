# xss_security_gui/attack_engine.py

import re
import time
import threading
import requests
from urllib.parse import urlparse
import os
import json
import uuid
from collections import Counter
from typing import Any, Dict, Optional, List


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

from xss_security_gui.settings import settings

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
        }

    # ===================== API для GUI (модульные вызовы) =====================

    def _init_session(self) -> None:
        """Создаёт HTTP-сессию для всех сетевых модулей."""
        self._session = requests.Session()
        self._session.verify = False  # отключаем SSL warnings для тестовых целей

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

    def _send_intel(self, attack_type: str, result: dict) -> None:
        try:
            self.threat_sender(module=attack_type, target=self.domain, result=result)
        except Exception as e:
            self._log(f"⚠️ Ошибка ThreatSender: {e}", level="warn")

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
        ctx = {
            "method": "GET",
            "url": url,
            "params": {"x": payload},
            "data": None,
            "json": None,
            "headers": {
                "User-Agent": "XSS-Security-GUI-AutoAttack/6.0",
                "Accept": "*/*",
            },
            "cookies": {},
            "timeout": 10,
            "verify": False,
        }
        if "{payload}" in url:
            ctx["url"] = url.replace("{payload}", payload)
            ctx["params"] = {}
        return ctx

    def _send_payload(self, url: str, payload: str, method: str = "GET"):
        try:
            url = self._normalize_url(url)
            ctx = self._build_request_context(url, payload)
            method = method.upper()
            resp = requests.request(method, **ctx)
            return resp
        except Exception as e:
            self._log(f"❌ Ошибка _send_payload [{method}]: {e}", level="error")
            return None

    def _make_request(self, method: str, endpoint: str, payload=None, headers=None):
        headers = headers or {"Content-Type": "application/json"}
        start = time.time()

        try:
            method = method.upper()
            kwargs = {"headers": headers, "timeout": 5}

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

    def attack_payload(self, url: str, payload: str) -> dict:
        try:
            response = self._send_payload(url, payload)
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

    def _run_api_endpoints(self, ctx: Dict[str, Any]) -> dict:
        allow_real = ctx.get("settings", {}).get("allow_real_run", True)
        if not allow_real:
            return {"status": "skipped", "reason": "real-run-not-allowed"}

        crawl = ctx["crawl"]
        api_endpoints = crawl.get("api_endpoints", [])
        if not api_endpoints:
            return {"status": "skipped", "items": [], "count": 0, "reason": "no api_endpoints"}

        results = attack_api_endpoints(
            ctx["session"],
            ctx["base_url"],
            api_endpoints,
            ctx["headers_list"],
            self._log,
        ) or []

        return {
            "status": "done",
            "items": results,
            "count": len(results),
            "severity": "info",
        }

    def _run_token_bruteforce(self, ctx: Dict[str, Any]) -> dict:
        domain = ctx.get("domain")
        settings_ctx = ctx.get("settings", {})
        allow_real = settings_ctx.get("allow_real_run", True)

        if not allow_real:
            return {"status": "skipped", "reason": "real-run-not-allowed"}

        if domain not in getattr(settings, "ALLOWED_TARGETS", []):
            return {"status": "skipped", "reason": "domain-not-allowed"}

        # список токенів
        tokens = ctx.get("secrets", {}).get("tokens", [])
        if not tokens:
            return {"status": "skipped", "reason": "no-tokens"}

        # базовий URL
        base_url = f"https://{domain}"

        # виклик реального brute-force
        results = brute_force_tokens(
            session=self._session,
            base_url=base_url,
            tokens=tokens,
            log=self._log_func,
        )

        return {
            "status": "done",
            "count": len(results),
            "items": results,
        }

    def _run_parameters(self, ctx: Dict[str, Any]) -> dict:
        allow_real = ctx.get("settings", {}).get("allow_real_run", True)
        if not allow_real:
            return {"status": "skipped", "reason": "real-run-not-allowed"}

        crawl = ctx["crawl"]
        parameters = crawl.get("parameters", [])
        if not parameters:
            return {"status": "skipped", "items": [], "count": 0, "reason": "no parameters"}

        results = attack_parameters(
            ctx["session"],
            ctx["base_url"],
            parameters,
            self._log,
        ) or []

        return {
            "status": "done",
            "items": results,
            "count": len(results),
            "severity": "info",
        }

    def _run_user_ids(self, ctx: Dict[str, Any]) -> dict:
        allow_real = ctx.get("settings", {}).get("allow_real_run", True)
        if not allow_real:
            return {"status": "skipped", "reason": "real-run-not-allowed"}

        crawl = ctx["crawl"]
        user_ids = crawl.get("user_ids", [])
        if not user_ids:
            return {"status": "skipped", "items": [], "count": 0, "reason": "no user_ids"}

        results = attack_user_ids(
            ctx["session"],
            ctx["base_url"],
            user_ids,
            self._log,
        ) or []

        return {
            "status": "done",
            "items": results,
            "count": len(results),
            "severity": "info",
        }

    def _run_xss_targets(self, ctx: Dict[str, Any]) -> dict:
        allow_real = ctx.get("settings", {}).get("allow_real_run", True)
        if not allow_real:
            return {"status": "skipped", "reason": "real-run-not-allowed"}

        crawl = ctx["crawl"]
        xss_targets = crawl.get("xss_targets", [])
        if not xss_targets:
            return {"status": "skipped", "items": [], "count": 0, "reason": "no xss_targets"}

        results = attack_xss_targets(
            ctx["session"],
            ctx["base_url"],
            xss_targets,
            self._log,
        ) or []

        severity = "high" if results else "low"

        return {
            "status": "done",
            "items": results,
            "count": len(results),
            "severity": severity,
        }

    def _run_graphql(self, ctx: Dict[str, Any]) -> dict:
        crawl = ctx["crawl"]
        graphql = crawl.get("graphql", [])
        items = [{"endpoint": ep} for ep in graphql]
        return {
            "status": "done",
            "items": items,
            "count": len(items),
            "severity": "info",
        }

    def _run_js_sensitive(self, ctx: Dict[str, Any]) -> dict:
        crawl = ctx["crawl"]
        scripts = crawl.get("scripts", [])
        allow_real = ctx.get("settings", {}).get("allow_real_run", True)
        if not allow_real:
            return {"status": "skipped", "reason": "real-run-not-allowed"}
        if not scripts:
            return {"status": "skipped", "items": [], "count": 0, "reason": "no scripts"}

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

        # Собираем уже записанные результаты по found_targets и dom_vectors
        for r in self.results:
            if r.get("attack_type") in ("found_targets", "dom_vectors"):
                findings.append(r)

        severity = "medium" if findings else "low"
        return {
            "status": "done",
            "items": findings,
            "count": len(findings),
            "severity": severity,
        }

    def _run_security_headers(self, ctx: Dict[str, Any]) -> dict:
        allow_real = ctx.get("settings", {}).get("allow_real_run", True)
        if not allow_real:
            return {"status": "skipped", "reason": "real-run-not-allowed"}

        crawl = ctx["crawl"]
        headers_info = crawl.get("headers", [])

        return {
            "status": "done",
            "items": [{"headers": headers_info}],
            "count": 1 if headers_info else 0,
            "severity": "info",
        }

    def _run_csp(self, ctx: Dict[str, Any]) -> dict:
        allow_real = ctx.get("settings", {}).get("allow_real_run", True)
        if not allow_real:
            return {"status": "skipped", "reason": "real-run-not-allowed"}

        crawl = ctx["crawl"]
        csp_info = crawl.get("csp_analysis", [])

        return {
            "status": "done",
            "items": [{"csp": csp_info}],
            "count": 1 if csp_info else 0,
            "severity": "info",
        }

    def _run_secrets(self, ctx: Dict[str, Any]) -> dict:
        allow_real = ctx.get("settings", {}).get("allow_real_run", True)
        if not allow_real:
            return {"status": "skipped", "reason": "real-run-not-allowed"}

        crawl = ctx["crawl"]
        secrets = crawl.get("secrets", [])
        api_keys = crawl.get("api_keys", [])

        items = [{"secrets": secrets, "api_keys": api_keys}]
        severity = "high" if secrets or api_keys else "low"

        return {
            "status": "done",
            "items": items,
            "count": 1,
            "severity": severity,
        }

    def _run_jwt(self, ctx: Dict[str, Any]) -> dict:
        allow_real = ctx.get("settings", {}).get("allow_real_run", True)
        if not allow_real:
            return {"status": "skipped", "reason": "real-run-not-allowed"}

        crawl = ctx["crawl"]
        jwt_tokens = crawl.get("jwt_tokens", [])

        items = [{"token": t} for t in jwt_tokens]
        severity = "medium" if jwt_tokens else "low"

        return {
            "status": "done",
            "items": items,
            "count": len(items),
            "severity": severity,
        }

    def _run_forms(self, ctx: Dict[str, Any]) -> dict:
        allow_real = ctx.get("settings", {}).get("allow_real_run", True)
        if not allow_real:
            return {"status": "skipped", "reason": "real-run-not-allowed"}

        crawl = ctx["crawl"]
        forms = crawl.get("forms", [])

        items = [{"form": f} for f in forms]

        return {
            "status": "done",
            "items": items,
            "count": len(items),
            "severity": "info",
        }

    def _run_errors(self, ctx: Dict[str, Any]) -> dict:
        allow_real = ctx.get("settings", {}).get("allow_real_run", True)
        if not allow_real:
            return {"status": "skipped", "reason": "real-run-not-allowed"}

        crawl = ctx["crawl"]
        errors = crawl.get("errors", [])

        items = [{"error": e} for e in errors]
        severity = "warn" if errors else "info"

        return {
            "status": "done",
            "items": items,
            "count": len(items),
            "severity": severity,
        }

    def _run_csrf(self, ctx: Dict[str, Any]) -> dict:
        allow_real = ctx.get("settings", {}).get("allow_real_run", True)
        if not allow_real:
            return {"status": "skipped", "reason": "real-run-not-allowed"}
        domain = ctx.get("domain")
        if domain not in getattr(settings, "ALLOWED_TARGETS", []):
            return {"status": "skipped", "reason": "domain-not-allowed"}

        try:
            csrf_file = ctx["crawl"].get("csrf_file") or settings.get("payloads.csrf_file")
            with open(csrf_file, encoding="utf-8") as f:
                csrf_payloads = json.load(f)
        except Exception as e:
            return {"status": "error", "items": [], "count": 0, "error": str(e)}

        findings = []
        for category, urls in csrf_payloads.items():
            for url in urls:
                try:
                    result = self.attack_payload(ctx["base_url"] + url, "csrf_test")
                    findings.append({
                        "category": category,
                        "url": url,
                        "result": result
                    })
                except Exception as e:
                    findings.append({
                        "category": category,
                        "url": url,
                        "error": str(e)
                    })

        severity = "high" if findings else "low"
        return {
            "status": "done",
            "items": findings,
            "count": len(findings),
            "severity": severity
        }

    # ===================== Атаки по найденным целям (совместимость) =====================

    def attack_found_targets(self, scripts: List[Dict[str, Any]]) -> None:
        findings = []
        try:
            for s in scripts:
                url = s.get("src") or s.get("url")
                if not url:
                    continue
                for payload in ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]:
                    result = self.attack_payload(url, payload)
                    findings.append({"url": url, "payload": payload, "result": result})

            summary = {
                "status": "done",
                "items": findings,
                "count": len(findings),
                "severity": "high" if findings else "low",
            }
            self._record_result("found_targets", summary)
            self._log(
                f"✔️ AttackEngine: атака по найденным точкам завершена ({len(findings)} результатов)."
            )
        except Exception as e:
            self._record_result(
                "found_targets",
                {"status": "error", "items": [], "error": str(e)},
            )
            self._log(f"❌ Ошибка атаки по найденным точкам: {e}", level="error")

    def attack_dom_vectors(self, scripts: List[Dict[str, Any]]) -> None:
        findings = []
        try:
            for s in scripts:
                dom_code = s.get("code") or s.get("inline")
                if not dom_code:
                    continue
                if "document.write" in dom_code or "innerHTML" in dom_code:
                    findings.append({"vector": "DOM", "code": dom_code[:120]})

            summary = {
                "status": "done",
                "items": findings,
                "count": len(findings),
                "severity": "medium" if findings else "low",
            }
            self._record_result("dom_vectors", summary)
            self._log(
                f"✔️ AttackEngine: DOM-вектора проверены ({len(findings)} потенциальных точек)."
            )
        except Exception as e:
            self._record_result(
                "dom_vectors",
                {"status": "error", "items": [], "error": str(e)},
            )
            self._log(f"❌ Ошибка DOM-атаки: {e}", level="error")

    # ===================== Автоатака (обёртка) =====================

    def run_auto_attack(
        self,
        crawl_json: Dict[str, Any],
        sandbox_info: Optional[Dict[str, Any]] = None,
        launcher: Optional[callable] = None,
    ) -> None:
        self._log("🧨 Запуск автоатаки...")

        def _run():
            try:
                start = time.time()
                if sandbox_info:
                    self._log(f"🛡 Sandbox: {sandbox_info.get('sandboxed', False)}")

                if launcher:
                    try:
                        report = launcher(crawl_json, self._log) or {}
                    except Exception as e:
                        report = {"error": str(e)}
                else:
                    self.run_modular_auto_attack(crawl_json)
                    report = {"status": "modular_auto_attack"}

                elapsed = (time.time() - start) * 1000.0
                result = {
                    "target": crawl_json.get("url", self.domain),
                    "sandbox": bool(sandbox_info.get("sandboxed"))
                    if isinstance(sandbox_info, dict)
                    else False,
                    "sandbox_info": sandbox_info or {},
                    "report": report,
                    "elapsed_ms": elapsed,
                    "severity": "n/a",
                }
                self._record_result("auto_attack", result)
                self._log(f"✔️ Автоатака завершена за {elapsed:.0f}ms.")
            except Exception as e:
                self._record_result(
                    "auto_attack",
                    {"target": self.domain, "error": str(e), "severity": "error"},
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
                dir_name = os.path.dirname(path)
                if dir_name:
                    os.makedirs(dir_name, exist_ok=True)

            summary = self.get_summary()
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

        return {
            "attack_id": self.attack_id,
            "domain": self.domain,
            "count": len(self.results),
            "high": high,
            "errors": errors,
            "by_type": self._group_by_type(),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def send_summary_to_threat_intel(self) -> None:
        summary = self.get_summary()
        try:
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
