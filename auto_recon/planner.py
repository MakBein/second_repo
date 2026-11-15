# xss_security_gui/auto_recon/planner.py
"""
AttackPlanner — синхронный и параллельный планировщики атак.
Поддержка:
• GET/POST/любые HTTP-запросы
• NDJSON логирования
• ThreatConnector интеграции
• Параллельного выполнения (threading)
"""

import json
import os
import time
import threading
from queue import Empty, Queue
from typing import List, Dict, Any, Optional

import requests
from bs4 import BeautifulSoup

from xss_security_gui.threat_analysis.threat_connector import ThreatConnector
from xss_security_gui import DIRS
from xss_security_gui.auto_recon.scope import (
    RequestBudget,
    is_target_authorized,
    scoped_request,
)


def _read_response_excerpt(response: requests.Response, max_bytes: int = 1024 * 1024) -> str:
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        remaining = max_bytes - size
        chunks.append(chunk[:remaining])
        size += min(len(chunk), remaining)
        if size >= max_bytes:
            break
    text = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
    soup = BeautifulSoup(text, "html.parser")
    for field in soup.find_all(["input", "textarea"]):
        name = str(field.get("name") or "").lower()
        field_type = str(field.get("type") or "").lower()
        if field_type in {"password", "file"} or any(
            marker in name
            for marker in ("password", "passwd", "secret", "token", "cookie", "auth")
        ):
            field.attrs.pop("value", None)
            field.clear()
    return str(soup)[:2000]


# ============================================================
#  Синхронный планировщик
# ============================================================
class AttackPlanner:
    """
    Синхронный планировщик атак.
    Выполняет запросы последовательно.
    """

    def __init__(
        self,
        payloads: List[Dict[str, Any]],
        headers: Optional[Dict[str, str]] = None,
        delay: float = 0.1,
        timeout: int = 5,
        active_testing: bool = False,
        active_request_budget: Optional[RequestBudget] = None,
    ):
        self.payloads = payloads[:200]
        self.headers = headers or {"User-Agent": "AutoReconAgent"}
        self.delay = min(max(delay, 0), 1)
        self.timeout = min(max(timeout, 1), 5)
        self.active_testing = active_testing is True
        self.active_request_budget = active_request_budget or RequestBudget(200)
        self.responses: List[Dict[str, Any]] = []

    def execute(self) -> List[Dict[str, Any]]:
        """Последовательно выполняет все запросы."""
        for item in self.payloads:
            url = item.get("url") if isinstance(item, dict) else None
            method_value = item.get("method", "GET") if isinstance(item, dict) else "GET"
            method = method_value.upper() if isinstance(method_value, str) else ""
            if not self.active_testing:
                self.responses.append({
                    "url": url,
                    "method": method,
                    "status": "BLOCKED",
                    "error": "Active testing was not explicitly enabled",
                    "source": "AttackPlanner",
                })
                continue
            if not isinstance(url, str) or not is_target_authorized(url):
                self.responses.append({
                    "url": url,
                    "method": method,
                    "status": "BLOCKED",
                    "error": "Target is outside ALLOW_REAL_RUN/ALLOWED_TARGETS",
                    "source": "AttackPlanner",
                })
                continue
            if method not in {"GET", "POST"}:
                self.responses.append({
                    "url": url,
                    "method": method,
                    "status": "BLOCKED",
                    "error": "Only GET and POST are allowed by AutoRecon",
                    "source": "AttackPlanner",
                })
                continue
            if not self.active_request_budget.try_consume():
                self.responses.append({
                    "url": url,
                    "method": method,
                    "status": "BLOCKED",
                    "error": "Active request budget exhausted",
                    "source": "AttackPlanner",
                })
                continue

            time.sleep(self.delay)
            form_data = item.get("data")
            body = item.get("json", {})

            try:
                request_args = {
                    "headers": self.headers,
                    "timeout": self.timeout,
                    "stream": True,
                }
                if method == "POST":
                    request_args["data" if isinstance(form_data, dict) else "json"] = (
                        form_data if isinstance(form_data, dict) else body
                    )
                r = scoped_request(
                    requests,
                    method,
                    url,
                    root_url=url,
                    request_budget=self.active_request_budget,
                    initial_budget_consumed=True,
                    **request_args,
                )
                if r.is_redirect:
                    r.close()
                    self.responses.append({
                        "url": url,
                        "method": method,
                        "status": "BLOCKED",
                        "error": "Redirect target is outside the authorized origin",
                        "source": item.get("source", "AttackPlanner"),
                    })
                    continue

                self.responses.append({
                    "url": url,
                    "method": method,
                    "status": r.status_code,
                    "text": r.text,
                    "headers": dict(r.headers),
                    "source": item.get("source", "AttackPlanner"),
                })
                r.close()
            except (requests.exceptions.RequestException, ValueError) as e:
                self.responses.append({
                    "url": url,
                    "method": method,
                    "status": "ERR",
                    "error": str(e),
                    "source": item.get("source", "AttackPlanner"),
                })

        return self.responses


# ============================================================
#  Параллельный планировщик
# ============================================================
class AttackPlannerV2:
    """
    AttackPlannerV2 — параллельный планировщик атак.
    Возможности:
    • Параллельное выполнение запросов (threading)
    • NDJSON логирование
    • Интеграция с ThreatConnector
    """

    def __init__(
        self,
        payloads: List[Dict[str, Any]],
        threat_connector: Optional[ThreatConnector] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 5,
        max_workers: int = 10,
        ndjson_log: str = "attack_results.ndjson",
        active_testing: bool = False,
        active_request_budget: Optional[RequestBudget] = None,
    ):
        self.payloads = payloads[:200]
        self.headers = headers or {"User-Agent": "AutoReconAgent"}
        self.timeout = min(max(timeout, 1), 5)
        self.max_workers = min(max(1, max_workers), 10)
        self.threat_connector = threat_connector
        self.active_testing = active_testing is True
        self.active_request_budget = active_request_budget or RequestBudget(200)

        logs_dir = DIRS["logs"]
        os.makedirs(logs_dir, exist_ok=True)
        self.ndjson_path = os.path.join(logs_dir, ndjson_log)

        self._queue: Queue[Dict[str, Any]] = Queue()
        self._results: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def _do_request(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Выполняет один HTTP-запрос."""
        method_value = item.get("method", "GET")
        method = method_value.upper() if isinstance(method_value, str) else ""
        url = item.get("url")
        form_data = item.get("data")
        body = item.get("json", {})

        if not self.active_testing:
            return {
                "url": url,
                "method": method,
                "status": "BLOCKED",
                "error": "Active testing was not explicitly enabled",
                "source": item.get("source", "AttackPlannerV2"),
                "ts": time.time(),
            }
        if not isinstance(url, str) or not is_target_authorized(url):
            return {
                "url": url,
                "method": method,
                "status": "BLOCKED",
                "error": "Target is outside ALLOW_REAL_RUN/ALLOWED_TARGETS",
                "source": item.get("source", "AttackPlannerV2"),
                "ts": time.time(),
            }
        if method not in {"GET", "POST"}:
            return {
                "url": url,
                "method": method,
                "status": "BLOCKED",
                "error": "Only GET and POST are allowed by AutoRecon",
                "source": item.get("source", "AttackPlannerV2"),
                "ts": time.time(),
            }
        if not self.active_request_budget.try_consume():
            return {
                "url": url,
                "method": method,
                "status": "BLOCKED",
                "error": "Active request budget exhausted",
                "source": item.get("source", "AttackPlannerV2"),
                "ts": time.time(),
            }

        try:
            request_args = {"headers": self.headers, "timeout": self.timeout}
            if method == "POST":
                request_args["data" if isinstance(form_data, dict) else "json"] = (
                    form_data if isinstance(form_data, dict) else body
                )
            r = scoped_request(
                requests,
                method,
                url,
                root_url=url,
                request_budget=self.active_request_budget,
                initial_budget_consumed=True,
                **request_args,
            )
            if r.is_redirect:
                r.close()
                return {
                    "url": url,
                    "method": method,
                    "status": "BLOCKED",
                    "error": "Redirect target is outside the authorized origin",
                    "source": item.get("source", "AttackPlannerV2"),
                    "ts": time.time(),
                }

            try:
                safe_headers = {
                    name: (
                        "[redacted]"
                        if name.lower() in {
                            "authorization",
                            "proxy-authorization",
                            "cookie",
                            "set-cookie",
                        }
                        else value
                    )
                    for name, value in r.headers.items()
                }
                return {
                    "url": url,
                    "method": method,
                    "status": r.status_code,
                    "text": _read_response_excerpt(r),
                    "headers": safe_headers,
                    "source": item.get("source", "AttackPlannerV2"),
                    "ts": time.time(),
                }
            finally:
                r.close()
        except (requests.exceptions.RequestException, ValueError) as e:
            return {
                "url": url,
                "method": method,
                "status": "ERR",
                "error": str(e),
                "source": item.get("source", "AttackPlannerV2"),
                "ts": time.time(),
            }

    def _worker(self):
        """Worker-поток: обрабатывает задачи из очереди."""
        while True:
            try:
                item = self._queue.get_nowait()
            except Empty:
                break

            try:
                result = self._do_request(item)
                with self._lock:
                    self._results.append(result)
                self._append_ndjson(result)
                if self.threat_connector:
                    self._push_to_threat_connector(result)
            except Exception as exc:
                result = {
                    "url": item.get("url") if isinstance(item, dict) else None,
                    "status": "ERR",
                    "error": f"Planner worker failed: {exc}",
                    "source": "AttackPlannerV2",
                    "ts": time.time(),
                }
                with self._lock:
                    self._results.append(result)
                self._append_ndjson(result)
            finally:
                self._queue.task_done()

    def _append_ndjson(self, entry: Dict[str, Any]):
        """Записывает результат в NDJSON-лог."""
        try:
            with open(self.ndjson_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[AttackPlannerV2] Ошибка записи NDJSON: {e}")

    def _push_to_threat_connector(self, result: Dict[str, Any]):
        """Интеграция с ThreatConnector."""
        if not self.threat_connector:
            return

        url = result.get("url", "")
        status = result.get("status")
        text = result.get("text", "") or ""

        artifacts = []
        if status == "ERR":
            artifacts.append({"type": "ERROR", "details": result.get("error", "")})
        elif isinstance(status, int) and status >= 500:
            artifacts.append({"type": "SERVER_ERROR", "status": status})
        if "error" in text.lower():
            artifacts.append({"type": "SUSPICIOUS_TEXT", "snippet": text[:200]})

        if artifacts:
            self.threat_connector.add_artifact("ATTACK", url, artifacts)

    def execute(self) -> List[Dict[str, Any]]:
        """Запускает параллельное выполнение запросов."""
        for item in self.payloads:
            self._queue.put(item)

        threads = []
        for _ in range(self.max_workers):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            threads.append(t)

        self._queue.join()
        return self._results


# ============================================================
#  Генерация и сохранение плана атаки
# ============================================================
def build_attack_plan(endpoints: List[Dict[str, Any]], payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Создаёт план атаки на основе endpoints и payloads."""
    return {
        "endpoints": endpoints,
        "payloads": payloads,
        "meta": {
            "count": len(payloads),
            "timestamp": time.time(),
        },
    }


def save_attack_plan(plan: Dict[str, Any], path: str = "attack_plan.json") -> bool:
    """Сохраняет план атаки в JSON."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(plan, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[AttackPlanner] Ошибка сохранения плана: {e}")
        return False


__all__ = ["AttackPlanner", "AttackPlannerV2", "build_attack_plan", "save_attack_plan"]