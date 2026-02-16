# xss_security_gui/auto_recon/planner.py

import requests
import time
import json
import os
import threading
from queue import Queue
from typing import List, Dict, Any, Optional

from xss_security_gui.threat_analysis.threat_connector import ThreatConnector
from xss_security_gui import DIRS


# ---------------------------------------------------------
# Базовый планировщик (синхронный)
# ---------------------------------------------------------
class AttackPlanner:
    """
    Синхронный планировщик атак.
    """

    def __init__(self, payloads, headers=None, delay=0.1, timeout=5):
        self.payloads = payloads
        self.headers = headers or {"User-Agent": "AutoReconAgent"}
        self.delay = delay
        self.timeout = timeout
        self.responses = []

    def execute(self):
        for item in self.payloads:
            time.sleep(self.delay)

            method = item.get("method", "GET").upper()
            url = item.get("url")
            body = item.get("json", {})

            try:
                if method == "GET":
                    r = requests.get(url, headers=self.headers, timeout=self.timeout)
                elif method == "POST":
                    r = requests.post(url, headers=self.headers, json=body, timeout=self.timeout)
                else:
                    r = requests.request(method, url, headers=self.headers, json=body, timeout=self.timeout)

                self.responses.append({
                    "url": url,
                    "method": method,
                    "status": r.status_code,
                    "text": r.text,
                    "headers": dict(r.headers),
                    "source": item.get("source", "")
                })

            except Exception as e:
                self.responses.append({
                    "url": url,
                    "method": method,
                    "status": "ERR",
                    "error": str(e),
                    "source": item.get("source", "")
                })

        return self.responses


# ---------------------------------------------------------
# AttackPlannerV2 — параллельный, с NDJSON и ThreatConnector
# ---------------------------------------------------------
class AttackPlannerV2:
    """
    AttackPlannerV2
    ----------------
    • Параллельное выполнение запросов (threading)
    • Логирование результатов в NDJSON
    • Интеграция с ThreatConnector
    """

    def __init__(
        self,
        payloads: List[Dict[str, Any]],
        threat_connector: Optional[ThreatConnector] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 5,
        max_workers: int = 5,
        ndjson_log: str = "attack_results.ndjson",
    ):
        self.payloads = payloads
        self.headers = headers or {"User-Agent": "AutoReconAgent"}
        self.timeout = timeout
        self.max_workers = max_workers
        self.threat_connector = threat_connector

        logs_dir = DIRS["logs"]
        os.makedirs(logs_dir, exist_ok=True)
        self.ndjson_path = os.path.join(logs_dir, ndjson_log)

        self._queue: "Queue[Dict[str, Any]]" = Queue()
        self._results: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    # -----------------------------
    # Внутренний метод: выполнение одного запроса
    # -----------------------------
    def _do_request(self, item: Dict[str, Any]) -> Dict[str, Any]:
        method = item.get("method", "GET").upper()
        url = item.get("url")
        body = item.get("json", {})

        try:
            if method == "GET":
                r = requests.get(url, headers=self.headers, timeout=self.timeout)
            elif method == "POST":
                r = requests.post(url, headers=self.headers, json=body, timeout=self.timeout)
            else:
                r = requests.request(method, url, headers=self.headers, json=body, timeout=self.timeout)

            return {
                "url": url,
                "method": method,
                "status": r.status_code,
                "text": r.text,
                "headers": dict(r.headers),
                "source": item.get("source", "AttackPlannerV2"),
                "ts": time.time(),
            }

        except Exception as e:
            return {
                "url": url,
                "method": method,
                "status": "ERR",
                "error": str(e),
                "source": item.get("source", "AttackPlannerV2"),
                "ts": time.time(),
            }

    # -----------------------------
    # Внутренний метод: worker-поток
    # -----------------------------
    def _worker(self):
        while True:
            try:
                item = self._queue.get_nowait()
            except Exception:
                break

            result = self._do_request(item)

            # Локально сохраняем результат
            with self._lock:
                self._results.append(result)

            # Логируем в NDJSON
            self._append_ndjson(result)

            # Отправляем в ThreatConnector (если есть)
            if self.threat_connector:
                self._push_to_threat_connector(result)

            self._queue.task_done()

    # -----------------------------
    # Логирование в NDJSON
    # -----------------------------
    def _append_ndjson(self, entry: Dict[str, Any]):
        try:
            with open(self.ndjson_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[AttackPlannerV2] Ошибка записи NDJSON: {e}")

    # -----------------------------
    # Интеграция с ThreatConnector
    # -----------------------------
    def _push_to_threat_connector(self, result: Dict[str, Any]):
        """
        Простейшая интеграция:
        • Если статус ERR — артефакт ERROR
        • Если статус 500+ — артефакт SERVER_ERROR
        • Если найдено слово 'error' в тексте — артефакт SUSPICIOUS
        """
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

    # -----------------------------
    # Публичный метод: запуск
    # -----------------------------
    def execute(self) -> List[Dict[str, Any]]:
        # Заполняем очередь
        for item in self.payloads:
            self._queue.put(item)

        # Стартуем воркеры
        threads = []
        for _ in range(self.max_workers):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            threads.append(t)

        # Ждём завершения
        self._queue.join()

        return self._results


# ---------------------------------------------------------
# Генерация и сохранение плана атаки
# ---------------------------------------------------------
def build_attack_plan(endpoints: List[Dict[str, Any]], payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Создаёт план атаки на основе endpoints и payloads.
    """
    return {
        "endpoints": endpoints,
        "payloads": payloads,
        "meta": {
            "count": len(payloads),
            "timestamp": time.time(),
        },
    }


def save_attack_plan(plan: Dict[str, Any], path: str = "attack_plan.json") -> bool:
    """
    Сохраняет план атаки в JSON.
    """
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(plan, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[AttackPlanner] Ошибка сохранения плана: {e}")
        return False