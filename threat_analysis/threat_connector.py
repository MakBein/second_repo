# xss_security_gui/threat_analysis/threat_connector.py
# 🛡️ ThreatConnector 6.0 — Async Queue + Batched Writes

import os
import json
import threading
import hashlib
import logging
import requests
import sqlite3
from datetime import datetime
from typing import Dict, Any, List, Optional, Iterable
from queue import Queue, Empty

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)


# ============================================================
#  Базовый backend (расширенный)
# ============================================================

class ThreatBackendBase:
    def add_artifact(self, artifact: Dict[str, Any]) -> None:
        raise NotImplementedError

    def add_batch(self, artifacts: Iterable[Dict[str, Any]]) -> None:
        for a in artifacts:
            self.add_artifact(a)

    def load_all(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def update_artifact(self, artifact: Dict[str, Any]) -> None:
        raise NotImplementedError

    def delete_artifact(self, hash_value: str) -> None:
        raise NotImplementedError

    def find_by_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def find_by_target(self, target: str) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def find_by_module(self, module: str) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def stats(self) -> Dict[str, Any]:
        data = self.load_all()
        by_module: Dict[str, int] = {}
        for a in data:
            mod = a.get("module", "unknown")
            by_module[mod] = by_module.get(mod, 0) + 1
        return {"total": len(data), "by_module": by_module}

    def clear_all(self) -> None:
        raise NotImplementedError


# ============================================================
#  NDJSON backend
# ============================================================

class NdjsonBackend(ThreatBackendBase):
    def __init__(self, filename: str = "threat_intel.ndjson"):
        self.log_file = os.path.join(LOGS_DIR, filename)
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    def add_artifact(self, artifact: Dict[str, Any]) -> None:
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(artifact, ensure_ascii=False, default=str) + "\n")

    def load_all(self) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        if not os.path.exists(self.log_file):
            return items
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return items

    def update_artifact(self, artifact: Dict[str, Any]) -> None:
        items = self.load_all()
        for i, a in enumerate(items):
            if a["_hash"] == artifact["_hash"]:
                items[i] = artifact
        with open(self.log_file, "w", encoding="utf-8") as f:
            for a in items:
                f.write(json.dumps(a, ensure_ascii=False, default=str) + "\n")

    def delete_artifact(self, hash_value: str) -> None:
        items = [a for a in self.load_all() if a["_hash"] != hash_value]
        with open(self.log_file, "w", encoding="utf-8") as f:
            for a in items:
                f.write(json.dumps(a, ensure_ascii=False, default=str) + "\n")

    def find_by_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        for a in self.load_all():
            if a["_hash"] == hash_value:
                return a
        return None

    def find_by_target(self, target: str) -> List[Dict[str, Any]]:
        return [a for a in self.load_all() if a.get("target") == target]

    def find_by_module(self, module: str) -> List[Dict[str, Any]]:
        return [a for a in self.load_all() if a.get("module") == module]

    def clear_all(self) -> None:
        open(self.log_file, "w").close()


# ============================================================
#  SQLite backend
# ============================================================

class SQLiteBackend(ThreatBackendBase):
    def __init__(self, filename: str = "threat_intel.db"):
        self.db_path = os.path.join(LOGS_DIR, filename)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash TEXT UNIQUE,
                    timestamp TEXT,
                    module TEXT,
                    target TEXT,
                    result_json TEXT
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def add_artifact(self, artifact: Dict[str, Any]) -> None:
        self.add_batch([artifact])

    def add_batch(self, artifacts: Iterable[Dict[str, Any]]) -> None:
        artifacts = list(artifacts)
        if not artifacts:
            return
        conn = self._connect()
        try:
            conn.executemany(
                """
                INSERT OR IGNORE INTO artifacts (hash, timestamp, module, target, result_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        a["_hash"],
                        a["timestamp"],
                        a["module"],
                        a["target"],
                        json.dumps(a["result"], ensure_ascii=False, default=str),
                    )
                    for a in artifacts
                ],
            )
            conn.commit()
        finally:
            conn.close()

    def load_all(self) -> List[Dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT hash, timestamp, module, target, result_json FROM artifacts"
            ).fetchall()
        finally:
            conn.close()
        items: List[Dict[str, Any]] = []
        for h, ts, mod, tgt, res_json in rows:
            try:
                res = json.loads(res_json)
            except Exception:
                res = {}
            items.append({"_hash": h, "timestamp": ts, "module": mod, "target": tgt, "result": res})
        return items

    def update_artifact(self, artifact: Dict[str, Any]) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                UPDATE artifacts SET timestamp=?, module=?, target=?, result_json=?
                WHERE hash=?
                """,
                (
                    artifact["timestamp"],
                    artifact["module"],
                    artifact["target"],
                    json.dumps(artifact["result"], ensure_ascii=False, default=str),
                    artifact["_hash"],
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def delete_artifact(self, hash_value: str) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM artifacts WHERE hash=?", (hash_value,))
            conn.commit()
        finally:
            conn.close()

    def find_by_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT hash, timestamp, module, target, result_json FROM artifacts WHERE hash=?",
                (hash_value,),
            ).fetchone()
        finally:
            conn.close()
        if row:
            return {"_hash": row[0], "timestamp": row[1], "module": row[2], "target": row[3], "result": json.loads(row[4])}
        return None

    def find_by_target(self, target: str) -> List[Dict[str, Any]]:
        return [a for a in self.load_all() if a.get("target") == target]

    def find_by_module(self, module: str) -> List[Dict[str, Any]]:
        return [a for a in self.load_all() if a.get("module") == module]

    def clear_all(self) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM artifacts")
            conn.commit()
        finally:
            conn.close()

# ============================================================
#  Elasticsearch backend (batched)
# ============================================================

class ElasticSearchBackend(ThreatBackendBase):
    def __init__(
        self,
        url: str,
        index: str = "threat_intel",
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.url = url.rstrip("/")
        self.index = index
        self.auth = (username, password) if username and password else None
        self.log = logging.getLogger("ThreatConnector")

    def _index_url(self) -> str:
        return f"{self.url}/{self.index}/_doc"

    def add_artifact(self, artifact: Dict[str, Any]) -> None:
        self.add_batch([artifact])

    def add_batch(self, artifacts: Iterable[Dict[str, Any]]) -> None:
        artifacts = list(artifacts)
        if not artifacts:
            return
        bulk_lines = []
        for a in artifacts:
            bulk_lines.append(json.dumps({"index": {}}))
            bulk_lines.append(json.dumps(a, ensure_ascii=False, default=str))
        data = "\n".join(bulk_lines) + "\n"
        try:
            resp = requests.post(
                f"{self.url}/{self.index}/_bulk",
                data=data.encode("utf-8"),
                headers={"Content-Type": "application/x-ndjson"},
                auth=self.auth,
                timeout=5,
            )
            if resp.status_code >= 300:
                self.log.warning("ElasticSearch backend: bulk failed with status %s", resp.status_code)
        except Exception:
            self.log.warning("ElasticSearch backend: failed to send bulk artifacts", exc_info=True)

    def load_all(self) -> List[Dict[str, Any]]:
        try:
            resp = requests.get(
                f"{self.url}/{self.index}/_search",
                json={"query": {"match_all": {}}},
                auth=self.auth,
                timeout=5,
            )
            hits = resp.json().get("hits", {}).get("hits", [])
            return [h.get("_source", {}) for h in hits]
        except Exception:
            self.log.warning("ElasticSearch backend: failed to load_all", exc_info=True)
            return []

    def update_artifact(self, artifact: Dict[str, Any]) -> None:
        try:
            resp = requests.post(
                f"{self.url}/{self.index}/_update/{artifact['_hash']}",
                json={"doc": artifact},
                auth=self.auth,
                timeout=5,
            )
            if resp.status_code >= 300:
                self.log.warning("ElasticSearch backend: update failed %s", resp.status_code)
        except Exception:
            self.log.warning("ElasticSearch backend: failed to update artifact", exc_info=True)

    def delete_artifact(self, hash_value: str) -> None:
        try:
            resp = requests.delete(
                f"{self.url}/{self.index}/_doc/{hash_value}",
                auth=self.auth,
                timeout=5,
            )
            if resp.status_code >= 300:
                self.log.warning("ElasticSearch backend: delete failed %s", resp.status_code)
        except Exception:
            self.log.warning("ElasticSearch backend: failed to delete artifact", exc_info=True)

    def find_by_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        try:
            resp = requests.get(
                f"{self.url}/{self.index}/_doc/{hash_value}",
                auth=self.auth,
                timeout=5,
            )
            if resp.status_code == 200:
                return resp.json().get("_source")
        except Exception:
            self.log.warning("ElasticSearch backend: failed to find_by_hash", exc_info=True)
        return None

    def find_by_target(self, target: str) -> List[Dict[str, Any]]:
        try:
            resp = requests.get(
                f"{self.url}/{self.index}/_search",
                json={"query": {"term": {"target": target}}},
                auth=self.auth,
                timeout=5,
            )
            hits = resp.json().get("hits", {}).get("hits", [])
            return [h.get("_source", {}) for h in hits]
        except Exception:
            return []

    def find_by_module(self, module: str) -> List[Dict[str, Any]]:
        try:
            resp = requests.get(
                f"{self.url}/{self.index}/_search",
                json={"query": {"term": {"module": module}}},
                auth=self.auth,
                timeout=5,
            )
            hits = resp.json().get("hits", {}).get("hits", [])
            return [h.get("_source", {}) for h in hits]
        except Exception:
            return []

    def clear_all(self) -> None:
        try:
            requests.delete(
                f"{self.url}/{self.index}",
                auth=self.auth,
                timeout=5,
            )
        except Exception:
            self.log.warning("ElasticSearch backend: failed to clear_all", exc_info=True)


# ============================================================
#  ThreatConnector 6.0 — Async Queue + Batched Writes
# ============================================================

class ThreatConnector:
    """
    ThreatConnector 6.0
    -------------------
    • Плагинные backend'ы: NDJSON / SQLite / ElasticSearch
    • Дедупликация по module + target + hash(result)
    • Кэш хешей в памяти
    • Асинхронная очередь артефактов
    • Batched writes (по умолчанию пачки до 50 элементов)
    """

    def __init__(
        self,
        backend: ThreatBackendBase,
        batch_size: int = 50,
        flush_interval: float = 1.0,
    ):
        self.backend = backend
        self.log = logging.getLogger("ThreatConnector")
        self.log.setLevel(logging.INFO)

        self._hash_cache = set()
        self._load_initial_hashes()

        self._queue: "Queue[Dict[str, Any]]" = Queue()
        self._batch_size = max(1, batch_size)
        self._flush_interval = max(0.1, flush_interval)

        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="ThreatConnectorWorker",
            daemon=True,
        )
        self._worker_thread.start()

    # ---------------------------------------------------------
    #  Инициализация кэша хешей
    # ---------------------------------------------------------
    def _load_initial_hashes(self) -> None:
        try:
            for a in self.backend.load_all():
                h = a.get("_hash")
                if h:
                    self._hash_cache.add(h)
        except Exception:
            self.log.warning("Failed to preload hashes from backend", exc_info=True)

    # ---------------------------------------------------------
    #  Хеширование артефакта
    # ---------------------------------------------------------
    def _hash_artifact(self, module: str, target: str, result: Dict[str, Any]) -> str:
        h = hashlib.sha256()
        h.update(module.encode())
        h.update(target.encode())
        h.update(json.dumps(result, sort_keys=True, default=str).encode())
        return h.hexdigest()

    # ---------------------------------------------------------
    #  Публичный API: emit / bulk
    # ---------------------------------------------------------
    def emit(self, module: str, target: str, result: Dict[str, Any]) -> None:
        self.add_artifact(module, target, [result])

    def bulk(self, module: str, target: str, results: List[Dict[str, Any]]) -> None:
        self.add_artifact(module, target, results)

    # ---------------------------------------------------------
    #  Добавление артефактов (асинхронно, через очередь)
    # ---------------------------------------------------------
    def add_artifact(self, module_name: str, target: str, results: List[Dict[str, Any]]) -> None:
        timestamp = datetime.utcnow().isoformat() + "Z"

        for result in results:
            result.setdefault("severity", "info")
            result.setdefault("category", module_name.lower())
            result.setdefault("tags", [])
            result.setdefault("source", "engine")

            h = self._hash_artifact(module_name, target, result)
            if h in self._hash_cache:
                continue

            artifact = {
                "_hash": h,
                "timestamp": timestamp,
                "module": module_name,
                "target": target,
                "result": result,
            }

            self._hash_cache.add(h)
            self._queue.put(artifact)

    # ---------------------------------------------------------
    #  Worker: batched writes
    # ---------------------------------------------------------
    def _worker_loop(self) -> None:
        """
        Фоновый поток:
        • собирает артефакты из очереди
        • пишет их пачками в backend
        """
        batch: List[Dict[str, Any]] = []

        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=self._flush_interval)
                batch.append(item)

                if len(batch) >= self._batch_size:
                    self._flush_batch(batch)
                    batch = []
            except Empty:
                if batch:
                    self._flush_batch(batch)
                    batch = []
                continue
            except Exception:
                self.log.error("ThreatConnector worker loop error", exc_info=True)

        # Финальный сброс при остановке
        if batch:
            self._flush_batch(batch)

    def _flush_batch(self, batch: List[Dict[str, Any]]) -> None:
        try:
            self.backend.add_batch(batch)
            self.log.info(f"[ThreatIntel] Flushed {len(batch)} artifacts")
            for a in batch:
                self.log.debug(f"[ThreatIntel] {a.get('module')} → {a.get('target')}")
        except Exception:
            self.log.error("Failed to flush batch to backend", exc_info=True)
        finally:
            # очищаем батч независимо от результата
            batch.clear()

    # ---------------------------------------------------------
    #  Управление жизненным циклом
    # ---------------------------------------------------------
    def shutdown(self) -> None:
        """
        Корректная остановка worker'а.
        Вызывать при завершении приложения.
        """
        self._stop_event.set()
        self._worker_thread.join(timeout=5)

    # ---------------------------------------------------------
    #  Чтение / фильтры / отчёты
    # ---------------------------------------------------------
    def load_all(self) -> List[Dict[str, Any]]:
        """
        Чтение всегда идёт из backend (источник истины).
        """
        try:
            return self.backend.load_all()
        except Exception:
            self.log.error("Failed to load_all from backend", exc_info=True)
            return []

    def filter_by_module(self, module: str) -> List[Dict[str, Any]]:
        data = self.load_all()
        return [a for a in data if a.get("module") == module]

    def filter_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        data = self.load_all()
        return [a for a in data if a["result"].get("severity") == severity]

    def filter_by_target(self, target: str) -> List[Dict[str, Any]]:
        data = self.load_all()
        return [a for a in data if a.get("target") == target]

    def summary(self) -> Dict[str, Any]:
        data = self.load_all()
        by_module: Dict[str, int] = {}

        for a in data:
            mod = a.get("module", "unknown")
            by_module[mod] = by_module.get(mod, 0) + 1

        return {
            "total": len(data),
            "by_module": by_module,
        }

    def generate_report(self) -> Dict[str, Any]:
        data = self.load_all()

        report = {
            "total": len(data),
            "by_module": {},
            "by_severity": {},
            "by_category": {},
            "by_source": {},
            "artifacts": data,
        }

        for a in data:
            mod = a.get("module", "unknown")
            sev = a["result"].get("severity", "info")
            cat = a["result"].get("category", "unknown")
            src = a["result"].get("source", "unknown")

            report["by_module"][mod] = report["by_module"].get(mod, 0) + 1
            report["by_severity"][sev] = report["by_severity"].get(sev, 0) + 1
            report["by_category"][cat] = report["by_category"].get(cat, 0) + 1
            report["by_source"][src] = report["by_source"].get(src, 0) + 1

        return report


# ============================================================
#  Глобальный экземпляр ThreatConnector 6.0
# ============================================================

def _build_backend_from_env() -> ThreatBackendBase:
    """
    THREAT_BACKEND=ndjson|sqlite|elastic

    Для ElasticSearch:
      THREAT_ES_URL=https://localhost:9200
      THREAT_ES_INDEX=threat_intel
      THREAT_ES_USER=...
      THREAT_ES_PASS=...
    """
    backend_type = os.environ.get("THREAT_BACKEND", "ndjson").lower()

    if backend_type == "sqlite":
        return SQLiteBackend()

    if backend_type == "elastic":
        url = os.environ.get("THREAT_ES_URL", "http://localhost:9200")
        index = os.environ.get("THREAT_ES_INDEX", "threat_intel")
        user = os.environ.get("THREAT_ES_USER")
        pwd = os.environ.get("THREAT_ES_PASS")
        return ElasticSearchBackend(url=url, index=index, username=user, password=pwd)

    return NdjsonBackend()


THREAT_CONNECTOR = ThreatConnector(_build_backend_from_env())