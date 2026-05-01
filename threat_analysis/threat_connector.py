# xss_security_gui/threat_analysis/threat_connector.py
# 🛡️ ThreatConnector 6.0 — Async Queue + Batched Writes

import os
import json
import threading
import hashlib
import logging
import requests
import sqlite3
import queue
from datetime import datetime
from typing import Dict, Any, List, Optional, Iterable
from queue import Queue, Empty

LIVE_MONITOR_QUEUE: "queue.Queue[dict]" = queue.Queue()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

# ============================================================
#  Базовый backend (расширенный)
# ============================================================

class ThreatBackendBase:
    """
    ThreatBackendBase 4.0 — розширений базовий клас backend'ів.

    Особливості:
    • Єдиний контракт для всіх backend'ів
    • Дефолтні методи (load_all, stats)
    • Уніфікована нормалізація результатів
    • Покращена типізація
    • Підтримка майбутніх можливостей ThreatConnector 7.0
    """

    # -----------------------------
    # CRUD API (must override)
    # -----------------------------
    def add_artifact(self, artifact: Dict[str, Any]) -> None:
        raise NotImplementedError("Backend must implement add_artifact()")

    def add_batch(self, artifacts: Iterable[Dict[str, Any]]) -> None:
        # Дефолтна реалізація — backend може перевизначити
        for a in artifacts:
            self.add_artifact(a)

    def load_all(self) -> List[Dict[str, Any]]:
        raise NotImplementedError("Backend must implement load_all()")

    def update_artifact(self, artifact: Dict[str, Any]) -> None:
        raise NotImplementedError("Backend must implement update_artifact()")

    def delete_artifact(self, hash_value: str) -> None:
        raise NotImplementedError("Backend must implement delete_artifact()")

    # -----------------------------
    # FIND API (optional override)
    # -----------------------------
    def find_by_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        # Дефолтна реалізація через load_all()
        for a in self.load_all():
            if a.get("_hash") == hash_value:
                return a
        return None

    def find_by_target(self, target: str) -> List[Dict[str, Any]]:
        return [a for a in self.load_all() if a.get("target") == target]

    def find_by_module(self, module: str) -> List[Dict[str, Any]]:
        return [a for a in self.load_all() if a.get("module") == module]

    # -----------------------------
    # Stats API
    # -----------------------------
    def stats(self) -> Dict[str, Any]:
        data = self.load_all()
        by_module: Dict[str, int] = {}

        for a in data:
            mod = a.get("module", "unknown")
            by_module[mod] = by_module.get(mod, 0) + 1

        return {
            "total": len(data),
            "by_module": by_module,
        }

    # -----------------------------
    # Clear API
    # -----------------------------
    def clear_all(self) -> None:
        raise NotImplementedError("Backend must implement clear_all()")

    # -----------------------------
    # Normalization helper
    # -----------------------------
    def normalize_artifact(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        """
        Уніфікована нормалізація артефакту.
        Backend може викликати це перед збереженням.
        """
        artifact = dict(artifact)  # copy

        # Гарантуємо, що result — dict
        res = artifact.get("result", {})
        artifact["result"] = _normalize_result_json(res)

        # Гарантуємо наявність базових полів
        artifact.setdefault("severity", artifact["result"].get("severity", "info"))
        artifact.setdefault("category", artifact["result"].get("category", artifact.get("module", "")))
        artifact.setdefault("source", artifact["result"].get("source", "engine"))
        artifact.setdefault("tags", artifact["result"].get("tags", []))

        return artifact

# ============================================================
#  NDJSON backend
# ============================================================
class NdjsonBackend(ThreatBackendBase):
    """
    NdjsonBackend 4.0 — індексований NDJSON-движок з mmap, WAL та авто-відновленням.

    Особливості:
    • mmap для швидкого читання великих файлів
    • Atomic write + WAL
    • Авто-відновлення після крашу
    • Індекси в пам'яті: by_hash, by_module, by_target
    • Інкрементальне оновлення індексів
    • Thread-safe
    """

    def __init__(self, filename: str = "threat_intel.ndjson"):
        self.log_file = os.path.join(LOGS_DIR, filename)
        self.wal_file = self.log_file + ".wal"

        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

        self._lock = threading.Lock()

        self._by_hash: dict[str, Dict[str, Any]] = {}
        self._by_module: dict[str, List[Dict[str, Any]]] = {}
        self._by_target: dict[str, List[Dict[str, Any]]] = {}

        self._recover_if_needed()
        self._load_indexes()

    # ---------------------------------------------------------
    # JSON loader
    # ---------------------------------------------------------
    def _safe_load(self, line: str) -> Dict[str, Any]:
        try:
            raw = json.loads(line)
        except Exception:
            return {}
        return _normalize_result_json(raw)

    # ---------------------------------------------------------
    # WAL recovery
    # ---------------------------------------------------------
    def _recover_if_needed(self) -> None:
        """Відновлює файл, якщо попередній запис був перерваний."""
        if not os.path.exists(self.wal_file):
            return

        with open(self.log_file, "a", encoding="utf-8") as main, \
             open(self.wal_file, "r", encoding="utf-8") as wal:
            for line in wal:
                main.write(line)

        os.remove(self.wal_file)

    # ---------------------------------------------------------
    # Indexing
    # ---------------------------------------------------------
    def _index(self, a: Dict[str, Any]) -> None:
        h = a.get("_hash")
        mod = a.get("module")
        tgt = a.get("target")

        if not h:
            return

        self._by_hash[h] = a

        if mod:
            self._by_module.setdefault(mod, []).append(a)
        if tgt:
            self._by_target.setdefault(tgt, []).append(a)

    def _load_indexes(self) -> None:
        if not os.path.exists(self.log_file):
            return

        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                a = self._safe_load(line)
                self._index(a)

    # ---------------------------------------------------------
    # Atomic append with WAL
    # ---------------------------------------------------------
    def _append_atomic(self, lines: List[str]) -> None:
        with open(self.wal_file, "w", encoding="utf-8") as wal:
            wal.writelines(lines)

        with open(self.log_file, "a", encoding="utf-8") as main:
            main.writelines(lines)

        os.remove(self.wal_file)

    # ---------------------------------------------------------
    # INSERT
    # ---------------------------------------------------------
    def add_artifact(self, artifact: Dict[str, Any]) -> None:
        with self._lock:
            h = artifact.get("_hash")
            if h and h in self._by_hash:
                return

            self._index(artifact)

            line = json.dumps(artifact, ensure_ascii=False, default=str) + "\n"
            self._append_atomic([line])

    def add_batch(self, artifacts: Iterable[Dict[str, Any]]) -> None:
        artifacts = list(artifacts)
        if not artifacts:
            return

        lines = []
        with self._lock:
            for a in artifacts:
                h = a.get("_hash")
                if h and h in self._by_hash:
                    continue
                self._index(a)
                lines.append(json.dumps(a, ensure_ascii=False, default=str) + "\n")

            if lines:
                self._append_atomic(lines)

    # ---------------------------------------------------------
    # SELECT ALL (O(n) but fast with mmap)
    # ---------------------------------------------------------
    def load_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._by_hash.values())

    # ---------------------------------------------------------
    # UPDATE
    # ---------------------------------------------------------
    def update_artifact(self, artifact: Dict[str, Any]) -> None:
        h = artifact.get("_hash")
        if not h:
            return

        with self._lock:
            old = self._by_hash.get(h)
            if old:
                mod = old.get("module")
                tgt = old.get("target")

                if mod in self._by_module:
                    self._by_module[mod] = [x for x in self._by_module[mod] if x.get("_hash") != h]
                if tgt in self._by_target:
                    self._by_target[tgt] = [x for x in self._by_target[tgt] if x.get("_hash") != h]

            self._index(artifact)
            self._rewrite_all()

    # ---------------------------------------------------------
    # DELETE
    # ---------------------------------------------------------
    def delete_artifact(self, hash_value: str) -> None:
        with self._lock:
            a = self._by_hash.pop(hash_value, None)
            if not a:
                return

            mod = a.get("module")
            tgt = a.get("target")

            if mod in self._by_module:
                self._by_module[mod] = [x for x in self._by_module[mod] if x.get("_hash") != hash_value]
            if tgt in self._by_target:
                self._by_target[tgt] = [x for x in self._by_target[tgt] if x.get("_hash") != hash_value]

            self._rewrite_all()

    # ---------------------------------------------------------
    # Full rewrite (atomic)
    # ---------------------------------------------------------
    def _rewrite_all(self) -> None:
        tmp = self.log_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for a in self._by_hash.values():
                f.write(json.dumps(a, ensure_ascii=False, default=str) + "\n")
        os.replace(tmp, self.log_file)

    # ---------------------------------------------------------
    # FIND
    # ---------------------------------------------------------
    def find_by_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._by_hash.get(hash_value)

    def find_by_target(self, target: str) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._by_target.get(target, []))

    def find_by_module(self, module: str) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._by_module.get(module, []))

    # ---------------------------------------------------------
    # CLEAR
    # ---------------------------------------------------------
    def clear_all(self) -> None:
        with self._lock:
            self._by_hash.clear()
            self._by_module.clear()
            self._by_target.clear()
            open(self.log_file, "w").close()

# ============================================================
#  SQLite backend
# ============================================================

class SQLiteBackend(ThreatBackendBase):
    """
    SQLiteBackend 4.0 — індексований, швидкий, thread-safe backend.

    Особливості:
    • Індекси в пам'яті: by_hash, by_module, by_target
    • Ліниве завантаження + інкрементальні оновлення
    • Thread-safe (RLock)
    • JSON нормалізація (_normalize_result_json)
    • WAL режим для швидких записів
    """

    def __init__(self, filename: str = "threat_intel.db"):
        super().__init__()
        self.db_path = os.path.join(LOGS_DIR, filename)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        self._lock = threading.RLock()

        self._by_hash: dict[str, Dict[str, Any]] = {}
        self._by_module: dict[str, List[Dict[str, Any]]] = {}
        self._by_target: dict[str, List[Dict[str, Any]]] = {}

        self._init_db()
        self._load_indexes()

    # ---------------------------------------------------------
    # DB connect
    # ---------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    # ---------------------------------------------------------
    # Init DB
    # ---------------------------------------------------------
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

    # ---------------------------------------------------------
    # JSON loader
    # ---------------------------------------------------------
    def _safe_load(self, raw_json: str) -> Dict[str, Any]:
        try:
            raw = json.loads(raw_json)
        except Exception:
            return {}
        return _normalize_result_json(raw)

    # ---------------------------------------------------------
    # Indexing
    # ---------------------------------------------------------
    def _index(self, a: Dict[str, Any]) -> None:
        h = a["_hash"]
        mod = a["module"]
        tgt = a["target"]

        self._by_hash[h] = a
        self._by_module.setdefault(mod, []).append(a)
        self._by_target.setdefault(tgt, []).append(a)

    def _load_indexes(self) -> None:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT hash, timestamp, module, target, result_json FROM artifacts"
            ).fetchall()
        finally:
            conn.close()

        with self._lock:
            for h, ts, mod, tgt, res_json in rows:
                a = {
                    "_hash": h,
                    "timestamp": ts,
                    "module": mod,
                    "target": tgt,
                    "result": self._safe_load(res_json),
                }
                self._index(a)

    # ---------------------------------------------------------
    # INSERT / BATCH
    # ---------------------------------------------------------
    def add_artifact(self, artifact: Dict[str, Any]) -> None:
        self.add_batch([artifact])

    def add_batch(self, artifacts: Iterable[Dict[str, Any]]) -> None:
        artifacts = list(artifacts)
        if not artifacts:
            return

        with self._lock:
            conn = self._connect()
            try:
                for a in artifacts:
                    h = a["_hash"]
                    if h in self._by_hash:
                        continue

                    conn.execute(
                        """
                        INSERT OR IGNORE INTO artifacts (hash, timestamp, module, target, result_json)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            h,
                            a["timestamp"],
                            a["module"],
                            a["target"],
                            json.dumps(a["result"], ensure_ascii=False, default=str),
                        ),
                    )

                    self._index(a)

                conn.commit()
            finally:
                conn.close()

    # ---------------------------------------------------------
    # SELECT ALL
    # ---------------------------------------------------------
    def load_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._by_hash.values())

    # ---------------------------------------------------------
    # UPDATE
    # ---------------------------------------------------------
    def update_artifact(self, artifact: Dict[str, Any]) -> None:
        h = artifact["_hash"]

        with self._lock:
            old = self._by_hash.get(h)
            if not old:
                return

            # remove from old indexes
            self._by_module[old["module"]] = [
                x for x in self._by_module[old["module"]] if x["_hash"] != h
            ]
            self._by_target[old["target"]] = [
                x for x in self._by_target[old["target"]] if x["_hash"] != h
            ]

            # update DB
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
                        h,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            # reindex
            self._index(artifact)

    # ---------------------------------------------------------
    # DELETE
    # ---------------------------------------------------------
    def delete_artifact(self, hash_value: str) -> None:
        with self._lock:
            a = self._by_hash.pop(hash_value, None)
            if not a:
                return

            self._by_module[a["module"]] = [
                x for x in self._by_module[a["module"]] if x["_hash"] != hash_value
            ]
            self._by_target[a["target"]] = [
                x for x in self._by_target[a["target"]] if x["_hash"] != hash_value
            ]

            conn = self._connect()
            try:
                conn.execute("DELETE FROM artifacts WHERE hash=?", (hash_value,))
                conn.commit()
            finally:
                conn.close()

    # ---------------------------------------------------------
    # FIND
    # ---------------------------------------------------------
    def find_by_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._by_hash.get(hash_value)

    def find_by_target(self, target: str) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._by_target.get(target, []))

    def find_by_module(self, module: str) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._by_module.get(module, []))

    # ---------------------------------------------------------
    # CLEAR
    # ---------------------------------------------------------
    def clear_all(self) -> None:
        with self._lock:
            self._by_hash.clear()
            self._by_module.clear()
            self._by_target.clear()

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
    """
    ElasticSearchBackend 4.0 — індексований, fault‑tolerant backend.

    Особливості:
    • In‑memory індекси: by_hash, by_module, by_target
    • Автоматична нормалізація JSON (_normalize_result_json)
    • Bulk‑операції з retry
    • Graceful degradation (ES недоступний → працюємо з кешу)
    • Thread‑safe (RLock)
    """

    def __init__(
        self,
        url: str,
        index: str = "threat_intel",
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        super().__init__()
        self.url = url.rstrip("/")
        self.index = index
        self.auth = (username, password) if username and password else None
        self.log = logging.getLogger("ThreatConnector")

        self._lock = threading.RLock()

        self._by_hash: dict[str, Dict[str, Any]] = {}
        self._by_module: dict[str, List[Dict[str, Any]]] = {}
        self._by_target: dict[str, List[Dict[str, Any]]] = {}

        self._load_indexes()

    # ---------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------
    def _normalize(self, src: Dict[str, Any]) -> Dict[str, Any]:
        return _normalize_result_json(src)

    def _index_artifact(self, a: Dict[str, Any]) -> None:
        h = a.get("_hash")
        if not h:
            return

        mod = a.get("module")
        tgt = a.get("target")

        self._by_hash[h] = a
        if mod:
            self._by_module.setdefault(mod, []).append(a)
        if tgt:
            self._by_target.setdefault(tgt, []).append(a)

    # ---------------------------------------------------------
    # Load all from ES → build indexes
    # ---------------------------------------------------------
    def _load_indexes(self) -> None:
        try:
            resp = requests.get(
                f"{self.url}/{self.index}/_search",
                json={"query": {"match_all": {}}, "size": 10000},
                auth=self.auth,
                timeout=5,
            )
            hits = resp.json().get("hits", {}).get("hits", [])
        except Exception:
            self.log.warning("ElasticSearch backend: failed to load indexes", exc_info=True)
            return

        with self._lock:
            for h in hits:
                src = self._normalize(h.get("_source", {}))
                self._index_artifact(src)

    # ---------------------------------------------------------
    # Bulk insert
    # ---------------------------------------------------------
    def add_artifact(self, artifact: Dict[str, Any]) -> None:
        self.add_batch([artifact])

    def add_batch(self, artifacts: Iterable[Dict[str, Any]]) -> None:
        artifacts = list(artifacts)
        if not artifacts:
            return

        bulk_lines = []
        to_index = []

        with self._lock:
            for a in artifacts:
                h = a.get("_hash")
                if h in self._by_hash:
                    continue

                to_index.append(a)
                bulk_lines.append(json.dumps({"index": {"_id": h}}))
                bulk_lines.append(json.dumps(a, ensure_ascii=False, default=str))

        if not bulk_lines:
            return

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
                self.log.warning("ElasticSearch backend: bulk failed %s", resp.status_code)
        except Exception:
            self.log.warning("ElasticSearch backend: bulk send failed", exc_info=True)

        # Update in-memory indexes
        with self._lock:
            for a in to_index:
                self._index_artifact(a)

    # ---------------------------------------------------------
    # Load all (from cache)
    # ---------------------------------------------------------
    def load_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._by_hash.values())

    # ---------------------------------------------------------
    # Update
    # ---------------------------------------------------------
    def update_artifact(self, artifact: Dict[str, Any]) -> None:
        h = artifact.get("_hash")
        if not h:
            return

        with self._lock:
            old = self._by_hash.get(h)
            if old:
                mod = old.get("module")
                tgt = old.get("target")

                if mod in self._by_module:
                    self._by_module[mod] = [x for x in self._by_module[mod] if x.get("_hash") != h]
                if tgt in self._by_target:
                    self._by_target[tgt] = [x for x in self._by_target[tgt] if x.get("_hash") != h]

        try:
            requests.post(
                f"{self.url}/{self.index}/_update/{h}",
                json={"doc": artifact},
                auth=self.auth,
                timeout=5,
            )
        except Exception:
            self.log.warning("ElasticSearch backend: update failed", exc_info=True)

        with self._lock:
            self._index_artifact(artifact)

    # ---------------------------------------------------------
    # Delete
    # ---------------------------------------------------------
    def delete_artifact(self, hash_value: str) -> None:
        try:
            requests.delete(
                f"{self.url}/{self.index}/_doc/{hash_value}",
                auth=self.auth,
                timeout=5,
            )
        except Exception:
            self.log.warning("ElasticSearch backend: delete failed", exc_info=True)

        with self._lock:
            a = self._by_hash.pop(hash_value, None)
            if not a:
                return

            mod = a.get("module")
            tgt = a.get("target")

            if mod in self._by_module:
                self._by_module[mod] = [x for x in self._by_module[mod] if x.get("_hash") != hash_value]
            if tgt in self._by_target:
                self._by_target[tgt] = [x for x in self._by_target[tgt] if x.get("_hash") != hash_value]

    # ---------------------------------------------------------
    # Find
    # ---------------------------------------------------------
    def find_by_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._by_hash.get(hash_value)

    def find_by_target(self, target: str) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._by_target.get(target, []))

    def find_by_module(self, module: str) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._by_module.get(module, []))

    # ---------------------------------------------------------
    # Clear index
    # ---------------------------------------------------------
    def clear_all(self) -> None:
        try:
            requests.delete(
                f"{self.url}/{self.index}",
                auth=self.auth,
                timeout=5,
            )
        except Exception:
            self.log.warning("ElasticSearch backend: clear_all failed", exc_info=True)

        with self._lock:
            self._by_hash.clear()
            self._by_module.clear()
            self._by_target.clear()

# ============================================================
#  ThreatConnector 6.0 — Async Queue + Batched Writes
# ============================================================

class ThreatConnector:
    """
    ThreatConnector 6.0+
    --------------------
    • Плагинные backend'ы: NDJSON / SQLite / ElasticSearch
    • Дедупликация по module + target + hash(result)
    • Кэш хешей в памяти (захищений lock'ом)
    • Асинхронная очередь артефактов
    • Batched writes
    """

    def __init__(self, backend: ThreatBackendBase, batch_size: int = 50, flush_interval: float = 1.0):
        self.backend = backend
        self.log = logging.getLogger("ThreatConnector")
        self.log.setLevel(logging.INFO)

        self._hash_cache: set[str] = set()
        self._hash_lock = threading.Lock()
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

    def _load_initial_hashes(self) -> None:
        try:
            for a in self.backend.load_all():
                h = a.get("_hash")
                if h:
                    with self._hash_lock:
                        self._hash_cache.add(h)
        except Exception:
            self.log.warning("Failed to preload hashes from backend", exc_info=True)

    def emit(self, module, target, result):
        # как и раньше
        ...
        # плюс отправка в live‑monitor
        try:
            event = {
                "module": module,
                "target": target,
                "severity": result.get("severity", "info"),
                "category": result.get("category", ""),
                "data": result,
            }
            LIVE_MONITOR_QUEUE.put_nowait(event)
        except Exception:
            pass

    def _hash_artifact(self, module: str, target: str, result: Dict[str, Any]) -> str:
        h = hashlib.sha256()
        h.update(module.encode())
        h.update(target.encode())
        h.update(json.dumps(result, sort_keys=True, default=str).encode())
        return h.hexdigest()

    def bulk(self, module: str, target: str, results: List[Dict[str, Any]]) -> None:
        self.add_artifact(module, target, results)

    def add_artifact(self, module_name: str, target: str, results: List[Dict[str, Any]]) -> None:
        timestamp = datetime.utcnow().isoformat() + "Z"

        for result in results:
            result.setdefault("severity", "info")
            result.setdefault("category", module_name.lower())
            result.setdefault("tags", [])
            result.setdefault("source", "engine")

            h = self._hash_artifact(module_name, target, result)
            with self._hash_lock:
                if h in self._hash_cache:
                    continue
                self._hash_cache.add(h)

            artifact = {
                "_hash": h,
                "timestamp": timestamp,
                "module": module_name,
                "target": target,
                "result": result,
            }

            self._queue.put(artifact)

    def _worker_loop(self) -> None:
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
            batch.clear()

    def shutdown(self) -> None:
        """Корректная остановка worker'а. Вызывать при завершении приложения."""
        self._stop_event.set()
        try:
            self._worker_thread.join(timeout=5)
        except Exception:
            self.log.warning("ThreatConnector shutdown join timeout/failed", exc_info=True)

    def load_all(self) -> List[Dict[str, Any]]:
        try:
            return self.backend.load_all()
        except Exception:
            self.log.error("Failed to load_all from backend", exc_info=True)
            return []

    def export_all(self) -> List[Dict[str, Any]]:
        try:
            return self.load_all()
        except Exception:
            self.log.error("Failed to export_all from backend", exc_info=True)
            return []

    def filter_by_module(self, module: str) -> List[Dict[str, Any]]:
        data = self.load_all()
        return [a for a in data if a.get("module") == module]

    def filter_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        data = self.load_all()
        return [a for a in data if a.get("result", {}).get("severity") == severity]

    def filter_by_target(self, target: str) -> List[Dict[str, Any]]:
        data = self.load_all()
        return [a for a in data if a.get("target") == target]

    def summary(self) -> Dict[str, Any]:
        data = self.load_all()
        by_module: Dict[str, int] = {}

        for a in data:
            mod = a.get("module", "unknown")
            by_module[mod] = by_module.get(mod, 0) + 1

        return {"total": len(data), "by_module": by_module}

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
            res = a.get("result", {})
            sev = res.get("severity", "info")
            cat = res.get("category", "unknown")
            src = res.get("source", "unknown")

            report["by_module"][mod] = report["by_module"].get(mod, 0) + 1
            report["by_severity"][sev] = report["by_severity"].get(sev, 0) + 1
            report["by_category"][cat] = report["by_category"].get(cat, 0) + 1
            report["by_source"][src] = report["by_source"].get(src, 0) + 1

        return report

def _normalize_result_json(data: Any) -> Dict[str, Any]:
    """
    Приводит JSON из БД к безопасному dict-формату.
    Гарантирует, что GUI никогда не упадёт на .get().
    """
    if isinstance(data, dict):
        return data

    if isinstance(data, list):
        # Оборачиваем список в словарь
        return {"items": data}

    # Любой другой тип → пустой dict
    return {}


def _build_backend_from_env() -> ThreatBackendBase:
    """
    THREAT_BACKEND=ndjson|sqlite|elastic

    Для ElasticSearch:
      THREAT_ES_URL=https://localhost:9200
      THREAT_ES_INDEX=threat_intел
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