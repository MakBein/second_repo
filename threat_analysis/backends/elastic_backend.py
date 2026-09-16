# xss_security_gui/threat_analysis/backends/elastic_backend.py

import json
import hashlib
import threading
from datetime import datetime
from time import sleep
from typing import Dict, Any, Iterable, List, Optional

import requests

from xss_security_gui.threat_analysis.backends.base_backend import ThreatBackendBase
from xss_security_gui.threat_data_loader import ThreatRisk


class ElasticSearchBackend(ThreatBackendBase):
    """
    ElasticSearchBackend 11.0 — Combat‑Grade Threat Intel Backend
    """

    def __init__(
        self,
        url: str,
        index: str = "threat_intel",
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 5.0,
        max_bulk_size: int = 1000,
    ):
        super().__init__()
        self.url = url.rstrip("/")
        self.index = index
        self.auth = (username, password) if username and password else None
        self.timeout = timeout
        self.max_bulk_size = max_bulk_size

        self.log = logging.getLogger("ThreatConnector")

        self._lock = threading.RLock()
        self._by_hash: dict[str, Dict[str, Any]] = {}
        self._by_module: dict[str, List[Dict[str, Any]]] = {}
        self._by_target: dict[str, List[Dict[str, Any]]] = {}

        self._ensure_index_exists()
        self._load_indexes()

    def _normalize(self, src: Dict[str, Any]) -> Dict[str, Any]:
        res = src.get("result", {}) or {}

        res["risk"] = ThreatRisk.normalize(res.get("risk"))
        res.setdefault("category", "unknown")
        res.setdefault("type", "")
        res.setdefault("chain", "")
        res.setdefault("details", "")
        res.setdefault("suggestions", [])

        src["result"] = res
        return src

    def _ensure_hash(self, a: Dict[str, Any]) -> Dict[str, Any]:
        if a.get("_hash"):
            return a
        raw = json.dumps(a, sort_keys=True, ensure_ascii=False, default=str)
        a["_hash"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return a

    def _index_artifact(self, a: Dict[str, Any]) -> None:
        a = self._ensure_hash(a)
        h = a["_hash"]

        mod = a.get("module", "unknown")
        tgt = a.get("target", "unknown")

        self._by_hash[h] = a
        self._by_module.setdefault(mod, []).append(a)
        self._by_target.setdefault(tgt, []).append(a)

    def _ensure_index_exists(self) -> None:
        try:
            resp = requests.head(
                f"{self.url}/{self.index}",
                auth=self.auth,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                return
        except Exception:
            pass

        mapping = {
            "mappings": {
                "properties": {
                    "_hash": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "module": {"type": "keyword"},
                    "target": {"type": "keyword"},
                    "result": {
                        "properties": {
                            "risk": {"type": "keyword"},
                            "category": {"type": "keyword"},
                            "type": {"type": "keyword"},
                            "chain": {"type": "keyword"},
                            "details": {"type": "text"},
                            "suggestions": {"type": "keyword"},
                        }
                    },
                }
            }
        }

        try:
            resp = requests.put(
                f"{self.url}/{self.index}",
                json=mapping,
                auth=self.auth,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            self.log.info("ElasticSearch backend: index %s created", self.index)
        except Exception as e:
            self.log.warning("ElasticSearch backend: failed to create index: %s", e)

    def _load_indexes(self) -> None:
        try:
            resp = requests.get(
                f"{self.url}/{self.index}/_search",
                json={"query": {"match_all": {}}, "size": 10000},
                auth=self.auth,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            hits = resp.json().get("hits", {}).get("hits", [])
        except Exception as e:
            self.log.warning("ElasticSearch backend: failed to load indexes: %s", e)
            return

        with self._lock:
            for h in hits:
                src = self._normalize(h.get("_source", {}))
                self._index_artifact(src)

    def _bulk_send(self, bulk_lines: List[str]) -> None:
        if not bulk_lines:
            return

        data = "\n".join(bulk_lines) + "\n"
        max_retries = 3
        backoff = 1.0

        for attempt in range(1, max_retries + 1):
            try:
                resp = requests.post(
                    f"{self.url}/_bulk",
                    data=data,
                    headers={"Content-Type": "application/x-ndjson"},
                    auth=self.auth,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                body = resp.json()
                if body.get("errors"):
                    self.log.warning("ElasticSearch bulk: partial errors")
                return
            except Exception as e:
                self.log.warning("ElasticSearch bulk attempt %d failed: %s", attempt, e)
                sleep(backoff)
                backoff *= 2.0

        self.log.error("ElasticSearch bulk: all retries failed")

    def add_artifact(self, artifact: Dict[str, Any]) -> None:
        self.add_batch([artifact])

    def add_batch(self, artifacts: Iterable[Dict[str, Any]]) -> None:
        artifacts = list(artifacts)
        if not artifacts:
            return

        bulk_lines: List[str] = []

        with self._lock:
            for a in artifacts:
                a = self.normalize_artifact(a)
                a = self._normalize(a)
                a = self._ensure_hash(a)

                h = a["_hash"]
                if h in self._by_hash:
                    continue

                ts = a.get("timestamp") or datetime.utcnow().isoformat()
                a["timestamp"] = ts

                self._index_artifact(a)

                meta = {"index": {"_index": self.index, "_id": h}}
                bulk_lines.append(json.dumps(meta, ensure_ascii=False))
                bulk_lines.append(json.dumps(a, ensure_ascii=False))

                if len(bulk_lines) >= self.max_bulk_size * 2:
                    self._bulk_send(bulk_lines)
                    bulk_lines = []

        if bulk_lines:
            self._bulk_send(bulk_lines)

    def load_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._by_hash.values())

    def update_artifact(self, artifact: Dict[str, Any]) -> None:
        artifact = self.normalize_artifact(artifact)
        artifact = self._normalize(artifact)
        artifact = self._ensure_hash(artifact)

        h = artifact["_hash"]
        if not h:
            return

        with self._lock:
            old = self._by_hash.get(h)
            if not old:
                return

            old_mod = old.get("module", "unknown")
            old_tgt = old.get("target", "unknown")

            self._by_module[old_mod] = [
                x for x in self._by_module.get(old_mod, []) if x.get("_hash") != h
            ]
            self._by_target[old_tgt] = [
                x for x in self._by_target.get(old_tgt, []) if x.get("_hash") != h
            ]

            ts = artifact.get("timestamp") or datetime.utcnow().isoformat()
            artifact["timestamp"] = ts

            self._index_artifact(artifact)

            try:
                resp = requests.put(
                    f"{self.url}/{self.index}/_doc/{h}",
                    json=artifact,
                    auth=self.auth,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
            except Exception as e:
                self.log.warning("ElasticSearch update failed: %s", e)

    def delete_artifact(self, hash_value: str) -> None:
        with self._lock:
            a = self._by_hash.pop(hash_value, None)
            if not a:
                return

            mod = a.get("module", "unknown")
            tgt = a.get("target", "unknown")

            self._by_module[mod] = [
                x for x in self._by_module.get(mod, []) if x.get("_hash") != hash_value
            ]
            self._by_target[tgt] = [
                x for x in self._by_target.get(tgt, []) if x.get("_hash") != hash_value
            ]

        try:
            resp = requests.delete(
                f"{self.url}/{self.index}/_doc/{hash_value}",
                auth=self.auth,
                timeout=self.timeout,
            )
            if resp.status_code not in (200, 404):
                self.log.warning("ElasticSearch delete failed: %s", resp.text)
        except Exception as e:
            self.log.warning("ElasticSearch delete error: %s", e)

    def find_by_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._by_hash.get(hash_value)

    def find_by_target(self, target: str) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._by_target.get(target, []))

    def find_by_module(self, module: str) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._by_module.get(module, []))

    def clear_all(self) -> None:
        with self._lock:
            self._by_hash.clear()
            self._by_module.clear()
            self._by_target.clear()

        try:
            resp = requests.delete(
                f"{self.url}/{self.index}",
                auth=self.auth,
                timeout=self.timeout,
            )
            if resp.status_code not in (200, 404):
                self.log.warning("ElasticSearch clear_all: %s", resp.text)
        except Exception as e:
            self.log.warning("ElasticSearch clear_all error: %s", e)
