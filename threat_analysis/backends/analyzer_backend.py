# xss_security_gui/threat_analysis/analyzer_backend.py

import os
import json
import sqlite3
import hashlib
import threading
from datetime import datetime
from typing import Dict, Any, Iterable, List

from xss_security_gui.threat_analysis.backends.base_backend import ThreatBackendBase
from xss_security_gui.threat_data_loader import ThreatRisk

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)


class AnalyzerJsonBackend(ThreatBackendBase):
    """
    AnalyzerJsonBackend 11.0 — Combat‑Grade SQLite Backend
    ------------------------------------------------------
    • JSON → SQLite (WAL, NORMAL sync)
    • Автоматичні міграції (schema evolution)
    • Підтримка Pipeline 11.0:
        - category
        - type
        - chain
        - details
        - suggestions
        - raw result_json
    """

    def __init__(self, filename: str = "analyzer1.db"):
        self.db_path = os.path.join(LOGS_DIR, filename)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        self._lock = threading.RLock()
        self._init_db()
        self._migrate_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA mmap_size=268435456;")
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
                    risk TEXT,
                    category TEXT,
                    type TEXT,
                    chain TEXT,
                    details TEXT,
                    suggestions TEXT,
                    result_json TEXT
                )
                """
            )

            cols = {row[1] for row in conn.execute("PRAGMA table_info(artifacts)").fetchall()}

            if "hash" in cols:
                conn.execute("CREATE INDEX IF NOT EXISTS idx_hash ON artifacts(hash);")
            if "module" in cols:
                conn.execute("CREATE INDEX IF NOT EXISTS idx_module ON artifacts(module);")
            if "target" in cols:
                conn.execute("CREATE INDEX IF NOT EXISTS idx_target ON artifacts(target);")
            if "timestamp" in cols:
                conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON artifacts(timestamp);")
            if "category" in cols:
                conn.execute("CREATE INDEX IF NOT EXISTS idx_category ON artifacts(category);")
            if "risk" in cols:
                conn.execute("CREATE INDEX IF NOT EXISTS idx_risk ON artifacts(risk);")
            if "type" in cols:
                conn.execute("CREATE INDEX IF NOT EXISTS idx_type ON artifacts(type);")
            if "chain" in cols:
                conn.execute("CREATE INDEX IF NOT EXISTS idx_chain ON artifacts(chain);")

            conn.commit()
        finally:
            conn.close()

    def _migrate_schema(self):
        conn = self._connect()
        try:
            existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(artifacts)").fetchall()}

            migrations = [
                ("category", "TEXT"),
                ("type", "TEXT"),
                ("chain", "TEXT"),
                ("details", "TEXT"),
                ("suggestions", "TEXT"),
            ]

            for col, typ in migrations:
                if col not in existing_cols:
                    try:
                        conn.execute(f"ALTER TABLE artifacts ADD COLUMN {col} {typ}")
                    except Exception as e:
                        print(f"[Migration] Failed to add column {col}: {e}")

            conn.commit()
        finally:
            conn.close()

    def _ensure_hash(self, a: Dict[str, Any]) -> Dict[str, Any]:
        if a.get("_hash"):
            return a
        raw = json.dumps(a, sort_keys=True, ensure_ascii=False, default=str)
        a["_hash"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return a

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
                    a = self.normalize_artifact(a)
                    a = self._ensure_hash(a)

                    ts = a.get("timestamp") or datetime.utcnow().isoformat()
                    mod = a.get("module", "unknown")
                    tgt = a.get("target", "unknown")

                    res = a.get("result", {}) or {}
                    risk = ThreatRisk.normalize(res.get("risk"))
                    category = res.get("category", "unknown")
                    typ = res.get("type", "")
                    chain = res.get("chain", "")
                    details = res.get("details", "")
                    suggestions = json.dumps(res.get("suggestions", []), ensure_ascii=False)

                    conn.execute(
                        """
                        INSERT OR IGNORE INTO artifacts
                        (hash, timestamp, module, target, risk, category, type, chain, details, suggestions, result_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            a["_hash"],
                            ts,
                            mod,
                            tgt,
                            risk,
                            category,
                            typ,
                            chain,
                            details,
                            suggestions,
                            json.dumps(res, ensure_ascii=False, default=str),
                        ),
                    )
                conn.commit()
            finally:
                conn.close()

    def load_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT hash, timestamp, module, target, risk, category, type, chain, details, suggestions, result_json
                    FROM artifacts
                    """
                ).fetchall()
            finally:
                conn.close()

        result = []
        for h, ts, mod, tgt, risk, cat, typ, chain, details, suggestions, res_json in rows:
            try:
                res = json.loads(res_json)
            except Exception:
                res = {}

            res["risk"] = risk
            res["category"] = cat
            res["type"] = typ
            res["chain"] = chain
            res["details"] = details

            try:
                res["suggestions"] = json.loads(suggestions)
            except Exception:
                res["suggestions"] = suggestions

            result.append({
                "_hash": h,
                "timestamp": ts,
                "module": mod,
                "target": tgt,
                "result": res,
            })

        return result

    def update_artifact(self, artifact: Dict[str, Any]) -> None:
        artifact = self._ensure_hash(self.normalize_artifact(artifact))
        h = artifact["_hash"]

        ts = artifact.get("timestamp") or datetime.utcnow().isoformat()
        mod = artifact.get("module", "unknown")
        tgt = artifact.get("target", "unknown")

        res = artifact.get("result", {}) or {}
        risk = ThreatRisk.normalize(res.get("risk"))
        category = res.get("category", "unknown")
        typ = res.get("type", "")
        chain = res.get("chain", "")
        details = res.get("details", "")
        suggestions = json.dumps(res.get("suggestions", []), ensure_ascii=False)

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    UPDATE artifacts
                    SET timestamp=?, module=?, target=?, risk=?, category=?, type=?, chain=?, details=?, suggestions=?, result_json=?
                    WHERE hash=?
                    """,
                    (
                        ts,
                        mod,
                        tgt,
                        risk,
                        category,
                        typ,
                        chain,
                        details,
                        suggestions,
                        json.dumps(res, ensure_ascii=False, default=str),
                        h,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def delete_artifact(self, hash_value: str) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM artifacts WHERE hash=?", (hash_value,))
                conn.commit()
            finally:
                conn.close()

    def clear_all(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM artifacts")
                conn.commit()
            finally:
                conn.close()
