# xss_security_gui/threat_analysis/backends/sqlite_backend.py
import os
import json
import sqlite3
import hashlib
import threading
from datetime import datetime
from typing import Dict, Any, Iterable, List, Optional

from xss_security_gui.threat_analysis.backends.base_backend import ThreatBackendBase
from xss_security_gui.threat_data_loader import ThreatRisk

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)



class SQLiteBackend(ThreatBackendBase):
    """
    SQLiteBackend 11.0 — Combat‑Grade Threat Intel Backend
    ------------------------------------------------------
    • Ultra‑fast WAL SQLite
    • Full Pipeline 11.0 support:
        - category
        - type
        - chain
        - details
        - suggestions
        - raw result_json
    • Automatic schema migration (safe)
    • Query API with limit/offset (GUI‑friendly)
    • Compatible with ThreatEngine 12.0 / LiveAttackMonitor 11.0
    """

    def __init__(self, filename: str = "threat_intel_gui.db"):
        super().__init__()
        self.db_path = os.path.join(LOGS_DIR, filename)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        self._lock = threading.RLock()
        self._init_db()
        self._migrate_schema()

    # ============================================================
    # DB connect
    # ============================================================
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA mmap_size=268435456;")  # 256MB mmap
        return conn

    # ============================================================
    # Initial schema
    # ============================================================
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hash ON artifacts(hash);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_module ON artifacts(module);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_target ON artifacts(target);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON artifacts(timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_category ON artifacts(category);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_risk ON artifacts(risk);")
            # Create indexes only if column exists
            cols = {row[1] for row in conn.execute("PRAGMA table_info(artifacts)").fetchall()}

            if "type" in cols:
                conn.execute("CREATE INDEX IF NOT EXISTS idx_type ON artifacts(type);")

            if "chain" in cols:
                conn.execute("CREATE INDEX IF NOT EXISTS idx_chain ON artifacts(chain);")

            conn.commit()
        finally:
            conn.close()

    # ============================================================
    # Schema migration (Pipeline 11.0)
    # ============================================================
    def _migrate_schema(self):
        conn = self._connect()
        try:
            cols = [
                ("category", "TEXT"),
                ("type", "TEXT"),
                ("chain", "TEXT"),
                ("details", "TEXT"),
                ("suggestions", "TEXT"),
            ]
            for col, typ in cols:
                try:
                    conn.execute(f"ALTER TABLE artifacts ADD COLUMN {col} {typ}")
                except Exception:
                    pass
            conn.commit()
        finally:
            conn.close()

    # ============================================================
    # Hash
    # ============================================================
    def _ensure_hash(self, a: Dict[str, Any]) -> Dict[str, Any]:
        if a.get("_hash"):
            return a
        raw = json.dumps(a, sort_keys=True, ensure_ascii=False, default=str)
        a["_hash"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return a

    # ============================================================
    # Add artifact
    # ============================================================
    def add_artifact(self, artifact: Dict[str, Any]) -> None:
        self.add_batch([artifact])

    # ============================================================
    # Batch insert (L1-safe)
    # ============================================================
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

    # ============================================================
    # Load all (debug only)
    # ============================================================
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

    # ============================================================
    # Update artifact
    # ============================================================
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

    # ============================================================
    # Delete
    # ============================================================
    def delete_artifact(self, hash_value: str) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM artifacts WHERE hash=?", (hash_value,))
                conn.commit()
            finally:
                conn.close()

    # ============================================================
    # Query API (GUI-friendly)
    # ============================================================
    def query(
        self,
        *,
        category: Optional[str] = None,
        risk: Optional[str] = None,
        module: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "timestamp",
        order_desc: bool = True,
    ) -> List[Dict[str, Any]]:
        allowed_cols = {"timestamp", "risk", "module", "category", "type", "chain"}
        col = order_by if order_by in allowed_cols else "timestamp"
        direction = "DESC" if order_desc else "ASC"

        clauses = []
        params = []

        if category:
            clauses.append("category = ?")
            params.append(category)
        if risk:
            clauses.append("LOWER(risk) = LOWER(?)")
            params.append(risk)
        if module:
            clauses.append("LOWER(module) = LOWER(?)")
            params.append(module)
        if search:
            clauses.append("(result_json LIKE ? OR module LIKE ? OR target LIKE ? OR chain LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like, like])

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        sql = f"""
            SELECT hash, timestamp, module, target, risk, category, type, chain, details, suggestions, result_json
            FROM artifacts
            {where}
            ORDER BY {col} {direction}
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(sql, params).fetchall()
            finally:
                conn.close()

        result = []
        for h, ts, mod, tgt, rsk, cat, typ, chain, details, suggestions, res_json in rows:
            try:
                res = json.loads(res_json)
            except Exception:
                res = {}

            res["risk"] = rsk
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

    # ============================================================
    # Count
    # ============================================================
    def count(
        self,
        *,
        category: Optional[str] = None,
        risk: Optional[str] = None,
        module: Optional[str] = None,
        search: Optional[str] = None,
    ) -> int:
        clauses = []
        params = []

        if category:
            clauses.append("category = ?")
            params.append(category)
        if risk:
            clauses.append("LOWER(risk) = LOWER(?)")
            params.append(risk)
        if module:
            clauses.append("LOWER(module) = LOWER(?)")
            params.append(module)
        if search:
            clauses.append("(result_json LIKE ? OR module LIKE ? OR target LIKE ? OR chain LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like, like])

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT COUNT(*) FROM artifacts {where}"

        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(sql, params).fetchone()
            finally:
                conn.close()

        return row[0] if row else 0

    # ============================================================
    # Clear
    # ============================================================
    def clear_all(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM artifacts")
                conn.commit()
            finally:
                conn.close()