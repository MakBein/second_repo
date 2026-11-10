# xss_security_gui/threat_data_loader.py
"""
ThreatDataLoader 10.0 — Ultra‑safe Threat Intel Loader для GUI + воркерів.

Ключові принципи:
- НІКОЛИ не вантажить більше 500 записів за раз (жорсткий L1‑ліміт).
- ZERO load_all() — тільки ThreatConnector.query(...) з limit <= 500.
- L1 = невелике вікно для GUI (top‑500), L2 = SQLite/ES через ThreatConnector.
- Стрімінг для воркерів: iter_artifacts() / stream_query() (батчами по 500).
- Window‑pagination для GUI: window_query(page_size=500, page=N).
- Авто‑детект email/password + account_state_leak (як у 8.0).
- Повністю thread‑safe (_data_lock).
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Generator
import re
from threading import Lock, Thread

logger = logging.getLogger(__name__)

class ThreatCategory:
    EMAIL_LEAK = "email_leak"
    CREDIT_CARD_LEAK = "credit_card_leak"
    PASSWORD_DUMP = "password_dump"
    USER_DATA_LEAK = "user_data_leak"
    ACCOUNT_STATE_LEAK = "account_state_leak"
    PHONE_LEAK = "phone_leak"
    LOCATION_LEAK = "location_leak"


class ThreatRisk:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    ORDER = {
        CRITICAL: 4,
        HIGH: 3,
        MEDIUM: 2,
        LOW: 1,
        INFO: 0,
        UNKNOWN: -1,
    }

    @classmethod
    def normalize(cls, value: Any) -> str:
        if not value:
            return cls.UNKNOWN
        v = str(value).lower().strip()
        return v if v in cls.ORDER else cls.UNKNOWN

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}")
PASSWORD_HINT_REGEX = re.compile(r"(password|pass|pwd|smtp_password|smtp_pass)", re.I)


def _get_connector():
    from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
    return THREAT_CONNECTOR


class ThreatDataLoader:
    """
    ThreatDataLoader 10.0 — GUI‑safe Threat Intel Loader.

    - L1_LIMIT = 500 (жорстко, без винятків).
    - load() / load_async() працюють тільки через connector.query(limit<=500).
    - get_summary() рахує тільки по L1 (top‑500).
    - iter_artifacts()/stream_query()/window_query() працюють напряму через ThreatConnector.
    """

    L1_LIMIT = 500

    def __init__(
        self,
        json_path: Optional[Path | str] = None,
        base_dir: Optional[Path] = None,
        on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        debug_telemetry: bool = False,
        connector=None,
    ):
        if base_dir is None:
            base_dir = Path(__file__).resolve().parent

        if json_path is None:
            json_path = base_dir / "logs" / "analyzer1.json"
        else:
            json_path = Path(json_path)

        self.base_dir: Path = base_dir
        self.json_path: Path = json_path

        # L1 cache — тільки невелике вікно (до 500 артефактів)
        self.data: Dict[str, Any] = {}
        self.artifacts: List[Dict[str, Any]] = []

        self._index_by_module: Dict[str, List[Dict[str, Any]]] = {}
        self._index_by_category: Dict[str, List[Dict[str, Any]]] = {}
        self._index_by_risk: Dict[str, List[Dict[str, Any]]] = {}

        self.on_event = on_event
        self.debug_telemetry = debug_telemetry

        self._connector = connector
        self._data_lock = Lock()

    # ============================================================
    #  Connector property
    # ============================================================
    @property
    def connector(self):
        if self._connector is None:
            self._connector = _get_connector()
        return self._connector

    # ============================================================
    #  Internal helpers
    # ============================================================
    def _log_debug(self, msg: str) -> None:
        if self.debug_telemetry:
            logger.info(msg)

    def _emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        if not self.on_event:
            return
        try:
            self.on_event(event_type, payload)
        except Exception:
            logger.exception("ThreatDataLoader: on_event callback error")

    def get_email_leaks(self) -> List[Dict[str, Any]]:
        """
        GOD‑MODE:
        Повертає всі email_leak артефакти + артефакти, що містять email у PII.
        """
        leaks = []

        for artifact in getattr(self, "artifacts", []):
            result = artifact.get("result", {}) or {}
            category = result.get("category", "").lower()
            text_repr = str(result).lower()

            if category == "email_leak":
                leaks.append(artifact)
                continue

            # PII email detection
            if "@" in text_repr and ("email" in text_repr or "pii" in text_repr):
                leaks.append(artifact)

        return leaks

    # ============================================================
    #  L1‑SAFE LOAD (max 500, ZERO load_all)
    # ============================================================
    def load(self, max_items: Optional[int] = None) -> bool:
        """
        Завантажує НЕ більше 500 артефактів у L1‑кеш.
        ZERO load_all(): тільки ThreatConnector.query(limit<=500).
        """
        try:
            limit = max_items if (max_items and max_items > 0) else self.L1_LIMIT
            if limit > self.L1_LIMIT:
                limit = self.L1_LIMIT

            raw_artifacts = self.connector.query(
                limit=limit,
                offset=0,
                order_by="timestamp",
                order_desc=True,
            )

            with self._data_lock:
                self.artifacts = [a for a in raw_artifacts if isinstance(a, dict)]
                self.data = {
                    "artifacts": self.artifacts,
                    "total": len(self.artifacts),
                }
                self._rebuild_indexes()

            logger.info(
                "ThreatDataLoader 10.0: L1-safe load → %d artifacts (limit=%d)",
                len(self.artifacts),
                limit,
            )

            self._emit_event("threatintel_loaded", {"total": len(self.artifacts)})
            return len(self.artifacts) > 0

        except Exception as e:
            logger.exception("ThreatDataLoader 10.0: load() error: %s", e)
            with self._data_lock:
                self.data = {"artifacts": [], "total": 0}
                self.artifacts = []
                self._rebuild_indexes()
            self._emit_event("threatintel_loaded", {"total": 0, "error": str(e)})
            return False

    def load_async(self, bridge=None, max_items: Optional[int] = None) -> None:
        def bg():
            try:
                return self.load(max_items=max_items)
            except Exception as e:
                logger.exception("ThreatDataLoader 10.0: load_async error: %s", e)
                return e

        def done(result):
            if isinstance(result, Exception):
                self._log_debug(f"[ThreatDataLoader 10.0] load_async failed: {result}")
            else:
                self._log_debug(f"[ThreatDataLoader 10.0] load_async completed: ok={result}")

        if bridge is not None and hasattr(bridge, "post_bg"):
            try:
                bridge.post_bg(bg, done)
                return
            except Exception:
                logger.exception("ThreatDataLoader 10.0: bridge.post_bg failed")

        Thread(target=lambda: done(bg()), daemon=True, name="ThreatDataLoaderLoadAsync").start()

    # ============================================================
    #  Index rebuild (L1 only)
    # ============================================================
    def _rebuild_indexes(self) -> None:
        self._index_by_module.clear()
        self._index_by_category.clear()
        self._index_by_risk.clear()

        for a in self.artifacts:
            result = a.get("result", {}) or {}
            category = result.get("category", "unknown")
            risk = str(result.get("risk", "unknown")).lower()
            module = a.get("module", "unknown")

            self._index_by_module.setdefault(module, []).append(a)
            self._index_by_category.setdefault(category, []).append(a)
            self._index_by_risk.setdefault(risk, []).append(a)

        self._log_debug(
            f"[ThreatDataLoader 10.0] Indexes rebuilt: modules={len(self._index_by_module)}, "
            f"categories={len(self._index_by_category)}, risks={len(self._index_by_risk)}"
        )

    # ============================================================
    #  Summary (L1 only, top‑500)
    # ============================================================
    def get_summary(self) -> Dict[str, Any]:
        with self._data_lock:
            by_category: Dict[str, int] = {}
            by_module: Dict[str, int] = {}
            by_risk: Dict[str, int] = {}

            for a in self.artifacts:
                result = a.get("result", {}) or {}
                category = result.get("category", "unknown")
                risk = str(result.get("risk", "unknown")).lower()
                module = a.get("module", "unknown")

                by_category[category] = by_category.get(category, 0) + 1
                by_module[module] = by_module.get(module, 0) + 1
                by_risk[risk] = by_risk.get(risk, 0) + 1

            summary = {
                "total": len(self.artifacts),
                "by_module": by_module,
                "by_category": by_category,
                "by_risk": by_risk,
                "artifact_count": len(self.artifacts),
            }

        self._emit_event("threatintel_summary", summary)
        return summary

    def get_summary_async(self, bridge=None) -> None:
        def bg():
            try:
                return self.get_summary()
            except Exception as e:
                logger.exception("ThreatDataLoader 10.0: get_summary_async error: %s", e)
                return e

        def done(result):
            if isinstance(result, Exception):
                self._log_debug(f"[ThreatDataLoader 10.0] get_summary_async failed: {result}")
            else:
                self._log_debug(f"[ThreatDataLoader 10.0] get_summary_async completed")

        if bridge is not None and hasattr(bridge, "post_bg"):
            try:
                bridge.post_bg(bg, done)
                return
            except Exception:
                logger.exception("ThreatDataLoader 10.0: bridge.post_bg failed")

        Thread(target=lambda: done(bg()), daemon=True, name="ThreatDataLoaderSummaryAsync").start()

    # ============================================================
    #  Auto‑detect email/password + accounts
    # ============================================================
    def _auto_detect_email_password(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        result = artifact.get("result", {}) or {}
        text_blob = json.dumps(result, ensure_ascii=False)

        emails = EMAIL_REGEX.findall(text_blob)
        passwords: List[str] = []

        accounts = result.get("extracted_accounts") or artifact.get("extracted_accounts", [])
        if isinstance(accounts, list) and accounts:
            result["category"] = "account_state_leak"
            result["account_leak"] = {
                "accounts": accounts,
                "count": len(accounts),
                "phones": [acc.get("phone") for acc in accounts if acc.get("phone")],
                "emails": [acc.get("email") for acc in accounts if acc.get("email")],
                "usernames": [acc.get("username") for acc in accounts if acc.get("username")],
                "passwords": [acc.get("password") for acc in accounts if acc.get("password")],
                "addresses": [acc.get("address") for acc in accounts if acc.get("address")],
                "credit_cards": [acc.get("credit_card") for acc in accounts if acc.get("credit_card")],
                "statuses": [acc.get("account_status") for acc in accounts if acc.get("account_status")],
                "urls": [acc.get("url") for acc in accounts if acc.get("url")],
                "sources": [acc.get("source") for acc in accounts if acc.get("source")],
                "risks": [acc.get("risk") for acc in accounts if acc.get("risk")],
            }

        for key, value in result.items():
            if PASSWORD_HINT_REGEX.search(str(key)):
                if isinstance(value, str):
                    passwords.append(value)
                elif isinstance(value, list):
                    passwords.extend([str(v) for v in value])

        if emails or passwords:
            result["category"] = "email_leak"
            result["email_leak"] = {
                "emails": emails,
                "passwords": passwords,
                "smtp_users": emails,
                "smtp_passwords": passwords,
                "logins": emails,
            }

        artifact["result"] = result
        return artifact

    # ============================================================
    #  GUI artifact conversion
    # ============================================================
    def _base_gui_artifact(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        result = artifact.get("result", {}) or {}
        risk = str(result.get("risk", "info")).lower()
        category = result.get("category", "unknown")

        return {
            "type": result.get("type", "event"),
            "module": artifact.get("module", "unknown"),
            "url": result.get("url", artifact.get("target", "")),
            "risk": risk,
            "category": category,
            "source": result.get("source", "analyzer"),
            "timestamp": artifact.get("timestamp", ""),
        }

    def convert_artifact_for_gui(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(artifact, dict):
            return {}

        artifact = self._auto_detect_email_password(artifact)
        result = artifact.get("result", {}) or {}
        gui_artifact = self._base_gui_artifact(artifact)

        if gui_artifact["category"] == "email_leak":
            email_leak = result.get("email_leak", {}) or {}
            gui_artifact["email_leak"] = {
                "emails": email_leak.get("emails", []),
                "passwords": email_leak.get("passwords", []),
                "smtp_users": email_leak.get("smtp_users", []),
                "smtp_passwords": email_leak.get("smtp_passwords", []),
                "logins": email_leak.get("logins", []),
            }

        if gui_artifact["category"] == "account_state_leak":
            account_leak = result.get("account_leak", {}) or {}
            gui_artifact["account_leak"] = {
                "accounts": account_leak.get("accounts", []),
                "count": account_leak.get("count", 0),
                "phones": account_leak.get("phones", []),
                "emails": account_leak.get("emails", []),
                "usernames": account_leak.get("usernames", []),
                "passwords": account_leak.get("passwords", []),
                "addresses": account_leak.get("addresses", []),
                "credit_cards": account_leak.get("credit_cards", []),
                "statuses": account_leak.get("statuses", []),
                "urls": account_leak.get("urls", []),
                "sources": account_leak.get("sources", []),
                "risks": account_leak.get("risks", []),
            }

        return gui_artifact

    # ============================================================
    #  Query API (по L1 кешу) — backward‑compatible
    # ============================================================
    def query(
        self,
        category: Optional[str] = None,
        risk: Optional[str] = None,
        module: Optional[str] = None,
        offset: int = 0,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        with self._data_lock:
            artifacts = self.artifacts

            if category:
                artifacts = self._index_by_category.get(category, [])

            if risk:
                risk_norm = str(risk).lower()
                artifacts = [
                    a for a in artifacts
                    if str((a.get("result") or {}).get("risk", "")).lower() == risk_norm
                ]

            if module:
                artifacts = [
                    a for a in artifacts
                    if str(a.get("module", "")).lower() == module.lower()
                ]

            if offset < 0:
                offset = 0
            if limit is not None and limit > 0:
                return artifacts[offset:offset + limit]
            return artifacts[offset:]

    # ============================================================
    #  Stream‑API: iter_artifacts() / stream_query()
    # ============================================================
    def iter_artifacts(self, batch_size: int = 500) -> Generator[Dict[str, Any], None, None]:
        """
        Стрімінговий доступ до всіх артефактів через backend.query().
        Не завантажує все в пам’ять, батчами по 500.
        """
        offset = 0
        while True:
            batch = self.connector.query(
                limit=batch_size,
                offset=offset,
                order_by="timestamp",
                order_desc=True,
            )
            if not batch:
                break
            for a in batch:
                yield a
            offset += batch_size

    def stream_query(
        self,
        *,
        category: Optional[str] = None,
        risk: Optional[str] = None,
        module: Optional[str] = None,
        search: Optional[str] = None,
        batch_size: int = 500,
        order_by: str = "timestamp",
        order_desc: bool = True,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Стрімінговий Threat‑query API (SQL‑рівень, без L1 кешу).
        """
        offset = 0
        while True:
            batch = self.connector.query(
                category=category,
                risk=risk,
                module=module,
                search=search,
                limit=batch_size,
                offset=offset,
                order_by=order_by,
                order_desc=order_desc,
            )
            if not batch:
                break
            for a in batch:
                yield a
            offset += batch_size

    # ============================================================
    #  Window/adaptive query (для GUI‑пагінації)
    # ============================================================
    def window_query(
        self,
        *,
        category: Optional[str] = None,
        risk: Optional[str] = None,
        module: Optional[str] = None,
        search: Optional[str] = None,
        page_size: int = 500,
        page: int = 0,
        order_by: str = "timestamp",
        order_desc: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Window‑query для GUI: сторінка page з розміром page_size (<=500).
        """
        if page < 0:
            page = 0
        if page_size > 500:
            page_size = 500
        offset = page * page_size
        return self.connector.query(
            category=category,
            risk=risk,
            module=module,
            search=search,
            limit=page_size,
            offset=offset,
            order_by=order_by,
            order_desc=order_desc,
        )

    def adaptive_query(
        self,
        *,
        min_risk: Optional[str] = None,
        module: Optional[str] = None,
        category: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """
        Adaptive‑query: спочатку високий ризик, потім решта (limit<=500).
        """
        if limit > 500:
            limit = 500

        artifacts = self.connector.query(
            category=category,
            risk=None,
            module=module,
            search=search,
            limit=limit,
            offset=0,
            order_by="risk",
            order_desc=True,
        )

        if not min_risk:
            return artifacts

        min_risk_norm = str(min_risk).lower()
        order_map = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0,
        }

        filtered: List[Dict[str, Any]] = []
        for a in artifacts:
            res = a.get("result", {}) or {}
            r = str(res.get("risk", "unknown")).lower()
            if order_map.get(r, -1) >= order_map.get(min_risk_norm, -1):
                filtered.append(a)
        return filtered

    # ============================================================
    #  filter_leaks() — по L1 кешу (GUI‑friendly)
    # ============================================================
    def filter_leaks(
        self,
        min_risk: Optional[str] = None,
        module: Optional[str] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        grouped = {
            "email_leak": [],
            "account_state_leak": [],
            "password_leak": [],
        }

        with self._data_lock:
            for a in self.artifacts:
                result = a.get("result", {}) or {}
                category = result.get("category", "unknown")
                risk = str(result.get("risk", "unknown")).lower()

                if min_risk:
                    min_risk_norm = str(min_risk).lower()
                    order_map = {
                        "critical": 4,
                        "high": 3,
                        "medium": 2,
                        "low": 1,
                        "info": 0,
                    }
                    if order_map.get(risk, -1) < order_map.get(min_risk_norm, -1):
                        continue

                if module:
                    if str(a.get("module", "")).lower() != module.lower():
                        continue

                if category == "email_leak":
                    grouped["email_leak"].append(result.get("email_leak", {}))
                elif category == "account_state_leak":
                    grouped["account_state_leak"].append(result.get("account_leak", {}))
                elif "password" in json.dumps(result, ensure_ascii=False).lower():
                    grouped["password_leak"].append(result)

        self._emit_event("threatintel_leaks_filtered", grouped)
        return grouped


# ====================================================================
#  GUI helpers (стрімінговий, без фризів)
# ====================================================================

def _safe_add_threat(threat_tab, gui_artifact: Dict[str, Any]) -> None:
    if not gui_artifact or threat_tab is None:
        return

    bridge = getattr(threat_tab, "_bridge", None)
    if bridge is not None:
        try:
            bridge.post_ui(threat_tab.add_threat, gui_artifact)
            return
        except Exception:
            logger.exception("ThreatDataLoader 10.0: bridge.post_ui failed, fallback to after")

    try:
        threat_tab.after(0, threat_tab.add_threat, gui_artifact)
    except Exception:
        logger.exception("ThreatDataLoader 10.0: не удалось добавить артефакт в GUI")


def load_threat_data_to_gui(threat_tab, page_size: int = 500, max_pages: int = 1) -> int:
    """
    Стрімінгове завантаження артефактів з ThreatConnector (SQLite/ES) в GUI.
    Використовує window_query + UIQueueBridge для безпечної вставки.
    page_size — розмір сторінки (<=500)
    max_pages — скільки сторінок завантажити (1 → тільки топ‑500)
    """
    if page_size > 500:
        page_size = 500

    connector = _get_connector()
    loader = ThreatDataLoader(connector=connector)

    total_added = 0
    for page in range(max_pages):
        artifacts = loader.window_query(
            page_size=page_size,
            page=page,
            order_by="risk",
            order_desc=True,
        )
        if not artifacts:
            break

        for artifact in artifacts:
            gui_artifact = loader.convert_artifact_for_gui(artifact)
            if not gui_artifact:
                continue
            _safe_add_threat(threat_tab, gui_artifact)
            total_added += 1

    return total_added


def load_threat_data_to_gui_async(threat_tab, bridge=None, page_size: int = 500, max_pages: int = 1) -> None:
    def bg():
        try:
            return load_threat_data_to_gui(threat_tab, page_size=page_size, max_pages=max_pages)
        except Exception as e:
            logger.exception("ThreatDataLoader 10.0: async load error: %s", e)
            return e

    def done(result):
        if isinstance(result, Exception):
            msg = f"[⚠️ TI] Async load error: {result}"
        else:
            msg = f"[TI] Async loaded {result} artifacts into GUI (page_size={page_size}, max_pages={max_pages})"

        try:
            if hasattr(threat_tab, "log"):
                threat_tab.log(msg)
            else:
                logger.info(msg)
        except Exception:
            logger.info(msg)

    if bridge is not None and hasattr(bridge, "post_bg"):
        try:
            bridge.post_bg(bg, done)
            return
        except Exception:
            logger.exception("ThreatDataLoader 10.0: bridge.post_bg failed, fallback to Thread")

    Thread(target=lambda: done(bg()), daemon=True, name="ThreatDataLoaderAsync").start()





