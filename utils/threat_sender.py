# xss_security_gui/utils/threat_sender.py
"""
Threat Sender 11.0 — Unified Threat Event Bus
---------------------------------------------
Роль в Pipeline 11.0:
• мінімальна нормалізація raw‑артефактів
• авто‑додавання _ts та _hash
• thread‑safe event bus
• передача артефактів у ThreatConnector через listeners
• НЕ виконує correlation / chain‑детекцію / risk‑engine
"""

from __future__ import annotations
import json
import threading
import time
import hashlib
from typing import Any, Dict, List, Callable, Union


# ============================================================
#  Глобальный Threat Event Bus (thread‑safe)
# ============================================================

_listeners: List[Callable[[Dict[str, Any]], None]] = []
_bus_lock = threading.Lock()


def register_threat_listener(fn: Callable[[Dict[str, Any]], None]) -> None:
    """Регистрирует подписчика ThreatConnector stream."""
    with _bus_lock:
        if fn not in _listeners:
            _listeners.append(fn)


def emit_threat_event(artifact: Dict[str, Any]) -> None:
    """Рассылает артефакт всем подписчикам."""
    with _bus_lock:
        listeners_copy = list(_listeners)

    for fn in listeners_copy:
        try:
            fn(artifact)
        except Exception as e:
            print(f"[ThreatSender] listener error: {e}")


# ============================================================
#  Нормализация + enrich (минимальная, Pipeline 11.0‑safe)
# ============================================================

def _ensure_ts(entry: Dict[str, Any]) -> str:
    ts = entry.get("_ts")
    if ts:
        return ts
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _ensure_hash(entry: Dict[str, Any]) -> str:
    h = entry.get("_hash")
    if h:
        return h
    blob = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def normalize_threat_artifact(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Минимальная нормализация raw‑артефакта.
    НЕ выполняет Pipeline 11.0 normalization — это делает ThreatConnector.
    """

    norm = {
        "category": entry.get("category", "unknown"),
        "context": entry.get("context", "unknown"),
        "payload": entry.get("payload", ""),
        "url": entry.get("url", "—"),
        "snippet": entry.get("snippet", ""),
        "risk": entry.get("risk", entry.get("severity", "info")),

        # Технические
        "parameter": entry.get("parameter"),
        "method": entry.get("method"),
        "status_code": entry.get("status_code"),
        "reflected": entry.get("reflected"),
        "length": entry.get("length"),
        "full_response": entry.get("full_response"),

        # Метаданные
        "timestamp": entry.get("timestamp"),
        "source": entry.get("source"),
        "iid": entry.get("iid"),

        # AI / Heuristics
        "ai_score": entry.get("ai_score"),
        "ai_label": entry.get("ai_label"),
        "context_confidence": entry.get("context_confidence"),

        # Связи (raw)
        "parent_url": entry.get("parent_url"),
        "chain": entry.get("chain"),

        # WAF
        "waf_detected": entry.get("waf_detected"),
        "waf_signature": entry.get("waf_signature"),

        # Навигация
        "line": entry.get("line"),
        "column": entry.get("column"),

        # ThreatConnector
        "module": entry.get("module", "unknown"),
        "_ts": entry.get("_ts"),
        "_hash": entry.get("_hash"),
    }

    return norm


def enrich_threat_artifact(entry: Dict[str, Any], module_name: str | None = None) -> Dict[str, Any]:
    """
    Обогащает артефакт:
    • module (если передан)
    • _ts (ISO)
    • _hash (sha256)
    """

    norm = normalize_threat_artifact(entry)

    if module_name:
        norm["module"] = module_name

    norm["_ts"] = _ensure_ts(norm)
    norm["_hash"] = _ensure_hash(norm)

    return norm


# ============================================================
#  ThreatSenderMixin — отправка артефактов из модулей
# ============================================================

class ThreatSenderMixin:
    """
    ThreatSenderMixin 11.0
    ----------------------
    Универсальный миксин для отправки raw‑артефактов в ThreatConnector.

    Поддерживает:
    • одиночные артефакты
    • списки артефактов
    • минимальную нормализацию + enrich
    • автоматическую рассылку через emit_threat_event()
    • интеграцию с ThreatTab (если есть)
    """

    def send_to_threat_intel(
        self,
        module_name: str,
        data: Union[Dict[str, Any], List[Any], Any],
    ) -> None:

        if not hasattr(self, "threat_tab") or self.threat_tab is None:
            self._send_to_stream_only(module_name, data)
            return

        try:
            payload = {"module": module_name, "entries": []}

            if isinstance(data, dict):
                norm = enrich_threat_artifact(data, module_name)
                payload["entries"].append(norm)
                emit_threat_event(norm)

            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        norm = enrich_threat_artifact(item, module_name)
                        payload["entries"].append(norm)
                        emit_threat_event(norm)
                    else:
                        payload["entries"].append({"info": str(item)})

            else:
                payload["entries"].append({"info": str(data)})

            self.threat_tab.load_results(payload)

        except Exception as e:
            self._safe_log(
                f"Threat Intel send error: {type(e).__name__}: {e}",
                level="error",
                exc_info=True,
            )

    def _send_to_stream_only(self, module_name: str, data: Any) -> None:
        try:
            if isinstance(data, dict):
                norm = enrich_threat_artifact(data, module_name)
                emit_threat_event(norm)

            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        norm = enrich_threat_artifact(item, module_name)
                        emit_threat_event(norm)

        except Exception as e:
            self._safe_log(f"Threat stream error: {e}", level="error")

    def _safe_log(self, message: str, level: str = "info", exc_info: bool = False) -> None:
        if not hasattr(self, "log"):
            print(message)
            return

        log_obj = getattr(self, "log")

        if hasattr(log_obj, level):
            log_method = getattr(log_obj, level)
            if callable(log_method):
                if exc_info and level == "error":
                    log_method(message, exc_info=True)
                else:
                    log_method(message)
                return

        if callable(log_obj):
            log_obj(message)
            return

        print(f"[{level.upper()}] {message}")



