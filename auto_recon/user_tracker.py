# xss_security_gui/auto_recon/user_tracker.py
"""Operator / kill-chain / attack-surface tracker for AutoReconOrchestrator."""

from __future__ import annotations

import socket
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class OperatorIdentity:
    user_id: str = "local-operator"
    hostname: str = socket.gethostname()
    ip_address: str = "127.0.0.1"
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)


@dataclass
class UserContext:
    user: OperatorIdentity = field(default_factory=OperatorIdentity)
    current_phase: str = "reconnaissance"
    opsec_mode: str = "standard"
    threat_level: str = "unknown"


class UserTracker:
    def __init__(self) -> None:
        self.operations: List[Dict[str, Any]] = []
        self.kill_chain: List[Dict[str, Any]] = []
        self.endpoints: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.parameters: List[Dict[str, Any]] = []
        self.surfaces: Dict[str, Dict[str, Any]] = {}
        self.errors: List[Dict[str, Any]] = []

    def track_operation(self, name: str, **kwargs: Any) -> None:
        self.operations.append({"ts": _utc(), "name": name, **kwargs})

    def track_attack_chain(self, tactic: str, technique: str, **kwargs: Any) -> None:
        self.kill_chain.append({
            "ts": _utc(),
            "tactic": tactic,
            "technique": technique,
            **kwargs,
        })

    def track_endpoint(self, target: str, endpoint: Any) -> None:
        url = endpoint.get("url", endpoint) if isinstance(endpoint, dict) else str(endpoint)
        self.endpoints.append({"ts": _utc(), "target": target, "url": url})

    def track_vulnerability_found(self, vuln_type: str, url: str, **kwargs: Any) -> None:
        self.vulnerabilities.append({
            "ts": _utc(),
            "type": vuln_type,
            "url": url,
            **kwargs,
        })

    def track_parameter(self, target: str, param: str, value: Any = "") -> None:
        self.parameters.append({
            "ts": _utc(),
            "target": target,
            "param": param,
            "value": str(value)[:200],
        })

    def track_attack_surface(self, target: str, surface: Dict[str, Any]) -> None:
        self.surfaces[target] = surface

    def track_error(self, **kwargs: Any) -> None:
        self.errors.append({"ts": _utc(), **kwargs})


_TRACKER: Optional[UserTracker] = None
_CONTEXT: Optional[UserContext] = None


def get_user_tracker() -> UserTracker:
    global _TRACKER
    if _TRACKER is None:
        _TRACKER = UserTracker()
    return _TRACKER


def get_user_context() -> UserContext:
    global _CONTEXT
    if _CONTEXT is None:
        _CONTEXT = UserContext()
    return _CONTEXT


def build_attack_surface(target: Optional[str] = None) -> Dict[str, Any]:
    tracker = get_user_tracker()
    if target and target in tracker.surfaces:
        return tracker.surfaces[target]

    endpoints = [e["url"] for e in tracker.endpoints]
    if target:
        endpoints = [e["url"] for e in tracker.endpoints if e.get("target") == target]

    params = [p["param"] for p in tracker.parameters]
    return {
        "target": target or "all",
        "endpoints": list(dict.fromkeys(endpoints)),
        "parameters": list(dict.fromkeys(params)),
        "forms": [],
        "js_libs": [],
        "cms": None,
        "cdn": None,
        "vulnerabilities": len(tracker.vulnerabilities),
    }
