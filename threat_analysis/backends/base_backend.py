# xss_security_gui/threat_analysis/base_backend.py

from typing import Dict, Any, Iterable, List, Optional

def _normalize_result_json(data: Any) -> Dict[str, Any]:
    if isinstance(data, dict):
        return data
    if isinstance(data, list):
        return {"items": data}
    return {}

class ThreatBackendBase:
    """
    Unified backend contract for ThreatConnector 11.x.
    """

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
        for a in self.load_all():
            if a.get("_hash") == hash_value:
                return a
        return None

    def find_by_target(self, target: str) -> List[Dict[str, Any]]:
        return [a for a in self.load_all() if a.get("target") == target]

    def find_by_module(self, module: str) -> List[Dict[str, Any]]:
        return [a for a in self.load_all() if a.get("module") == module]

    def stats(self) -> Dict[str, Any]:
        data = self.load_all()
        by_module: Dict[str, int] = {}
        for a in data:
            mod = a.get("module", "unknown")
            by_module[mod] = by_module.get(mod, 0) + 1
        return {"total": len(data), "by_module": by_module}

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
        """Default in-memory query with filtering + pagination."""
        data = self.load_all()
        filtered = []
        for a in data:
            res = a.get("result") or {}
            if category and res.get("category") != category:
                continue
            if risk and str(res.get("risk", "")).lower() != str(risk).lower():
                continue
            if module and str(a.get("module", "")).lower() != str(module).lower():
                continue
            if search:
                blob = f"{a} {res}".lower()
                if search.lower() not in blob:
                    continue
            filtered.append(a)

        key_map = {
            "timestamp": lambda x: x.get("timestamp", ""),
            "risk": lambda x: (x.get("result") or {}).get("risk", ""),
            "module": lambda x: x.get("module", ""),
            "category": lambda x: (x.get("result") or {}).get("category", ""),
        }
        key = key_map.get(order_by, key_map["timestamp"])
        filtered.sort(key=key, reverse=order_desc)
        return filtered[offset: offset + limit]

    def count(
        self,
        *,
        category: Optional[str] = None,
        risk: Optional[str] = None,
        module: Optional[str] = None,
        search: Optional[str] = None,
    ) -> int:
        """Return total count matching filters (for pagination)."""
        return len(self.query(
            category=category, risk=risk, module=module,
            search=search, limit=999_999_999, offset=0,
        ))

    def clear_all(self) -> None:
        raise NotImplementedError

    def normalize_artifact(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        artifact = dict(artifact)
        res = artifact.get("result", {})
        artifact["result"] = _normalize_result_json(res)
        artifact.setdefault("severity", artifact["result"].get("severity", "info"))
        artifact.setdefault("category", artifact["result"].get("category", artifact.get("module", "")))
        artifact.setdefault("source", artifact["result"].get("source", "engine"))
        artifact.setdefault("tags", artifact["result"].get("tags", []))
        return artifact
