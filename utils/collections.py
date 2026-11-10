import json
from typing import Any, Iterable, List, Set


def dedupe_preserve_order(seq: Iterable[Any]) -> List[Any]:
    """Return unique values in input order, including JSON-serializable containers."""
    seen: Set[Any] = set()
    result: List[Any] = []

    for item in seq:
        try:
            key = (
                item
                if isinstance(item, (str, int, float, tuple))
                else json.dumps(item, sort_keys=True, ensure_ascii=False)
            )
            hash(key)
        except Exception:
            try:
                key = json.dumps(item, sort_keys=True, ensure_ascii=False)
                hash(key)
            except Exception:
                key = str(item)

        if key not in seen:
            seen.add(key)
            result.append(item)

    return result
