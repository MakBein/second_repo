"""Safe compatibility interface for the optional watcher stealth adapter.

The watcher retains its ordinary HTTP behavior when this optional component is
unavailable; this implementation deliberately does not disguise traffic.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any


class StealthMode:
    """Disabled adapter that lets the watcher use its standard HTTP fallback."""

    def __init__(self) -> None:
        self.is_active = False
        self.header_engine = SimpleNamespace(profile_count=0)

    def activate(self) -> bool:
        return False

    def get_delay(self) -> float:
        return 1.0

    def get_stealth_headers(self, locale: str = "en") -> dict[str, str]:
        return {"Accept-Language": locale}

    def get_stealth_context(self) -> tuple[Any, str]:
        raise RuntimeError("Traffic-disguise TLS profiles are disabled")

    def report_block(self) -> None:
        return None

    def report_success(self) -> None:
        return None

    def adaptive_throttle(self, elapsed_seconds: float) -> None:
        return None


__all__ = ["StealthMode"]
