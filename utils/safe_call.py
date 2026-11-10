# xss_security_gui/utils/safe_call.py
"""Safe callback invocation — never raise into worker threads."""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

_logger = logging.getLogger(__name__)


def safe_invoke(fn: Optional[Callable[..., Any]], *args: Any, **kwargs: Any) -> Any:
    if fn is None:
        return None
    try:
        return fn(*args, **kwargs)
    except Exception:
        _logger.debug("safe_invoke dropped exception from %s", getattr(fn, "__name__", fn), exc_info=True)
        return None


def safe_call(fn: Optional[Callable[..., Any]], *args: Any, **kwargs: Any) -> Any:
    return safe_invoke(fn, *args, **kwargs)
