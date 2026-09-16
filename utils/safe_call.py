# xss_security_gui/utils/safe_call.py
"""
SafeCall 10.0 — безопасный вызов callback'ов из фоновых потоков.

Особенности:
- Полная совместимость с Tkinter / ttk / customtkinter
- Поддержка after(), after_idle(), event_generate()
- Защита от вызова на уничтоженных виджетах
- Thread‑safe вызовы
- Fallback на прямой вызов
- Zero‑crash гарантия
"""

from __future__ import annotations
from typing import Callable, Any
import threading
import logging

logger = logging.getLogger(__name__)

# Глобальный лок для thread‑safe вызовов
_SAFE_CALL_LOCK = threading.Lock()


def _is_widget_destroyed(owner: Any) -> bool:
    """Проверяет, уничтожен ли Tk‑виджет."""
    try:
        if owner is None:
            return True

        # Tkinter widgets have .winfo_exists()
        if hasattr(owner, "winfo_exists"):
            exists = owner.winfo_exists()
            return not bool(exists)

        return False
    except Exception as e:
        logger.debug("SafeCall: widget existence check failed: %r", e)
        return True


def _schedule_tk(owner: Any, callback: Callable[..., Any], *args: Any, **kwargs: Any) -> bool:
    """Пытается запланировать вызов через Tk‑механизмы."""
    try:
        if _is_widget_destroyed(owner):
            return False

        # 1. after(0, ...)
        if hasattr(owner, "after"):
            after = owner.after
            if callable(after):
                after(0, lambda: callback(*args, **kwargs))
                return True

        # 2. after_idle(...)
        if hasattr(owner, "after_idle"):
            after_idle = owner.after_idle
            if callable(after_idle):
                after_idle(lambda: callback(*args, **kwargs))
                return True

        # 3. event_generate (редкий fallback)
        if hasattr(owner, "event_generate"):
            event_generate = owner.event_generate
            if callable(event_generate):
                event_generate("<<SafeCall>>")
                return True

        # 4. invoke (некоторые UI‑фреймворки)
        if hasattr(owner, "invoke"):
            invoke = owner.invoke
            if callable(invoke):
                invoke()
                return True

    except Exception as e:
        logger.debug("SafeCall: Tk scheduling failed: %r", e)
        return False

    return False


def safe_invoke(callback: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
    """
    Безопасно вызывает callback из фонового потока.

    Логика:
    1. Если callback привязан к Tk‑виджету → планируем через after/after_idle.
    2. Если виджет уничтожен → fallback на прямой вызов.
    3. Если callback обычный → прямой вызов.
    4. Все исключения подавляются (zero‑crash).
    """

    if not callable(callback):
        return

    owner = getattr(callback, "__self__", None)

    with _SAFE_CALL_LOCK:
        # Попытка вызвать через Tk‑механизмы
        if owner is not None:
            if _schedule_tk(owner, callback, *args, **kwargs):
                return

        # Fallback: прямой вызов
        try:
            callback(*args, **kwargs)
        except Exception as e:
            logger.debug("SafeCall suppressed exception: %r", e)
            # zero‑crash: не даём упасть mainloop
            pass



