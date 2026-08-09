"""
xss_security_gui.utils.safe_call

Утилита для безопасного вызова callback'ов, возможно привязанных к Tk widgets,
из фоновых потоков. Если callback является bound‑method и у его owner есть
метод `after`, вызов будет запланирован в GUI‑потоке через owner.after(0, ...).
В противном случае выполняется прямой вызов.
"""
from typing import Callable, Any


def safe_invoke(callback: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
    """Безопасно вызвать callback: если он привязан к Tk widget — запланировать через after.

    Примеры:
        safe_invoke(widget.insert, 'end', text)
        safe_invoke(some_bound_method, data)
    """
    if not callable(callback):
        return

    owner = getattr(callback, "__self__", None)
    after = getattr(owner, "after", None)

    if callable(after):
        try:
            # schedule in GUI thread
            owner.after(0, lambda: callback(*args, **kwargs))
            return
        except Exception:
            # fallback to direct call
            pass

    try:
        callback(*args, **kwargs)
    except Exception:
        # Swallow exceptions — logging can be added if desired
        pass

