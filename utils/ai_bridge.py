"""xss_security_gui.utils.ai_bridge

Small helper to run AI Core calls in background threads and safely deliver results to GUI callbacks.
"""
from typing import Any, Callable, Optional
import threading

from xss_security_gui.utils.safe_call import safe_invoke

_GLOBAL_AI = None


def get_global_ai():
    global _GLOBAL_AI
    if _GLOBAL_AI is None:
        try:
            from xss_security_gui.ai_core import AICore
            _GLOBAL_AI = AICore()
        except Exception:
            _GLOBAL_AI = None
    return _GLOBAL_AI


def analyze_async(threat: Any, callback: Optional[Callable[[Any], None]] = None, name: Optional[str] = None) -> threading.Thread:
    """Run AI analyze(threat) in a background thread and call ``callback(result)`` when done.

    The callback will be invoked via safe_invoke so bound widget methods will be scheduled
    on the Tk mainloop.
    """

    def worker():
        try:
            ai = get_global_ai()
            if not ai:
                res = {"error": "AI core unavailable"}
            else:
                res = ai.analyze(threat)
        except Exception as e:
            res = {"error": str(e)}

        if callback:
            try:
                safe_invoke(callback, res)
            except Exception:
                pass

    t = threading.Thread(target=worker, daemon=True, name=name or "AIAnalyze")
    t.start()
    return t

