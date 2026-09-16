# xss_security_gui/utils/ai_bridge.py
# ============================================================
# AI Bridge 10.0 — ultra‑safe, async, throttled, GUI‑friendly
# ============================================================

import threading
import time
from typing import Any, Callable, Optional, cast

from xss_security_gui.utils.safe_call import safe_invoke

# ============================================================
# Global AI Core (lazy, safe, thread‑locked)
# ============================================================

_GLOBAL_AI: Any | None = None
_AI_LOCK = threading.Lock()
_AI_INIT_IN_PROGRESS = False


def get_global_ai() -> Any:
    """Гарантовано повертає AICore або safe‑stub. Захист від подвійної ініціалізації."""
    global _GLOBAL_AI, _AI_INIT_IN_PROGRESS

    with _AI_LOCK:
        if _GLOBAL_AI is not None:
            return _GLOBAL_AI

        if _AI_INIT_IN_PROGRESS:
            # Якщо інший потік вже ініціалізує — чекаємо
            for _ in range(50):
                time.sleep(0.05)
                if _GLOBAL_AI is not None:
                    return _GLOBAL_AI
            return {"error": "AI core initialization timeout"}

        _AI_INIT_IN_PROGRESS = True

        try:
            from xss_security_gui.ai_core import AICore
            _GLOBAL_AI = AICore()
        except Exception as e:
            _GLOBAL_AI = {"error": f"AI core unavailable: {e}"}
        finally:
            _AI_INIT_IN_PROGRESS = False

        return cast(Any, _GLOBAL_AI)


# ============================================================
# Async AI analyze wrapper (battle‑grade)
# ============================================================

def analyze_async(
    threat: Any,
    callback: Optional[Callable[[Any], None]] = None,
    name: Optional[str] = None,
    timeout: float = 10.0,
    throttle_delay: float = 0.01,
) -> threading.Thread:
    """
    Запускає ai.analyze(threat) у фоновому потоці.
    Особливості:
    • timeout — захист від зависання AI
    • throttle_delay — захист від спаму
    • safe_invoke — GUI‑safe callback
    • guaranteed result delivery
    """

    def worker():
        time.sleep(throttle_delay)

        try:
            ai = get_global_ai()

            if isinstance(ai, dict) and "error" in ai:
                res = ai
            else:
                result_container = {"value": None}

                def run_ai():
                    try:
                        result_container["value"] = ai.analyze(threat)
                    except Exception as e:
                        result_container["value"] = {"error": str(e)}

                t = threading.Thread(target=run_ai, daemon=True)
                t.start()
                t.join(timeout)

                if result_container["value"] is None:
                    res = {"error": "AI analyze timeout"}
                else:
                    res = result_container["value"]

        except Exception as e:
            res = {"error": f"AI worker failure: {e}"}

        if callback:
            try:
                safe_invoke(callback, res)
            except Exception:
                pass

    t = threading.Thread(
        target=worker,
        daemon=True,
        name=name or "AIAnalyze10",
    )
    t.start()
    return t


