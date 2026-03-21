# xss_security_gui/trap_engine.py
"""
TrapEngine ULTRA 7.0
--------------------
• Безпечне генерування JS/HTML пасток
• Екранування payload (захист від XSS у самому trap)
• Надійна відправка webhook з retry + timeout
• Повна ізоляція помилок (GUI не падає)
• Threat Intel інтеграція (опціонально)
• Потокобезпечний асинхронний режим
"""

import html
import threading
import requests
from datetime import datetime
from typing import Optional, Callable, Any

from xss_security_gui.settings import TRAP_WEBHOOK_URL
from xss_security_gui.threat_tab_connector import ThreatIntelConnector


# ============================================================
#  Генерація пасток
# ============================================================

def generate_js_trap(payload: str) -> str:
    """Безпечна JS‑пастка з екрануванням."""
    safe = html.escape(payload, quote=True)
    return (
        "<script>"
        f"console.log('trap:{safe}');"
        "document.cookie='xss_trapped=true';"
        "</script>"
    )


def generate_html_trap(payload: str) -> str:
    """Безпечна HTML‑пастка з екрануванням."""
    safe = html.escape(payload, quote=True)
    return f"<form action='#' method='post'><input value='{safe}'></form>"


# ============================================================
#  Відправка пастки на webhook
# ============================================================

def send_trap_to_webhook(
    payload: str,
    trap_type: str = "js",
    timeout: int = 5,
    retries: int = 3,
    threat: Optional[ThreatIntelConnector] = None,
    callback: Optional[Callable[[bool, str], None]] = None,
) -> None:
    """
    Відправляє пастку на webhook у окремому потоці.
    • timeout — захист від зависання
    • retries — повтори при помилках
    • callback(success, message)
    """

    def safe_callback(ok: bool, msg: str):
        if callback:
            try:
                callback(ok, msg)
            except Exception:
                pass

    def worker():
        trap = generate_js_trap(payload) if trap_type == "js" else generate_html_trap(payload)
        timestamp = datetime.utcnow().isoformat() + "Z"

        data = {
            "trap": trap,
            "original": payload,
            "timestamp": timestamp,
            "type": trap_type,
        }

        # Threat Intel інтеграція
        if threat:
            try:
                threat.report_generic(
                    module="TrapEngine",
                    target="webhook",
                    result={"trap_type": trap_type, "payload": payload},
                )
            except Exception:
                pass

        # Надійна відправка з retry
        for attempt in range(1, retries + 1):
            try:
                r = requests.post(
                    TRAP_WEBHOOK_URL,
                    json=data,
                    timeout=timeout,
                )
                if r.status_code < 300:
                    safe_callback(True, f"Trap delivered ({trap_type})")
                    return
                else:
                    msg = f"Webhook error {r.status_code}: {r.text}"
            except Exception as e:
                msg = f"Send error: {e}"

            if attempt == retries:
                safe_callback(False, msg)

    threading.Thread(target=worker, daemon=True, name="TrapEngineThread").start()