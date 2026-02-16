from settings import TRAP_WEBHOOK_URL
import requests
from datetime import datetime

# === Типы ловушек ===
def generate_js_trap(payload):
    return f"<script>console.log('trap:{payload}');document.cookie='xss_trapped=true';</script>"

def generate_html_trap(payload):
    return f"<form action='#' method='post'><input value='{payload}'></form>"

def send_trap_to_webhook(payload, trap_type="js"):
    trap = generate_js_trap(payload) if trap_type == "js" else generate_html_trap(payload)
    timestamp = datetime.now().isoformat()
    try:
        response = requests.post(
            TRAP_WEBHOOK_URL,  # замените на актуальный endpoint
            json={"trap": trap, "original": payload, "timestamp": timestamp}
        )
        return response.status_code
    except Exception as e:
        print(f"[TrapEngine] ❌ Ошибка отправки ловушки: {e}")
        return None