# xss_security_gui/honeypot_server.py
"""
Honeypot Server ULTRA 6.0
- Flask-based honeypot
- XSS detection via signatures
- Logging to honeypot.log
- Integration with ThreatConnector
- Запуск в отдельном потоке, чтобы не блокировать систему
"""

import datetime
import os
import threading
import json
from flask import Flask, request
from xss_security_gui import settings
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR

app = Flask(__name__)

def detect_xss(payload_str: str) -> bool:
    """Проверка строки на наличие XSS-подписи"""
    signatures = settings.get("honeypot.signatures", [])
    return any(sig in payload_str.lower() for sig in signatures)

@app.route("/", methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def trap(path=""):
    """Основной honeypot endpoint"""
    payload = request.args.to_dict()
    body = request.get_data(as_text=True)
    ip = request.remote_addr
    headers = dict(request.headers)

    payload_str = " ".join([path, body] + list(payload.values()))
    xss_flag = detect_xss(payload_str)

    log_entry = {
        "time": datetime.datetime.utcnow().isoformat(),
        "ip": ip,
        "path": path,
        "xss_detected": xss_flag,
        "params": payload,
        "body": body,
        "user_agent": headers.get("User-Agent", "")
    }

    os.makedirs(settings.LOG_DIR, exist_ok=True)
    try:
        with open(settings.LOG_HONEYPOT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[⚠️] Ошибка записи лога honeypot: {e}")

    if xss_flag:
        print(f"[🚨 XSS] Попытка XSS от {ip} — path: /{path}")
        try:
            THREAT_CONNECTOR.emit(
                module="honeypot_server",
                target=ip,
                result={"check": "honeypot_xss", "entry": log_entry}
            )
        except Exception as e:
            print(f"[⚠️] Ошибка передачи в ThreatConnector: {e}")

    return "👀 Honeypot active. You found nothing.\n"

def run_server(port: int):
    """Запуск Flask-сервера (в отдельном потоке)"""
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

def start_honeypot_server():
    """Запускает honeypot-сервер в отдельном потоке"""
    port = settings.get("honeypot.port", 8080)
    thread = threading.Thread(target=run_server, args=(port,), daemon=True)
    thread.start()
    print(f"[+] Honeypot server запущен на http://0.0.0.0:{port}")

if __name__ == "__main__":
    port = settings.get("honeypot.port", 8080)
    run_server(port)