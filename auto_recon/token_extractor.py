# xss_security_gui/auto_recon/token_extractor.py
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from xss_security_gui.utils.jwt_decoder import decode_jwt, assess_risks
import re
import json

def extract_tokens(headers, html):
    tokens = []

    for k, v in headers.items():
        if "token" in k.lower() or "authorization" in k.lower():
            tokens.append({"source": k, "value": v})

    csrf_matches = re.findall(r'name=["\']csrf["\'].*?value=["\'](.*?)["\']', html, re.I)
    for match in csrf_matches:
        tokens.append({"source": "CSRF Hidden Field", "value": match})

    storage_matches = re.findall(r'localStorage\.setItem\(["\'](\w+)["\']\,\s*["\'](.*?)["\']\)', html)
    for key, val in storage_matches:
        tokens.append({"source": f"localStorage:{key}", "value": val})

    return tokens

def analyze_tokens(tokens, expected_aud="expected-aud"):
    analyzed = []
    for t in tokens:
        result = {"source": t["source"], "value": t["value"], "type": "opaque", "risks": []}
        decoded = decode_jwt(t["value"])
        if decoded:
            result["type"] = "JWT"
            result["decoded"] = decoded
            result["risks"] = assess_risks(decoded, expected_aud)
            # ➕ Оценка уровня риска
            risk_count = len(result["risks"])
            if "📛 Алгоритм подписи: none" in result["risks"]:
                result["risk_level"] = "high"
            elif risk_count >= 2:
                result["risk_level"] = "medium"
            else:
                result["risk_level"] = "low"
        analyzed.append(result)
    return analyzed

def save_token_log(analyzed, path="logs/token_risks.json"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(analyzed, f, indent=2)

# 📦 CLI-режим
def run_from_cli(headers_path, html_path, output_path="logs/token_risks.json"):
    try:
        with open(headers_path, encoding="utf-8") as f:
            headers = json.load(f)
        with open(html_path, encoding="utf-8") as f:
            html = f.read()
    except Exception as e:
        print(f"❌ Ошибка загрузки входных данных: {e}")
        return

    tokens = extract_tokens(headers, html)
    analyzed = analyze_tokens(tokens)
    save_token_log(analyzed, output_path)
    print(f"✅ Анализ завершён. Лог сохранён в: {output_path}")

# 🔧 GUI-режим: вызывается напрямую
def analyze_from_gui(headers, html, output_path="logs/token_risks.json"):
    tokens = extract_tokens(headers, html)
    analyzed = analyze_tokens(tokens)
    save_token_log(analyzed, output_path)
    return analyzed

# 🚀 Автоматический выбор режима
if __name__ == "__main__":
    if len(sys.argv) >= 3:
        headers_file = sys.argv[1]
        html_file = sys.argv[2]
        output_file = sys.argv[3] if len(sys.argv) > 3 else "logs/token_risks.json"
        run_from_cli(headers_file, html_file, output_file)
    else:
        print("📘 Использование:")
        print("  python token_extractor.py headers.json response.html [output.json]")