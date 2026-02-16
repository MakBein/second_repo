# xss_security_gui/utils/jwt_decoder.py
import base64, json

def base64url_decode(input_str):
    padding = '=' * ((4 - len(input_str) % 4) % 4)
    return base64.urlsafe_b64decode(input_str + padding)

def decode_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header = json.loads(base64url_decode(parts[0]).decode(errors="ignore"))
        payload = json.loads(base64url_decode(parts[1]).decode(errors="ignore"))
        return {"header": header, "payload": payload}
    except Exception:
        return None

def assess_risks(decoded, expected_aud="expected-aud"):
    risks = []
    if decoded["header"].get("alg", "") == "none":
        risks.append("📛 Алгоритм подписи: none")
    if not decoded["payload"].get("exp"):
        risks.append("⏰ Отсутствует exp")
    if decoded["payload"].get("aud") != expected_aud:
        risks.append(f"🔐 Недопустимый аудит: {decoded['payload'].get('aud')}")
    return risks