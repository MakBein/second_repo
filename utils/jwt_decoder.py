# xss_security_gui/utils/jwt_decoder.py
import base64
import json
import datetime


# ============================================================
#  Base64URL decoding
# ============================================================
def base64url_decode(input_str: str) -> bytes:
    """Декодирует строку в формате base64url с учётом паддинга."""
    padding = '=' * ((4 - len(input_str) % 4) % 4)
    return base64.urlsafe_b64decode(input_str + padding)


# ============================================================
#  JWT decoding
# ============================================================
def decode_jwt(token: str):
    """
    Декодирует JWT-токен.
    Возвращает словарь с header и payload, либо None при ошибке.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None

        header = json.loads(base64url_decode(parts[0]).decode(errors="ignore"))
        payload = json.loads(base64url_decode(parts[1]).decode(errors="ignore"))

        return {"header": header, "payload": payload}
    except Exception:
        return None


# ============================================================
#  Risk assessment
# ============================================================
def assess_risks(decoded: dict, expected_aud: str = "expected-aud") -> list[str]:
    """
    Оценивает риски JWT-токена:
    • Алгоритм подписи
    • Наличие exp
    • Проверка аудитории
    • Проверка истечения срока
    """
    risks: list[str] = []

    # Алгоритм подписи
    if decoded["header"].get("alg", "").lower() == "none":
        risks.append("📛 Алгоритм подписи: none")

    # exp
    exp = decoded["payload"].get("exp")
    if not exp:
        risks.append("⏰ Отсутствует exp")
    else:
        try:
            exp_time = datetime.datetime.utcfromtimestamp(int(exp))
            if exp_time < datetime.datetime.utcnow():
                risks.append(f"⏳ Токен истёк: {exp_time.isoformat()} UTC")
        except Exception:
            risks.append("⚠️ Некорректное значение exp")

    # aud
    aud = decoded["payload"].get("aud")
    if aud != expected_aud:
        risks.append(f"🔐 Недопустимый аудит: {aud}")

    # iat
    if not decoded["payload"].get("iat"):
        risks.append("⏰ Отсутствует iat (issued-at)")

    # iss
    if not decoded["payload"].get("iss"):
        risks.append("🌐 Отсутствует iss (issuer)")

    return risks