# xss_security_gui/utils/jwt_decoder.py
# ============================================================
# JWT Decoder 9.0 — safe, strict, risk-aware, threat-ready
# ============================================================

import base64
import json
from datetime import datetime, timezone
import hashlib
from typing import Optional, Dict, Any, List


# ============================================================
# Base64URL decoding (safe)
# ============================================================

def base64url_decode(input_str: str) -> Optional[bytes]:
    """Безопасное декодирование base64url с защитой от мусорных данных."""
    try:
        padding = "=" * ((4 - len(input_str) % 4) % 4)
        return base64.urlsafe_b64decode(input_str + padding)
    except Exception:
        return None


# ============================================================
# JWT decoding 9.0
# ============================================================

def decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    """
    Декодирует JWT-токен.
    Возвращает:
        {
            "header": {...},
            "payload": {...},
            "signature": "hex",
            "raw_signature": "base64url"
        }
    или None при ошибке.
    """

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        raw_header = base64url_decode(parts[0])
        raw_payload = base64url_decode(parts[1])
        raw_signature = parts[2]

        if raw_header is None or raw_payload is None:
            return None

        try:
            header = json.loads(raw_header.decode(errors="ignore"))
        except Exception:
            header = {}

        try:
            payload = json.loads(raw_payload.decode(errors="ignore"))
        except Exception:
            payload = {}

        signature_hex = hashlib.sha256(raw_signature.encode()).hexdigest()

        return {
            "header": header,
            "payload": payload,
            "signature": signature_hex,
            "raw_signature": raw_signature,
        }

    except Exception:
        return None


# ============================================================
# Risk assessment 9.0
# ============================================================

def assess_risks(decoded: Dict[str, Any], expected_aud: str = "expected-aud") -> List[str]:
    """
    Оценивает риски JWT-токена:
    • Алгоритм подписи
    • Наличие exp / iat / iss / nbf / jti
    • Проверка аудитории
    • Проверка истечения срока
    • Проверка слишком большого окна iat
    • Проверка отсутствия подписи
    • Проверка слабых алгоритмов
    """

    risks: List[str] = []
    header = decoded.get("header", {})
    payload = decoded.get("payload", {})

    # --------------------------------------------------------
    # alg
    # --------------------------------------------------------
    alg = header.get("alg", "").lower()

    if alg == "none":
        risks.append("📛 Алгоритм подписи: none (критическая уязвимость)")

    if alg in ("hs256", "hs384", "hs512") and "kid" not in header:
        risks.append("🔑 Отсутствует kid при HMAC-алгоритме")

    if alg in ("hs256", "rs256"):
        pass  # нормальные алгоритмы

    if alg in ("hs128", "rs128"):
        risks.append("⚠️ Слабый алгоритм подписи (128-bit)")

    # --------------------------------------------------------
    # exp
    # --------------------------------------------------------
    exp = payload.get("exp")
    if not exp:
        risks.append("⏰ Отсутствует exp")
    else:
        try:
            exp_time = datetime.fromtimestamp(int(exp), tz=timezone.utc)
            if exp_time < datetime.now(timezone.utc):
                risks.append(f"⏳ Токен истёк: {exp_time.isoformat()}")
        except Exception:
            risks.append("⚠️ Некорректное значение exp")

    # --------------------------------------------------------
    # iat
    # --------------------------------------------------------
    iat = payload.get("iat")
    if not iat:
        risks.append("⏰ Отсутствует iat (issued-at)")
    else:
        try:
            iat_time = datetime.fromtimestamp(int(iat), tz=timezone.utc)
            now = datetime.now(timezone.utc)
            if (now - iat_time).days > 365:
                risks.append("📅 Слишком старый iat (> 1 года)")
        except Exception:
            risks.append("⚠️ Некорректное значение iat")

    # --------------------------------------------------------
    # nbf
    # --------------------------------------------------------
    nbf = payload.get("nbf")
    if nbf:
        try:
            nbf_time = datetime.fromtimestamp(int(nbf), tz=timezone.utc)
            if nbf_time > datetime.now(timezone.utc):
                risks.append(f"⏳ Токен ещё не активен (nbf={nbf_time.isoformat()})")
        except Exception:
            risks.append("⚠️ Некорректное значение nbf")

    # --------------------------------------------------------
    # iss
    # --------------------------------------------------------
    if not payload.get("iss"):
        risks.append("🌐 Отсутствует iss (issuer)")

    # --------------------------------------------------------
    # aud
    # --------------------------------------------------------
    aud = payload.get("aud")
    if aud != expected_aud:
        risks.append(f"🔐 Недопустимый аудит: {aud}")

    # --------------------------------------------------------
    # jti
    # --------------------------------------------------------
    if not payload.get("jti"):
        risks.append("🆔 Отсутствует jti (token ID)")

    # --------------------------------------------------------
    # signature
    # --------------------------------------------------------
    signature = decoded.get("raw_signature", "")
    if not signature or signature.strip() == "":
        risks.append("⚠️ Подпись отсутствует или пустая")

    return risks
