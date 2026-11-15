"""
AI Core 20.0 — nn_model.py (SAFE MODE)

NN/ML-модель 20.0:
- завантажується з диска (joblib)
- працює на розширених фічах 20.0
- має сигнатурно-евристичний fallback
- повністю підтримує AI_SAFE_MODE / AI_FALLBACK_ON_ERROR / AI_DISABLE_NN
"""

from typing import Dict, Any, Optional
import math
import re
import joblib

from xss_security_gui.settings import (
    AI_SAFE_MODE,
    AI_FALLBACK_ON_ERROR,
    AI_DISABLE_NN,
    AI_MODEL_PATH,
)

_MODEL: Optional[object] = None


# ============================================================
#  Завантаження моделі
# ============================================================

def load_trained_model(path: str | None = None) -> None:
    """
    Завантажує NN-модель з joblib.
    Якщо файл пошкоджений — SAFE MODE не дає GUI впасти.
    """
    global _MODEL
    model_path = path or AI_MODEL_PATH

    try:
        _MODEL = joblib.load(model_path)
        print(f"[AI Core] NN model loaded: {model_path}")
    except Exception as e:
        print(f"[AI Core] NN model load failed: {e}")
        _MODEL = None


def get_nn_model() -> Optional[object]:
    return _MODEL


# ============================================================
#  Сигнатурний fallback
# ============================================================

_SUSPICIOUS_PATTERNS = [
    r"_0x[a-f0-9]{4,}",
    r"while\s*\(\s*true\s*\)",
    r"debugger",
    r"atob\(",
    r"btoa\(",
    r"fromCharCode",
    r"Function\(",
    r"eval\(",
    r"setTimeout\([^,]+?,\s*0\)",
    r"document\.cookie",
    r"window\['eval'\]",
    r"eval\(atob",
    r"Function\(atob",
    r"navigator\.webdriver",
]


def _fallback_nn_score(raw_js: str, features: Dict[str, Any]) -> float:
    """
    Сигнатурно-евристичний fallback, який працює завжди.
    Використовується, якщо модель не завантажена або впала.
    """
    score = 0.0

    # Підозрілі патерни
    for pat in _SUSPICIOUS_PATTERNS:
        if re.search(pat, raw_js):
            score += 0.10

    # Dynamic execution
    score += 0.15 * features.get("num_dynamic_execution", 0)

    # Prototype pollution
    score += 0.10 * features.get("num_prototype_pollution", 0)

    # Entropy
    entropy = features.get("entropy", 0.0)
    if entropy > 3:
        score += min((entropy - 3) / 8.0, 0.20)

    # Довгі строки
    if any(len(s) > 200 for s in re.findall(r"['\"]([^'\"]{200,})['\"]", raw_js)):
        score += 0.15

    # Softmax-like стабілізація
    score = 1 - math.exp(-score)
    return max(0.0, min(1.0, score))


# ============================================================
#  Основна функція NN-ризику
# ============================================================

def nn_risk_score(raw_js: str, features: Dict[str, Any]) -> float:
    """
    Повертає NN-ризик.
    SAFE MODE гарантує, що GUI не впаде.
    """

    # NN вимкнено через settings.py
    if AI_DISABLE_NN:
        return 0.0

    model = get_nn_model()

    # Модель не завантажена → fallback
    if model is None:
        if AI_SAFE_MODE:
            return _fallback_nn_score(raw_js, features)
        return 0.0

    # Формуємо вектор фіч
    x = [
        features.get("num_dom_sinks", 0),
        features.get("num_dangerous_calls", 0),
        features.get("num_dynamic_execution", 0),
        features.get("num_prototype_pollution", 0),
        features.get("num_csp_bypass", 0),
        features.get("num_api_endpoints", 0),
        features.get("behavior_density", 0.0),
        features.get("sink_score", 0.0),
        features.get("danger_score", 0.0),
        features.get("execution_score", 0.0),
        features.get("sig_hex_obfuscation", 0),
        features.get("sig_infinite_loop", 0),
        features.get("sig_eval_chain", 0),
        features.get("sig_cookie_access", 0),
        features.get("sig_anti_debug", 0),
        features.get("sig_fromCharCode", 0),
        features.get("sig_base64", 0),
        features.get("js_length", 0),
        features.get("js_lines", 0),
        features.get("js_avg_line_len", 0.0),
        features.get("entropy", 0.0),
        features.get("complexity", 0.0),
    ]

    # Пробуємо зробити predict
    try:
        proba = float(model.predict_proba([x])[0][1])
        return max(0.0, min(1.0, proba))

    except Exception as e:
        print(f"[AI Core] NN model predict failed: {e}")

        if AI_FALLBACK_ON_ERROR or AI_SAFE_MODE:
            return _fallback_nn_score(raw_js, features)

        # Якщо SAFE MODE вимкнено — кидаємо помилку
        raise e


