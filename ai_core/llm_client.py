"""
AI Core 20.0 — llm_client.py (ABSOLUTE SAFE MODE)

LLM-шар:
- пояснення ризиків
- high-level аналіз
- генерація "reasons" / summary
- вагові коефіцієнти
- llm_risk для Risk Engine
- повна підтримка AI_DISABLE_LLM, AI_SAFE_MODE, AI_FALLBACK_ON_ERROR
- 100% GUI-SAFE (жодних блокуючих операцій)
"""

from typing import Dict, Any, List

from xss_security_gui.settings import (
    AI_DISABLE_LLM,
    AI_SAFE_MODE,
    AI_FALLBACK_ON_ERROR,
)


# ============================================================
#  Вагові коефіцієнти
# ============================================================

_REASON_WEIGHTS = {
    "dom_sinks": 0.25,
    "dangerous_calls": 0.30,
    "dynamic_execution": 0.35,
    "prototype_pollution": 0.40,
    "csp_bypass": 0.20,
    "api_endpoints": 0.10,
    "behavior_density": 0.25,
    "signature_flags": 0.30,
    "no_issues": 0.05,
}


# ============================================================
#  Генерація причин (GUI-SAFE)
# ============================================================

def _generate_reasons(features: Dict[str, Any]) -> List[str]:
    try:
        reasons: List[str] = []

        if features.get("num_dom_sinks", 0) > 0:
            reasons.append("Виявлено DOM-sinks, що можуть бути XSS-точками.")

        if features.get("num_dangerous_calls", 0) > 0:
            reasons.append("Використовуються небезпечні виклики (eval, Function, setTimeout...).")

        if features.get("num_dynamic_execution", 0) > 0:
            reasons.append("Виявлено ознаки динамічного виконання коду.")

        if features.get("num_prototype_pollution", 0) > 0:
            reasons.append("Можливі патерни prototype pollution.")

        if features.get("num_csp_bypass", 0) > 0:
            reasons.append("Виявлено CSP bypass індикатори.")

        if features.get("num_api_endpoints", 0) > 0:
            reasons.append("JS-код взаємодіє з API, що може бути точкою атаки.")

        if features.get("behavior_density", 0.0) > 0.5:
            reasons.append("Висока щільність небезпечних патернів у JS-коді.")

        if any(features.get(k, 0) for k in (
            "sig_hex_obfuscation",
            "sig_eval_chain",
            "sig_cookie_access",
            "sig_anti_debug",
            "sig_fromCharCode",
            "sig_base64",
        )):
            reasons.append("Виявлено сигнатури, характерні для обфускації або шкідливої поведінки.")

        if not reasons:
            reasons.append("Критичних патернів не виявлено, рекомендовано додатковий аналіз.")

        return reasons

    except Exception as e:
        if AI_SAFE_MODE or AI_FALLBACK_ON_ERROR:
            return [f"AI SAFE MODE: reason generation failed ({e})"]
        return ["LLM error"]


# ============================================================
#  Ризик на основі причин (GUI-SAFE)
# ============================================================

def _llm_reason_risk(features: Dict[str, Any]) -> float:
    try:
        score = 0.0

        if features.get("num_dom_sinks", 0) > 0:
            score += _REASON_WEIGHTS["dom_sinks"]

        if features.get("num_dangerous_calls", 0) > 0:
            score += _REASON_WEIGHTS["dangerous_calls"]

        if features.get("num_dynamic_execution", 0) > 0:
            score += _REASON_WEIGHTS["dynamic_execution"]

        if features.get("num_prototype_pollution", 0) > 0:
            score += _REASON_WEIGHTS["prototype_pollution"]

        if features.get("num_csp_bypass", 0) > 0:
            score += _REASON_WEIGHTS["csp_bypass"]

        if features.get("num_api_endpoints", 0) > 0:
            score += _REASON_WEIGHTS["api_endpoints"]

        if features.get("behavior_density", 0.0) > 0.5:
            score += _REASON_WEIGHTS["behavior_density"]

        if any(features.get(k, 0) for k in (
            "sig_hex_obfuscation",
            "sig_eval_chain",
            "sig_cookie_access",
            "sig_anti_debug",
            "sig_fromCharCode",
            "sig_base64",
        )):
            score += _REASON_WEIGHTS["signature_flags"]

        if score == 0.0:
            score = _REASON_WEIGHTS["no_issues"]

        return min(score, 1.0)

    except Exception:
        return 0.0


# ============================================================
#  Summary (GUI-SAFE)
# ============================================================

def _generate_summary(reasons: List[str]) -> str:
    try:
        if len(reasons) == 1:
            return reasons[0]
        return " ".join(reasons)
    except Exception as e:
        if AI_SAFE_MODE or AI_FALLBACK_ON_ERROR:
            return f"AI SAFE MODE: summary failed ({e})"
        return "LLM summary error"


# ============================================================
#  Головна функція LLM-шару (ABSOLUTE SAFE MODE)
# ============================================================

def llm_analyze_js(js_code: str, features: Dict[str, Any]) -> Dict[str, Any]:
    """
    ABSOLUTE SAFE MODE:
    - LLM ніколи не блокує GUI
    - LLM ніколи не падає
    - LLM ніколи не викликає мережевих запитів
    - LLM завжди повертає результат < 5 мс
    """

    # LLM вимкнено
    if AI_DISABLE_LLM:
        return {
            "llm_summary": "LLM вимкнено (AI_SAFE_MODE)",
            "llm_reasons": ["LLM disabled"],
            "llm_risk": 0.0,
        }

    try:
        reasons = _generate_reasons(features)
        summary = _generate_summary(reasons)
        llm_risk = _llm_reason_risk(features)

        return {
            "llm_summary": summary,
            "llm_reasons": reasons,
            "llm_risk": llm_risk,
        }

    except Exception as e:
        if AI_SAFE_MODE or AI_FALLBACK_ON_ERROR:
            return {
                "llm_summary": f"AI SAFE MODE: LLM failed ({e})",
                "llm_reasons": ["LLM error"],
                "llm_risk": 0.0,
            }

        return {
            "llm_summary": "LLM error",
            "llm_reasons": ["LLM exception"],
            "llm_risk": 0.0,
        }


