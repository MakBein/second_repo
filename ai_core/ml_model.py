"""
AI Core 20.0 — ml_model.py (SAFE MODE)

Hybrid ML Model 20.0:
- вагові коефіцієнти для розширених фіч
- behavior-density / sink / danger / execution scoring
- signature-aware scoring
- structural-aware scoring
- risk-curve compression + softmax-like стабілізація
- повна підтримка AI_DISABLE_ML та SAFE MODE
"""

from typing import Dict, Any
import math

from xss_security_gui.settings import (
    AI_DISABLE_ML,
    AI_SAFE_MODE,
    AI_FALLBACK_ON_ERROR,
)


class HybridMLModel20:
    # ------------------------------------------------------------
    #  Signature-based scoring
    # ------------------------------------------------------------
    def _signature_risk(self, features: Dict[str, Any]) -> float:
        score = 0.0
        if features.get("sig_hex_obfuscation", 0):
            score += 0.25
        if features.get("sig_eval_chain", 0):
            score += 0.30
        if features.get("sig_cookie_access", 0):
            score += 0.15
        if features.get("sig_anti_debug", 0):
            score += 0.15
        if features.get("sig_fromCharCode", 0):
            score += 0.10
        if features.get("sig_base64", 0):
            score += 0.10
        return min(score, 1.0)

    # ------------------------------------------------------------
    #  Основний ML-скоринг
    # ------------------------------------------------------------
    def predict_proba(self, features: Dict[str, Any]) -> float:
        try:
            sinks = features.get("num_dom_sinks", 0)
            dangerous = features.get("num_dangerous_calls", 0)
            dynamic = features.get("num_dynamic_execution", 0)
            pollution = features.get("num_prototype_pollution", 0)
            csp = features.get("num_csp_bypass", 0)
            api = features.get("num_api_endpoints", 0)

            behavior_density = features.get("behavior_density", 0.0)
            sink_score = features.get("sink_score", 0.0)
            danger_score = features.get("danger_score", 0.0)
            execution_score = features.get("execution_score", 0.0)

            js_length = features.get("js_length", 0)
            js_lines = features.get("js_lines", 0)
            js_avg_line_len = features.get("js_avg_line_len", 0.0)

            entropy = features.get("entropy", 0.0)
            complexity = features.get("complexity", 0.0)

            sig_risk = self._signature_risk(features)

            score = 0.0
            score += sinks * 0.08
            score += dangerous * 0.12
            score += dynamic * 0.14
            score += pollution * 0.16
            score += csp * 0.06
            score += api * 0.04

            score += behavior_density * 0.25
            score += sink_score * 0.10
            score += danger_score * 0.12
            score += execution_score * 0.15

            if js_length > 5000:
                score += 0.10
            if js_lines > 200:
                score += 0.05
            if js_avg_line_len > 120:
                score += 0.05

            if entropy > 3:
                score += min((entropy - 3) / 8.0, 0.20)

            score += complexity * 0.20
            score += sig_risk * 0.30

            # Risk curve compression
            score = math.log1p(score) / math.log(3)

            # Softmax-like стабілізація
            score = 1 - math.exp(-score)

            return max(0.0, min(1.0, score))

        except Exception as e:
            print(f"[AI Core] ML model failed: {e}")

            if AI_SAFE_MODE or AI_FALLBACK_ON_ERROR:
                return 0.0  # ML fallback = 0.0 (NN і Heuristic компенсують)

            raise e


# ------------------------------------------------------------
#  Глобальна ML-модель
# ------------------------------------------------------------

_ml_model = HybridMLModel20()


def get_ml_model() -> HybridMLModel20:
    return _ml_model


# ------------------------------------------------------------
#  Публічна функція ML-скорингу
# ------------------------------------------------------------

def ml_risk_score(features: Dict[str, Any]) -> float:
    """
    SAFE MODE:
    - якщо ML вимкнено → повертає 0.0
    - якщо ML впав → повертає 0.0
    """
    if AI_DISABLE_ML:
        return 0.0

    try:
        return get_ml_model().predict_proba(features)
    except Exception as e:
        print(f"[AI Core] ML risk score failed: {e}")

        if AI_SAFE_MODE or AI_FALLBACK_ON_ERROR:
            return 0.0

        raise e




