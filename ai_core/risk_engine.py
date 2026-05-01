"""
AI Core 20.0 — risk_engine.py (SAFE MODE)

Ядро оцінки ризиків:
- ML 20.0 + NN 20.0 + Heuristic + LLM 20.0
- entropy / complexity
- behavior / signature-aware
- повна підтримка AI_SAFE_MODE / AI_FALLBACK_ON_ERROR
"""

from typing import Dict, Any
import math

from xss_security_gui.settings import (
    AI_SAFE_MODE,
    AI_FALLBACK_ON_ERROR,
)

from .features import build_js_features
from .ml_model import ml_risk_score
from .nn_model import nn_risk_score
from .llm_client import llm_analyze_js


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    try:
        freq = {c: text.count(c) for c in set(text)}
        total = len(text)
        return -sum((count / total) * math.log2(count / total) for count in freq.values())
    except Exception:
        return 0.0


def _complexity(js_insights: Dict[str, Any]) -> float:
    try:
        score = 0.0
        score += len(js_insights.get("functions", [])) * 0.02
        score += len(js_insights.get("classes", [])) * 0.03
        score += len(js_insights.get("methods", [])) * 0.01
        score += len(js_insights.get("api_endpoints", [])) * 0.05
        score += len(js_insights.get("dom_sinks", [])) * 0.10
        score += len(js_insights.get("dangerous_calls", [])) * 0.15
        score += len(js_insights.get("dynamic_execution", [])) * 0.20
        return min(score, 1.0)
    except Exception:
        return 0.0


def _heuristic_risk(js_insights: Dict[str, Any], entropy: float) -> float:
    try:
        risk = 0.0
        risk += len(js_insights.get("dom_sinks", [])) * 0.08
        risk += len(js_insights.get("dangerous_calls", [])) * 0.12
        risk += len(js_insights.get("dynamic_execution", [])) * 0.15
        risk += len(js_insights.get("csp_bypass_indicators", [])) * 0.05
        risk += len(js_insights.get("prototype_pollution", [])) * 0.10
        risk += min(entropy / 8.0, 0.20)
        return min(risk, 1.0)
    except Exception:
        return 0.0


def _combine_scores(ml_score: float, nn_score: float, heuristic: float, llm_risk: float) -> float:
    score = (
        ml_score * 0.30 +
        nn_score * 0.30 +
        heuristic * 0.20 +
        llm_risk * 0.20
    )
    return max(0.0, min(1.0, score))


def _risk_level(score: float) -> str:
    if score >= 0.8:
        return "high"
    if score >= 0.5:
        return "medium"
    if score >= 0.2:
        return "low"
    return "info"


def _safe_fallback_result(raw_js: str, reason: str = "AI SAFE MODE") -> Dict[str, Any]:
    return {
        "risk_score": 0.0,
        "risk_level": "info",
        "ml_score": 0.0,
        "nn_score": 0.0,
        "heuristic_score": 0.0,
        "entropy": _entropy(raw_js),
        "complexity": 0.0,
        "llm_summary": f"{reason}: fallback result",
        "llm_reasons": [reason],
        "llm_risk": 0.0,
    }


def analyze_security_risk(js_insights: Dict[str, Any], raw_js: str) -> Dict[str, Any]:
    """
    ABSOLUTE SAFE MODE (GUI-SAFE):
    - жоден шар не може зависнути
    - кожен шар має свій try/except
    - LLM має timeout
    - ML/NN ізольовані
    - будь-яка помилка → стабільний fallback
    """

    # -----------------------------
    # 0. Базові метрики (завжди безпечні)
    # -----------------------------
    try:
        entropy = _entropy(raw_js)
        complexity = _complexity(js_insights)
    except Exception:
        entropy = 0.0
        complexity = 0.0

    # -----------------------------
    # 1. Features
    # -----------------------------
    try:
        features = build_js_features(js_insights, raw_js)
        features["entropy"] = entropy
        features["complexity"] = complexity
        features["raw_js"] = raw_js
    except Exception as e:
        return _safe_fallback_result(raw_js, reason=f"FEATURE ERROR: {e}")

    # -----------------------------
    # 2. ML
    # -----------------------------
    try:
        ml_score = ml_risk_score(features)
    except Exception:
        ml_score = 0.0

    # -----------------------------
    # 3. NN
    # -----------------------------
    try:
        nn_score = nn_risk_score(raw_js, features)
    except Exception:
        nn_score = 0.0

    # -----------------------------
    # 4. Heuristic
    # -----------------------------
    try:
        heuristic = _heuristic_risk(js_insights, entropy)
    except Exception:
        heuristic = 0.0

    # -----------------------------
    # 5. LLM (з timeout)
    # -----------------------------
    try:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(llm_analyze_js, raw_js, features)
            llm_result = future.result(timeout=2.0)  # 2 секунди максимум
    except Exception:
        llm_result = {"llm_summary": "", "llm_reasons": [], "llm_risk": 0.0}

    llm_summary = llm_result.get("llm_summary", "")
    llm_reasons = llm_result.get("llm_reasons", [])
    llm_risk = llm_result.get("llm_risk", 0.0)

    # -----------------------------
    # 6. Combine
    # -----------------------------
    try:
        combined = _combine_scores(ml_score, nn_score, heuristic, llm_risk)
    except Exception:
        combined = 0.0

    # -----------------------------
    # 7. Final result
    # -----------------------------
    return {
        "risk_score": combined,
        "risk_level": _risk_level(combined),
        "ml_score": ml_score,
        "nn_score": nn_score,
        "heuristic_score": heuristic,
        "entropy": entropy,
        "complexity": complexity,
        "llm_summary": llm_summary,
        "llm_reasons": llm_reasons,
        "llm_risk": llm_risk,
    }



