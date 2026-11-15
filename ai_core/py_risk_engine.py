# py_risk_engine
from typing import Dict, Any

def analyze_py_risk(features: Dict[str, Any]) -> Dict[str, Any]:
    score = 0.0

    if features["has_threads"] and features["has_tk"]:
        score += 0.4  # потенційні проблеми з потоками і GUI
    if features["has_network"] and features["has_tk"]:
        score += 0.2  # можливі блокуючі виклики
    if features["loc"] > 500:
        score += 0.2
    if features["num_classes"] > 10 or features["num_functions"] > 30:
        score += 0.2

    score = max(0.0, min(1.0, score))

    if score >= 0.8:
        level = "high"
    elif score >= 0.5:
        level = "medium"
    elif score >= 0.2:
        level = "low"
    else:
        level = "info"

    return {
        "risk_score": score,
        "risk_level": level,
    }
