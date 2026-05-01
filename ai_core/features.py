"""
AI Core 20.0 — features.py (SAFE MODE)

Розширений витяг фіч:
- JS Inspector
- behavioral scoring
- sink/danger/dynamic weights
- obfuscation indicators
- signature flags
- JS structural metrics
- risk context hints (для LLM/ML/NN)
- повна підтримка SAFE MODE
"""

from typing import Dict, Any, List
import re

from xss_security_gui.settings import (
    AI_SAFE_MODE,
    AI_FALLBACK_ON_ERROR,
)


# ============================================================
#  Допоміжні функції
# ============================================================

def _count_lines(js: str) -> int:
    try:
        return js.count("\n") + 1 if js else 0
    except Exception:
        return 0


def _avg_line_length(js: str) -> float:
    try:
        if not js:
            return 0.0
        lines = js.split("\n")
        return sum(len(l) for l in lines) / len(lines)
    except Exception:
        return 0.0


def _signature_flags(js: str) -> Dict[str, int]:
    try:
        return {
            "sig_hex_obfuscation": int(bool(re.search(r"_0x[a-f0-9]{4,}", js))),
            "sig_infinite_loop": int("while(true)" in js.replace(" ", "")),
            "sig_eval_chain": int("eval(atob" in js or "Function(atob" in js),
            "sig_cookie_access": int("document.cookie" in js),
            "sig_anti_debug": int("debugger" in js),
            "sig_fromCharCode": int("fromCharCode" in js),
            "sig_base64": int("atob(" in js or "btoa(" in js),
        }
    except Exception:
        if AI_SAFE_MODE or AI_FALLBACK_ON_ERROR:
            return {
                "sig_hex_obfuscation": 0,
                "sig_infinite_loop": 0,
                "sig_eval_chain": 0,
                "sig_cookie_access": 0,
                "sig_anti_debug": 0,
                "sig_fromCharCode": 0,
                "sig_base64": 0,
            }
        raise


# ============================================================
#  Основні JS-фічі
# ============================================================

def build_js_features(js_insights: Dict[str, Any], raw_js: str = "") -> Dict[str, Any]:
    """
    Приймає результат extract_js_insights(...) і перетворює в фічі для ML/NN/LLM.
    SAFE MODE гарантує, що GUI не впаде.
    """

    try:
        base = {
            "num_functions": len(js_insights.get("functions", [])),
            "num_classes": len(js_insights.get("classes", [])),
            "num_methods": len(js_insights.get("methods", [])),
            "num_fetch": len(js_insights.get("fetch_calls", [])),
            "num_ajax": len(js_insights.get("ajax_calls", [])),
            "num_xhr": len(js_insights.get("xhr_calls", [])),
            "num_websocket": len(js_insights.get("websocket_calls", [])),
            "num_eventsource": len(js_insights.get("eventsource_calls", [])),
            "num_event_listeners": len(js_insights.get("event_listeners", [])),
            "num_timers": len(js_insights.get("timers", [])),
            "num_dom_sinks": len(js_insights.get("dom_sinks", [])),
            "num_dangerous_calls": len(js_insights.get("dangerous_calls", [])),
            "num_api_endpoints": len(js_insights.get("api_endpoints", [])),
            "num_graphql_queries": len(js_insights.get("graphql_queries", [])),
            "num_frameworks": len(js_insights.get("frameworks", [])),
            "num_libraries": len(js_insights.get("libraries", [])),
            "num_prototype_pollution": len(js_insights.get("prototype_pollution", [])),
            "num_dynamic_execution": len(js_insights.get("dynamic_execution", [])),
            "num_csp_bypass": len(js_insights.get("csp_bypass_indicators", [])),
            "num_jquery_calls": len(js_insights.get("jquery_calls", [])),
        }

        # Behavioral
        base["behavior_density"] = min(
            (
                base["num_dom_sinks"]
                + base["num_dangerous_calls"]
                + base["num_dynamic_execution"]
                + base["num_prototype_pollution"]
                + base["num_csp_bypass"]
            ) / 20.0,
            1.0,
        )
        base["sink_score"] = base["num_dom_sinks"] * 0.25
        base["danger_score"] = base["num_dangerous_calls"] * 0.30
        base["execution_score"] = base["num_dynamic_execution"] * 0.35

        # Structural
        base["js_length"] = len(raw_js)
        base["js_lines"] = _count_lines(raw_js)
        base["js_avg_line_len"] = _avg_line_length(raw_js)

        # Signature flags
        base.update(_signature_flags(raw_js))

        return base

    except Exception as e:
        print(f"[AI Core] features.py failed: {e}")

        if AI_SAFE_MODE or AI_FALLBACK_ON_ERROR:
            return {
                "num_functions": 0,
                "num_classes": 0,
                "num_methods": 0,
                "num_fetch": 0,
                "num_ajax": 0,
                "num_xhr": 0,
                "num_websocket": 0,
                "num_eventsource": 0,
                "num_event_listeners": 0,
                "num_timers": 0,
                "num_dom_sinks": 0,
                "num_dangerous_calls": 0,
                "num_api_endpoints": 0,
                "num_graphql_queries": 0,
                "num_frameworks": 0,
                "num_libraries": 0,
                "num_prototype_pollution": 0,
                "num_dynamic_execution": 0,
                "num_csp_bypass": 0,
                "num_jquery_calls": 0,
                "behavior_density": 0.0,
                "sink_score": 0.0,
                "danger_score": 0.0,
                "execution_score": 0.0,
                "js_length": len(raw_js),
                "js_lines": _count_lines(raw_js),
                "js_avg_line_len": _avg_line_length(raw_js),
                **_signature_flags(raw_js),
            }

        raise


# ============================================================
#  Фічі для сторінки
# ============================================================

def build_page_features(
    url: str,
    status_code: int | None = None,
    content_type: str | None = None,
    js_features: Dict[str, Any] | None = None,
    threat_tags: List[str] | None = None,
) -> Dict[str, Any]:

    try:
        js_features = js_features or {}
        threat_tags = threat_tags or []

        base = {
            "url": url,
            "status_code": status_code or 0,
            "is_html": int("html" in (content_type or "").lower()),
            "is_js": int("javascript" in (content_type or "").lower()),
            "threat_tags_count": len(threat_tags),
        }

        base.update(js_features)
        return base

    except Exception as e:
        print(f"[AI Core] build_page_features failed: {e}")

        if AI_SAFE_MODE or AI_FALLBACK_ON_ERROR:
            return {
                "url": url,
                "status_code": status_code or 0,
                "is_html": 0,
                "is_js": 0,
                "threat_tags_count": 0,
                **(js_features or {}),
            }

        raise


