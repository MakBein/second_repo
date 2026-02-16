# xss_security_gui/risk_classifier.py
"""
RiskClassifier ULTRA 6.x
Единый модуль классификации и оценки риска XSS-пейлоадов.
Используется Mutator ULTRA, Honeypot ULTRA, AttackEngine и Analyzer.
"""

from typing import Dict, Any


def classify_payload(payload: str) -> str:
    p = payload.lower()

    if any(tag in p for tag in ("<svg", "<iframe", "<img", "<script", "<math", "<body")):
        return "html_tag"

    if "javascript:" in p or "eval(" in p or "fromcharcode" in p:
        return "js_exec"

    if "data:text/javascript" in p or "srcdoc" in p:
        return "csp_bypass"

    if any(x in p for x in ["document.cookie", "document.domain", "location.href", "window.name"]):
        return "dom_leak"

    if "%3c" in p or "%3e" in p or "%3cscript" in p:
        return "url_encoded"

    if "jsfuck" in p or "string.fromcharcode" in p:
        return "obfuscation"

    if "<?xml" in p or "<xml" in p:
        return "xml"

    if "{" in p and "}" in p and ":" in p:
        return "json"

    return "generic"


def estimate_risk(payload: str, family: str) -> int:
    p = payload.lower()
    risk = 1

    if "alert(" in p:
        risk += 1
    if any(x in p for x in ["document.cookie", "document.domain", "location.href", "window.name"]):
        risk += 3
    if "eval(" in p or "fromcharcode" in p:
        risk += 2
    if "data:text/javascript" in p or "srcdoc" in p:
        risk += 2
    if "javascript:" in p:
        risk += 1

    if family in ("dom_leak", "csp_bypass", "js_exec"):
        risk += 2
    if family in ("obfuscation", "framework"):
        risk += 1

    return min(risk, 10)


def risk_level(score: int) -> str:
    if score >= 8:
        return "critical"
    if score >= 5:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def build_structured(payload: str) -> Dict[str, Any]:
    family = classify_payload(payload)
    risk = estimate_risk(payload, family)
    return {
        "payload": payload,
        "family": family,
        "risk": risk,
        "risk_level": risk_level(risk),
    }