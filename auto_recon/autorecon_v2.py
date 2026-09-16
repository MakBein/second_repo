# xss_security_gui/auto_recon/autorecon_v2.py
from typing import Dict, Any
import json
import datetime

from xss_security_gui.auto_recon.scanner import EndpointScanner, save_reflected_response
from xss_security_gui.threat_analysis.threat_connector import ThreatConnector
from xss_security_gui.auto_recon.user_tracker import (
    get_user_tracker,
    get_user_context,
    build_attack_surface,
)


def run_autorecon(
    target_url: str,
    base_params: Dict[str, Any] | None = None,
    method: str = "GET",
) -> Dict[str, Any]:
    """
    AutoRecon V2 — боевой Red Team Recon Engine.
    Полный пайплайн:
    1) Endpoint Recon
    2) XSS Detection
    3) XSS Fuzzing
    4) Attack Surface Builder
    5) Threat Intelligence Aggregation
    6) MITRE + Kill Chain Tracking
    7) Risk Scoring
    8) Final Threat Report
    """

    tracker = get_user_tracker()
    ctx = get_user_context()

    # === 0. Логируем начало операции Recon ===
    tracker.track_operation("autorecon_start", {"target": target_url}, target=target_url)

    # === 1. Endpoint Recon ===
    scanner = EndpointScanner(target_url)
    endpoints = scanner.scan()

    tracker.track_operation("endpoint_recon", {"count": len(endpoints)}, target=target_url)

    # === 2. XSS Detection ===
    xss_results = scanner.scan_xss_on_endpoints()
    tracker.track_operation("xss_detection", {"count": len(xss_results)}, target=target_url)

    for entry in xss_results:
        if entry.get("context") and entry.get("context") != "❌ Not reflected":
            save_reflected_response(entry)
            tracker.track_vulnerability_found(
                vuln_type="XSS",
                url=entry.get("url", target_url),
                severity="medium",
                payload=entry.get("payload"),
                details=entry,
                cvss=5.4,
                exploitable=True,
                chainable=True,
            )

    # === 3. XSS Fuzzing ===
    fuzz_results = scanner.fuzz_xss_parameters(base_params or {}, method=method)
    tracker.track_operation("xss_fuzzing", {"count": len(fuzz_results)}, target=target_url)

    # === 4. Attack Surface Builder ===
    surface = build_attack_surface(target_url)
    tracker.track_attack_surface(target_url, surface)

    # === 5. Threat Intelligence Aggregation ===
    connector = ThreatConnector()
    connector.add_artifact("ENDPOINTS", target_url, endpoints)
    connector.add_artifact("XSS", target_url, xss_results)
    connector.add_artifact("XSS_FUZZ", target_url, fuzz_results)
    connector.add_artifact("ATTACK_SURFACE", target_url, surface)

    # === 6. MITRE + Kill Chain Tracking ===
    tracker.track_attack_chain(
        tactic="TA0043",          # Reconnaissance
        technique="T1595",        # Active Scanning
        subtechnique="T1595.002", # Vulnerability Scanning
        target=target_url,
        status="executed",
        details={"endpoints": len(endpoints)},
        operator_note="AutoRecon completed reconnaissance phase."
    )

    # === 7. Threat Level + Risk Score ===
    risk_score = 0
    risk_score += len(surface["endpoints"]) * 2
    risk_score += len(surface["parameters"]) * 1
    risk_score += len(surface["forms"]) * 3
    risk_score += len(surface["js_libs"]) * 1

    if surface["cms"]:
        risk_score += 10
    if surface["cdn"]:
        risk_score += 5
    if surface["tls"].get("weak"):
        risk_score += 7

    if risk_score < 20:
        threat_level = "low"
    elif risk_score < 40:
        threat_level = "medium"
    elif risk_score < 70:
        threat_level = "high"
    else:
        threat_level = "critical"

    ctx.threat_level = threat_level
    ctx.last_event = {
        "event": "risk_score_updated",
        "score": risk_score,
        "level": threat_level,
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
    }

    tracker.track_operation(
        "risk_scoring",
        {"risk_score": risk_score, "threat_level": threat_level},
        target=target_url,
    )

    # === 8. Final Threat Report ===
    threat_report = connector.generate_report()

    tracker.track_operation("autorecon_complete", {"threat_level": threat_level}, target=target_url)

    return {
        "target": target_url,
        "endpoints": endpoints,
        "xss_results": xss_results,
        "fuzz_results": fuzz_results,
        "attack_surface": surface,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "threat_report": threat_report,
    }


__all__ = ["run_autorecon"]

