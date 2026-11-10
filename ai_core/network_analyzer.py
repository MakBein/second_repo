# xss_security_gui/ai_core/network_analyzer.py

from typing import Any
from typing import Dict


def analyze_network_risk(
        scan_data: Dict[str, Any]
) -> Dict[str, Any]:

    score = 0

    findings = []
    positives = []
    risk_reasons = []

    confirmed_services = set(
        scan_data.get(
            "confirmed_services",
            []
        )
    )

    possible_services = set(
        scan_data.get(
            "possible_services",
            []
        )
    )

    open_port_count = scan_data.get(
        "open_port_count",
        0
    )

    web_port_count = scan_data.get(
        "web_port_count",
        0
    )

    service_port_count = scan_data.get(
        "service_port_count",
        0
    )

    tls = scan_data.get(
        "tls_version"
    )

    waf_detected = scan_data.get(
        "waf_detected",
        False
    )

    csp_present = scan_data.get(
        "csp_present",
        False
    )

    icmp_reachable = scan_data.get(
        "icmp_reachable",
        False
    )

    # ====================================================
    # Confidence
    # ====================================================

    confirmed_count = len(confirmed_services)
    possible_count = len(possible_services)
    service_count = len(confirmed_services | possible_services)

    confidence = 0.0

    if service_count:
        confidence = round(
            confirmed_count / service_count * 100,
            1
        )

    # ====================================================
    # Confirmed Services
    # ====================================================

    service_risk = {
        "Docker": 50,
        "Docker TLS": 20,
        "Elasticsearch": 25,
        "Redis": 20,
        "PostgreSQL": 15,
        "MongoDB": 15,
        "MySQL": 15,
    }

    for service in confirmed_services:

        if service in service_risk:

            value = service_risk[service]

            score += value

            findings.append(
                f"{service} confirmed "
                f"(+{value})"
            )

            risk_reasons.append(
                f"Confirmed service: {service}"
            )

    # ====================================================
    # WEB
    # ====================================================

    if "WEB" in confirmed_services:

        positives.append(
            "Web service verified"
        )

        findings.append(
            "Web service confirmed"
        )

    # ====================================================
    # SSH/SMTP
    # ====================================================

    if "SSH" in confirmed_services:

        positives.append(
            "SSH banner verified"
        )

    if "SMTP" in confirmed_services:

        positives.append(
            "SMTP banner verified"
        )

    # ====================================================
    # Exposure
    # ====================================================

    findings.append(
        f"{open_port_count} TCP endpoints responded"
    )

    if open_port_count <= 5:

        exposure = "minimal"

    elif open_port_count <= 15:

        exposure = "moderate"

    else:

        exposure = "large"

    findings.append(
        f"Exposure classification: "
        f"{exposure}"
    )

    if service_port_count >= 10:

        findings.append(
            f"Large service surface "
            f"({service_port_count})"
        )

    if web_port_count >= 3:

        findings.append(
            f"Multiple web endpoints "
            f"({web_port_count})"
        )

    # ====================================================
    # Infrastructure Profile
    # ====================================================

    infra_type = "unknown"

    if (
            "WEB" in confirmed_services
            and open_port_count > 15
    ):

        infra_type = (
            "web platform or "
            "load-balanced infrastructure"
        )

    elif "WEB" in confirmed_services:

        infra_type = (
            "web application"
        )

    findings.append(
        f"Infrastructure: {infra_type}"
    )

    # ====================================================
    # WAF
    # ====================================================

    if waf_detected:

        positives.append(
            "WAF detected"
        )

    else:

        score += 5

        findings.append(
            "WAF not detected"
        )

        risk_reasons.append(
            "WAF not detected"
        )

    # ====================================================
    # CSP
    # ====================================================

    if csp_present:

        positives.append(
            "CSP enabled"
        )

    else:

        score += 5

        findings.append(
            "CSP missing"
        )

        risk_reasons.append(
            "CSP missing"
        )

    # ====================================================
    # TLS
    # ====================================================

    if tls == "TLSv1.3":

        positives.append(
            "Modern TLSv1.3 enabled"
        )

        findings.append(
            "TLSv1.3 enabled"
        )

    elif tls == "TLSv1.2":

        positives.append(
            "TLSv1.2 enabled"
        )

    elif tls:

        score += 10

        findings.append(
            f"Legacy TLS detected ({tls})"
        )

        risk_reasons.append(
            f"Legacy TLS ({tls})"
        )

    else:

        score += 10

        risk_reasons.append(
            "TLS information unavailable"
        )

    # ====================================================
    # HTTPS
    # ====================================================

    if tls and str(tls).lower() != "unknown":

        positives.append(
            "HTTPS available"
        )

    else:

        score += 20

        findings.append(
            "HTTPS not detected"
        )

        risk_reasons.append(
            "HTTPS unavailable"
        )

    # ====================================================
    # ICMP
    # ====================================================

    if icmp_reachable:

        positives.append(
            "ICMP reachable"
        )

    else:

        findings.append(
            "ICMP filtered or blocked"
        )

    # ====================================================
    # Unconfirmed Services
    # ====================================================

    uncertain = sorted(
        possible_services
        - confirmed_services
    )

    if uncertain:

        findings.append(
            "Unconfirmed services: "
            + ", ".join(uncertain)
        )

    # ====================================================
    # Risk Level
    # ====================================================

    if score >= 80:

        risk = "CRITICAL"

    elif score >= 50:

        risk = "HIGH"

    elif score >= 20:

        risk = "MEDIUM"

    else:

        risk = "LOW"

    # ====================================================
    # Summary
    # ====================================================

    summary = (
        f"Risk={risk}, "
        f"Score={score}, "
        f"Confirmed={confirmed_count}, "
        f"Possible={possible_count}, "
        f"Confidence={confidence}%, "
        f"TCP={open_port_count}"
    )

    # ====================================================
    # Result
    # ====================================================

    return {
        "risk_level": risk,
        "risk_score": score,
        "confidence": confidence,
        "summary": summary,
        "positives": positives,
        "risk_reasons": risk_reasons,
        "confirmed_services": sorted(
            confirmed_services
        ),
        "possible_services": sorted(
            possible_services
        ),
        "findings": findings,
    }