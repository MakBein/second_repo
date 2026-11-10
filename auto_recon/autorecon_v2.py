# xss_security_gui/auto_recon/autorecon_v2.py
"""
AutoRecon V2 — Red Team Enterprise Edition
Полный автоматизированный пайплайн разведки:

1) EndpointScanner (боевой режим)
2) XSS-сканирование (контекст + выполнение)
3) XSS-fuzzing (реальные payload’ы)
4) ThreatConnector (fail-safe агрегация)
5) Генерация итогового отчёта (никогда не падает)
"""

import json
import logging
import argparse
from typing import Dict, Any

from xss_security_gui.auto_recon.scanner import EndpointScanner, save_reflected_response
from xss_security_gui.threat_analysis.threat_connector import ThreatConnector

log = logging.getLogger("AutoReconV2")


def run_autorecon(
    target_url: str,
    base_params: Dict[str, Any] | None = None,
    method: str = "GET",
    active_testing: bool = False,
) -> Dict[str, Any]:
    """
    Запускает полный AutoRecon-процесс (Red Team Safe Version).

    • Каждый этап изолирован try/except
    • Никаких падений GUI
    • Никаких падений AutoRecon RT
    • ThreatConnector всегда возвращает отчёт
    """

    method = method.upper()
    if method not in {"GET", "POST"}:
        raise ValueError("method must be GET or POST")

    # ============================================================
    # 1. EndpointScanner
    # ============================================================
    try:
        scanner = EndpointScanner(target_url, active_testing=active_testing)
        endpoints = scanner.scan()
    except Exception as e:
        log.error(f"[AutoReconV2] EndpointScanner error: {e}", exc_info=True)
        endpoints = []

    # ============================================================
    # 2. XSS-сканирование
    # ============================================================
    try:
        xss_results = scanner.scan_xss_on_endpoints()
        for entry in xss_results:
            if entry.get("context") and entry.get("context") != "❌ Not reflected":
                save_reflected_response(entry)
    except Exception as e:
        log.error(f"[AutoReconV2] XSS scan error: {e}", exc_info=True)
        xss_results = []

    # ============================================================
    # 3. XSS-fuzzing (реальные payload’ы)
    # ============================================================
    try:
        fuzz_results = scanner.fuzz_xss_parameters(base_params or {}, method=method)
    except Exception as e:
        log.error(f"[AutoReconV2] XSS fuzzing error: {e}", exc_info=True)
        fuzz_results = []

    # ============================================================
    # 4. ThreatConnector (fail-safe)
    # ============================================================
    try:
        connector = ThreatConnector()

        try:
            connector.add_artifact("ENDPOINTS", target_url, endpoints)
        except Exception as e:
            log.error(f"[AutoReconV2] ThreatConnector ENDPOINTS error: {e}", exc_info=True)

        try:
            connector.add_artifact("XSS", target_url, xss_results)
        except Exception as e:
            log.error(f"[AutoReconV2] ThreatConnector XSS error: {e}", exc_info=True)

        try:
            connector.add_artifact("XSS_FUZZ", target_url, fuzz_results)
        except Exception as e:
            log.error(f"[AutoReconV2] ThreatConnector XSS_FUZZ error: {e}", exc_info=True)

        try:
            threat_report = connector.generate_report()
        except Exception as e:
            log.error(f"[AutoReconV2] ThreatConnector report error: {e}", exc_info=True)
            threat_report = {"error": str(e)}

    except Exception as e:
        log.error(f"[AutoReconV2] ThreatConnector fatal error: {e}", exc_info=True)
        threat_report = {"error": str(e)}

    # ============================================================
    # 5. Итоговый отчёт (fail-safe)
    # ============================================================
    return {
        "target": target_url,
        "endpoints": endpoints,
        "xss_results": xss_results,
        "fuzz_results": fuzz_results,
        "threat_report": threat_report,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run AutoRecon against an authorized URL.")
    parser.add_argument("target", help="URL in the configured authorized target scope")
    target = parser.parse_args().target
    results = {
        method: run_autorecon(
            target,
            base_params={"q": "test"},
            method=method,
        )
        for method in ("GET", "POST")
    }
    print(json.dumps(
        {
            method: result["threat_report"]
            for method, result in results.items()
        },
        ensure_ascii=False,
        indent=2,
    ))


__all__ = ["run_autorecon"]
