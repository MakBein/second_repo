# xss_security_gui/auto_recon/run_full_autorecon.py

"""
Полный AutoRecon-процесс:
1) Скан эндпоинтов
2) XSS-сканирование
3) XSS-fuzzing
4) Param Fuzzer
5) Backend-анализ (AutoReconAnalyzerV2)
6) ThreatConnector-агрегация
"""

from typing import Dict, Any, List

import json

from xss_security_gui.auto_recon.scanner import (
    EndpointScanner,
    save_reflected_response,
)
from xss_security_gui.auto_recon.analyzer import AutoReconAnalyzerV2
from xss_security_gui.threat_analysis.threat_connector import ThreatConnector
from xss_security_gui.param_fuzzer import fuzz_url_params


def _build_backend_responses(
    xss_results: List[Dict[str, Any]],
    fuzz_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Собирает HTTP-ответы из результатов XSS и fuzzing
    в формат, ожидаемый AutoReconAnalyzerV2.
    """
    responses: List[Dict[str, Any]] = []

    for r in xss_results + fuzz_results:
        full_response = r.get("full_response")
        if not full_response:
            continue

        responses.append({
            "url": r.get("url"),
            "text": full_response,
            "headers": r.get("headers", {}),
            "status": r.get("status", ""),
            "source": r.get("source", "scanner"),
        })

    return responses


def run_full_autorecon(
    target_url: str,
    base_params: Dict[str, Any] | None = None,
    method: str = "GET",
) -> Dict[str, Any]:
    """
    Запускает полный AutoRecon-процесс для одного URL.

    :param target_url: целевой URL
    :param base_params: базовые параметры для XSS-fuzzing
    :param method: HTTP-метод для fuzzing
    :return: финальный отчёт AutoRecon
    """
    print(f"[🔍] Starting AutoRecon for: {target_url}")

    pipeline_output: Dict[str, Any] = {}

    # --------------------------------------------------------
    # 1. Скан эндпоинтов
    # --------------------------------------------------------
    scanner = EndpointScanner(target_url)
    endpoints = scanner.scan()
    pipeline_output["endpoints"] = endpoints

    # --------------------------------------------------------
    # 2. Param Fuzzer
    # --------------------------------------------------------
    param_fuzz_results = fuzz_url_params(target_url, log_all=True)
    pipeline_output["param_fuzzer"] = param_fuzz_results

    # --------------------------------------------------------
    # 3. XSS-сканирование
    # --------------------------------------------------------
    xss_results = scanner.scan_xss_on_endpoints()
    pipeline_output["xss_results"] = xss_results

    for r in xss_results:
        if r.get("context") and r.get("context") != "❌ Not reflected":
            save_reflected_response(r)

    # --------------------------------------------------------
    # 4. XSS-fuzzing
    # --------------------------------------------------------
    fuzz_results = scanner.fuzz_xss_parameters(base_params or {}, method=method)
    pipeline_output["xss_fuzz"] = fuzz_results

    # --------------------------------------------------------
    # 5. ThreatConnector
    # --------------------------------------------------------
    connector = ThreatConnector()
    connector.add_artifact("XSS", target_url, xss_results)
    connector.add_artifact("XSS_FUZZ", target_url, fuzz_results)
    connector.add_artifact("PARAM_FUZZ", target_url, param_fuzz_results)

    # --------------------------------------------------------
    # 6. Подготовка HTTP-ответов для backend-анализа
    # --------------------------------------------------------
    backend_responses = _build_backend_responses(xss_results, fuzz_results)

    # --------------------------------------------------------
    # 7. Backend-анализ (AutoReconAnalyzerV2)
    # --------------------------------------------------------
    analyzer = AutoReconAnalyzerV2(connector)
    backend_report = analyzer.analyze(backend_responses)
    pipeline_output["backend_report"] = backend_report

    # --------------------------------------------------------
    # 8. Финальный отчёт
    # --------------------------------------------------------
    final_report: Dict[str, Any] = {
        "target": target_url,
        "endpoints": endpoints,
        "xss_results": xss_results,
        "fuzz_results": fuzz_results,
        "param_fuzzer": param_fuzz_results,
        "backend_report": backend_report,
        "pipeline": pipeline_output,
        "threat_summary": connector.summary(),
    }

    print("[✅] AutoRecon completed.")
    return final_report


if __name__ == "__main__":
    target = "https://gazprombank.ru/"
    result = run_full_autorecon(
        target,
        base_params={"search": "test"},
        method="GET",
    )
    print(json.dumps(result["threat_summary"], ensure_ascii=False, indent=2))