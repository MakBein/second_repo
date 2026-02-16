# xss_security_gui/auto_recon/run_full_autorecon.py

import json
from xss_security_gui.auto_recon.scanner import EndpointScanner, save_reflected_response
from xss_security_gui.auto_recon.analyzer import AutoReconAnalyzerV2
from xss_security_gui.threat_analysis.threat_connector import ThreatConnector
from xss_security_gui.param_fuzzer import fuzz_url_params


def run_full_autorecon(target_url: str, base_params=None, method="GET"):
    print(f"[🔍] Starting AutoRecon for: {target_url}")

    # === PIPELINE OUTPUT ===
    pipeline_output = {}

    # 1. Скан ендпоінтів
    scanner = EndpointScanner(target_url)
    endpoints = scanner.scan()
    pipeline_output["endpoints"] = endpoints

    # === PARAM FUZZER ===
    param_fuzz_results = fuzz_url_params(target_url, log_all=True)
    pipeline_output["param_fuzzer"] = param_fuzz_results

    # 2. XSS-сканування
    xss_results = scanner.scan_xss_on_endpoints()
    pipeline_output["xss_results"] = xss_results

    for r in xss_results:
        if r.get("context") and r.get("context") != "❌ Not reflected":
            save_reflected_response(r)

    # 3. XSS-fuzzing
    fuzz_results = scanner.fuzz_xss_parameters(base_params or {}, method=method)
    pipeline_output["xss_fuzz"] = fuzz_results

    # 4. ThreatConnector
    connector = ThreatConnector()
    connector.add_artifact("XSS", target_url, xss_results)
    connector.add_artifact("XSS_FUZZ", target_url, fuzz_results)
    connector.add_artifact("PARAM_FUZZ", target_url, param_fuzz_results)

    # 5. Збір HTTP-відповідей для бекенд-аналізу
    responses = []
    for r in xss_results + fuzz_results:
        if r.get("full_response"):
            responses.append({
                "url": r.get("url"),
                "text": r.get("full_response"),
                "headers": r.get("headers", {}),  # Якщо у тебе є реальні headers — вставляй
                "status": r.get("status", ""),
                "source": r.get("source", "scanner")
            })

    # 6. Запуск бекенд-аналізу
    analyzer = AutoReconAnalyzerV2(connector)
    backend_report = analyzer.analyze(responses)
    pipeline_output["backend_report"] = backend_report

    # 7. Підсумок
    final_report = {
        "target": target_url,
        "endpoints": endpoints,
        "xss_results": xss_results,
        "fuzz_results": fuzz_results,
        "backend_report": backend_report,
        "pipeline": pipeline_output,
        "threat_summary": connector.summary()
    }

    print("[✅] AutoRecon completed.")
    return final_report


if __name__ == "__main__":
    target = "https://gazprombank.ru/"
    result = run_full_autorecon(target, base_params={"search": "test"}, method="GET")
    print(json.dumps(result["threat_summary"], ensure_ascii=False, indent=2))