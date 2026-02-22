# xss_security_gui/auto_recon/autorecon_v2.py

"""
AutoRecon V2 — полный автоматизированный пайплайн разведки:
1) Сканирование эндпоинтов
2) XSS-сканирование
3) XSS-fuzzing
4) ThreatConnector (агрегация артефактов)
5) Генерация итогового отчёта
"""

from typing import Dict, Any, List
import json

from xss_security_gui.auto_recon.scanner import (
    EndpointScanner,
    save_reflected_response,
)
from xss_security_gui.threat_analysis.threat_connector import ThreatConnector


def run_autorecon(
    target_url: str,
    base_params: Dict[str, Any] | None = None,
    method: str = "GET",
) -> Dict[str, Any]:
    """
    Запускает полный AutoRecon-процесс.

    :param target_url: URL цели
    :param base_params: параметры для XSS-fuzzing
    :param method: HTTP-метод для fuzzing
    :return: словарь с результатами всех этапов
    """

    # ------------------------------------------------------------
    # 1. Сканирование эндпоинтов
    # ------------------------------------------------------------
    scanner = EndpointScanner(target_url)
    endpoints = scanner.scan()

    # ------------------------------------------------------------
    # 2. XSS-сканирование
    # ------------------------------------------------------------
    xss_results = scanner.scan_xss_on_endpoints()

    # Логируем отражённые XSS
    for entry in xss_results:
        if entry.get("context") and entry.get("context") != "❌ Not reflected":
            save_reflected_response(entry)

    # ------------------------------------------------------------
    # 3. XSS-fuzzing
    # ------------------------------------------------------------
    fuzz_results = scanner.fuzz_xss_parameters(
        base_params or {},
        method=method,
    )

    # ------------------------------------------------------------
    # 4. ThreatConnector — агрегация артефактов
    # ------------------------------------------------------------
    connector = ThreatConnector()

    connector.add_artifact("XSS", target_url, xss_results)
    connector.add_artifact("XSS_FUZZ", target_url, fuzz_results)
    connector.add_artifact("ENDPOINTS", target_url, endpoints)

    # ------------------------------------------------------------
    # 5. Итоговый отчёт
    # ------------------------------------------------------------
    threat_report = connector.generate_report()

    return {
        "target": target_url,
        "endpoints": endpoints,
        "xss_results": xss_results,
        "fuzz_results": fuzz_results,
        "threat_report": threat_report,
    }


if __name__ == "__main__":
    target = "https://gazprombank.ru/"
    result = run_autorecon(
        target,
        base_params={"q": "test"},
        method="GET",
    )
    print(json.dumps(result["threat_report"], ensure_ascii=False, indent=2))


__all__ = [
    "run_autorecon",
]
