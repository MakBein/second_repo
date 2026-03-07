# xss_security_gui/param_fuzzer.py
# ============================================================
#  Param Fuzzer 5.0 (Enterprise-grade)
#  - Глубокий фуззинг URL‑параметров (GET)
#  - Расширенные сигнатуры XSS/инъекций/SSRF/LFI
#  - Риск‑скоринг и категоризация
#  - Интеграция с ThreatConnector (batched-style, но синхронно)
#  - Совместим с XSSAnalyzerApp.run_fuzzing (list[tuple])
# ============================================================

from __future__ import annotations

import copy
import logging
import os
import re
import html
from dataclasses import dataclass, asdict
from typing import List, Tuple, Optional, Dict, Iterable

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from xss_security_gui.settings import PARAM_FUZZ_LOG_PATH
from xss_security_gui.payloads import get_random_payload
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


# ============================================================
#  Логгер модуля (отдельный файл + формат)
# ============================================================

logger = logging.getLogger("ParamFuzzer")
if not logger.handlers:
    os.makedirs(os.path.dirname(PARAM_FUZZ_LOG_PATH), exist_ok=True)
    fh = logging.FileHandler(PARAM_FUZZ_LOG_PATH, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    logger.setLevel(logging.INFO)


# ============================================================
#  Сигнатуры и профили атак
# ============================================================

XSS_PATTERNS: Iterable[str] = [
    r"<script[^>]*?>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"onmouseover\s*=",
    r"onfocus\s*=",
    r"alert\s*\(",
    r"prompt\s*\(",
    r"confirm\s*\(",
    r"document\.cookie",
    r"document\.location",
    r"window\.location",
    r"\beval\s*\(",
    r"innerHTML\s*=",
]

INJECTION_PATTERNS: Iterable[str] = [
    r"UNION\s+SELECT",
    r"SELECT\s+.*\s+FROM",
    r"INSERT\s+INTO",
    r"UPDATE\s+.*\s+SET",
    r"DELETE\s+FROM",
    r"information_schema",
    r"xp_cmdshell",
    r"LOAD_FILE\s*\(",
]

LFI_SSRF_PATTERNS: Iterable[str] = [
    r"\.\./\.\./",
    r"/etc/passwd",
    r"file://",
    r"http://169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"aws_metadata",
    r"gopher://",
]


@dataclass
class ParamFuzzFinding:
    module: str
    param: str
    payload: str
    url: str
    status: Optional[int]
    detected: bool
    flags: Dict[str, bool]
    risk_score: int
    severity: str
    source: str = "AutoRecon.ParamFuzzer"

    def to_threat_result(self) -> Dict[str, any]:
        return {
            "severity": self.severity,
            "category": "param_fuzzer",
            "source": self.source,
            "param": self.param,
            "payload": self.payload,
            "url": self.url,
            "status": self.status,
            "detected": self.detected,
            "flags": self.flags,
            "risk_score": self.risk_score,
        }


def _analyze_response(text: str, payload: str) -> Dict[str, bool]:
    """
    Анализирует текст ответа на предмет потенциальной инъекции.
    Ничего не исполняет — только поиск по сигнатурам.
    """
    _ = html.escape(text)  # пример доп. обработки, если понадобится
    lowered = text.lower()

    flags = {
        "xss": False,
        "injection": False,
        "lfi_ssrf": False,
        "reflected": False,
    }

    for pattern in XSS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            flags["xss"] = True
            break

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            flags["injection"] = True
            break

    for pattern in LFI_SSRF_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            flags["lfi_ssrf"] = True
            break

    if payload and payload.lower() in lowered:
        flags["reflected"] = True

    return flags


def _calculate_risk_score(flags: Dict[str, bool]) -> int:
    """
    Простейший риск‑скоринг на основе флагов.
    """
    score = 0
    if flags.get("xss"):
        score += 5
    if flags.get("injection"):
        score += 5
    if flags.get("lfi_ssrf"):
        score += 4
    if flags.get("reflected"):
        score += 2
    return score


def _severity_from_score(score: int) -> str:
    if score >= 8:
        return "critical"
    if score >= 5:
        return "high"
    if score >= 3:
        return "medium"
    if score >= 1:
        return "low"
    return "info"


# ============================================================
#  Основная функция фуззинга (совместима с analyzer.py)
# ============================================================

def fuzz_url_params(
    url: str,
    payload: Optional[str] = None,
    category: str = "Reflected",
    log_all: bool = False,
    timeout: int = 4,
    max_retries: int = 3,
) -> List[Tuple[str, str, str]]:
    """
    Фуззинг URL‑параметров с расширенной детекцией и интеграцией ThreatConnector.

    Args:
        url: целевой URL
        payload: кастомный payload (если None — берётся из PAYLOADS по категории)
        category: категория payload’а (например, "Reflected", "Stored", "DOM")
        log_all: логировать все запросы, даже без детекции
        timeout: таймаут HTTP‑запроса
        max_retries: количество повторов при ошибках сети

    Returns:
        list[tuple]: список найденных потенциальных уязвимостей в формате
                     (param_name, payload, test_url)

    Совместимость:
        XSSAnalyzerApp.run_fuzzing ожидает именно такой формат.
    """

    if not url or not isinstance(url, str):
        raise ValueError("Invalid URL provided")

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    findings_for_gui: List[Tuple[str, str, str]] = []
    artifacts_for_threat: List[ParamFuzzFinding] = []

    if not params:
        logger.warning(f"No parameters found in URL: {url}")
        return findings_for_gui

    logger.info(f"Starting parameter fuzzing for URL: {url}")
    logger.info(f"Parameters detected: {list(params.keys())}")

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Security Scanner)",
            "X-Fuzzing-Scanner": "URLParamFuzzer/5.0",
        }
    )

    for key in params:
        for attempt in range(max_retries):
            try:
                test_params = copy.deepcopy(params)
                test_payload = str(payload or get_random_payload(category))
                test_params[key] = [test_payload]

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                r = session.get(
                    test_url,
                    timeout=timeout,
                    allow_redirects=False,
                )

                flags = _analyze_response(r.text, test_payload)
                risk_score = _calculate_risk_score(flags)
                severity = _severity_from_score(risk_score)
                detected = risk_score > 0

                if detected:
                    logger.critical(
                        "Potential issue detected | "
                        f"param='{key}' | url='{test_url}' | payload='{test_payload}' | "
                        f"status={r.status_code} | flags={flags} | score={risk_score}"
                    )
                elif log_all:
                    logger.info(
                        "No reflection detected | "
                        f"param='{key}' | url='{test_url}' | status={r.status_code}"
                    )

                finding = ParamFuzzFinding(
                    module="ParamFuzzer",
                    param=key,
                    payload=test_payload,
                    url=test_url,
                    status=r.status_code,
                    detected=detected,
                    flags=flags,
                    risk_score=risk_score,
                    severity=severity,
                )
                artifacts_for_threat.append(finding)

                if detected:
                    findings_for_gui.append((key, test_payload, test_url))

                # успешный запрос — выходим из цикла попыток
                break

            except Exception as e:
                logger.error(
                    f"Request error for param '{key}' "
                    f"(attempt {attempt + 1}/{max_retries}): {e}"
                )
                if attempt == max_retries - 1:
                    err_finding = ParamFuzzFinding(
                        module="ParamFuzzer (error)",
                        param=key,
                        payload="",
                        url=url,
                        status=None,
                        detected=False,
                        flags={"error": True},
                        risk_score=0,
                        severity="error",
                    )
                    artifacts_for_threat.append(err_finding)

    # ========================================================
    #  Интеграция с ThreatConnector (batched‑style)
    # ========================================================
    try:
        if artifacts_for_threat:
            # группируем по целевому URL (target)
            by_target: Dict[str, List[Dict[str, any]]] = {}
            for f in artifacts_for_threat:
                by_target.setdefault(f.url, []).append(f.to_threat_result())

            for target, results in by_target.items():
                THREAT_CONNECTOR.bulk(
                    module="ParamFuzzer",
                    target=target,
                    results=results,
                )
    except Exception:
        logger.warning("Failed to send artifacts to ThreatConnector", exc_info=True)

    logger.info(
        "Fuzzing completed. Detected: "
        f"{len(findings_for_gui)} interesting issues (reflections/injections)."
    )

    return findings_for_gui