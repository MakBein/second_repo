# xss_security_gui/auto_recon/recon_pipeline.py

import os
import json
import logging
import re
from typing import List, Dict, Any
import urllib.parse

import requests
from bs4 import BeautifulSoup
from xss_security_gui.auto_recon.scanner import scan_multiple
from xss_security_gui.auto_recon.analyzer import AutoReconAnalyzerV2
from xss_security_gui.auto_recon.planner import AttackPlannerV2, build_attack_plan
from xss_security_gui.auto_recon.payloads import PayloadGenerator
from xss_security_gui.auto_recon.token_extractor import (
    extract_tokens,
    analyze_tokens,
    save_token_log,
)

from xss_security_gui.threat_analysis.threat_connector import ThreatConnector
from xss_security_gui import DIRS


# ---------------------------------------------------------
# ЛОГГЕР
# ---------------------------------------------------------
os.makedirs(DIRS["logs"], exist_ok=True)

logging.basicConfig(
    filename=os.path.join(DIRS["logs"], "recon_pipeline.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ---------------------------------------------------------
# Загрузка конфигурации
# ---------------------------------------------------------
def load_recon_config(path: str = "presets.json") -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"error": "config_not_found"}

# ---------------------------------------------------------
# ADVANCED ATTACK METHODS (Reflected XSS Scanner)
# ---------------------------------------------------------

class AdvancedAttackMethods:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()

    # -----------------------------------------------------
    # MAIN METHOD: Full reflected XSS scan
    # -----------------------------------------------------
    def xss_reflected_scan(self, payload_list: List[str]) -> List[Dict[str, Any]]:
        results = []

        for payload in payload_list:
            # GET tests
            results.extend(self._test_get_parameter(payload))

            # POST tests
            results.extend(self._test_post_parameter(payload))

        return results

    # -----------------------------------------------------
    # GET parameter XSS test
    # -----------------------------------------------------
    def _test_get_parameter(self, payload: str) -> List[Dict[str, Any]]:
        results = []

        try:
            parsed_url = urllib.parse.urlparse(self.base_url)
            params = urllib.parse.parse_qs(parsed_url.query)

            for param_name in params:
                original_value = params[param_name][0]

                test_url = self.base_url.replace(
                    f"{param_name}={original_value}",
                    f"{param_name}={urllib.parse.quote(payload)}"
                )

                response = self.session.get(test_url)

                if self._check_xss_trigger(response.text, payload):
                    results.append({
                        "type": "GET Reflected XSS",
                        "parameter": param_name,
                        "payload": payload,
                        "url": test_url,
                        "vulnerable": True
                    })

        except Exception as e:
            logging.error(f"GET XSS Test Error: {e}")

        return results

    # -----------------------------------------------------
    # POST parameter XSS test
    # -----------------------------------------------------
    def _test_post_parameter(self, payload: str) -> List[Dict[str, Any]]:
        results = []

        try:
            test_fields = ["username", "email", "comment", "search"]

            for field in test_fields:
                post_data = {field: payload}
                response = self.session.post(self.base_url, data=post_data)

                if self._check_xss_trigger(response.text, payload):
                    results.append({
                        "type": "POST Reflected XSS",
                        "parameter": field,
                        "payload": payload,
                        "url": self.base_url,
                        "vulnerable": True
                    })

        except Exception as e:
            logging.error(f"POST XSS Test Error: {e}")

        return results

    # -----------------------------------------------------
    # XSS trigger detection
    # -----------------------------------------------------
    def _check_xss_trigger(self, response_text: str, payload: str) -> bool:
        triggers = [
            re.escape(payload),
            urllib.parse.unquote(payload),
            BeautifulSoup(payload, "html.parser").get_text()
        ]

        for t in triggers:
            if t in response_text:
                return True

        return False

# ---------------------------------------------------------
# Анализ HTML (локальный)
# ---------------------------------------------------------
def run_recon_from_html(html: str, url: str, headers: dict) -> dict:
    logging.info("🔍 Запуск анализа HTML")

    connector = ThreatConnector()
    analyzer = AutoReconAnalyzerV2(connector)

    response = [{
        "url": url,
        "text": html,
        "headers": headers,
        "status": 200,
        "source": "manual_html"
    }]

    return analyzer.analyze(response)


# ---------------------------------------------------------
# Анализ токенов
# ---------------------------------------------------------
def run_target_analysis(headers, html, save_json=True):
    try:
        logging.info("🚀 Запуск анализа токенов")

        tokens = extract_tokens(headers, html)
        analyzed = analyze_tokens(tokens)

        save_token_log(analyzed)

        if save_json:
            path = os.path.join(DIRS["logs"], "token_analysis.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(analyzed, f, indent=4, ensure_ascii=False)

        return analyzed

    except Exception as e:
        logging.error(f"❌ Ошибка при анализе цели: {e}", exc_info=True)
        return []


# ---------------------------------------------------------
# ПОЛНЫЙ AutoRecon-процесс + AdvancedAttackMethods
# ---------------------------------------------------------
def run_full_recon(urls: List[str]) -> Dict[str, Any]:
    logging.info("🚀 Запуск полного AutoRecon")

    # 1. Сканирование
    responses = scan_multiple(urls)

    # 2. Генерация payloads
    endpoints = [
        {"url": r["url"], "method": "GET", "params": ["test"], "source": "scanner"}
        for r in responses
    ]
    payloads = PayloadGenerator(endpoints).generate()

    # 3. План атаки
    plan = build_attack_plan(endpoints, payloads)

    # 4. Выполнение атак
    connector = ThreatConnector()
    planner = AttackPlannerV2(payloads, threat_connector=connector)
    attack_results = planner.execute()

    # 5. Анализ
    analyzer = AutoReconAnalyzerV2(connector)
    analysis_results = analyzer.analyze(responses)

    # 6. AdvancedAttackMethods (Reflected XSS)
    xss_results = []
    try:
        # Берём первый URL как базовый
        base_url = urls[0]
        adv = AdvancedAttackMethods(base_url)

        # Передаём список payload-строк
        payload_strings = [p["url"] for p in payloads]

        xss_results = adv.xss_reflected_scan(payload_strings)

        # Добавляем в ThreatConnector
        if xss_results:
            connector.add_artifact("XSS_REFLECTED", base_url, xss_results)

    except Exception as e:
        logging.error(f"❌ Ошибка AdvancedAttackMethods: {e}")

    # 7. Итоговый отчёт
    report = {
        "scan": responses,
        "attack": attack_results,
        "analysis": analysis_results,
        "xss_reflected": xss_results,
        "threat_summary": connector.summary()
    }

    save_recon_report(report)

    return report


def run_advanced_xss_recon(urls: List[str], aggressive: bool = False) -> Dict[str, Any]:
    """
    Enhanced XSS reconnaissance with optional aggressive mode.

    Args:
        urls (List[str]): Target URLs to scan.
        aggressive (bool): Enable more invasive scanning techniques.

    Returns:
        Dict[str, Any]: Comprehensive attack reconnaissance report.
    """
    logging.info(
        f"🚀 Запуск расширенного XSS-сканирования "
        f"(Агрессивный режим: {aggressive})"
    )

    # ---------------------------------------------------------
    # 1. Basic scanning
    # ---------------------------------------------------------
    responses = scan_multiple(urls)

    # ---------------------------------------------------------
    # 2. Enhanced payload generation
    # ---------------------------------------------------------
    endpoints = [
        {
            "url": r["url"],
            "method": "GET",
            "params": ["test"],
            "source": "scanner"
        }
        for r in responses
    ]

    payload_generator = PayloadGenerator(endpoints)
    payloads = payload_generator.generate(aggressive_mode=aggressive)

    # ---------------------------------------------------------
    # 3. Advanced attack planning
    # ---------------------------------------------------------
    plan = build_attack_plan(endpoints, payloads)

    # ---------------------------------------------------------
    # 4. Threat connector with enhanced detection
    # ---------------------------------------------------------
    connector = ThreatConnector(
        sensitivity_level="high" if aggressive else "medium"
    )

    # ---------------------------------------------------------
    # 5. Advanced attack execution
    # ---------------------------------------------------------
    planner = AttackPlannerV2(
        payloads,
        threat_connector=connector,
        aggressive_mode=aggressive
    )
    attack_results = planner.execute()

    # ---------------------------------------------------------
    # 6. Comprehensive analysis
    # ---------------------------------------------------------
    analyzer = AutoReconAnalyzerV2(connector)
    analysis_results = analyzer.analyze(
        responses,
        deep_scan=aggressive
    )

    # ---------------------------------------------------------
    # 7. Detailed report generation
    # ---------------------------------------------------------
    report = {
        "scan_mode": "aggressive" if aggressive else "standard",
        "scan": responses,
        "attack": attack_results,
        "analysis": analysis_results,
        "threat_summary": connector.summary(),
        "potential_vulnerabilities": connector.get_vulnerabilities()
    }

    save_recon_report(
        report,
        filename=f"advanced_recon_{'aggressive' if aggressive else 'standard'}.json"
    )

    return report

# ---------------------------------------------------------
# Сохранение отчёта
# ---------------------------------------------------------
def save_recon_report(report: dict, filename: str = "full_recon_report.json"):
    path = os.path.join(DIRS["logs"], filename)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logging.info(f"📁 Отчёт сохранён: {path}")
    except Exception as e:
        logging.error(f"❌ Ошибка сохранения отчёта: {e}")

# ---------------------------------------------------------
# Універсальний фасад AutoRecon
# ---------------------------------------------------------
def run_recon_pipeline(target) -> Dict[str, Any]:
    """
    Універсальний метод запуску AutoRecon.
    Приймає:
        • один URL (str)
        • список URL (list)
    Повертає повний звіт AutoRecon.
    """

    logging.info("🚀 Запуск run_recon_pipeline")

    # Якщо передано один URL — робимо список
    if isinstance(target, str):
        urls = [target]
    elif isinstance(target, list):
        urls = target
    else:
        raise ValueError("run_recon_pipeline: target має бути str або list[str]")

    # Виконуємо повний AutoRecon
    return run_full_recon(urls)