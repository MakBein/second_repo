# xss_security_gui/auto_recon/recon_pipeline.py

"""
Recon Pipeline 6.0
Полный стек:
• Basic & Advanced Recon
• Reflected XSS Scanner
• AutoRecon Analyzer
• ThreatConnector Integration
• Attack Planning & Execution
"""

import os
import json
import logging
import re
import urllib.parse
from typing import List, Dict, Any

import requests
from bs4 import BeautifulSoup

from xss_security_gui.auto_recon.scanner import scan_multiple
from xss_security_gui.auto_recon.analyzer import AutoReconAnalyzerV2
from xss_security_gui.auto_recon.planner import AttackPlannerV2, build_attack_plan
from xss_security_gui.auto_recon.payloads import (
    PayloadGenerator,
    generate_xss_payloads,
)
from xss_security_gui.auto_recon.token_extractor import (
    extract_tokens,
    analyze_tokens,
    save_token_log,
)

from xss_security_gui.threat_analysis.threat_connector import ThreatConnector
from xss_security_gui import DIRS


# ============================================================
#  ЛОГГЕР
# ============================================================

os.makedirs(DIRS["logs"], exist_ok=True)

logging.basicConfig(
    filename=os.path.join(DIRS["logs"], "recon_pipeline.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


# ============================================================
#  Загрузка конфигурации
# ============================================================

def load_recon_config(path: str = "presets.json") -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"error": "config_not_found"}


# ============================================================
#  AdvancedAttackMethods — Reflected XSS
# ============================================================

class AdvancedAttackMethods:
    """Расширенный Reflected XSS сканер."""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()

    # --------------------------------------------------------

    def xss_reflected_scan(self, payload_list: List[str]) -> List[Dict[str, Any]]:
        results = []
        for payload in payload_list:
            results.extend(self._test_get_parameter(payload))
            results.extend(self._test_post_parameter(payload))
        return results

    # --------------------------------------------------------

    def _test_get_parameter(self, payload: str) -> List[Dict[str, Any]]:
        results = []
        try:
            parsed = urllib.parse.urlparse(self.base_url)
            params = urllib.parse.parse_qs(parsed.query)

            for name, values in params.items():
                original = values[0]
                test_url = self.base_url.replace(
                    f"{name}={original}",
                    f"{name}={urllib.parse.quote(payload)}"
                )

                r = self.session.get(test_url)

                if self._check_xss_trigger(r.text, payload):
                    results.append({
                        "type": "GET Reflected XSS",
                        "parameter": name,
                        "payload": payload,
                        "url": test_url,
                        "vulnerable": True,
                    })

        except Exception as e:
            logging.error(f"GET XSS Test Error: {e}", exc_info=True)

        return results

    # --------------------------------------------------------

    def _test_post_parameter(self, payload: str) -> List[Dict[str, Any]]:
        results = []
        try:
            fields = ["username", "email", "comment", "search"]

            for field in fields:
                r = self.session.post(self.base_url, data={field: payload})

                if self._check_xss_trigger(r.text, payload):
                    results.append({
                        "type": "POST Reflected XSS",
                        "parameter": field,
                        "payload": payload,
                        "url": self.base_url,
                        "vulnerable": True,
                    })

        except Exception as e:
            logging.error(f"POST XSS Test Error: {e}", exc_info=True)

        return results

    # --------------------------------------------------------

    def _check_xss_trigger(self, text: str, payload: str) -> bool:
        triggers = [
            re.escape(payload),
            urllib.parse.unquote(payload),
            BeautifulSoup(payload, "html.parser").get_text(),
        ]
        return any(t and t in text for t in triggers)


# ============================================================
#  Анализ HTML
# ============================================================

def run_recon_from_html(html: str, url: str, headers: dict) -> dict:
    connector = ThreatConnector()
    analyzer = AutoReconAnalyzerV2(connector)

    response = [{
        "url": url,
        "text": html,
        "headers": headers,
        "status": 200,
        "source": "manual_html",
    }]

    return analyzer.analyze(response)


# ============================================================
#  Анализ токенов
# ============================================================

def run_target_analysis(headers: dict, html: str, save_json_file: bool = True):
    try:
        tokens = extract_tokens(headers, html)
        analyzed = analyze_tokens(tokens)
        save_token_log(analyzed)

        if save_json_file:
            path = os.path.join(DIRS["logs"], "token_analysis.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(analyzed, f, indent=4, ensure_ascii=False)

        return analyzed

    except Exception as e:
        logging.error(f"Token analysis error: {e}", exc_info=True)
        return []


# ============================================================
#  Сохранение отчёта
# ============================================================

def save_recon_report(report: dict, filename: str = "full_recon_report.json"):
    path = os.path.join(DIRS["logs"], filename)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logging.info(f"📁 Отчёт сохранён: {path}")
    except Exception as e:
        logging.error(f"❌ Ошибка сохранения отчёта: {e}")


# ============================================================
#  Полный AutoRecon-процесс
# ============================================================

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

    # 6. Reflected XSS
    xss_results = []
    try:
        base_url = urls[0]
        adv = AdvancedAttackMethods(base_url)
        xss_results = adv.xss_reflected_scan(generate_xss_payloads())

        if xss_results:
            connector.add_artifact("XSS_REFLECTED", base_url, xss_results)

    except Exception as e:
        logging.error(f"AdvancedAttackMethods error: {e}", exc_info=True)

    # 7. Итоговый отчёт
    report = {
        "scan": responses,
        "attack": attack_results,
        "analysis": analysis_results,
        "xss_reflected": xss_results,
        "attack_plan": plan,
        "threat_summary": connector.summary(),
    }

    save_recon_report(report)
    return report


# ============================================================
#  Advanced Recon (твоя новая часть)
# ============================================================

def run_advanced_recon(urls: List[str], aggressive: bool = False) -> Dict[str, Any]:
    logging.info(f"🚀 Запуск Advanced Recon (aggressive={aggressive})")

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

    # 4. ThreatConnector с уровнем чувствительности
    connector = ThreatConnector(
        sensitivity_level="high" if aggressive else "medium"
    )

    # 5. Выполнение атак
    planner = AttackPlannerV2(payloads, threat_connector=connector)
    attack_results = planner.execute()

    # 6. Анализ
    analyzer = AutoReconAnalyzerV2(connector)
    analysis_results = analyzer.analyze(responses)

    # 7. Итоговый отчёт
    report = {
        "scan_mode": "aggressive" if aggressive else "standard",
        "scan": responses,
        "attack": attack_results,
        "analysis": analysis_results,
        "threat_summary": connector.summary(),
    }

    save_recon_report(
        report,
        filename=f"advanced_recon_{'aggressive' if aggressive else 'standard'}.json"
    )

    return report


# ============================================================
#  Универсальный фасад AutoRecon
# ============================================================

def run_recon_pipeline(target) -> Dict[str, Any]:
    """
    Универсальный метод запуска AutoRecon.
    Принимает:
        • один URL (str)
        • список URL (list[str])
    """
    logging.info("🚀 Запуск run_recon_pipeline")

    if isinstance(target, str):
        urls = [target]
    elif isinstance(target, list):
        urls = target
    else:
        raise ValueError("run_recon_pipeline: target должен быть str или list[str]")

    return run_full_recon(urls)


__all__ = [
    "load_recon_config",
    "AdvancedAttackMethods",
    "run_recon_from_html",
    "run_target_analysis",
    "save_recon_report",
    "run_full_recon",
    "run_advanced_recon",
    "run_recon_pipeline",
]