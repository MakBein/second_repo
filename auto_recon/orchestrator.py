# xss_security_gui/auto_recon/orchestrator.py
"""
Orchestrator — главный оркестратор AutoRecon Enterprise V7.
Сценарии:
• Инициализация и управление скан-операциями
• Динамическое использование компонентов (scanner, analyzer, reporter)
• Управление логированием и метриками на уровне операции
• Интеграция с user_tracker и metrics
"""

import json
import logging
import time
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from urllib.parse import urljoin

from xss_security_gui.auto_recon.core_logger import get_logger, LogLevel
from xss_security_gui.auto_recon.user_tracker import get_user_tracker, get_user_context
from xss_security_gui.auto_recon.metrics import get_metrics_collector
from xss_security_gui.auto_recon.reporting import get_report_generator

from xss_security_gui.auto_recon.scanner import EndpointScanner, save_reflected_response
from xss_security_gui.auto_recon.analyzer import AutoReconAnalyzerV2
from xss_security_gui.auto_recon.planner import AttackPlannerV2, build_attack_plan
from xss_security_gui.auto_recon.payloads import PayloadGenerator, generate_xss_payloads

from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
from xss_security_gui.settings import LOG_DIR


class AutoReconOrchestrator:
    """
    Enterprise-level оркестратор для AutoRecon.
    Управляет всеми компонентами: сканирование, анализ, атаки, логирование, метрики, отчёты.
    """

    def __init__(
        self,
        target_urls: List[str],
        config: Optional[Dict[str, Any]] = None,
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.target_urls = target_urls
        self.config = config or self._default_config()
        self.callback = callback

        # Компоненты
        self.logger = get_logger("AutoReconOrchestrator")
        self.user_tracker = get_user_tracker()
        self.metrics_collector = get_metrics_collector()
        self.reporter = get_report_generator()

        # Результаты
        self.scan_results: List[Dict[str, Any]] = []
        self.analysis_results: Dict[str, Any] = {}
        self.attack_results: List[Dict[str, Any]] = []
        self.final_report: Dict[str, Any] = {}

        # Мониторинг
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

    @staticmethod
    def _default_config() -> Dict[str, Any]:
        """Конфигурация по умолчанию."""
        return {
            "aggressive": False,
            "max_workers": 5,
            "timeout": 10,
            "save_report": True,
            "export_html": True,
            "export_json": True,
            "include_xss_advanced": True,
            "include_sqli": True,
            "include_csrf": True,
            "include_ssrf": True,
            "include_dom_xss": True,
            "max_payloads": 50,
        }

    def _report_progress(self, stage: str, status: str, details: Optional[Dict[str, Any]] = None):
        """Отправляет обновление прогресса через callback."""
        if self.callback:
            try:
                message = {
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "stage": stage,
                    "status": status,
                    "details": details or {},
                }
                self.callback(message)
            except Exception as e:
                self.logger.error(f"Progress callback error: {e}")

    def run(self) -> Dict[str, Any]:
        """
        Запускает полный процесс AutoRecon.
        Возвращает итоговый отчёт.
        """
        self.start_time = time.time()
        user_ctx = self.user_context_dict

        self.logger.info(
            "🚀 AutoRecon Started",
            tags={"stage": "initialization"},
            user_id=user_ctx["user_id"],
        )

        self.user_tracker.track_operation(
            "autorecon_full_scan",
            details={"targets": self.target_urls, "config": self.config},
            target=", ".join(self.target_urls),
            status="started",
        )

        try:
            # 1. Сканирование
            self._report_progress("SCANNING", "starting")
            self.scan_results = self._run_scan_stage()

            # 2. Анализ
            self._report_progress("ANALYZING", "starting")
            self.analysis_results = self._run_analysis_stage()

            # 3. Атаки
            self._report_progress("ATTACKING", "starting")
            self.attack_results = self._run_attack_stage()

            # 4. Генерация отчёта
            self._report_progress("REPORTING", "starting")
            self.final_report = self._generate_final_report()

            self.end_time = time.time()

            self.logger.success(
                "✅ AutoRecon Complete",
                tags={"stage": "completion"},
                user_id=user_ctx["user_id"],
                duration_seconds=self.end_time - self.start_time,
            )

            self.user_tracker.track_operation(
                "autorecon_full_scan",
                details={
                    "scan_results": len(self.scan_results),
                    "vulnerabilities": sum(1 for r in self.scan_results if r.get("vulnerable")),
                    "errors": sum(1 for r in self.scan_results if "error" in r),
                },
                target=", ".join(self.target_urls),
                status="success",
            )

            return self.final_report

        except Exception as e:
            self.end_time = time.time()
            self.logger.error(
                f"❌ AutoRecon Error: {e}",
                tags={"stage": "error"},
                user_id=user_ctx["user_id"],
                exception_type=type(e).__name__,
            )

            self.user_tracker.track_error(
                error_type=type(e).__name__,
                message=str(e),
                operation="autorecon_full_scan",
                target=", ".join(self.target_urls),
            )

            return {
                "error": str(e),
                "status": "failed",
                "duration_seconds": self.end_time - self.start_time,
            }

    def _run_scan_stage(self) -> List[Dict[str, Any]]:
        """Этап 1: Сканирование эндпоинтов."""
        op_id = self.metrics_collector.start_operation("scan_endpoints", {"targets": self.target_urls})

        try:
            all_results = []

            for target_url in self.target_urls:
                self._report_progress("SCANNING", f"scanning_{target_url}")

                scanner = EndpointScanner(target_url, gui_callback=self._report_progress)

                # Сканирование эндпоинтов
                endpoints = scanner.scan()
                self.logger.info(
                    f"📍 Endpoints scanned: {len(endpoints)}",
                    tags={"target": target_url, "count": len(endpoints)},
                )

                # XSS-тестирование
                xss_results = scanner.scan_xss_on_endpoints()
                for entry in xss_results:
                    if entry.get("context") and entry.get("context") != "❌ Not reflected":
                        save_reflected_response(entry)
                        self.user_tracker.track_vulnerability_found(
                            vuln_type="XSS",
                            url=entry.get("url", target_url),
                            severity="high",
                            payload=entry.get("payload"),
                            details={"context": entry.get("context")},
                        )

                # Fuzzing
                fuzz_results = scanner.fuzz_xss_parameters({"q": "test"}, method="GET")

                all_results.extend(endpoints)
                all_results.extend(xss_results)
                all_results.extend(fuzz_results)

            items_processed = len(all_results)
            self.metrics_collector.finish_operation(op_id, success=True, items_processed=items_processed)

            self._report_progress("SCANNING", "complete", {"items": items_processed})

            return all_results

        except Exception as e:
            self.metrics_collector.finish_operation(op_id, success=False)
            self.logger.error(f"Scan stage error: {e}")
            raise

    def _run_analysis_stage(self) -> Dict[str, Any]:
        """Этап 2: Анализ результатов."""
        op_id = self.metrics_collector.start_operation("analyze_results", {"methods": ["XSS", "SQLi", "CSRF", "SSRF"]})

        try:
            analyzer = AutoReconAnalyzerV2(THREAT_CONNECTOR)

            # Подготовка входных данных
            responses = [
                {
                    "url": r.get("url", ""),
                    "text": r.get("full_response", ""),
                    "headers": r.get("response_headers", {}),
                    "status": r.get("status", 0),
                }
                for r in self.scan_results
                if "url" in r
            ]

            # Анализ
            results = analyzer.analyze(responses)

            self.logger.info(
                "📊 Analysis complete",
                tags={
                    "xss_findings": len(results.get("xss", [])),
                    "sqli_findings": len(results.get("sqli", [])),
                    "csrf_findings": len(results.get("csrf", [])),
                },
            )

            self.metrics_collector.finish_operation(op_id, success=True, items_processed=len(responses))

            self._report_progress("ANALYZING", "complete", {"analysis_modules": len(results)})

            return results

        except Exception as e:
            self.metrics_collector.finish_operation(op_id, success=False)
            self.logger.error(f"Analysis stage error: {e}")
            return {}

    def _run_attack_stage(self) -> List[Dict[str, Any]]:
        """Этап 3: Выполнение атак."""
        op_id = self.metrics_collector.start_operation("execute_attacks", {"max_workers": self.config["max_workers"]})

        try:
            # Генерация payload'ов
            endpoints = [
                {
                    "url": r.get("url", self.target_urls[0]),
                    "method": r.get("method", "GET"),
                    "params": r.get("params", {}),
                }
                for r in self.scan_results[:20]  # Limit to prevent explosion
            ]

            payload_gen = PayloadGenerator(endpoints, use_mutation=True)
            payloads = payload_gen.generate()[:self.config["max_payloads"]]

            # Атаки
            plan = build_attack_plan(endpoints, payloads)
            planner = AttackPlannerV2(
                payloads,
                threat_connector=THREAT_CONNECTOR,
                max_workers=self.config["max_workers"],
                timeout=self.config["timeout"],
            )

            attack_results = planner.execute()

            self.logger.info(
                "⚔️ Attack phase complete",
                tags={"payloads": len(payloads), "results": len(attack_results)},
            )

            self.metrics_collector.finish_operation(op_id, success=True, items_processed=len(payloads))

            self._report_progress("ATTACKING", "complete", {"results": len(attack_results)})

            return attack_results

        except Exception as e:
            self.metrics_collector.finish_operation(op_id, success=False)
            self.logger.error(f"Attack stage error: {e}")
            return []

    def _generate_final_report(self) -> Dict[str, Any]:
        """Этап 4: Генерация итогового отчёта."""
        # Подготовка данных
        vulnerabilities = [
            r for r in self.scan_results
            if r.get("vulnerable") or (r.get("context") and r.get("context") != "❌ Not reflected")
        ]

        # Генерация отчётов
        scan_report = self.reporter.generate_scan_report(
            self.scan_results,
            scan_name="AutoRecon Full Scan",
            targets=self.target_urls,
        )

        vulnerability_report = self.reporter.generate_vulnerability_report(
            vulnerabilities,
            target=", ".join(self.target_urls),
        )

        detailed_analysis = self.reporter.generate_detailed_analysis(
            self.scan_results,
            self.analysis_results,
            user_context=self.user_context_dict,
        )

        final_report = {
            "metadata": {
                "report_type": "full_autorecon_report",
                "generated_at": datetime.datetime.utcnow().isoformat(),
                "targets": self.target_urls,
                "duration_seconds": (self.end_time - self.start_time) if self.end_time and self.start_time else 0,
                "user": self.user_context_dict,
            },
            "scan_report": scan_report,
            "vulnerability_report": vulnerability_report,
            "detailed_analysis": detailed_analysis,
            "threat_summary": THREAT_CONNECTOR.summary(),
            "metrics": self.metrics_collector.get_summary(),
        }

        # Сохранение отчётов
        if self.config.get("save_report"):
            json_path = self.reporter.save_report(final_report)
            self.logger.info(f"📄 Report saved: {json_path}")

            if self.config.get("export_html"):
                html_path = self.reporter.generate_html_report(final_report)
                self.logger.info(f"📄 HTML Report saved: {html_path}")

        return final_report

    @property
    def user_context_dict(self) -> Dict[str, Any]:
        """Возвращает словарь контекста пользователя."""
        ctx = get_user_context()
        return {
            "user_id": ctx.user_id,
            "hostname": ctx.hostname,
            "ip_address": ctx.ip_address,
            "session_id": ctx.session_id,
        }


# API функции
def run_full_autorecon(
    targets: List[str] | str,
    config: Optional[Dict[str, Any]] = None,
    callback: Optional[Callable] = None,
) -> Dict[str, Any]:
    """
    Запускает полный процесс AutoRecon.

    Args:
        targets: список URL или один URL
        config: конфигурация сканирования
        callback: callback для прогресса

    Returns:
        Итоговый отчёт
    """
    if isinstance(targets, str):
        targets = [targets]

    orchestrator = AutoReconOrchestrator(targets, config, callback)
    return orchestrator.run()


def run_aggressive_scan(targets: List[str] | str, callback: Optional[Callable] = None) -> Dict[str, Any]:
    """Запускает агрессивное сканирование."""
    config = AutoReconOrchestrator._default_config()
    config["aggressive"] = True
    config["max_workers"] = 10
    config["max_payloads"] = 100

    return run_full_autorecon(targets, config, callback)


__all__ = [
    "AutoReconOrchestrator",
    "run_full_autorecon",
    "run_aggressive_scan",
]

