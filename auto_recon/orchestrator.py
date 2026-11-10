# xss_security_gui/auto_recon/orchestrator.py

import json
import logging
import time
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable

from xss_security_gui.auto_recon.core_logger import get_logger
from xss_security_gui.auto_recon.user_tracker import get_user_tracker, get_user_context, build_attack_surface
from xss_security_gui.auto_recon.metrics import get_metrics_collector
from xss_security_gui.auto_recon.reporting import get_report_generator

from xss_security_gui.auto_recon.scanner import EndpointScanner, save_reflected_response
from xss_security_gui.auto_recon.analyzer import AutoReconAnalyzerV2
from xss_security_gui.auto_recon.planner import AttackPlannerV2, build_attack_plan
from xss_security_gui.auto_recon.payloads import PayloadGenerator
from xss_security_gui.auto_recon.scope import (
    RequestBudget,
    is_target_authorized,
    normalize_http_url,
    same_origin,
)

from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


class AutoReconOrchestrator:
    """
    Red Team Orchestrator для AutoRecon Enterprise.
    Управляет:
    • Recon → Analyze → Attack → Report
    • MITRE / Kill Chain трейсингом
    • Threat / OPSEC / Session контекстом
    • Логированием и метриками
    """

    def __init__(
        self,
        target_urls: List[str] | str,
        config: Optional[Dict[str, Any]] = None,
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.target_urls = [target_urls] if isinstance(target_urls, str) else list(target_urls)
        self.config = {**self._default_config(), **(config or {})}
        self.active_request_budget = RequestBudget(200)
        self.callback = callback
        if self.config.get("opsec_mode"):
            try:
                get_user_context().opsec_mode = str(self.config.get("opsec_mode"))
            except Exception:
                pass

        # Компоненты
        self.logger = get_logger("AutoReconOrchestrator")
        self.user_tracker = get_user_tracker()
        self.metrics_collector = get_metrics_collector()
        self.reporter = get_report_generator()
        self.ctx = get_user_context()

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
        return {
            "aggressive": False,
            "max_workers": 10,
            "timeout": 5,
            "save_report": True,
            "export_html": True,
            "export_json": True,
            "include_xss_advanced": True,
            "include_sqli": True,
            "include_csrf": True,
            "include_ssrf": True,
            "include_dom_xss": True,
            "max_payloads": 200,
            "active_testing": False,
        }

    def _emit_intel(self, module: str, target: str, payload: Any) -> None:
        """ThreatConnector.add_artifact iterates a list — never pass a raw dict."""
        if payload is None:
            return
        if isinstance(payload, dict):
            items = [payload]
        elif isinstance(payload, list):
            items = [x if isinstance(x, dict) else {"value": x} for x in payload]
        else:
            items = [{"value": payload}]
        try:
            THREAT_CONNECTOR.add_artifact(module, target, items)
        except Exception as e:
            self.logger.error(f"ThreatConnector emit failed: {e}")

    def _report_progress(self, stage=None, status=None, details=None, **kwargs):
        """Accepts orchestrator (stage, status, details) or scanner dict callbacks."""
        if not self.callback:
            return
        try:
            if isinstance(stage, dict):
                message = dict(stage)
                message.setdefault("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())
                message.setdefault("stage", message.get("stage") or "SCANNING")
                message.setdefault("status", message.get("status") or message.get("error") or "update")
                message.setdefault("details", {k: v for k, v in message.items() if k not in ("timestamp", "stage", "status", "details")})
            else:
                message = {
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "stage": stage or "UNKNOWN",
                    "status": status or "running",
                    "details": details or {},
                }
            if kwargs:
                message["details"] = {**(message.get("details") or {}), **kwargs}
            self.callback(message)
        except Exception as e:
            self.logger.error(f"Progress callback error: {e}")

    @property
    def user_context_dict(self) -> Dict[str, Any]:
        ctx = self.ctx
        return {
            "user_id": ctx.user.user_id,
            "hostname": ctx.user.hostname,
            "ip_address": ctx.user.ip_address,
            "session_id": ctx.user.session_id,
            "phase": ctx.current_phase,
            "opsec_mode": ctx.opsec_mode,
            "threat_level": ctx.threat_level,
        }

    def run(self) -> Dict[str, Any]:
        """
        Полный Red Team AutoRecon пайплайн:
        Recon → Analyze → Attack → Report + MITRE / Kill Chain / Metrics.
        """
        self.start_time = time.time()
        try:
            self.target_urls = list(dict.fromkeys(
                normalize_http_url(target) for target in self.target_urls
            ))
        except (TypeError, ValueError) as exc:
            return self._blocked_report(f"Invalid target scope: {exc}")

        unauthorized = [
            target for target in self.target_urls if not is_target_authorized(target)
        ]
        if not self.target_urls or unauthorized:
            reason = (
                "No targets were provided."
                if not self.target_urls
                else "Targets are not enabled by ALLOW_REAL_RUN/ALLOWED_TARGETS: "
                + ", ".join(unauthorized)
            )
            return self._blocked_report(reason)

        self.config["active_testing"] = self.config.get("active_testing") is True
        self.config["aggressive"] = bool(self.config.get("aggressive"))
        if not self.config["active_testing"]:
            self.config["aggressive"] = False
        self.config["max_workers"] = min(max(1, int(self.config.get("max_workers", 1))), 10)
        self.config["max_payloads"] = min(max(0, int(self.config.get("max_payloads", 0))), 200)
        self.config["timeout"] = min(max(int(self.config.get("timeout", 5)), 1), 5)
        self.active_request_budget = RequestBudget(self.config["max_payloads"])

        user_ctx = self.user_context_dict

        self.logger.info(
            "🚀 AutoRecon Started",
            tags={"stage": "initialization", "targets": self.target_urls},
            user_id=user_ctx["user_id"],
            session_id=user_ctx["session_id"],
        )

        self.user_tracker.track_operation(
            "autorecon_full_scan",
            details={"targets": self.target_urls, "config": self.config},
            target=", ".join(self.target_urls),
            status="started",
        )

        # MITRE: Reconnaissance / Active Scanning
        self.user_tracker.track_attack_chain(
            tactic="TA0043",
            technique="T1595",
            subtechnique="T1595.002",
            target=", ".join(self.target_urls),
            status="executed",
            details={"stage": "initialization"},
            operator_note="AutoRecon orchestration started.",
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

            # Attack Surface + Risk
            surface = build_attack_surface()
            self._emit_intel("ATTACK_SURFACE", ", ".join(self.target_urls), surface)

            self.end_time = time.time()
            duration = self.end_time - self.start_time

            self.logger.success(
                "✅ AutoRecon Complete",
                tags={"stage": "completion"},
                user_id=user_ctx["user_id"],
                session_id=user_ctx["session_id"],
                duration_seconds=duration,
            )

            self.user_tracker.track_operation(
                "autorecon_full_scan",
                details={
                    "scan_results": len(self.scan_results),
                    "analysis_modules": len(self.analysis_results),
                    "attack_results": len(self.attack_results),
                },
                target=", ".join(self.target_urls),
                status="success",
            )

            return self.final_report

        except Exception as e:
            self.end_time = time.time()
            duration = (self.end_time - self.start_time) if self.start_time else 0

            self.logger.error(
                f"❌ AutoRecon Error: {e}",
                tags={"stage": "error"},
                user_id=user_ctx["user_id"],
                session_id=user_ctx["session_id"],
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
                "duration_seconds": duration,
            }

    def _blocked_report(self, reason: str) -> Dict[str, Any]:
        report = {
            "status": "blocked",
            "error": reason,
            "metadata": {
                "report_type": "full_autorecon_report",
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "targets": list(self.target_urls),
                "active_testing": True,
                "scope_enforced": True,
                "risk_level": "unknown",
                "risk_score": 0,
            },
            "scan_report": {},
            "vulnerability_report": {},
            "detailed_analysis": {},
            "attack_results": [],
            "threat_summary": {},
        }
        self._report_progress(
            "SCOPE", "blocked", {"reason": reason, "targets": self.target_urls}
        )
        return report

    def _run_scan_stage(self) -> List[Dict[str, Any]]:
        """
        Этап 1: Сканирование эндпоинтов.
        Red Team версия:
        • MITRE Reconnaissance (TA0043)
        • Active Scanning (T1595)
        • Vulnerability Scanning (T1595.002)
        • OPSEC-aware поведение
        • Threat-aware логирование
        • Session-aware трейсинг
        """

        op_id = self.metrics_collector.start_operation(
            "scan_endpoints",
            {"targets": self.target_urls, "phase": self.ctx.current_phase}
        )

        self.logger.info(
            "🔍 Starting endpoint reconnaissance",
            tags={"targets": self.target_urls},
            user_id=self.ctx.user.user_id,
            session_id=self.ctx.user.session_id,
        )

        # MITRE: Reconnaissance → Active Scanning
        self.user_tracker.track_attack_chain(
            tactic="TA0043",
            technique="T1595",
            subtechnique="T1595.002",
            target=", ".join(self.target_urls),
            status="executed",
            details={"stage": "scan_start"},
            operator_note="Endpoint reconnaissance initiated."
        )

        try:
            all_results = []
            total_endpoints = 0
            total_xss = 0
            total_fuzz = 0

            for target_url in self.target_urls:
                self._report_progress("SCANNING", f"scanning_{target_url}")

                scanner = EndpointScanner(
                    target_url,
                    gui_callback=self._report_progress,
                    opsec_mode=getattr(self.ctx, "opsec_mode", "standard"),
                    timeout=self.config["timeout"],
                    active_request_budget=self.active_request_budget,
                    active_testing=self.config["active_testing"],
                )

                # === 1. Endpoint Discovery ===
                endpoints = scanner.scan()
                endpoints = [
                    endpoint for endpoint in endpoints
                    if isinstance(endpoint, dict)
                    and same_origin(str(endpoint.get("url") or target_url), target_url)
                ]
                total_endpoints += len(endpoints)

                self.logger.info(
                    f"📍 Endpoints scanned: {len(endpoints)}",
                    tags={"target": target_url, "count": len(endpoints)},
                    user_id=self.ctx.user.user_id,
                    session_id=self.ctx.user.session_id,
                )

                # Track each endpoint
                for ep in endpoints:
                    self.user_tracker.track_endpoint(target_url, ep.get("url", ep))

                # Active probes run only after an explicit operator opt-in.
                if self.config["active_testing"]:
                    xss_results = scanner.scan_xss_on_endpoints()
                else:
                    xss_results = []
                total_xss += len(xss_results)

                for entry in xss_results:
                    if entry.get("vulnerable") is True:
                        save_reflected_response(entry)

                        self.user_tracker.track_vulnerability_found(
                            vuln_type="XSS",
                            url=entry.get("url", target_url),
                            severity="high",
                            payload=entry.get("payload"),
                            details={"context": entry.get("context")},
                            cvss=6.1,
                            exploitable=True,
                            chainable=True,
                        )

                # === 3. Fuzzing ===
                fuzz_results = (
                    scanner.fuzz_xss_parameters({"q": "test"}, method="GET")
                    if self.config["active_testing"]
                    else []
                )
                total_fuzz += len(fuzz_results)

                # Track parameters
                for fr in fuzz_results:
                    if "param" in fr:
                        self.user_tracker.track_parameter(
                            target_url,
                            fr["param"],
                            fr.get("value", "")
                        )

                # Aggregate
                all_results.extend(endpoints)
                all_results.extend(xss_results)
                all_results.extend(fuzz_results)

                # === Attack Surface per target ===
                surface = build_attack_surface(target_url)
                self.user_tracker.track_attack_surface(target_url, surface)
                self._emit_intel("ATTACK_SURFACE", target_url, surface)

                # === OPSEC-aware logging ===
                if self.ctx.opsec_mode == "high" and len(endpoints) > 50:
                    self.logger.warning(
                        "⚠️ High OPSEC mode: too many endpoints discovered",
                        tags={"target": target_url, "endpoints": len(endpoints)},
                        user_id=self.ctx.user.user_id,
                        session_id=self.ctx.user.session_id,
                    )

            # === Metrics ===
            items_processed = len(all_results)
            self.metrics_collector.finish_operation(
                op_id,
                success=True,
                items_processed=items_processed
            )

            # === MITRE: Reconnaissance Completed ===
            self.user_tracker.track_attack_chain(
                tactic="TA0043",
                technique="T1595",
                subtechnique="T1595.002",
                target=", ".join(self.target_urls),
                status="executed",
                details={
                    "endpoints": total_endpoints,
                    "xss": total_xss,
                    "fuzz": total_fuzz,
                },
                operator_note="Reconnaissance stage completed."
            )

            # === Progress ===
            self._report_progress(
                "SCANNING",
                "complete",
                {
                    "endpoints": total_endpoints,
                    "xss": total_xss,
                    "fuzz": total_fuzz,
                    "items": items_processed,
                }
            )

            return all_results

        except Exception as e:
            self.metrics_collector.finish_operation(op_id, success=False)
            self.logger.error(f"Scan stage error: {e}")
            raise

    def _run_analysis_stage(self) -> Dict[str, Any]:
        """
        Этап 2: Анализ результатов.
        Red Team версия:
        • MITRE Initial Access (TA0001)
        • Exploit Public-Facing Application (T1190)
        • Threat-aware анализ
        • Risk scoring
        • OPSEC-aware поведение
        """

        op_id = self.metrics_collector.start_operation(
            "analyze_results",
            {"modules": ["XSS", "SQLi", "CSRF", "SSRF"], "phase": self.ctx.current_phase}
        )

        self.logger.info(
            "📊 Starting analysis stage",
            tags={"modules": ["XSS", "SQLi", "CSRF", "SSRF"]},
            user_id=self.ctx.user.user_id,
            session_id=self.ctx.user.session_id,
        )

        # MITRE: Initial Access → Exploit Public-Facing Application
        self.user_tracker.track_attack_chain(
            tactic="TA0001",
            technique="T1190",
            subtechnique=None,
            target=", ".join(self.target_urls),
            status="executed",
            details={"stage": "analysis_start"},
            operator_note="Analysis stage initiated."
        )

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

            # === Анализ ===
            results = analyzer.analyze(responses)

            xss_count = len(results.get("xss") or results.get("dom_xss") or [])
            sqli_count = len(results.get("sqli") or [])
            csrf_count = len(results.get("csrf") or [])
            ssrf_count = len(results.get("ssrf") or [])

            # ThreatConnector enrichment
            self._emit_intel("ANALYSIS", ", ".join(self.target_urls), {
                "xss": xss_count,
                "sqli": sqli_count,
                "csrf": csrf_count,
                "ssrf": ssrf_count,
            })

            # === Risk scoring (Red Team) ===
            risk_score = (
                    xss_count * 3 +
                    sqli_count * 5 +
                    csrf_count * 1 +
                    ssrf_count * 4
            )

            if risk_score < 10:
                risk_level = "low"
            elif risk_score < 25:
                risk_level = "medium"
            elif risk_score < 50:
                risk_level = "high"
            else:
                risk_level = "critical"

            # Обновление контекста
            self.ctx.threat_level = risk_level

            # === OPSEC-aware logging ===
            if self.ctx.opsec_mode == "high" and risk_level in ("high", "critical"):
                self.logger.warning(
                    "⚠️ High OPSEC mode: high-risk findings detected",
                    tags={"risk_level": risk_level, "risk_score": risk_score},
                    user_id=self.ctx.user.user_id,
                    session_id=self.ctx.user.session_id,
                )

            # === Metrics ===
            self.metrics_collector.finish_operation(
                op_id,
                success=True,
                items_processed=len(responses)
            )

            # === MITRE: Analysis Completed ===
            self.user_tracker.track_attack_chain(
                tactic="TA0001",
                technique="T1190",
                subtechnique=None,
                target=", ".join(self.target_urls),
                status="executed",
                details={
                    "xss": xss_count,
                    "sqli": sqli_count,
                    "csrf": csrf_count,
                    "ssrf": ssrf_count,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                },
                operator_note="Analysis stage completed."
            )

            # === Аномалии ===
            if xss_count > 20 or sqli_count > 10:
                self.logger.warning(
                    "⚠️ Anomaly detected: unusually high number of findings",
                    tags={"xss": xss_count, "sqli": sqli_count},
                    user_id=self.ctx.user.user_id,
                    session_id=self.ctx.user.session_id,
                )

            # === Progress ===
            self._report_progress(
                "ANALYZING",
                "complete",
                {
                    "xss": xss_count,
                    "sqli": sqli_count,
                    "csrf": csrf_count,
                    "ssrf": ssrf_count,
                    "risk_level": risk_level,
                    "risk_score": risk_score,
                }
            )

            return results

        except Exception as e:
            self.metrics_collector.finish_operation(op_id, success=False)
            self.logger.error(f"Analysis stage error: {e}")
            return {}

    def _run_attack_stage(self) -> List[Dict[str, Any]]:
        """
        Этап 3: Выполнение атак.
        Red Team версия:
        • MITRE Execution (TA0002)
        • Command and Control (TA0011)
        • Exploit Public-Facing Application (T1190)
        • OPSEC-aware атаки
        • Threat-aware payload selection
        • Anomaly detection
        """

        if not self.config["active_testing"]:
            self._report_progress(
                "ATTACKING",
                "skipped",
                {"reason": "active_testing_not_confirmed"},
            )
            return []

        op_id = self.metrics_collector.start_operation(
            "execute_attacks",
            {"max_workers": self.config["max_workers"], "phase": self.ctx.current_phase}
        )

        self.logger.info(
            "⚔️ Начало атакующего этапа",
            tags={"workers": self.config["max_workers"]},
            user_id=self.ctx.user.user_id,
            session_id=self.ctx.user.session_id,
        )

        # MITRE: Execution / Exploit Public-Facing Application
        self.user_tracker.track_attack_chain(
            tactic="TA0002",
            technique="T1190",
            subtechnique=None,
            target=", ".join(self.target_urls),
            status="executed",
            details={"stage": "attack_start"},
            operator_note="Атакующий этап начат."
        )

        # MITRE: Command and Control (TA0011)
        self.user_tracker.track_attack_chain(
            tactic="TA0011",
            technique="T1102",  # Web Service C2
            subtechnique=None,
            target=", ".join(self.target_urls),
            status="executed",
            details={"stage": "attack_c2_init"},
            operator_note="Инициализация канала управления."
        )

        try:
            # === 1. Подготовка эндпоинтов ===
            endpoints = [
                {
                    "url": r.get("url", self.target_urls[0]),
                    "method": r.get("method", "GET"),
                    "params": r.get("params", {}),
                    "source": r.get("source", "unknown"),
                }
                for r in self.scan_results
                if isinstance(r, dict)
                and any(
                    same_origin(
                        str(r.get("url") or target),
                        target,
                    )
                    for target in self.target_urls
                )
            ]

            # === 2. Генерация payload'ов ===
            payload_gen = PayloadGenerator(
                endpoints[: self.config["max_payloads"]],
                use_mutation=True,
            )
            payloads = payload_gen.generate()[:self.config["max_payloads"]]

            # Threat-aware payload selection (keep mixed set if filters would empty it)
            xss_hits = self.analysis_results.get("xss") or self.analysis_results.get("dom_xss")
            sqli_hits = self.analysis_results.get("sqli")
            filtered = list(payloads)
            if xss_hits:
                xss_only = [p for p in payloads if "xss" in str(p.get("type", "xss")).lower()]
                if xss_only:
                    filtered = xss_only
            if sqli_hits:
                sqli_only = [p for p in payloads if "sqli" in str(p.get("type", "")).lower()]
                if sqli_only:
                    filtered = filtered + sqli_only
            payloads = filtered or payloads
            payloads = [
                payload
                for payload in payloads
                if isinstance(payload, dict)
                and any(
                    same_origin(str(payload.get("url") or ""), target)
                    for target in self.target_urls
                )
            ][: self.config["max_payloads"]]

            self.logger.info(
                f"🧬 Генерация payload'ов завершена: {len(payloads)}",
                tags={"payloads": len(payloads)},
                user_id=self.ctx.user.user_id,
                session_id=self.ctx.user.session_id,
            )

            # === OPSEC-aware payload фильтрация ===
            if self.ctx.opsec_mode == "high":
                payloads = [p for p in payloads if not p.get("aggressive")]
                self.logger.warning(
                    "🔐 Высокий режим OPSEC: агрессивные payload'ы удалены",
                    tags={"оставшиеся_payloads": len(payloads)},
                    user_id=self.ctx.user.user_id,
                    session_id=self.ctx.user.session_id,
                )

            # === 3. Построение плана атаки ===
            plan = build_attack_plan(endpoints, payloads)

            # === 4. Выполнение атак ===
            planner = AttackPlannerV2(
                payloads,
                threat_connector=THREAT_CONNECTOR,
                max_workers=self.config["max_workers"],
                timeout=self.config["timeout"],
                active_testing=True,
                active_request_budget=self.active_request_budget,
            )

            attack_results = planner.execute()

            # === Enrichment цепи атаки ===
            for ar in attack_results:
                self.user_tracker.track_attack_chain(
                    tactic="TA0002",
                    technique="T1059",
                    subtechnique="T1059.007",
                    target=ar.get("url"),
                    status="executed" if ar.get("success") else "failed",
                    details=ar,
                    operator_note="Payload выполнен."
                )

            # === Anomaly detection ===
            if len(payloads) > 100:
                self.logger.warning(
                    "⚠️ Аномалия: слишком много payload'ов",
                    tags={"payloads": len(payloads)},
                    user_id=self.ctx.user.user_id,
                    session_id=self.ctx.user.session_id,
                )

            # === Метрики ===
            self.metrics_collector.finish_operation(
                op_id,
                success=True,
                items_processed=len(payloads)
            )

            # === Прогресс ===
            self._report_progress(
                "ATTACKING",
                "complete",
                {"results": len(attack_results), "payloads": len(payloads)}
            )

            return attack_results

        except Exception as e:
            self.metrics_collector.finish_operation(op_id, success=False)
            self.logger.error(f"Ошибка в атакующем этапе: {e}")
            return []

    def _generate_final_report(self) -> Dict[str, Any]:
        """
        Этап 4: Генерация итогового отчёта.
        Red Team версия:
        • Threat Intelligence Summary
        • Kill Chain Summary
        • MITRE Mapping
        • Attack Surface Summary
        • Risk Assessment
        """

        # === Сбор уязвимостей ===
        vulnerabilities = [
            r for r in self.scan_results
            if r.get("vulnerable") is True
        ]

        # === Генерация отчётов ===
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

        # === Attack Surface ===
        surface = build_attack_surface()
        self._emit_intel("ATTACK_SURFACE", ", ".join(self.target_urls), surface)

        # === Risk Assessment ===
        risk_score = (
                len(surface["endpoints"]) * 2 +
                len(surface["parameters"]) * 1 +
                len(surface["forms"]) * 3 +
                len(surface["js_libs"]) * 1 +
                (10 if surface["cms"] else 0) +
                (5 if surface["cdn"] else 0)
        )

        if risk_score < 20:
            risk_level = "low"
        elif risk_score < 40:
            risk_level = "medium"
        elif risk_score < 70:
            risk_level = "high"
        else:
            risk_level = "critical"

        self.ctx.threat_level = risk_level

        # === Финальный отчёт ===
        final_report = {
            "metadata": {
                "report_type": "full_autorecon_report",
                "generated_at": datetime.datetime.utcnow().isoformat(),
                "targets": self.target_urls,
                "duration_seconds": (
                    (self.end_time or time.time()) - (self.start_time or time.time())
                ),
                "user": self.user_context_dict,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "scope_enforced": True,
                "active_testing": self.config["active_testing"],
                "aggressive": self.config["aggressive"],
                "max_workers": self.config["max_workers"],
                "max_payloads": self.config["max_payloads"],
            },
            "scan_report": scan_report,
            "vulnerability_report": vulnerability_report,
            "detailed_analysis": detailed_analysis,
            "attack_results": self.attack_results,
            "attack_surface": surface,
            "threat_summary": THREAT_CONNECTOR.summary(),
            "metrics": self.metrics_collector.get_summary(),
        }

        # === Сохранение ===
        if self.config.get("save_report"):
            json_path = self.reporter.save_report(final_report)
            self.logger.info(f"📄 Report saved: {json_path}")

            if self.config.get("export_html"):
                html_path = self.reporter.generate_html_report(final_report)
                self.logger.info(f"🌐 HTML Report saved: {html_path}")

        return final_report


# API функции
def run_full_autorecon(
    targets: List[str] | str,
    config: Optional[Dict[str, Any]] = None,
    callback: Optional[Callable] = None,
) -> Dict[str, Any]:
    """
    Запускает полный Red Team AutoRecon пайплайн.
    • Recon → Analyze → Attack → Report
    • MITRE / Kill Chain / Threat / OPSEC / Session-aware
    """

    if isinstance(targets, str):
        targets = [targets]

    orchestrator = AutoReconOrchestrator(targets, config, callback)
    return orchestrator.run()


def run_aggressive_scan(
    targets: List[str] | str,
    callback: Optional[Callable] = None,
    *,
    active_testing: bool = False,
) -> Dict[str, Any]:
    """
    Запускает агрессивное сканирование.
    Red Team версия:
    • max_workers ↑
    • max_payloads ↑
    • OPSEC предупреждение
    """

    config = AutoReconOrchestrator._default_config()
    config["aggressive"] = True
    config["max_workers"] = 10
    config["max_payloads"] = 200
    config["timeout"] = 5
    config["active_testing"] = active_testing

    return run_full_autorecon(targets, config, callback)


__all__ = [
    "AutoReconOrchestrator",
    "run_full_autorecon",
    "run_aggressive_scan",
]


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        description="AutoRecon Enterprise Orchestrator — Red Team Edition"
    )

    parser.add_argument("targets", nargs="+", help="Target URLs to scan")
    parser.add_argument("--aggressive", action="store_true", help="Enable aggressive mode")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth OPSEC mode")
    parser.add_argument("--workers", type=int, default=5, help="Max workers")
    parser.add_argument("--payloads", type=int, default=50, help="Max payloads")
    parser.add_argument("--export-html", action="store_true", help="Export HTML report")
    parser.add_argument("--export-json", action="store_true", help="Export JSON report")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    # Logging
    if args.verbose:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    # Build config
    config = {
        "aggressive": args.aggressive,
        "max_workers": args.workers,
        "max_payloads": args.payloads,
        "export_html": args.export_html,
        "export_json": args.export_json,
    }

    # OPSEC mode
    if args.stealth:
        print("🔐 OPSEC: Stealth mode enabled (reduced payloads, silent scanning)")
        config["opsec_mode"] = "high"

    # Aggressive warning
    if args.aggressive:
        print("⚠️ Aggressive mode enabled — high‑noise scanning, heavy payloads")

    def progress_callback(msg: Dict[str, Any]):
        stage = msg.get("stage", "unknown").upper()
        status = msg.get("status", "running")
        details = msg.get("details", {})
        print(f"[{stage}] {status} {details}")

    try:
        print(f"🚀 Starting AutoRecon Enterprise scan for: {', '.join(args.targets)}")
        print(f"⚙️ Config: {config}")

        if args.aggressive:
            result = run_aggressive_scan(args.targets, progress_callback)
        else:
            result = run_full_autorecon(args.targets, config, progress_callback)

        print("✅ Scan completed successfully!")

        # Export reports
        if args.export_html or args.export_json:
            reporter = get_report_generator()

            if args.export_json:
                json_path = reporter.save_report(result)
                print(f"📄 JSON report saved: {json_path}")

            if args.export_html:
                html_path = reporter.generate_html_report(result)
                print(f"🌐 HTML report saved: {html_path}")

        # Threat summary
        print("\n📊 Threat Summary:")
        threat_summary = result.get("threat_summary", {})
        for k, v in threat_summary.items():
            print(f"  • {k}: {v}")

        # Risk summary
        risk = result.get("metadata", {}).get("risk_level", "unknown")
        score = result.get("metadata", {}).get("risk_score", 0)
        print(f"\n⚠️ Risk Level: {risk} (score: {score})")

    except KeyboardInterrupt:
        print("\n⚠️ Scan interrupted by user")
        sys.exit(1)

    except Exception as e:
        print(f"❌ Error during scan: {type(e).__name__}: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)