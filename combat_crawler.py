# xss_security_gui/combat_crawler.py
"""
Combat Crawler — Объединённый краулер + атакующий движок
Интегрирует глубокий краулинг с реальными боевыми атаками
"""
import queue
import threading
import time
import json
import logging
from typing import Dict, Any, List, Callable, Optional
from datetime import datetime
from pathlib import Path

from xss_security_gui.combat_attack_engine import CombatAttackEngine
from xss_security_gui.core.waf_engine import WAFDetector, HTTPEvasionWrapper, WAFType
from xss_security_gui.core.stealth_engine import StealthMode
from xss_security_gui.deep_crawler import deep_crawl_site, enhance_crawler_results
from xss_security_gui.settings import LOG_DIR
from xss_security_gui.ai_core import analyze_security_risk, AIWorker

logger = logging.getLogger("CombatCrawler")


class CombatCrawler:
    """
    Боевой краулер = Deep Crawl + Attack Engine
    Интегрирован с WAFDetector 13.0 для автоматического обхода WAF
    Выполняет краулинг и затем запускает реальные атаки.
    Все результаты передаются через очередь для GUI.
    """

    def __init__(
        self,
        target_url: str,
        result_queue: queue.Queue,
        progress_callback: Optional[Callable] = None,
    ):
        self.target_url = target_url
        self.result_queue = result_queue
        self.progress_callback = progress_callback
        self.stop_flag = threading.Event()

        # WAFDetector 13.0 Integration
        self.waf_detector = WAFDetector()
        self.detected_waf: Optional[WAFType] = None
        self.waf_detection_confidence: float = 0.0

        # Stealth Mode 11.0 — Red Team Edition
        self.stealth = StealthMode()
        self.stealth.activate()
        logger.info(
            "[CombatCrawler] Stealth Mode 11.0 ACTIVATED — %d browser profiles",
            self.stealth.header_engine.profile_count,
        )

        # HTTP evasion wrapper (чтобы AttackEngine мог использовать обход WAF)
        self.http_evasion = HTTPEvasionWrapper(self.waf_detector)

        # Результаты на каждом этапе
        self.crawl_results: Dict[str, Any] = {}
        self.attack_results: Dict[str, Any] = {}
        self.waf_info: Dict[str, Any] = {}
        self.final_report: Dict[str, Any] = {}
        self.ai_worker = AIWorker()
        self.ai_worker.start()
        self.ai_assessment: Dict[str, Any] = {
            "summary": {"risk_score": 0.0, "risk_level": "info"},
            "targets": [],
            "high_risk_targets": [],
        }

    def _safe_ai_score(self, url: str, js_text: str = "", js_insights: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Безопасная AI-подсказка для ранжирования целей. Никогда не валит GUI/краулер."""
        try:
            insight_map: Dict[str, Any] = js_insights or {}
            if not isinstance(insight_map, dict):
                insight_map = {}
            if not js_text:
                js_text = ""
            risk = analyze_security_risk(insight_map, js_text)
            score = float(risk.get("risk_score", 0.0))
            return {
                "url": url,
                "risk_score": round(score, 4),
                "risk_level": risk.get("risk_level", "info"),
                "llm_summary": risk.get("llm_summary", ""),
                "ml_score": float(risk.get("ml_score", 0.0)),
                "nn_score": float(risk.get("nn_score", 0.0)),
                "heuristic_score": float(risk.get("heuristic_score", 0.0)),
            }
        except Exception as exc:
            logger.debug(f"AI risk score fallback for {url}: {exc}")
            return {
                "url": url,
                "risk_score": 0.0,
                "risk_level": "info",
                "llm_summary": f"AI fallback: {exc}",
                "ml_score": 0.0,
                "nn_score": 0.0,
                "heuristic_score": 0.0,
            }

    def _ai_rank_targets(self, crawl_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ранжирует endpoint-ы через AI Core и добавляет приоритеты для атак."""
        scores: List[Dict[str, Any]] = []
        seen: set[str] = set()

        raw = crawl_data.get("raw", {}) if isinstance(crawl_data, dict) else {}
        pages = crawl_data.get("pages", []) if isinstance(crawl_data, dict) else []

        if isinstance(pages, list):
            for page in pages:
                page_url = str(page.get("url") or self.target_url)
                if page_url in seen:
                    continue
                seen.add(page_url)
                js_insights = page.get("js_insights", {}) or {}
                js_text = page.get("js_code") or "\n".join(page.get("scripts", []) or [])
                scores.append(self._safe_ai_score(page_url, js_text, js_insights))

        for endpoint in (raw.get("api_endpoints", []) or []):
            target = str(endpoint)
            if target in seen:
                continue
            seen.add(target)
            scores.append(self._safe_ai_score(target, "", {}))

        if not scores:
            scores.append(self._safe_ai_score(self.target_url, "", {}))

        sort_scores = sorted(scores, key=lambda s: float(s.get("risk_score", 0.0)), reverse=True)
        summary = {
            "risk_score": round(sum(item["risk_score"] for item in sort_scores) / max(len(sort_scores), 1), 4),
            "risk_level": "high" if sort_scores and sort_scores[0]["risk_score"] >= 0.8 else "medium" if sort_scores and sort_scores[0]["risk_score"] >= 0.5 else "low",
            "targets_evaluated": len(sort_scores),
            "top_target": sort_scores[0] if sort_scores else {"url": self.target_url, "risk_score": 0.0},
        }
        assessment = {
            "summary": summary,
            "targets": sort_scores,
            "high_risk_targets": [t for t in sort_scores if float(t.get("risk_score", 0.0)) >= 0.5],
        }
        self.ai_assessment = assessment
        self._emit_event("ai_assessment_complete", assessment)
        return assessment

    def _emit_progress(self, msg: str, progress_pct: int = 0) -> None:
        """Отправить прогресс"""
        if self.progress_callback:
            try:
                self.progress_callback(msg, progress_pct)
            except Exception:
                pass

        try:
            self.result_queue.put(
                {
                    "type": "progress",
                    "message": msg,
                    "progress": progress_pct,
                    "timestamp": datetime.now().isoformat(),
                },
                timeout=1,
            )
        except queue.Full:
            pass

    def _emit_event(self, event_type: str, data: Any) -> None:
        """Отправить событие"""
        try:
            self.result_queue.put(
                {
                    "type": event_type,
                    "data": data,
                    "timestamp": datetime.now().isoformat(),
                },
                timeout=1,
            )
        except queue.Full:
            pass

        # Логируем в JSONL для Threat Intel / истории
        try:
            log_path = Path(LOG_DIR) / "combat_events.jsonl"
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(
                    json.dumps(
                        {
                            "type": event_type,
                            "data": data,
                            "timestamp": datetime.now().isoformat(),
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
        except Exception:
            pass

    def _detect_waf(self) -> Optional[WAFType]:
        """Обнаружить WAF на целевом сайте (Stealth Mode headers + TLS)"""
        try:
            import requests

            stealth_headers = self.stealth.get_stealth_headers()
            time.sleep(self.stealth.get_delay())

            session = requests.Session()
            tls_ctx, tls_name = self.stealth.get_stealth_context()
            from xss_security_gui.real_time_watcher import _AdaptiveTLSAdapter

            session.mount("https://", _AdaptiveTLSAdapter(ssl_context=tls_ctx))
            response = session.get(
                self.target_url,
                headers=stealth_headers,
                timeout=10,
                verify=False,
            )

            detected = self.waf_detector.detect_waf(
                self.target_url,
                response.text,
                dict(response.headers),
                response.status_code,
            )

            if detected:
                waf_info = self.waf_detector.detected_wafes.get(
                    self.target_url, {}
                )
                self.waf_detection_confidence = waf_info.get("confidence", 0.0)
                self.detected_waf = detected

                # Stealth Mode: set detected WAF for targeted evasion
                self.stealth.set_detected_waf(detected.value)

                self.waf_info = {
                    "type": detected.value,
                    "confidence": self.waf_detection_confidence,
                    "fingerprints_matched": waf_info.get("score", 0),
                    "stealth_mode": self.stealth.stats,
                }

                logger.info(
                    "WAF detected: %s (confidence: %.1f%%)",
                    detected.value,
                    self.waf_detection_confidence * 100,
                )
                self._emit_progress(
                    f"⚠️ WAF обнаружен: {detected.value}", 10
                )
                return detected
        except Exception as e:
            logger.debug(f"WAF detection error: {e}")

        return None

    def stage_1_crawl(self) -> Dict[str, Any]:
        """Этап 1: Глубокое сканирование (краулинг) + Обнаружение WAF"""
        self._emit_progress(
            "📍 ЭТАП 1/3: Начинаем глубокое сканирование и обнаружение WAF...",
            5,
        )

        start_time = time.time()

        try:
            crawl_result = deep_crawl_site(self.target_url)
            enhanced = enhance_crawler_results(crawl_result)

            self.crawl_results = crawl_result
            ai_score = self._ai_rank_targets(crawl_result)

            # Обнаружение WAF
            self._detect_waf()

            crawl_event = {
                "pages_found": len(crawl_result.get("pages", [])),
                "scripts_found": len(
                    crawl_result.get("raw", {}).get("scripts", [])
                ),
                "endpoints_found": len(
                    crawl_result.get("raw", {}).get("api_endpoints", [])
                ),
                "status": enhanced.get("scan_status", "UNKNOWN"),
                "quality_score": enhanced.get("quality_score", 0),
                "duration_sec": round(time.time() - start_time, 2),
                "ai_summary": ai_score.get("summary", {}),
                "ai_top_targets": ai_score.get("high_risk_targets", [])[:5],
            }

            if self.detected_waf:
                crawl_event["detected_waf"] = self.detected_waf.value
                crawl_event["waf_confidence"] = self.waf_detection_confidence

            self._emit_event("crawl_complete", crawl_event)
            self._emit_progress("✅ ЭТАП 1 завершён: Краулинг выполнен + AI-ранжирование активировано", 30)
            return crawl_result

        except Exception as e:
            self._emit_progress(f"❌ ЭТАП 1 ошибка: {e}", 30)
            logger.error(f"Crawl stage error: {e}", exc_info=True)
            raise

    def stage_2_analyze(self, crawl_data: Dict[str, Any]) -> Dict[str, List]:
        """Этап 2: Анализ найденных параметров"""
        self._emit_progress(
            "🔍 ЭТАП 2/3: Анализируем найденные параметры...", 40
        )

        endpoints: List[str] = []
        parameters: Dict[str, List[str]] = {}

        try:
            raw = crawl_data.get("raw", {}) if isinstance(crawl_data, dict) else {}
            endpoints = raw.get("api_endpoints", []) if isinstance(raw, dict) else []
            endpoints = [str(ep) for ep in list(endpoints)[:10]]

            if self.ai_assessment.get("targets"):
                ranked = sorted(
                    self.ai_assessment["targets"],
                    key=lambda item: float(item.get("risk_score", 0.0)),
                    reverse=True,
                )
                ai_prioritized = [item["url"] for item in ranked if item.get("url")]
                endpoints = list(dict.fromkeys(ai_prioritized + endpoints))[:10]

            visited = raw.get("visited", []) if isinstance(raw, dict) else []
            for url in list(visited)[:20]:
                if self.stop_flag.is_set():
                    self._emit_progress(
                        "⏸️ Анализ остановлен пользователем", 40
                    )
                    break
                try:
                    from urllib.parse import urlparse, parse_qs

                    parsed = urlparse(str(url))
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for key, values in params.items():
                            if key not in parameters:
                                parameters[key] = []
                            parameters[key].extend(values)
                except Exception:
                    pass

            self._emit_event(
                "analysis_complete",
                {
                    "endpoints_count": len(endpoints),
                    "parameters_count": len(parameters),
                    "top_endpoints": endpoints[:5],
                    "top_parameters": list(parameters.keys())[:5],
                    "ai_priority": self.ai_assessment.get("summary", {}),
                },
            )

            self._emit_progress("✅ ЭТАП 2 завершён: Анализ выполнен + AI-приоритизация активирована", 55)

            return {
                "endpoints": endpoints,
                "parameters": parameters,
            }

        except Exception as e:
            self._emit_progress(f"⚠️ ЭТАП 2 ошибка: {e}", 55)
            logger.warning(f"Analysis stage error: {e}", exc_info=True)
            return {"endpoints": [], "parameters": {}}

    def stage_3_attack(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Этап 3: Боевые атаки на найденные параметры"""
        self._emit_progress("🎯 ЭТАП 3/3: Запускаем боевые атаки...", 60)

        start_time = time.time()

        attack_engine = CombatAttackEngine(
            target_url=self.target_url,
            result_queue=self.result_queue,
            progress_callback=self._emit_progress,
            timeout=10.0,
        )

        # Передаём WAF‑контекст и HTTP‑обход в AttackEngine, если он это поддерживает
        try:
            attack_engine.detected_waf = self.detected_waf
            attack_engine.waf_detection_confidence = (
                self.waf_detection_confidence
            )
            attack_engine.http_evasion = self.http_evasion
        except Exception:
            pass

        endpoints_to_attack = analysis_data.get("endpoints", [])[:5]
        if not endpoints_to_attack:
            endpoints_to_attack = [self.target_url]

        # AI priority: sort targets by risk score, highest first
        if self.ai_assessment.get("targets"):
            priority_by_url = {t.get("url"): float(t.get("risk_score", 0.0)) for t in self.ai_assessment["targets"] if t.get("url")}
            endpoints_to_attack = sorted(
                endpoints_to_attack,
                key=lambda ep: priority_by_url.get(ep, 0.0),
                reverse=True,
            )

        try:
            attack_engine.total_attacks = 100

            params = analysis_data.get("parameters", {})
            if not params:
                logger.info(
                    "[CombatCrawler] Нет параметров для SQLi атак — пропускаем SQLi этап"
                )
                sqli_results = []
            else:
                sqli_results = attack_engine.attack_sqli(params)

            xss_results = attack_engine.attack_xss(endpoints_to_attack)
            csrf_results = attack_engine.attack_csrf()
            ssrf_results = attack_engine.attack_ssrf()
            lfi_results = attack_engine.attack_lfi()

            results: Dict[str, Any] = {
                "xss_attacks": xss_results,
                "sqli_attacks": sqli_results,
                "csrf_attacks": csrf_results,
                "ssrf_attacks": ssrf_results,
                "lfi_attacks": lfi_results,
            }

            self.attack_results = results

            vulnerable_count = sum(
                1
                for attack_list in results.values()
                for attack in attack_list
                if getattr(attack, "vulnerable", False)
            )

            critical_count = sum(
                1
                for attack_list in results.values()
                for attack in attack_list
                if getattr(attack, "severity", "") == "CRITICAL"
            )

            attack_time = round(time.time() - start_time, 2)
            ai_summary = self.ai_assessment.get("summary", {})

            logger.info(
                "[CombatCrawler] Attack summary: XSS=%d, SQLi=%d, CSRF=%d, SSRF=%d, LFI=%d AI-score=%.3f (%.2fs)",
                len([a for a in xss_results if a.vulnerable]),
                len([a for a in sqli_results if a.vulnerable]),
                len([a for a in csrf_results if a.vulnerable]),
                len([a for a in ssrf_results if a.vulnerable]),
                len([a for a in lfi_results if a.vulnerable]),
                ai_summary.get("risk_score", 0.0),
                attack_time,
            )

            self._emit_event(
                "attacks_complete",
                {
                    "xss_found": len(
                        [a for a in xss_results if a.vulnerable]
                    ),
                    "sqli_found": len(
                        [a for a in sqli_results if a.vulnerable]
                    ),
                    "csrf_found": len(
                        [a for a in csrf_results if a.vulnerable]
                    ),
                    "ssrf_found": len(
                        [a for a in ssrf_results if a.vulnerable]
                    ),
                    "lfi_found": len(
                        [a for a in lfi_results if a.vulnerable]
                    ),
                    "total_vulnerable": vulnerable_count,
                    "critical_severity": critical_count,
                    "duration_sec": attack_time,
                    "ai_priority": self.ai_assessment.get("summary", {}),
                },
            )

            self._emit_event("attack_time", {"seconds": attack_time})
            self._emit_progress("✅ ЭТАП 3 завершён: Атаки выполнены", 95)

            return results

        except Exception as e:
            self.attack_results = {}
            self._emit_event("attacks_failed", {"error": str(e)})
            self._emit_progress(f"❌ ЭТАП 3 ошибка: {e}", 95)
            logger.error(f"Attack stage error: {e}", exc_info=True)
            return {}
    
    def generate_final_report(self) -> Dict[str, Any]:
        """Генерировать финальный отчёт (с информацией о WAF)"""
        self._emit_progress("📊 Генерируем финальный отчёт...", 97)
        
        report = {
            "metadata": {
                "target": self.target_url,
                "timestamp": datetime.now().isoformat(),
                "combat_version": "2.1",
                "waf_detector_version": "13.0",
                "stealth_mode_version": "11.0",
                "ai_core": "analyze_security_risk / AIWorker",
            },
            "stealth_stats": self.stealth.stats,
            "waf_detection": self.waf_info,
            "ai_assessment": self.ai_assessment,
            "stage_1_crawl": {
                "status": "COMPLETE",
                "pages": len(self.crawl_results.get("pages", [])),
                "endpoints": len(self.crawl_results.get("raw", {}).get("api_endpoints", [])),
                "ai_ranked_targets": [item["url"] for item in self.ai_assessment.get("targets", [])[:10]],
            },
            "stage_2_analysis": {
                "status": "COMPLETE",
                "ai_priority": self.ai_assessment.get("summary", {}),
            },
            "stage_3_attacks": {
                "xss": len([a for a in self.attack_results.get("xss_attacks", []) if a.vulnerable]),
                "sqli": len([a for a in self.attack_results.get("sqli_attacks", []) if a.vulnerable]),
                "csrf": len([a for a in self.attack_results.get("csrf_attacks", []) if a.vulnerable]),
                "ssrf": len([a for a in self.attack_results.get("ssrf_attacks", []) if a.vulnerable]),
                "lfi": len([a for a in self.attack_results.get("lfi_attacks", []) if a.vulnerable]),
                "successful_evasions": sum(
                    1 for attack_list in self.attack_results.values()
                    for attack in attack_list
                    if getattr(attack, 'evasion_success', False)
                ),
            },
            "vulnerability_summary": self._calculate_summary(),
        }
        
        self.final_report = report
        
        # Сохраняем отчёт
        try:
            report_path = Path(LOG_DIR) / f"combat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self._emit_event("report_saved", {
                "path": str(report_path),
                "size": report_path.stat().st_size,
                "waf_detected": bool(self.detected_waf),
            })
        except Exception as e:
            logger.error(f"Report save error: {e}")
        
        return report
    
    def _calculate_summary(self) -> Dict[str, Any]:
        """Рассчитать сводку уязвимостей"""
        critical = 0
        high = 0
        medium = 0
        low = 0
        
        for attack_list in self.attack_results.values():
            for attack in attack_list:
                if attack.severity == "CRITICAL":
                    critical += 1
                elif attack.severity == "HIGH":
                    high += 1
                elif attack.severity == "MEDIUM":
                    medium += 1
                else:
                    low += 1
        
        risk_level = "LOW"
        if critical > 0:
            risk_level = "CRITICAL"
        elif high > 0:
            risk_level = "HIGH"
        elif medium > 0:
            risk_level = "MEDIUM"
        
        return {
            "risk_level": risk_level,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "total": critical + high + medium + low,
        }
    
    def run_full_combat_cycle(self) -> Dict[str, Any]:
        """Запустить полный боевой цикл (все 3 этапа)"""
        try:
            # Этап 1
            crawl_data = self.stage_1_crawl()
            
            if self.stop_flag.is_set():
                self._emit_progress("⏸️ Боевой цикл остановлен", 0)
                return {}
            
            time.sleep(1)
            
            # Этап 2
            analysis_data = self.stage_2_analyze(crawl_data)
            
            if self.stop_flag.is_set():
                self._emit_progress("⏸️ Боевой цикл остановлен", 0)
                return {}
            
            time.sleep(1)
            
            # Этап 3
            attack_data = self.stage_3_attack(analysis_data)
            
            # Финальный отчёт
            report = self.generate_final_report()
            
            self._emit_progress("🎉 БОЕВОЙ ЦИКЛ ЗАВЕРШЁН УСПЕШНО!", 100)
            self._emit_event("combat_complete", report)
            
            return report
            
        except Exception as e:
            self._emit_progress(f"❌ БОЕВОЙ ЦИКЛ ПРЕРВАН: {e}", 0)
            logger.error(f"Combat cycle error: {e}", exc_info=True)
            return {}
    
    def stop(self):
        """Остановить боевой цикл"""
        self.stop_flag.set()


# ============================================================
#  Удобная функция для запуска
# ============================================================

def run_combat_crawl(target_url: str,
                     result_queue: queue.Queue,
                     progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
    """
    Удобная функция для запуска полного боевого цикла.
    
    Args:
        target_url: Целевой URL
        result_queue: Очередь для результатов
        progress_callback: Функция callback для прогресса
    
    Returns:
        Финальный отчёт о результатах
    """
    crawler = CombatCrawler(target_url, result_queue, progress_callback)
    return crawler.run_full_combat_cycle()

