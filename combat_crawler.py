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
from xss_security_gui.deep_crawler import deep_crawl_site, enhance_crawler_results
from xss_security_gui.settings import LOG_DIR

logger = logging.getLogger("CombatCrawler")

# ============================================================
#  Combat Crawler Class
# ============================================================

class CombatCrawler:
    """
    Боевой краулер = Deep Crawl + Attack Engine
    Выполняет краулинг и затем запускает реальные атаки.
    Все результаты передаются через очередь для GUI.
    """
    
    def __init__(self,
                 target_url: str,
                 result_queue: queue.Queue,
                 progress_callback: Optional[Callable] = None):
        self.target_url = target_url
        self.result_queue = result_queue
        self.progress_callback = progress_callback
        self.stop_flag = threading.Event()
        
        # Результаты на каждом этапе
        self.crawl_results = {}
        self.attack_results = {}
        self.final_report = {}
        
    def _emit_progress(self, msg: str, progress_pct: int = 0):
        """Отправить прогресс"""
        if self.progress_callback:
            try:
                self.progress_callback(msg, progress_pct)
            except Exception:
                pass
        
        try:
            self.result_queue.put({
                "type": "progress",
                "message": msg,
                "progress": progress_pct,
                "timestamp": datetime.now().isoformat()
            }, timeout=1)
        except queue.Full:
            pass
    
    def _emit_event(self, event_type: str, data: Any):
        """Отправить событие"""
        try:
            self.result_queue.put({
                "type": event_type,
                "data": data,
                "timestamp": datetime.now().isoformat()
            }, timeout=1)
        except queue.Full:
            pass
    
    def stage_1_crawl(self) -> Dict[str, Any]:
        """Этап 1: Глубокое сканирование (краулинг)"""
        self._emit_progress("📍 ЭТАП 1/3: Начинаем глубокое сканирование...", 5)
        
        try:
            crawl_result = deep_crawl_site(self.target_url)
            enhanced = enhance_crawler_results(crawl_result)
            
            self.crawl_results = crawl_result
            
            # Отправляем результаты краулинга
            self._emit_event("crawl_complete", {
                "pages_found": len(crawl_result.get("pages", [])),
                "scripts_found": len(crawl_result.get("raw", {}).get("scripts", [])),
                "endpoints_found": len(crawl_result.get("raw", {}).get("api_endpoints", [])),
                "status": enhanced.get("scan_status", "UNKNOWN"),
                "quality_score": enhanced.get("quality_score", 0),
            })
            
            self._emit_progress("✅ ЭТАП 1 завершён: Краулинг выполнен", 30)
            return crawl_result
            
        except Exception as e:
            self._emit_progress(f"❌ ЭТАП 1 ошибка: {e}", 30)
            logger.error(f"Crawl stage error: {e}")
            raise
    
    def stage_2_analyze(self, crawl_data: Dict[str, Any]) -> Dict[str, List]:
        """Этап 2: Анализ найденных параметров"""
        self._emit_progress("🔍 ЭТАП 2/3: Анализируем найденные параметры...", 40)
        
        endpoints = []
        parameters = {}
        
        try:
            raw = crawl_data.get("raw", {})
            
            # Собираем endpoints
            endpoints = list(raw.get("api_endpoints", []))[:10]  # Ограничиваем
            
            # Собираем параметры из посещённых страниц
            visited = raw.get("visited", [])
            for url in visited[:20]:  # Ограничиваем
                try:
                    from urllib.parse import urlparse, parse_qs
                    parsed = urlparse(url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for key, values in params.items():
                            if key not in parameters:
                                parameters[key] = []
                            parameters[key].extend(values)
                except Exception:
                    pass
            
            # Отправляем результаты анализа
            self._emit_event("analysis_complete", {
                "endpoints_count": len(endpoints),
                "parameters_count": len(parameters),
                "top_endpoints": endpoints[:5],
                "top_parameters": list(parameters.keys())[:5],
            })
            
            self._emit_progress("✅ ЭТАП 2 завершён: Анализ выполнен", 55)
            
            return {
                "endpoints": endpoints,
                "parameters": parameters,
            }
            
        except Exception as e:
            self._emit_progress(f"⚠️ ЭТАП 2 ошибка: {e}", 55)
            logger.warning(f"Analysis stage error: {e}")
            return {"endpoints": [], "parameters": {}}
    
    def stage_3_attack(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Этап 3: Боевые атаки на найденные параметры"""
        self._emit_progress("🎯 ЭТАП 3/3: Запускаем боевые атаки...", 60)
        
        attack_engine = CombatAttackEngine(
            target_url=self.target_url,
            result_queue=self.result_queue,
            progress_callback=self._emit_progress,
            timeout=10.0
        )
        
        # Масштабируем использование endpoints
        endpoints_to_attack = analysis_data.get("endpoints", [])[:5]
        if not endpoints_to_attack:
            endpoints_to_attack = [self.target_url]
        
        # Запускаем атаки
        try:
            attack_engine.total_attacks = 100  # Примерно
            
            results = {
                "xss_attacks": attack_engine.attack_xss(endpoints_to_attack),
                "sqli_attacks": attack_engine.attack_sqli(analysis_data.get("parameters", {})),
                "csrf_attacks": attack_engine.attack_csrf(),
                "ssrf_attacks": attack_engine.attack_ssrf(),
                "lfi_attacks": attack_engine.attack_lfi(),
            }
            
            self.attack_results = results
            
            # Подсчитываем уязвимости
            vulnerable_count = sum(
                1 for attack_list in results.values()
                for attack in attack_list
                if attack.vulnerable
            )
            
            critical_count = sum(
                1 for attack_list in results.values()
                for attack in attack_list
                if attack.severity == "CRITICAL"
            )
            
            self._emit_event("attacks_complete", {
                "xss_found": len([a for a in results["xss_attacks"] if a.vulnerable]),
                "sqli_found": len([a for a in results["sqli_attacks"] if a.vulnerable]),
                "csrf_found": len([a for a in results["csrf_attacks"] if a.vulnerable]),
                "ssrf_found": len([a for a in results["ssrf_attacks"] if a.vulnerable]),
                "lfi_found": len([a for a in results["lfi_attacks"] if a.vulnerable]),
                "total_vulnerable": vulnerable_count,
                "critical_severity": critical_count,
            })
            
            self._emit_progress("✅ ЭТАП 3 завершён: Атаки выполнены", 95)
            
            return results
            
        except Exception as e:
            self._emit_progress(f"❌ ЭТАП 3 ошибка: {e}", 95)
            logger.error(f"Attack stage error: {e}")
            return {}
    
    def generate_final_report(self) -> Dict[str, Any]:
        """Генерировать финальный отчёт"""
        self._emit_progress("📊 Генерируем финальный отчёт...", 97)
        
        report = {
            "metadata": {
                "target": self.target_url,
                "timestamp": datetime.now().isoformat(),
                "combat_version": "1.0",
            },
            "stage_1_crawl": {
                "status": "COMPLETE",
                "pages": len(self.crawl_results.get("pages", [])),
                "endpoints": len(self.crawl_results.get("raw", {}).get("api_endpoints", [])),
            },
            "stage_2_analysis": {
                "status": "COMPLETE",
            },
            "stage_3_attacks": {
                "xss": len([a for a in self.attack_results.get("xss_attacks", []) if a.vulnerable]),
                "sqli": len([a for a in self.attack_results.get("sqli_attacks", []) if a.vulnerable]),
                "csrf": len([a for a in self.attack_results.get("csrf_attacks", []) if a.vulnerable]),
                "ssrf": len([a for a in self.attack_results.get("ssrf_attacks", []) if a.vulnerable]),
                "lfi": len([a for a in self.attack_results.get("lfi_attacks", []) if a.vulnerable]),
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

