# xss_security_gui/core/waf_monitor.py
"""
WAF Monitoring & Analytics Module — WAFDetector 13.0 Integration
Отслеживание обнаруженных WAF и статистика обходов
"""

import json
import logging
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

from .waf_engine import WAFType

_logger = logging.getLogger(__name__)


class WAFMonitor:
    """Мониторинг и аналитика WAF"""
    
    def __init__(self):
        self.waf_detections: List[Dict] = []
        self.evasion_stats: Dict[str, Dict] = defaultdict(lambda: {
            "total_attempts": 0,
            "successful_evasions": 0,
            "success_rate": 0.0,
        })
        self.waf_timeline: List[Tuple[datetime, WAFType, float]] = []
    
    def record_waf_detection(self, url: str, waf_type: WAFType, confidence: float, 
                            fingerprints_count: int = 0) -> None:
        """Записать обнаруженный WAF"""
        detection = {
            "timestamp": datetime.now().isoformat(),
            "url": url,
            "waf_type": waf_type.value,
            "confidence": confidence,
            "fingerprints_matched": fingerprints_count,
        }
        self.waf_detections.append(detection)
        self.waf_timeline.append((datetime.now(), waf_type, confidence))
        _logger.info(f"WAF recorded: {waf_type.value} at {url}")
    
    def record_evasion_attempt(self, waf_type: WAFType, success: bool, 
                               payload_variant: str = "") -> None:
        """Записать попытку обхода WAF"""
        waf_key = waf_type.value
        self.evasion_stats[waf_key]["total_attempts"] += 1
        
        if success:
            self.evasion_stats[waf_key]["successful_evasions"] += 1
        
        # Обновляем процент успеха
        total = self.evasion_stats[waf_key]["total_attempts"]
        successful = self.evasion_stats[waf_key]["successful_evasions"]
        self.evasion_stats[waf_key]["success_rate"] = (successful / total) * 100 if total > 0 else 0.0
    
    def get_waf_statistics(self) -> Dict[str, Any]:
        """Получить статистику по WAF"""
        detected_wafes = defaultdict(int)
        for detection in self.waf_detections:
            detected_wafes[detection["waf_type"]] += 1
        
        avg_confidence = 0.0
        if self.waf_detections:
            avg_confidence = sum(d["confidence"] for d in self.waf_detections) / len(self.waf_detections)
        
        return {
            "total_detections": len(self.waf_detections),
            "unique_wafes": len(detected_wafes),
            "detected_wafes": dict(detected_wafes),
            "average_confidence": round(avg_confidence, 2),
            "evasion_statistics": dict(self.evasion_stats),
        }
    
    def get_top_wafes(self, top_n: int = 5) -> List[Tuple[str, int]]:
        """Получить топ обнаруженных WAF"""
        detected_wafes = defaultdict(int)
        for detection in self.waf_detections:
            detected_wafes[detection["waf_type"]] += 1
        
        sorted_wafes = sorted(detected_wafes.items(), key=lambda x: x[1], reverse=True)
        return sorted_wafes[:top_n]
    
    def get_most_effective_evasions(self, top_n: int = 5) -> List[Tuple[str, float]]:
        """Получить наиболее эффективные обходы WAF"""
        evasions = [
            (waf_type, stats["success_rate"])
            for waf_type, stats in self.evasion_stats.items()
            if stats["total_attempts"] > 0
        ]
        return sorted(evasions, key=lambda x: x[1], reverse=True)[:top_n]
    
    def export_report(self, filepath: Path) -> None:
        """Экспортировать отчёт в JSON"""
        try:
            report = {
                "generated": datetime.now().isoformat(),
                "summary": self.get_waf_statistics(),
                "top_wafes": self.get_top_wafes(10),
                "evasion_success_rates": dict(
                    (waf, stats["success_rate"]) 
                    for waf, stats in self.evasion_stats.items()
                ),
                "detections": self.waf_detections[-100:],  # Last 100
            }
            
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            _logger.info(f"WAF monitor report exported to {filepath}")
        except Exception as e:
            _logger.error(f"Failed to export WAF report: {e}")


class WAFAnalytics:
    """Расширенная аналитика WAF"""
    
    def __init__(self, monitor: WAFMonitor):
        self.monitor = monitor
    
    def identify_waf_patterns(self) -> Dict[str, List]:
        """Выявить закономерности в WAF обнаружениях"""
        patterns = defaultdict(list)
        
        for detection in self.monitor.waf_detections:
            waf_type = detection["waf_type"]
            confidence = detection["confidence"]
            
            # Группируем по типу WAF
            patterns[waf_type].append({
                "confidence": confidence,
                "url": detection["url"],
                "timestamp": detection["timestamp"],
            })
        
        return dict(patterns)
    
    def suggest_evasion_strategy(self, waf_type: WAFType) -> str:
        """Предложить стратегию обхода для конкретного WAF"""
        strategies = {
            WAFType.CLOUDFLARE: "Используйте case-mutations и space-encodings, затем HTML entities",
            WAFType.AKAMAI: "Попробуйте UTF-16 encoding и базовые comment injections",
            WAFType.AWS_WAF: "Используйте URL encoding с double-encoding техниками",
            WAFType.AZURE_WAF: "Применяйте JS Unicode escape sequences и SQL hex encoding",
            WAFType.MOD_SECURITY: "SQL комментарии и пробельные мутации наиболее эффективны",
            WAFType.IMPERVA: "Комбинируйте различные кодирования для большей вероятности",
            WAFType.F5_ASM: "Используйте HTML entities и базовые обфускации",
            WAFType.BARRACUDA: "Space mutations и case changes часто обходят защиту",
            WAFType.PALOALTO: "Применяйте комментарии и кодирование одновременно",
            WAFType.INCAPSULA: "URL encoding и HTML entities - оптимальная комбинация",
        }
        
        return strategies.get(waf_type, "Начните с базовых кодирований и постепенно усложняйте")
    
    def calculate_bypass_probability(self, waf_type: WAFType) -> float:
        """Рассчитать вероятность успешного обхода WAF"""
        if waf_type.value not in self.monitor.evasion_stats:
            return 0.0
        
        stats = self.monitor.evasion_stats[waf_type.value]
        return stats.get("success_rate", 0.0)
    
    def get_risk_assessment(self) -> Dict[str, Any]:
        """Оценка риска WAF"""
        stats = self.monitor.get_waf_statistics()
        top_wafes = self.monitor.get_top_wafes(3)
        evasions = self.monitor.get_most_effective_evasions(3)
        
        # Расчитываем risk score
        risk_score = 0.0
        if stats["total_detections"] > 0:
            risk_score += min(50, stats["total_detections"] * 5)
        
        avg_evasion_rate = sum(e[1] for e in evasions) / len(evasions) if evasions else 0
        risk_score += avg_evasion_rate
        
        risk_level = "LOW"
        if risk_score > 60:
            risk_level = "CRITICAL"
        elif risk_score > 40:
            risk_level = "HIGH"
        elif risk_score > 20:
            risk_level = "MEDIUM"
        
        return {
            "risk_score": round(min(100, risk_score), 1),
            "risk_level": risk_level,
            "top_threats": [w[0] for w in top_wafes],
            "bypass_success_rate": round(avg_evasion_rate, 1),
        }


# Глобальный монитор
_global_monitor = WAFMonitor()
_global_analytics = WAFAnalytics(_global_monitor)


def get_waf_monitor() -> WAFMonitor:
    """Получить глобальный монитор WAF"""
    return _global_monitor


def get_waf_analytics() -> WAFAnalytics:
    """Получить глобальную аналитику WAF"""
    return _global_analytics
