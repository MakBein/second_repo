# xss_security_gui/ai_threat_analyzer.py
"""
AI Threat Analyzer 1.0 — Интеграция AI Core с анализом угроз

Возможности:
- Анализ угроз через AI моделей
- Обучение на основе обнаруженных угроз
- Категоризация и оценка рисков
- Синтетическая генерация угроз для боевых сценариев
- Real-time обновление с потокобезопасностью
"""

from __future__ import annotations

import json
import threading
import queue
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime

from xss_security_gui.settings import BASE_DIR, AI_SAFE_MODE, AI_FALLBACK_ON_ERROR
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge

# Импортируем AI Core
try:
    from xss_security_gui.ai_core import (
        analyze_security_risk,
        scan_project,
        train_from_logs,
        generate_synthetic_xss,
        ProjectAnalyzerRunner,
        AITrainingRunner,
    )
    AI_CORE_AVAILABLE = True
except Exception as e:
    print(f"[⚠️] AI Core not available: {e}")
    AI_CORE_AVAILABLE = False


@dataclass
class ThreatAnalysisResult:
    """Результат анализа угрозы"""
    threat_id: str
    category: str
    original_risk: str
    ai_risk_score: float  # 0.0 - 1.0
    ai_confidence: float  # 0.0 - 1.0
    ai_reasons: List[str]
    ai_recommendations: List[str]
    timestamp: str
    processed_data: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AIThreatAnalyzer:
    """
    Анализатор угроз с интеграцией AI Core
    """
    
    def __init__(self, threat_tab=None, ui_bridge: Optional[UIQueueBridge] = None):
        self.threat_tab = threat_tab
        self.ui_bridge = ui_bridge
        self._analysis_queue: queue.Queue = queue.Queue()
        self._results_cache: Dict[str, ThreatAnalysisResult] = {}
        self._analysis_lock = threading.Lock()
        self._is_running = False
        self._learning_enabled = True
        
        # История анализа для обучения
        self._history_file = BASE_DIR / "logs" / "threat_analysis_history.json"
        self._history: List[Dict[str, Any]] = self._load_history()
        
    def _load_history(self) -> List[Dict[str, Any]]:
        """Загружает историю анализа"""
        if self._history_file.exists():
            try:
                with open(self._history_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[⚠️] Error loading history: {e}")
        return []
    
    def _save_history(self) -> None:
        """Сохраняет историю анализа"""
        try:
            self._history_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._history_file, "w", encoding="utf-8") as f:
                json.dump(self._history, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            print(f"[⚠️] Error saving history: {e}")
    
    def analyze_threat(self, artifact: Dict[str, Any], threat_id: str) -> ThreatAnalysisResult:
        """
        Анализирует угрозу с помощью AI
        """
        category = artifact.get("result", {}).get("category", "unknown")
        original_risk = artifact.get("result", {}).get("risk", "unknown")
        
        # Инициализируем результат
        result = ThreatAnalysisResult(
            threat_id=threat_id,
            category=category,
            original_risk=original_risk,
            ai_risk_score=0.0,
            ai_confidence=0.0,
            ai_reasons=[],
            ai_recommendations=[],
            timestamp=datetime.now().isoformat(),
            processed_data={}
        )
        
        if not AI_CORE_AVAILABLE:
            result.ai_reasons.append("AI Core недоступен, используется default анализ")
            result.ai_risk_score = self._get_legacy_risk_score(category, original_risk)
            result.ai_confidence = 0.5
            return result
        
        try:
            # Анализируем на основе категории
            if category == "email_leak":
                result = self._analyze_email_leak(artifact, result)
            elif category == "credit_card_leak":
                result = self._analyze_credit_card_leak(artifact, result)
            elif category == "password_dump":
                result = self._analyze_password_dump(artifact, result)
            elif category == "xss_vulnerability":
                result = self._analyze_xss(artifact, result)
            elif category == "sqli_vulnerability":
                result = self._analyze_sqli(artifact, result)
            elif category == "csrf_vulnerability":
                result = self._analyze_csrf(artifact, result)
            else:
                result = self._analyze_generic(artifact, result)
            
            # Кешируем результат
            with self._analysis_lock:
                self._results_cache[threat_id] = result
                self._history.append({
                    "threat_id": threat_id,
                    "category": category,
                    "result": result.to_dict(),
                    "timestamp": datetime.now().isoformat()
                })
            
            # Сохраняем историю для обучения
            if len(self._history) % 10 == 0:  # Сохраняем каждые 10 анализов
                self._save_history()
            
            return result
            
        except Exception as e:
            print(f"[⚠️] Error analyzing threat: {e}")
            result.ai_reasons.append(f"Ошибка анализа: {str(e)}")
            return result
    
    def _analyze_email_leak(self, artifact: Dict[str, Any], result: ThreatAnalysisResult) -> ThreatAnalysisResult:
        """Анализирует утечку email"""
        email_leak = artifact.get("result", {}).get("email_leak", {})
        emails = email_leak.get("emails", [])
        smtp_users = email_leak.get("smtp_users", [])
        
        # Количество скомпрометированных аккаунтов
        compromised_count = len(emails) + len(smtp_users)
        
        # Оценка риска
        if compromised_count > 100:
            result.ai_risk_score = 0.95
            result.ai_reasons.append(f"Огромное количество скомпрометированных аккаунтов: {compromised_count}")
        elif compromised_count > 10:
            result.ai_risk_score = 0.85
            result.ai_reasons.append(f"Значительное количество скомпрометированных аккаунтов: {compromised_count}")
        else:
            result.ai_risk_score = 0.75
            result.ai_reasons.append(f"Email leak обнаружен с {compromised_count} аккаунтами")
        
        result.ai_confidence = 0.95
        result.ai_recommendations = [
            "Немедленно уведомить пользователей",
            "Запустить процесс reset паролей",
            "Включить двухфакторную аутентификацию",
            "Проверить другие сервисы на скомпрометированные учетные данные"
        ]
        result.processed_data = {
            "emails_count": len(emails),
            "smtp_users_count": len(smtp_users),
            "total_compromised": compromised_count
        }
        
        return result
    
    def _analyze_credit_card_leak(self, artifact: Dict[str, Any], result: ThreatAnalysisResult) -> ThreatAnalysisResult:
        """Анализирует утечку кредитных карт"""
        cc_leak = artifact.get("result", {}).get("credit_card_leak", {})
        cards = cc_leak.get("cards", [])
        
        result.ai_risk_score = 0.98 if len(cards) > 0 else 0.90
        result.ai_confidence = 0.98
        result.ai_reasons = [
            f"Утечка {len(cards)} кредитных карт обнаружена",
            "Данные могут быть использованы для мошенничества",
            "Прямое финансовое воздействие на компанию"
        ]
        result.ai_recommendations = [
            "Срочно уведомить платежные системы",
            "Заблокировать скомпрометированные карты",
            "Запустить программу кредитного мониторинга",
            "Подать отчет в правоохранительные органы"
        ]
        result.processed_data = {
            "cards_count": len(cards),
            "risk_type": "financial"
        }
        
        return result
    
    def _analyze_password_dump(self, artifact: Dict[str, Any], result: ThreatAnalysisResult) -> ThreatAnalysisResult:
        """Анализирует дамп паролей"""
        pwd_dump = artifact.get("result", {}).get("password_dump", {})
        passwords = pwd_dump.get("passwords", [])
        
        result.ai_risk_score = 0.80 if len(passwords) > 0 else 0.70
        result.ai_confidence = 0.90
        result.ai_reasons = [
            f"Обнаружен дамп {len(passwords)} паролей",
            "Пароли могут быть использованы для несанкционированного доступа"
        ]
        result.ai_recommendations = [
            "Срочно оповестить пользователей",
            "Принудительно сбросить пароли",
            "Проверить логи доступа на предмет компрометации",
            "Внедрить защиту от преобразования паролей"
        ]
        result.processed_data = {
            "passwords_count": len(passwords),
            "encoded": pwd_dump.get("encoded", False)
        }
        
        return result
    
    def _analyze_xss(self, artifact: Dict[str, Any], result: ThreatAnalysisResult) -> ThreatAnalysisResult:
        """Анализирует XSS уязвимость через AI Core"""
        if AI_CORE_AVAILABLE:
            try:
                # Используем Risk Engine из AI Core
                payload = artifact.get("result", {}).get("payload", "")
                if payload:
                    risk_info = analyze_security_risk(payload)
                    result.ai_risk_score = risk_info.get("score", 0.75)
                    result.ai_confidence = risk_info.get("confidence", 0.80)
                    result.ai_reasons = risk_info.get("reasons", ["XSS vulnerability detected"])
                    result.processed_data = risk_info
                else:
                    result.ai_risk_score = 0.75
                    result.ai_confidence = 0.85
                    result.ai_reasons = ["XSS vulnerability detected"]
            except Exception as e:
                print(f"[⚠️] AI XSS analysis error: {e}")
                result.ai_risk_score = 0.75
                result.ai_confidence = 0.50
        else:
            result.ai_risk_score = 0.75
            result.ai_confidence = 0.70
        
        result.ai_recommendations = [
            "Применить input validation",
            "Использовать HTML escaping",
            "Внедрить Content Security Policy (CSP)",
            "Провести security review кода"
        ]
        
        return result
    
    def _analyze_sqli(self, artifact: Dict[str, Any], result: ThreatAnalysisResult) -> ThreatAnalysisResult:
        """Анализирует SQL Injection"""
        result.ai_risk_score = 0.90
        result.ai_confidence = 0.95
        result.ai_reasons = [
            "SQL Injection уязвимость обнаружена",
            "Возможен несанкционированный доступ к БД",
            "Потенциал для утечки всех данных"
        ]
        result.ai_recommendations = [
            "Использовать prepared statements",
            "Внедрить parameterized queries",
            "Провести input validation",
            "Запустить WAF rules для SQLi",
            "Проверить логи БД на предмет несанкционированного доступа"
        ]
        
        return result
    
    def _analyze_csrf(self, artifact: Dict[str, Any], result: ThreatAnalysisResult) -> ThreatAnalysisResult:
        """Анализирует CSRF"""
        result.ai_risk_score = 0.70
        result.ai_confidence = 0.85
        result.ai_reasons = [
            "CSRF уязвимость обнаружена",
            "Возможно выполнение несанкционированных операций"
        ]
        result.ai_recommendations = [
            "Внедрить CSRF tokens",
            "Использовать SameSite cookies",
            "Проверить Origin header",
            "Внедрить дополнительную аутентификацию для операций"
        ]
        
        return result
    
    def _analyze_generic(self, artifact: Dict[str, Any], result: ThreatAnalysisResult) -> ThreatAnalysisResult:
        """Generic анализ для неизвестных типов"""
        result.ai_risk_score = 0.50
        result.ai_confidence = 0.60
        result.ai_reasons = ["Неизвестный тип угрозы обнаружен"]
        result.ai_recommendations = ["Провести ручной анализ угрозы"]
        
        return result
    
    def _get_legacy_risk_score(self, category: str, risk: str) -> float:
        """Legacy оценка для случаев когда AI недоступен"""
        risk_map = {
            "critical": 0.95,
            "high": 0.80,
            "medium": 0.60,
            "low": 0.40,
            "info": 0.20
        }
        return risk_map.get(risk.lower(), 0.50)
    
    def train_on_threats(self, threat_history: Optional[List[Dict[str, Any]]] = None) -> bool:
        """Тренирует AI модель на основе истории угроз"""
        if not AI_CORE_AVAILABLE:
            print("[⚠️] AI Core not available for training")
            return False
        
        if threat_history is None:
            threat_history = self._history
        
        if not threat_history:
            print("[⚠️] No threat history to train on")
            return False
        
        try:
            print(f"[🤖] Training AI on {len(threat_history)} threats...")
            
            # Используем AITrainingRunner для асинхронного обучения
            runner = AITrainingRunner(
                logs_dir=BASE_DIR / "logs",
                max_samples=None,
                output_name="threat_analysis_model"
            )
            
            # Запускаем обучение в фоне
            def train_task():
                try:
                    runner.run()
                    print("[✅] AI training completed successfully")
                except Exception as e:
                    print(f"[❌] AI training failed: {e}")
            
            train_thread = threading.Thread(target=train_task, daemon=True, name="AIThreatTraining")
            train_thread.start()
            
            return True
            
        except Exception as e:
            print(f"[❌] Training error: {e}")
            return False
    
    def generate_synthetic_threats(self, count: int = 5) -> List[Dict[str, Any]]:
        """Генерирует синтетические угрозы для тестирования"""
        if not AI_CORE_AVAILABLE:
            print("[⚠️] AI Core not available for synthetic generation")
            return []
        
        try:
            print(f"[🤖] Generating {count} synthetic threats...")
            synthetic_threats = []
            
            for i in range(count):
                threat = {
                    "type": "synthetic_xss",
                    "payload": generate_synthetic_xss(),
                    "timestamp": datetime.now().isoformat(),
                    "severity": "medium"
                }
                synthetic_threats.append(threat)
            
            return synthetic_threats
            
        except Exception as e:
            print(f"[⚠️] Error generating synthetic threats: {e}")
            return []
    
    def get_threat_analysis(self, threat_id: str) -> Optional[ThreatAnalysisResult]:
        """Возвращает кешированный результат анализа"""
        with self._analysis_lock:
            return self._results_cache.get(threat_id)
    
    def clear_cache(self) -> None:
        """Очищает кеш анализов"""
        with self._analysis_lock:
            self._results_cache.clear()
    
    def export_history(self, filepath: str) -> bool:
        """Экспортирует историю анализов"""
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self._history, f, indent=2, ensure_ascii=False, default=str)
            print(f"[✅] History exported to {filepath}")
            return True
        except Exception as e:
            print(f"[❌] Export error: {e}")
            return False

