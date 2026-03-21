# xss_security_gui/threat_analysis/tester_base.py
"""
TesterBase (ULTRA Hybrid 6.5+)
------------------------------
Базовый класс для всех тестеров (SQLi, XSS, CSRF, SSRF, LFI, RCE).

• Гибридные настройки (таймауты, ретраи, User-Agent) через settings.
• Централизованная отправка артефактов в ThreatConnector.
• Единый, расширяемый формат результата.
• Безопасный вызов output_callback (GUI не падает из-за тестера).
• Адаптивный троттлинг и детектор стабильности ответа.
• Управляемый жизненный цикл (stop/abort), хуки до/после payload.
"""

import threading
import logging
import time
import hashlib
from typing import Dict, Any, List, Optional, Callable

from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
from xss_security_gui.settings import settings


class TesterBase(threading.Thread):
    """Базовый класс для тестеров уязвимостей."""

    def __init__(
        self,
        module_name: str,
        base_url: str,
        param: str,
        base_value: str,
        payloads: Dict[str, List[str]],
        output_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        super().__init__(daemon=True)

        self.module_name = module_name
        self.base_url = base_url
        self.param = param
        self.base_value = base_value
        self.payloads = payloads
        self.output_callback = output_callback
        self.connector = THREAT_CONNECTOR
        self.results: List[Dict[str, Any]] = []

        # ================================
        # Гибридные настройки ULTRA 6.5+
        # ================================
        self.timeout: int = int(settings.get("http.request_timeout", 7))
        self.max_retries: int = int(settings.get("network.max_retries", 3))
        self.retry_delay: float = float(settings.get("network.retry_delay", 1.0))

        # User-Agent
        self.default_headers: Dict[str, str] = {
            "User-Agent": settings.get("http.default_user_agent", "XSS-Security-GUI/6.5")
        }

        # Логирование
        self.logger = logging.getLogger(f"{__name__}.{self.module_name}")
        log_level = settings.get("logging.level", "INFO").upper()
        self.logger.setLevel(getattr(logging, log_level, logging.INFO))

        # -----------------------------
        # Механизмы стабильности/троттлинга
        # -----------------------------
        self.last_hashes: List[str] = []
        self.throttle_delay: float = 0.0
        self._stability_window: int = int(settings.get("analysis.stability_window", 10))
        self._throttle_step_up: float = float(settings.get("analysis.throttle_step_up", 0.2))
        self._throttle_step_down: float = float(settings.get("analysis.throttle_step_down", 0.1))
        self._throttle_max: float = float(settings.get("analysis.throttle_max", 2.0))

        # Управление жизненным циклом
        self._stop_event = threading.Event()

    # ============================================================
    #  Управление жизненным циклом
    # ============================================================
    def stop(self) -> None:
        """Запрашивает остановку тестера (мягкий abort)."""
        self.logger.info("[%s] Получен запрос на остановку", self.module_name)
        self._stop_event.set()

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    # ============================================================
    #  Основной поток тестирования
    # ============================================================
    def run(self) -> None:
        total_payloads = sum(len(v) for v in self.payloads.values())
        self.logger.info(
            "[%s] Запуск тестирования для %s (payloads=%d)",
            self.module_name,
            self.base_url,
            total_payloads,
        )

        for category, plist in self.payloads.items():
            for payload in plist:
                if self.is_stopped():
                    self.logger.info(
                        "[%s] Тестирование прервано пользователем (category=%s, payload=%r)",
                        self.module_name,
                        category,
                        payload,
                    )
                    self._flush_results()
                    return

                full_value = f"{self.base_value}{payload}"

                # Хук перед payload (можно переопределить в модуле)
                self._before_payload(category, payload, full_value)

                result = self._execute_with_retries(category, payload, full_value)
                if result is not None:
                    self.results.append(result)
                    self._safe_emit(result)

                # Хук после payload
                self._after_payload(category, payload, full_value, result)

        self._flush_results()

    def _flush_results(self) -> None:
        """Отправка артефактов в ThreatConnector."""
        if not self.results:
            return
        try:
            self.connector.add_artifact(self.module_name, self.base_url, self.results)
            self.logger.info(
                "[%s] %d результатов отправлено в ThreatConnector",
                self.module_name,
                len(self.results),
            )
        except Exception as e:
            self.logger.error(
                "[%s] Ошибка отправки артефактов в ThreatConnector: %s",
                self.module_name,
                e,
            )

    # ============================================================
    #  Безопасный вызов output_callback
    # ============================================================
    def _safe_emit(self, result: Dict[str, Any]) -> None:
        if not self.output_callback:
            return
        try:
            self.output_callback(result)
        except Exception as e:
            # Никогда не валим поток из-за GUI/логики вывода
            self.logger.error(
                "[%s] Ошибка в output_callback: %s (result=%r)",
                self.module_name,
                e,
                result,
            )

    # ============================================================
    #  Ретраи (повторные попытки)
    # ============================================================
    def _execute_with_retries(
        self,
        category: str,
        payload: str,
        full_value: str,
    ) -> Optional[Dict[str, Any]]:
        last_error: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 1):
            if self.is_stopped():
                self.logger.debug(
                    "[%s] Прерывание перед попыткой payload=%r",
                    self.module_name,
                    payload,
                )
                return None

            start = time.monotonic()
            try:
                result = self._test_single(category, payload, full_value)
                # Подкласс может вернуть None, если считает payload нерелевантным
                if result is None:
                    return None

                # Гарантируем базовые поля и duration
                duration = time.monotonic() - start
                result.setdefault("duration", duration)
                result.setdefault("module", self.module_name)
                result.setdefault("url", self.base_url)
                result.setdefault("param", self.param)
                result.setdefault("payload", payload)
                result.setdefault("category", category)
                result.setdefault("status", "success")

                return result

            except Exception as e:
                last_error = e
                self.logger.error(
                    "[%s] Ошибка payload=%r (попытка %d/%d): %s",
                    self.module_name,
                    payload,
                    attempt,
                    self.max_retries,
                    e,
                )
                if attempt < self.max_retries and not self.is_stopped():
                    time.sleep(self.retry_delay)

        # Все попытки провалились — возвращаем унифицированный error-result
        if last_error is not None:
            return self._format_error_result(category, payload, last_error)

        return None

    # ============================================================
    #  Универсальный тест одного payload
    # ============================================================
    def _test_single(self, category: str, payload: str, full_value: str) -> Dict[str, Any]:
        """
        Базовая реализация, завязанная на:
        • send_request (реализует подкласс)
        • _analyze_response (реализует подкласс)
        • _check_stability / _apply_throttle (реализованы здесь)
        """
        self._apply_throttle()

        response = self.send_request(full_value)

        if isinstance(response, dict) and response.get("status") == "blocked":
            return self._format_result(
                category=category,
                payload=payload,
                severity="INFO",
                details={
                    "status": "skipped",
                    "reason": response.get("reason"),
                    "response_length": 0,
                    "http_status": None,
                    "body_hit": False,
                    "header_hit": False,
                },
            )

        text = response.text.lower()
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}

        analysis = self._analyze_response(text, headers_lower, response)

        # Стабильность ответа
        if self._check_stability(response.text):
            analysis["severity"] = "INFO"
            analysis["filtered"] = True
            analysis["note"] = "Сервер повертає однакову відповідь — фільтр активний."
            self.throttle_delay = min(self.throttle_delay + self._throttle_step_up, self._throttle_max)
        else:
            self.throttle_delay = max(self.throttle_delay - self._throttle_step_down, 0.0)

        return self._format_result(
            category=category,
            payload=payload,
            severity=analysis.get("severity", "INFO"),
            details=analysis,
        )

    # ============================================================
    #  Throttle + stability helpers
    # ============================================================
    def _apply_throttle(self) -> None:
        if self.throttle_delay > 0:
            time.sleep(self.throttle_delay)

    def _hash_body(self, text: str) -> str:
        return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()

    def _check_stability(self, response_text: str) -> bool:
        h = self._hash_body(response_text)
        self.last_hashes.append(h)
        if len(self.last_hashes) > self._stability_window:
            self.last_hashes.pop(0)
        return len(self.last_hashes) >= 2 and len(set(self.last_hashes)) == 1

    # ============================================================
    #  Хуки (могут быть переопределены в модулях)
    # ============================================================
    def _before_payload(self, category: str, payload: str, full_value: str) -> None:
        """Хук перед отправкой payload (для модулей, если нужно)."""
        pass

    def _after_payload(
        self,
        category: str,
        payload: str,
        full_value: str,
        result: Optional[Dict[str, Any]],
    ) -> None:
        """Хук после обработки payload (для модулей, если нужно)."""
        pass

    # ============================================================
    #  Методы, которые должен реализовать подкласс
    # ============================================================
    def send_request(self, full_value: str):
        """
        Должен быть реализован в модуле (SQLi/XSS/SSRF и т.д.).
        Должен вернуть либо requests.Response, либо dict со статусом 'blocked'.
        """
        raise NotImplementedError("Подкласс должен реализовать send_request()")

    def _analyze_response(
        self,
        text: str,
        headers_lower: Dict[str, str],
        response,
    ) -> Dict[str, Any]:
        """
        Анализирует ответ и возвращает dict с полями:
        • severity
        • http_status / response_length / body_hit / header_hit / и т.д.
        """
        raise NotImplementedError("Подкласс должен реализовать _analyze_response()")

    # ============================================================
    #  Унифицированный формат успешного результата
    # ============================================================
    def _format_result(
        self,
        category: str,
        payload: str,
        severity: str,
        details: Any,
        **extra: Any,
    ) -> Dict[str, Any]:
        """Базовый формат результата, который можно расширять через extra."""
        base: Dict[str, Any] = {
            "module": self.module_name,
            "url": self.base_url,
            "param": self.param,
            "payload": payload,
            "category": category,
            "severity": severity,
            "details": details,
            "status": "success",
        }
        base.update(extra)
        return base

    # ============================================================
    #  Унифицированный формат ошибки
    # ============================================================
    def _format_error_result(
        self,
        category: str,
        payload: str,
        error: Exception,
    ) -> Dict[str, Any]:
        """
        Стандартизованный error-result, чтобы GUI/ThreatConnector
        могли обрабатывать ошибки так же, как и успехи.
        """
        return {
            "module": self.module_name,
            "url": self.base_url,
            "param": self.param,
            "payload": payload,
            "category": category,
            "severity": "error",
            "details": str(error),
            "status": "error",
        }