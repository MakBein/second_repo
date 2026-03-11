# xss_security_gui/threat_analysis/tester_base.py
"""
TesterBase (ULTRA Hybrid 6.5+)
------------------------------
Базовый класс для всех тестеров (SQLi, XSS, CSRF, SSRF, LFI, RCE).

• Гибридные настройки (таймауты, ретраи, User-Agent) через settings.
• Централизованная отправка артефактов в ThreatConnector.
• Единый, расширяемый формат результата.
• Безопасный вызов output_callback (GUI не падает из-за тестера).
"""

import threading
import logging
import time
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
        self.timeout = int(settings.get("http.request_timeout", 7))
        self.max_retries = int(settings.get("network.max_retries", 3))
        self.retry_delay = float(settings.get("network.retry_delay", 1.0))

        # User-Agent
        self.default_headers = {
            "User-Agent": settings.get("http.default_user_agent", "XSS-Security-GUI/6.5")
        }

        # Логирование
        self.logger = logging.getLogger(f"{__name__}.{self.module_name}")
        log_level = settings.get("logging.level", "INFO").upper()
        self.logger.setLevel(getattr(logging, log_level, logging.INFO))

    # ============================================================
    #  Основной поток тестирования
    # ============================================================
    def run(self) -> None:
        self.logger.info(
            "[%s] Запуск тестирования для %s (payloads=%d)",
            self.module_name,
            self.base_url,
            sum(len(v) for v in self.payloads.values()),
        )

        for category, plist in self.payloads.items():
            for payload in plist:
                full_value = f"{self.base_value}{payload}"

                result = self._execute_with_retries(category, payload, full_value)
                if result is not None:
                    self.results.append(result)
                    self._safe_emit(result)

        # Отправка артефактов в ThreatConnector
        if self.results:
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
            start = time.monotonic()
            try:
                result = self._test_single(category, payload, full_value)
                # Подкласс может вернуть None, если считает payload нерелевантным
                if result is None:
                    return None

                # Гарантируем базовые поля и duration
                duration = time.monotonic() - start
                if "duration" not in result:
                    result["duration"] = duration
                if "module" not in result:
                    result["module"] = self.module_name
                if "url" not in result:
                    result["url"] = self.base_url
                if "param" not in result:
                    result["param"] = self.param
                if "payload" not in result:
                    result["payload"] = payload
                if "category" not in result:
                    result["category"] = category
                if "status" not in result:
                    result["status"] = "success"

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
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)

        # Все попытки провалились — возвращаем унифицированный error-result
        if last_error is not None:
            return self._format_error_result(category, payload, last_error)

        return None

    # ============================================================
    #  Метод должен быть реализован в подклассе
    # ============================================================
    def _test_single(
        self,
        category: str,
        payload: str,
        full_value: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Должен быть реализован в подклассе.

        Ожидается, что вернет dict с полями:
        - category, payload, status, severity, details, response_length (опционально)
        или None, если результат не нужно учитывать.
        """
        raise NotImplementedError("Подкласс должен реализовать _test_single()")

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
        """
        Базовый формат результата, который можно расширять через extra.
        """
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