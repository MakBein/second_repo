# xss_security_gui/threat_analysis/tester_base.py
import threading
import logging
import time
from typing import Dict, Any, List, Optional

from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
from xss_security_gui.settings import settings


class TesterBase(threading.Thread):
    """
    Enterprise 6.5 TesterBase (ULTRA Hybrid)
    ----------------------------------------
    • Базовый класс для всех тестеров (SQLi, XSS, CSRF, SSRF, LFI, RCE)
    • Поддерживает гибридные настройки (таймауты, ретраи, User-Agent)
    • Централизованная отправка артефактов в ThreatConnector
    • Единая система логирования
    """

    def __init__(
        self,
        module_name: str,
        base_url: str,
        param: str,
        base_value: str,
        payloads: Dict[str, List[str]],
        output_callback: Optional[callable] = None
    ):
        super().__init__()

        self.module_name = module_name
        self.base_url = base_url
        self.param = param
        self.base_value = base_value
        self.payloads = payloads
        self.output_callback = output_callback
        self.connector = THREAT_CONNECTOR
        self.results: List[Dict[str, Any]] = []

        # ================================
        # Гибридные настройки ULTRA 6.5
        # ================================
        self.timeout = int(settings.get("http.request_timeout", 7))
        self.max_retries = int(settings.get("network.max_retries", 3))
        self.retry_delay = float(settings.get("network.retry_delay", 1.0))

        # User-Agent
        self.default_headers = {
            "User-Agent": settings.get("http.default_user_agent", "XSS-Security-GUI/6.5")
        }

        # Логирование
        log_level = settings.get("logging.level", "INFO").upper()
        logging.getLogger(__name__).setLevel(getattr(logging, log_level, logging.INFO))

    # ============================================================
    #  Основной поток тестирования
    # ============================================================
    def run(self) -> None:
        logging.info(f"[{self.module_name}] Запуск тестирования для {self.base_url}")

        for category, plist in self.payloads.items():
            for payload in plist:
                full_value = f"{self.base_value}{payload}"

                result = self._execute_with_retries(category, payload, full_value)
                if result:
                    self.results.append(result)

                    if self.output_callback:
                        self.output_callback(result)

        # Отправка артефактов в ThreatConnector
        if self.results:
            self.connector.add_artifact(self.module_name, self.base_url, self.results)
            logging.info(
                f"[{self.module_name}] {len(self.results)} результатов отправлено в ThreatConnector"
            )

    # ============================================================
    #  Ретраи (повторные попытки)
    # ============================================================
    def _execute_with_retries(self, category: str, payload: str, full_value: str):
        for attempt in range(1, self.max_retries + 1):
            try:
                return self._test_single(category, payload, full_value)
            except Exception as e:
                logging.error(
                    f"[{self.module_name}] Ошибка payload={payload} "
                    f"(попытка {attempt}/{self.max_retries}): {e}"
                )
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
        return None

    # ============================================================
    #  Метод должен быть реализован в подклассе
    # ============================================================
    def _test_single(self, category: str, payload: str, full_value: str) -> Dict[str, Any]:
        raise NotImplementedError("Подкласс должен реализовать _test_single()")