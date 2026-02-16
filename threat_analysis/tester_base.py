# xss_security_gui/threat_analysis/tester_base.py
import threading
import logging
from typing import Dict, Any, List, Optional

from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


class TesterBase(threading.Thread):
    """
    Enterprise 6.0 TesterBase
    -------------------------
    • Базовый класс для всех тестеров (SQLi, XSS, CSRF, SSRF, LFI, RCE)
    • Обеспечивает потоковость, логирование, callback, дедупликацию
    • Интегрируется с ThreatConnector для централизованного хранения артефактов
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
        self.payloads = payloads  # dict: {category: [payloads]}
        self.output_callback = output_callback
        self.connector = THREAT_CONNECTOR
        self.results: List[Dict[str, Any]] = []

    def run(self) -> None:
        """
        Основной метод потока — перебор payload-ов.
        """
        logging.info(f"[{self.module_name}] Запуск тестирования для {self.base_url}")

        for category, plist in self.payloads.items():
            for payload in plist:
                full_value = f"{self.base_value}{payload}"
                try:
                    result = self._test_single(category, payload, full_value)
                    self.results.append(result)

                    if self.output_callback:
                        self.output_callback(result)

                except Exception as e:
                    logging.error(f"[{self.module_name}] Ошибка при тестировании payload={payload}: {e}")

        if self.results:
            self.connector.add_artifact(self.module_name, self.base_url, self.results)
            logging.info(f"[{self.module_name}] {len(self.results)} результатов отправлено в ThreatConnector")

    def _test_single(self, category: str, payload: str, full_value: str) -> Dict[str, Any]:
        """
        Метод должен быть реализован в подклассе.
        Должен возвращать dict с ключами:
        - timestamp, module, category, param, payload, target, status, severity, response_length
        """
        raise NotImplementedError("Подкласс должен реализовать _test_single()")