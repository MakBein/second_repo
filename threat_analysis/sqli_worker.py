# xss_security_gui/threat_analysis/sqli_worker.py
import threading
import queue
from typing import Dict, Any


class SQLiWorker:
    """
    Фоновий воркер для SQLiTester.
    - НЕ змінює логіку тестера.
    - НЕ викликає Tkinter.
    - НЕ блокує GUI.
    - Весь важкий код виконується тут.
    """

    def __init__(self, tester):
        self.tester = tester
        self.queue: queue.Queue[Dict[str, Any]] = queue.Queue()
        self._stop_flag = False

    def start(self):
        """Запускає воркер у фоновому потоці."""
        self._stop_flag = False
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        """Зупиняє воркер."""
        self._stop_flag = True

    def _run(self):
        """
        Тут можна робити ВСЕ важке:
        - send_request()
        - time.sleep()
        - великі цикли
        - мережеві запити
        Це НЕ GUI‑потік, тому нічого не блокує.
        """
        for category, payload_list in self.tester.payloads.items():
            if self._stop_flag:
                break

            for payload in payload_list:
                if self._stop_flag:
                    break

                try:
                    # ВАЖЛИВО: логіка тестера НЕ змінюється
                    response = self.tester.send_request(payload)

                    event = {
                        "type": "result",
                        "payload": payload,
                        "category": category,
                        "response": response,
                    }

                except Exception as e:
                    event = {
                        "type": "error",
                        "payload": payload,
                        "category": category,
                        "error": str(e),
                    }

                # Відправляємо подію в GUI
                self.queue.put(event)

        # Сигнал завершення
        self.queue.put({"type": "done"})
