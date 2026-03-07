# xss_security_gui/xss_attacker.py
# ============================================================
#  XSS Attacker ULTRA 5.0
#  • Поддержка ULTRA Hybrid Settings
#  • Auto‑mutation (Mutator ULTRA)
#  • Threat Intel интеграция
#  • TokenBucket 2.0
#  • Rotating User Agents PRO
#  • RetrySession 7.0
# ============================================================

import threading
import time
import random
import html

from xss_security_gui.settings import settings
from xss_security_gui.payloads import get_payloads
from xss_security_gui.utils.network import (
    create_retry_session,
    TokenBucket,
    rotating_user_agents,
    default_accepts,
)
from xss_security_gui.threat_tab_connector import ThreatIntelConnector
from xss_security_gui.payload_mutator import mutate_async


class XSSAttacker:
    def __init__(
        self,
        url,
        method="POST",
        token=None,
        category="basic",
        interval=None,
        timeout=None,
        rps=None,
        proxies=None,
        on_log=None,
        auto_mutate=False,
        threat_intel=True,
    ):
        # --------------------------------------------------------
        #  Настройки ULTRA Hybrid
        # --------------------------------------------------------
        self.url = url
        self.method = method
        self.token = token
        self.category = category

        # Интервал между атаками
        self.interval = interval or settings.get("attack_engine.interval", 5)

        # Таймаут запроса
        self.timeout = timeout or settings.get("attack_engine.timeout", 10)

        # Requests per second
        self.rps = rps or settings.get("attack_engine.rps", 1.0)

        self.running = False
        self.thread = None
        self.on_log = on_log

        # HTTP session
        self.session = create_retry_session(total=7, proxies=proxies)

        # TokenBucket 2.0
        self.bucket = TokenBucket(self.rps)

        # Auto‑mutation
        self.auto_mutate = auto_mutate

        # Threat Intel
        self.threat_enabled = threat_intel and settings.get("threat_enabled", True)
        self.threat = ThreatIntelConnector() if self.threat_enabled else None

    # ============================================================
    #  Управление атакой
    # ============================================================
    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    # ============================================================
    #  Основной цикл атаки
    # ============================================================
    def run(self):
        payloads = get_payloads(self.category)

        if not payloads:
            self._log("[⚠️] Нет доступных payload’ов. Атака не запущена.")
            self.running = False
            return

        # Auto‑mutation ULTRA
        if self.auto_mutate:
            mutated = mutate_async("Reflected", payloads[0], "generic")
            if mutated:
                payloads.extend(mutated)

        index = 0

        while self.running:
            payload = payloads[index % len(payloads)]
            data = {"input": payload}

            headers = {
                "User-Agent": random.choice(rotating_user_agents()),
                "Accept": random.choice(default_accepts()),
            }

            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"

            try:
                self.bucket.wait()

                if self.method == "POST":
                    r = self.session.post(
                        self.url, json=data, headers=headers, timeout=self.timeout
                    )
                else:
                    r = self.session.get(
                        self.url, params=data, headers=headers, timeout=self.timeout
                    )

                # Проверка XSS
                reflected = payload in r.text or payload in html.unescape(r.text)

                if reflected:
                    msg = f"[💥] Успешная XSS: {payload[:40]} → {r.status_code} ({len(r.text)} bytes)"

                    # Threat Intel
                    if self.threat:
                        self.threat.report_xss(self.url, payload, r.status_code)

                else:
                    msg = f"➡️ {payload[:40]} → {r.status_code} ({len(r.text)} bytes)"

            except Exception as e:
                msg = f"[❌ Ошибка] {str(e)}"

            self._log(msg)
            index += 1
            time.sleep(self.interval)

    # ============================================================
    #  Кастомные payload’ы
    # ============================================================
    def start_custom_payloads(self, custom_list):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(
            target=lambda: self.run_custom(custom_list), daemon=True
        )
        self.thread.start()

    def run_custom(self, payloads):
        if not payloads:
            self._log("[⚠️] Список кастомных payload’ов пуст.")
            self.running = False
            return

        while self.running:
            for payload in payloads:
                if not self.running:
                    break

                data = {"input": payload}
                headers = {
                    "User-Agent": random.choice(rotating_user_agents()),
                    "Accept": random.choice(default_accepts()),
                }

                if self.token:
                    headers["Authorization"] = f"Bearer {self.token}"

                try:
                    self.bucket.wait()

                    if self.method == "POST":
                        r = self.session.post(
                            self.url, json=data, headers=headers, timeout=self.timeout
                        )
                    else:
                        r = self.session.get(
                            self.url, params=data, headers=headers, timeout=self.timeout
                        )

                    reflected = payload in r.text or payload in html.unescape(r.text)

                    if reflected:
                        msg = f"[💥] Успешная XSS: {payload[:40]} → {r.status_code} ({len(r.text)} bytes)"
                        if self.threat:
                            self.threat.report_xss(self.url, payload, r.status_code)
                    else:
                        msg = f"➡️ {payload[:40]} → {r.status_code} ({len(r.text)} bytes)"

                except Exception as e:
                    msg = f"[❌ Ошибка] {str(e)}"

                self._log(msg)
                time.sleep(self.interval)

    # ============================================================
    #  Логирование
    # ============================================================
    def _log(self, msg):
        if self.on_log:
            self.on_log(msg)