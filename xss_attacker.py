# xss_security_gui/xss_attacker.py
# ============================================================
#  XSS Attacker ULTRA 6.5+
#  • ULTRA Hybrid Settings
#  • Auto‑mutation (Mutator ULTRA)
#  • Threat Intel інтеграція
#  • TokenBucket 2.0
#  • Rotating User Agents PRO
#  • RetrySession 7.0
# ============================================================

import threading
import time
import random
import html
from typing import Callable, List, Optional, Any

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
        url: str,
        method: str = "POST",
        token: Optional[str] = None,
        category: str = "basic",
        interval: Optional[float] = None,
        timeout: Optional[float] = None,
        rps: Optional[float] = None,
        proxies: Optional[dict] = None,
        on_log: Optional[Callable[[str], None]] = None,
        auto_mutate: bool = False,
        threat_intel: bool = True,
    ) -> None:
        # --------------------------------------------------------
        #  Настройки ULTRA Hybrid
        # --------------------------------------------------------
        self.url = url
        self.method = method.upper()
        self.token = token
        self.category = category

        # Интервал между атаками
        self.interval: float = float(interval or settings.get("attack_engine.interval", 5.0))

        # Таймаут запроса
        self.timeout: float = float(timeout or settings.get("attack_engine.timeout", 10.0))

        # Requests per second
        self.rps: float = float(rps or settings.get("attack_engine.rps", 1.0))

        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.on_log = on_log

        # HTTP session
        self.session = create_retry_session(total=7, proxies=proxies)

        # TokenBucket 2.0
        self.bucket = TokenBucket(self.rps)

        # Auto‑mutation
        self.auto_mutate = auto_mutate

        # Threat Intel
        self.threat_enabled = bool(threat_intel and settings.get("threat_enabled", True))
        self.threat = ThreatIntelConnector() if self.threat_enabled else None

    # ============================================================
    #  Управление атакой
    # ============================================================
    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.running = False

    # ============================================================
    #  Основной цикл атаки
    # ============================================================
    def run(self) -> None:
        payloads: List[str] = get_payloads(self.category)

        if not payloads:
            self._log("[⚠️] Нет доступных payload’ов. Атака не запущена.")
            self.running = False
            return

        # Auto‑mutation ULTRA
        if self.auto_mutate:
            try:
                mutated = mutate_async("Reflected", payloads[0], "generic")
                if mutated:
                    payloads.extend(mutated)
                    self._log(f"[🧬] Auto‑mutation: добавлено {len(mutated)} payload’ов")
            except Exception as e:
                self._log(f"[⚠️] Auto‑mutation ошибка: {e}")

        index = 0

        while self.running:
            payload = payloads[index % len(payloads)]
            msg = self._attack_single(payload)
            self._log(msg)
            index += 1
            time.sleep(self.interval)

    def _attack_single(self, payload: str) -> str:
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
                r = self.session.post(self.url, json=data, headers=headers, timeout=self.timeout)
            else:
                r = self.session.get(self.url, params=data, headers=headers, timeout=self.timeout)

            body = r.text
            reflected = payload in body or payload in html.unescape(body)
            length = len(body)

            if reflected:
                msg = f"[💥] Успешная XSS: {payload[:40]} → {r.status_code} ({length} bytes)"

                if self.threat:
                    try:
                        self.threat.report_xss(self.url, payload, r.status_code)
                    except Exception as e:
                        self._log(f"[⚠️] Threat Intel ошибка: {e}")
            else:
                msg = f"➡️ {payload[:40]} → {r.status_code} ({length} bytes)"

        except Exception as e:
            msg = f"[❌ Ошибка] {e}"

        return msg

    # ============================================================
    #  Кастомные payload’ы
    # ============================================================
    def start_custom_payloads(self, custom_list: List[str]) -> None:
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(
            target=lambda: self.run_custom(custom_list),
            daemon=True,
        )
        self.thread.start()

    def run_custom(self, payloads: List[str]) -> None:
        if not payloads:
            self._log("[⚠️] Список кастомных payload’ов пуст.")
            self.running = False
            return

        while self.running:
            for payload in payloads:
                if not self.running:
                    break
                msg = self._attack_single(payload)
                self._log(msg)
                time.sleep(self.interval)

    # ============================================================
    #  Логирование
    # ============================================================
    def _log(self, msg: str) -> None:
        if not self.on_log:
            return
        try:
            self.on_log(msg)
        except Exception:
            # Логгер не должен ломать атаку
            pass