# xss_security_gui/threat_analysis/engine.py
"""
ThreatEngine 11.0 — Combat Edition
==================================
Оркестратор для модулів аналізу загроз:
• CSPAnalyzer 11.0
• DOMEventMapper 11.0
• CookieTracer 11.0
• DOMXSSDetector 11.0 (якщо підключено)
• Plug-and-play модулі
• Повністю fault-tolerant
• Асинхронний safe‑wait без блокування GUI
• ThreatConnector-friendly структура
"""

from __future__ import annotations

import traceback
import time
from typing import Any, Dict

from .csp_module import CSPAnalyzer
from .dom_events_module import DOMEventMapper
from .cookie_tracer import CookieTracer


class ThreatEngine:
    """Управляє запуском всіх модулів аналізу загроз (стабільний, розширюваний, бойовий)."""

    def __init__(self) -> None:
        # Модулі повинні мати run(page_data) або run_async(page_data, callback)
        self.modules: Dict[str, Any] = {
            "csp": CSPAnalyzer(),
            "dom_events": DOMEventMapper(),
            "cookie": CookieTracer(),
        }

    # ---------------------------------------------------------
    # Реєстрація модулів
    # ---------------------------------------------------------
    def register_module(self, name: str, module: Any) -> None:
        """
        Реєструє новий модуль аналізу.
        Модуль повинен мати run(page_data) або run_async(page_data, callback).
        """
        self.modules[name] = module

    # ---------------------------------------------------------
    # Запуск всіх модулів
    # ---------------------------------------------------------
    def run_all(self, page_data: dict) -> Dict[str, Any]:
        """
        Запускає всі зареєстровані модулі аналізу.

        :param page_data: дані сторінки (HTML, заголовки, скрипти)
        :return: словник з результатами по кожному модулю
        """
        results: Dict[str, Any] = {}

        for name, module in self.modules.items():
            try:
                # === Асинхронний модуль ===
                if hasattr(module, "run_async"):
                    container = {"done": False, "result": None}

                    def callback(res):
                        container["done"] = True
                        container["result"] = res

                    module.run_async(page_data, callback)

                    # Safe‑wait: не блокує GUI, не зависає
                    for _ in range(300):
                        if container["done"]:
                            break
                        time.sleep(0.01)

                    results[name] = {
                        "status": "success",
                        "data": container["result"],
                    }
                    continue

                # === Синхронний модуль ===
                if hasattr(module, "run") and callable(module.run):
                    data = module.run(page_data)
                    results[name] = {
                        "status": "success",
                        "data": data,
                    }
                else:
                    results[name] = {
                        "status": "error",
                        "error": f"Module '{name}' has no run() method",
                    }

            except Exception as e:
                # Модуль упав — але ThreatEngine і GUI продовжують працювати
                results[name] = {
                    "status": "error",
                    "error": str(e),
                    "type": type(e).__name__,
                    "trace": traceback.format_exc(),
                }

        return results

    # ---------------------------------------------------------
    # Запуск одного модуля
    # ---------------------------------------------------------
    def run_single(self, name: str, page_data: dict) -> Dict[str, Any]:
        """
        Запускає один модуль за ім'ям.
        """
        module = self.modules.get(name)
        if not module:
            return {
                "status": "error",
                "error": f"Module '{name}' not found",
            }

        try:
            if hasattr(module, "run"):
                return {
                    "status": "success",
                    "data": module.run(page_data),
                }
            return {
                "status": "error",
                "error": f"Module '{name}' has no run() method",
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "type": type(e).__name__,
                "trace": traceback.format_exc(),
            }
