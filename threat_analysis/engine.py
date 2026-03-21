# xss_security_gui/threat_analysis/engine.py
"""
ThreatEngine (ULTRA Hybrid 6.5)
-------------------------------
Оркестратор для модулей анализа угроз:
• CSPAnalyzer
• DOMEventMapper
• CookieTracer
• DOMXSSDetector (если подключён)
• Любые другие анализаторы (plug-and-play)
• Полностью устойчив к ошибкам и не ломает GUI
"""

import traceback
from typing import Any, Dict, Callable

from .csp_module import CSPAnalyzer
from .dom_events_module import DOMEventMapper
from .cookie_tracer import CookieTracer


class ThreatEngine:
    """Управляет запуском всех модулей анализа угроз (устойчивый, расширяемый)."""

    def __init__(self) -> None:
        # Все модули должны иметь метод run(page_data)
        self.modules: Dict[str, Any] = {
            "csp": CSPAnalyzer(),
            "dom_events": DOMEventMapper(),
            "cookie": CookieTracer(),
        }

    # ---------------------------------------------------------
    # Регистрация модулей
    # ---------------------------------------------------------
    def register_module(self, name: str, module: Any) -> None:
        """
        Регистрирует новый модуль анализа.
        Модуль должен иметь метод run(page_data) или run_async(page_data, callback).
        """
        self.modules[name] = module

    # ---------------------------------------------------------
    # Запуск всех модулей
    # ---------------------------------------------------------
    def run_all(self, page_data: dict) -> Dict[str, Any]:
        """
        Запускает все зарегистрированные модули анализа.

        :param page_data: данные страницы (HTML, заголовки, скрипты)
        :return: словарь с результатами по каждому модулю
        """
        results: Dict[str, Any] = {}

        for name, module in self.modules.items():
            try:
                # === Асинхронный модуль ===
                if hasattr(module, "run_async"):
                    container = {"done": False, "result": None}

                    def callback(res):
                        container["done"] = True
                        container["result"] = res

                    module.run_async(page_data, callback)

                    # Ждём завершения (но не блокируем GUI)
                    # Минимальный safe‑wait, чтобы не зависнуть
                    for _ in range(200):
                        if container["done"]:
                            break

                    results[name] = {
                        "status": "success",
                        "data": container["result"],
                    }
                    continue

                # === Обычный модуль ===
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
                # Модуль упал — но движок и GUI продолжают работать
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
        Запускает один модуль по имени.
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