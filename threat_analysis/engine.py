# xss_security_gui/threat_analysis/engine.py
"""
ThreatEngine
------------
Оркестратор для модулей анализа угроз:
• CSPAnalyzer
• DOMEventMapper
• CookieTracer
и любых других подключаемых анализаторов.
"""

import traceback
from typing import Any, Dict

from .csp_module import CSPAnalyzer
from .dom_events_module import DOMEventMapper
from .cookie_tracer import CookieTracer


class ThreatEngine:
    """Управляет запуском всех модулей анализа угроз."""

    def __init__(self) -> None:
        self.modules: Dict[str, Any] = {
            "csp": CSPAnalyzer(),
            "dom": DOMEventMapper(),
            "cookie": CookieTracer(),
        }

    def register_module(self, name: str, module: Any) -> None:
        """Регистрирует новый модуль анализа."""
        self.modules[name] = module

    def run_all(self, page_data: dict) -> Dict[str, Any]:
        """
        Запускает все зарегистрированные модули анализа.

        :param page_data: данные страницы (HTML, заголовки и т.п.)
        :return: словарь с результатами по каждому модулю
        """
        results: Dict[str, Any] = {}
        for name, module in self.modules.items():
            try:
                results[name] = {
                    "status": "success",
                    "data": module.run(page_data),
                }
            except Exception as e:
                results[name] = {
                    "status": "error",
                    "error": str(e),
                    "type": type(e).__name__,
                    "trace": traceback.format_exc(),
                }
        return results