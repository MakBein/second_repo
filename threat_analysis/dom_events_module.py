# xss_security_gui/threat_analysis/dom_events_module.py
"""
DOMEventMapper
--------------
Анализирует JavaScript-код на наличие событий DOM
и потенциально опасных конструкций.
"""

from typing import Any, Dict, List


class DOMEventMapper:
    """Модуль анализа DOM-событий в скриптах."""

    DEFAULT_EVENTS = ["click", "input", "submit", "mouseover", "keydown", "change"]

    def __init__(self, events: List[str] | None = None) -> None:
        self.events = events if events is not None else self.DEFAULT_EVENTS

    def run(self, page_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Анализирует скрипты страницы на наличие DOM-событий.

        :param page_data: словарь с ключами "dom" и "scripts"
        :return: словарь с найденными событиями
        """
        scripts = page_data.get("scripts", [])
        results: List[Dict[str, Any]] = []

        for script in scripts:
            code = script.get("content", "")
            for event_type in self.events:
                if event_type in code:
                    risk = self._assess_risk(code)
                    results.append({
                        "type": event_type,
                        "snippet": code[:120],  # показываем первые 120 символов
                        "risk": risk,
                    })

        return {
            "status": "success",
            "events": results,
        }

    @staticmethod
    def _assess_risk(code: str) -> str:
        """Простейшая оценка риска по содержимому кода."""
        if "eval(" in code or "Function(" in code:
            return "HIGH"
        elif "innerHTML" in code or "document.write" in code:
            return "MEDIUM"
        return "LOW"