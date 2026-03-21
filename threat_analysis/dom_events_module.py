# xss_security_gui/threat_analysis/dom_events_module.py
"""
DOMEventMapper (ULTRA Hybrid 6.5)
---------------------------------
• Анализирует JavaScript-код на наличие DOM-событий
• Определяет опасные DOM-синки (innerHTML, eval, write, insertAdjacentHTML)
• Строит карту событий → потенциальных уязвимостей
• Возвращает унифицированный Threat Intel-friendly результат
"""

from typing import Any, Dict, List


class DOMEventMapper:
    """Модуль анализа DOM-событий и опасных конструкций."""

    DEFAULT_EVENTS = [
        "click", "input", "submit", "mouseover", "keydown", "change",
        "keyup", "dblclick", "contextmenu", "touchstart", "touchend",
    ]

    DANGEROUS_SINKS = [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "document.writeln",
        "eval(",
        "Function(",
        "setTimeout(",
        "setInterval(",
    ]

    def __init__(self, events: List[str] | None = None) -> None:
        self.events = events if events is not None else self.DEFAULT_EVENTS

    # ---------------------------------------------------------
    # Основной метод
    # ---------------------------------------------------------
    def run(self, page_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Анализирует скрипты страницы на наличие DOM-событий и опасных конструкций.

        :param page_data: словарь с ключами "dom" и "scripts"
        :return: словарь с найденными событиями и рисками
        """
        scripts = page_data.get("scripts", [])
        results: List[Dict[str, Any]] = []

        for script in scripts:
            code = script.get("content", "") or ""
            lower = code.lower()

            # === Поиск событий ===
            for event_type in self.events:
                if event_type in lower:
                    sink_hits = self._find_sinks(code)
                    risk = self._assess_risk(sink_hits)

                    results.append({
                        "event": event_type,
                        "snippet": code[:200],
                        "sinks": sink_hits,
                        "risk": risk,
                    })

            # === Если нет событий, но есть опасные синки ===
            sink_hits = self._find_sinks(code)
            if sink_hits:
                results.append({
                    "event": None,
                    "snippet": code[:200],
                    "sinks": sink_hits,
                    "risk": self._assess_risk(sink_hits),
                })

        return {
            "status": "success",
            "events_detected": len(results),
            "results": results,
        }

    # ---------------------------------------------------------
    # Поиск опасных DOM-синков
    # ---------------------------------------------------------
    def _find_sinks(self, code: str) -> List[str]:
        found = []
        lower = code.lower()

        for sink in self.DANGEROUS_SINKS:
            if sink.lower() in lower:
                found.append(sink)

        return found

    # ---------------------------------------------------------
    # Оценка риска
    # ---------------------------------------------------------
    def _assess_risk(self, sinks: List[str]) -> str:
        """
        Оценка риска по наличию опасных DOM-синков.
        """
        if any(s in sinks for s in ["eval(", "Function("]):
            return "HIGH"

        if any(s in sinks for s in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"]):
            return "MEDIUM"

        if sinks:
            return "LOW"

        return "LOW"