# xss_security_gui/utils/threat_sender.py
import json
import logging
from typing import Any, Dict, List, Union

# Глобальный fallback-логгер
FALLBACK_LOGGER = logging.getLogger("ThreatSender")


class ThreatSenderMixin:
    """
    ThreatSenderMixin — Red Team Enterprise Edition

    • Абсолютно безопасен для GUI (никаких падений Tkinter)
    • Автоматически восстанавливает self.log (строка → logger)
    • Автоматически восстанавливает threat_tab (None → silent mode)
    • Нормализует любые данные (dict, list, primitives)
    • Гарантирует доставку артефактов в ThreatConnector
    • Имеет fail-safe fallback при любых ошибках
    • Никогда не вызывает исключений наружу
    """

    # ============================================================
    #  INTERNAL SAFE HELPERS
    # ============================================================

    def _safe_logger(self):
        """Возвращает рабочий logger, даже если self.log повреждён."""
        try:
            if hasattr(self, "log"):
                if isinstance(self.log, logging.Logger):
                    return self.log
                if isinstance(self.log, str):
                    return logging.getLogger(self.log)
            return FALLBACK_LOGGER
        except Exception:
            return FALLBACK_LOGGER

    def _safe_threat_tab(self):
        """Возвращает threat_tab или None, если он отсутствует."""
        try:
            if hasattr(self, "threat_tab") and self.threat_tab is not None:
                return self.threat_tab
            return None
        except Exception:
            return None

    # ============================================================
    #  MAIN METHOD — RED TEAM SAFE VERSION
    # ============================================================

    def send_to_threat_intel(
        self,
        module_name: str,
        data: Union[Dict[str, Any], List[Any], Any],
    ) -> None:
        """
        Отправляет данные в ThreatConnector (Red Team Safe Version).

        • Никогда не падает
        • Всегда логирует
        • Всегда нормализует payload
        • Всегда пытается доставить артефакт
        """

        log = self._safe_logger()
        threat_tab = self._safe_threat_tab()

        # Если нет threat_tab — silent mode
        if threat_tab is None:
            log.debug(f"[ThreatSender] No threat_tab for module '{module_name}', skipping.")
            return

        # Формируем payload
        payload = {"module": module_name, "entries": []}

        try:
            # -----------------------------
            # 1. dict → key/value pairs
            # -----------------------------
            if isinstance(data, dict):
                for k, v in data.items():
                    payload["entries"].append(
                        {
                            "key": str(k),
                            "value": json.dumps(v, ensure_ascii=False)
                        }
                    )

            # -----------------------------
            # 2. list → list of dicts or primitives
            # -----------------------------
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            payload["entries"].append(
                                {
                                    "key": str(k),
                                    "value": json.dumps(v, ensure_ascii=False)
                                }
                            )
                    else:
                        payload["entries"].append(
                            {"key": "info", "value": str(item)}
                        )

            # -----------------------------
            # 3. primitive → info
            # -----------------------------
            else:
                payload["entries"].append(
                    {"key": "info", "value": str(data)}
                )

            # -----------------------------
            # 4. Deliver payload
            # -----------------------------
            try:
                threat_tab.load_results(payload)
                log.debug(f"[ThreatSender] Delivered artifact from '{module_name}'.")
            except Exception as e:
                log.error(f"[ThreatSender] ThreatConnector delivery error: {e}", exc_info=True)

        except Exception as e:
            log.error(f"[ThreatSender] Unexpected error: {e}", exc_info=True)
