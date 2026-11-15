# xss_security_gui/gui/run_dashboard_qt.py
"""
Security Dashboard — Standalone Launcher (7.0, Tkinter Edition)
==============================================================
Автономный запуск SecurityDashboardPanel без основного GUI.
Используется для тестирования, отладки и отдельного применения.

История: файл назывался «PyQt Launcher», но SecurityDashboardPanel — это
``tkinter.Frame``. PyQt-версия физически не могла работать
(``QMainWindow.setCentralWidget`` не принимает tk-виджет, а панель к тому же
конструировалась без обязательных аргументов ``ui``/``threat_monitor``).
Лаунчер переписан на чистом Tkinter и теперь действительно запускается.

Запуск:  python -m xss_security_gui.gui.run_dashboard_qt
"""

from __future__ import annotations

import sys
import logging
import tkinter as tk
from tkinter import ttk

# Централизованные настройки
from xss_security_gui.settings import LOG_DIR, settings
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge
from threat_analysis.live_attack_monitor import LiveAttackMonitor
from xss_security_gui.gui.security_dashboard_panel import SecurityDashboardPanel


# ------------------------------------------------------------
#  Логирование (отдельный лог для standalone-версии)
# ------------------------------------------------------------
DASHBOARD_LOG_FILE = LOG_DIR / "dashboard_standalone.log"
DASHBOARD_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(DASHBOARD_LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)

_logger = logging.getLogger(__name__)


# ------------------------------------------------------------
#  Главное окно (Tkinter)
# ------------------------------------------------------------
class DashboardWindow(tk.Tk):
    """Автономное окно, хостящее SecurityDashboardPanel со всеми зависимостями."""

    def __init__(self) -> None:
        super().__init__()

        self.title("Security Dashboard — Standalone Edition")
        self.geometry("900x650")

        theme = settings.get("gui.theme", "default") if hasattr(settings, "get") else "default"
        _logger.info("Тема интерфейса: %s", theme)

        # Зависимости панели: UIQueueBridge (thread-safe обновления GUI) и
        # LiveAttackMonitor (источник heatmap / timeline / chains).
        self.ui_bridge = UIQueueBridge(self, poll_ms=100)
        self.monitor = LiveAttackMonitor(self.ui_bridge)

        try:
            self.panel = SecurityDashboardPanel(
                self,
                ui=self.ui_bridge,
                threat_monitor=self.monitor,
            )
            self.panel.pack(fill="both", expand=True)
            _logger.info("SecurityDashboardPanel успешно загружен.")
        except Exception as e:  # pragma: no cover - defensive UI fallback
            _logger.error("Ошибка загрузки SecurityDashboardPanel: %s", e, exc_info=True)
            fallback = ttk.Frame(self)
            fallback.pack(fill="both", expand=True)
            ttk.Label(
                fallback,
                text=f"Security Dashboard unavailable:\n{e}",
                justify="center",
            ).pack(expand=True)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self) -> None:
        try:
            self.ui_bridge.stop()
        except Exception:
            pass
        self.destroy()


# ------------------------------------------------------------
#  Точка входа
# ------------------------------------------------------------
def main() -> int:
    _logger.info("=== Запуск Security Dashboard (standalone) ===")
    try:
        window = DashboardWindow()
        window.mainloop()
        return 0
    except Exception as e:  # pragma: no cover
        _logger.error("Критическая ошибка Dashboard: %s", e, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
