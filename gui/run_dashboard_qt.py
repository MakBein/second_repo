# xss_security_gui/gui/run_dashboard_qt.py
"""
Security Dashboard ULTRA 6.5 — PyQt Launcher
--------------------------------------------
Автономный запуск панели SecurityDashboardPanel без Tkinter GUI.
Используется для тестирования, отладки и отдельного применения.
"""

import sys
import logging
from pathlib import Path
from PyQt5.QtWidgets import QApplication, QMainWindow

# Централизованные настройки
from xss_security_gui.settings import LOG_DIR, settings
from xss_security_gui.gui.security_dashboard_panel import SecurityDashboardPanel


# ------------------------------------------------------------
#  Логирование (отдельный лог для PyQt-версии)
# ------------------------------------------------------------
QT_LOG_FILE = LOG_DIR / "qt_dashboard.log"
QT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(QT_LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)

logging.info("=== Запуск Security Dashboard ULTRA 6.5 (PyQt) ===")


# ------------------------------------------------------------
#  Главное окно PyQt
# ------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Security Dashboard ULTRA 6.5 — PyQt Edition")
        self.resize(900, 650)

        # Центральная панель
        try:
            panel = SecurityDashboardPanel()
            self.setCentralWidget(panel)
            logging.info("SecurityDashboardPanel успешно загружен.")
        except Exception as e:
            logging.error(f"Ошибка загрузки SecurityDashboardPanel: {e}", exc_info=True)
            raise


# ------------------------------------------------------------
#  Точка входа
# ------------------------------------------------------------
def main():
    try:
        app = QApplication(sys.argv)

        # Тема интерфейса (если включена в settings.json)
        theme = settings.get("gui.theme", "default")
        logging.info(f"PyQt тема интерфейса: {theme}")

        window = MainWindow()
        window.show()

        return app.exec_()

    except Exception as e:
        logging.error(f"Критическая ошибка PyQt Dashboard: {e}", exc_info=True)
        return 1


# ------------------------------------------------------------
#  Запуск через python -m xss_security_gui.gui.run_dashboard_qt
# ------------------------------------------------------------
if __name__ == "__main__":
    sys.exit(main())
