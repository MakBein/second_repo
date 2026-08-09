# xss_security_gui/integrations/threat_data_integration.py
"""
Интеграция Threat Data Loader с GUI при запуске

Загружает analyzer1.json в Threat Tab автоматически
"""

import threading
from typing import TYPE_CHECKING
from xss_security_gui.threat_data_loader import ThreatDataLoader, load_threat_data_to_gui

if TYPE_CHECKING:
    from xss_security_gui.threat_tab import ThreatAnalysisTab


def load_threat_data_background(threat_tab: 'ThreatAnalysisTab') -> None:
    """
    Загружает данные в фоновом потоке для неблокирования UI

    :param threat_tab: экземпляр ThreatAnalysisTab
    """
    def worker():
        try:
            count = load_threat_data_to_gui(threat_tab)
            if count > 0:
                print(f"[✅] Загружено {count} артефактов в Threat Tab")
            else:
                print("[⚠️] Нет артефактов для загрузки")
        except Exception as e:
            print(f"[❌] Ошибка загрузки данных: {e}")

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()


def load_threat_data_sync(threat_tab: 'ThreatAnalysisTab') -> int:
    """
    Синхронно загружает данные (блокирует UI)

    :param threat_tab: экземпляр ThreatAnalysisTab
    :return: количество загруженных артефактов
    """
    return load_threat_data_to_gui(threat_tab)


def initialize_threat_intel_on_startup(threat_tab: 'ThreatAnalysisTab', async_mode: bool = True) -> None:
    """
    Инициализирует Threat Intel данные при запуске GUI.
    Может работать синхронно или асинхронно.

    :param threat_tab: экземпляр ThreatAnalysisTab
    :param async_mode: если True, загружает в фоновом потоке
    """
    if async_mode:
        load_threat_data_background(threat_tab)
    else:
        load_threat_data_sync(threat_tab)


if __name__ == "__main__":
    # Для тестирования
    print("[🧪] Test: Threat Data Integration")

    loader = ThreatDataLoader()
    if loader.load():
        print(f"[✅] Загружено {len(loader.artifacts)} артефактов")

        # Пример: вывести Email Leaks
        email_leaks = loader.get_email_leaks()
        print(f"[📧] Email Leaks: {len(email_leaks)}")
        for leak in email_leaks:
            gui_artifact = loader.convert_artifact_for_gui(leak)
            print(f"  - {gui_artifact['category']} ({gui_artifact['risk']})")
    else:
        print("[⚠️] Не удалось загрузить данные")

