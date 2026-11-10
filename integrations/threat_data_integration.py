# xss_security_gui/integrations/threat_data_integration.py
"""
Threat Data Integration 11.0 GOD‑MODE

Интеграция ThreatDataLoader / PII Aggregator / Email Leak Engine с GUI при запуске.

Возможности:
  - Асинхронная загрузка analyzer1.json (не блокирует UI)
  - Загрузка PII из crawler_results.json в Email Leak панель
  - Безопасная работа с ThreatAnalysisTab (проверка winfo_exists)
  - Ретраи при ошибках, телеметрия попыток
  - Парсинг Email Leak, Credit Card, Password, User Data и других артефактов
  - Полная поддержка ThreatDataLoader.get_email_leaks()
"""

import json
import threading
import time
import logging
from pathlib import Path
from typing import TYPE_CHECKING, List, Dict, Any

from xss_security_gui.settings import JSON_CRAWL_EXPORT_PATH
from xss_security_gui.threat_data_loader import ThreatDataLoader, load_threat_data_to_gui
from xss_security_gui.utils.pii_aggregator import (
    aggregate_pii_from_crawler,
    build_email_leak_artifact,
    pii_has_data,
)

if TYPE_CHECKING:
    from xss_security_gui.threat_tab import ThreatAnalysisTab

logger = logging.getLogger(__name__)


# ============================================================
#  Загрузка PII из crawler_results.json
# ============================================================

def load_crawler_pii_to_gui(threat_tab: "ThreatAnalysisTab", json_path: Path | None = None) -> int:
    """Загружает PII из crawler_results.json в Email Leak панель."""
    path = Path(json_path or JSON_CRAWL_EXPORT_PATH)
    if not path.exists():
        logger.info("[Email Leak] crawler_results.json не найден: %s", path)
        return 0

    try:
        with open(path, encoding="utf-8") as f:
            result = json.load(f)
    except Exception as e:
        logger.warning("[Email Leak] не удалось прочитать %s: %s", path, e)
        print(f"[⚠️] Email Leak: не удалось прочитать {path}: {e}")
        return 0

    pii = aggregate_pii_from_crawler(result)
    if not pii_has_data(pii):
        logger.info("[Email Leak] PII отсутствуют в crawler_results.json")
        return 0

    target = result.get("root") or result.get("url") or str(path)
    artifact = build_email_leak_artifact(pii, target_url=str(target), source="crawler_json")
    if not artifact:
        logger.info("[Email Leak] не удалось построить email_leak артефакт из crawler_results.json")
        return 0

    bridge = getattr(threat_tab, "_bridge", None)
    if bridge is not None and hasattr(bridge, "post_ui"):
        bridge.post_ui(threat_tab.ingest_crawl_result, result)
    else:
        threat_tab.after(0, lambda: threat_tab.ingest_crawl_result(result))

    logger.info("[Email Leak] PII загружены из crawler_results.json в Threat Tab")
    print(f"[✅] Email Leak: PII загружены из crawler_results.json")
    return 1


# ============================================================
#  Асинхронная загрузка Threat Intel
# ============================================================

def load_threat_data_background(threat_tab: "ThreatAnalysisTab", retries: int = 3) -> None:
    """
    Загружает данные в фоновом потоке для неблокирования UI.
    """

    def worker():
        for attempt in range(1, retries + 1):
            try:
                if not threat_tab.winfo_exists():
                    msg = "[⚠️] Threat Tab был закрыт, прерываем загрузку"
                    logger.warning(msg)
                    print(msg)
                    return

                logger.info("[Threat Data] Email Leak Integration: попытка %d/%d", attempt, retries)
                print(f"[📦] Email Leak Integration: попытка {attempt}/{retries}")

                # 1) analyzer1.json → Threat Tab
                count = load_threat_data_to_gui(threat_tab)

                if count > 0:
                    logger.info("[Threat Data] Успешно загружено %d артефактов в Threat Tab", count)
                    print(f"[✅] Успешно загружено {count} артефактов в Threat Tab")
                else:
                    logger.info("[Threat Data] analyzer1.json пуст — пробуем crawler_results.json")
                    print("[⚠️] analyzer1.json пуст — пробуем crawler_results.json")

                # 2) crawler_results.json → Email Leak панель
                crawler_count = load_crawler_pii_to_gui(threat_tab)
                if crawler_count:
                    logger.info("[Threat Data] Email Leak: PII загружены из crawler_results.json")

                if count > 0 or crawler_count:
                    return

                logger.info("[Threat Data] Нет артефактов для загрузки (analyzer1.json + crawler_results.json)")
                print("[⚠️] Нет артефактов для загрузки")
                return

            except Exception as e:
                logger.exception("[Threat Data] Попытка %d: ошибка загрузки данных: %s", attempt, e)
                print(f"[❌] Попытка {attempt}: ошибка загрузки данных: {e}")
                if attempt < retries:
                    time.sleep(0.5)
                else:
                    logger.error("[Threat Data] Не удалось загрузить Email Leak данные после всех попыток")
                    print("[❌] Не удалось загрузить Email Leak данные после всех попыток")
                    return

    thread = threading.Thread(target=worker, daemon=True, name="ThreatDataBackgroundLoader")
    thread.start()


# ============================================================
#  Синхронная загрузка Threat Intel
# ============================================================

def load_threat_data_sync(threat_tab: "ThreatAnalysisTab") -> int:
    """Синхронно загружает analyzer1.json (блокирует UI)."""
    logger.info("[Threat Data] Синхронная загрузка analyzer1.json в Threat Tab")
    return load_threat_data_to_gui(threat_tab)


# ============================================================
#  Инициализация Threat Intel при запуске GUI
# ============================================================

def initialize_threat_intel_on_startup(threat_tab: "ThreatAnalysisTab", async_mode: bool = True) -> None:
    """
    Инициализирует Threat Intel данные при запуске GUI.
    """
    if threat_tab is None:
        msg = "[⚠️] Email Leak Integration: threat_tab is None, skipping"
        logger.warning(msg)
        print(msg)
        return

    if async_mode:
        logger.info("[Threat Data] Инициализация Threat Intel (async mode)")
        load_threat_data_background(threat_tab, retries=3)
    else:
        logger.info("[Threat Data] Инициализация Threat Intel (sync mode)")
        load_threat_data_sync(threat_tab)


# ============================================================
#  Тестовый режим
# ============================================================

if __name__ == "__main__":
    print("[🧪] Test: Threat Data Integration")

    loader = ThreatDataLoader()
    if loader.load():
        print(f"[✅] Загружено {len(loader.artifacts)} артефактов")

        # Полноценный встроенный метод get_email_leaks()
        email_leaks = loader.get_email_leaks()
        print(f"[📧] Email Leaks: {len(email_leaks)}")

        for leak in email_leaks:
            gui_artifact = loader.convert_artifact_for_gui(leak)
            if not gui_artifact:
                continue
            print(f"  - {gui_artifact['category']} ({gui_artifact['risk']})")

    else:
        print("[⚠️] Не удалось загрузить данные")





