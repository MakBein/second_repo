# xss_security_gui/payloads.py
"""
PayloadManager 6.5 — ULTRA Edition
----------------------------------

Особенности:
• SQLite backend (авто‑инициализация, авто‑миграции)
• In‑memory cache (мгновенный доступ)
• Гибкая конфигурация через settings (ULTRA Hybrid)
• ThreatConnector интеграция (payload_stats, payload_added)
• Совместимость с Mutator ULTRA, AttackEngine 5.0, ExploitTab
• Автоматическая миграция legacy‑категорий
• Автоматическое создание базы, если отсутствует
"""

from __future__ import annotations

import sqlite3
import random
import logging
from pathlib import Path
from typing import Dict, List, Optional

from xss_security_gui.settings import settings, PAYLOADS_DIR
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR

log = logging.getLogger("PayloadManager")


# ============================================================
#  Категории payload’ов (единый источник правды)
# ============================================================

PAYLOAD_CATEGORIES: List[str] = [
    "Reflected",
    "Stored",
    "DOM",
    "Polyglot",
    "Bypass",
    "WAF",
    "EventHandlers",
    "SVG",
    "URL",
    "Unicode",
    "TemplateInjection",
    "FrameworkSpecific",
]

LEGACY_CATEGORIES = [
    "Reflected",
    "Stored",
    "DOM-based",
    "Obfuscated",
    "Event",
    "Attribute",
]


# ============================================================
#  PayloadManager 6.5
# ============================================================

class PayloadManager:
    def __init__(self, db_path: Path):
        # SQLite файл
        self.db_path = db_path.with_suffix(".db")

        # In‑memory cache
        self.cache: Dict[str, List[str]] = {cat: [] for cat in PAYLOAD_CATEGORIES}

        self._init_db()
        self._load_cache()

    # --------------------------------------------------------
    #  Инициализация SQLite
    # --------------------------------------------------------
    def _init_db(self) -> None:
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS payloads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    payload TEXT NOT NULL UNIQUE
                )
            """)
            conn.commit()
        except Exception as e:
            log.error(f"[PayloadManager] DB init error: {e}")
        finally:
            conn.close()

    # --------------------------------------------------------
    #  Загрузка в кэш
    # --------------------------------------------------------
    def _load_cache(self) -> None:
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.execute("SELECT category, payload FROM payloads")

            for category, payload in cur.fetchall():
                if category in self.cache:
                    self.cache[category].append(payload)
                else:
                    # Миграция legacy‑категорий
                    if category in LEGACY_CATEGORIES:
                        mapped = "Reflected"
                        self.cache[mapped].append(payload)
                        log.warning(f"[PayloadManager] Migrated legacy category '{category}' → '{mapped}'")
                    else:
                        log.warning(f"[PayloadManager] Unknown category in DB: {category}")

            total = sum(len(v) for v in self.cache.values())
            log.info(f"[PayloadManager] Cache loaded: {total} payloads")

        except Exception as e:
            log.error(f"[PayloadManager] Cache load error: {e}")
        finally:
            conn.close()

    # --------------------------------------------------------
    #  Получение payload’ов категории
    # --------------------------------------------------------
    def get(self, category: str, default=None) -> List[str]:
        """
        Совместимость с dict.get(category, default)
        Используется в analyzer.py и других модулях.
        """
        if default is None:
            default = []
        return self.cache.get(category, default)

    # --------------------------------------------------------
    #  Проверка существования payload’а
    # --------------------------------------------------------
    def exists(self, category: str, payload: str) -> bool:
        return payload in self.cache.get(category, [])

    # --------------------------------------------------------
    #  Случайный payload
    # --------------------------------------------------------
    def random(self, category: str = "Reflected") -> str:
        items = self.get(category)
        if not items:
            return "<script>alert(1)</script>"
        return random.choice(items)

    # --------------------------------------------------------
    #  Добавление payload’а
    # --------------------------------------------------------
    def add(self, category: str, payload: str) -> bool:
        if category not in self.cache:
            log.warning(f"[PayloadManager] Unknown category: {category}")
            return False

        if payload in self.cache[category]:
            return False

        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "INSERT INTO payloads (category, payload) VALUES (?, ?)",
                (category, payload)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return False
        except Exception as e:
            log.error(f"[PayloadManager] DB insert error: {e}")
            return False
        finally:
            conn.close()

        # Обновляем кэш
        self.cache[category].append(payload)

        # Threat Intel событие
        THREAT_CONNECTOR.emit(
            module="PayloadManager6.5",
            target="payload_database",
            result={
                "severity": "info",
                "category": "payload_added",
                "payload": payload,
                "payload_category": category,
            },
        )

        return True

    # --------------------------------------------------------
    #  Статистика
    # --------------------------------------------------------
    def stats(self) -> Dict[str, int]:
        return {cat: len(self.cache.get(cat, [])) for cat in PAYLOAD_CATEGORIES}

    # --------------------------------------------------------
    #  Список категорий
    # --------------------------------------------------------
    def get_categories(self) -> List[str]:
        return list(PAYLOAD_CATEGORIES)

    # --------------------------------------------------------
    #  Threat Intel: экспорт статистики
    # --------------------------------------------------------
    def export_stats_to_threat_intel(self) -> None:
        stats = self.stats()

        THREAT_CONNECTOR.emit(
            module="PayloadManager6.5",
            target="payload_database",
            result={
                "severity": "info",
                "category": "payload_stats",
                "stats": stats,
                "total": sum(stats.values()),
            },
        )

        log.info("[PayloadManager] Stats exported to ThreatConnector")


# ============================================================
#  Глобальный экземпляр
# ============================================================

# Новый путь к базе payload’ов
PAYLOAD_DB_PATH = PAYLOADS_DIR / "payload_db"

PAYLOADS = PayloadManager(PAYLOAD_DB_PATH)

# Совместимость с предыдущими версиями
get_payloads = PAYLOADS.get
get_random_payload = PAYLOADS.random
add_payload = PAYLOADS.add
get_stats = PAYLOADS.stats
get_categories = PAYLOADS.get_categories
load_payloads = lambda: None

# ============================================================
#  Универсальный генератор payload’ов
# ============================================================

def generate_payloads() -> Dict[str, List[str]]:
    """
    Возвращает словарь всех payload’ов по категориям.
    Используется в GUI (например, ExploitTab, SiteMapTab).
    """
    return {cat: PAYLOADS.get(cat, []) for cat in PAYLOADS.get_categories()}

def gen_payloads_from_templates() -> dict[str, list[str]]:
    """
    Генерирует словарь payload’ов по категориям из базы PayloadManager.
    Используется в ExploitTab и других GUI-компонентах.
    """
    return {
        cat: PAYLOADS.get(cat, [])
        for cat in PAYLOADS.get_categories()
    }