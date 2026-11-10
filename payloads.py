# xss_security_gui/payloads.py
"""
PayloadManager 7.1 — Enterprise Attack/Canary Edition
-----------------------------------------------------

Особенности:
• Два режима работы: Canary Mode и Real Attack Mode
• Real Attack Mode загружает реальные payload’ы из локального файла real_payloads.txt
• Canary Mode использует безопасные тестовые payload’ы
• SQLite backend + in‑memory cache
• ThreatConnector интеграция
• Совместимость с Mutator ULTRA, CombatAttackEngine, ExploitTab
• Автоматическая миграция legacy‑категорий
"""

from __future__ import annotations

import sqlite3
import random
import logging
from pathlib import Path
from typing import Dict, List

from xss_security_gui.settings import settings, PAYLOADS_DIR
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR

log = logging.getLogger("PayloadManager")

# --------------------------------------------------------
#  Режимы работы
# --------------------------------------------------------

USE_REAL_ATTACK_MODE = settings.get("use_real_attack_mode", True)

# --------------------------------------------------------
#  Категории payload’ов
# --------------------------------------------------------

PAYLOAD_CATEGORIES: List[str] = [
    "XSS",
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

# --------------------------------------------------------
#  Canary payload’ы (безопасные)
# --------------------------------------------------------

DEFAULT_PAYLOADS: Dict[str, List[str]] = {
    "XSS": [
        "xss-canary",
        "\"><xss-canary>",
        "'><xss-canary>",
    ],
    "Reflected": [
        "reflected-canary",
        "\"><reflected-canary>",
    ],
    "DOM": [
        "dom-canary",
        "#dom-canary",
    ],
    "URL": [
        "url-canary",
        "%3Cxss-canary%3E",
    ],
}

# --------------------------------------------------------
#  Real Attack payload’ы (загружаются из файла)
# --------------------------------------------------------

REAL_PAYLOADS_FILE = PAYLOADS_DIR.parent / "auto_recon" / "target" / "real_payloads.txt"

def load_real_payloads() -> Dict[str, List[str]]:
    real_payloads: Dict[str, List[str]] = {cat: [] for cat in PAYLOAD_CATEGORIES}

    if not REAL_PAYLOADS_FILE.exists():
        log.warning("[PayloadManager] real_payloads.txt отсутствует — Real Attack Mode отключён")
        return real_payloads

    current_category = None

    with open(REAL_PAYLOADS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            if line.startswith("[") and line.endswith("]"):
                cat = line[1:-1]
                if cat in PAYLOAD_CATEGORIES:
                    current_category = cat
                else:
                    log.warning(f"[PayloadManager] неизвестная категория в real_payloads.txt: {cat}")
                continue

            if current_category:
                real_payloads[current_category].append(line)

    log.info("[PayloadManager] Real payloads загружены")
    return real_payloads

LEGACY_CATEGORIES = [
    "Reflected",
    "Stored",
    "DOM-based",
    "Obfuscated",
    "Event",
    "Attribute",
]

# ============================================================
#  PayloadManager 7.1
# ============================================================

class PayloadManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path.with_suffix(".db")
        self.cache: Dict[str, List[str]] = {cat: [] for cat in PAYLOAD_CATEGORIES}

        self._init_db()
        self._load_cache()

    # --------------------------------------------------------
    #  Инициализация базы
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

            count = conn.execute("SELECT COUNT(*) FROM payloads").fetchone()[0]

            if count == 0:
                if USE_REAL_ATTACK_MODE:
                    source_payloads = load_real_payloads()
                    log.info("[PayloadManager] Инициализация базы реальными payload’ами (Real Attack Mode)")
                else:
                    source_payloads = DEFAULT_PAYLOADS
                    log.info("[PayloadManager] Инициализация базы canary payload’ами (Canary Mode)")

                for category, payloads in source_payloads.items():
                    for payload in payloads:
                        conn.execute(
                            "INSERT OR IGNORE INTO payloads (category, payload) VALUES (?, ?)",
                            (category, payload),
                        )

            conn.commit()

        except Exception as e:
            log.error(f"[PayloadManager] DB init error: {e}")
        finally:
            conn.close()

    # --------------------------------------------------------
    #  Загрузка кэша
    # --------------------------------------------------------
    def _load_cache(self) -> None:
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.execute("SELECT category, payload FROM payloads")

            for category, payload in cur.fetchall():
                if category in self.cache:
                    self.cache[category].append(payload)
                else:
                    if category in LEGACY_CATEGORIES:
                        mapped = "Reflected"
                        self.cache[mapped].append(payload)
                        log.warning(f"[PayloadManager] Migrated legacy category '{category}' → '{mapped}'")
                    else:
                        log.warning(f"[PayloadManager] Unknown category in DB: {category}")

            # Добавляем реальные payload’ы поверх, если включён режим
            if USE_REAL_ATTACK_MODE:
                real = load_real_payloads()
                for cat, items in real.items():
                    self.cache[cat].extend(items)
                log.info("[PayloadManager] Real Attack Mode: реальные payload’ы добавлены в кэш")

            total = sum(len(v) for v in self.cache.values())
            log.info(f"[PayloadManager] Cache loaded: {total} payloads")

        except Exception as e:
            log.error(f"[PayloadManager] Cache load error: {e}")
        finally:
            conn.close()

    # --------------------------------------------------------
    def get(self, category: str, default=None) -> List[str]:
        if default is None:
            default = []
        return self.cache.get(category, default)

    def exists(self, category: str, payload: str) -> bool:
        return payload in self.cache.get(category, [])

    def random(self, category: str = "XSS") -> str:
        items = self.get(category)
        if not items:
            return "<empty>"
        return random.choice(items)

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

        self.cache[category].append(payload)

        THREAT_CONNECTOR.emit(
            module="PayloadManager7.1",
            target="payload_database",
            result={
                "severity": "info",
                "category": "payload_added",
                "payload": payload,
                "payload_category": category,
            },
        )

        return True

    def stats(self) -> Dict[str, int]:
        return {cat: len(self.cache.get(cat, [])) for cat in PAYLOAD_CATEGORIES}

    def get_categories(self) -> List[str]:
        return list(PAYLOAD_CATEGORIES)

    def export_stats_to_threat_intel(self) -> None:
        stats = self.stats()

        THREAT_CONNECTOR.emit(
            module="PayloadManager7.1",
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

PAYLOAD_DB_PATH = PAYLOADS_DIR / "payload_db"
PAYLOADS = PayloadManager(PAYLOAD_DB_PATH)

get_payloads = PAYLOADS.get
get_random_payload = PAYLOADS.random
add_payload = PAYLOADS.add
get_stats = PAYLOADS.stats
get_categories = PAYLOADS.get_categories
load_payloads = lambda: None

# --------------------------------------------------------
#  Универсальный генератор payload’ов
# ============================================================

def generate_payloads() -> Dict[str, List[str]]:
    return {cat: PAYLOADS.get(cat, []) for cat in PAYLOADS.get_categories()}

def gen_payloads_from_templates() -> dict[str, list[str]]:
    return {cat: PAYLOADS.get(cat, []) for cat in PAYLOADS.get_categories()}

