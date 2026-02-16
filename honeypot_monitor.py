# xss_security_gui/honeypot_monitor.py
"""
HoneypotMonitor ULTRA 6.0

• Следит за honeypot-логом в реальном времени
• Извлекает XSS-пейлоады, классифицирует и оценивает риск (через risk_classifier)
• Пишет структурированные JSON-логи
• Шлёт события в ThreatConnector
• Запускает Mutator ULTRA (mutate_async)
• Запускает AutoAttackEngine в режиме instant-attack:
    - на оригинальный payload
    - на мутанты с высоким риском
• Обновляет GUI (если передан GUI-объект), иначе пишет в консоль
"""

import os
import re
import time
import json
import threading
from datetime import datetime
from typing import List, Dict, Any, Tuple

from xss_security_gui.settings import (
    settings, LOG_HONEYPOT_PATH, LOG_HONEYPOT_HITS,
    JSON_CRAWL_EXPORT_PATH, LOG_DIR
)
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
from xss_security_gui.payload_mutator import mutate_async, mutate_payload
from xss_security_gui.attack_engine import AttackEngine
from xss_security_gui.risk_classifier import (
    classify_payload, estimate_risk, risk_level
)

# Настройки honeypot из settings
POLL_INTERVAL = settings.get("honeypot.poll_interval", 5)
MAX_LOG_SIZE_MB = settings.get("honeypot.max_log_size_mb", 10)
ENABLE_AUTO_TRAPS = settings.get("honeypot.enable", True)
ENABLE_MUTATION = settings.get("honeypot.enable_mutation", True)
ENABLE_INSTANT_ATTACK = settings.get("honeypot.instant_attack", True)
INSTANT_ATTACK_MAX_MUTANTS = settings.get("honeypot.instant_attack_max_mutants", 10)

processed_payloads = set()
HONEYPOT_JSON_LOG = LOG_DIR / "honeypot_events.jsonl"


# ============================================================
# Вспомогательные функции
# ============================================================

def _load_crawler_results() -> Dict[str, Any]:
    if not os.path.exists(JSON_CRAWL_EXPORT_PATH):
        return {}
    try:
        with open(JSON_CRAWL_EXPORT_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _get_target_domain() -> str | None:
    data = _load_crawler_results()
    if not data:
        return None
    if isinstance(data, dict):
        if "domain" in data:
            return data["domain"]
        visited = data.get("visited") or []
        if visited:
            return visited[0]
    return None


def _extract_payloads(log_text: str) -> List[str]:
    pattern = (
        r"(?:<script.*?>.*?</script>|"
        r"<img\s+[^>]*?onerror\s*=.*?>|"
        r"javascript:[^ \n\r]+|"
        r"on\w+\s*=\s*['\"].*?['\"]|"
        r"<svg[^>]*onload\s*=.*?>)"
    )
    matches = re.findall(pattern, log_text, re.IGNORECASE | re.DOTALL)
    return list({m.strip() for m in matches if m.strip()})


def _append_json_log(event: Dict[str, Any]) -> None:
    try:
        with open(HONEYPOT_JSON_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[HoneypotULTRA] Ошибка записи JSON-лога: {e}")


def _insert(target, text: str) -> None:
    try:
        if hasattr(target, "output_box"):
            target.output_box.insert("end", text)
            target.output_box.see("end")
        else:
            target.insert("end", text)
            target.see("end")
    except Exception as err:
        print(f"[HoneypotULTRA] insert error: {err}")


# ============================================================
# Основная логика Honeypot ULTRA
# ============================================================

def start_monitor_thread(gui_or_text) -> None:
    thread = threading.Thread(target=lambda: monitor_log_thread(gui_or_text), daemon=True)
    thread.start()


def monitor_log_thread(gui_or_text) -> None:
    last_size = 0
    os.makedirs(os.path.dirname(LOG_HONEYPOT_PATH), exist_ok=True)

    while True:
        try:
            if not os.path.exists(LOG_HONEYPOT_PATH):
                _insert(gui_or_text, "🕵️ Honeypot лог не найден — ожидание...\n")
                time.sleep(POLL_INTERVAL)
                continue

            size = os.path.getsize(LOG_HONEYPOT_PATH)
            if size > MAX_LOG_SIZE_MB * 1024 * 1024:
                _insert(gui_or_text, f"🧹 Лог > {MAX_LOG_SIZE_MB}MB — очищаю...\n")
                open(LOG_HONEYPOT_PATH, "w", encoding="utf-8").close()
                last_size = 0
                continue

            if size > last_size:
                with open(LOG_HONEYPOT_PATH, "r", encoding="utf-8") as f:
                    f.seek(last_size)
                    new_data = f.read()
                    last_size = f.tell()

                payloads = _extract_payloads(new_data)
                for payload in payloads:
                    if payload in processed_payloads:
                        continue
                    processed_payloads.add(payload)
                    _handle_captured_payload(gui_or_text, payload)

            time.sleep(POLL_INTERVAL)

        except Exception as e:
            _insert(gui_or_text, f"\n⚠️ Ошибка HoneypotULTRA: {e}\n")
            time.sleep(10)


def _handle_captured_payload(gui_or_text, payload: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Единая классификация и риск
    family = classify_payload(payload)
    risk_score = estimate_risk(payload, family)
    level = risk_level(risk_score)

    _insert(
        gui_or_text,
        f"\n🧲 [{timestamp}] Honeypot поймал payload "
        f"(risk={risk_score}, level={level}, family={family}):\n{payload}\n"
    )

    # Запись в hits-лог
    try:
        with open(LOG_HONEYPOT_HITS, "a", encoding="utf-8") as out_log:
            out_log.write(f"[{timestamp}] [{level}] {payload}\n")
    except Exception as e:
        print(f"[HoneypotULTRA] Ошибка записи hits-лога: {e}")

    # JSON-лог
    event = {
        "timestamp": timestamp,
        "payload": payload,
        "family": family,
        "risk_score": risk_score,
        "risk_level": level,
        "source": "honeypot",
    }
    _append_json_log(event)

    # ThreatConnector
    try:
        THREAT_CONNECTOR.emit(
            module="HoneypotULTRA",
            target="honeypot",
            result={
                "severity": "high" if risk_score >= 5 else "info",
                "category": "honeypot_capture",
                "payload": payload,
                "family": family,
                "risk_score": risk_score,
                "risk_level": level,
            },
        )
    except Exception as e:
        print(f"[HoneypotULTRA] Ошибка ThreatConnector.emit: {e}")

    # Авто-подстановка в GUI
    try:
        if hasattr(gui_or_text, "input_entry") and hasattr(gui_or_text, "scan"):
            gui_or_text.input_entry.delete(0, "end")
            gui_or_text.input_entry.insert(0, payload)
            gui_or_text.scan()
    except Exception as e:
        print(f"[HoneypotULTRA] Ошибка GUI-автосканирования: {e}")

    # Mutator ULTRA
    if ENABLE_MUTATION:
        try:
            mutate_async("honeypot", payload)
        except Exception as e:
            print(f"[HoneypotULTRA] Ошибка mutate_async: {e}")

    # Instant-Attack ULTRA
    if ENABLE_INSTANT_ATTACK:
        _run_instant_attack(gui_or_text, payload, family, risk_score)


def _run_instant_attack(gui_or_text, payload: str, family: str, risk_score: int) -> None:
    domain = _get_target_domain()
    if not domain:
        _insert(gui_or_text, "⚠️ Instant-Attack: домен не найден в crawler_results.json — пропуск.\n")
        return

    try:
        engine = AttackEngine(domain)
    except Exception as e:
        _insert(gui_or_text, f"⚠️ Instant-Attack: не удалось инициализировать AttackEngine: {e}\n")
        return

    _insert(gui_or_text, f"🚀 Instant-Attack: запуск атаки на {domain} с honeypot payload.\n")

    # 1) Атака оригинального payload
    try:
        if hasattr(engine, "run_single_payload_attack"):
            engine.run_single_payload_attack(payload)
        else:
            _insert(gui_or_text, "⚠️ Instant-Attack: run_single_payload_attack не найден.\n")
    except Exception as e:
        _insert(gui_or_text, f"⚠️ Instant-Attack: ошибка при атаке оригинального payload: {e}\n")

    # 2) Атака мутантов с высоким риском
    try:
        mutants = mutate_payload(payload, framework="generic")

        high_risk_mutants: List[Tuple[str, int]] = []
        for m in mutants:
            fam = classify_payload(m)
            r = estimate_risk(m, fam)
            if r >= 7:
                high_risk_mutants.append((m, r))

        high_risk_mutants.sort(key=lambda x: x[1], reverse=True)
        high_risk_mutants = high_risk_mutants[:INSTANT_ATTACK_MAX_MUTANTS]

        if not high_risk_mutants:
            _insert(gui_or_text, "ℹ️ Instant-Attack: высокорисковых мутантов не найдено.\n")
            return

        _insert(
            gui_or_text,
            f"🔥 Instant-Attack: запуск атак по {len(high_risk_mutants)} мутантам с высоким риском.\n",
        )

        for mutant_payload, risk_value in high_risk_mutants:
            try:
                if hasattr(engine, "run_single_payload_attack"):
                    engine.run_single_payload_attack(mutant_payload)
                else:
                    _insert(gui_or_text, "⚠️ Instant-Attack: метод run_single_payload_attack отсутствует.\n")
                    break
            except Exception as e:
                _insert(
                    gui_or_text,
                    f"⚠️ Instant-Attack: ошибка при атаке мутанта (risk={risk_value}): {e}\n"
                )

    except Exception as e:
        _insert(gui_or_text, f"⚠️ Instant-Attack: ошибка при подготовке мутантов: {e}\n")


# ============================================================
#  Legacy wrapper для совместимости
# ============================================================

def start_honeypot(gui_or_text=None):
    """
    Legacy wrapper для backward compatibility.
    Запускает мониторинг honeypot-логов в отдельном потоке.
    Совместимо со старыми модулями (exploit_tab.py).
    """
    thread = threading.Thread(
        target=lambda: monitor_log_thread(gui_or_text),
        daemon=True
    )
    thread.start()
    return thread