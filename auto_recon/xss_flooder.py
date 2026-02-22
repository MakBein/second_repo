# xss_security_gui/auto_recon/xss_flooder.py
"""
XSS Flooder ULTRA 6.0 — многопоточный движок
--------------------------------------------
Особенности:
- Worker-потоки (постоянные)
- Очередь задач (Queue)
- Rate limiting
- Callback для GUI
- Логи в logs/xss_flood_log.txt
- Интеграция с settings.py и ThreatConnector
"""

import time
import queue
import threading
import requests
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Optional

from xss_security_gui.settings import LOG_DIR, BASE_DIR, settings
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR

# 📂 Путь к файлу целей
TARGETS_FILE: Path = BASE_DIR / "xss_security_gui" / "auto_recon" / "configs" / "targets.txt"

# 📁 Подготовка лог-файла
LOG_PATH: Path = LOG_DIR / "xss_flood_log.txt"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

# Тип callback
FloodCallback = Callable[[str, int | str, str], None]

# 💣 Список целей (загружается из файла)
payload_urls: list[str] = []


# 📝 Логирование ответа (локальный файл)
def log_response(url: str, status: int | str, content: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] [{status}] {url}\n")
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
    callback: Optional[FloodCallback],
    timeout: int = 1,
    repeat: int = 20,
    delay: float = 0.0,
) -> None:
    """Отправляет несколько запросов подряд на один URL."""
    for _ in range(repeat):
        try:
            response = requests.get(url, timeout=timeout)
            status = response.status_code if response.ok else f"FAIL-{response.status_code}"
            snippet = response.text[:200]
        except Exception as e:
            status = "ERROR"
            snippet = str(e)

        # ThreatConnector интеграция
        THREAT_CONNECTOR.emit(
            module="xss_flooder",
            target=url,
            result={
                "status": status,
                "snippet": snippet,
                "error": snippet if status == "ERROR" else None,
            },
        )

        # Callback для GUI
        if callback:
            callback(url, status, snippet)

        # Локальное логирование
        log_response(url, status, snippet)

        if delay > 0:
            time.sleep(delay)


# 🔁 Worker-поток
def worker_thread(task_queue: queue.Queue[tuple[str, int, float]], callback: Optional[FloodCallback], timeout: int) -> None:
    while True:
        try:
            url, repeat, delay = task_queue.get(timeout=1)
            if url is None:
                task_queue.task_done()
                break  # сигнал завершения
            send_payload(url, callback, timeout, repeat=repeat, delay=delay)
            task_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[XSSFlooder] Ошибка в worker: {e}")


# 🚀 Запуск многопоточного флудера
def start_flood(
    target_urls: Iterable[str] = None,
    flood_interval: float = 1.0,
    flood_count: int = 1,
    max_workers: Optional[int] = None,
    callback: Optional[FloodCallback] = None,
    timeout: int = 1,
    repeat_each: int = 20,
    delay_each: float = 0.0,
) -> None:
    urls = list(target_urls or payload_urls)
    if not urls:
        print(f"[XSSFlooder] Нет целевых URL. Проверь файл {TARGETS_FILE}")
        return

    if max_workers is None:
        max_workers = settings.get("attack_engine.threads", 6)

    total_requests = len(urls) * repeat_each * flood_count
    print(f"[XSSFlooder] Starting flood: {len(urls)} URLs, cycles={flood_count}, workers={max_workers}, total_requests={total_requests}")

    task_queue: queue.Queue[tuple[str, int, float]] = queue.Queue()

    # Создаём worker-потоки
    workers = []
    for _ in range(max_workers):
        t = threading.Thread(target=worker_thread, args=(task_queue, callback, timeout), daemon=True)
        t.start()
        workers.append(t)

    # Основной цикл
    for cycle in range(flood_count):
        print(f"[XSSFlooder] Cycle {cycle + 1}/{flood_count}")
        for url in urls:
            task_queue.put((url, repeat_each, delay_each))
        task_queue.join()
        if cycle < flood_count - 1:
            time.sleep(flood_interval)

    # Завершаем worker-потоки
    for _ in workers:
        task_queue.put((None, 0, 0))
    for t in workers:
        t.join()

    print("[XSSFlooder] Flood complete.")
