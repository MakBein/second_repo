# xss_security_gui/auto_recon/xss_flooder.py
"""
XSS Flooder ULTRA 6.1 — Safe Load Tester Edition
-----------------------------------------------
Назначение:
- Контролируемое многопоточное нагрузочное тестирование ДОЗВОЛЕННЫХ целей
- Не для DDoS, а для аудита устойчивости и XSS-поведения

Особенности:
- Worker-потоки (постоянные)
- Очередь задач (Queue)
- Rate limiting + глобальный лимит запросов
- Per-host throttling
- Callback для GUI
- Логи в logs/xss_flood_log.txt
- Интеграция с settings.py и ThreatConnector (fail-safe)
"""

import time
import queue
import threading
import requests
import logging
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Optional

from xss_security_gui.settings import LOG_DIR, BASE_DIR, settings
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
from xss_security_gui.auto_recon.scope import (
    is_target_authorized,
    normalize_http_url,
    scoped_request,
)


# 📂 Путь к файлу целей
TARGETS_FILE: Path = BASE_DIR / "auto_recon" / "target" / "targets.txt"

# 📁 Подготовка лог-файла
LOG_PATH: Path = LOG_DIR / "xss_flood_log.txt"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

# Логгер
log = logging.getLogger("XSSFlooder")
log.setLevel(logging.DEBUG)

FloodCallback = Callable[[str, str, str], None]

# 💣 Список целей (загружается из файла)
payload_urls: list[str] = []

# Глобальные ограничения (защита от случайного DDoS)
MAX_TOTAL_REQUESTS_HARD = 200
MIN_DELAY_BETWEEN_REQUESTS = 0.05
PER_HOST_THROTTLE_DELAY = 1.0

STOP_FLOOD = threading.Event()

def stop_flood():
    STOP_FLOOD.set()


# 📝 Логирование ответа (локальный файл)
def log_response(url: str, status: str, snippet: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(
                f"[{timestamp}] [{status}] {url}\n"
                f"Snippet: {snippet[:200]}\n"
                f"{'-'*60}\n"
            )
    except Exception as e:
        log.error(f"[XSSFlooder] Ошибка записи лога: {e}", exc_info=True)


def clear_flood_log() -> None:
    LOG_PATH.write_text("", encoding="utf-8")


# 📂 Загрузка целей из файла
def load_targets_from_file(path: Path) -> list[str]:
    """Загружает список целей из файла, игнорируя пустые строки и комментарии (#)."""
    if not path.exists():
        log.warning(f"[XSSFlooder] Файл {path} не найден.")
        return []
    try:
        with path.open(encoding="utf-8") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
    except Exception as e:
        log.error(f"[XSSFlooder] Ошибка чтения файла {path}: {e}", exc_info=True)
        return []


# Инициализация списка целей
payload_urls = load_targets_from_file(TARGETS_FILE)


# 🚀 Отправка одного пейлоада (с повтором)
def send_payload(
    url: str,
    callback: Optional[FloodCallback],
    timeout: int,
    repeat: int,
    delay: float,
    per_host_delay: float,
) -> None:
    """Отправляет несколько запросов подряд на один URL (контролируемо)."""

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        "Connection": "close",
    }

    for _ in range(repeat):
        if STOP_FLOOD.is_set():
            break
        try:
            response = scoped_request(
                requests,
                "GET",
                url,
                root_url=url,
                timeout=timeout,
                headers=headers,
            )
            try:
                if response.is_redirect:
                    status = (
                        f"REDIRECT-{response.status_code}"
                        f" -> {response.headers.get('Location', '')}"
                    )
                    snippet = ""
                else:
                    status = (
                        str(response.status_code)
                        if response.ok
                        else f"FAIL-{response.status_code}"
                    )
                    snippet = response.text[:200]
            finally:
                response.close()
        except Exception as e:
            status = "ERROR"
            snippet = str(e)

        # ThreatConnector интеграция (fail-safe)
        try:
            THREAT_CONNECTOR.emit(
                module="xss_flooder",
                target=url,
                result={
                    "status": status,
                    "snippet": snippet,
                    "error": snippet if status == "ERROR" else None,
                    "ts": datetime.now().isoformat(),
                },
            )
        except Exception as e:
            log.error(f"[XSSFlooder] ThreatConnector error: {e}", exc_info=True)

        # Callback для GUI
        if callback:
            try:
                callback(url, status, snippet)
            except Exception as e:
                log.error(f"[XSSFlooder] Callback error: {e}", exc_info=True)

        # Локальное логирование
        log_response(url, status, snippet)

        # Пер-host тротлінг
        if per_host_delay > 0:
            time.sleep(per_host_delay)

        # Дополнительная задержка между запросами
        if delay > 0:
            time.sleep(max(delay, MIN_DELAY_BETWEEN_REQUESTS))


# 🔁 Worker-поток
def worker_thread(
    task_queue: queue.Queue[tuple[str, int, float]],
    callback: Optional[FloodCallback],
    timeout: int,
    per_host_delay: float,
) -> None:
    """Worker-поток с защитой от зависаний и контролем нагрузки."""
    while True:
        try:
            item = task_queue.get(timeout=1)
        except queue.Empty:
            time.sleep(0.1)
            continue

        try:
            url, repeat, delay = item
            if url is None:
                log.debug("[XSSFlooder] Worker завершён.")
                break

            log.debug(f"[Worker] ▶️ {url} ×{repeat} (delay={delay})")
            send_payload(
                url,
                callback,
                timeout,
                repeat=repeat,
                delay=delay,
                per_host_delay=per_host_delay,
            )
        except Exception as e:
            log.error(f"[XSSFlooder] Ошибка в worker: {e}", exc_info=True)
        finally:
            task_queue.task_done()


# 🚀 Запуск многопоточного флудера (контролируемый)
def start_flood(
    target_urls: Iterable[str] = None,
    flood_interval: float = None,
    flood_count: int = None,
    max_workers: Optional[int] = None,
    callback: Optional[FloodCallback] = None,
    timeout: int = None,
    repeat_each: int = None,
    delay_each: float = None,
    infinite: bool = False,
) -> None:

    if isinstance(target_urls, str):
        urls = [target_urls]
    else:
        urls = list(target_urls if target_urls is not None else payload_urls)
    if not urls:
        raise ValueError(f"No target URLs were provided. Check {TARGETS_FILE}")

    normalized_urls = []
    for target in urls:
        normalized = normalize_http_url(str(target))
        if not is_target_authorized(normalized):
            raise PermissionError(
                f"Target is not authorized by ALLOW_REAL_RUN/ALLOWED_TARGETS: {normalized}"
            )
        normalized_urls.append(normalized)
    urls = normalized_urls

    flood_interval = flood_interval or settings.get("flood.interval", 1.0)
    flood_count = flood_count or settings.get("flood.cycles", 1)
    max_workers = max_workers or settings.get("attack_engine.threads", 6)
    timeout = timeout or settings.get("flood.timeout", 2)
    repeat_each = repeat_each or settings.get("flood.repeat_each", 10)
    delay_each = delay_each or settings.get("flood.delay_each", 0.0)
    max_workers = min(max(int(max_workers), 1), 10)
    timeout = min(max(float(timeout), 1.0), 5.0)
    flood_count = max(int(flood_count), 1)
    repeat_each = max(int(repeat_each), 1)
    flood_interval = max(float(flood_interval), 0.0)
    delay_each = max(float(delay_each), MIN_DELAY_BETWEEN_REQUESTS)

    requests_per_cycle = len(urls) * repeat_each
    if infinite:
        flood_count = max(1, MAX_TOTAL_REQUESTS_HARD // requests_per_cycle)
    total_requests = requests_per_cycle * flood_count
    if total_requests > MAX_TOTAL_REQUESTS_HARD:
        raise ValueError(
            f"Requested {total_requests} requests exceeds the per-run limit "
            f"of {MAX_TOTAL_REQUESTS_HARD}."
        )

    STOP_FLOOD.clear()

    print(
        f"[XSSFlooder] 🚀 Starting controlled flood\n"
        f" • URLs: {len(urls)}\n"
        f" • Cycles: {flood_count}\n"
        f" • Workers: {max_workers}\n"
        f" • Repeat each: {repeat_each}\n"
        f" • Total requests: {total_requests}\n"
        f"{'-'*60}"
    )

    task_queue: queue.Queue[tuple[str, int, float]] = queue.Queue()
    per_host_delay = PER_HOST_THROTTLE_DELAY

    # Создаём worker-потоки
    workers = []
    for wid in range(max_workers):
        t = threading.Thread(
            target=worker_thread,
            args=(task_queue, callback, timeout, per_host_delay),
            daemon=True,
        )
        t.start()
        workers.append(t)
        log.debug(f"[XSSFlooder] 🧵 Worker {wid+1} запущен")

    # Основной цикл
    cycle = 0
    while True:

        # Користувач натиснув "СТОП"
        if STOP_FLOOD.is_set():
            print("[XSSFlooder] 🛑 Цикл остановлен пользователем")
            break

        log.debug(f"[XSSFlooder] 🔁 Cycle {cycle + 1}")

        for url in urls:
            log.debug(f"[XSSFlooder] ➕ Queue: {url}")
            task_queue.put((url, repeat_each, delay_each))

        task_queue.join()

        cycle += 1

        if cycle >= flood_count:
            break

        log.debug(f"[XSSFlooder] ⏳ Ожидание перед следующим циклом: {flood_interval}s")
        STOP_FLOOD.wait(flood_interval)

    # Завершаем worker-потоки
    print("[XSSFlooder] 🛑 Завершение потоков...")
    for _ in workers:
        task_queue.put((None, 0, 0))

    for t in workers:
        t.join()

    print("[XSSFlooder] ✅ Controlled flood complete.")
