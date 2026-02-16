# xss_security_gui/auto_recon/scanner.py
# === Стандартная библиотека ===
import os
import re
import json
import threading
import datetime
import logging
from urllib.parse import urljoin
from typing import Optional, List, Dict, Any

# === Внешние библиотеки ===
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup

# === Локальные утилиты ===
from xss_security_gui.utils.core_utils import normalize_url

# === Локальные модули ===
from xss_security_gui.xss_detector import XSSDetector
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


# =======================
# Устойчивый HTTP-сессия
# =======================
def create_retry_session(
    total: int = 3,
    backoff_factor: float = 0.5,
    status_forcelist: tuple = (429, 500, 502, 503, 504),
) -> requests.Session:
    """
    Создаёт HTTP-сессию с автоматическим повтором запросов.
    • total: количество попыток
    • backoff_factor: задержка между попытками
    • status_forcelist: список кодов для повторных попыток
    """
    retry = Retry(
        total=total,
        connect=total,
        read=total,
        status=total,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(
            ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "PATCH"]
        ),
        raise_on_status=False,
        respect_retry_after_header=True,
    )

    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# =======================
# Основной сканер
# =======================
class EndpointScanner:
    """
    AutoRecon Enterprise 2.0 EndpointScanner
    • Сканирует страницы, формы, JS и XHR
    • Интегрируется с ThreatConnector
    • Поддерживает XSS-сканирование
    """

    def __init__(self, target_url: str, gui_callback=None):
        self.session = create_retry_session()
        self.target = target_url.rstrip("/")
        self.headers = {"User-Agent": "AutoReconScanner/2.0"}
        self.endpoints: list[dict] = []
        self.gui_callback = gui_callback
        self.detector = XSSDetector()

    # -----------------------
    # Основной сбор эндпоинтов
    # -----------------------
    def scan(self) -> list[dict]:
        try:
            response = self.session.get(self.target, headers=self.headers, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            self._report_gui({"error": f"Failed to fetch target: {e}"})
            return []

        soup = BeautifulSoup(response.text, "html.parser")

        forms = self.extract_forms(soup)
        js_links = self.extract_js_links(soup)
        apis = self.extract_xhr(js_links)

        root_entry = {
            "url": self.target,
            "method": "GET",
            "params": {},
            "source": "root",
            "status": response.status_code,
            "headers": dict(response.request.headers),
            "response_headers": dict(response.headers),
            "full_response": response.text[:2000],  # ограничиваем для читаемости
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

        self.endpoints = [root_entry] + forms + apis
        self._report_gui({"info": f"Discovered {len(self.endpoints)} endpoints"})

        # Отправляем артефакты в ThreatConnector
        THREAT_CONNECTOR.add_artifact("EndpointScanner", self.target, self.endpoints)

        return self.endpoints

    # -----------------------
    # Формы
    # -----------------------
    def extract_forms(self, soup: BeautifulSoup) -> list[dict]:
        result = []
        for form in soup.find_all("form"):
            action = urljoin(self.target, form.get("action", ""))
            method = form.get("method", "GET").upper()

            params = {
                inp.get("name"): ""
                for inp in form.find_all("input")
                if inp.get("name")
            }

            result.append({
                "url": action,
                "method": method,
                "params": params,
                "source": "form",
                "status": None,
                "headers": dict(self.headers),
                "response_headers": {},
                "timestamp": datetime.datetime.utcnow().isoformat()
            })
        return result

    # -----------------------
    # JS-файлы
    # -----------------------
    def extract_js_links(self, soup: BeautifulSoup) -> list[str]:
        return [urljoin(self.target, s["src"]) for s in soup.find_all("script", src=True)]

    # -----------------------
    # XHR / fetch / ajax
    # -----------------------
    def extract_xhr(self, js_links: list[str]) -> list[dict]:
        api_patterns = []
        xhr_regex = re.compile(
            r"(fetch|xhr|ajax)\s*\(\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE
        )

        for js_url in js_links:
            try:
                resp = self.session.get(js_url, headers=self.headers, timeout=10)
                js_text = resp.text
                found = xhr_regex.findall(js_text)

                for _, url in found:
                    full_url = urljoin(self.target, url)
                    api_patterns.append({
                        "url": full_url,
                        "method": "POST",
                        "params": {"key": ""},
                        "source": "js",
                        "status": resp.status_code,
                        "headers": dict(resp.request.headers),
                        "response_headers": dict(resp.headers),
                        "timestamp": datetime.datetime.utcnow().isoformat()
                    })
            except requests.exceptions.RequestException as e:
                self._report_gui({"warning": f"Failed to fetch JS {js_url}: {e}"})
                continue

        return api_patterns

    # -----------------------
    # XSS-сканирование эндпоинтов
    # -----------------------
    def scan_xss_on_endpoints(self, payload: str = '<img src=x onerror=alert(1)>') -> list[dict]:
        results = []
        for ep in self.endpoints:
            if ep["method"] != "GET":
                continue

            try:
                full_url = normalize_url(self.target, ep["url"])
                response = self.session.get(
                    full_url,
                    params=ep.get("params", {}),
                    headers=self.headers,
                    timeout=10
                )
                html = response.text
                reflected = payload in html

                if reflected:
                    context = self.detector.detect_xss_context(html, payload)
                    js_hits = self.detector.scan_inline_js_for_payload(html, payload)
                else:
                    context, js_hits = "❌ Not reflected", []

                result = {
                    "url": response.url,
                    "request_url": response.url,
                    "status": response.status_code,
                    "method": ep.get("method", "GET"),
                    "payload": payload,
                    "context": context or "❓ Unknown",
                    "category": context if reflected else "none",
                    "js_hits": js_hits,
                    "source": ep.get("source", "unknown"),
                    "full_response": html[:2000],
                    "headers": dict(response.request.headers),
                    "response_headers": dict(response.headers),
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "vulnerable": reflected
                }

                results.append(result)
                self._report_gui(result)
                THREAT_CONNECTOR.add_artifact("XSSScanner", response.url, [result])

            except requests.exceptions.RequestException as e:
                error_result = {
                    "url": ep["url"],
                    "error": str(e),
                    "source": ep.get("source", "unknown"),
                    "timestamp": datetime.datetime.utcnow().isoformat()
                }
                results.append(error_result)
                self._report_gui(error_result)

        return results

    # -----------------------
    # XSS fuzzing параметров
    # -----------------------
    def fuzz_xss_parameters(self, base_params=None, method="GET"):
        """
        Фуззинг параметров для XSS.
        • base_params: словарь базовых параметров
        • method: HTTP метод (GET/POST)
        """
        results = []
        generated = self.detector.fuzz_xss_parameters(self.target, base_params or {}, method)

        for payload_entry in generated:
            try:
                if method.upper() == "GET" and isinstance(payload_entry, str):
                    full_url = normalize_url(self.target, payload_entry)
                    response = self.session.get(full_url, headers=self.headers, timeout=10)

                elif isinstance(payload_entry, dict):
                    url = normalize_url(self.target, payload_entry.get("url", self.target))
                    response = self.session.post(
                        url,
                        json=payload_entry.get("json", {}),
                        headers=self.headers,
                        timeout=10
                    )
                else:
                    continue

                html = response.text
                payload_str = payload_entry if isinstance(payload_entry, str) else str(payload_entry.get("json", {}))
                reflected = payload_str in html

                if reflected:
                    context = self.detector.detect_xss_context(html, payload_str)
                    js_hits = self.detector.scan_inline_js_for_payload(html, payload_str)
                else:
                    context, js_hits = "❌ Not reflected", []

                result = {
                    "module": "XSSFuzzer",
                    "url": getattr(response, "url", payload_entry),
                    "request_url": getattr(response, "url", payload_entry),
                    "status": response.status_code,
                    "method": method,
                    "payload": payload_str,
                    "context": context or "❓ Unknown",
                    "category": context if reflected else "none",
                    "js_hits": js_hits,
                    "source": "xss_fuzzer",
                    "full_response": html[:2000],
                    "headers": dict(response.request.headers),
                    "response_headers": dict(response.headers),
                    "response_length": len(html),
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "vulnerable": reflected,
                    "severity": "high" if reflected else "info"
                }

                results.append(result)
                self._report_gui(result)
                THREAT_CONNECTOR.add_artifact("XSSFuzzer", result["url"], [result])

            except requests.exceptions.RequestException as e:
                error_result = {
                    "module": "XSSFuzzer",
                    "url": payload_entry if isinstance(payload_entry, str) else payload_entry.get("url", self.target),
                    "error": str(e),
                    "source": "xss_fuzzer",
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "severity": "error",
                    "vulnerable": False
                }
                results.append(error_result)
                self._report_gui(error_result)
                THREAT_CONNECTOR.add_artifact("XSSFuzzer", error_result["url"], [error_result])

        return results

    # -----------------------
    # GUI callback
    # -----------------------
    def _report_gui(self, data: dict):
        """
        Отправка данных в GUI с безопасной обработкой.
        • data: словарь результата или ошибки
        """
        data.setdefault("timestamp", datetime.datetime.utcnow().isoformat())
        wrapped = {"scanner": data}

        # Логируем
        if "error" in data:
            logging.error(f"[GUI] {data.get('error')}")
        elif data.get("vulnerable"):
            logging.info(f"[GUI] XSS найден: {data.get('url')} payload={data.get('payload')}")
        else:
            logging.info(f"[GUI] {data.get('url')} → {data.get('status')}")

        if self.gui_callback:
            try:
                self.gui_callback(wrapped)
            except Exception as e:
                logging.warning(f"[GUI] Ошибка при вызове callback: {e}")


# =======================
# Вспомогательные функции
# =======================

def extract_context(payload: str, html: str, context: int = 50) -> Optional[tuple[str, int]]:
    """
    Извлекает контекст вокруг отражённого payload в HTML.
    • payload: строка, которую ищем
    • html: HTML-код ответа
    • context: количество символов вокруг payload
    Возвращает (фрагмент, индекс) или None.
    """
    if not payload or not html:
        return None

    index = html.find(payload)
    if index == -1:
        return None

    start = max(0, index - context)
    end = min(len(html), index + len(payload) + context)

    snippet = html[start:end]
    return snippet, index


def categorize_reflection(payload: str, html: str) -> str:
    """
    Определяет категорию отражения payload в HTML.
    • payload: строка, которую ищем
    • html: HTML-код ответа
    Возвращает категорию: HTML, JS, Attribute Injection, raw или unknown.
    """
    snippet, _ = extract_context(payload, html, context=100) or (None, None)
    if not snippet:
        return "unknown"

    if re.search(r"<[^>]+{}[^>]*>".format(re.escape(payload)), snippet):
        return "🔤 Reflected HTML"

    if re.search(r'["\']{}["\']'.format(re.escape(payload)), snippet):
        return "📜 Reflected JS"

    if re.search(r'\s+\w+=["\']{}["\']'.format(re.escape(payload)), snippet):
        return "🧬 Attribute Injection"

    return "raw"


def suggest_payload_by_category(category: str) -> str:
    """
    Предлагает подходящий payload для выбранной категории отражения.
    • category: строка категории
    Возвращает строку payload.
    """
    mapping = {
        "🔤 Reflected HTML": "<script>alert(1)</script>",
        "🧬 Attribute Injection": '" onerror="alert(1)',
        "📜 Reflected JS": '";alert(1)//',
        "raw": "<img src=x onerror=alert(1)>"
    }
    return mapping.get(category, "<img src=x onerror=alert(1)>")


def scan_url(url: str) -> dict:
    """
    Минимальный сканер одного URL.
    Возвращает структуру, совместимую с AutoReconAnalyzerV2.
    """
    try:
        import requests
        r = requests.get(url, timeout=5)
        return {
            "module": "URLScanner",
            "url": url,
            "text": r.text[:2000],  # ограничиваем для читаемости
            "headers": dict(r.headers),
            "status": r.status_code,
            "source": "scan_url",
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "module": "URLScanner",
            "url": url,
            "text": "",
            "headers": {},
            "status": "error",
            "error": str(e),
            "source": "scan_url",
            "timestamp": datetime.datetime.utcnow().isoformat()
        }


def scan_multiple(urls: list[str]) -> list[dict]:
    """
    Сканирует список URL и возвращает список responses.
    • urls: список URL
    Возвращает список структур.
    """
    results = []
    for u in urls:
        result = scan_url(u)
        results.append(result)
    return results


# =======================
# NDJSON логирование XSS
# =======================

LOG_DIR = "logs/xss"
LOG_FILE = os.path.join(LOG_DIR, "reflected_responses.json")

_write_lock = threading.Lock()


def rotate_if_big(path: str, max_mb: int = 20) -> None:
    """
    Ротация логов, если файл слишком большой.
    • path: путь к файлу
    • max_mb: максимальный размер в мегабайтах
    """
    try:
        if os.path.exists(path) and os.path.getsize(path) > max_mb * 1024 * 1024:
            ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup = f"{path}.{ts}.bak"
            os.rename(path, backup)
            logging.info(f"[NDJSON] Лог {path} ротирован → {backup}")
    except Exception as e:
        logging.error(f"[NDJSON] Ошибка ротации: {e}")


def validate_result(result: Dict[str, Any]) -> bool:
    """
    Минимальная валидация структуры артефакта.
    • result: словарь результата
    """
    required = {"url", "category", "context"}
    missing = required - result.keys()
    if missing:
        logging.warning(f"[NDJSON] Пропущены поля: {missing}")
        return False
    return True


def save_reflected_response(result: Dict[str, Any]) -> None:
    """
    Сохраняет XSS-отражение в NDJSON формате.
    • result: словарь результата
    """
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        result.setdefault("_ts", datetime.datetime.utcnow().isoformat())

        if not validate_result(result):
            return

        rotate_if_big(LOG_FILE)

        with _write_lock:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(result, ensure_ascii=False) + "\n")

        logging.info(f"[NDJSON] Артефакт сохранён: {result.get('url')} [{result.get('category')}]")

    except Exception as e:
        logging.error(f"[NDJSON] Ошибка записи: {e}")


def load_reflected_responses(path: str = LOG_FILE) -> List[Dict[str, Any]]:
    """
    Загружает NDJSON файл и возвращает список словарей.
    • path: путь к файлу
    """
    results: List[Dict[str, Any]] = []
    if not os.path.exists(path):
        logging.warning(f"[NDJSON] Файл {path} не найден.")
        return results

    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError as e:
                    logging.warning(f"[NDJSON] Ошибка декодирования строки: {e}")
    except Exception as e:
        logging.error(f"[NDJSON] Ошибка чтения файла {path}: {e}")

    logging.info(f"[NDJSON] Загружено {len(results)} артефактов из {path}")
    return results


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler("logs/xss_ndjson.log", encoding="utf-8"),
            logging.StreamHandler()
        ]
    )

    responses = load_reflected_responses()
    print(f"Загружено {len(responses)} результатов")
    for r in responses[:3]:
        print(r.get("url"), r.get("category"), r.get("context"))
