# xss_security_gui/auto_recon/scanner.py

# === Стандартная библиотека ===
from pathlib import Path
import datetime
import json
import logging
import re
import threading
from typing import Optional, List, Dict, Any
from urllib.parse import urljoin

# === Внешние библиотеки ===
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup

# === Локальные утилиты ===
from xss_security_gui.utils.core_utils import normalize_url
from xss_security_gui.config_manager import LOGS_DIR

# === Локальные модули ===
from xss_security_gui.xss_detector import XSSDetector
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


# ============================================================
#  Устойчивый HTTP-сессия
# ============================================================

def create_retry_session(
    total: int = 3,
    backoff_factor: float = 0.5,
    status_forcelist: tuple = (429, 500, 502, 503, 504),
) -> requests.Session:
    """
    Создаёт HTTP-сессию с автоматическим повтором запросов.

    Args:
        total: общее количество попыток.
        backoff_factor: задержка между попытками.
        status_forcelist: коды ответов, при которых выполняется повтор.
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


# ============================================================
#  Основной сканер эндпоинтов
# ============================================================

class EndpointScanner:
    """
    AutoRecon EndpointScanner 2.0

    • Сканирует страницы, формы, JS и XHR
    • Интегрируется с ThreatConnector
    • Поддерживает XSS-сканирование
    """

    def __init__(self, target_url: str, gui_callback: Optional[callable] = None):
        self.session = create_retry_session()
        self.target = target_url.rstrip("/")
        self.headers = {"User-Agent": "AutoReconScanner/2.0"}
        self.endpoints: List[Dict[str, Any]] = []
        self.gui_callback = gui_callback
        self.detector = XSSDetector()

    # --------------------------------------------------------
    # Вспомогательный метод: отправка событий в GUI
    # --------------------------------------------------------

    def _report_gui(self, message: Dict[str, Any]):
        if self.gui_callback:
            try:
                self.gui_callback(message)
            except Exception as e:
                logging.error(f"[EndpointScanner] GUI callback error: {e}", exc_info=True)

    # --------------------------------------------------------
    # Основной сбор эндпоинтов
    # --------------------------------------------------------

    def scan(self) -> List[Dict[str, Any]]:
        """Сканирует целевую страницу и извлекает формы, JS и XHR."""
        try:
            response = self.session.get(self.target, headers=self.headers, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            self._report_gui({"error": f"Failed to fetch target: {e}"})
            logging.error(f"[EndpointScanner] Failed to fetch target {self.target}: {e}")
            return []

        soup = BeautifulSoup(response.text, "html.parser")

        forms = self.extract_forms(soup)
        js_links = self.extract_js_links(soup)
        apis = self.extract_xhr(js_links)

        root_entry: Dict[str, Any] = {
            "url": self.target,
            "method": "GET",
            "params": {},
            "source": "root",
            "status": response.status_code,
            "headers": dict(response.request.headers),
            "response_headers": dict(response.headers),
            "full_response": response.text[:2000],
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }

        self.endpoints = [root_entry] + forms + apis
        self._report_gui({"info": f"Discovered {len(self.endpoints)} endpoints"})

        # Отправляем артефакты в ThreatConnector
        try:
            THREAT_CONNECTOR.add_artifact("EndpointScanner", self.target, self.endpoints)
        except Exception as e:
            logging.error(f"[EndpointScanner] ThreatConnector error: {e}", exc_info=True)

        return self.endpoints

    # --------------------------------------------------------
    # Формы
    # --------------------------------------------------------

    def extract_forms(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Извлекает HTML-формы и превращает их в эндпоинты."""
        result: List[Dict[str, Any]] = []

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
                "timestamp": datetime.datetime.utcnow().isoformat(),
            })

        return result

    # --------------------------------------------------------
    # JS-файлы
    # --------------------------------------------------------

    def extract_js_links(self, soup: BeautifulSoup) -> List[str]:
        """Возвращает список абсолютных ссылок на JS-файлы."""
        return [
            urljoin(self.target, s["src"])
            for s in soup.find_all("script", src=True)
        ]

    # --------------------------------------------------------
    # XHR / fetch / ajax
    # --------------------------------------------------------

    def extract_xhr(self, js_links: List[str]) -> List[Dict[str, Any]]:
        """
        Ищет в JS-файлах вызовы fetch/xhr/ajax и строит эндпоинты.
        """
        api_patterns: List[Dict[str, Any]] = []
        xhr_regex = re.compile(
            r"(fetch|xhr|ajax)\s*\(\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE,
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
                        "timestamp": datetime.datetime.utcnow().isoformat(),
                    })

            except requests.exceptions.RequestException as e:
                self._report_gui({"warning": f"Failed to fetch JS {js_url}: {e}"})
                logging.warning(f"[EndpointScanner] Failed to fetch JS {js_url}: {e}")

        return api_patterns

    # --------------------------------------------------------
    # XSS-сканирование эндпоинтов
    # --------------------------------------------------------

    def scan_xss_on_endpoints(
        self,
        payload: str = "<img src=x onerror=alert(1)>",
    ) -> List[Dict[str, Any]]:
        """
        Выполняет простое XSS-сканирование по всем GET-эндпоинтам.
        """
        results: List[Dict[str, Any]] = []

        for ep in self.endpoints:
            if ep.get("method", "GET").upper() != "GET":
                continue

            try:
                full_url = normalize_url(self.target, ep["url"])
                response = self.session.get(
                    full_url,
                    params=ep.get("params", {}),
                    headers=self.headers,
                    timeout=10,
                )
                html = response.text
                reflected = payload in html

                if reflected:
                    context = self.detector.detect_xss_context(html, payload)
                    js_hits = self.detector.scan_inline_js_for_payload(html, payload)
                else:
                    context, js_hits = "❌ Not reflected", []

                result: Dict[str, Any] = {
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
                    "vulnerable": reflected,
                }

                results.append(result)
                self._report_gui(result)

                try:
                    THREAT_CONNECTOR.add_artifact("XSSScanner", response.url, [result])
                except Exception as e:
                    logging.error(f"[EndpointScanner] ThreatConnector XSS error: {e}", exc_info=True)

            except requests.exceptions.RequestException as e:
                error_result = {
                    "url": ep.get("url"),
                    "error": str(e),
                    "source": ep.get("source", "unknown"),
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                }
                results.append(error_result)
                self._report_gui(error_result)
                logging.error(f"[EndpointScanner] XSS scan error for {ep.get('url')}: {e}")

        return results

    def fuzz_xss_parameters(self, base_params: Optional[Dict[str, Any]] = None, method: str = "GET") -> List[Dict[str, Any]]:
        """
        Выполняет XSS‑fuzzing параметров.

        Args:
            base_params: словарь базовых параметров
            method: HTTP‑метод (GET/POST)

        Returns:
            Список результатов fuzzing в формате, совместимом с AutoReconAnalyzerV2.
        """
        results: List[Dict[str, Any]] = []
        base_params = base_params or {}

        # Генерация payload‑ов через XSSDetector
        generated = self.detector.fuzz_xss_parameters(
            self.target,
            base_params,
            method,
        )

        for entry in generated:
            try:
                # ------------------------------------------------------------
                # 1. Определяем тип запроса
                # ------------------------------------------------------------
                if method.upper() == "GET" and isinstance(entry, str):
                    full_url = normalize_url(self.target, entry)
                    response = self.session.get(
                        full_url,
                        headers=self.headers,
                        timeout=10,
                    )
                    payload_str = entry

                elif isinstance(entry, dict):
                    url = normalize_url(self.target, entry.get("url", self.target))
                    response = self.session.post(
                        url,
                        json=entry.get("json", {}),
                        headers=self.headers,
                        timeout=10,
                    )
                    payload_str = json.dumps(entry.get("json", {}), ensure_ascii=False)

                else:
                    continue

                html = response.text
                reflected = payload_str in html

                # ------------------------------------------------------------
                # 2. Анализ отражения
                # ------------------------------------------------------------
                if reflected:
                    context = self.detector.detect_xss_context(html, payload_str)
                    js_hits = self.detector.scan_inline_js_for_payload(html, payload_str)
                else:
                    context, js_hits = "❌ Not reflected", []

                # ------------------------------------------------------------
                # 3. Формирование результата
                # ------------------------------------------------------------
                result = {
                    "module": "XSSFuzzer",
                    "url": response.url,
                    "request_url": response.url,
                    "status": response.status_code,
                    "method": method.upper(),
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
                    "severity": "high" if reflected else "info",
                }

                results.append(result)
                self._report_gui(result)

                try:
                    THREAT_CONNECTOR.add_artifact("XSSFuzzer", result["url"], [result])
                except Exception as e:
                    logging.error(f"[XSSFuzzer] ThreatConnector error: {e}", exc_info=True)

            except requests.exceptions.RequestException as e:
                # ------------------------------------------------------------
                # Ошибка запроса
                # ------------------------------------------------------------
                error_result = {
                    "module": "XSSFuzzer",
                    "url": entry if isinstance(entry, str) else entry.get("url", self.target),
                    "error": str(e),
                    "source": "xss_fuzzer",
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "severity": "error",
                    "vulnerable": False,
                }

                results.append(error_result)
                self._report_gui(error_result)

                try:
                    THREAT_CONNECTOR.add_artifact("XSSFuzzer", error_result["url"], [error_result])
                except Exception as e2:
                    logging.error(f"[XSSFuzzer] ThreatConnector error: {e2}", exc_info=True)

        return results

    # ============================================================
    #  GUI callback
    # ============================================================
    def _report_gui(self, data: Dict[str, Any]):
        """
        Безопасная отправка данных в GUI.

        Args:
            data: словарь результата или ошибки
        """
        data.setdefault("timestamp", datetime.datetime.utcnow().isoformat())
        wrapped = {"scanner": data}

        # Логирование
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

# ============================================================
#  Вспомогательные функции
# ============================================================

def extract_context(payload: str, html: str, context: int = 50) -> Optional[tuple[str, int]]:
    """Возвращает фрагмент HTML вокруг payload."""
    if not payload or not html:
        return None

    index = html.find(payload)
    if index == -1:
        return None

    start = max(0, index - context)
    end = min(len(html), index + len(payload) + context)
    return html[start:end], index


def categorize_reflection(payload: str, html: str) -> str:
    """Определяет категорию отражения payload."""
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
    """Возвращает подходящий payload для категории отражения."""
    mapping = {
        "🔤 Reflected HTML": "<script>alert(1)</script>",
        "🧬 Attribute Injection": '" onerror="alert(1)',
        "📜 Reflected JS": '";alert(1)//',
        "raw": "<img src=x onerror=alert(1)>",
    }
    return mapping.get(category, "<img src=x onerror=alert(1)>")


def scan_url(url: str) -> Dict[str, Any]:
    """Минимальный сканер одного URL."""
    try:
        r = requests.get(url, timeout=5)
        return {
            "module": "URLScanner",
            "url": url,
            "text": r.text[:2000],
            "headers": dict(r.headers),
            "status": r.status_code,
            "source": "scan_url",
            "timestamp": datetime.datetime.utcnow().isoformat(),
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
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }


def scan_multiple(urls: List[str]) -> List[Dict[str, Any]]:
    """Сканирует список URL и возвращает список структур."""
    return [scan_url(u) for u in urls]

# ============================================================
#  NDJSON логирование XSS
# ============================================================

LOG_DIR: Path = LOGS_DIR / "xss"
LOG_FILE: Path = LOG_DIR / "reflected_responses.json"

LOG_DIR.mkdir(parents=True, exist_ok=True)
_write_lock = threading.Lock()


def rotate_if_big(path: Path, max_mb: int = 20) -> None:
    """Ротирует файл, если он превышает max_mb мегабайт."""
    try:
        if not path.exists():
            return

        size = path.stat().st_size
        if size <= max_mb * 1024 * 1024:
            return

        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup = path.with_suffix(path.suffix + f".{ts}.bak")
        path.rename(backup)

        logging.info(f"[NDJSON] Лог ротирован: {path} → {backup}")
    except Exception as e:
        logging.error(f"[NDJSON] Ошибка ротации файла {path}: {e}", exc_info=True)


def validate_result(result: Dict[str, Any]) -> bool:
    """Минимальная валидация структуры XSS-артефакта."""
    required = {"url", "category", "context"}
    missing = required - result.keys()

    if missing:
        logging.warning(f"[NDJSON] Пропущены обязательные поля: {missing}")
        return False
    return True


def save_reflected_response(result: Dict[str, Any]) -> None:
    """Сохраняет XSS-отражение в NDJSON-файл."""
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        result.setdefault("_ts", datetime.datetime.utcnow().isoformat())

        if not validate_result(result):
            return

        rotate_if_big(LOG_FILE)

        with _write_lock:
            with LOG_FILE.open("a", encoding="utf-8") as f:
                f.write(json.dumps(result, ensure_ascii=False) + "\n")

        logging.info(f"[NDJSON] Сохранён артефакт: {result.get('url')} [{result.get('category')}]")
    except Exception as e:
        logging.error(f"[NDJSON] Ошибка записи артефакта: {e}", exc_info=True)


def load_reflected_responses(path: Path = LOG_FILE) -> List[Dict[str, Any]]:
    """Загружает NDJSON-файл и возвращает список артефактов."""
    results: List[Dict[str, Any]] = []

    if not path.exists():
        logging.warning(f"[NDJSON] Файл не найден: {path}")
        return results

    try:
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError as e:
                    logging.warning(f"[NDJSON] Ошибка JSON в строке: {e}")
    except Exception as e:
        logging.error(f"[NDJSON] Ошибка чтения файла {path}: {e}", exc_info=True)

    logging.info(f"[NDJSON] Загружено {len(results)} артефактов из {path}")
    return results



if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler("logs/xss_ndjson.log", encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )

    responses = load_reflected_responses()
    print(f"Загружено {len(responses)} результатов")

    for r in responses[:3]:
        print(r.get("url"), r.get("category"), r.get("context"))


