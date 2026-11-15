# xss_security_gui/idor_tab.py

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import threading
import json
import math
import logging
from typing import Any, Dict, List, Optional, Tuple

from xss_security_gui.idor_tester import fuzz_id_parameter
from xss_security_gui.settings import settings
from xss_security_gui.auto_recon.scope import is_target_authorized, normalize_http_url
from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge

from xss_security_gui.crawler import (
    get_random_user_agent,
    get_random_referer,
    get_random_language,
)



def _int_setting(key: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(settings.get(key, default))
    except (TypeError, ValueError):
        value = default
    return min(maximum, max(minimum, value))


def _float_setting(key: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(settings.get(key, default))
    except (TypeError, ValueError):
        value = default
    if not math.isfinite(value):
        value = default
    return min(maximum, max(minimum, value))


REQUEST_TIMEOUT = _int_setting("http.request_timeout", 10, 1, 30)
RATE_LIMIT = _float_setting("crawl.max_rps", 2.0, 0.1, 5.0)
MAX_REQUESTS_PER_TEST = _int_setting("crawl.max_matches_per_key", 200, 1, 200)
MAX_CONCURRENT_TESTS = _int_setting("crawl.max_workers", 3, 1, 3)

# Anti-detection settings
ENABLE_TLS_SPOOFING: bool = bool(settings.get("anti_detection.tls_spoofing", True))
ENABLE_PLAYWRIGHT_STEALTH: bool = bool(settings.get("anti_detection.playwright_stealth", True))
ENABLE_DOH_RESOLVER: bool = bool(settings.get("anti_detection.dns_over_https", True))
ENABLE_GEO_IP_ROTATION: bool = bool(settings.get("anti_detection.geo_ip_rotation", True))
ENABLE_CHROME_FINGERPRINT: bool = bool(settings.get("anti_detection.chrome_fingerprint", True))
ENABLE_MULTI_SESSION_ROTATION: bool = bool(settings.get("anti_detection.multi_session", True))
ENABLE_AUTO_RETRY: bool = bool(settings.get("anti_detection.auto_retry", True))
# Sensitive extraction mode
ENABLE_ULTRA_SENSITIVE = bool(settings.get("sensitive.ultra_mode", False))


# ---------------------------------------------------------------------
# Logger and error logging helper
# ---------------------------------------------------------------------
logger = logging.getLogger("crawler")
logger.setLevel(logging.INFO)

# -----------------------------------------
# ADD THESE THREE LINES
# -----------------------------------------
COMMON_USER_AGENTS = []
COMMON_REFERERS = []
COMMON_LANGUAGES = []

# ---------------------------------------------------------------------
# Common JA3 fingerprints (real browser TLS ClientHello fingerprints)
# ---------------------------------------------------------------------
JA3_FINGERPRINTS = [
    # Chrome 120 (Windows)
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-13-16-5,23-24,0",

    # Firefox 121 (Windows)
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-13-16-5,23-24,0",

    # Safari 17.2 (macOS)
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-13-16-5,23-24,0",

    # Edge 120 (Windows)
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-13-16-5,23-24,0",

    # Opera 106 (Windows)
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-13-16-5,23-24,0"
]

# Common user agents for rotation
COMMON_USER_AGENTS.extend([
    # Windows 11 Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36",
    # Windows 11 Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36 Edg/125.0.2535.67",
    # macOS Sonoma Chrome
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36",
    # macOS Sonoma Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    # Linux Chrome
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36",
    # Android Chrome
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Mobile Safari/537.36",
    # iPhone Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
])

# Common referers
COMMON_REFERERS.extend([
    "https://www.facebook.com/",
    "https://www.instagram.com/",
    "https://www.reddit.com/",
    "https://news.google.com/",
    "https://www.youtube.com/",
    "https://www.linkedin.com/",
    "https://t.co/",  # Twitter redirect
    "https://l.facebook.com/",  # Facebook redirect
])

# Common accept languages
COMMON_LANGUAGES.extend([
    "en-CA,en;q=0.9",
    "en-AU,en;q=0.9",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "pl-PL,pl;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.8"
])


class IDORTab(ttk.Frame):
    """
    IDORTab ULTRA 7.x (боевой)

    • Уніфікований формат результатів
    • Threat Intel інтеграція (normalized severity + summary)
    • Стабільність GUI навіть при помилках
    • Підтримка кількох паралельних тестів
    """

    def __init__(self, parent, threat_tab=None):
        super().__init__(parent)
        self.threat_tab = threat_tab

        # всі результати (накопичувально, а не перезапис)
        self.results: List[Dict[str, Any]] = []

        # контроль паралельних тестів
        self.active_tests = 0
        self.max_workers = MAX_CONCURRENT_TESTS
        self._cancel_events: set[threading.Event] = set()

        # простий лок для потокобезпечних змін
        self._lock = threading.Lock()
        self._bridge = UIQueueBridge(self, poll_ms=50)

        self._build_ui()

    # ---------------------------------------------------------
    # UI
    # ---------------------------------------------------------
    def _build_ui(self):
        ctrl = ttk.Frame(self)
        ctrl.pack(fill="x", padx=5, pady=5)

        def add_labeled_entry(parent, label, width, default=""):
            ttk.Label(parent, text=label).pack(side="left", padx=5)
            entry = ttk.Entry(parent, width=width)
            if default:
                entry.insert(0, default)
            entry.pack(side="left", padx=5)
            return entry

        url_row = ttk.Frame(ctrl)
        url_row.pack(fill="x", pady=2)
        self.url_entry = add_labeled_entry(url_row, "🔗 URL:", 60)
        self.url_entry.pack_configure(fill="x", expand=True)

        fields_row = ttk.Frame(ctrl)
        fields_row.pack(fill="x", pady=2)
        self.param_entry = add_labeled_entry(fields_row, "🔑 Параметр:", 10, "user_id")
        self.method_combo = ttk.Combobox(
            fields_row, values=["GET", "POST"], width=6, state="readonly"
        )
        self.method_combo.set("GET")
        ttk.Label(fields_row, text="📦 Метод:").pack(side="left", padx=(5, 0))
        self.method_combo.pack(side="left", padx=5)
        self.start_entry = add_labeled_entry(fields_row, "🔢 Start:", 5, "1")
        self.stop_entry = add_labeled_entry(fields_row, "Stop:", 5, "5")
        self.delay_entry = add_labeled_entry(fields_row, "⏱️ Delay:", 5, "0.5")

        auth_row = ttk.Frame(ctrl)
        auth_row.pack(fill="x", pady=2)
        self.token_entry = add_labeled_entry(auth_row, "🔐 Token:", 20)
        self.agent_entry = add_labeled_entry(
            auth_row,
            "🧭 Agent:",
            28,
            str(settings.get("http.default_user_agent", "XSS-Security-GUI/6.5")),
        )
        self.use_rotation_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            auth_row,
            text="UA rotation",
            variable=self.use_rotation_var
        ).pack(side="left", padx=5)

        actions = ttk.Frame(ctrl)
        actions.pack(fill="x", pady=2)
        ttk.Button(actions, text="🧪 Тестувати", command=self.start_test).pack(
            side="left", padx=5
        )
        ttk.Button(actions, text="⏹️ Зупинити", command=self.cancel_tests).pack(
            side="left", padx=5
        )
        ttk.Button(actions, text="♻️ Очистити", command=self.clear_result).pack(
            side="left", padx=5
        )
        ttk.Button(actions, text="📤 Експорт", command=self.export_result).pack(
            side="left", padx=5
        )

        self.result_box = tk.Text(
            self,
            bg="black",
            fg="white",
            height=25,
            wrap="none",
            insertbackground="white",
        )
        self.result_box.pack(fill="both", expand=True, padx=10, pady=5)

        # Кольорові теги
        self.result_box.tag_config("CRITICAL", foreground="red")
        self.result_box.tag_config("HIGH", foreground="lime")
        self.result_box.tag_config("MEDIUM", foreground="yellow")
        self.result_box.tag_config("LOW", foreground="cyan")
        self.result_box.tag_config("INFO", foreground="white")
        self.result_box.tag_config("ERROR", foreground="red")

    # ---------------------------------------------------------
    # Thread-safe log
    # ---------------------------------------------------------
    def _safe_log(self, data: Any) -> None:
        self._bridge.call_ui(self._append, data)

    def _append(self, data: Any) -> None:
        if isinstance(data, tuple):
            text, tag = data
            self.result_box.insert("end", text, tag)
        else:
            self.result_box.insert("end", data)
        self.result_box.see("end")

    # ---------------------------------------------------------
    # Validation
    # ---------------------------------------------------------
    def validate_inputs(self) -> Optional[Tuple[str, str, str, str, int, int, float]]:
        url = self.url_entry.get().strip()
        param = self.param_entry.get().strip()
        method = self.method_combo.get().strip().upper()
        token = self.token_entry.get().strip()

        if not url or not param:
            messagebox.showerror("Помилка", "Вкажи URL і параметр")
            return None
        if any(ord(char) < 32 for char in param):
            messagebox.showerror("Помилка", "Параметр містить неприпустимі символи")
            return None

        try:
            url = normalize_http_url(url)
        except ValueError as exc:
            messagebox.showerror("Помилка", f"Некоректний URL: {exc}")
            return None

        if not is_target_authorized(url):
            messagebox.showerror(
                "Ціль не дозволена",
                "Реальні IDOR-запити дозволені лише для цілей з ALLOWED_TARGETS "
                "при ввімкненому ALLOW_REAL_RUN.",
            )
            return None

        if method not in ("GET", "POST"):
            messagebox.showerror("Помилка", "Метод повинен бути GET або POST")
            return None

        try:
            start = int(self.start_entry.get().strip())
            stop = int(self.stop_entry.get().strip())
            delay = float(self.delay_entry.get().strip())
        except ValueError:
            messagebox.showerror("Помилка", "Start, Stop і Delay повинні бути числами")
            return None

        if not math.isfinite(delay):
            messagebox.showerror("Помилка", "Delay повинен бути скінченним числом")
            return None
        if start > stop:
            messagebox.showerror("Помилка", "Start не може бути більшим за Stop")
            return None

        if start < 0:
            messagebox.showerror("Помилка", "Start не може бути від’ємним")
            return None

        if stop - start + 1 > MAX_REQUESTS_PER_TEST:
            messagebox.showerror(
                "Перевищено ліміт",
                f"Один тест може виконати не більше {MAX_REQUESTS_PER_TEST} запитів.",
            )
            return None

        minimum_delay = 1.0 / RATE_LIMIT
        if delay < minimum_delay:
            messagebox.showerror(
                "Занадто мала затримка",
                f"Затримка має бути не меншою за {minimum_delay:.2f} с "
                f"(ліміт {RATE_LIMIT:g} запитів/с).",
            )
            return None

        return url, param, method, token, start, stop, delay

    # ---------------------------------------------------------
    # Start test
    # ---------------------------------------------------------
    def start_test(self):
        with self._lock:
            if self.active_tests >= self.max_workers:
                self._safe_log("⚠️ Досягнуто ліміт потоків, зачекай завершення.\n")
                return

        validated = self.validate_inputs()
        if not validated:
            return

        url, param, method, token, start, stop, delay = validated
        agent = self.agent_entry.get().strip() or "Igor"
        rotate_ua = self.use_rotation_var.get()
        cancel_event = threading.Event()

        self._safe_log(
            f"\n🧬 Запуск IDOR-тесту: {url} [param={param}, method={method}, range={start}-{stop}]\n"
        )

        with self._lock:
            self.active_tests += 1
            self._cancel_events.add(cancel_event)

        try:
            self._bridge.post_bg(
                self._run_idor,
                None,
                url,
                param,
                method,
                token,
                start,
                stop,
                delay,
                agent,
                name=f"IDOR-{url}-{param}",
                rotate_ua=rotate_ua,
                cancel_event=cancel_event,
            )
        except Exception as exc:
            with self._lock:
                self.active_tests = max(0, self.active_tests - 1)
                self._cancel_events.discard(cancel_event)
            self._safe_log((f"❌ Не вдалося запустити IDOR-тест: {exc}\n", "ERROR"))

    def cancel_tests(self):
        with self._lock:
            cancel_events = tuple(self._cancel_events)
        if not cancel_events:
            self._safe_log("ℹ️ Немає активних тестів для зупинки.\n")
            return
        for cancel_event in cancel_events:
            cancel_event.set()
        self._safe_log("⏹️ Надіслано запит на зупинку активних тестів.\n")

    # ---------------------------------------------------------
    # Severity нормалізація для Threat Intel
    # ---------------------------------------------------------
    @staticmethod
    def _map_severity(differs: bool, r: Dict[str, Any]) -> str:
        """
        Threat Intel очікує: critical, high, medium, low, info, none
        """
        if not differs or not r.get("comparison_reliable", True):
            return "info"

        # якщо є явні маркери чужих даних
        markers = r.get("user_markers") or []
        if markers:
            return "critical"

        # якщо статус 200 і довжина/контент сильно відрізняються
        status = r.get("status")
        if status == 200 and r.get("length", 0) > 0:
            return "medium"

        return "low"

    @staticmethod
    def _severity_tag(severity: str) -> str:
        if severity == "critical":
            return "CRITICAL"
        if severity == "high":
            return "HIGH"
        if severity == "medium":
            return "MEDIUM"
        if severity == "low":
            return "LOW"
        return "INFO"

    # ---------------------------------------------------------
    # Run IDOR logic
    # ---------------------------------------------------------
    def _run_idor(
        self,
        url,
        param,
        method,
        token,
        start,
        stop,
        delay,
        agent,
        name=None,
        rotate_ua=True,
        cancel_event=None,
    ):

        try:
            headers = {
                "User-Agent": agent,
            }

            # UA rotation toggle
            if rotate_ua:
                headers["User-Agent"] = get_random_user_agent()
            else:
                headers["User-Agent"] = agent

            # 2. Referer rotation
            headers["Referer"] = get_random_referer()
            # 3. Language rotation
            headers["Accept-Language"] = get_random_language()
            # 4. Chrome fingerprint headers
            headers["Accept"] = (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            )
            headers["Accept-Encoding"] = "gzip, deflate, br"
            headers["Connection"] = "keep-alive"
            headers["Upgrade-Insecure-Requests"] = "1"

            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Dest"] = "document"

            headers["Sec-Ch-Ua"] = (
                "\"Chromium\";v=\"129\", \"Google Chrome\";v=\"129\", \"Not=A?Brand\";v=\"99\""
            )
            headers["Sec-Ch-Ua-Mobile"] = "?0"
            headers["Sec-Ch-Ua-Platform"] = "\"Windows\""
            # 5. Anti-WAF headers
            headers["X-Requested-With"] = "XMLHttpRequest"
            headers["DNT"] = "1"
            headers["Pragma"] = "no-cache"
            headers["Cache-Control"] = "no-cache"

            # токен у заголовках для реалістичного бою
            if token:
                headers["Authorization"] = f"Bearer {token}"
                headers["X-Auth-Token"] = token
                headers["Authorization"] = "Bearer " + token

            try:
                results = fuzz_id_parameter(
                    url,
                    param=param,
                    start=start,
                    stop=stop,
                    method=method,
                    headers=headers,
                    delay=delay,
                    timeout=REQUEST_TIMEOUT,
                    auth_token=token or None,
                    cancel_event=cancel_event,
                    on_result=lambda result: self._record_idor_result(result, url),
                )
            except Exception as e:
                self._safe_log((f"❌ Помилка виконання fuzz_id_parameter: {e}\n", "ERROR"))
                return

            if not results:
                if cancel_event and cancel_event.is_set():
                    self._safe_log("⏹️ IDOR-тест зупинено.\n")
                else:
                    self._safe_log("ℹ️ IDOR-тест завершено, але результатів немає.\n")
                return

            if cancel_event and cancel_event.is_set():
                self._safe_log("⏹️ IDOR-тест зупинено; показано отримані результати.\n")

        except Exception as e:
            self._safe_log((f"❌ Помилка: {e}\n", "ERROR"))

        finally:
            with self._lock:
                self.active_tests = max(0, self.active_tests - 1)
                if cancel_event is not None:
                    self._cancel_events.discard(cancel_event)

    def _record_idor_result(self, result: Dict[str, Any], fallback_url: str) -> None:
        with self._lock:
            self.results.append(result)

        differs = bool(result.get("differs", False))
        status = result.get("status", "?")
        length = result.get("length", "?")
        hash_ = result.get("hash", "?")
        full_url = result.get("url") or fallback_url
        value = result.get("value")
        summary = result.get("summary") or ""
        markers = result.get("user_markers") or []

        severity_norm = self._map_severity(differs, result)
        severity_tag = self._severity_tag(severity_norm)
        mark = "✅ Різниця" if differs else "⚠️ Повтор"
        line = (
            f"{mark} | {full_url} | [status={status}] "
            f"| len={length} | hash={hash_} | value={value}\n"
        )
        self._safe_log((line, severity_tag))

        if summary:
            self._safe_log((f"   🧠 Summary: {summary}\n", "INFO"))
        if markers:
            self._safe_log((f"   👤 Markers: {', '.join(markers)}\n", "INFO"))
        if "error" in result:
            self._safe_log((f"   ❌ Помилка: {result['error']}\n", "ERROR"))

        if self.threat_tab and hasattr(self.threat_tab, "add_threat"):
            threat = {
                "type": "IDOR",
                "url": full_url,
                "payload": value,
                "status": status,
                "length": length,
                "differs": differs,
                "hash": hash_,
                "truncated": result.get("truncated", False),
                "comparison_reliable": result.get("comparison_reliable", False),
                "severity": severity_norm,
                "summary": summary,
                "markers": markers,
                "source": "IDOR Scanner",
            }
            self._bridge.post_ui(self.threat_tab.add_threat, threat)

    # ---------------------------------------------------------
    # Clear
    # ---------------------------------------------------------
    def clear_result(self):
        self.result_box.delete("1.0", "end")
        with self._lock:
            self.results = []

    # ---------------------------------------------------------
    # Export
    # ---------------------------------------------------------
    def export_result(self):
        with self._lock:
            if not self.results:
                messagebox.showinfo("Експорт", "Немає даних для експорту")
                return

        export_type = simpledialog.askstring(
            "Формат експорту",
            "Вибери формат: markdown або json",
        )

        if not export_type:
            return

        export_type = export_type.lower().strip()
        if export_type not in ("markdown", "json"):
            messagebox.showerror("Помилка", "Підтримуються тільки markdown і json")
            return

        ext = ".md" if export_type == "markdown" else ".json"
        file_path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[("Усі файли", "*.*")],
        )

        if not file_path:
            return

        try:
            if export_type == "markdown":
                self._export_markdown(file_path)
            else:
                self._export_json(file_path)

            messagebox.showinfo("Експорт", f"Результати збережено:\n{file_path}")

        except Exception as e:
            messagebox.showerror("Помилка експорту", str(e))

    # ---------------------------------------------------------
    # Export helpers
    # ---------------------------------------------------------
    @staticmethod
    def _markdown_escape(value: Any) -> str:
        text = str(value if value is not None else "")
        return (
            text.replace("\\", "\\\\")
            .replace("`", "&#96;")
            .replace("|", "\\|")
            .replace("\r", " ")
            .replace("\n", " ")
        )

    def _export_markdown(self, file_path):
        with self._lock:
            data = list(self.results)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write("# 🧬 IDOR Scan Results\n\n")
            for r in data:
                differs = bool(r.get("differs"))
                severity = self._map_severity(differs, r)
                mark = "✅" if differs else "⚠️"
                url = r.get("url") or "unknown"
                status = r.get("status", "?")
                length = r.get("length", "?")
                hash_ = r.get("hash", "?")
                value = r.get("value")
                summary = r.get("summary") or ""
                markers = r.get("user_markers") or []

                f.write(f"{mark} `{self._markdown_escape(url)}`\n")
                f.write(f"- Param value: `{self._markdown_escape(value)}`\n")
                f.write(f"- Status: `{self._markdown_escape(status)}`\n")
                f.write(f"- Length: `{self._markdown_escape(length)}`\n")
                f.write(f"- Hash: `{self._markdown_escape(hash_)}`\n")
                f.write(f"- Severity: `{self._markdown_escape(severity)}`\n")
                if summary:
                    f.write(f"- Summary: `{self._markdown_escape(summary)}`\n")
                if markers:
                    f.write(
                        f"- Markers: `{self._markdown_escape(', '.join(markers))}`\n"
                    )
                if "error" in r:
                    f.write(f"- ❌ Error: `{self._markdown_escape(r['error'])}`\n")
                f.write("\n")

    def _export_json(self, file_path):
        with self._lock:
            data = list(self.results)

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def destroy(self):
        with self._lock:
            for cancel_event in self._cancel_events:
                cancel_event.set()
        self._bridge.stop()
        super().destroy()
