# xss_security_gui/dom_parser_tab.py
"""
DOMParserTab ULTRA 10.0
Burp Suite Pro‑level DOM Inspector:
- Playwright full browser rendering
- JS-aware DOM analysis
- Network capture (XHR/fetch/axios)
- Console logs
- JS endpoints extraction
- Dynamic DOM snapshot
- Threat Intel integration
"""
import re
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
from datetime import datetime
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse

import requests

from playwright.sync_api import sync_playwright
from xss_security_gui.crawler import (
    get_random_session,
    should_retry,
    extract_sensitive_data,
    build_anti_waf_headers,
    build_browser_headers,
)

from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge
from xss_security_gui.utils.threat_sender import ThreatSenderMixin
from xss_security_gui.file_loader import save_json

try:
    from xss_security_gui.dom_parser import DOMParser
    _DOM_PARSER_IMPORT_ERROR: Optional[ImportError] = None
except ImportError as exc:
    DOMParser = None
    _DOM_PARSER_IMPORT_ERROR = exc


# ---------------------------------------------------------------------
# Automatic Retry Strategy
# ---------------------------------------------------------------------

MAX_RETRIES = 5
RETRY_DELAYS = [1, 2, 4]  # Exponential backoff (1s → 2s → 4s)

# Retry-worthy HTTP status codes:
# 408 — Request Timeout
# 429 — Too Many Requests (rate limit)
# 5xx — Server errors
RETRY_STATUS_CODES = {
    408,
    429,
    500,
    502,
    503,
    504,
}



class DOMParserTab(ttk.Frame, ThreatSenderMixin):
    """
    DOMParserTab ULTRA 10.0
    Реалізує повноцінний браузерний DOM‑аналізатор:
    - Playwright headless Chromium
    - Network/XHR/fetch/axios перехоплення
    - Console logs/errors
    - JS endpoints
    - Dynamic DOM snapshot
    """

    def __init__(self, parent, threat_tab=None):
        super().__init__(parent)

        # External integration
        self.threat_tab = threat_tab

        # Internal state
        self.servers: List[Dict[str, Any]] = []
        self.current_html: Optional[str] = None
        self.dom_results: Dict[str, Any] = {}
        self.network_log: List[Dict[str, Any]] = []
        self.console_log: List[Dict[str, Any]] = []
        self.js_endpoints: List[str] = []
        self.api_endpoints: List[str] = []
        self.dynamic_dom: Optional[str] = None
        self.security_headers: Dict[str, Any] = {}
        self.cookies: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {}
        self.blocked: bool = False
        self.http_status: Optional[int] = None


        # Crawler recon data
        self.websockets: List[str] = []
        self.comments: List[str] = []

        # Infrastructure
        self.hostnames: List[str] = []
        self.ips: List[str] = []
        self.ipv6: List[str] = []
        self.cidr: List[str] = []

        # Infrastructure Intelligence
        self.detected_frameworks: List[str] = []
        self.detected_servers: List[str] = []
        self.detected_waf: List[str] = []
        self.detected_analytics: List[str] = []
        self.detected_frontend: List[str] = []
        self.detected_services: List[str] = []

        # Sensitive data
        self.emails: List[str] = []
        self.phones: List[str] = []
        self.api_keys: List[str] = []
        self.jwt_tokens: List[str] = []
        self.interesting_jwt: List[str] = []
        self.weak_jwt: List[str] = []

        # JWT Intelligence
        self.jwt_algorithms: List[str] = []
        self.jwt_issuers: List[str] = []
        self.jwt_subjects: List[str] = []
        self.expired_jwt: List[str] = []
        self.anonymous_jwt: List[str] = []
        self.admin_jwt: List[str] = []
        self.secrets: List[str] = []
        self.parameters: List[str] = []
        self.hashes: List[str] = []
        self.base64_strings: List[str] = []
        self.uuids: List[str] = []

        # DOM extras
        self.data_attributes: List[str] = []

        # UI engine
        self._bridge = UIQueueBridge(self, poll_ms=60)

        # Status throttling
        self._last_status_update = 0.0
        self._progress_running = False

        if not DOMParser:
            self._show_missing_parser_warning()

        self._build_ui_ultra()

    def _show_missing_parser_warning(self):
        """
        Показывает профессиональное предупреждение о том,
        что модуль DOMParser отсутствует или не загружен.
        Сообщение оформлено в стиле Burp Suite / Pro Tools.
        """
        warning_text = (
            "Модуль DOMParser не загружен.\n\n"
            "Возможные причины:\n"
            " • Ошибка импорта пакета xss_security_gui.dom_parser\n"
            " • Отсутствует зависимость beautifulsoup4\n\n"
            "Рекомендации:\n"
            " • Проверьте установку beautifulsoup4\n"
            " • Проверьте журнал приложения для подробностей\n"
            " • Перезапустите приложение после исправления"
        )
        if _DOM_PARSER_IMPORT_ERROR is not None:
            warning_text += (
                f"\n\nОшибка импорта: {type(_DOM_PARSER_IMPORT_ERROR).__name__}: "
                f"{_DOM_PARSER_IMPORT_ERROR}"
            )

        try:
            messagebox.showwarning("⚠️ DOMParser недоступен", warning_text)
        except Exception:
            pass

        # Отправляем предупреждение в Threat Intel (если есть)
        try:
            if self.threat_tab:
                artifact = {
                    "category": "dom_parser_missing",
                    "risk": "medium",
                    "message": "DOMParser module missing or failed to load",
                }
                self.send_to_threat_intel("dom_parser_missing", [artifact])
        except Exception:
            pass


    # ============================================================
    # UI BUILDING (ULTRA VERSION)
    # ============================================================

    def _build_ui_ultra(self):
        """Створює повністю оновлений UI з новими вкладками."""

        # ============================
        # CONTROL PANEL
        # ============================
        ctrl_frame = ttk.LabelFrame(self, text="🔧 Управление", padding=10)
        ctrl_frame.pack(fill="x", padx=10, pady=5)

        # URL input
        url_frame = ttk.Frame(ctrl_frame)
        url_frame.pack(fill="x", pady=5)

        ttk.Label(url_frame, text="URL/Файл:").pack(side="left", padx=5)
        self.url_entry = ttk.Entry(url_frame, width=50)
        self.url_entry.insert(0, "https://example.com")
        self.url_entry.pack(side="left", padx=5, fill="x", expand=True)

        ttk.Button(url_frame, text="📂 HTML файл", command=self.load_html_file).pack(side="left", padx=2)

        # Action buttons
        btn_frame = ttk.Frame(ctrl_frame)
        btn_frame.pack(fill="x", pady=5)

        ttk.Button(btn_frame, text="🌐 Загрузить", command=self.fetch_and_parse).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="📄 Анализировать", command=self.parse_html).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="🗑 Очистить", command=self.clear_results).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="💾 Экспорт JSON", command=self.export_results).pack(side="left", padx=2)

        # Options
        options_frame = ttk.LabelFrame(ctrl_frame, text="⚙️ Опции анализа", padding=5)
        options_frame.pack(fill="x", pady=5)

        self.extract_forms_var = tk.BooleanVar(value=True)
        self.extract_scripts_var = tk.BooleanVar(value=True)
        self.extract_events_var = tk.BooleanVar(value=True)
        self.extract_media_var = tk.BooleanVar(value=True)
        self.extract_links_var = tk.BooleanVar(value=True)
        self.use_playwright_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(options_frame, text="📋 Формы", variable=self.extract_forms_var).pack(side="left", padx=5)
        ttk.Checkbutton(options_frame, text="📜 Скрипты", variable=self.extract_scripts_var).pack(side="left", padx=5)
        ttk.Checkbutton(options_frame, text="⚡ События", variable=self.extract_events_var).pack(side="left", padx=5)
        ttk.Checkbutton(options_frame, text="🖼 Медиа", variable=self.extract_media_var).pack(side="left", padx=5)
        ttk.Checkbutton(options_frame, text="🔗 Ссылки", variable=self.extract_links_var).pack(side="left", padx=5)

        ttk.Checkbutton(
            options_frame,
            text="🧠 Браузерный рендер (Playwright)",
            variable=self.use_playwright_var
        ).pack(side="left", padx=5)

        # ============================
        # RESULT NOTEBOOK
        # ============================
        result_frame = ttk.LabelFrame(self, text="📊 Результаты анализа", padding=10)
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.notebook = ttk.Notebook(result_frame)
        self.notebook.pack(fill="both", expand=True)

        # Summary
        self.summary_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.summary_frame, text="📋 Сводка")

        self.summary_text = self._make_textbox(self.summary_frame, "#00ff00")

        # Forms
        self.forms_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.forms_frame, text="📋 Формы")
        self.forms_text = self._make_textbox(self.forms_frame, "#ffff00")

        # Scripts
        self.scripts_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scripts_frame, text="📜 Скрипты")
        self.scripts_text = self._make_textbox(self.scripts_frame, "#00ffff")

        # Events
        self.events_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.events_frame, text="⚡ События")
        self.events_text = self._make_textbox(self.events_frame, "#ff00ff")

        # Media
        self.media_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.media_frame, text="🖼 Медиа")
        self.media_text = self._make_textbox(self.media_frame, "#00ff99")

        # NEW: Network
        self.network_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.network_frame, text="🌐 Network")
        self.network_text = self._make_textbox(self.network_frame, "#ffaa00")

        # NEW: JS Endpoints
        self.js_endpoints_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.js_endpoints_frame, text="🛰 JS Endpoints")
        self.js_endpoints_text = self._make_textbox(self.js_endpoints_frame, "#ffdd00")

        # NEW: API Endpoints
        self.api_endpoints_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.api_endpoints_frame, text="🌐 API Endpoints")
        self.api_endpoints_text = self._make_textbox(self.api_endpoints_frame, "#66ccff")

        # NEW: WebSockets

        self.websockets_frame = ttk.Frame(self.notebook)
        self.notebook.add(
            self.websockets_frame,
            text="📡 WebSockets"
        )

        self.websockets_text = self._make_textbox(
            self.websockets_frame,
            "#00ffaa"
        )

        # NEW: Comments

        self.comments_frame = ttk.Frame(self.notebook)
        self.notebook.add(
            self.comments_frame,
            text="💬 Comments"
        )

        self.comments_text = self._make_textbox(
            self.comments_frame,
            "#cccccc"
        )

        # NEW: Infrastructure

        self.infrastructure_frame = ttk.Frame(self.notebook)
        self.notebook.add(
            self.infrastructure_frame,
            text="📡 Infrastructure"
        )

        self.infrastructure_text = self._make_textbox(
            self.infrastructure_frame,
            "#66ffcc"
        )

        # NEW: Servers

        self.servers_frame = ttk.Frame(
            self.notebook
        )

        self.notebook.add(
            self.servers_frame,
            text="🖥 Servers"
        )

        self.servers_text = self._make_textbox(
            self.servers_frame,
            "#66ff66"
        )

        # NEW: Sensitive Data

        self.sensitive_frame = ttk.Frame(self.notebook)
        self.notebook.add(
            self.sensitive_frame,
            text="📦 Sensitive Data"
        )

        self.sensitive_text = self._make_textbox(
            self.sensitive_frame,
            "#ff9999"
        )

        # NEW: Console Logs
        self.console_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.console_frame, text="🧩 Console")
        self.console_text = self._make_textbox(self.console_frame, "#ff4444")

        # NEW: Dynamic DOM
        self.dynamic_dom_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dynamic_dom_frame, text="🧬 Dynamic DOM")
        self.dynamic_dom_text = self._make_textbox(
            self.dynamic_dom_frame,
            "#66ff66"
        )

        # NEW: Security Headers
        self.security_headers_frame = ttk.Frame(self.notebook)
        self.notebook.add(
            self.security_headers_frame,
            text="🛡 Security Headers"
        )

        self.security_headers_text = self._make_textbox(
            self.security_headers_frame,
            "#ff6666"
        )

        # NEW: Cookies
        self.cookies_frame = ttk.Frame(self.notebook)
        self.notebook.add(
            self.cookies_frame,
            text="🍪 Cookies"
        )

        self.cookies_text = self._make_textbox(
            self.cookies_frame,
            "#ffaa66"
        )

        # ============================
        # STATUS BAR
        # ============================
        self.status_label = ttk.Label(self, text="Готов к анализу", relief="sunken")
        self.status_label.pack(fill="x", padx=5, pady=2)

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", padx=5, pady=1)

    # ============================================================
    # HELPERS
    # ============================================================

    def _make_textbox(self, parent, fg):
        """Створює текстове поле з темною темою."""
        text = tk.Text(parent, height=15, bg="#1e1e1e", fg=fg, wrap="word")
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        return text

    # ============================================================
    # FILE LOADING
    # ============================================================

    def load_html_file(self):
        """Завантажити HTML файл."""
        path = filedialog.askopenfilename(
            title="Выбери HTML файл",
            filetypes=[("HTML files", "*.html *.htm"), ("All files", "*.*")]
        )
        if path:
            self.url_entry.delete(0, "end")
            self.url_entry.insert(0, path)

    # ============================================================
    # FETCH & ANALYZE (Playwright + fallback)
    # ============================================================

    def fetch_and_parse(self):
        """
        Завантажити URL або локальний HTML файл.
        """

        url = self.url_entry.get().strip()

        print("=" * 80)
        print("[DOM] FETCH REQUEST")
        print(f"[DOM] Input: {url}")

        if not url:
            messagebox.showwarning(
                "⚠️ Требуется URL",
                "Пожалуйста, введите URL",
            )
            return

        if not url.startswith(("http://", "https://")) and not os.path.isfile(url):
            url = f"https://{url}"

        print(f"[DOM] Normalized URL: {url}")

        self._update_status(
            "⏳ Загрузка страницы...",
            True,
        )

        self._bridge.post_bg(
            self._fetch_and_parse_thread,
            None,
            url,
        )

    def _fetch_and_parse_thread(self, url: str):
        """
        Фонове завантаження сторінки.
        """

        print("=" * 80)
        print(f"[DOM] WORKER STARTED")
        print(f"[DOM] Target: {url}")

        try:

            # ------------------------------------------------------
            # LOCAL FILE
            # ------------------------------------------------------

            if os.path.isfile(url):
                print(f"[DOM] Reading local file: {url}")

                with open(
                        url,
                        "r",
                        encoding="utf-8",
                ) as f:
                    html = f.read()

                self.current_html = html
                self.dynamic_dom = html

                print(
                    f"[DOM] Local HTML loaded: {len(html)} bytes"
                )

                self._update_status(
                    "✅ HTML файл загружен",
                    False,
                )

                self._bridge.post_ui(self.parse_html)

                return

            # ------------------------------------------------------
            # WEB FETCH
            # ------------------------------------------------------

            engine = (
                "playwright"
                if self.use_playwright_var.get()
                else "requests"
            )

            print(f"[DOM] Fetch engine: {engine}")

            if self.use_playwright_var.get():

                result = self._fetch_page_playwright_ultra(
                    url
                )

            else:

                result = self._fetch_page_requests(
                    url
                )

            if not result.get("success"):
                error = result.get("error")

                print(
                    f"[DOM] Fetch failed: {error}"
                )

                self._update_status(
                    f"❌ Ошибка загрузки: {error}",
                    False,
                )

                self._bridge.post_ui(
                    messagebox.showerror,
                    "Ошибка загрузки",
                    str(error),
                )

                return

            html = result.get("html") or ""

            print(
                f"[DOM] HTML loaded: {len(html)} bytes"
            )

            self.current_html = html
            self.dynamic_dom = (
                    result.get("dom")
                    or html
            )

            self.network_log = (
                    result.get("network")
                    or []
            )

            self.console_log = (
                    result.get("console")
                    or []
            )

            self.js_endpoints = (
                    result.get("js_endpoints")
                    or []
            )


            api_patterns = (
                "/api/",
                "/v1/",
                "/v2/",
                "/v3/",
                "/rest/",
                "/graphql",
                "/rpc/",
                "/backend/",
                "/gateway/",
                "/auth/",
                "/oauth/",
            )

            self.api_endpoints = sorted(
                {
                    endpoint
                    for endpoint in self.js_endpoints
                    if any(
                    p in endpoint.lower()
                    for p in api_patterns
                )
                }
            )

            self.security_headers = (
                result.get(
                    "security_headers",
                    {}
                )
            )

            self.cookies = (
                result.get(
                    "cookies",
                    []
                )
            )

            # ------------------------------------------------------------------
            # Crawler Recon Data
            # ------------------------------------------------------------------
            self.websockets = (
                result.get(
                    "websockets",
                    []
                )
            )

            self.comments = (
                result.get(
                    "comments",
                    []
                )
            )

            # Infrastructure

            self.hostnames = (
                result.get(
                    "hostnames",
                    []
                )
            )

            self.ips = (
                result.get(
                    "ips",
                    []
                )
            )

            self.ipv6 = (
                result.get(
                    "ipv6",
                    []
                )
            )

            self.cidr = (
                result.get(
                    "cidr",
                    []
                )
            )

            # Sensitive

            self.emails = (
                result.get(
                    "emails",
                    []
                )
            )

            self.phones = (
                result.get(
                    "phones",
                    []
                )
            )

            self.api_keys = (
                result.get(
                    "api_keys",
                    []
                )
            )

            self.jwt_tokens = (
                result.get(
                    "jwt_tokens",
                    []
                )
            )

            self.interesting_jwt = (
                result.get(
                    "interesting_jwt",
                    []
                )
            )

            self.weak_jwt = (
                result.get(
                    "weak_jwt",
                    []
                )
            )

            self.jwt_algorithms = (
                result.get(
                    "jwt_algorithms",
                    []
                )
            )

            self.jwt_issuers = (
                result.get(
                    "jwt_issuers",
                    []
                )
            )

            self.jwt_subjects = (
                result.get(
                    "jwt_subjects",
                    []
                )
            )

            self.expired_jwt = (
                result.get(
                    "expired_jwt",
                    []
                )
            )

            self.anonymous_jwt = (
                result.get(
                    "anonymous_jwt",
                    []
                )
            )

            self.admin_jwt = (
                result.get(
                    "admin_jwt",
                    []
                )
            )

            self.secrets = (
                result.get(
                    "secrets",
                    []
                )
            )

            self.parameters = (
                result.get(
                    "parameters",
                    []
                )
            )

            self.hashes = (
                result.get(
                    "hashes",
                    []
                )
            )

            self.base64_strings = (
                result.get(
                    "base64_strings",
                    []
                )
            )

            self.uuids = (
                result.get(
                    "uuids",
                    []
                )
            )

            # DOM Extras

            self.data_attributes = (
                result.get(
                    "data_attributes",
                    []
                )
            )

            self.servers = (
                result.get(
                    "servers",
                    []
                )
            )

            self.detected_frameworks = (
                result.get(
                    "detected_frameworks",
                    []
                )
            )

            self.detected_servers = (
                result.get(
                    "detected_servers",
                    []
                )
            )

            self.detected_waf = (
                result.get(
                    "detected_waf",
                    []
                )
            )

            self.detected_analytics = (
                result.get(
                    "detected_analytics",
                    []
                )
            )

            self.detected_frontend = (
                result.get(
                    "detected_frontend",
                    []
                )
            )

            self.detected_services = (
                result.get(
                    "detected_services",
                    []
                )
            )

            self.metadata = (
                    result.get("metadata")
                    or {}
            )

            self.blocked = (
                    result.get("blocked")
                    or False
            )

            self.http_status = result.get(
                "status"
            )

            if self.blocked:
                print(
                    "[DOM] Security/WAF page detected"
                )

                self._update_status(
                    "⚠️ Possible security block detected",
                    False,
                )

            print(
                f"[DOM] Network entries: {len(self.network_log)}"
            )

            print(
                f"[DOM] Console entries: {len(self.console_log)}"
            )

            print(
                f"[DOM] JS endpoints: {len(self.js_endpoints)}"
            )

            print(
                f"[DOM] HTTP Status: {self.http_status}"
            )

            print(
                f"[DOM] Blocked: {self.blocked}"
            )

            print(
                f"[DOM] Final URL: "
                f"{self.metadata.get('final_url')}"
            )

            self._update_status(
                "✅ HTML загружен",
                False,
            )

            self._bridge.post_ui(
                self.parse_html
            )

        except Exception as e:

            import traceback

            traceback.print_exc()

            print(
                f"[DOM] WORKER CRASH: {e}"
            )

            self._update_status(
                f"❌ Ошибка: {e}",
                False,
            )

            self._bridge.post_ui(
                messagebox.showerror,
                "DOM Parser Error",
                str(e),
            )

    # ============================================================
    # PLAYWRIGHT ENGINE (ULTRA)
    # ============================================================

    def _fetch_page_playwright_ultra(self, url: str) -> dict:
        """
        Полноценный Playwright‑рендер:
        - HTML/DOM
        - Network (XHR/fetch/axios)
        - Console logs
        - JS endpoints
        """
        print("=" * 80)
        print("[PLAYWRIGHT] START")
        print(f"[PLAYWRIGHT] URL = {url}")

        try:
            network_log: List[Dict[str, Any]] = []
            console_log: List[Dict[str, Any]] = []
            js_endpoints: List[str] = []

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                print("[PLAYWRIGHT] Browser launched")
                session = get_random_session()
                # headers = build_anti_waf_headers()
                headers = build_browser_headers(region="ru")

                context = browser.new_context(
                    user_agent=session["user_agent"],
                    viewport=session["viewport"],
                    extra_http_headers=headers,
                )

                page = context.new_page()

                # --- Network capture ---
                def on_request(request):

                    try:
                        post_data = request.post_data

                        if (
                                isinstance(post_data, str)
                                and len(post_data) > 5000
                        ):
                            post_data = (
                                    post_data[:5000]
                                    + "\n...[truncated]"
                            )
                    except Exception:
                        post_data = "<binary-data>"

                    network_log.append(
                        {
                            "method": request.method,
                            "url": request.url,
                            "headers": dict(request.headers),
                            "resource_type": request.resource_type,
                            "post_data": post_data,
                        }
                    )

                def on_response(response):
                    try:
                        body = ""
                        # Не читаем огромные бинарники
                        if "text" in response.headers.get("content-type", ""):
                            body = response.text()
                    except Exception:
                        body = "<unavailable>"
                    for entry in network_log:

                        if entry["url"] == response.url:
                            entry["status"] = response.status

                            entry["body"] = body

                            entry["content_type"] = (
                                response.headers.get(
                                    "content-type",
                                    ""
                                )
                            )

                            entry["server_header"] = (
                                response.headers.get(
                                    "server",
                                    ""
                                )
                            )

                            entry["powered_by"] = (
                                response.headers.get(
                                    "x-powered-by",
                                    ""
                                )
                            )

                            break

                page.on("request", on_request)
                page.on("response", on_response)

                # --- Console capture ---
                def on_console(msg):
                    console_log.append({
                        "type": msg.type,
                        "text": msg.text,
                    })

                page.on("console", on_console)

                # --- JS endpoints (fetch/XHR/axios) ---
                js_hook = """
                (function() {
                    const endpoints = [];

                    // fetch
                    if (window.fetch) {
                        const origFetch = window.fetch;
                        window.fetch = function() {
                            try {
                                const url = arguments[0];
                                if (typeof url === 'string') {
                                    endpoints.push(url);
                                } else if (url && url.url) {
                                    endpoints.push(url.url);
                                }
                            } catch (e) {}
                            return origFetch.apply(this, arguments);
                        };
                    }

                    // XMLHttpRequest
                    if (window.XMLHttpRequest) {
                        const OrigXHR = window.XMLHttpRequest;
                        const open = OrigXHR.prototype.open;
                        OrigXHR.prototype.open = function(method, url) {
                            try {
                                endpoints.push(url);
                            } catch (e) {}
                            return open.apply(this, arguments);
                        };
                    }

                    // axios
                    if (window.axios && window.axios.interceptors && window.axios.interceptors.request) {
                        window.axios.interceptors.request.use(function(config) {
                            try {
                                if (config && config.url) {
                                    endpoints.push(config.url);
                                }
                            } catch (e) {}
                            return config;
                        });
                    }

                    window.__xssgui_js_endpoints = endpoints;
                })();
                """

                page.add_init_script(js_hook)

                response = None

                for attempt in range(MAX_RETRIES):

                    try:

                        response = page.goto(
                            url,
                            timeout=30000,
                            wait_until="domcontentloaded",
                        )

                        status = (
                            response.status
                            if response
                            else 200
                        )

                        print(
                            f"[PLAYWRIGHT] Attempt #{attempt + 1}"
                        )

                        print(
                            f"[PLAYWRIGHT] HTTP STATUS: {status}"
                        )

                        if should_retry(status):

                            if attempt < len(RETRY_DELAYS):

                                delay = RETRY_DELAYS[attempt]

                            else:

                                delay = RETRY_DELAYS[-1]

                            print(
                                f"[PLAYWRIGHT] Retry after {delay}s"
                            )

                            time.sleep(delay)

                            continue

                        break

                    except Exception as ex:

                        print(
                            f"[PLAYWRIGHT] Navigation error: {ex}"
                        )

                        if attempt >= MAX_RETRIES - 1:
                            raise

                        if attempt < len(RETRY_DELAYS):

                            delay = RETRY_DELAYS[attempt]

                        else:

                            delay = RETRY_DELAYS[-1]

                        time.sleep(delay)

                print("[PLAYWRIGHT] Page loaded")

                print(
                    f"[PLAYWRIGHT] FINAL URL: {page.url}"
                )

                final_status = (
                    response.status
                    if response
                    else None
                )

                response_headers = (
                    response.headers
                    if response
                    else {}
                )

                security_headers = {
                    "Content-Security-Policy":
                        response_headers.get(
                            "content-security-policy"
                        ),

                    "Strict-Transport-Security":
                        response_headers.get(
                            "strict-transport-security"
                        ),

                    "X-Frame-Options":
                        response_headers.get(
                            "x-frame-options"
                        ),

                    "X-Content-Type-Options":
                        response_headers.get(
                            "x-content-type-options"
                        ),

                    "Referrer-Policy":
                        response_headers.get(
                            "referrer-policy"
                        ),

                    "Permissions-Policy":
                        response_headers.get(
                            "permissions-policy"
                        ),
                }

                print(
                    f"[PLAYWRIGHT] FINAL STATUS: {final_status}"
                )


                # DOM snapshot
                dom_html = page.content()
                from bs4 import BeautifulSoup, Comment
                soup = BeautifulSoup(
                    dom_html,
                    "html.parser"
                )
                comments = []

                for comment in soup.find_all(
                        string=lambda t: isinstance(
                            t,
                            Comment,
                        )
                ):
                    txt = str(comment).strip()

                    if txt:
                        comments.append(txt[:1000])  # limit to 1000 chars

                data_attributes = []

                for tag in soup.find_all(True):

                    for attr, value in tag.attrs.items():

                        if attr.startswith("data-"):
                            data_attributes.append(
                                f"{tag.name}.{attr}={value}"
                            )

                websockets = list(
                    set(
                        re.findall(
                            r"wss?://[^\s\"']+",
                            dom_html,
                            re.I,
                        )
                    )
                )

                hostnames = list(
                    set(
                        re.findall(
                            r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}",
                            dom_html,
                        )
                    )
                )

                bad_suffixes = {
                    "png",
                    "jpg",
                    "jpeg",
                    "gif",
                    "svg",
                    "webp",
                    "css",
                    "js",
                    "ico",
                    "woff",
                    "woff2",
                    "ttf",
                    "eot",
                }

                bad_prefixes = (
                    "document.",
                    "window.",
                    "screen.",
                    "navigator.",
                    "math.",
                    "classlist.",
                )

                hostnames = sorted(
                    {
                        h.lower()

                        for h in hostnames

                        if (
                                   h.split(".")[-1].lower()
                                   not in bad_suffixes
                           )

                           and not any(
                        h.lower().startswith(
                            prefix
                        )
                        for prefix in bad_prefixes
                    )
                    }
                )

                # ============================================================
                # Analysis Sources
                # ============================================================

                dom_text = dom_html

                network_text = ""

                javascript_text = ""

                inline_js_text = ""

                # ============================================================
                # Network responses
                # ============================================================

                for req in network_log:
                    network_text += "\n"

                    network_text += req.get(
                        "url",
                        ""
                    )

                    network_text += "\n"

                    network_text += str(
                        req.get(
                            "body",
                            ""
                        )
                    )

                # ============================================================
                # External script sources
                # ============================================================

                script_sources = set()

                for script in soup.find_all("script"):

                    src = script.get("src")

                    if not src:
                        continue

                    if isinstance(src, list):

                        for item in src:

                            if isinstance(item, str):
                                script_sources.add(item)

                    elif isinstance(src, str):

                        script_sources.add(src)

                javascript_text += "\n".join(
                    script_sources
                )

                # ============================================================
                # Download JS
                # ============================================================
                from urllib.parse import urljoin

                js_contents = []

                for src in script_sources:

                    try:

                        js_url = urljoin(
                            page.url,
                            src,
                        )

                        print(
                            f"[PLAYWRIGHT] Download JS: {js_url}"
                        )

                        response = page.context.request.get(
                            js_url,
                            timeout=10000,
                        )

                        if not response.ok:
                            continue

                        js_text = response.text()

                        # захист від величезних bundle

                        if len(js_text) > 5000000:
                            js_text = js_text[:5000000]

                        js_contents.append(
                            js_text
                        )

                    except Exception as ex:

                        print(
                            f"[PLAYWRIGHT] JS load failed: {src} -> {ex}"
                        )

                javascript_text += "\n".join(
                    js_contents
                )

                # ============================================================
                # Inventory servers
                # ============================================================

                servers = {}

                for entry in network_log:

                    try:

                        parsed = urlparse(
                            entry.get(
                                "url",
                                "",
                            )
                        )

                        host = parsed.netloc.lower()

                        if not host:
                            continue

                        if host not in servers:
                            servers[host] = {
                                "host": host,
                                "requests": 0,
                                "statuses": set(),
                                "resource_types": set(),
                                "content_types": set(),
                                "server_headers": set(),
                                "powered_by": set(),
                                "ips": set(),
                                "ipv6": set(),
                                "cidr": set(),
                                "samples": [],
                                "response_samples": [],
                                # Infrastructure Intelligence
                                "detected_technologies": set(),
                                "detected_frameworks": set(),
                                "detected_servers": set(),
                                "detected_waf": set(),
                                "detected_analytics": set(),
                                "detected_frontend": set(),
                                "detected_services": set(),
                                "detected_cdn": set(),
                                "detected_auth": set(),
                                "country": "",
                                "provider": "",
                                "asn": "",

                            }

                        srv = servers[host]

                        #
                        # Role intelligence
                        #
                        if "auth." in host:
                            srv["detected_auth"].add(
                                "Authentication"
                            )

                        if "api." in host:
                            srv["detected_services"].add(
                                "API"
                            )

                        if "cdn" in host:
                            srv["detected_cdn"].add(
                                "CDN"
                            )

                        if "yandex" in host:
                            srv["detected_analytics"].add(
                                "Yandex Metrika"
                            )

                        if "mail.ru" in host:
                            srv["detected_analytics"].add(
                                "Mail.ru Analytics"
                            )

                        if "targetads" in host:
                            srv["detected_analytics"].add(
                                "TargetAds"
                            )

                        if "adriver" in host:
                            srv["detected_analytics"].add(
                                "AdRiver"
                            )

                        srv["requests"] += 1

                        status = entry.get("status")

                        if status:
                            srv["statuses"].add(status)

                        resource_type = entry.get(
                            "resource_type"
                        )

                        if resource_type:
                            srv["resource_types"].add(
                                resource_type
                            )

                        if len(srv["samples"]) < 10:
                            srv["samples"].append(
                                entry.get(
                                    "url",
                                    ""
                                )
                            )
                        body = entry.get(
                            "body",
                            ""
                        )

                        if (
                                isinstance(body, str)
                                and body
                                and len(srv["response_samples"]) < 5
                        ):
                            srv["response_samples"].append(
                                body[:300]
                            )

                        content_type = entry.get(
                            "content_type"
                        )

                        if content_type:
                            srv["content_types"].add(
                                content_type
                            )

                        server_header = entry.get(
                            "server_header"
                        )

                        if server_header:
                            srv["server_headers"].add(
                                server_header
                            )

                        if server_header:

                            value = server_header.lower()

                            if "nginx" in value:
                                srv["detected_servers"].add(
                                    "nginx"
                                )

                            if "apache" in value:
                                srv["detected_servers"].add(
                                    "Apache"
                                )

                            if "iis" in value:
                                srv["detected_servers"].add(
                                    "IIS"
                                )

                            if "openresty" in value:
                                srv["detected_servers"].add(
                                    "OpenResty"
                                )

                            if "cloudflare" in value:
                                srv["detected_cdn"].add(
                                    "Cloudflare"
                                )

                        powered_by = entry.get(
                            "powered_by"
                        )

                        if powered_by:
                            srv["powered_by"].add(
                                powered_by
                            )

                        if powered_by:

                            value = powered_by.lower()

                            if "express" in value:
                                srv["detected_technologies"].add(
                                    "Express"
                                )

                            if "next" in value:
                                srv["detected_frameworks"].add(
                                    "Next.js"
                                )

                            if "react" in value:
                                srv["detected_frameworks"].add(
                                    "React"
                                )

                            if "php" in value:
                                srv["detected_technologies"].add(
                                    "PHP"
                                )

                            if "asp.net" in value:
                                srv["detected_technologies"].add(
                                    "ASP.NET"
                                )

                    except Exception:
                        pass

                # ============================================================
                # Servers list
                # ============================================================
                servers_list = []

                for srv in servers.values():
                    servers_list.append(
                        {
                            "host": srv["host"],
                            "requests": srv["requests"],
                            "statuses": sorted(
                                srv["statuses"]
                            ),
                            "resource_types": sorted(
                                srv["resource_types"]
                            ),
                            "content_types": sorted(
                                srv["content_types"]
                            ),
                            "server_headers": sorted(
                                srv["server_headers"]
                            ),
                            "powered_by": sorted(
                                srv["powered_by"]
                            ),
                            "response_samples": (
                                srv["response_samples"]
                            ),
                            "detected_technologies":
                                sorted(
                                    srv["detected_technologies"]
                                ),

                            "detected_frameworks":
                                sorted(
                                    srv["detected_frameworks"]
                                ),

                            "detected_servers":
                                sorted(
                                    srv["detected_servers"]
                                ),

                            "detected_cdn":
                                sorted(
                                    srv["detected_cdn"]
                                ),

                            "detected_waf":
                                sorted(
                                    srv["detected_waf"]
                                ),

                            "detected_auth":
                                sorted(
                                    srv["detected_auth"]
                                ),

                            "detected_analytics":
                                sorted(
                                    srv["detected_analytics"]
                                ),

                            "detected_services":
                                sorted(
                                    srv["detected_services"]
                                ),

                            "country":
                                srv["country"],

                            "provider":
                                srv["provider"],

                            "asn":
                                srv["asn"],

                            "samples": srv["samples"],
                        }
                    )

                servers_list.sort(
                    key=lambda s: s["requests"],
                    reverse=True,
                )
                # ============================================================
                # Inline JavaScript
                # ============================================================

                script_content = []

                for script in soup.find_all("script"):

                    try:

                        if script.string:
                            script_content.append(
                                script.string
                            )

                    except Exception:
                        pass

                inline_js_text += "\n".join(
                    script_content
                )

                combined_text = (
                        dom_text
                        + "\n"
                        + network_text
                        + "\n"
                        + javascript_text
                        + "\n"
                        + inline_js_text
                )

                # ============================================================
                # Technology Detection
                # ============================================================
                detected_frameworks = set()
                detected_servers = set()
                detected_waf = set()
                detected_analytics = set()
                detected_frontend = set()
                detected_services = set()
                tech_source = (
                        dom_html
                        + "\n"
                        + javascript_text
                ).lower()

                if (
                        "__react"
                        in tech_source
                        or "react-dom"
                        in tech_source
                        or "react.production"
                        in tech_source
                ):
                    detected_frameworks.add(
                        "React"
                    )

                if (
                        "/_next/"
                        in tech_source
                        or "__next_data__"
                        in tech_source
                        or "_next/static"
                        in tech_source
                ):
                    detected_frameworks.add(
                        "Next.js"
                    )

                if (
                        "webpack"
                        in tech_source
                        or "/chunks/"
                        in tech_source
                ):
                    detected_frontend.add(
                        "Webpack"
                    )

                if (
                        "mc.yandex.ru"
                        in tech_source
                        or "ym("
                        in tech_source
                ):
                    detected_analytics.add(
                        "Yandex Metrika"
                    )

                if (
                        "matomo"
                        in tech_source
                        or "_paq"
                        in tech_source
                ):
                    detected_analytics.add(
                        "Matomo"
                    )

                if (
                        "auth."
                        in tech_source
                        or "/oauth"
                        in tech_source
                        or "/login"
                        in tech_source
                ):
                    detected_services.add(
                        "Authentication Service"
                    )

                detected_frameworks = sorted(
                    detected_frameworks
                )

                detected_servers = sorted(
                    detected_servers
                )

                detected_waf = sorted(
                    detected_waf
                )

                detected_analytics = sorted(
                    detected_analytics
                )

                detected_frontend = sorted(
                    detected_frontend
                )

                detected_services = sorted(
                    detected_services
                )
                # ============================================================
                # Sensitive extraction
                # ============================================================
                sensitive = extract_sensitive_data(
                    combined_text
                )

                emails = sensitive.get(
                    "emails",
                    []
                )

                phones = sensitive.get(
                    "phones",
                    []
                )

                ips = sensitive.get(
                    "ips",
                    []
                )

                ipv6 = sensitive.get(
                    "ipv6",
                    []
                )

                # прибираємо шумові IPv6

                ipv6 = [
                    ip
                    for ip in ipv6
                    if ip not in (
                        "::",
                        "::1",
                        "0:0:0:0:0:0:0:1",
                    )
                ]

                cidr = sensitive.get(
                    "cidr",
                    []
                )

                parameters = sensitive.get(
                    "parameters",
                    []
                )

                base64_strings = sensitive.get(
                    "base64_strings",
                    []
                )

                uuids = sensitive.get(
                    "uuids",
                    []
                )

                hashes = sensitive.get(
                    "hashes",
                    []
                )

                api_keys = sensitive.get(
                    "api_keys",
                    []
                )

                jwt_tokens = sensitive.get(
                    "jwt_tokens",
                    []
                )

                interesting_jwt = sensitive.get(
                    "interesting_jwt",
                    []
                )

                weak_jwt = sensitive.get(
                    "weak_jwt",
                    []
                )

                jwt_algorithms = sensitive.get(
                    "jwt_algorithms",
                    []
                )

                jwt_issuers = sensitive.get(
                    "jwt_issuers",
                    []
                )

                jwt_subjects = sensitive.get(
                    "jwt_subjects",
                    []
                )

                expired_jwt = sensitive.get(
                    "expired_jwt",
                    []
                )

                anonymous_jwt = sensitive.get(
                    "anonymous_jwt",
                    []
                )

                admin_jwt = sensitive.get(
                    "admin_jwt",
                    []
                )

                secrets = sensitive.get(
                    "secrets",
                    []
                )
                page_title = page.title()
                html_lower = dom_html.lower()

                html_head = html_lower[:10000]

                blocked_markers = [
                    "access denied",
                    "request blocked",
                    "forbidden",
                ]

                security_blocked = any(
                    marker in html_head
                    for marker in blocked_markers
                )

                print(
                    f"[PLAYWRIGHT] TITLE: {page_title}"
                )

                print(
                    f"[PLAYWRIGHT] BLOCKED: {security_blocked}"
                )
                print(
                    f"[PLAYWRIGHT] DOM size = {len(dom_html)}"
                )
                print("=" * 80)
                print(dom_html[:1000])
                print("=" * 80)

                # JS endpoints snapshot
                try:
                    endpoints = page.evaluate("() => window.__xssgui_js_endpoints || []")
                    js_endpoints = list(dict.fromkeys(endpoints))  # unique
                except Exception:
                    js_endpoints = []

                # ------------------------------------------------------------
                # API Endpoints Extraction
                # ------------------------------------------------------------
                api_patterns = (
                    "/api/",
                    "/v1/",
                    "/v2/",
                    "/v3/",
                    "/rest/",
                    "/graphql",
                    "/rpc/",
                    "/backend/",
                    "/gateway/",
                    "/auth/",
                    "/oauth/",
                )

                api_endpoints = sorted(
                    {
                        endpoint

                        for endpoint in js_endpoints

                        if isinstance(endpoint, str)

                           and any(
                        pattern in endpoint.lower()
                        for pattern in api_patterns
                    )
                    }
                )

                print(
                    f"[PLAYWRIGHT] JS endpoints: {len(js_endpoints)}"
                )

                print(
                    f"[PLAYWRIGHT] API endpoints: {len(api_endpoints)}"
                )

                final_url = page.url
                cookies = context.cookies()
                context.close()
                browser.close()

                print(
                    f"[PLAYWRIGHT] WebSockets: {len(websockets)}"
                )

                print(
                    f"[PLAYWRIGHT] Comments: {len(comments)}"
                )

                print(
                    f"[PLAYWRIGHT] Emails: {len(emails)}"
                )

                print(
                    f"[PLAYWRIGHT] Phones: {len(phones)}"
                )

                print(
                    f"[PLAYWRIGHT] Hostnames: {len(hostnames)}"
                )

                print(
                    f"[PLAYWRIGHT] Data Attributes: {len(data_attributes)}"
                )

                print(
                    f"[PLAYWRIGHT] IPs: {len(ips)}"
                )

                print(
                    f"[PLAYWRIGHT] UUIDs: {len(uuids)}"
                )

                print(
                    f"[PLAYWRIGHT] API Keys: {len(api_keys)}"
                )

                print(
                    f"[PLAYWRIGHT] JWT: {len(jwt_tokens)}"
                )

                print(
                    f"[PLAYWRIGHT] Secrets: {len(secrets)}"
                )

            return {
                "success": True,
                "html": dom_html,
                "dom": dom_html,
                "network": network_log,
                "console": console_log,
                "js_endpoints": js_endpoints,
                "security_headers": security_headers,
                "cookies": cookies,
                "status": final_status,
                "blocked": security_blocked,
                "api_endpoints": api_endpoints,
                "websockets": websockets,
                "comments": comments,

                "servers": servers_list,
                "detected_frameworks": detected_frameworks,
                "detected_servers": detected_servers,
                "detected_waf": detected_waf,
                "detected_analytics": detected_analytics,
                "detected_frontend": detected_frontend,
                "detected_services": detected_services,

                "hostnames": hostnames,
                "ips": ips,
                "ipv6": ipv6,
                "cidr": cidr,

                "parameters": parameters,
                "base64_strings": base64_strings,
                "uuids": uuids,
                "hashes": hashes,

                "api_keys": api_keys,
                "jwt_tokens": jwt_tokens,
                "interesting_jwt": interesting_jwt,
                "weak_jwt": weak_jwt,

                "jwt_algorithms": jwt_algorithms,
                "jwt_issuers": jwt_issuers,
                "jwt_subjects": jwt_subjects,

                "expired_jwt": expired_jwt,
                "anonymous_jwt": anonymous_jwt,
                "admin_jwt": admin_jwt,

                "secrets": secrets,
                "emails": emails,
                "phones": phones,

                "data_attributes": data_attributes,

                "metadata": {
                    "final_url": final_url,
                    "status": final_status,
                    "network_entries": len(network_log),
                    "console_entries": len(console_log),
                    "js_endpoints": len(js_endpoints),
                    "dom_size": len(dom_html),
                    "page_title": page_title,
                },
        }


        except Exception as e:
            import traceback
            traceback.print_exc()
            return {
                "success": False,
                "error": str(e),
            }


    def _fetch_page_requests(self, url: str) -> dict:
        """
        ULTRA Requests Fallback Engine.

        Features:
        - Session pooling
        - Redirect tracking
        - Header capture
        - Timing metrics
        - Encoding detection
        - Safe HTML limits
        - Diagnostics
        """

        import time

        started = time.perf_counter()

        try:

            print("=" * 80)
            print("[REQUESTS] START")
            print(f"[REQUESTS] URL: {url}")

            session = requests.Session()

            # headers = build_anti_waf_headers(
            #     {
            #         "Accept": (
            #             "text/html,"
            #             "application/xhtml+xml,"
            #             "application/xml;q=0.9,"
            #             "*/*;q=0.8"
            #         ),
            #     }
            # )

            headers = build_browser_headers(
                region="ru"
            )

            response = session.get(
                url,
                headers=headers,
                timeout=(10, 30),
                allow_redirects=True,
                verify=True,
            )

            response.raise_for_status()

            security_headers = {
                "Content-Security-Policy":
                    response.headers.get(
                        "Content-Security-Policy"
                    ),

                "Strict-Transport-Security":
                    response.headers.get(
                        "Strict-Transport-Security"
                    ),

                "X-Frame-Options":
                    response.headers.get(
                        "X-Frame-Options"
                    ),

                "X-Content-Type-Options":
                    response.headers.get(
                        "X-Content-Type-Options"
                    ),

                "Referrer-Policy":
                    response.headers.get(
                        "Referrer-Policy"
                    ),

                "Permissions-Policy":
                    response.headers.get(
                        "Permissions-Policy"
                    ),
            }

            cookies = [
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                }
                for cookie in session.cookies
            ]

            if not response.encoding:
                response.encoding = response.apparent_encoding

            html = response.text

            html_lower = html.lower()

            blocked = any(
                marker in html_lower
                for marker in (
                    "forbidden",
                    "access denied",
                    "captcha",
                    "request blocked",
                )
            )

            print(
                f"[REQUESTS] BLOCKED: {blocked}"
            )

            max_size = 25 * 1024 * 1024

            if len(html.encode("utf-8")) > max_size:
                raise ValueError(
                    f"HTML exceeds limit: {max_size:,} bytes"
                )

            elapsed = (
                    time.perf_counter() - started
            )

            network_entry = {
                "url": response.url,
                "method": "GET",
                "status": response.status_code,
                "content_type": response.headers.get(
                    "Content-Type",
                    "",
                ),
                "content_length": len(html),
                "server": response.headers.get(
                    "Server",
                    "",
                ),
                "elapsed_sec": round(
                    elapsed,
                    3,
                ),
                "redirects": [
                    r.url
                    for r in response.history
                ],
            }

            print(
                f"[REQUESTS] Status: {response.status_code}"
            )

            print(
                f"[REQUESTS] HTML size: {len(html):,}"
            )

            print(
                f"[REQUESTS] Redirects: {len(response.history)}"
            )

            return {
                "success": True,
                "html": html,
                "dom": html,
                "blocked": blocked,
                "security_headers": security_headers,
                "cookies": cookies,

                "network": [
                    network_entry
                ],

                "console": [
                    {
                        "type": "requests",
                        "text":
                            f"HTTP {response.status_code} "
                            f"({response.status_code})",
                    }
                ],

                "js_endpoints": [],

                "metadata": {
                    "url": response.url,
                    "status": response.status_code,
                    "server": response.headers.get(
                        "Server",
                        ""
                    ),
                    "content_type": response.headers.get(
                        "Content-Type",
                        ""
                    ),
                    "redirect_count": len(
                        response.history
                    ),
                    "fetch_time": round(
                        elapsed,
                        3,
                    ),
                },
            }

        except Exception as e:

            import traceback

            traceback.print_exc()

            print(
                f"[REQUESTS] ERROR: {e}"
            )

            return {
                "success": False,
                "error": str(e),
            }

    # ============================================================
    # PARSE HTML (DOMParser)
    # ============================================================

    def parse_html(self):
        """Запустить DOM‑анализ."""
        if not self.current_html:
            path = self.url_entry.get().strip()
            if os.path.isfile(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        self.current_html = f.read()
                        self.dynamic_dom = self.current_html
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Ошибка чтения файла: {e}")
                    return
            else:
                messagebox.showwarning(
                    "⚠️ HTML не загружен",
                    "Сначала загрузите страницу с URL или выберите HTML файл",
                )
                return

        self._bridge.post_bg(self._parse_thread_ultra)

    def _parse_thread_ultra(self):
        """Фоновый поток: DOMParser + Threat Intel."""
        try:
            self._update_status("🔍 Анализ DOM структуры...", True)

            if DOMParser is None:
                self._update_status("❌ DOMParser не доступен", False)
                self._bridge.post_ui(
                    messagebox.showerror,
                    "Ошибка",
                    "Модуль DOMParser не загружен",
                )
                return

            parser = DOMParser(self.current_html)
            results = parser.parse(self.current_html)
            self.dom_results = results

            self._bridge.post_ui(self._display_results_ultra, results)
            self._update_status("✅ Анализ завершён", False)
            self._bridge.post_ui(
                messagebox.showinfo,
                "✅ Анализ",
                "Анализ DOM завершён успешно!",
            )

            # Threat Intel: отправляем артефакт
            if self.threat_tab:
                artifact = {
                    "category": "dom_parser_ultra",
                    "risk": "info",
                    "results": self.dom_results,
                    "network": self.network_log,
                    "console": self.console_log,
                    "js_endpoints": self.js_endpoints,
                }
                self.send_to_threat_intel("dom_parser_ultra", [artifact])

        except Exception as e:
            self._update_status(f"❌ Ошибка анализа: {e}", False)
            self._bridge.post_ui(messagebox.showerror, "Ошибка", f"Ошибка при анализе: {e}")

    # ============================================================
    # DISPLAY RESULTS (ULTRA VIEW)
    # ============================================================
    def _display_results_ultra(self, results: Dict[str, Any]):
        """Отобразить результаты анализа во всех вкладках."""
        # Очистка
        self.servers_text.delete("1.0","end")
        self.summary_text.delete("1.0", "end")
        self.forms_text.delete("1.0", "end")
        self.scripts_text.delete("1.0", "end")
        self.events_text.delete("1.0", "end")
        self.media_text.delete("1.0", "end")
        self.network_text.delete("1.0", "end")
        self.js_endpoints_text.delete("1.0", "end")
        self.api_endpoints_text.delete("1.0","end")
        self.console_text.delete("1.0", "end")
        self.dynamic_dom_text.delete("1.0", "end")
        self.security_headers_text.delete("1.0","end",)
        self.websockets_text.delete("1.0","end")
        self.comments_text.delete("1.0","end")
        self.infrastructure_text.delete("1.0","end")
        self.sensitive_text.delete("1.0","end")
        self.cookies_text.delete("1.0","end",)

        elements = results.get("elements", [])
        forms = results.get("forms", [])
        scripts = results.get("scripts", [])
        events = results.get("dom_events", [])
        media = results.get("media", [])
        links = results.get("links", [])

        headers = results.get("headers", [])
        lists_data = results.get("lists", [])
        json_ld = results.get("json_ld", [])
        canonical = results.get("canonical", {})

        inline_scripts = [
            s for s in scripts
            if s.get("inline")
        ]

        external_scripts = [
            s for s in scripts
            if s.get("src")
        ]
        high_risk_events = [
            e for e in events
            if "Высокий" in e.get("risk_level", "")
        ]

        metadata = self.metadata or {}

        risk_score = (
                len(high_risk_events) * 10
                + len(inline_scripts) * 3
                + len(self.js_endpoints)
                + len(forms)
        )

        # Sensitive Findings

        risk_score += len(self.api_keys) * 75

        risk_score += len(self.jwt_tokens) * 75

        risk_score += len(self.secrets) * 40

        risk_score += min(
            len(self.base64_strings),
            20
        )

        risk_score += min(
            len(self.hashes),
            10
        )

        risk_score += min(
            len(self.parameters),
            20
        )

        risk_score += min(
            len(self.phones),
            10
        )

        risk_level = (
            "CRITICAL"
            if risk_score > 150 else
            "HIGH"
            if risk_score > 75 else
            "MEDIUM"
            if risk_score > 30 else
            "LOW"
        )

        js_density = round(
            (len(scripts) / max(len(elements), 1)) * 100,
            2
        )

        link_density = round(
            (len(links) / max(len(elements), 1)) * 100,
            2
        )

        risk_icon = {
            "LOW": "🟢",
            "MEDIUM": "🟡",
            "HIGH": "🔴",
            "CRITICAL": "🚨",
        }.get(risk_level, "⚪")

        elements_per_form = (
            round(
                len(elements) / len(forms),
                2
            )
            if forms
            else "N/A"
        )

        dom_complexity = (
            "HIGH"
            if len(elements) > 5000 else
            "MEDIUM"
            if len(elements) > 1500 else
            "LOW"
        )

        # SUMMARY
        summary = f"""
        ═══════════════════════════════════════════════════════════════
        🔍 DOM АНАЛИЗ — СВОДКА (ULTRA)
        ═══════════════════════════════════════════════════════════════

        📊 Структура DOM:
          • Всего элементов: {len(elements)}
          • Форм: {len(forms)}
          • Скриптов: {len(scripts)}
          • Событий: {len(events)}
          • Медиа: {len(media)}
          • Ссылок: {len(links)}

        🧠 JavaScript:
          • Внешние скрипты: {len(external_scripts)}
          • Inline скрипты: {len(inline_scripts)}
          • Высокорисковые события: {len(high_risk_events)}
          • JS endpoints: {len(self.js_endpoints)}
          • API endpoints: {len(self.api_endpoints)}
          • WebSockets: {len(self.websockets)}
          • Comments: {len(self.comments)}
          
        🎯 Risk Overview:
          • Risk score: {risk_score}
          • Risk level: {risk_icon} {risk_level}

        📡 Browser Telemetry:
          • Network requests: {metadata.get("network_entries", len(self.network_log))}
          • Console entries: {metadata.get("console_entries", len(self.console_log))}
          • Captured endpoints: {metadata.get("js_endpoints", len(self.js_endpoints))}
          • Hostnames: {len(self.hostnames)}
          • Servers: {len(self.servers)}
          • IPv4: {len(self.ips)}
          • IPv6: {len(self.ipv6)}

        🌐 HTTP:
          • Status: {self.http_status}
          • Blocked: {"YES" if self.blocked else "NO"}

        🧭 Navigation:
          • Final URL: {metadata.get("final_url", "—")}
          • Page title: {metadata.get("page_title", "—")}

        📄 DOM Snapshot:
          • DOM size: {metadata.get("dom_size", 0):,} bytes
          • Elements per form: {elements_per_form}
          • DOM complexity: {dom_complexity}
        
        📑 SEO / Structure:
          • Headers: {len(headers)}
          • Lists: {len(lists_data)}
          • JSON-LD blocks: {len(json_ld)}
          • Canonical URL: {"YES" if canonical else "NO"}
             
        📈 Density Metrics:
          • JS density: {js_density}%
          • Link density: {link_density}%
        
        ⚠️ Security Indicators:
          • Inline scripts: {len(inline_scripts)}
          • Event handlers: {len(events)}
          • Dynamic endpoints: {len(self.js_endpoints)}
          • Console messages: {len(self.console_log)}
        
        📦 Sensitive Data:
          • Emails: {len(self.emails)}
          • Phones: {len(self.phones)}
          • Parameters: {len(self.parameters)}
          • UUIDs: {len(self.uuids)}
          • Base64: {len(self.base64_strings)}
          • Hashes: {len(self.hashes)}
          • API Keys: {len(self.api_keys)}
          • JWT Tokens: {len(self.jwt_tokens)}
          • Secrets: {len(self.secrets)}
          • Interesting JWT: {len(self.interesting_jwt)}
          • Weak JWT: {len(self.weak_jwt)}
          ════════ JWT INTELLIGENCE ════════
          • JWT Algorithms: {len(self.jwt_algorithms)}
          • JWT Issuers: {len(self.jwt_issuers)}
          • JWT Subjects: {len(self.jwt_subjects)}
          • Expired JWT: {len(self.expired_jwt)}
          • Anonymous JWT: {len(self.anonymous_jwt)}
          • Admin JWT: {len(self.admin_jwt)}
          
        
        ═══════════════════════════════════════════════════════════════
        """
        self.summary_text.insert("1.0", summary)

        headers_text = (
            "═══════════════════════════════════════\n"
            "🛡 SECURITY HEADERS\n"
            "═══════════════════════════════════════\n\n"
        )

        for header, value in (
                self.security_headers.items()
        ):
            headers_text += (
                f"{header}: "
                f"{value or '❌ Missing'}\n"
            )

        self.security_headers_text.insert(
            "1.0",
            headers_text,
        )

        cookies_text = (
            "═══════════════════════════════════════\n"
            "🍪 COOKIES\n"
            "═══════════════════════════════════════\n\n"
        )

        for cookie in self.cookies:
            cookies_text += (
                f"Name: "
                f"{cookie.get('name')}\n"
                f"Domain: "
                f"{cookie.get('domain')}\n"
                f"Path: "
                f"{cookie.get('path', '/')}\n\n"
            )

        self.cookies_text.insert(
            "1.0",
            cookies_text,
        )

        # FORMS
        if self.extract_forms_var.get():
            forms_text = "═══════════════════════════════════════════════════════════════\n"
            forms_text += "📋 ФОРМЫ\n"
            forms_text += "═══════════════════════════════════════════════════════════════\n\n"

            for idx, form in enumerate(forms, 1):
                forms_text += f"🔹 Форма #{idx}\n"
                forms_text += f"   Action: {form.get('action', '—')}\n"
                forms_text += f"   Method: {form.get('method', 'GET')}\n"
                inputs = form.get("inputs", [])
                forms_text += f"   Inputs: {', '.join([i.get('name', '?') for i in inputs])}\n"
                js_events = form.get("js_events") or {}
                forms_text += f"   JS обработчики: {', '.join(js_events.keys()) if js_events else '—'}\n\n"

            self.forms_text.insert("1.0", forms_text)

        # SCRIPTS
        if self.extract_scripts_var.get():
            scripts_text = "═══════════════════════════════════════════════════════════════\n"
            scripts_text += "📜 СКРИПТЫ\n"
            scripts_text += "═══════════════════════════════════════════════════════════════\n\n"

            for idx, script in enumerate(scripts, 1):
                src = script.get("src", "")
                content = script.get("content", "")
                inline = "[INLINE]" if content else "[EXTERNAL]"
                scripts_text += f"🔹 Скрипт #{idx} {inline}\n"
                if src:
                    scripts_text += f"   Src: {src}\n"
                if content:
                    preview = content[:160].replace("\n", " ")
                    scripts_text += f"   Content: {preview}...\n"
                scripts_text += "\n"

            self.scripts_text.insert("1.0", scripts_text)

        # EVENTS
        if self.extract_events_var.get():
            events_text = "═══════════════════════════════════════════════════════════════\n"
            events_text += "⚡ СОБЫТИЯ И ОБРАБОТЧИКИ\n"
            events_text += "═══════════════════════════════════════════════════════════════\n\n"

            for idx, event in enumerate(events, 1):
                risk = event.get("risk")
                if risk == "high":
                    risk_label = "⚠️ ВЫСОКИЙ"
                elif risk == "medium":
                    risk_label = "ℹ️ СРЕДНИЙ"
                else:
                    risk_label = "✓ НИЗКИЙ"

                events_text += f"🔹 Событие #{idx}\n"
                events_text += f"   Тип: {event.get('type', '?')}\n"
                events_text += f"   Элемент: {event.get('element', '?')}\n"
                events_text += f"   Обработчик: {event.get('handler', '—')}\n"
                events_text += f"   Риск: {risk_label}\n\n"

            self.events_text.insert("1.0", events_text)

        # MEDIA
        if self.extract_media_var.get():
            media_text = "═══════════════════════════════════════════════════════════════\n"
            media_text += "🖼  МЕДИА (изображения, видео, аудио)\n"
            media_text += "═══════════════════════════════════════════════════════════════\n\n"

            for idx, media_item in enumerate(media, 1):
                media_text += f"🔹 Медиа #{idx}\n"
                media_text += f"   Тип: {media_item.get('type', '?')}\n"
                media_text += f"   Src: {media_item.get('src', '—')[:80]}...\n"
                media_text += f"   Alt: {media_item.get('alt', '—')}\n\n"

            self.media_text.insert("1.0", media_text)

        # NETWORK
        net_text = "═══════════════════════════════════════════════════════════════\n"
        net_text += "🌐 NETWORK ЗАПРОСЫ (XHR/fetch/axios)\n"
        net_text += "═══════════════════════════════════════════════════════════════\n\n"

        for idx, entry in enumerate(self.network_log, 1):
            net_text += f"🔹 Запрос #{idx}\n"
            net_text += f"   Метод: {entry.get('method', '?')}\n"
            net_text += f"   URL: {entry.get('url', '—')}\n"
            net_text += f"   Тип ресурса: {entry.get('resource_type', '—')}\n"
            net_text += f"   Статус: {entry.get('status', '—')}\n"
            post_data = entry.get("post_data")
            if post_data:
                net_text += f"   Body: {str(post_data)[:160]}...\n"
            net_text += "\n"

        self.network_text.insert("1.0", net_text)

        # JS ENDPOINTS
        js_text = "═══════════════════════════════════════════════════════════════\n"
        js_text += "🛰 JS ENDPOINTS (fetch/XHR/axios)\n"
        js_text += "═══════════════════════════════════════════════════════════════\n\n"

        for idx, ep in enumerate(self.js_endpoints, 1):
            js_text += f"🔹 Endpoint #{idx}\n"
            js_text += f"   URL: {ep}\n\n"

        self.js_endpoints_text.insert("1.0", js_text)

        # API ENDPOINTS
        api_text = (
            "═══════════════════════════════════════════════════════════════\n"
            "🔗 API ENDPOINTS\n"
            "═══════════════════════════════════════════════════════════════\n\n"
        )

        if self.api_endpoints:

            for idx, endpoint in enumerate(
                    self.api_endpoints,
                    1,
            ):
                api_text += (
                    f"🔹 API #{idx}\n"
                    f"   URL: {endpoint}\n\n"
                )

        else:

            api_text += (
                "API endpoints not detected.\n"
            )

        self.api_endpoints_text.insert(
            "1.0",
            api_text,
        )

        # WEBSOCKETS

        ws_text = (
            "═══════════════════════════════════════════════════════════════\n"
            "📡 WEBSOCKETS\n"
            "═══════════════════════════════════════════════════════════════\n\n"
        )

        if self.websockets:

            for idx, ws in enumerate(
                    self.websockets,
                    1,
            ):
                ws_text += (
                    f"🔹 WebSocket #{idx}\n"
                    f"   URL: {ws}\n\n"
                )

        else:

            ws_text += (
                "No WebSockets detected.\n"
            )

        self.websockets_text.insert(
            "1.0",
            ws_text,
        )

        # COMMENTS

        comments_text = (
            "═══════════════════════════════════════════════════════════════\n"
            "💬 HTML COMMENTS\n"
            "═══════════════════════════════════════════════════════════════\n\n"
        )

        if self.comments:

            for idx, comment in enumerate(
                    self.comments,
                    1,
            ):
                comments_text += (
                    f"🔹 Comment #{idx}\n"
                    f"{comment}\n\n"
                )

        else:

            comments_text += (
                "No comments found.\n"
            )

        self.comments_text.insert(
            "1.0",
            comments_text,
        )

        # INFRASTRUCTURE

        infra_text = (
            "═══════════════════════════════════════════════════════════════\n"
            "📡 INFRASTRUCTURE\n"
            "═══════════════════════════════════════════════════════════════\n\n"
        )

        infra_text += (
            f"Hostnames: {len(self.hostnames)}\n"
            f"IPv4: {len(self.ips)}\n"
            f"IPv6: {len(self.ipv6)}\n"
            f"CIDR: {len(self.cidr)}\n\n"
        )

        infra_text += (
            "══════════ HOSTNAMES ══════════\n"
        )

        for item in self.hostnames:
            infra_text += f"{item}\n"

        infra_text += (
            "\n══════════ IPv4 ══════════\n"
        )

        for item in self.ips:
            infra_text += f"{item}\n"

        infra_text += (
            "\n══════════ IPv6 ══════════\n"
        )

        for item in self.ipv6:
            infra_text += f"{item}\n"

        infra_text += (
            "\n══════════ CIDR ══════════\n"
        )

        for item in self.cidr:
            infra_text += f"{item}\n"

        self.infrastructure_text.insert(
            "1.0",
            infra_text,
        )

        # SERVERS

        servers_text = (
            "═══════════════════════════════════════════════\n"
            "🛰 INFRASTRUCTURE INTELLIGENCE\n"
            "═══════════════════════════════════════════════\n\n"
        )

        # =====================================================
        # Technology Detection
        # =====================================================

        servers_text += (
            "════════ TECHNOLOGY DETECTION ════════\n"
        )

        if self.detected_frameworks:
            servers_text += (
                f"Frameworks: "
                f"{', '.join(self.detected_frameworks)}\n"
            )

        if self.detected_frontend:
            servers_text += (
                f"Frontend: "
                f"{', '.join(self.detected_frontend)}\n"
            )

        if self.detected_analytics:
            servers_text += (
                f"Analytics: "
                f"{', '.join(self.detected_analytics)}\n"
            )

        if self.detected_services:
            servers_text += (
                f"Services: "
                f"{', '.join(self.detected_services)}\n"
            )

        if self.detected_servers:
            servers_text += (
                f"Servers: "
                f"{', '.join(self.detected_servers)}\n"
            )

        if self.detected_waf:
            servers_text += (
                f"WAF/CDN: "
                f"{', '.join(self.detected_waf)}\n"
            )

        servers_text += "\n"

        # =====================================================
        # Infrastructure Hosts
        # =====================================================

        if self.servers:

            for server in self.servers:

                host = server["host"].lower()

                role = "Unknown"

                if "auth." in host:

                    role = "Authentication"

                elif "api." in host:

                    role = "API"

                elif "cdn" in host:

                    role = "CDN"

                elif "yandex" in host:

                    role = "Analytics"

                elif "mail.ru" in host:

                    role = "Analytics"

                elif (
                        "targetads" in host
                        or
                        "adriver" in host
                ):

                    role = "Advertising"

                risk = "LOW"

                if role in (
                        "Authentication",
                        "API",
                ):
                    risk = "HIGH"

                elif role in (
                        "Analytics",
                        "Advertising",
                ):
                    risk = "MEDIUM"

                statuses = server.get(
                    "statuses",
                    []
                )

                resource_types = server.get(
                    "resource_types",
                    []
                )

                content_types = server.get(
                    "content_types",
                    []
                )

                server_headers = server.get(
                    "server_headers",
                    []
                )

                powered_by = server.get(
                    "powered_by",
                    []
                )

                servers_text += (
                    "══════════════════════════════════════\n"
                    f"HOST: {server['host']}\n"
                    "══════════════════════════════════════\n"

                    f"Role: {role}\n"
                    f"Risk Level: {risk}\n\n"

                    f"Requests: {server['requests']}\n"

                    f"Statuses: "
                    f"{', '.join(map(str, statuses))}\n"

                    f"Resource Types: "
                    f"{', '.join(resource_types)}\n"

                    f"Content Types: "
                    f"{', '.join(content_types)}\n"

                    f"Server Headers: "
                    f"{', '.join(server_headers)}\n"

                    f"Powered By: "
                    f"{', '.join(powered_by)}\n\n"

                    f"Unique Status Count: "
                    f"{len(statuses)}\n"

                    f"Resource Categories: "
                    f"{len(resource_types)}\n"

                    f"Content Categories: "
                    f"{len(content_types)}\n"
                )

                #
                # Sample URLs
                #

                samples = server.get(
                    "samples",
                    []
                )

                if samples:

                    servers_text += (
                        "\nSample URLs:\n"
                    )

                    for sample in samples[:5]:
                        servers_text += (
                            f"  • {sample}\n"
                        )

                #
                # Response Samples
                #

                responses = server.get(
                    "response_samples",
                    []
                )

                if responses:

                    servers_text += (
                        "\nResponse Samples:\n"
                    )

                    for response in responses[:3]:
                        snippet = (
                            response[:200]
                            .replace("\n", " ")
                            .replace("\r", " ")
                        )

                        servers_text += (
                            f"  • {snippet}\n"
                        )

                #
                # Traffic Profile
                #

                if "xhr" in resource_types:
                    servers_text += (
                        "\nIndicators:\n"
                        "  • API / AJAX Traffic\n"
                    )

                if "fetch" in resource_types:
                    servers_text += (
                        "  • Fetch Requests\n"
                    )

                if "script" in resource_types:
                    servers_text += (
                        "  • JavaScript Delivery\n"
                    )

                if "stylesheet" in resource_types:
                    servers_text += (
                        "  • Static Assets\n"
                    )

                if "image" in resource_types:
                    servers_text += (
                        "  • Media Delivery\n"
                    )

                servers_text += (
                    "\n"
                    "──────────────────────────────────────\n\n"
                )

        self.servers_text.insert(
            "1.0",
            servers_text,
        )


        # SENSITIVE DATA

        sensitive_text = (
            "═══════════════════════════════════════════════════════════════\n"
            "📦 SENSITIVE DATA\n"
            "═══════════════════════════════════════════════════════════════\n\n"
        )

        sections = {
            "Emails": self.emails,
            "Phones": self.phones,
            "API Keys": self.api_keys,
            "JWT Tokens": self.jwt_tokens,
            "Secrets": self.secrets,
            "Parameters": self.parameters,
            "Hashes": self.hashes,
            "Base64 Strings": self.base64_strings,
            "UUIDs": self.uuids,
        }

        for section, values in sections.items():

            sensitive_text += (
                f"\n══════════ {section} ══════════\n"
            )

            if values:

                for value in values:
                    sensitive_text += (
                        f"{value}\n"
                    )

            else:

                sensitive_text += (
                    "[none]\n"
                )

        self.sensitive_text.insert(
            "1.0",
            sensitive_text,
        )

        # CONSOLE LOGS
        console_text = "═══════════════════════════════════════════════════════════════\n"
        console_text += "🧩 CONSOLE LOGS\n"
        console_text += "═══════════════════════════════════════════════════════════════\n\n"

        for idx, msg in enumerate(self.console_log, 1):
            console_text += f"🔹 Сообщение #{idx}\n"
            console_text += f"   Тип: {msg.get('type', 'log')}\n"
            console_text += f"   Текст: {msg.get('text', '')}\n\n"

        self.console_text.insert("1.0", console_text)

        # DYNAMIC DOM
        dyn_text = "═══════════════════════════════════════════════════════════════\n"
        dyn_text += "🧬 DYNAMIC DOM SNAPSHOT\n"
        dyn_text += "═══════════════════════════════════════════════════════════════\n\n"

        if self.dynamic_dom:
            self.dynamic_dom_text.insert("1.0", dyn_text + self.dynamic_dom[:50000])
        else:
            self.dynamic_dom_text.insert("1.0", dyn_text + "DOM snapshot недоступен.\n")

    # ============================================================
    # CLEAR / EXPORT / STATUS / DESTROY
    # ============================================================
    def clear_results(self):
        """Очистить все результаты."""
        self.summary_text.delete("1.0", "end")
        self.forms_text.delete("1.0", "end")
        self.scripts_text.delete("1.0", "end")
        self.events_text.delete("1.0", "end")
        self.media_text.delete("1.0", "end")
        self.network_text.delete("1.0", "end")
        self.js_endpoints_text.delete("1.0", "end")
        self.console_text.delete("1.0", "end")
        self.dynamic_dom_text.delete("1.0", "end")
        self.servers_text.delete("1.0", "end")
        self.dom_results = {}
        self.current_html = None
        self.network_log = []
        self.console_log = []
        self.js_endpoints = []
        self.dynamic_dom = None
        self.metadata = {}
        self.blocked = False
        self.http_status = None

        self.status_label.config(text="Готов к анализу")

    def export_results(self):
        """Экспортировать результаты в JSON."""
        if not self.dom_results and not self.network_log and not self.js_endpoints:
            messagebox.showwarning("⚠️ Нет данных", "Сначала проведите анализ")
            return

        path = filedialog.asksaveasfilename(
            title="Сохранить результаты DOM анализа (ULTRA)",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if not path:
            return

        try:
            export_data = {
                "exported_at": datetime.now().isoformat(),
                "module": "dom_parser_tab_ultra",
                "analysis": self.dom_results,
                "network": self.network_log,
                "console": self.console_log,
                "js_endpoints": self.js_endpoints,
                "dynamic_dom": (self.dynamic_dom[:50000] if self.dynamic_dom else None),
            }

            save_json(path, export_data)
            messagebox.showinfo("✅ Экспорт", f"Результаты сохранены:\n{path}")
            self._update_status(f"✅ Экспортировано в {path}", False)

            if self.threat_tab:
                self.send_to_threat_intel("dom_parser_ultra_export", [export_data])

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при экспорте: {e}")

    def _update_status(self, text: str, is_loading: bool = False):
        """Обновить статус (потокобезопасно, без мерцаний, с throttle)."""
        now = datetime.now().timestamp()
        if hasattr(self, "_last_status_update") and now - self._last_status_update < 0.05:
            return
        self._last_status_update = now

        def update():
            if self.status_label.cget("text") != text:
                self.status_label.config(text=text)

            if is_loading:
                if not getattr(self, "_progress_running", False):
                    self.progress.start(10)
                    self._progress_running = True
            else:
                if getattr(self, "_progress_running", False):
                    self.progress.stop()
                    self._progress_running = False

        self._bridge.call_ui(update)

    def destroy(self):
        try:
            self._bridge.stop()
        except Exception:
            pass
        super().destroy()

