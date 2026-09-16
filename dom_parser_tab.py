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

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
from datetime import datetime
from typing import Optional, Dict, Any, List
import requests

from playwright.sync_api import sync_playwright

from xss_security_gui.utils.ui_queue_bridge import UIQueueBridge
from xss_security_gui.utils.threat_sender import ThreatSenderMixin
from xss_security_gui.file_loader import save_json

try:
    from xss_security_gui.dom_parser import DOMParser, DOMParserAsync
except ImportError:
    DOMParser = None
    DOMParserAsync = None


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
        self.current_html: Optional[str] = None
        self.dom_results: Dict[str, Any] = {}
        self.network_log: List[Dict[str, Any]] = []
        self.console_log: List[Dict[str, Any]] = []
        self.js_endpoints: List[str] = []
        self.dynamic_dom: Optional[str] = None

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
            " • Файл dom_parser.py отсутствует или повреждён\n"
            " • Ошибка импорта в xss_security_gui/dom_parser/__init__.py\n"
            " • Нарушена структура пакета\n\n"
            "Рекомендации:\n"
            " • Проверьте, что каталог xss_security_gui/dom_parser существует\n"
            " • Убедитесь, что в нём есть parser.py и __init__.py\n"
            " • Перезапустите приложение после исправления\n"
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

        # NEW: Console Logs
        self.console_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.console_frame, text="🧩 Console")
        self.console_text = self._make_textbox(self.console_frame, "#ff4444")

        # NEW: Dynamic DOM
        self.dynamic_dom_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dynamic_dom_frame, text="🧬 Dynamic DOM")
        self.dynamic_dom_text = self._make_textbox(self.dynamic_dom_frame, "#66ff66")

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
        """Загрузить страницу с URL и запустить анализ."""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("⚠️ Требуется URL", "Пожалуйста, введите URL")
            return

        if not url.startswith(("http://", "https://")) and not os.path.isfile(url):
            url = "https://" + url

        self._bridge.post_bg(self._fetch_and_parse_thread, url)

    def _fetch_and_parse_thread(self, url: str):
        """Фоновый поток: загрузка страницы + запуск анализа."""
        try:
            self._update_status("⏳ Загрузка страницы...", True)

            # Файл → читаем локально
            if os.path.isfile(url):
                try:
                    with open(url, "r", encoding="utf-8") as f:
                        self.current_html = f.read()
                    self.dynamic_dom = self.current_html
                    self._update_status("🔍 Анализ DOM (локальный файл)...", True)
                    self._bridge.post_ui(self.parse_html)
                    return
                except Exception as e:
                    self._update_status(f"❌ Ошибка чтения файла: {e}", False)
                    self._bridge.post_ui(
                        messagebox.showerror,
                        "Ошибка",
                        f"Ошибка чтения файла: {e}",
                    )
                    return

            # URL → Playwright / requests
            if self.use_playwright_var.get():
                result = self._fetch_page_playwright_ultra(url)
            else:
                result = self._fetch_page_requests(url)

            if not result.get("success"):
                self._update_status(f"❌ Ошибка загрузки: {result.get('error')}", False)
                self._bridge.post_ui(
                    messagebox.showerror,
                    "Ошибка",
                    f"Ошибка загрузки: {result.get('error')}",
                )
                return

            # HTML + доп. данные
            self.current_html = result.get("html")
            self.dynamic_dom = result.get("dom") or self.current_html
            self.network_log = result.get("network", [])
            self.console_log = result.get("console", [])
            self.js_endpoints = result.get("js_endpoints", [])

            self._update_status("🔍 Анализ DOM...", True)
            self._bridge.post_ui(self.parse_html)

        except Exception as e:
            self._update_status(f"❌ Ошибка: {e}", False)
            self._bridge.post_ui(messagebox.showerror, "Ошибка", f"Ошибка загрузки: {e}")

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
        try:
            network_log: List[Dict[str, Any]] = []
            console_log: List[Dict[str, Any]] = []
            js_endpoints: List[str] = []

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()

                page = context.new_page()

                # --- Network capture ---
                def on_request(request):
                    network_log.append({
                        "method": request.method,
                        "url": request.url,
                        "headers": dict(request.headers),
                        "resource_type": request.resource_type,
                        "post_data": request.post_data,
                    })

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

                page.goto(url, timeout=20000, wait_until="networkidle")

                # DOM snapshot
                dom_html = page.content()

                # JS endpoints snapshot
                try:
                    endpoints = page.evaluate("() => window.__xssgui_js_endpoints || []")
                    js_endpoints = list(dict.fromkeys(endpoints))  # unique
                except Exception:
                    js_endpoints = []

                browser.close()

            return {
                "success": True,
                "html": dom_html,
                "dom": dom_html,
                "network": network_log,
                "console": console_log,
                "js_endpoints": js_endpoints,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _fetch_page_requests(self, url: str) -> dict:
        """Простой fallback через requests."""
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            return {
                "success": True,
                "html": resp.text,
                "dom": resp.text,
                "network": [],
                "console": [],
                "js_endpoints": [],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

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
        self.summary_text.delete("1.0", "end")
        self.forms_text.delete("1.0", "end")
        self.scripts_text.delete("1.0", "end")
        self.events_text.delete("1.0", "end")
        self.media_text.delete("1.0", "end")
        self.network_text.delete("1.0", "end")
        self.js_endpoints_text.delete("1.0", "end")
        self.console_text.delete("1.0", "end")
        self.dynamic_dom_text.delete("1.0", "end")

        elements = results.get("elements", [])
        forms = results.get("forms", [])
        scripts = results.get("scripts", [])
        events = results.get("events", [])
        media = results.get("media", [])
        links = results.get("links", [])

        inline_scripts = [s for s in scripts if s.get("content")]
        external_scripts = [s for s in scripts if s.get("src")]
        high_risk_events = [e for e in events if e.get("risk") == "high"]

        # SUMMARY
        summary = f"""
═══════════════════════════════════════════════════════════════
🔍 DOM АНАЛИЗ — СВОДКА (ULTRA)
═══════════════════════════════════════════════════════════════

📊 Статистика:
  • Всего элементов: {len(elements)}
  • Форм: {len(forms)}
  • Скриптов: {len(scripts)}
  • Событий: {len(events)}
  • Медиа: {len(media)}
  • Ссылок: {len(links)}

🧠 JS-осведомлённость:
  • Внешние скрипты: {len(external_scripts)}
  • Встроенные (inline) скрипты: {len(inline_scripts)}
  • Высокорисковые обработчики событий: {len(high_risk_events)}

🌐 Network:
  • Всего запросов: {len(self.network_log)}
  • JS endpoints: {len(self.js_endpoints)}
  • Console сообщений: {len(self.console_log)}

═══════════════════════════════════════════════════════════════
"""
        self.summary_text.insert("1.0", summary)

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

        self.dom_results = {}
        self.current_html = None
        self.network_log = []
        self.console_log = []
        self.js_endpoints = []
        self.dynamic_dom = None

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



