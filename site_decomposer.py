# xss_security_gui/site_decomposer.py
"""
SiteDecomposerEngine ULTRA 5.0

- Гибридный анализ сайта:
  • Статический HTML + заголовки + cookies
  • JS-рендер DOM через Playwright (опционально)
  • Извлечение форм, инпутов, событий, слушателей
  • Корреляция DOM-событий с полями ввода
  • Оценка риска по JS-паттернам

- Инженерные фичи:
  • Асинхронный запуск в отдельном потоке (run_async)
  • Таймауты и устойчивость к ошибкам сети/рендера
  • Расширяемая модель риска
  • Чистый JSON-отчёт для Threat Intel / OverviewTab
"""

import json
import threading
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError


# ==========================
#  Модели данных
# ==========================

@dataclass
class InputField:
    id: Optional[str]
    name: Optional[str]
    type: Optional[str]
    placeholder: Optional[str]


@dataclass
class EventListener:
    type: str
    handler_code: str
    risk_level: str


@dataclass
class CorrelatedEvent:
    input: InputField
    event: str
    handler: str
    risk_level: str


@dataclass
class SecurityMeta:
    csp: str
    cors: Dict[str, str]
    cookie_flags: List[str]


@dataclass
class DecompositionReport:
    title: str
    url: str
    security: SecurityMeta
    inputs: List[InputField]
    events: List[EventListener]
    correlations: List[CorrelatedEvent]
    structure: Dict[str, Any]


class SiteDecomposerEngine:
    def __init__(self, url: str, timeout: int = 15, enable_js_render: bool = True):
        self.url = url
        self.timeout = timeout
        self.enable_js_render = enable_js_render
        self.report: Optional[DecompositionReport] = None

        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "XSS-Security-Suite-Decomposer/5.0"
        })

    # ==========================
    #  Публичные методы
    # ==========================

    def run(self) -> DecompositionReport:
        """Синхронный запуск анализа (блокирующий)."""
        static = self.fetch_static_data()

        js_dom = static["html"]
        title = static.get("title", "")

        if self.enable_js_render:
            dom_result = self.render_js_dom_safe()
            if dom_result:
                js_dom, title = dom_result

        security_meta = self.extract_security_meta(static["headers"])
        inputs = self.extract_inputs(static["soup"])
        listeners = self.extract_event_listeners(js_dom)
        correlations = self.correlate_dom_events(inputs, listeners)
        structure = self.build_decomposition_tree(inputs, correlations)

        self.report = DecompositionReport(
            title=title or "(no title)",
            url=self.url,
            security=security_meta,
            inputs=inputs,
            events=listeners,
            correlations=correlations,
            structure=structure,
        )
        return self.report

    def run_async(self, callback=None):
        """
        Асинхронный запуск анализа в отдельном потоке.
        callback(report: DecompositionReport | None, error: Exception | None)
        """

        def worker():
            try:
                report = self.run()
                if callback:
                    callback(report, None)
            except Exception as e:
                if callback:
                    callback(None, e)

        threading.Thread(target=worker, daemon=True).start()

    def export_json(self, path: str = "decomposition_logs/report.json"):
        if not self.report:
            raise RuntimeError("Отчёт ещё не сформирован. Сначала вызовите run() или run_async().")

        data = asdict(self.report)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    # ==========================
    #  Внутренние шаги анализа
    # ==========================

    def fetch_static_data(self) -> Dict[str, Any]:
        resp = self._session.get(self.url, timeout=self.timeout)
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")
        title_tag = soup.find("title")
        title = title_tag.text.strip() if title_tag else ""

        return {
            "html": resp.text,
            "headers": dict(resp.headers),
            "cookies": resp.cookies.get_dict(),
            "soup": soup,
            "title": title,
        }

    def render_js_dom_safe(self) -> Optional[tuple[str, str]]:
        """JS-рендер DOM через Playwright с защитой от ошибок."""
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(self.url, wait_until="networkidle", timeout=self.timeout * 1000)
                content = page.content()
                title = page.evaluate("() => document.title") or ""
                browser.close()
            return content, title
        except PlaywrightTimeoutError:
            return None
        except Exception:
            return None

    def extract_security_meta(self, headers: Dict[str, str]) -> SecurityMeta:
        csp = headers.get("Content-Security-Policy", "")
        cors = {k: v for k, v in headers.items() if "Access-Control" in k}
        cookie_raw = headers.get("Set-Cookie", "")
        cookie_flags = [flag.strip() for flag in cookie_raw.split(";") if flag.strip()]
        return SecurityMeta(csp=csp, cors=cors, cookie_flags=cookie_flags)

    def extract_inputs(self, soup: BeautifulSoup) -> List[InputField]:
        inputs: List[InputField] = []
        for tag in soup.find_all(["input", "textarea", "select"]):
            inputs.append(
                InputField(
                    id=tag.get("id"),
                    name=tag.get("name"),
                    type=tag.get("type"),
                    placeholder=tag.get("placeholder"),
                )
            )
        return inputs

    def extract_event_listeners(self, html: str) -> List[EventListener]:
        listeners: List[EventListener] = []
        soup = BeautifulSoup(html, "html.parser")
        scripts = soup.find_all("script")

        for script in scripts:
            js = script.string or ""
            if not js:
                continue

            for event_type in ["click", "input", "change", "focus", "submit", "keydown", "keyup"]:
                if event_type in js:
                    risk = self.assess_risk(js)
                    listeners.append(
                        EventListener(
                            type=event_type,
                            handler_code=js,
                            risk_level=risk,
                        )
                    )
        return listeners

    def assess_risk(self, js_code: str) -> str:
        js_lower = js_code.lower()

        high_markers = ["eval(", "new Function", "document.write", "innerHTML", "setTimeout(", "setInterval("]
        medium_markers = ["innerhtml", "outerhtml", "insertadjacenthtml"]

        if any(m.lower() in js_lower for m in high_markers):
            return "HIGH"
        if any(m.lower() in js_lower for m in medium_markers):
            return "MEDIUM"
        return "LOW"

    def correlate_dom_events(
        self,
        inputs: List[InputField],
        listeners: List[EventListener],
    ) -> List[CorrelatedEvent]:
        correlations: List[CorrelatedEvent] = []

        for input_el in inputs:
            id_ = input_el.id or ""
            name_ = input_el.name or ""
            if not id_ and not name_:
                continue

            for event in listeners:
                code = event.handler_code
                if (id_ and id_ in code) or (name_ and name_ in code):
                    correlations.append(
                        CorrelatedEvent(
                            input=input_el,
                            event=event.type,
                            handler=event.handler_code[:200],
                            risk_level=event.risk_level,
                        )
                    )
        return correlations

    def build_decomposition_tree(
        self,
        inputs: List[InputField],
        events: List[CorrelatedEvent],
    ) -> Dict[str, Any]:
        tree: Dict[str, Any] = {"forms": [], "events": []}

        for ev in events:
            tree["events"].append(
                {
                    "input": asdict(ev.input),
                    "event": ev.event,
                    "risk_level": ev.risk_level,
                    "handler_preview": ev.handler,
                }
            )

        for input_el in inputs:
            linked = [e for e in events if e.input == input_el]
            tree["forms"].append(
                {
                    "input": asdict(input_el),
                    "linked_events": [
                        {
                            "event": e.event,
                            "risk_level": e.risk_level,
                            "handler_preview": e.handler,
                        }
                        for e in linked
                    ],
                }
            )

        return tree