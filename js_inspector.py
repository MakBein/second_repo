# xss_security_gui/js_inspector.py
"""
JavaScript Inspector — ULTRA 5.0 FINAL
======================================

Промышленный анализатор JavaScript-кода:
- функции, стрелочные функции, классы, методы
- fetch / ajax / XHR / WebSocket / EventSource
- DOM sinks (innerHTML, insertAdjacentHTML, srcdoc, outerHTML, etc.)
- dangerous sinks (eval, Function, setTimeout, setInterval)
- API endpoints (REST, GraphQL, RPC, WebSocket endpoints)
- framework detection (React, Vue, Angular, jQuery, Svelte, Next.js, Nuxt, Ember)
- CSP bypass indicators
- inline script analysis
- fingerprinting JS-фреймворков и библиотек
- detection of dynamic code execution
- detection of prototype pollution patterns
"""

import re
from typing import Dict, List, Any


# ============================================================
# 🔍 Основной интерфейс
# ============================================================

def extract_js_insights(js_code: str) -> Dict[str, Any]:
    """Анализирует JS-код и возвращает расширенный отчёт ULTRA 5.0."""
    return {
        "functions": _extract_functions(js_code),
        "classes": _extract_classes(js_code),
        "methods": _extract_methods(js_code),

        "fetch_calls": _extract_fetch(js_code),
        "ajax_calls": _extract_ajax(js_code),
        "xhr_calls": _extract_xhr(js_code),
        "websocket_calls": _extract_websocket(js_code),
        "eventsource_calls": _extract_eventsource(js_code),

        "event_listeners": _extract_event_listeners(js_code),
        "timers": _extract_timers(js_code),

        "dom_sinks": _extract_dom_sinks(js_code),
        "dangerous_calls": _extract_dangerous(js_code),

        "api_endpoints": _extract_api_endpoints(js_code),
        "graphql_queries": _extract_graphql(js_code),

        "frameworks": _detect_frameworks(js_code),
        "libraries": _detect_libraries(js_code),

        "prototype_pollution": _detect_prototype_pollution(js_code),
        "dynamic_execution": _detect_dynamic_execution(js_code),

        "csp_bypass_indicators": _detect_csp_bypass(js_code),
    }


# ============================================================
# 🧩 Функции, классы, методы
# ============================================================

def _extract_functions(js: str) -> List[str]:
    patterns = [
        r"function\s+([a-zA-Z0-9_]+)\s*\(",
        r"([a-zA-Z0-9_]+)\s*=\s*\([^)]*\)\s*=>",
        r"(?:var|let|const)\s+([a-zA-Z0-9_]+)\s*=\s*function\s*\(",
    ]
    out = []
    for p in patterns:
        out.extend(re.findall(p, js))
    return sorted(set(out))


def _extract_classes(js: str) -> List[str]:
    return sorted(set(re.findall(r"class\s+([A-Za-z0-9_]+)", js)))


def _extract_methods(js: str) -> List[str]:
    return sorted(set(re.findall(r"([A-Za-z0-9_]+)\s*\([^)]*\)\s*\{", js)))


# ============================================================
# 🌐 HTTP / AJAX / XHR / WebSocket / EventSource
# ============================================================

def _extract_fetch(js: str) -> List[str]:
    return [m[1] for m in re.findall(r"fetch\((['\"])(.+?)\1", js)]


def _extract_ajax(js: str) -> List[str]:
    return re.findall(r"\.ajax\(\s*\{\s*url\s*:\s*['\"](.+?)['\"]", js)


def _extract_xhr(js: str) -> List[str]:
    return ["XMLHttpRequest"] if "new XMLHttpRequest" in js else []


def _extract_websocket(js: str) -> List[str]:
    return re.findall(r"new\s+WebSocket\(['\"](.+?)['\"]", js)


def _extract_eventsource(js: str) -> List[str]:
    return re.findall(r"new\s+EventSource\(['\"](.+?)['\"]", js)


# ============================================================
# 🎧 Event listeners
# ============================================================

def _extract_event_listeners(js: str) -> List[str]:
    return re.findall(r"\.addEventListener\(\s*['\"](.+?)['\"]", js)


# ============================================================
# ⏱ Таймеры
# ============================================================

def _extract_timers(js: str) -> List[str]:
    timers = []
    if "setTimeout(" in js:
        timers.append("setTimeout")
    if "setInterval(" in js:
        timers.append("setInterval")
    return timers


# ============================================================
# 🧨 DOM sinks (XSS точки)
# ============================================================

DOM_SINK_PATTERNS = {
    "innerHTML": r"\binnerHTML\s*=",
    "outerHTML": r"\bouterHTML\s*=",
    "insertAdjacentHTML": r"insertAdjacentHTML\s*\(",
    "document.write": r"document\.write",
    "eval": r"\beval\s*\(",
    "Function": r"\bFunction\s*\(",
    "location.href": r"location\.href\s*=",
    "src_assignment": r"\.src\s*=",
    "iframe_srcdoc": r"srcdoc\s*=",
    "setAttribute_html": r"setAttribute\(['\"](?:innerHTML|src|href)['\"]",
    "template_inner": r"<template>.*?</template>",
}


def _extract_dom_sinks(js: str) -> List[str]:
    return [name for name, pat in DOM_SINK_PATTERNS.items() if re.search(pat, js)]


# ============================================================
# ⚠️ Dangerous calls
# ============================================================

DANGEROUS_PATTERNS = {
    "eval": r"\beval\s*\(",
    "Function": r"\bFunction\s*\(",
    "setTimeout": r"setTimeout\s*\(",
    "setInterval": r"setInterval\s*\(",
    "document.write": r"document\.write",
    "execScript": r"execScript\s*\(",
    "import_dynamic": r"import\(['\"]",
}


def _extract_dangerous(js: str) -> List[str]:
    return [name for name, pat in DANGEROUS_PATTERNS.items() if re.search(pat, js)]


# ============================================================
# 🔐 API endpoints (REST, RPC, GraphQL)
# ============================================================

API_PATTERNS = [
    r"https?://[^\s'\"<>]+",
    r"/api/[a-zA-Z0-9_\-/]+",
    r"/v[0-9]+/[a-zA-Z0-9_\-/]+",
    r"/graphql",
    r"/rpc/[a-zA-Z0-9_\-/]+",
]


def _extract_api_endpoints(js: str) -> List[str]:
    out = []
    for p in API_PATTERNS:
        out.extend(re.findall(p, js))
    return sorted(set(out))


def _extract_graphql(js: str) -> List[str]:
    return re.findall(r"graphql.*?\{(.+?)\}", js, flags=re.S)


# ============================================================
# 🧠 Framework detection
# ============================================================

FRAMEWORK_PATTERNS = {
    "React": r"React\.|useState\(|useEffect\(",
    "Vue": r"Vue\.|new Vue\(",
    "Angular": r"angular\.module|ng-controller",
    "jQuery": r"\$\(|jQuery\(",
    "Svelte": r"import\s+{\s*onMount",
    "Next.js": r"getServerSideProps|getStaticProps",
    "Nuxt.js": r"nuxt\.config|defineNuxtConfig",
    "Ember": r"Ember\.|ember\.component",
}


def _detect_frameworks(js: str) -> List[str]:
    return [fw for fw, pat in FRAMEWORK_PATTERNS.items() if re.search(pat, js)]


# ============================================================
# 📚 Library detection (fingerprinting)
# ============================================================

LIBRARY_PATTERNS = {
    "Lodash": r"_\.",
    "Moment.js": r"moment\(",
    "Axios": r"axios\.",
    "RxJS": r"rxjs",
    "Three.js": r"THREE\.",
    "D3.js": r"d3\.",
    "Leaflet": r"L\.map",
    "Chart.js": r"new Chart\(",
}


def _detect_libraries(js: str) -> List[str]:
    return [lib for lib, pat in LIBRARY_PATTERNS.items() if re.search(pat, js)]


# ============================================================
# 🧬 Prototype pollution detection
# ============================================================

PROTOTYPE_PATTERNS = [
    r"__proto__",
    r"prototype\s*=",
    r"Object\.assign\(\s*.*?prototype",
]


def _detect_prototype_pollution(js: str) -> List[str]:
    return [p for p in PROTOTYPE_PATTERNS if re.search(p, js)]


# ============================================================
# 🔥 Dynamic execution detection
# ============================================================

DYNAMIC_EXEC_PATTERNS = [
    r"eval\s*\(",
    r"new Function",
    r"setTimeout\s*\([^,]+?,\s*0\)",
    r"import\(",
]


def _detect_dynamic_execution(js: str) -> List[str]:
    return [p for p in DYNAMIC_EXEC_PATTERNS if re.search(p, js)]


# ============================================================
# 🛡 CSP bypass indicators
# ============================================================

CSP_BYPASS_PATTERNS = [
    r"nonce=",
    r"integrity=",
    r"crossorigin=",
    r"unsafe-inline",
    r"unsafe-eval",
]


def _detect_csp_bypass(js: str) -> List[str]:
    return [p for p in CSP_BYPASS_PATTERNS if re.search(p, js)]