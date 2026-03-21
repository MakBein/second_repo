# xss_security_gui/xss_detector.py
"""
XSSDetector ULTRA 7.1
---------------------
• Контекстний аналіз відображеного payload (HTML / JS / DOM)
• Inline JS аналіз + класифікація DOM-based / Reflected
• Генератор XSS‑фуззингу для GET/POST з унікальною дедуплікацією
• Threat Intel‑friendly події (add_threat), але ніколи не ламає GUI
"""

from __future__ import annotations

from typing import Any, Union, Optional, List, Dict, Tuple, Set
from bs4 import BeautifulSoup
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


# ======================
# Константы и настройки
# ======================

DEFAULT_XSS_VECTORS: List[str] = [
    '<script>alert("XSS")</script>',
    '"><b>XSS</b>',
    '" onerror="alert(\'XSS\')"',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<div onclick="alert(\'XSS\')">Click</div>',
    '<scr<script>ipt>alert(1)</scr<script>ipt>',
    "'\"><svg/onload=alert(1)>",
    "';alert(1);//",
    "\"><script>confirm(1)</script>",
]

# Попередньо скомпільовані патерни
_ATTR_ON_EVENT_RE = re.compile(r"\son\w+\s*=")
_ATTR_GENERIC_RE = re.compile(r"\s[\w:-]+\s*=\s*['\"].*?['\"]", re.DOTALL)


# ===========================================
# Класс XSSDetector с Threat Intel интеграцией
# ===========================================

class XSSDetector:
    def __init__(self, threat_tab: Any = None) -> None:
        self.threat_tab = threat_tab

    # -------------------------------------------
    # Контекстная эвристика
    # -------------------------------------------
    def detect_xss_context(
        self,
        response_text: str,
        payload: str,
        window: int = 160,
    ) -> Optional[str]:

        if not payload or not response_text:
            return None

        index = response_text.find(payload)
        if index == -1:
            return None

        start = max(0, index - window // 2)
        end = index + len(payload) + window // 2
        snippet = response_text[start:end]
        snippet_lower = snippet.lower()

        # 1) Внутри <script>...</script>?
        rel_index = index - start
        left_tag_open = snippet_lower.rfind("<script", 0, rel_index)
        right_tag_close = snippet_lower.find("</script>", rel_index)
        in_script = (
            left_tag_open != -1
            and right_tag_close != -1
            and left_tag_open < rel_index < right_tag_close
        )

        if in_script:
            context = "📜 Reflected JS"
        else:
            js_indicators = (
                "eval(",
                "new function",
                "settimeout(",
                "setinterval(",
                "function(",
                "=>",
                "console.",
                "var ",
                "let ",
                "const ",
            )
            if any(i in snippet_lower for i in js_indicators):
                context = "📜 Reflected JS"
            else:
                # Атрибутный контекст
                lt = snippet_lower.rfind("<", 0, rel_index)
                gt = snippet_lower.find(">", rel_index)

                if lt != -1 and gt != -1 and lt < rel_index < gt:
                    tag_segment = snippet_lower[lt:gt]
                    if _ATTR_ON_EVENT_RE.search(tag_segment):
                        context = "🧬 Attribute Injection"
                    elif _ATTR_GENERIC_RE.search(tag_segment):
                        context = "🧬 Attribute Injection"
                    else:
                        context = "🔤 Reflected HTML"

                elif any(
                    s in snippet_lower
                    for s in (
                        "innerhtml",
                        "outerhtml",
                        "insertadjacenthtml",
                        "document.write",
                        "document.writeln",
                    )
                ):
                    context = "🧠 DOM-based"

                elif "<" in snippet_lower and ">" in snippet_lower:
                    context = "🔤 Reflected HTML"
                else:
                    context = "❓ Unknown"

        self._safe_threat_add(
            {
                "type": "XSS",
                "payload": payload,
                "context": context,
                "snippet": snippet,
                "source": "XSSDetector",
            }
        )

        return context

    # -------------------------------------------
    # Inline JS анализ
    # -------------------------------------------
    def extract_inline_js_blocks(self, html: str) -> List[str]:
        if not html:
            return []
        soup = BeautifulSoup(html, "html.parser")
        return [s.get_text(strip=True) for s in soup.find_all("script") if not s.get("src")]

    def scan_inline_js_for_payload(
        self,
        html: str,
        payload: str,
        window: int = 60,
    ) -> List[Tuple[str, str]]:

        if not payload or not html:
            return []

        scripts = self.extract_inline_js_blocks(html)
        hits: List[Tuple[str, str]] = []

        for code in scripts:
            if payload in code:
                vuln_type = self.classify_js_payload(code)
                snippet = self.get_code_snippet(code, payload, window=window)
                hits.append((vuln_type, snippet))

                self._safe_threat_add(
                    {
                        "type": "XSS_INLINE",
                        "payload": payload,
                        "context": vuln_type,
                        "snippet": snippet,
                        "source": "XSSDetector",
                    }
                )

        return hits

    def classify_js_payload(self, code: str) -> str:
        code_lower = (code or "").lower()
        dom_indicators = (
            "eval(",
            "new function",
            "settimeout",
            "setinterval",
            "document.write",
            "document.writeln",
            "innerhtml",
            "outerhtml",
            "insertadjacenthtml",
        )
        return "🧠 DOM-based" if any(ind in code_lower for ind in dom_indicators) else "📜 Reflected JS"

    def get_code_snippet(self, text: str, payload: str, window: int = 60) -> str:
        if not payload or not text:
            return ""
        index = text.find(payload)
        if index == -1:
            return ""
        start = max(0, index - window)
        end = index + len(payload) + window
        return text[start:end].replace("\n", " ").strip()

    # -------------------------------------------
    # GET URL builder
    # -------------------------------------------
    def _build_get_url(self, base_url: str, params_dict: Dict[str, Any]) -> str:
        split = urlsplit(base_url)
        existing = dict(parse_qsl(split.query, keep_blank_values=True))

        merged: Dict[str, Any] = existing.copy()
        for k, v in params_dict.items():
            if isinstance(v, (list, tuple)):
                merged[k] = [str(x) for x in v]
            else:
                merged[k] = "" if v is None else str(v)

        query = urlencode(merged, doseq=True, safe="()[],'\"<>/\\;:")
        return urlunsplit((split.scheme, split.netloc, split.path, query, split.fragment))

    # -------------------------------------------
    # XSS Fuzzing (GET + POST)
    # -------------------------------------------
    def fuzz_xss_parameters(
        self,
        base_url: str,
        payload_data: Optional[Dict[str, Any]],
        method: str,
        xss_vectors: Optional[List[str]] = None,
    ) -> List[Union[str, Dict[str, Any]]]:

        vectors = xss_vectors or DEFAULT_XSS_VECTORS

        base_params: Dict[str, Any] = {
            k: [str(x) for x in v] if isinstance(v, (list, tuple)) else ("" if v is None else str(v))
            for k, v in (payload_data or {}).items()
        }

        def mutate_params(params: Dict[str, Any], key: str, vector: str) -> Dict[str, Any]:
            modified = dict(params)
            if isinstance(modified.get(key), list) and modified[key]:
                modified[key] = [modified[key][0] + vector] + modified[key][1:]
            else:
                current = modified.get(key, "")
                modified[key] = (current or "") + vector
            return modified

        results: List[Union[str, Dict[str, Any]]] = []
        seen: Set[Any] = set()

        m = method.upper()

        # -----------------------
        # GET fuzzing
        # -----------------------
        if m == "GET":
            for vector in vectors:
                for key in base_params:
                    mutated = mutate_params(base_params, key, vector)
                    fuzzed_url = self._build_get_url(base_url, mutated)

                    if fuzzed_url in seen:
                        continue

                    results.append(fuzzed_url)
                    seen.add(fuzzed_url)

                    self._safe_threat_add(
                        {
                            "type": "XSS_FUZZ",
                            "method": "GET",
                            "url": fuzzed_url,
                            "param": key,
                            "payload": vector,
                            "source": "XSSDetector",
                        }
                    )

        # -----------------------
        # POST fuzzing (оновлений блок)
        # -----------------------
        elif m == "POST":
            for vector in vectors:
                for key in base_params:
                    mutated = mutate_params(base_params, key, vector)

                    entry = {"url": base_url, "json": mutated}

                    # Унікальний ключ для дедуплікації
                    key_ = (
                        entry["url"],
                        tuple(
                            sorted(
                                (k, tuple(v) if isinstance(v, list) else v)
                                for k, v in entry["json"].items()
                            )
                        ),
                    )

                    if key_ in seen:
                        continue

                    results.append(entry)
                    seen.add(key_)

                    self._safe_threat_add(
                        {
                            "type": "XSS_FUZZ",
                            "method": "POST",
                            "url": base_url,
                            "param": key,
                            "payload": vector,
                            "json": mutated,
                            "source": "XSSDetector",
                        }
                    )

        return results

    # -------------------------------------------
    # Safe Threat Intel
    # -------------------------------------------
    def _safe_threat_add(self, payload: Dict[str, Any]) -> None:
        if not self.threat_tab or not payload:
            return
        try:
            self.threat_tab.add_threat(payload)
        except Exception:
            pass