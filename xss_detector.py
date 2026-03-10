# xss_security_gui/xss_detector.py

from typing import Any, Union, Optional, List, Dict, Tuple
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

# Попередньо скомпільовані патерни для швидкості
_ATTR_ON_EVENT_RE = re.compile(r'\son\w+\s*=')
_ATTR_GENERIC_RE = re.compile(r'\s[\w:-]+\s*=\s*["\'].*?["\']')


# ===========================================
# Класс XSSDetector с Threat Intel интеграцией
# ===========================================

class XSSDetector:
    def __init__(self, threat_tab: Any = None) -> None:
        """
        Конструктор: принимает threat_tab для интеграции в Threat Intel.
        threat_tab ожидается с методом add_threat(dict).
        """
        self.threat_tab = threat_tab

    # -------------------------------------------
    # Контекстная эвристика и анализ HTML/JS
    # -------------------------------------------
    def detect_xss_context(self, response_text: str, payload: str, window: int = 160) -> Optional[str]:
        """
        Возвращает тип контекста для отражённого payload.
        """
        if not payload:
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
            # 2) Явные JS-контексты рядом
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
                # 3) Атрибутный контекст
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

        if self.threat_tab and context:
            try:
                self.threat_tab.add_threat(
                    {
                        "type": "XSS",
                        "payload": payload,
                        "context": context,
                        "snippet": snippet,
                        "source": "XSSDetector",
                    }
                )
            except Exception:
                # Threat Intel не должен ломать детектор
                pass

        return context

    # -------------------------------------------
    # Inline JS анализ
    # -------------------------------------------
    def extract_inline_js_blocks(self, html: str) -> List[str]:
        """Извлекает все inline <script> без src."""
        soup = BeautifulSoup(html, "html.parser")
        return [s.get_text(strip=True) for s in soup.find_all("script") if not s.get("src")]

    def scan_inline_js_for_payload(self, html: str, payload: str, window: int = 60) -> List[Tuple[str, str]]:
        """
        Проверяет inline JS-блоки на наличие payload'а и классифицирует.
        """
        if not payload:
            return []

        scripts = self.extract_inline_js_blocks(html)
        hits: List[Tuple[str, str]] = []

        for code in scripts:
            if payload in code:
                vuln_type = self.classify_js_payload(code)
                snippet = self.get_code_snippet(code, payload, window=window)
                hits.append((vuln_type, snippet))

                if self.threat_tab:
                    try:
                        self.threat_tab.add_threat(
                            {
                                "type": "XSS_INLINE",
                                "payload": payload,
                                "context": vuln_type,
                                "snippet": snippet,
                                "source": "XSSDetector",
                            }
                        )
                    except Exception:
                        pass

        return hits

    def classify_js_payload(self, code: str) -> str:
        """Грубая классификация JS-контекста для payload внутри inline-скрипта."""
        code_lower = code.lower()
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
        """Возвращает сниппет текста вокруг payload без переводов строк."""
        if not payload:
            return ""
        index = text.find(payload)
        if index == -1:
            return ""
        start = max(0, index - window)
        end = index + len(payload) + window
        return text[start:end].replace("\n", " ").strip()

    # -------------------------------------------
    # Утилита сборки GET‑URL с учётом query
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
    # Генератор XSS‑фуззинга для GET и POST
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
        seen: set = set()

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

                    if self.threat_tab:
                        try:
                            self.threat_tab.add_threat(
                                {
                                    "type": "XSS_FUZZ",
                                    "method": "GET",
                                    "url": fuzzed_url,
                                    "param": key,
                                    "payload": vector,
                                    "source": "XSSDetector",
                                }
                            )
                        except Exception:
                            pass

        # -----------------------
        # POST fuzzing
        # -----------------------
        elif m == "POST":
            for vector in vectors:
                for key in base_params:
                    mutated = mutate_params(base_params, key, vector)
                    entry = {"url": base_url, "json": mutated}

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

                    if self.threat_tab:
                        try:
                            self.threat_tab.add_threat(
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
                        except Exception:
                            pass

        return results