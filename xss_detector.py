# xss_security_gui/xss_detector.py
"""
XSSDetector ULTRA 7.1
---------------------
• Контекстний аналіз відображеного payload (HTML / JS / DOM)
• Inline JS аналіз + класифікація DOM-based / Reflected
• Генератор XSS‑фуззингу для GET/POST з унікальною дедуплікацією
• Threat Intel‑friendly події (add_threat), але ніколи не ламає GUI
• Реальний бойовий red-team probe для GET/POST target endpoints
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

try:
    from xss_security_gui.ai_core.synthetic_xss import generate_synthetic_xss
except Exception:  # pragma: no cover
    def generate_synthetic_xss(n: int = 200) -> List[str]:
        items = [
            "<svg/onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<script>alert(1)</script>",
            "\"\"><script>alert(1)</script>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
        ]
        return items[: max(1, min(n, len(items)))]


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
    '\"><script>confirm(1)</script>',
]

_ATTR_ON_EVENT_RE = re.compile(r"\son\w+\s*=")
_ATTR_GENERIC_RE = re.compile(r"\s[\w:-]+\s*=\s*['\"].*?['\"]", re.DOTALL)


class XSSDetector:
    def __init__(self, threat_tab: Any = None) -> None:
        self.threat_tab = threat_tab
        self.session = requests.Session() if requests is not None else None
        self.default_headers = {
            "User-Agent": "Mozilla/5.0 (XSS-RedTeam/7.1)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

    def build_payload_set(
        self,
        include_default: bool = True,
        limit: int = 200,
        custom_payloads: Optional[List[str]] = None,
    ) -> List[str]:
        payloads: List[str] = []
        seen: Set[str] = set()

        if include_default:
            payloads.extend(DEFAULT_XSS_VECTORS)
        if custom_payloads:
            payloads.extend(custom_payloads)
        try:
            payloads.extend(generate_synthetic_xss(max(1, limit)))
        except Exception:
            pass

        unique: List[str] = []
        for vector in payloads:
            if not vector or vector in seen:
                continue
            seen.add(vector)
            unique.append(vector)
            if len(unique) >= max(1, limit):
                break
        return unique

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

    def extract_inline_js_blocks(self, html: str) -> List[str]:
        if not html or BeautifulSoup is None:
            return []

        try:
            soup = BeautifulSoup(html, "html.parser")
            scripts = soup.find_all("script")
            return [
                s.get_text(strip=True)
                for s in scripts
                if not s.get("src")
            ]
        except Exception:
            return []

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

        try:
            index = text.find(payload)
            if index == -1:
                return ""

            start = max(0, index - window)
            end = index + len(payload) + window
            snippet = text[start:end]
            return snippet.replace("\n", " ").strip()
        except Exception:
            return ""

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

    @staticmethod
    def _stable_dedupe_key(value: Any) -> str:
        return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))

    def fuzz_xss_parameters(
        self,
        base_url: str,
        payload_data: Optional[Dict[str, Any]],
        method: str,
        xss_vectors: Optional[List[str]] = None,
    ) -> List[Union[str, Dict[str, Any]]]:

        vectors = xss_vectors if xss_vectors is not None else self.build_payload_set(limit=200)

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
        seen: Set[str] = set()

        m = method.upper()

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

        elif m == "POST":
            for vector in vectors:
                for key in base_params:
                    mutated = mutate_params(base_params, key, vector)
                    entry = {"url": base_url, "json": mutated}
                    key_ = self._stable_dedupe_key(entry)

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

    def probe_target(
        self,
        url: str,
        payloads: Optional[List[str]] = None,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 10.0,
        verify_ssl: bool = False,
        json_payload: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        if not url or self.session is None:
            return []

        vectors = self.build_payload_set(limit=100, custom_payloads=payloads)
        if not vectors:
            return []

        merged_params = dict(params or {})
        req_headers = {**self.default_headers, **(headers or {})}
        result_rows: List[Dict[str, Any]] = []

        for payload in vectors:
            send_params = dict(merged_params)
            if send_params:
                for key in list(send_params.keys()):
                    current = send_params[key]
                    send_params[key] = current + payload if isinstance(current, str) else payload
            else:
                send_params = {"q": payload}

            try:
                if method.upper() == "POST":
                    response = self.session.request(
                        method.upper(),
                        url,
                        headers=req_headers,
                        params=None,
                        data=send_params,
                        json=json_payload,
                        timeout=timeout,
                        verify=verify_ssl,
                    )
                else:
                    response = self.session.request(
                        method.upper(),
                        url,
                        headers=req_headers,
                        params=send_params,
                        timeout=timeout,
                        verify=verify_ssl,
                    )

                body = response.text or ""
                context = self.detect_xss_context(body, payload) if payload in body else None
                hit = bool(payload in body or context is not None)

                row = {
                    "method": method.upper(),
                    "url": url,
                    "payload": payload,
                    "status_code": response.status_code,
                    "length": len(body),
                    "reflected": hit,
                    "context": context,
                    "snippet": self.get_code_snippet(body, payload, window=80),
                }
                result_rows.append(row)

                self._safe_threat_add(
                    {
                        "type": "XSS_PROBE",
                        "method": method.upper(),
                        "url": url,
                        "payload": payload,
                        "status_code": response.status_code,
                        "context": context,
                        "reflected": hit,
                        "source": "XSSDetector",
                    }
                )
            except Exception:
                continue

        return result_rows

    def _safe_threat_add(self, payload: Dict[str, Any]) -> None:
        if not payload or self.threat_tab is None:
            return
        try:
            add_threat = getattr(self.threat_tab, "add_threat", None)
            if callable(add_threat):
                add_threat(payload)
        except Exception:
            pass
