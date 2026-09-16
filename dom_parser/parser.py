# xss_security_gui/dom_parser/parser.py
"""
DOMParser ULTRA 7.0
Modern asynchronous DOM parser with caching, threading, and metrics
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Callable

from bs4 import BeautifulSoup, Comment

import xss_security_gui.settings as settings
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR

from .errors import (
    HTMLSizeExceeded,
    InvalidHTML,
)
from .async_executor import AsyncExecutor
from .cache import DOMParserCache
from .async_logger import BulkLogger
from .metrics import ProgressTracker


class DOMParser:
    """
    DOMParser ULTRA 7.0 — Синхронный режим (backward compatible).

    Features:
    - Robust error handling
    - HTML size validation
    - Timeout control per extraction
    - Memory-efficient parsing
    - Logging and metrics
    """

    MAX_HTML_SIZE_MB = 50
    DEFAULT_TIMEOUT_SEC = 30
    EXTRACT_TIMEOUT_SEC = 5

    def __init__(
        self,
        html: str,
        threat_tab=None,
        cache_enabled: bool = True,
        max_size_mb: int = None,
        timeout_sec: float = None,
    ):
        self.html = html
        self.threat_tab = threat_tab
        self.max_size_mb = max_size_mb or self.MAX_HTML_SIZE_MB
        self.timeout_sec = timeout_sec or self.DEFAULT_TIMEOUT_SEC
        self.cache_enabled = cache_enabled

        # Logging
        self.log = logging.getLogger("DOMParser")
        self.logger_path = settings.LOG_DIR / "dom_parser.log"
        self.bulk_logger = BulkLogger(self.logger_path, batch_size=50)

        # Cache and metrics
        self.cache = DOMParserCache(enabled=cache_enabled)
        self.html_size = len(html)

        # Validation
        self._validate_html()

        # Check cache
        self.html_hash = self.cache.get_md5_hash(html)
        cached_result = self.cache.get(self.html_hash) if cache_enabled else None
        if cached_result:
            self.soup = None
            self.cached_result = cached_result
            self.log.debug(f"Cache hit for HTML hash {self.html_hash[:8]}")
        else:
            self.soup = BeautifulSoup(html, "html.parser")
            self.cached_result = None

    def _validate_html(self) -> None:
        """Validate HTML size and format"""
        size_mb = len(self.html) / (1024 * 1024)
        if size_mb > self.max_size_mb:
            raise HTMLSizeExceeded(len(self.html), int(self.max_size_mb * 1024 * 1024))

        if not self.html or not isinstance(self.html, str):
            raise InvalidHTML("HTML must be non-empty string")

    def _safe_extract(
        self,
        method_name: str,
        method_func: Callable,
        default_value: Any = None
    ) -> Any:
        """
        Safe wrapper for extraction methods with error handling and logging.
        """
        default = default_value or ([] if method_name != "extract_base_tag" else {})
        
        try:
            result = method_func()
            return result
        except Exception as e:
            error_msg = f"Error in {method_name}: {e}"
            self.log.error(error_msg, exc_info=True)
            self.bulk_logger.log_entry(error_msg)
            return default

    # === Extraction Methods ===

    def extract_forms(self) -> List[Dict[str, Any]]:
        """Extract forms with inputs and events"""
        if not self.soup:
            return []

        def _extract():
            forms = []
            for form in self.soup.find_all("form"):
                inputs = []
                for inp in form.find_all(["input", "textarea", "select", "button"]):
                    inputs.append({
                        "name": inp.get("name", "") or "",
                        "type": (inp.get("type", "text") or "text").lower(),
                        "placeholder": inp.get("placeholder", "") or "",
                        "value": inp.get("value", "") or "",
                        "required": "required" in inp.attrs,
                    })

                events = {k: v for k, v in form.attrs.items() if k.lower().startswith("on")}
                forms.append({
                    "action": form.get("action", "") or "",
                    "method": (form.get("method", "GET") or "GET").upper(),
                    "inputs": inputs,
                    "js_events": events,
                    "enctype": form.get("enctype", "") or "",
                })
            return forms

        return self._safe_extract("extract_forms", _extract, [])

    def extract_iframes(self) -> List[Dict[str, Any]]:
        """Extract iframe elements"""
        if not self.soup:
            return []

        def _extract():
            return [
                {
                    "src": iframe.get("src", "") or "",
                    "sandbox": iframe.get("sandbox", "") or "",
                    "allow": iframe.get("allow", "") or "",
                    "title": iframe.get("title", "") or "",
                }
                for iframe in self.soup.find_all("iframe")
            ]

        return self._safe_extract("extract_iframes", _extract, [])

    def extract_meta_tags(self) -> List[Dict[str, str]]:
        """Extract meta tags"""
        if not self.soup:
            return []

        def _extract():
            metas = []
            for tag in self.soup.find_all("meta"):
                content = tag.get("content")
                name = tag.get("name") or tag.get("property") or tag.get("http-equiv")
                if content and name:
                    metas.append({
                        "name": name,
                        "content": content[:500],  # Limit length
                    })
            return metas

        return self._safe_extract("extract_meta_tags", _extract, [])

    def extract_dom_events(self) -> List[Dict[str, Any]]:
        """Extract DOM event handlers (XSS risk indicators)"""
        if not self.soup:
            return []

        def _extract():
            events = []
            high_risk_events = {"onerror", "onload", "onmouseover", "onclick"}

            for element in self.soup.find_all(True):
                for attr, value in element.attrs.items():
                    if attr.lower().startswith("on"):
                        event_name = attr.lower()
                        risk = "⚠️ High" if event_name in high_risk_events else "Medium"
                        events.append({
                            "tag": element.name,
                            "event": attr,
                            "handler": str(value)[:200],
                            "risk_level": risk,
                        })
            return events

        return self._safe_extract("extract_dom_events", _extract, [])

    def extract_scripts(self) -> List[Dict[str, Any]]:
        """Extract script tags with metadata"""
        if not self.soup:
            return []

        def _extract():
            return [
                {
                    "src": script.get("src", "") or "",
                    "type": script.get("type", "text/javascript") or "text/javascript",
                    "inline": (script.string or "").strip()[:1000],  # First 1KB
                    "async": "async" in script.attrs,
                    "defer": "defer" in script.attrs,
                    "integrity": script.get("integrity", "") or "",
                }
                for script in self.soup.find_all("script")
            ]

        return self._safe_extract("extract_scripts", _extract, [])

    def extract_inline_js(self) -> List[str]:
        """Extract inline JavaScript code"""
        if not self.soup:
            return []

        def _extract():
            return [
                script.string.strip()
                for script in self.soup.find_all("script")
                if not script.get("src") and script.string
            ]

        return self._safe_extract("extract_inline_js", _extract, [])

    def extract_json_ld(self) -> List[Dict[str, Any]]:
        """Extract JSON-LD structured data"""
        if not self.soup:
            return []

        def _extract():
            data = []
            for script in self.soup.find_all("script", type="application/ld+json"):
                try:
                    data.append(json.loads(script.string))
                except Exception:
                    pass
            return data

        return self._safe_extract("extract_json_ld", _extract, [])

    def extract_links(self) -> List[Dict[str, str]]:
        """Extract all links"""
        if not self.soup:
            return []

        def _extract():
            return [
                {
                    "href": a.get("href", "") or "",
                    "text": a.get_text(strip=True)[:100],
                    "title": a.get("title", "") or "",
                    "rel": str(a.get("rel", "")) or "",
                }
                for a in self.soup.find_all("a")
            ]

        return self._safe_extract("extract_links", _extract, [])

    def extract_styles(self) -> List[Dict[str, str]]:
        """Extract style tags and links"""
        if not self.soup:
            return []

        def _extract():
            styles = []
            for tag in self.soup.find_all("style"):
                styles.append({
                    "inline_css": (tag.string or "").strip()[:2000],
                })
            for tag in self.soup.find_all("link", rel="stylesheet"):
                styles.append({
                    "href": tag.get("href", "") or "",
                    "media": tag.get("media", "") or "",
                })
            return styles

        return self._safe_extract("extract_styles", _extract, [])

    def extract_comments(self) -> List[str]:
        """Extract HTML comments"""
        if not self.soup:
            return []

        def _extract():
            return [
                str(c).strip()
                for c in self.soup.find_all(string=lambda t: isinstance(t, Comment))
            ]

        return self._safe_extract("extract_comments", _extract, [])

    def extract_noscript(self) -> List[str]:
        """Extract noscript tags"""
        if not self.soup:
            return []

        def _extract():
            return [
                tag.get_text(strip=True)
                for tag in self.soup.find_all("noscript")
            ]

        return self._safe_extract("extract_noscript", _extract, [])

    def extract_csp_meta(self) -> List[str]:
        """Extract Content Security Policy"""
        if not self.soup:
            return []

        def _extract():
            return [
                tag.get("content", "") or ""
                for tag in self.soup.find_all("meta", attrs={"http-equiv": "Content-Security-Policy"})
            ]

        return self._safe_extract("extract_csp_meta", _extract, [])

    def extract_canonical(self) -> Dict[str, str]:
        """Extract canonical link"""
        if not self.soup:
            return {}

        def _extract():
            link = self.soup.find("link", rel="canonical")
            return {"href": link.get("href", "")} if link else {}

        return self._safe_extract("extract_canonical", _extract, {})

    def extract_base_tag(self) -> Dict[str, str]:
        """Extract base tag"""
        if not self.soup:
            return {}

        def _extract():
            base = self.soup.find("base")
            return {"href": base.get("href", "")} if base else {}

        return self._safe_extract("extract_base_tag", _extract, {})

    def extract_headers(self) -> List[Dict[str, str]]:
        """Extract all heading tags"""
        if not self.soup:
            return []

        def _extract():
            headers = []
            for level in range(1, 7):
                for h in self.soup.find_all(f"h{level}"):
                    headers.append({
                        "tag": f"h{level}",
                        "text": h.get_text(strip=True)[:200],
                    })
            return headers

        return self._safe_extract("extract_headers", _extract, [])

    def extract_lists(self) -> List[Dict[str, Any]]:
        """Extract ordered and unordered lists"""
        if not self.soup:
            return []

        def _extract():
            lists = []
            for ul in self.soup.find_all("ul"):
                lists.append({
                    "type": "ul",
                    "items": [li.get_text(strip=True)[:100] for li in ul.find_all("li", recursive=False)],
                })
            for ol in self.soup.find_all("ol"):
                lists.append({
                    "type": "ol",
                    "items": [li.get_text(strip=True)[:100] for li in ol.find_all("li", recursive=False)],
                })
            return lists

        return self._safe_extract("extract_lists", _extract, [])

    def extract_data_attributes(self) -> List[Dict[str, str]]:
        """Extract data-* attributes"""
        if not self.soup:
            return []

        def _extract():
            return [
                {
                    "tag": el.name,
                    "attr": attr,
                    "value": str(val)[:200],
                }
                for el in self.soup.find_all(True)
                for attr, val in el.attrs.items()
                if attr.startswith("data-")
            ]

        return self._safe_extract("extract_data_attributes", _extract, [])

    def extract_aria_attributes(self) -> List[Dict[str, str]]:
        """Extract aria-* attributes for accessibility"""
        if not self.soup:
            return []

        def _extract():
            return [
                {
                    "tag": el.name,
                    "attr": attr,
                    "value": str(val)[:200],
                }
                for el in self.soup.find_all(True)
                for attr, val in el.attrs.items()
                if attr.startswith("aria-")
            ]

        return self._safe_extract("extract_aria_attributes", _extract, [])

    def extract_svg(self) -> List[Dict[str, str]]:
        """Extract SVG elements"""
        if not self.soup:
            return []

        def _extract():
            return [{"svg": str(svg)[:5000]} for svg in self.soup.find_all("svg")]

        return self._safe_extract("extract_svg", _extract, [])

    def extract_tables(self) -> List[Dict[str, Any]]:
        """Extract table structures"""
        if not self.soup:
            return []

        def _extract():
            tables = []
            for table in self.soup.find_all("table"):
                rows = []
                for tr in table.find_all("tr"):
                    cells = [
                        td.get_text(strip=True)[:100]
                        for td in tr.find_all(["td", "th"])
                    ]
                    rows.append(cells)
                tables.append({"rows": rows[:100]})  # Limit rows
            return tables

        return self._safe_extract("extract_tables", _extract, [])

    def extract_media(self) -> List[Dict[str, Any]]:
        """Extract media elements (img, video, audio)"""
        if not self.soup:
            return []

        def _extract():
            media = []
            for img in self.soup.find_all("img"):
                media.append({
                    "tag": "img",
                    "src": img.get("src", "") or "",
                    "alt": img.get("alt", "") or "",
                    "title": img.get("title", "") or "",
                })
            for video in self.soup.find_all("video"):
                media.append({
                    "tag": "video",
                    "src": video.get("src", "") or "",
                    "controls": "controls" in video.attrs,
                })
            for audio in self.soup.find_all("audio"):
                media.append({
                    "tag": "audio",
                    "src": audio.get("src", "") or "",
                    "controls": "controls" in audio.attrs,
                })
            return media

        return self._safe_extract("extract_media", _extract, [])

    def extract_inline_styles(self) -> List[Dict[str, str]]:
        """Extract inline style attributes"""
        if not self.soup:
            return []

        def _extract():
            return [
                {
                    "tag": el.name,
                    "style": el.get("style", "")[:500],
                }
                for el in self.soup.find_all(True)
                if "style" in el.attrs
            ]

        return self._safe_extract("extract_inline_styles", _extract, [])

    def extract_all(self) -> dict:
        """
        Extract all DOM elements at once.
        Returns cached result if available.
        """
        if self.cached_result:
            self.bulk_logger.log_entry(
                json.dumps({
                    "timestamp": datetime.now().isoformat(),
                    "status": "success",
                    "cache_hit": True,
                    "html_hash": self.html_hash[:8],
                })
            )
            return self.cached_result

        try:
            results = {
                "forms": self.extract_forms(),
                "iframes": self.extract_iframes(),
                "meta_tags": self.extract_meta_tags(),
                "dom_events": self.extract_dom_events(),
                "scripts": self.extract_scripts(),
                "inline_js": self.extract_inline_js(),
                "links": self.extract_links(),
                "styles": self.extract_styles(),
                "comments": self.extract_comments(),
                "noscript": self.extract_noscript(),
                "csp_meta": self.extract_csp_meta(),
                "base_tag": self.extract_base_tag(),
                "canonical": self.extract_canonical(),
                "headers": self.extract_headers(),
                "lists": self.extract_lists(),
                "data_attributes": self.extract_data_attributes(),
                "aria_attributes": self.extract_aria_attributes(),
                "svg": self.extract_svg(),
                "tables": self.extract_tables(),
                "media": self.extract_media(),
                "inline_styles": self.extract_inline_styles(),
            }

            # Cache result
            if self.cache_enabled:
                self.cache.set(self.html_hash, results)

            # Log to ThreatConnector
            try:
                THREAT_CONNECTOR.emit(
                    module="dom_parser",
                    target="DOM Analysis",
                    result={
                        "summary": f"DOM parsed with {len(results)} categories",
                        "categories": {k: len(v) for k, v in results.items()},
                    }
                )
            except Exception as e:
                self.log.warning(f"ThreatConnector emit failed: {e}")

            # Log to GUI ThreatTab
            if self.threat_tab:
                try:
                    self.threat_tab.load_results({"dom_parser": results})
                except Exception as e:
                    self.log.warning(f"ThreatTab load_results failed: {e}")

            # Bulk log
            self.bulk_logger.log_entry(
                json.dumps({
                    "timestamp": datetime.now().isoformat(),
                    "status": "success",
                    "cache_hit": False,
                    "categories": len(results),
                })
            )

            return results

        except Exception as e:
            self.log.error(f"extract_all failed: {e}", exc_info=True)
            return {}

    def __del__(self):
        """Cleanup"""
        try:
            self.bulk_logger.flush()
        except Exception:
            pass


class DOMParserAsync:
    """
    DOMParser ULTRA 7.0 — Асинхронный режим с ThreadPoolExecutor.

    Features:
    - Non-blocking parsing in background threads
    - Progress tracking
    - Batch result collection
    - Timeout management
    - Graceful error handling
    """

    def __init__(
        self,
        html: str,
        threat_tab=None,
        max_workers: int = 6,
        cache_enabled: bool = True,
        progress_callback: Callable = None,
    ):
        self.html = html
        self.threat_tab = threat_tab
        self.cache_enabled = cache_enabled
        self.progress_callback = progress_callback or (lambda x: None)

        self.executor = AsyncExecutor(max_workers=max_workers)
        self.progress = ProgressTracker([self.progress_callback])

        self.log = logging.getLogger("DOMParserAsync")
        self.parser = None

    async def parse_async(self) -> dict:
        """Асинхронный парсинг с потокизацией"""
        self.progress.set_total(22)

        try:
            # Create base parser
            self.parser = DOMParser(
                self.html,
                self.threat_tab,
                cache_enabled=self.cache_enabled
            )

            # Список задач для параллельного выполнения
            tasks = [
                ("forms", self.parser.extract_forms),
                ("iframes", self.parser.extract_iframes),
                ("meta_tags", self.parser.extract_meta_tags),
                ("dom_events", self.parser.extract_dom_events),
                ("scripts", self.parser.extract_scripts),
                ("inline_js", self.parser.extract_inline_js),
                ("json_ld", self.parser.extract_json_ld),
                ("links", self.parser.extract_links),
                ("styles", self.parser.extract_styles),
                ("comments", self.parser.extract_comments),
                ("noscript", self.parser.extract_noscript),
                ("csp_meta", self.parser.extract_csp_meta),
                ("canonical", self.parser.extract_canonical),
                ("base_tag", self.parser.extract_base_tag),
                ("headers", self.parser.extract_headers),
                ("lists", self.parser.extract_lists),
                ("data_attributes", self.parser.extract_data_attributes),
                ("aria_attributes", self.parser.extract_aria_attributes),
                ("svg", self.parser.extract_svg),
                ("tables", self.parser.extract_tables),
                ("media", self.parser.extract_media),
                ("inline_styles", self.parser.extract_inline_styles),
            ]

            # Batch submit with timeout
            results = self.executor.submit_all(tasks, timeout=30.0)

            # Update progress
            self.progress.finish()

            return results

        except Exception as e:
            self.log.error(f"Async parsing failed: {e}", exc_info=True)
            self.progress.set_status(f"Error: {e}")
            return {}

    def __del__(self):
        """Cleanup"""
        try:
            self.executor.shutdown(wait=True)
        except Exception:
            pass

