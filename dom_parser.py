# xss_security_gui/dom_parser.py
"""
DOMParser ULTRA 6.0
Парсер DOM для XSS Security Suite:
- Извлечение форм, скриптов, событий, медиа и др.
- Интеграция с settings.py и ThreatConnector
"""

import os
import json
from bs4 import BeautifulSoup, Comment
from typing import Any, Dict, List
from xss_security_gui import settings
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR


class DOMParser:
    def __init__(self, html: str, threat_tab=None):
        self.soup = BeautifulSoup(html, "html.parser")
        self.threat_tab = threat_tab
        self.log_path = settings.LOG_DIR / "dom_parser.log"

    def _safe_log(self, text: str):
        """Логирование в файл и консоль"""
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(text + "\n")
        except Exception:
            pass
        print(text)

    # === Формы ===
    def extract_forms(self) -> List[Dict[str, Any]]:
        forms = []
        for form in self.soup.find_all("form"):
            inputs = []
            for inp in form.find_all(["input", "textarea", "select", "button"]):
                inputs.append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text").lower(),
                    "placeholder": inp.get("placeholder", ""),
                    "value": inp.get("value", "")
                })
            events = {k: v for k, v in form.attrs.items() if k.lower().startswith("on")}
            forms.append({
                "action": form.get("action", ""),
                "method": form.get("method", "GET").upper(),
                "inputs": inputs,
                "js_events": events
            })
        return forms

    # === Iframes ===
    def extract_iframes(self) -> List[Dict[str, Any]]:
        return [{"src": iframe.get("src", ""), "sandbox": iframe.get("sandbox", "")}
                for iframe in self.soup.find_all("iframe")]

    # === Meta-теги ===
    def extract_meta_tags(self) -> List[Dict[str, str]]:
        metas = []
        for tag in self.soup.find_all("meta"):
            content = tag.get("content")
            name = tag.get("name") or tag.get("property") or tag.get("http-equiv")
            if content and name:
                metas.append({"name": name, "content": content})
        return metas

    # === DOM-события ===
    def extract_dom_events(self) -> List[Dict[str, Any]]:
        events = []
        for element in self.soup.find_all(True):
            for attr, value in element.attrs.items():
                if attr.lower().startswith("on"):
                    risk = "⚠️ Высокий" if attr.lower() in ("onerror", "onload") else "Средний"
                    events.append({
                        "tag": element.name,
                        "event": attr,
                        "handler": value,
                        "risk_level": risk
                    })
        return events

    # === Скрипты ===
    def extract_scripts(self) -> List[Dict[str, Any]]:
        return [{
            "src": script.get("src", ""),
            "type": script.get("type", "text/javascript"),
            "inline": script.string.strip() if script.string else "",
            "async": "async" in script.attrs,
            "defer": "defer" in script.attrs
        } for script in self.soup.find_all("script")]

    # === Inline JS ===
    def extract_inline_js(self) -> List[str]:
        return [script.string.strip()
                for script in self.soup.find_all("script")
                if not script.get("src") and script.string]

    # === JSON-LD ===
    def extract_json_ld(self) -> List[Dict[str, Any]]:
        data = []
        for script in self.soup.find_all("script", type="application/ld+json"):
            try:
                data.append(json.loads(script.string))
            except Exception:
                continue
        return data

    # === Ссылки ===
    def extract_links(self) -> List[Dict[str, str]]:
        return [{"href": a.get("href", ""), "text": a.get_text(strip=True)}
                for a in self.soup.find_all("a")]

    # === Стили ===
    def extract_styles(self) -> List[Dict[str, str]]:
        styles = []
        for tag in self.soup.find_all("style"):
            styles.append({"inline_css": tag.string.strip() if tag.string else ""})
        for tag in self.soup.find_all("link", rel="stylesheet"):
            styles.append({"href": tag.get("href", ""), "media": tag.get("media", "")})
        return styles

    # === Комментарии ===
    def extract_comments(self) -> List[str]:
        return [str(c).strip() for c in self.soup.find_all(string=lambda t: isinstance(t, Comment))]

    # === Noscript ===
    def extract_noscript(self) -> List[str]:
        return [tag.get_text(strip=True) for tag in self.soup.find_all("noscript")]

    # === CSP ===
    def extract_csp_meta(self) -> List[str]:
        return [tag.get("content", "")
                for tag in self.soup.find_all("meta", attrs={"http-equiv": "Content-Security-Policy"})]

    # === Canonical ===
    def extract_canonical(self) -> Dict[str, str]:
        link = self.soup.find("link", rel="canonical")
        return {"href": link.get("href", "")} if link else {}

    # === Base ===
    def extract_base_tag(self) -> Dict[str, str]:
        base = self.soup.find("base")
        return {"href": base.get("href", "")} if base else {}

    # === Headers ===
    def extract_headers(self) -> List[Dict[str, str]]:
        headers = []
        for level in range(1, 7):
            for h in self.soup.find_all(f"h{level}"):
                headers.append({"tag": f"h{level}", "text": h.get_text(strip=True)})
        return headers

    # === Lists ===
    def extract_lists(self) -> List[Dict[str, Any]]:
        lists = []
        for ul in self.soup.find_all("ul"):
            lists.append({"type": "ul", "items": [li.get_text(strip=True) for li in ul.find_all("li")]})
        for ol in self.soup.find_all("ol"):
            lists.append({"type": "ol", "items": [li.get_text(strip=True) for li in ol.find_all("li")]})
        return lists

    # === Data-* атрибуты ===
    def extract_data_attributes(self) -> List[Dict[str, str]]:
        return [{"tag": el.name, "attr": attr, "value": val}
                for el in self.soup.find_all(True)
                for attr, val in el.attrs.items() if attr.startswith("data-")]

    # === ARIA атрибуты ===
    def extract_aria_attributes(self) -> List[Dict[str, str]]:
        return [{"tag": el.name, "attr": attr, "value": val}
                for el in self.soup.find_all(True)
                for attr, val in el.attrs.items() if attr.startswith("aria-")]

    # === SVG ===
    def extract_svg(self) -> List[Dict[str, str]]:
        return [{"svg": str(svg)} for svg in self.soup.find_all("svg")]

    # === Таблицы ===
    def extract_tables(self) -> List[Dict[str, Any]]:
        tables = []
        for table in self.soup.find_all("table"):
            rows = []
            for tr in table.find_all("tr"):
                cells = [td.get_text(strip=True) for td in tr.find_all(["td", "th"])]
                rows.append(cells)
            tables.append({"rows": rows})
        return tables

    # === Медиа ===
    def extract_media(self) -> List[Dict[str, Any]]:
        media = []
        for img in self.soup.find_all("img"):
            media.append({"tag": "img", "src": img.get("src", ""), "alt": img.get("alt", "")})
        for video in self.soup.find_all("video"):
            media.append({"tag": "video", "src": video.get("src", ""), "controls": "controls" in video.attrs})
        for audio in self.soup.find_all("audio"):
            media.append({"tag": "audio", "src": audio.get("src", ""), "controls": "controls" in audio.attrs})
        return media

    # === Inline style атрибут
    def extract_inline_styles(self) -> List[Dict[str, str]]:
        return [{"tag": el.name, "style": el.get("style")} for el in self.soup.find_all(True) if "style" in el.attrs]

    # === Все вместе ===
    def extract_all(self) -> dict:
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
            "data_attributes": self.extract_data_attributes(),
            "aria_attributes": self.extract_aria_attributes(),
            "svg": self.extract_svg(),
            "tables": self.extract_tables(),
            "media": self.extract_media(),
            "inline_styles": self.extract_inline_styles()
        }

        # Интеграция с ThreatConnector
        try:
            THREAT_CONNECTOR.emit(
                module="dom_parser",
                target="DOM Analysis",
                result={
                    "summary": f"DOM parsed with {len(results)} categories",
                    "details": results
                }
            )
        except Exception as e:
            print(f"[⚠️] Ошибка передачи в ThreatConnector: {e}")

        # Интеграция с GUI ThreatTab (если есть)
        if self.threat_tab:
            try:
                self.threat_tab.load_results({"dom_parser": results})
            except Exception as e:
                self._safe_log(f"[⚠️] Ошибка передачи в ThreatTab: {e}")

        # Логирование в файл
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(results, ensure_ascii=False, indent=2) + "\n")
        except Exception as e:
            self._safe_log(f"[⚠️] Ошибка записи лога DOMParser: {e}")

        return results

