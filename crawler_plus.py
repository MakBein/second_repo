# xss_security_gui/crawler_plus.py

import requests
import re
import json
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import RequestException, Timeout
from concurrent.futures import ThreadPoolExecutor, as_completed

# Универсальные пути пакета
from xss_security_gui import DIRS

# Путь для сохранения deep_crawl.json
CRAWL_OUTPUT = os.path.join(DIRS["logs"], "deep_crawl.json")

# Session with retries
session = requests.Session()
session.headers.update({"User-Agent": "CrawlerPlus/1.0 (+https://gazprombank.ru)"})
retries = Retry(total=2, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504))
session.mount("http://", HTTPAdapter(max_retries=retries))
session.mount("https://", HTTPAdapter(max_retries=retries))

# Limits and configuration
MAX_JS_BYTES = 200_000
MAX_SOURCEMAPS = 10
MAX_EXTERNAL_JS = 20
MAX_TOKENS_PER_PAGE = 50
JS_FETCH_TIMEOUT = 3
PAGE_FETCH_TIMEOUT = 5
SOURCEMAP_TIMEOUT = 2
CONCURRENT_JS_FETCH = 6

# Precompiled patterns
EMBEDDED_JSON_TEMPLATE = r'{key}\s*=\s*(\{{.*?\}}|\[.*?\])\s*;?'
TOKEN_PATTERNS = [
    re.compile(r'["\']?(access[_-]?token|auth[_-]?token|jwt|api[_-]?key|token|secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9\-._~+/=]{10,})["\']', re.I),
    re.compile(r'(localStorage|sessionStorage)\.setItem\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]', re.I),
    re.compile(r'Authorization\s*[:=]\s*["\']?Bearer\s+([A-Za-z0-9\-._~+/=]+)["\']?', re.I),
    re.compile(r'[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}')
]
JS_SRC_RE = re.compile(r'src=["\'](.*?\.js)["\']', re.I)
INLINE_ENDPOINT_RE = re.compile(r'(\/[a-zA-Z0-9/_\-\.\?\=]+)')


def fetch_text_limited(url, timeout=JS_FETCH_TIMEOUT, max_bytes=MAX_JS_BYTES):
    """Fetch text with stream and size limit. Returns empty string on error."""
    try:
        r = session.get(url, timeout=timeout, stream=True)
        r.raise_for_status()
        content_chunks = []
        total = 0
        for chunk in r.iter_content(chunk_size=8192, decode_unicode=True):
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                break
            content_chunks.append(chunk)
        return "".join(content_chunks)
    except (RequestException, Timeout):
        return ""


def dedupe_preserve_order(seq):
    seen = set()
    out = []
    for item in seq:
        try:
            key = item if isinstance(item, (str, int, float, tuple)) else json.dumps(item, sort_keys=True, ensure_ascii=False)
        except Exception:
            key = str(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def extract_embedded_json(soup, keys):
    found = []
    for script in soup.find_all("script"):
        text = script.string or ""
        if not text:
            continue
        for key in keys:
            try:
                pattern = re.compile(EMBEDDED_JSON_TEMPLATE.format(key=re.escape(key)), re.DOTALL)
            except re.error:
                continue
            match = pattern.search(text)
            if match:
                raw = match.group(1).strip().rstrip(";,")
                try:
                    data = json.loads(raw)
                    found.append({key: data})
                except json.JSONDecodeError:
                    continue
    return found


def find_tokens(js_text):
    tokens = []
    if not js_text:
        return tokens
    for p in TOKEN_PATTERNS:
        for m in p.finditer(js_text):
            tokens.append({"pattern": p.pattern, "match": m.groups()})
            if len(tokens) >= MAX_TOKENS_PER_PAGE:
                return tokens
    return tokens


def find_sourcemaps(base_url):
    maps = []
    try:
        r = session.get(base_url, timeout=PAGE_FETCH_TIMEOUT)
        r.raise_for_status()
        js_files = JS_SRC_RE.findall(r.text)
        for js_url in js_files[:MAX_EXTERNAL_JS]:
            full_js = urljoin(base_url, js_url)
            sm_url = full_js + ".map"
            try:
                sm_text = fetch_text_limited(sm_url, timeout=SOURCEMAP_TIMEOUT, max_bytes=50_000)
                if sm_text and "sources" in sm_text:
                    maps.append(sm_url)
                    if len(maps) >= MAX_SOURCEMAPS:
                        break
            except Exception:
                continue
    except Exception:
        pass
    return dedupe_preserve_order(maps)


def detect_graphql_endpoint(base_url):
    candidates = ["/graphql", "/api/graphql"]
    found = []
    for path in candidates:
        try:
            r = session.post(urljoin(base_url, path), json={"query": "{__typename}"}, timeout=3)
            if r.status_code == 200 and ("errors" in r.text or "data" in r.text):
                found.append(urljoin(base_url, path))
        except Exception:
            continue
    return dedupe_preserve_order(found)


def analyze_deep(url):
    result = {
        "url": url,
        "meta": {},
        "cms": None,
        "frameworks": [],
        "adaptive": False,
        "headings": [],
        "api_endpoints": [],
        "tokens": [],
        "initial_state": [],
        "sourcemaps": [],
        "graphql": [],
        "content_score": 0,
        "robots_txt": [],
        "headers": {},
        "cookies": [],
        "debug_flags": [],
        "forms": [],
        "input_keywords": [],
        "xss_reflected": False,
        "csp_status": "missing",
        "error": None
    }

    try:
        r = session.get(url, timeout=PAGE_FETCH_TIMEOUT)
        r.raise_for_status()

        content_type = r.headers.get("Content-Type", "")
        if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
            result["error"] = f"Unsupported Content-Type: {content_type}"
            return result

        html = r.text
        soup = BeautifulSoup(html, "html.parser")

        result["headers"] = dict(r.headers)
        result["cookies"] = [f"{c.name}={c.value}" for c in r.cookies]

        # CSP
        for k, v in r.headers.items():
            if k.lower() == "content-security-policy":
                result["csp_status"] = "present" if "script-src" in v else "weak"

        # Meta
        for meta in soup.find_all("meta"):
            name = (meta.get("name") or meta.get("property") or "").lower()
            if name in ["description", "keywords", "viewport", "robots"]:
                result["meta"][name] = meta.get("content", "")
        if soup.find("meta", charset=True):
            result["meta"]["charset"] = soup.find("meta", charset=True).get("charset")

        # CMS detect
        cms_signatures = {
            "wordpress": ["wp-content", "wp-json"],
            "drupal": ["drupal-settings-json"],
            "shopify": ["cdn.shopify.com"]
        }
        for cms, patterns in cms_signatures.items():
            if any(p in html for p in patterns):
                result["cms"] = cms

        # Frameworks
        js_signatures = {
            "react": ["__REACT_DEVTOOLS_GLOBAL_HOOK__"],
            "vue": ["__vue__"],
            "angular": ["ng-version"],
            "next": ["__NEXT_DATA__"]
        }
        for fw, patterns in js_signatures.items():
            if any(p in html for p in patterns):
                result["frameworks"].append(fw)

        # Debug flags
        debug_keywords = ["__debug__", "window.debug", "devMode", "isDev", "debugMode"]
        for kw in debug_keywords:
            if kw in html:
                result["debug_flags"].append(kw)

        # Adaptive
        if "viewport" in result["meta"] or "@media" in html:
            result["adaptive"] = True

        # Headings
        for tag in ["h1", "h2"]:
            for h in soup.find_all(tag):
                content = h.get_text(strip=True)
                if content:
                    result["headings"].append({tag: content})

        # Forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = []
            for inp in form.find_all("input"):
                inputs.append({
                    "name": inp.get("name"),
                    "type": inp.get("type"),
                    "placeholder": inp.get("placeholder")
                })
                result["input_keywords"].append(inp.get("name", ""))
            result["forms"].append({"action": action, "method": method, "inputs": inputs})

        # Reflected XSS
        test_payload = "<script>alert(1)</script>"
        try:
            test = session.get(url, params={"xss": test_payload}, timeout=3)
            if test_payload in test.text:
                result["xss_reflected"] = True
        except Exception:
            pass

        # Inline JS
        for script in soup.find_all("script"):
            if not script.get("src") and script.string:
                matches = INLINE_ENDPOINT_RE.findall(script.string)
                for m in matches:
                    if any(p in m for p in ["/api", ".php", ".json", "/auth"]):
                        full = urljoin(url, m)
                        result["api_endpoints"].append(full)
                result["tokens"].extend(find_tokens(script.string))

        # External JS
        js_links = [s.get("src") for s in soup.find_all("script") if s.get("src")]
        js_links = js_links[:MAX_EXTERNAL_JS]
        if js_links:
            with ThreadPoolExecutor(max_workers=CONCURRENT_JS_FETCH) as ex:
                futures = {ex.submit(fetch_text_limited, urljoin(url, js), JS_FETCH_TIMEOUT): js for js in js_links}
                for fut in as_completed(futures):
                    try:
                        js_text = fut.result()
                    except Exception:
                        js_text = ""
                    if js_text:
                        result["tokens"].extend(find_tokens(js_text))

        # Deduplication
        result["api_endpoints"] = dedupe_preserve_order(result["api_endpoints"])
        result["tokens"] = dedupe_preserve_order(result["tokens"])

        # Embedded JSON, sourcemaps, graphql
        result["initial_state"] = extract_embedded_json(soup, ["__INITIAL_STATE__", "__NEXT_DATA__"])
        result["sourcemaps"] = find_sourcemaps(url)
        result["graphql"] = detect_graphql_endpoint(url)

        # Content score
        paragraphs = soup.find_all("p")
        result["content_score"] = sum(len(p.get_text(strip=True)) for p in paragraphs)

        # robots.txt
        try:
            rb = session.get(urljoin(url, "/robots.txt"), timeout=3)
            if rb.status_code == 200:
                result["robots_txt"] = [line.strip() for line in rb.text.splitlines() if line.lower().startswith("disallow")]
        except Exception:
            result["robots_txt"] = []

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_list(urls, export_path=None):
    # Универсальный путь по умолчанию
    if export_path is None:
        export_path = CRAWL_OUTPUT

    os.makedirs(DIRS["logs"], exist_ok=True)

    all_results = []
    for url in urls:
        print(f"🧬 Анализ: {url}")
        info = analyze_deep(url)
        all_results.append(info)

    summary = {
        "total": len(urls),
        "with_tokens": sum(1 for r in all_results if r.get("tokens")),
        "with_graphql": sum(1 for r in all_results if r.get("graphql")),
        "with_sourcemaps": sum(1 for r in all_results if r.get("sourcemaps")),
        "reflected_xss": sum(1 for r in all_results if r.get("xss_reflected"))
    }

    print("📊 Статистика анализа:")
    for k, v in summary.items():
        percent = (v / summary["total"] * 100) if summary["total"] else 0
        print(f"  {k}: {v} ({percent:.1f}%)")

    try:
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)
        print(f"✅ {export_path} сохранён.")
    except Exception as e:
        print(f"❌ Ошибка сохранения {export_path}: {e}")