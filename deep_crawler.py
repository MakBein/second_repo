# xss_security_gui/deep_crawler.py

import os
import queue
import re
import json
import logging
import traceback
import datetime as dt
from typing import Any, List
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime, UTC

import requests
from playwright.sync_api import sync_playwright

from xss_security_gui.js_inspector import extract_js_insights
from xss_security_gui.crawler import extract_sensitive_data
from xss_security_gui.settings import LOG_DIR
# Глобальная очередь для Live Monitor
LIVE_MONITOR_QUEUE: "queue.Queue[dict]" = queue.Queue()

# Используем единую лог‑директорию из settings.py
LOGS_DIR = str(LOG_DIR)
os.makedirs(LOGS_DIR, exist_ok=True)

logger = logging.getLogger("ThreatConnector6")
logger.setLevel(logging.INFO)

from xss_security_gui.auth.login_flow import (
    perform_login,
)


# ============================================================
#  Логирование 6.0 — расширенная версия (без дублей директорий)
# ============================================================

# Используем единую лог-директорию из settings.py
LOGS_DIR = str(LOG_DIR)

os.makedirs(LOGS_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s"
)
logger = logging.getLogger("DeepCrawler6")


def _write_gui_log(filename: str, prefix: str, msg: str) -> None:
    """
    Вспомогательная функция для записи в GUI‑логи.
    Все логи лежат в общей директории LOGS_DIR.
    """
    from datetime import datetime, UTC

    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    path = os.path.join(LOGS_DIR, filename)

    with open(path, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {prefix} {msg}\n")

# ============================================================
#  INFO
# ============================================================
def log_info(msg: str) -> None:
    """
    Пишет информационное сообщение:
    • в стандартный логгер
    • в logs/info_log.txt
    """
    logger.info(msg)
    _write_gui_log("info_log.txt", "ℹ️ INFO:", msg)


# ============================================================
#  WARNING
# ============================================================
def log_warn(msg: str) -> None:
    """
    Пишет предупреждение:
    • в стандартный логгер
    • в logs/warn_log.txt
    """
    logger.warning(msg)
    _write_gui_log("warn_log.txt", "⚠️ WARNING:", msg)


# ============================================================
#  ERROR
# ============================================================
def log_error(msg: str, exc: Exception | None = None) -> None:
    """
    Пишет ошибку:
    • в стандартный логгер
    • в logs/error_log.txt
    • сохраняет traceback, если есть Exception
    """
    from datetime import datetime, UTC

    logger.error(msg)

    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    path = os.path.join(LOGS_DIR, "error_log.txt")

    with open(path, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] ❌ ERROR: {msg}\n")
        if exc:
            f.write(f"{type(exc).__name__}: {str(exc)}\n")
            f.write(traceback.format_exc() + "\n")


def detect_logout_url(page):
    """
    Расширенный детектор logout‑URL.
    """
    candidates: set[str] = set()
    html = page.content().lower()

    # 1) Ссылки <a>
    for a in page.query_selector_all("a[href]"):
        href = a.get_attribute("href") or ""
        text = (a.inner_text() or "").lower()

        if any(k in text for k in ["logout", "sign out", "выход"]):
            candidates.add(href)

        if "logout" in href.lower():
            candidates.add(href)

    # 2) Кнопки <button>
    for b in page.query_selector_all("button"):
        text = (b.inner_text() or "").lower()
        onclick = (b.get_attribute("onclick") or "").lower()

        if any(k in text for k in ["logout", "sign out", "выход"]):
            candidates.add(page.url)

        if "logout" in onclick:
            candidates.add(page.url)

    # 3) API logout
    api_patterns = ["/api/logout", "/logout", "/auth/logout"]
    for p in api_patterns:
        if p in html:
            candidates.add(p)

    # 4) SPA logout
    spa_patterns = ["#/logout", "/#/logout"]
    for p in spa_patterns:
        if p in html:
            candidates.add(p.replace("#", ""))

    return list(candidates) or None

# === Часть 4: CMS / Framework detection ===

def detect_cms(html: str, headers: dict = None, cookies: list = None, url: str = ""):
    html_lower = html.lower()
    headers = headers or {}
    cookies = cookies or []
    url_lower = url.lower()

    detected: set[str] = set()

    # 1) Meta generator
    meta_gen = re.findall(r'<meta[^>]+name="generator"[^>]+content="([^"]+)"', html_lower)
    for gen in meta_gen:
        if "wordpress" in gen:
            detected.add("WordPress")
        if "drupal" in gen:
            detected.add("Drupal")
        if "joomla" in gen:
            detected.add("Joomla")
        if "ghost" in gen:
            detected.add("Ghost")
        if "typo3" in gen:
            detected.add("TYPO3")

    # 2) Cookies
    cookie_names = [c.get("name", "").lower() for c in cookies]

    cookie_map = {
        "wordpress_logged_in_": "WordPress",
        "wp-settings": "WordPress",
        "drupal_uid": "Drupal",
        "ocsession": "OpenCart",
        "prestashop": "PrestaShop",
        "mage-cache": "Magento",
        "magento": "Magento",
        "shopify": "Shopify",
        "bitrix": "1C-Bitrix",
    }

    for cname in cookie_names:
        for key, cms in cookie_map.items():
            if key in cname:
                detected.add(cms)

    # 3) HTTP headers
    header_map = {
        "x-powered-by": {
            "php": "PHP site",
            "express": "Express.js",
            "laravel": "Laravel",
            "next.js": "Next.js",
        },
        "server": {
            "apache": "Apache",
            "nginx": "Nginx",
            "iis": "IIS",
            "cloudflare": "Cloudflare",
        },
        "x-generator": {
            "drupal": "Drupal",
            "wordpress": "WordPress",
            "joomla": "Joomla",
        },
    }

    for hname, patterns in header_map.items():
        val = headers.get(hname, "").lower()
        for key, cms in patterns.items():
            if key in val:
                detected.add(cms)

    # 4) URL patterns
    url_patterns = {
        "/wp-json": "WordPress",
        "/wp-content": "WordPress",
        "/sites/default/files": "Drupal",
        "/ghost/api": "Ghost",
        "/index.php?route=": "OpenCart",
        "/bitrix/": "1C-Bitrix",
        "/umbraco": "Umbraco",
        "/typo3/": "TYPO3",
    }

    for pattern, cms in url_patterns.items():
        if pattern in url_lower:
            detected.add(cms)

    # 5) HTML signatures
    cms_signatures = {
        "WordPress": ["wp-content", "wp-includes", "wp-json", "wp-admin"],
        "Drupal": ["drupal.js", "drupal-settings-json"],
        "Joomla": ["joomla.js", "com_content"],
        "Magento": ["mage", "x-magento-init"],
        "Shopify": ["cdn.shopify.com", "shopify-checkout"],
        "1C-Bitrix": ["bitrix", "bx.core"],
        "OpenCart": ["opencart", "ocstore"],
        "Ghost": ["ghost-sdk", "ghost-content-api"],
        "Strapi": ["strapi"],
        "Webflow": ["webflow"],
        "Wix": ["wix.com", "wixstatic"],
        "Squarespace": ["squarespace"],
        "MODX": ["modx"],
        "TYPO3": ["typo3"],
    }

    for cms, signs in cms_signatures.items():
        if any(sig in html_lower for sig in signs):
            detected.add(cms)

    return list(detected) or None


def detect_frameworks(html: str):
    html_lower = html.lower()
    frameworks: List[str] = []

    # React
    react_signatures = [
        "react.createelement",
        "reactdom.render",
        "window.react",
        "window.reactdom",
        "data-reactroot",
        "data-reactid",
        "__reactfiber",
        "__reactprops"
    ]
    if any(sig in html_lower for sig in react_signatures):
        frameworks.append("React")

    # Vue.js
    vue_signatures = [
        "vue.component",
        "window.vue",
        "new vue({",
        "vue.extend",
        "vue.config",
        "data-v-app",
        "data-v-"
    ]
    if any(sig in html_lower for sig in vue_signatures):
        frameworks.append("Vue.js")

    # Angular
    angular_signatures = [
        "ng-app",
        "angular.module",
        "ng-controller",
        "ng-version",
        "platform-browser-dynamic",
        "zone.js"
    ]
    if any(sig in html_lower for sig in angular_signatures):
        frameworks.append("Angular")

    # jQuery
    jquery_signatures = [
        "jquery",
        "window.jquery",
        "window.$",
        "$(document).ready",
        "jquery.fn"
    ]
    if any(sig in html_lower for sig in jquery_signatures):
        frameworks.append("jQuery")

    # Svelte
    svelte_signatures = [
        "svelte/internal",
        "svelte-h",
        "svelte-",
        "new svelte"
    ]
    if any(sig in html_lower for sig in svelte_signatures):
        frameworks.append("Svelte")

    # Next.js
    next_signatures = [
        "__next",
        "next-page",
        "next.config.js",
        "next-router",
        "next-head"
    ]
    if any(sig in html_lower for sig in next_signatures):
        frameworks.append("Next.js")

    # Nuxt.js
    nuxt_signatures = [
        "nuxt.config",
        "window.__nuxt__",
        "nuxt-link",
        "nuxt generate"
    ]
    if any(sig in html_lower for sig in nuxt_signatures):
        frameworks.append("Nuxt.js")

    # Ember.js
    ember_signatures = [
        "ember",
        "ember.js",
        "ember-application",
        "ember-cli"
    ]
    if any(sig in html_lower for sig in ember_signatures):
        frameworks.append("Ember.js")

    # Backbone.js
    backbone_signatures = [
        "backbone.model",
        "backbone.view",
        "backbone.collection"
    ]
    if any(sig in html_lower for sig in backbone_signatures):
        frameworks.append("Backbone.js")

    # Alpine.js
    alpine_signatures = [
        "alpine.js",
        "x-data=",
        "x-on:",
        "x-bind:"
    ]
    if any(sig in html_lower for sig in alpine_signatures):
        frameworks.append("Alpine.js")

    # Stimulus
    stimulus_signatures = [
        "stimulus",
        "data-controller",
        "data-action"
    ]
    if any(sig in html_lower for sig in stimulus_signatures):
        frameworks.append("Stimulus")

    # Mithril.js
    mithril_signatures = [
        "mithril",
        "m.route",
        "m.render"
    ]
    if any(sig in html_lower for sig in mithril_signatures):
        frameworks.append("Mithril.js")

    # Polymer
    polymer_signatures = [
        "polymer-element",
        "webcomponents-loader",
        "dom-module"
    ]
    if any(sig in html_lower for sig in polymer_signatures):
        frameworks.append("Polymer")

    # LitElement / Lit
    lit_signatures = [
        "lit-element",
        "lit-html",
        "lit.dev"
    ]
    if any(sig in html_lower for sig in lit_signatures):
        frameworks.append("LitElement")

    # Knockout.js
    knockout_signatures = [
        "data-bind=",
        "ko.applybindings",
        "knockout"
    ]
    if any(sig in html_lower for sig in knockout_signatures):
        frameworks.append("Knockout.js")

    # Dojo
    dojo_signatures = [
        "dojo.require",
        "dojo.declare",
        "dojo/dom"
    ]
    if any(sig in html_lower for sig in dojo_signatures):
        frameworks.append("Dojo Toolkit")

    # ExtJS
    extjs_signatures = [
        "ext.define",
        "ext.application",
        "ext.create"
    ]
    if any(sig in html_lower for sig in extjs_signatures):
        frameworks.append("ExtJS")

    # Bootstrap
    bootstrap_signatures = [
        "bootstrap.min.js",
        "data-bs-toggle",
        "data-toggle=\"modal\""
    ]
    if any(sig in html_lower for sig in bootstrap_signatures):
        frameworks.append("Bootstrap")

    # Tailwind CSS
    tailwind_signatures = [
        "tailwind",
        "class=\"flex",
        "class=\"grid",
        "class=\"container mx-auto"
    ]
    if any(sig in html_lower for sig in tailwind_signatures):
        frameworks.append("Tailwind CSS")

    # Material UI
    mui_signatures = [
        "material-ui",
        "mui",
        "class=\"mui"
    ]
    if any(sig in html_lower for sig in mui_signatures):
        frameworks.append("Material UI")

    # Semantic UI
    semantic_signatures = [
        "semantic-ui",
        "class=\"ui button"
    ]
    if any(sig in html_lower for sig in semantic_signatures):
        frameworks.append("Semantic UI")

    # Foundation
    foundation_signatures = [
        "foundation.min.js",
        "data-foundation"
    ]
    if any(sig in html_lower for sig in foundation_signatures):
        frameworks.append("Foundation")

    return frameworks


# === Часть 5: backend / server detection ===

def detect_backend_framework(headers: dict, html: str):
    html_lower = html.lower()
    server = headers.get("Server", "").lower()
    powered = headers.get("X-Powered-By", "").lower()
    cookies = "; ".join(headers.get("Set-Cookie", "").lower())

    frameworks: List[str] = []

    # PHP
    if "laravel" in powered or "laravel_session" in cookies:
        frameworks.append("Laravel")
    if "symfony" in powered or "symfony" in html_lower:
        frameworks.append("Symfony")
    if "yii" in powered or "yii" in html_lower:
        frameworks.append("Yii")
    if "codeigniter" in powered or "ci_session" in cookies:
        frameworks.append("CodeIgniter")

    # Python
    if "django" in powered or "csrftoken" in cookies or "django" in html_lower:
        frameworks.append("Django")
    if "flask" in powered or "flask" in html_lower:
        frameworks.append("Flask")
    if "werkzeug" in powered:
        frameworks.append("Werkzeug")
    if "fastapi" in html_lower or "x-fastapi" in powered:
        frameworks.append("FastAPI")

    # Node.js
    if "express" in powered or "express" in server:
        frameworks.append("Express.js")
    if "koa" in powered or "koa" in html_lower:
        frameworks.append("Koa.js")
    if "nestjs" in powered or "nestjs" in html_lower:
        frameworks.append("NestJS")

    # Ruby
    if "rails" in powered or "_rails" in cookies or "ruby on rails" in html_lower:
        frameworks.append("Ruby on Rails")

    # Java
    if "spring" in powered or "spring" in html_lower:
        frameworks.append("Spring Boot")
    if "jsp" in html_lower or "jsessionid" in cookies:
        frameworks.append("Java/JSP")

    # .NET
    if "asp.net" in powered or "asp.net" in server:
        frameworks.append("ASP.NET")
    if "x-aspnet-version" in headers:
        frameworks.append("ASP.NET")

    # Go
    if "go" in powered or "golang" in server:
        frameworks.append("Go HTTP Server")

    # Rust
    if "actix" in powered:
        frameworks.append("Actix Web")
    if "rocket" in powered:
        frameworks.append("Rocket")

    return frameworks or None


def detect_server(headers: dict):
    server = headers.get("Server", "").lower()
    powered = headers.get("X-Powered-By", "").lower()

    if not server and not powered:
        return None

    if "nginx" in server:
        return "Nginx"
    if "apache" in server or "apache" in powered:
        return "Apache"
    if "litespeed" in server:
        return "LiteSpeed"
    if "iis" in server or "asp.net" in powered:
        return "Microsoft IIS"
    if "caddy" in server:
        return "Caddy"
    if "cloudflare" in server:
        return "Cloudflare Edge"
    if "openresty" in server:
        return "OpenResty (Nginx)"
    if "gunicorn" in server:
        return "Gunicorn (Python)"
    if "uwsgi" in server:
        return "uWSGI (Python)"
    if "node" in server:
        return "Node.js HTTP Server"

    return server or None


# === Часть 6: deep_crawl ===

def deep_crawl(url: str, config: dict) -> dict:
    result: dict[str, Any] = {
        "visited": set(),
        "scripts": set(),
        "api_endpoints": set(),
        "emails": set(),
        "tokens": set(),
        "user_ids": set(),
        "js_insights": {},
        "phones": set(),
        "ips": set(),
        "ipv6": set(),
        "mac": set(),
        "cidr": set(),
        "hostnames": set(),
        "parameters": set(),
        "base64_strings": set(),
        "uuids": set(),
        "hashes": set(),
        "api_keys": set(),
        "jwt_tokens": set(),
        "credit_cards": set(),
        "ssn": set(),
        "passwords": set(),
        "secrets": set(),
        "graphql": set(),
        "errors": []
    }

    result["meta"] = {
        "target_url": url,
        "user_agent": config.get("user_agent", "Mozilla/5.0"),
        "timestamp": dt.datetime.now().isoformat()
    }

    ua = config.get("user_agent", "Mozilla/5.0")
    proxy = config.get("proxy", None)
    delay = config.get("delay", 1.0)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(user_agent=ua, proxy=proxy)
        page = context.new_page()

        if "login" in config:
            perform_login(page, config["login"])

        try:
            page.goto(url, timeout=15000)
            page.wait_for_timeout(delay * 1000)

            # Ссылки
            for a in page.query_selector_all("a[href]"):
                href = a.get_attribute("href")
                if href:
                    result["visited"].add(urljoin(url, href))

            # Формы
            for f in page.query_selector_all("form"):
                act = f.get_attribute("action")
                if act:
                    result["visited"].add(urljoin(url, act))

            # Скрипты
            for s in page.query_selector_all("script[src]"):
                src = s.get_attribute("src")
                if not src:
                    continue

                full_url = urljoin(url, src)
                result["scripts"].add(full_url)

                try:
                    js_resp = requests.get(full_url, timeout=5)
                    if js_resp.status_code == 200 and "javascript" in js_resp.headers.get("Content-Type", ""):
                        js_text = js_resp.text
                        insights = extract_js_insights(js_text)
                        result["js_insights"][full_url] = insights

                        result["api_endpoints"].update(insights.get("fetch_calls", []))
                        result["api_endpoints"].update(insights.get("ajax_calls", []))

                        if any("/graphql" in u for u in insights.get("fetch_calls", [])):
                            result["graphql"].add("/graphql")

                        js_sensitive = extract_sensitive_data(js_text)
                        for k, v in js_sensitive.items():
                            if k in result:
                                result[k].update(v)

                except Exception as e:
                    result["errors"].append(f"JS fetch error {full_url}: {e}")

            # Inline JS
            for s in page.query_selector_all("script"):
                if s.get_attribute("src"):
                    continue

                js_text = s.inner_text()
                if not js_text:
                    continue

                key = f"[INLINE_{len(result['js_insights'])}]"
                insights = extract_js_insights(js_text)
                result["js_insights"][key] = insights

                result["api_endpoints"].update(insights.get("fetch_calls", []))
                result["api_endpoints"].update(insights.get("ajax_calls", []))

                if any("/graphql" in u for u in insights.get("fetch_calls", [])):
                    result["graphql"].add("/graphql")

                js_sensitive = extract_sensitive_data(js_text)
                for k, v in js_sensitive.items():
                    if k in result:
                        result[k].update(v)

            # HTML
            content = page.content()
            html_sensitive = extract_sensitive_data(content)
            for k, v in html_sensitive.items():
                if k in result:
                    result[k].update(v)

            result["emails"].update(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", content))
            result["tokens"].update(re.findall(r"[A-Za-z0-9-_]{20,}", content))
            result["user_ids"].update(re.findall(r"user[_-]?id[\"':= ]+([0-9a-zA-Z]+)", content))

            # Параметры URL
            for u in result["visited"]:
                parsed = urlparse(u)
                qs = parse_qs(parsed.query)
                for k in qs:
                    result["parameters"].add(k)

        except Exception as e:
            result["errors"].append(f"deep_crawl error: {e}")

        browser.close()

    # Приведение множеств к спискам
    for k in list(result.keys()):
        if isinstance(result[k], set):
            result[k] = list(result[k])

    # Проверка js_insights
    for k, v in result.get("js_insights", {}).items():
        if not isinstance(v, dict):
            result["js_insights"][k] = {}

    # Статистика
    result["stats"] = {
        "total_links": len(result["visited"]),
        "total_scripts": len(result["scripts"]),
        "total_api_endpoints": len(result["api_endpoints"]),
        "total_sensitive_items": sum(
            len(v) for k, v in result.items()
            if isinstance(v, list) and k not in ("visited", "scripts", "js_insights")
        ),
        "errors_count": len(result["errors"])
    }

    return result


# === Часть 7–8: deep_crawl_site + summary ===

def deep_crawl_site(url: str) -> dict:
    """
    Глубокий анализ сайта после Playwright‑краулинга.
    """
    config = {
        "user_agent": "Mozilla/5.0 (XSS-Scanner)",
        "delay": 1.5,
        "login": {
            "url": url.rstrip("/") + "/login",
            "username": "admin",
            "password": "admin123",
            "selectors": {
                "username": "#username",
                "password": "#password",
                "submit": "button[type='submit']",
            },
        },
    }

    print(f"[🧬] Запуск глубокого анализа: {url}")
    raw = deep_crawl(url, config)

    visited = raw.get("visited", []) or []
    all_tokens = raw.get("tokens", {})
    all_user_ids = raw.get("user_ids", {})
    all_api_endpoints = raw.get("api_endpoints", {})
    all_js_insights = raw.get("js_insights", {})
    all_scripts = raw.get("scripts", []) or []
    all_errors = raw.get("errors", []) or []

    pages: list[dict] = []

    for u in visited:
        try:
            resp = requests.get(u, timeout=7)
            html = resp.text
            headers = resp.headers
            status_code = resp.status_code
        except Exception as e:
            resp = None
            html = ""
            headers = {}
            status_code = None
            all_errors.append(f"Page fetch error {u}: {e}")

        if isinstance(all_tokens, dict):
            page_tokens = all_tokens.get(u, []) or []
        else:
            page_tokens = all_tokens or []

        if isinstance(all_user_ids, dict):
            page_user_ids = all_user_ids.get(u, []) or []
        else:
            page_user_ids = all_user_ids or []

        if isinstance(all_api_endpoints, dict):
            page_api_endpoints = all_api_endpoints.get(u, []) or []
        else:
            page_api_endpoints = all_api_endpoints or []

        if isinstance(all_js_insights, dict):
            page_js_insights = all_js_insights.get(u, {}) or {}
        else:
            page_js_insights = {}

        cms = detect_cms(
            html,
            headers=headers,
            cookies=list(resp.cookies.get_dict().items()) if resp else [],
            url=u
        )
        frameworks = detect_frameworks(html)
        adaptive = is_adaptive(html)
        csp_info = analyze_csp(headers)
        backend = detect_backend_framework(headers, html)
        server = detect_server(headers)

        og_data = extract_opengraph(html)
        json_ld = extract_json_ld(html)
        meta_tags = extract_meta_tags(html)

        risk_score = calculate_page_risk(
            csp_info=csp_info,
            tokens=page_tokens,
            user_ids=page_user_ids,
            api_endpoints=page_api_endpoints,
            frameworks=frameworks,
            cms=cms,
        )

        graphql_hits: List[str] = []
        if "/graphql" in u:
            graphql_hits.append(u)
        for ep in page_api_endpoints:
            if "graphql" in ep.lower():
                graphql_hits.append(ep)

        content_score = len(page_tokens) + len(page_user_ids)

        pages.append({
            "url": u,
            "status_code": status_code,
            "content_length": len(html),

            "cms": cms,
            "frameworks": frameworks,
            "backend_framework": backend,
            "server": server,
            "adaptive": adaptive,
            "tech_stack": {
                "cms": cms,
                "frontend_frameworks": frameworks,
                "backend_framework": backend,
                "server": server,
                "js_libraries": page_js_insights.get("libraries", []),
                "ui_components": page_js_insights.get("ui_components", []),
            },

            "headers": dict(headers),
            "csp_analysis": csp_info,
            "risk_score": risk_score,
            "content_score": content_score,
            "security_flags": {
                "has_tokens": bool(page_tokens),
                "has_user_ids": bool(page_user_ids),
                "has_graphql": bool(graphql_hits),
                "weak_csp": csp_info.get("risk_level") == "weak",
                "no_csp": csp_info.get("risk_level") == "none",
                "unsafe_inline": csp_info.get("unsafe_inline", False),
                "cookies": page_js_insights.get("cookies", []),
                "local_storage": page_js_insights.get("local_storage", []),
                "session_storage": page_js_insights.get("session_storage", []),
                "dangerous_js_calls": page_js_insights.get("dangerous_calls", []),
            },

            "api_endpoints": page_api_endpoints,
            "tokens": page_tokens,
            "user_ids": page_user_ids,
            "graphql": graphql_hits,
            "js_insights": page_js_insights,

            "opengraph": og_data,
            "json_ld": json_ld,
            "meta_tags": meta_tags,
            "title": re.search(r"<title>(.*?)</title>", html, re.I).group(1)
            if re.search(r"<title>(.*?)</title>", html, re.I) else "",
            "description": next(
                (m[1] for m in re.findall(r'<meta name="description" content="([^"]+)"', html, re.I)),
                ""
            ),

            "word_count": len(re.findall(r"\w+", html)),
            "script_count": len(re.findall(r"<script", html, re.I)),
            "form_count": len(re.findall(r"<form", html, re.I)),
            "input_fields": re.findall(r'<input[^>]+name="([^"]+)"', html, re.I),
            "links": re.findall(r'href="([^"]+)"', html, re.I),
            "images": re.findall(r'<img[^>]+src="([^"]+)"', html, re.I),

            "is_login_page": bool(re.search(r"(login|signin)", u, re.I)),
            "is_admin_page": bool(re.search(r"(admin|dashboard)", u, re.I)),
            "is_api_page": u.endswith(".json") or "/api/" in u,
            "is_static_asset": any(u.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".svg"]),

            "response_time_ms": resp.elapsed.total_seconds() * 1000 if resp else None,
            "content_type": headers.get("Content-Type", ""),

            "sourcemaps": [],
            "initial_state": [],
            "raw_html_snippet": html[:5000],
        })

    summary = {
        "total_pages": len(pages),
        "total_errors": len(all_errors),
        "total_scripts": len(all_scripts),

        "total_api_endpoints": sum(len(v) for v in all_api_endpoints.values())
        if isinstance(all_api_endpoints, dict) else len(all_api_endpoints or []),
        "unique_api_endpoints": list({ep for lst in all_api_endpoints.values() for ep in lst})
        if isinstance(all_api_endpoints, dict) else all_api_endpoints,

        "total_tokens": sum(len(v) for v in all_tokens.values())
        if isinstance(all_tokens, dict) else len(all_tokens or []),
        "unique_tokens": list({t for lst in all_tokens.values() for t in lst})
        if isinstance(all_tokens, dict) else all_tokens,

        "total_user_ids": sum(len(v) for v in all_user_ids.values())
        if isinstance(all_user_ids, dict) else len(all_user_ids or []),
        "unique_user_ids": list({u for lst in all_user_ids.values() for u in lst})
        if isinstance(all_user_ids, dict) else all_user_ids,

        "graphql_endpoints": list({
            ep for page in pages for ep in page.get("graphql", [])
        }),
        "total_graphql_pages": sum(1 for p in pages if p.get("graphql")),

        "cms_usage": list({
            p.get("cms") for p in pages if p.get("cms")
        }),
        "frameworks_usage": list({
            fw for p in pages for fw in (p.get("frameworks") or [])
        }),
        "backend_frameworks_usage": list({
            p.get("backend_framework") for p in pages if p.get("backend_framework")
        }),

        "servers_detected": list({
            p.get("server") for p in pages if p.get("server")
        }),

        "csp_levels": {
            "none": sum(1 for p in pages if p.get("csp_analysis", {}).get("risk_level") == "none"),
            "weak": sum(1 for p in pages if p.get("csp_analysis", {}).get("risk_level") == "weak"),
            "strict": sum(1 for p in pages if p.get("csp_analysis", {}).get("risk_level") == "strict"),
        },

        "adaptive_pages": sum(1 for p in pages if p.get("adaptive")),
        "non_adaptive_pages": sum(1 for p in pages if not p.get("adaptive")),

        "max_risk_score": max((p.get("risk_score") or 0) for p in pages) if pages else 0,
        "min_risk_score": min((p.get("risk_score") or 0) for p in pages) if pages else 0,
        "avg_risk_score": round(
            sum((p.get("risk_score") or 0) for p in pages) / max(len(pages), 1), 2
        ),

        "total_content_length": sum(p.get("content_length") or 0 for p in pages),
        "avg_content_length": round(
            sum(p.get("content_length") or 0 for p in pages) / max(len(pages), 1), 2
        ),

        "pages_with_opengraph": sum(1 for p in pages if p.get("opengraph")),
        "pages_with_json_ld": sum(1 for p in pages if p.get("json_ld")),

        "pages_with_js_insights": sum(1 for p in pages if p.get("js_insights")),
        "unique_js_libraries": list({
            lib for p in pages for lib in (p.get("js_insights", {}).get("libraries") or [])
        }),

        "pages_with_meta_tags": sum(1 for p in pages if p.get("meta_tags")),
    }

    result = {
        "pages": pages,
        "summary": summary,
        "raw": raw
    }

    os.makedirs(LOGS_DIR, exist_ok=True)

    with open(os.path.join(LOGS_DIR, "deep_crawl.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    with open(os.path.join(LOGS_DIR, "deep_pages.json"), "w", encoding="utf-8") as f:
        json.dump(pages, f, indent=2, ensure_ascii=False)

    return result


# ============================
# 🛡️ CSP анализ
# ============================

def analyze_csp(headers: dict) -> dict:
    csp = headers.get("Content-Security-Policy", "") or ""
    csp_lower = csp.lower()

    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        if " " in part:
            key, val = part.split(" ", 1)
            directives[key] = val.split()
        else:
            directives[part] = []

    dangerous_sources: list[tuple[str, str]] = []
    for key, values in directives.items():
        for v in values:
            if v in ("*", "data:", "blob:", "filesystem:", "http:"):
                dangerous_sources.append((key, v))

    has_nonce = "'nonce-" in csp_lower
    has_hash = "'sha256-" in csp_lower or "'sha384-" in csp_lower or "'sha512-" in csp_lower
    strict_dynamic = "'strict-dynamic'" in csp_lower
    unsafe_inline = "unsafe-inline" in csp_lower
    unsafe_eval = "unsafe-eval" in csp_lower
    trusted_types = "trusted-types" in csp_lower
    upgrade_insecure = "upgrade-insecure-requests" in csp_lower
    frame_ancestors = directives.get("frame-ancestors", [])
    report_uris = re.findall(r"(?:report-uri|report-to)\s+([^;]+)", csp)

    def classify_csp() -> str:
        if not csp.strip():
            return "none"
        if unsafe_inline or unsafe_eval:
            return "weak"
        if strict_dynamic or has_nonce or has_hash:
            return "strong"
        if "*" in csp:
            return "weak"
        return "moderate"

    risk_level = classify_csp()

    return {
        "raw": csp,
        "directives": directives,
        "risk_level": risk_level,
        "unsafe_inline": unsafe_inline,
        "unsafe_eval": unsafe_eval,
        "dangerous_sources": dangerous_sources,
        "strict_dynamic": strict_dynamic,
        "has_nonce": has_nonce,
        "has_hash": has_hash,
        "trusted_types": trusted_types,
        "upgrade_insecure_requests": upgrade_insecure,
        "frame_ancestors": frame_ancestors,
        "report_uris": report_uris,
        "summary": {
            "strong": risk_level == "strong",
            "moderate": risk_level == "moderate",
            "weak": risk_level == "weak",
            "missing": risk_level == "none"
        }
    }

# ============================
# OpenGraph / JSON-LD / Meta
# ============================

def extract_opengraph(html: str) -> dict:
    og: dict[str, str] = {}
    for prop, content in re.findall(r'<meta property="og:([^"]+)" content="([^"]+)"', html, re.I):
        og[prop] = content
    return og


def extract_json_ld(html: str) -> list:
    blocks = re.findall(r'<script type="application/ld\+json">(.*?)</script>', html, re.S)
    parsed: list[Any] = []
    for block in blocks:
        try:
            parsed.append(json.loads(block))
        except Exception:
            pass
    return parsed


def extract_meta_tags(html: str) -> list:
    tags = re.findall(r'<meta\s+([^>]+)>', html, re.I)
    return tags


def calculate_page_risk(
    csp_info: dict,
    tokens: list,
    user_ids: list,
    api_endpoints: list,
    frameworks: list,
    cms: list | None
) -> int:
    score = 0

    if csp_info.get("risk_level") == "weak":
        score += 30
    if csp_info.get("risk_level") == "none":
        score += 50

    score += len(tokens) * 2
    score += len(user_ids) * 3
    score += len(api_endpoints) * 1

    if frameworks:
        score += 5

    if cms:
        score += 5

    return min(score, 100)


# ============================
# 📱 Адаптивность
# ============================

def is_adaptive(html: str) -> bool:
    """
    Проверяет, содержит ли HTML признаки адаптивного дизайна.
    """
    html_lower = html.lower()

    keywords = [
        "viewport",
        "@media",
        "mobile",
        "device-width",
        "responsive",
        "srcset=",
        "sizes=",
        "flex",
        "grid-template",
        "bootstrap",
        "tailwind",
        "foundation",
        "mui",
        "ant-design"
    ]

    return any(keyword in html_lower for keyword in keywords)