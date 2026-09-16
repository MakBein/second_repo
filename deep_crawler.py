# xss_security_gui/deep_crawler.py

import os
import queue
import re
import json
import logging
import traceback
import time
import datetime as dt
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime, UTC

import requests
from playwright.sync_api import sync_playwright

from xss_security_gui.js_inspector import extract_js_insights
from xss_security_gui.crawler import extract_sensitive_data
from xss_security_gui.settings import LOG_DIR
from xss_security_gui.auth.login_flow import perform_login


# Глобальная очередь для Live Monitor
LIVE_MONITOR_QUEUE: "queue.Queue[dict]" = queue.Queue()

# Используем единую лог‑директорию из settings.py
LOGS_DIR = str(LOG_DIR)
os.makedirs(LOGS_DIR, exist_ok=True)

# ============================================================
#  ENTERPRISE‑GRADE LOGGING 7.0 (Burp/ZAP‑style)
# ============================================================

LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] [%(threadName)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt=DATE_FORMAT,
)

logger = logging.getLogger("DeepCrawler7")
logger.setLevel(logging.INFO)


def _write_gui_log(filename: str, prefix: str, msg: str, extra: Dict[str, Any] | None = None) -> None:
    """
    Вспомогательная функция для записи в GUI‑логи (enterprise‑уровень).

    Особенности:
    - единая директория LOGS_DIR
    - ISO‑timestamp (UTC)
    - структурированный JSON‑блок для парсинга (Burp/ZAP‑style)
    - безопасна к исключениям (не ломает основной поток)
    """
    try:
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        path = os.path.join(LOGS_DIR, filename)

        payload = {
            "ts": timestamp,
            "prefix": prefix,
            "message": msg,
            "extra": extra or {},
        }

        line = f"[{timestamp}] {prefix} {msg}"
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            # JSON‑блок для машинного анализа
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        # Логирование не должно ломать краулер
        logging.getLogger("DeepCrawler7").debug("Failed to write GUI log", exc_info=True)


# ============================================================
#  INFO
# ============================================================

def log_info(msg: str, context: Dict[str, Any] | None = None) -> None:
    """
    Пишет информационное сообщение:
    • в стандартный логгер (Burp/ZAP‑style формат)
    • в logs/info_log.txt (читаемый + JSON)
    """
    logger.info(msg)
    _write_gui_log("info_log.txt", "ℹ️ INFO:", msg, extra=context)


# ============================================================
#  WARNING
# ============================================================

def log_warn(msg: str, context: Dict[str, Any] | None = None) -> None:
    """
    Пишет предупреждение:
    • в стандартный логгер
    • в logs/warn_log.txt
    • добавляет контекст (URL, модуль, шаг краулинга)
    """
    logger.warning(msg)
    _write_gui_log("warn_log.txt", "⚠️ WARNING:", msg, extra=context)


# ============================================================
#  ERROR
# ============================================================

def log_error(msg: str, exc: Exception | None = None, context: Dict[str, Any] | None = None) -> None:
    """
    Пишет ошибку:
    • в стандартный логгер
    • в logs/error_log.txt
    • сохраняет traceback
    • добавляет контекст (URL, модуль, шаг, severity)

    Формат JSON‑блока:
    {
      "ts": "...",
      "prefix": "❌ ERROR:",
      "message": "...",
      "extra": {
        "exception_type": "...",
        "exception_message": "...",
        "traceback": "...",
        "context": {...}
      }
    }
    """
    logger.error(msg, exc_info=bool(exc))

    try:
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        path = os.path.join(LOGS_DIR, "error_log.txt")

        tb_str = traceback.format_exc() if exc else ""

        payload = {
            "ts": timestamp,
            "prefix": "❌ ERROR:",
            "message": msg,
            "extra": {
                "exception_type": type(exc).__name__ if exc else None,
                "exception_message": str(exc) if exc else None,
                "traceback": tb_str,
                "context": context or {},
            },
        }

        with open(path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] ❌ ERROR: {msg}\n")
            if exc:
                f.write(f"{type(exc).__name__}: {str(exc)}\n")
                f.write(tb_str + "\n")
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        logging.getLogger("DeepCrawler7").debug("Failed to write error log", exc_info=True)

def detect_logout_url(page):
    """
    Logout Detector 12.0 OMNI‑MODE
    Рівень Burp Suite / OWASP ZAP:
    - HTML <a>, <button>, <form>
    - SPA (React/Angular/Vue/Next.js)
    - JS handlers (onclick, addEventListener)
    - JS code (fetch/axios/XMLHttpRequest)
    - Meta refresh
    - Hidden API endpoints
    - Heuristic scoring
    """

    candidates: set[str] = set()
    html = (page.content() or "").lower()
    url = page.url

    # ============================================================
    # 1) <a href="..."> logout
    # ============================================================
    for a in page.query_selector_all("a[href]"):
        href = (a.get_attribute("href") or "").strip()
        text = (a.inner_text() or "").lower()

        if any(k in text for k in ("logout", "sign out", "log out", "выход")):
            candidates.add(href)

        if "logout" in href.lower():
            candidates.add(href)

    # ============================================================
    # 2) <button> logout
    # ============================================================
    for b in page.query_selector_all("button"):
        text = (b.inner_text() or "").lower()
        onclick = (b.get_attribute("onclick") or "").lower()

        if any(k in text for k in ("logout", "sign out", "выход")):
            candidates.add(url)

        if "logout" in onclick:
            candidates.add(url)

    # ============================================================
    # 3) <form action="..."> logout
    # ============================================================
    for f in page.query_selector_all("form[action]"):
        action = (f.get_attribute("action") or "").lower()
        if "logout" in action:
            candidates.add(action)

    # ============================================================
    # 4) Meta refresh logout
    # ============================================================
    meta_refresh = re.findall(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\']\d+;\s*url=([^"\']+)', html)
    for m in meta_refresh:
        if "logout" in m:
            candidates.add(m)

    # ============================================================
    # 5) SPA logout (React/Angular/Vue/Next.js)
    # ============================================================
    spa_patterns = [
        "#/logout",
        "/#/logout",
        "/logout",
        "logout()",
        "router.push('/logout')",
        "router.navigate('/logout')",
        "navigate('/logout')",
        "window.location='/logout'",
        "window.location.href='/logout'",
    ]

    for p in spa_patterns:
        if p.lower() in html:
            # normalize "#/logout" → "/logout"
            candidates.add(p.replace("#", "").replace("()", "").strip())

    # ============================================================
    # 6) JS handlers (onclick, addEventListener)
    # ============================================================
    js_handlers = re.findall(r'onclick=["\']([^"\']+)["\']', html)
    for h in js_handlers:
        if "logout" in h.lower():
            candidates.add(url)

    add_event = re.findall(r'addEventListener\(\s*["\']click["\'],\s*(\w+)\)', html)
    for fn in add_event:
        # search function body
        fn_body = re.findall(rf'function\s+{fn}\s*\([^)]*\)\s*\{{([^}}]+)\}}', html)
        for body in fn_body:
            if "logout" in body.lower():
                candidates.add(url)

    # ============================================================
    # 7) JS code: fetch("/logout"), axios.post("/logout"), xhr.open("POST","/logout")
    # ============================================================
    js_patterns = [
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.(get|post|delete)\(["\']([^"\']+)["\']',
        r'xhr\.open\([^)]*["\']([^"\']+)["\']',
    ]

    for pattern in js_patterns:
        for match in re.findall(pattern, html):
            # match may be tuple → extract last element
            url_candidate = match[-1].lower()
            if "logout" in url_candidate:
                candidates.add(url_candidate)

    # ============================================================
    # 8) Hidden API endpoints
    # ============================================================
    api_patterns = [
        "/api/logout",
        "/auth/logout",
        "/user/logout",
        "/session/logout",
        "/v1/logout",
        "/v2/logout",
        "/logout",
    ]

    for p in api_patterns:
        if p in html:
            candidates.add(p)

    # ============================================================
    # 9) Heuristic scoring (Burp‑style)
    # ============================================================
    scored = {}

    for c in candidates:
        score = 0
        cl = c.lower()

        if "logout" in cl:
            score += 10
        if cl.startswith("/"):
            score += 3
        if cl.startswith("http"):
            score += 2
        if any(k in cl for k in ("auth", "session", "user")):
            score += 4
        if cl.endswith(("logout", "/logout")):
            score += 5

        scored[c] = score

    # sort by score desc
    final = sorted(scored.keys(), key=lambda x: scored[x], reverse=True)

    return final or None

# === Часть 4: CMS / Framework detection ===

def detect_cms(
    html: str,
    headers: Optional[Dict[str, Any]] = None,
    cookies: Optional[List[Any]] = None,
    url: str = "",
) -> Optional[List[str]]:
    """
    Robust CMS / framework detector (Burp‑level stability):

    - Never crashes on malformed cookies / headers / HTML
    - Accepts cookies as:
        * list[dict]
        * RequestsCookieJar
        * list[tuple]
        * any iterable
    - Works even if headers / cookies / url are None or unexpected types
    """

    # --- Defensive normalization ---
    html_lower = str(html or "").lower()
    headers = headers or {}
    cookies = cookies or []
    url_lower = str(url or "").lower()

    detected: Set[str] = set()

    # ============================================================
    # 1) Meta generator
    # ============================================================
    try:
        meta_gen = re.findall(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            html_lower,
        )
    except Exception:
        meta_gen = []

    for gen in meta_gen:
        g = gen.lower()
        if "wordpress" in g:
            detected.add("WordPress")
        if "drupal" in g:
            detected.add("Drupal")
        if "joomla" in g:
            detected.add("Joomla")
        if "ghost" in g:
            detected.add("Ghost")
        if "typo3" in g:
            detected.add("TYPO3")

    # ============================================================
    # 2) Cookies (robust normalization)
    # ============================================================
    normalized: List[Dict[str, str]] = []

    try:
        for c in cookies:
            # Case 1: already dict
            if isinstance(c, dict):
                name = str(c.get("name", "")).lower()
                normalized.append({"name": name})
                continue

            # Case 2: RequestsCookieJar Cookie object
            if hasattr(c, "name"):
                name = str(getattr(c, "name", "")).lower()
                normalized.append({"name": name})
                continue

            # Case 3: tuple ("name", "value") or ("name", ...)
            if isinstance(c, tuple) and len(c) >= 1:
                name = str(c[0]).lower()
                normalized.append({"name": name})
                continue

            # Fallback: anything else → string
            name = str(c).lower()
            normalized.append({"name": name})
    except Exception:
        # If cookies are completely broken, just ignore them
        normalized = []

    cookie_names = [c.get("name", "") for c in normalized]

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

    # ============================================================
    # 3) HTTP headers (defensive)
    # ============================================================
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
        try:
            val = str(headers.get(hname, "")).lower()
        except Exception:
            val = ""
        for key, cms in patterns.items():
            if key in val:
                detected.add(cms)

    # ============================================================
    # 4) URL patterns
    # ============================================================
    url_patterns = {
        # ============================================================
        # Classic CMS
        # ============================================================
        "/wp-json": "WordPress",
        "/wp-content": "WordPress",
        "/wp-admin": "WordPress",
        "/wp-includes": "WordPress",

        "/sites/default/files": "Drupal",
        "/drupal.js": "Drupal",
        "/drupal-settings-json": "Drupal",

        "/ghost/api": "Ghost",
        "/ghost/content": "Ghost",

        "/index.php?route=": "OpenCart",
        "/ocstore/": "OpenCart",

        "/bitrix/": "1C-Bitrix",
        "/bitrix/admin": "1C-Bitrix",
        "/bitrix/templates": "1C-Bitrix",

        "/umbraco": "Umbraco",
        "/umbraco/api": "Umbraco",

        "/typo3/": "TYPO3",
        "/typo3conf/": "TYPO3",

        "/joomla/": "Joomla",
        "/com_content": "Joomla",

        # ============================================================
        # E‑commerce platforms
        # ============================================================
        "/shopify/": "Shopify",
        "/cdn.shopify.com": "Shopify",
        "/shopify-checkout": "Shopify",

        "/magento/": "Magento",
        "/mage-cache": "Magento",
        "/x-magento-init": "Magento",

        "/prestashop/": "PrestaShop",
        "/ps_module/": "PrestaShop",

        "/woocommerce/": "WooCommerce",

        "/bigcommerce/": "BigCommerce",

        "/saleor/": "Saleor",

        # ============================================================
        # Headless CMS (Enterprise-grade)
        # ============================================================

        # Contentful
        "/contentful/": "Contentful",
        "/cdn.contentful.com": "Contentful",

        # Sanity
        "/sanity/": "Sanity",
        "/cdn.sanity.io": "Sanity",

        # Strapi
        "/strapi/": "Strapi",
        "/strapi-api": "Strapi",

        # Prismic
        "/prismic/": "Prismic",
        "/cdn.prismic.io": "Prismic",

        # Storyblok
        "/storyblok/": "Storyblok",
        "/cdn.storyblok.com": "Storyblok",

        # Hygraph (GraphCMS)
        "/hygraph/": "Hygraph",
        "/graphcms/": "Hygraph",
        "/graphql/hygraph": "Hygraph",

        # Directus
        "/directus/": "Directus",
        "/directus/api": "Directus",

        # ButterCMS
        "/buttercms/": "ButterCMS",

        # NetlifyCMS
        "/admin/#/collections": "NetlifyCMS",
        "/admin/#/workflow": "NetlifyCMS",

        # PayloadCMS
        "/payload/": "PayloadCMS",
        "/payload/api": "PayloadCMS",

        # KeystoneJS
        "/keystone/": "KeystoneJS",
        "/keystone-api": "KeystoneJS",

        # TinaCMS
        "/tina/": "TinaCMS",

        # DatoCMS
        "/datocms/": "DatoCMS",
        "/graphql/datocms": "DatoCMS",

        # Magnolia Headless
        "/magnolia/": "Magnolia",
        "/magnolia-headless": "Magnolia",

        # Bloomreach
        "/bloomreach/": "Bloomreach",
        "/brxm/": "Bloomreach",

        # Kentico Kontent
        "/kontent/": "Kentico",
        "/kontent.ai": "Kentico",

        # Umbraco Heartcore
        "/heartcore/": "Umbraco Heartcore",

        # Adobe Experience Manager (AEM Headless)
        "/aem/": "AEM",
        "/aem-headless": "AEM",
        "/content/dam": "AEM",

        # Sitecore Headless
        "/sitecore/": "Sitecore",
        "/sitecore/api": "Sitecore",
        "/sitecore-headless": "Sitecore",

        # ============================================================
        # Static site generators (SSG)
        # ============================================================
        "/_next/": "Next.js",
        "/_nuxt/": "Nuxt.js",
        "/svelte-kit/": "SvelteKit",
        "/gatsby/": "Gatsby",
        "/eleventy/": "Eleventy",

        # ============================================================
        # Framework-specific API routes
        # ============================================================
        "/api/auth/": "NextAuth",
        "/api/graphql": "GraphQL",
        "/graphql": "GraphQL",
        "/api/v1/": "Generic API",
        "/api/v2/": "Generic API",

        # ============================================================
        # Government / enterprise CMS
        # ============================================================
        "/plone/": "Plone",
        "/ezpublish/": "eZ Publish",
        "/liferay/": "Liferay",
        "/sharepoint/": "SharePoint",
        "/alfresco/": "Alfresco",
    }

    for pattern, cms in url_patterns.items():
        if pattern in url_lower:
            detected.add(cms)

    # ============================================================
    # 5) HTML signatures
    # ============================================================
    cms_signatures = {
        # Classic CMS
        "WordPress": ["wp-content", "wp-includes", "wp-json", "wp-admin"],
        "Drupal": ["drupal.js", "drupal-settings-json"],
        "Joomla": ["joomla.js", "com_content"],
        "Magento": ["mage", "x-magento-init"],
        "Shopify": ["cdn.shopify.com", "shopify-checkout"],
        "1C-Bitrix": ["bitrix", "bx.core"],
        "OpenCart": ["opencart", "ocstore"],
        "Ghost": ["ghost-sdk", "ghost-content-api"],
        "Strapi": ["strapi", "strapi.io", "strapi-cloud"],
        "Webflow": ["webflow"],
        "Wix": ["wix.com", "wixstatic"],
        "Squarespace": ["squarespace"],
        "MODX": ["modx"],
        "TYPO3": ["typo3"],

        # ============================================================
        # Headless CMS (Enterprise-grade)
        # ============================================================

        # Contentful
        "Contentful": [
            "contentful.com",
            "cdn.contentful.com",
            "contentful-delivery",
            "contentful-management",
            "contentful-preview",
        ],

        # Sanity.io
        "Sanity": [
            "sanity.io",
            "cdn.sanity.io",
            "sanityClient",
            "sanityConfig",
            "sanityImage",
        ],

        # Prismic
        "Prismic": [
            "prismic.io",
            "cdn.prismic.io",
            "prismic-javascript",
            "prismic-dom",
            "prismic-react",
        ],

        # Storyblok
        "Storyblok": [
            "storyblok.com",
            "cdn.storyblok.com",
            "storyblok-js-client",
            "storyblokBridge",
        ],

        # Hygraph (GraphCMS)
        "Hygraph": [
            "hygraph.com",
            "graphcms.com",
            "hygraphapi",
            "graphcmsapi",
            "graphql-hygraph",
        ],

        # Directus
        "Directus": [
            "directus.io",
            "directus-sdk",
            "directus-api",
            "directus-data",
        ],

        # ButterCMS
        "ButterCMS": [
            "buttercms.com",
            "api.buttercms.com",
            "butter.init",
            "butterCMS",
        ],

        # NetlifyCMS
        "NetlifyCMS": [
            "netlifycms",
            "netlify-cms",
            "netlifyIdentity",
            "netlifyCmsApp",
        ],

        # PayloadCMS
        "PayloadCMS": [
            "payloadcms.com",
            "payload.config",
            "payload.init",
            "payload-api",
        ],

        # KeystoneJS
        "KeystoneJS": [
            "keystonejs",
            "keystone-6",
            "keystone-api",
            "keystone-next",
        ],

        # TinaCMS
        "TinaCMS": [
            "tinacms",
            "tina.io",
            "tina-cloud",
            "tina-git",
        ],

        # DatoCMS
        "DatoCMS": [
            "datocms.com",
            "graphql.datocms.com",
            "datocms-client",
        ],

        # Magnolia Headless
        "Magnolia": [
            "magnolia-cms",
            "magnolia-headless",
            "magnolia-api",
        ],

        # Bloomreach
        "Bloomreach": [
            "bloomreach",
            "brxm",
            "hippo-cms",
            "bloomreach-experience",
        ],

        # Kentico Kontent
        "Kentico": [
            "kontent.ai",
            "kentico-kontent",
            "kontent-delivery",
        ],

        # Umbraco Heartcore (Headless)
        "Umbraco Heartcore": [
            "umbraco.io",
            "heartcore",
            "umbraco-cloud",
        ],

        # Adobe Experience Manager (AEM Headless)
        "AEM": [
            "adobeaemcloud",
            "aemheadless",
            "aem-delivery",
            "aem-content",
        ],

        # Sitecore Headless
        "Sitecore": [
            "sitecore",
            "sitecore-headless",
            "sitecore-jss",
            "sitecore-experience",
        ],
    }

    for cms, signs in cms_signatures.items():
        try:
            if any(sig in html_lower for sig in signs):
                detected.add(cms)
        except Exception:
            # If html is weird, just skip signatures
            continue

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

def _safe_goto(page, url: str, timeout_ms: int, wait_until: str) -> bool:
    try:
        page.goto(url, timeout=timeout_ms, wait_until=wait_until)
        return True
    except Exception as e:
        log_warn(f"Navigation failed ({wait_until}): {e}", {"url": url, "wait_until": wait_until})
        return False


def deep_crawl(url: str, config: dict) -> dict:
    """
    Глубокий краулинг сайта с Playwright — OMNI‑MODE.
    """

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
        "errors": [],
    }

    result["meta"] = {
        "target_url": url,
        "user_agent": config.get("user_agent", "Mozilla/5.0"),
        "timestamp": dt.datetime.now().isoformat(),
    }

    ua = config.get("user_agent", "Mozilla/5.0")
    proxy = config.get("proxy", None)
    delay = config.get("delay", 1.0)
    timeout_ms = config.get("timeout_ms", 60000)
    max_retries = config.get("max_retries", 2)
    wait_until_strategies = config.get("wait_until", ["domcontentloaded", "load"])

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(user_agent=ua, proxy=proxy)
        page = context.new_page()

        if "login" in config:
            try:
                perform_login(page, config["login"])
            except Exception as e:
                log_warn(f"Login flow failed: {e}", {"url": url})

        page_loaded = False
        last_error = None

        for retry_attempt in range(max_retries):
            for wait_strategy in wait_until_strategies:
                if _safe_goto(page, url, timeout_ms, wait_strategy):
                    page_loaded = True
                    result["meta"]["loaded_with"] = f"{wait_strategy} (attempt {retry_attempt+1})"
                    break
            if page_loaded:
                break
            if retry_attempt < max_retries - 1:
                log_info(f"Retry {retry_attempt+1}/{max_retries} for {url}")
                time.sleep(2 ** retry_attempt)

        if not page_loaded:
            result["errors"].append("Navigation timeout/failure")
            try:
                screenshot_path = os.path.join(
                    LOGS_DIR,
                    f"nav_failure_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.png",
                )
                page.screenshot(path=screenshot_path, full_page=True)
                log_info(f"Saved failure screenshot: {screenshot_path}")
            except Exception:
                pass
        else:
            page.wait_for_timeout(delay * 1000)

            # Links
            for a in page.query_selector_all("a[href]"):
                href = a.get_attribute("href")
                if href:
                    result["visited"].add(urljoin(url, href))

            # Forms
            for f in page.query_selector_all("form"):
                act = f.get_attribute("action")
                if act:
                    result["visited"].add(urljoin(url, act))

            # Scripts (external)
            for s in page.query_selector_all("script[src]"):
                src = s.get_attribute("src")
                if not src:
                    continue
                full_url = urljoin(url, src)
                result["scripts"].add(full_url)

                try:
                    # Prefer Playwright request API
                    js_resp = page.request.get(full_url, timeout=5000)
                    if js_resp.ok:
                        js_text = js_resp.text()
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

                        # Extra regex‑based detection in JS
                        email_regex = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
                        result["emails"].update(re.findall(email_regex, js_text))

                        jwt_regex = r"[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}"
                        result["jwt_tokens"].update(re.findall(jwt_regex, js_text))

                        api_key_regex = r"(?:api[_-]?key|apikey|x-api-key)[\"'\s:=]+([A-Za-z0-9\-_]{10,})"
                        result["api_keys"].update(re.findall(api_key_regex, js_text))

                        aws_key = r"AKIA[0-9A-Z]{16}"
                        aws_secret = r"[0-9a-zA-Z/+]{40}"
                        gcp_key = r"AIza[0-9A-Za-z\-_]{35}"
                        azure_key = r"[A-Za-z0-9]{32}"
                        for pat in (aws_key, aws_secret, gcp_key, azure_key):
                            result["secrets"].update(re.findall(pat, js_text))

                        api_regex = r"https?://[^\"' ]+"
                        result["api_endpoints"].update(re.findall(api_regex, js_text))

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

                email_regex = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
                result["emails"].update(re.findall(email_regex, js_text))

                jwt_regex = r"[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}"
                result["jwt_tokens"].update(re.findall(jwt_regex, js_text))

                api_key_regex = r"(?:api[_-]?key|apikey|x-api-key)[\"'\s:=]+([A-Za-z0-9\-_]{10,})"
                result["api_keys"].update(re.findall(api_key_regex, js_text))

                aws_key = r"AKIA[0-9A-Z]{16}"
                aws_secret = r"[0-9a-zA-Z/+]{40}"
                gcp_key = r"AIza[0-9A-Za-z\-_]{35}"
                azure_key = r"[A-Za-z0-9]{32}"
                for pat in (aws_key, aws_secret, gcp_key, azure_key):
                    result["secrets"].update(re.findall(pat, js_text))

                api_regex = r"https?://[^\"' ]+"
                result["api_endpoints"].update(re.findall(api_regex, js_text))

            # HTML
            content = page.content()
            html_sensitive = extract_sensitive_data(content)
            for k, v in html_sensitive.items():
                if k in result:
                    result[k].update(v)

            email_regex = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
            result["emails"].update(re.findall(email_regex, content))

            token_regex = r"[A-Za-z0-9-_]{20,}"
            result["tokens"].update(re.findall(token_regex, content))

            uid_regex = r"user[_-]?id[\"':= ]+([0-9a-zA-Z]+)"
            result["user_ids"].update(re.findall(uid_regex, content))

            jwt_regex = r"[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}"
            result["jwt_tokens"].update(re.findall(jwt_regex, content))

            api_key_regex = r"(?:api[_-]?key|apikey|x-api-key)[\"'\s:=]+([A-Za-z0-9\-_]{10,})"
            result["api_keys"].update(re.findall(api_key_regex, content))

            aws_key = r"AKIA[0-9A-Z]{16}"
            aws_secret = r"[0-9a-zA-Z/+]{40}"
            gcp_key = r"AIza[0-9A-Za-z\-_]{35}"
            azure_key = r"[A-Za-z0-9]{32}"
            for pat in (aws_key, aws_secret, gcp_key, azure_key):
                result["secrets"].update(re.findall(pat, content))

            cc_regex = r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
            result["credit_cards"].update(re.findall(cc_regex, content))

            ipv4_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
            result["ips"].update(re.findall(ipv4_regex, content))

            ipv6_regex = r"([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}"
            result["ipv6"].update(re.findall(ipv6_regex, content))

            mac_regex = r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"
            result["mac"].update(re.findall(mac_regex, content))

            cidr_regex = r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b"
            result["cidr"].update(re.findall(cidr_regex, content))

            hostname_regex = r"\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,})\b"
            result["hostnames"].update(re.findall(hostname_regex, content))

            uuid_regex = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
            result["uuids"].update(re.findall(uuid_regex, content))

            hash_regex = r"\b[a-fA-F0-9]{32,64}\b"
            result["hashes"].update(re.findall(hash_regex, content))

            b64_regex = r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b"
            result["base64_strings"].update(re.findall(b64_regex, content))

            pwd_regex = r"(?:password|passwd|pwd)[\"'\s:=]+([^\s\"']+)"
            result["passwords"].update(re.findall(pwd_regex, content))

            ssn_regex = r"\b\d{3}-\d{2}-\d{4}\b"
            result["ssn"].update(re.findall(ssn_regex, content))

            phone_regex = r"\+?\d[\d\s\-]{7,15}"
            result["phones"].update(re.findall(phone_regex, content))

            api_html_regex = r"https?://[^\"' ]+"
            result["api_endpoints"].update(re.findall(api_html_regex, content))

            param_regex = r"[?&]([a-zA-Z0-9_-]+)="
            result["parameters"].update(re.findall(param_regex, content))

            if "/graphql" in content:
                result["graphql"].add("/graphql")

            # SPA routes
            spa_routes = re.findall(r'router\.push\(["\']([^"\']+)["\']', content)
            spa_routes += re.findall(r'navigate\(["\']([^"\']+)["\']', content)
            spa_routes += re.findall(r'window\.location\.href\s*=\s*["\']([^"\']+)["\']', content)
            for r in spa_routes:
                result["visited"].add(urljoin(url, r))

            # URL parameters from visited
            for u in result["visited"]:
                parsed = urlparse(u)
                qs = parse_qs(parsed.query)
                for k in qs:
                    result["parameters"].add(k)

        browser.close()

    # Convert sets to lists
    for k in list(result.keys()):
        if isinstance(result[k], set):
            result[k] = list(result[k])

    # js_insights sanity
    for k, v in result.get("js_insights", {}).items():
        if not isinstance(v, dict):
            result["js_insights"][k] = {}

    result["stats"] = {
        "total_links": len(result["visited"]),
        "total_scripts": len(result["scripts"]),
        "total_api_endpoints": len(result["api_endpoints"]),
        "total_sensitive_items": sum(
            len(v) for k, v in result.items()
            if isinstance(v, list) and k not in ("visited", "scripts", "js_insights")
        ),
        "errors_count": len(result["errors"]),
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

    # --- Defensive logging & normalization ---
    try:
        # write a short debug snapshot of raw to disk for post-mortem
        dbg_path = os.path.join(LOGS_DIR, "deep_crawl_raw_debug.txt")
        with open(dbg_path, "a", encoding="utf-8") as df:
            df.write(f"--- {datetime.now().isoformat()} ---\n")
            df.write(repr(raw)[:10000] + "\n\n")
    except Exception:
        pass

    if isinstance(raw, tuple):
        # try to recover first dict-like element
        log_warn(f"deep_crawl returned tuple for {url}; attempting to recover dict element")
        recovered = None
        for part in raw:
            if isinstance(part, dict):
                recovered = part
                break
        if recovered is not None:
            raw = recovered
            log_info("Recovered dict from tuple returned by deep_crawl")
        else:
            log_error("deep_crawl returned tuple without any dict; coercing to empty result")
            raw = {"visited": [], "tokens": {}, "user_ids": {}, "api_endpoints": {}, "js_insights": {}, "scripts": [], "errors": []}

    if not isinstance(raw, dict):
        log_warn(f"deep_crawl returned unexpected type {type(raw).__name__}; coercing to dict")
        raw = {"visited": list(raw) if hasattr(raw, '__iter__') else [], "tokens": {}, "user_ids": {}, "api_endpoints": {}, "js_insights": {}, "scripts": [], "errors": []}

    visited = raw.get("visited", []) or []
    all_tokens = raw.get("tokens", {})
    all_user_ids = raw.get("user_ids", {})
    all_api_endpoints = raw.get("api_endpoints", {})
    all_js_insights = raw.get("js_insights", {})
    all_scripts = raw.get("scripts", []) or []
    all_errors = raw.get("errors", []) or []

    # Normalize common collection types
    if isinstance(visited, set):
        visited = list(visited)
    if isinstance(all_scripts, set):
        all_scripts = list(all_scripts)
    # js_insights should be a dict mapping url->insights
    if not isinstance(all_js_insights, dict):
        try:
            # if it's a list of tuples or pairs, convert
            alt = dict(all_js_insights)
            all_js_insights = alt
        except Exception:
            all_js_insights = {}
    # errors -> list
    if isinstance(all_errors, set):
        all_errors = list(all_errors)

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

    def _flatten_unique_values(values: Any) -> List[str]:
        collected: List[str] = []
        seen: Set[str] = set()

        def add_value(value: Any) -> None:
            if value is None:
                return
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    add_value(item)
                return
            text = str(value)
            if text not in seen:
                seen.add(text)
                collected.append(text)

        if isinstance(values, (list, tuple, set)):
            for value in values:
                add_value(value)
        else:
            add_value(values)

        return collected

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

        "cms_usage": _flatten_unique_values([p.get("cms") for p in pages if p.get("cms")]),
        "frameworks_usage": _flatten_unique_values([fw for p in pages for fw in (p.get("frameworks") or [])]),
        "backend_frameworks_usage": _flatten_unique_values([p.get("backend_framework") for p in pages if p.get("backend_framework")]),

        "servers_detected": _flatten_unique_values([p.get("server") for p in pages if p.get("server")]),

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

    # УЛУЧШЕНО: Enhance results with better summary and recommendations
    enhanced_result = enhance_crawler_results(result)
    
    # Save enhanced version
    with open(os.path.join(LOGS_DIR, "deep_crawl_enhanced.json"), "w", encoding="utf-8") as f:
        json.dump(enhanced_result, f, indent=2, ensure_ascii=False)

    return enhanced_result


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


# ============================
# 🎯 Enhanced Result Transformer (Боевое улучшение)
# ============================

def enhance_crawler_results(crawl_result: dict) -> dict:
    """
    Трансформирует сирые результаты краулинга в продакшн‑готовый формат.
    Добавляет детальный анализ ошибок, рекомендации, и качество сканирования.
    """
    try:
        raw = crawl_result.get("raw", {})
        pages = crawl_result.get("pages", [])
        summary = crawl_result.get("summary", {})
        
        # Analyze errors
        errors = raw.get("errors", [])
        error_categories = {
            "timeout": [],
            "auth": [],
            "network": [],
            "js_fetch": [],
            "other": []
        }
        
        for error_msg in errors:
            error_lower = str(error_msg).lower()
            if "timeout" in error_lower or "exceeded" in error_lower:
                error_categories["timeout"].append(error_msg)
            elif "auth" in error_lower or "login" in error_lower:
                error_categories["auth"].append(error_msg)
            elif "network" in error_lower or "refused" in error_lower:
                error_categories["network"].append(error_msg)
            elif "js" in error_lower or "fetch" in error_lower:
                error_categories["js_fetch"].append(error_msg)
            else:
                error_categories["other"].append(error_msg)
        
        # Determine scan status
        visited_count = len(raw.get("visited", []))
        has_timeout = len(error_categories["timeout"]) > 0
        has_errors = len(errors) > 0
        
        if visited_count > 0 and not has_errors:
            scan_status = "SUCCESS"
            scan_notes = "✅ Полный краулинг и анализ завершены успешно"
        elif visited_count > 0 and has_errors:
            scan_status = "PARTIAL"
            scan_notes = f"⚠️ Краулинг завершен с ошибками ({len(errors)} шт.)"
        elif has_timeout:
            scan_status = "TIMEOUT"
            scan_notes = "⏱️ Навигация истекла. Рекомендуется: увеличить таймаут, использовать прокси"
        else:
            scan_status = "FAILED"
            scan_notes = f"❌ Краулинг не выполнен. Причина: {errors[0] if errors else 'неизвестно'}"
        
        # Build recommendations
        recommendations = []
        if has_timeout:
            recommendations.append("🔹 Увеличить Playwright timeout до 90000-120000ms")
            recommendations.append("🔹 Использовать residential proxy для обхода WAF")
        if len(error_categories["auth"]) > 0:
            recommendations.append("🔹 Проверить учетные данные для авторизации")
        if visited_count == 0 and not has_timeout:
            recommendations.append("🔹 Проверить доступность целевого URL")
        
        # Build enhanced summary
        enhanced_summary = {
            "scan_status": scan_status,
            "scan_notes": scan_notes,
            "target_url": raw.get("meta", {}).get("target_url", "unknown"),
            "scan_timestamp": raw.get("meta", {}).get("timestamp", "unknown"),
            "pages_crawled": visited_count,
            "total_scripts": len(raw.get("scripts", [])),
            "total_api_endpoints": len(raw.get("api_endpoints", [])),
            "total_tokens_found": len(raw.get("tokens", [])),
            "error_count": len(errors),
            "error_summary": {
                "timeout_errors": len(error_categories["timeout"]),
                "auth_errors": len(error_categories["auth"]),
                "network_errors": len(error_categories["network"]),
                "js_errors": len(error_categories["js_fetch"]),
                "other_errors": len(error_categories["other"])
            },
            "error_details": error_categories,
            "recommendations": recommendations,
            "quality_score": max(0, 100 - (len(errors) * 15) - (50 if has_timeout else 0)),
        }
        
        # Build final enhanced result
        enhanced_result = {
            **crawl_result,
            "summary": enhanced_summary,
            "diagnostic": {
                "metadata": raw.get("meta", {}),
                "loading_method": raw.get("meta", {}).get("loaded_with", "unknown"),
            }
        }
        
        return enhanced_result
        
    except Exception as e:
        log_warn(f"Failed to enhance crawler results: {e}")
        return crawl_result
