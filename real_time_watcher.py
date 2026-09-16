# xss_security_gui/real_time_watcher.py
# ============================================================
# RealTimeThreatWatcher 11.0 Stealth Mode (Red Team Edition)
# - Stealth TLS Fingerprint Rotation (JA3 Impersonation)
# - Header Rotation Engine (20+ browser profiles)
# - Dynamic Delay Jitter (human-like behavior)
# - IP Reputation Randomizer
# - Full Stealth Mode 11.0 (Cloudflare/Akamai/PerimeterX/Imperva bypass)
# - adaptive retry (UA / timeout / TLS / headers / backoff)
# - adaptive interval + TTL‑dedup
# - parallel JS fetch + deep JSInspector
# - extended secrets / PII / SSRF / headers
# - live GUI status via ThreatAnalysisTab + UIQueueBridge
# - zero GUI freezes (pure worker thread)
# - EXPLOIT SIMULATION & ATTACK CAPABILITIES
# ============================================================

import threading
import time
import logging
import json
import random
import string
import ssl
from typing import Dict, Any, Optional, List, Set
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode

import os
import re
import tempfile
import concurrent.futures

import requests
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup

from xss_security_gui.settings import settings
from xss_security_gui.threat_tab_connector import ThreatIntelConnector
from xss_security_gui.combat_crawler import CombatCrawler
from xss_security_gui.core.stealth_engine import StealthMode

logger = logging.getLogger(__name__)

# HTTP status codes that trigger adaptive retry
_RETRYABLE_STATUS = frozenset({403, 408, 429, 500, 502, 503, 504, 520, 521, 522, 524})


class _AdaptiveTLSAdapter(HTTPAdapter):
    """Per-attempt TLS profile for HTTPS requests."""

    def __init__(self, ssl_context: Optional[ssl.SSLContext] = None, **kwargs):
        self._ssl_context = ssl_context

        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        if self._ssl_context is not None:
            pool_kwargs["ssl_context"] = self._ssl_context
        return super().init_poolmanager(connections, maxsize, block, **pool_kwargs)


class RealTimeThreatWatcher:
    """
    RealTimeThreatWatcher 11.0 Stealth Mode (Red Team Edition):
    - Stealth TLS Fingerprint Rotation (Chrome/Firefox/Safari/Randomized JA3)
    - JA3 Impersonation for WAF bypass
    - Header Rotation Engine (22 real browser profiles)
    - Anti-bot & anti-fingerprint headers
    - Dynamic Delay Jitter with human-like behavior
    - Adaptive throttling based on server response
    - IP Reputation Randomizer (Accept-Language / Timezone / Sec-CH-UA)
    - Full Stealth Mode 11.0 (Cloudflare / Akamai / PerimeterX / Imperva bypass)
    - НЕ блокує GUI (окремий потік)
    - adaptive throttling + TTL‑дедуп
    - паралельний JS‑аналіз
    - розширений Secret/PII/SSRF/Header сканер
    - live‑статус у ThreatAnalysisTab (update_watcher_status)
    """

    def __init__(
            self,
            threat_tab,
            url: str,
            interval: int = 30,
            capture_screenshot: bool = True,
            tic: Optional[ThreatIntelConnector] = None,
            max_artifacts_per_cycle: int = 100,
            dedup_ttl: float = 600.0,
            result_queue=None,  # 🔥 ДОДАНО
    ):

        self.threat_tab = threat_tab
        self.url = url
        self.result_queue = result_queue  # 🔥 ДОДАНО — ТЕПЕР ЧЕРГА ЗБЕРІГАЄТЬСЯ
        self._base_interval = max(5, interval)
        self.interval = self._base_interval
        self.capture_screenshot = capture_screenshot
        self.combat_enabled = True
        self.combat_last_run = 0
        self.combat_min_interval = 120  # не частіше ніж раз на 2 хвилини
        self.combat_thread: Optional[threading.Thread] = None
        self._bruteforce_enabled = bool(settings.get("watcher.bruteforce_enabled", True))
        self._bruteforce_aggressive = bool(settings.get("watcher.bruteforce_aggressive", False))
        self._login_probe_enabled = self._bruteforce_enabled
        self._aggressive_mode = self._bruteforce_aggressive
        self._bruteforce_candidates = [
            "admin", "admin123", "password", "Password1", "123456", "qwerty",
            "welcome", "letmein", "secret", "passw0rd", "user", "guest"
        ]
        if self._bruteforce_aggressive:
            self._bruteforce_candidates.extend([
                "Admin123", "Passw0rd!", "password123", "Welcome1", "Qwerty1",
                "root", "manager", "support", "test123", "demo123"
            ])
        self._network_noise = []
        self._network_noise_limit = 20

        # ============================================================
        # Proxy Rotation Pool — GEO‑Mix (RU / EU / US / Cloud)
        # ============================================================
        self.proxy_pool: List[Dict[str, str]] = []

        # Load from settings if provided
        raw_proxies = settings.get("watcher.proxy_pool") or []
        for item in raw_proxies:
            if isinstance(item, str):
                # "http://ip:port"
                self.proxy_pool.append({"http": item, "https": item})
            elif isinstance(item, dict):
                http_p = item.get("http")
                https_p = item.get("https", http_p)
                if http_p:
                    self.proxy_pool.append({"http": http_p, "https": https_p})

        # Default GEO‑mix if settings are empty
        if not self.proxy_pool:
            self.proxy_pool = [
                # RU / CIS
                {"http": "http://95.217.12.34:8080", "https": "http://95.217.12.34:8080"},
                {"http": "http://185.123.45.67:8080", "https": "http://185.123.45.67:8080"},
                # EU
                {"http": "http://51.68.200.55:3128", "https": "http://51.68.200.55:3128"},
                # US
                {"http": "http://104.248.63.15:8080", "https": "http://104.248.63.15:8080"},
                # Cloud / misc
                {"http": "http://167.71.12.34:8080", "https": "http://167.71.12.34:8080"},
            ]

        # WAF evasion parameters — INTL + RU/CIS locale pools
        self._user_agents_intl = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        ]
        self._user_agents_ru = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 YaBrowser/24.1.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
        ]
        self._referers_intl = [
            "https://www.google.com/",
            "https://www.bing.com/",
            "https://duckduckgo.com/",
            "https://www.yahoo.com/",
        ]
        self._referers_ru = [
            "https://yandex.ru/",
            "https://www.google.ru/",
            "https://mail.ru/",
            "https://vk.ru/",
            "https://dzen.ru/",
            "https://www.rambler.ru/",
            "https://news.google.com/",
        ]
        self._accept_languages_intl = [
            "en-US,en;q=0.9",
            "en-GB,en;q=0.8",
            "de-DE,de;q=0.9,en;q=0.8",
            "fr-FR,fr;q=0.9,en;q=0.8",
        ]
        self._accept_languages_ru = [
            "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "ru,en-US;q=0.9,en;q=0.8",
            "uk-UA,uk;q=0.9,ru;q=0.8,en;q=0.7",
            "be-BY,be;q=0.9,ru;q=0.8",
            "kk-KZ,kk;q=0.9,ru;q=0.8,en;q=0.7",
        ]

        # Sec‑CH‑UA / Timezone / Platform headers — anti‑fingerprint / anti‑bot
        self._sec_ch_ua_profiles = [
            {
                "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not:A-Brand";v="99"',
                "Sec-CH-UA-Mobile": "?0",
                "Sec-CH-UA-Platform": '"Windows"',
            },
            {
                "Sec-CH-UA": '"Chromium";v="124", "Microsoft Edge";v="124", "Not:A-Brand";v="99"',
                "Sec-CH-UA-Mobile": "?0",
                "Sec-CH-UA-Platform": '"Windows"',
            },
            {
                "Sec-CH-UA": '"Chromium";v="124", "Brave";v="124", "Not:A-Brand";v="99"',
                "Sec-CH-UA-Mobile": "?0",
                "Sec-CH-UA-Platform": '"Linux"',
            },
            {
                "Sec-CH-UA": '"Chromium";v="124", "Chrome";v="124", "Not:A-Brand";v="99"',
                "Sec-CH-UA-Mobile": "?1",
                "Sec-CH-UA-Platform": '"Android"',
            },
        ]

        self._timezone_headers = [
            "Europe/Moscow",
            "Europe/Kiev",
            "Europe/Berlin",
            "Europe/London",
            "Asia/Almaty",
        ]

        self._user_agents = self._user_agents_intl + self._user_agents_ru
        self._headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
        }

        # Adaptive retry (stealth / WAF resilience)
        self._retry_max_attempts = int(settings.get("watcher.retry_max_attempts", 5) or 5)
        self._retry_base_timeout = float(settings.get("watcher.retry_base_timeout", 8.0) or 8.0)
        self._retry_backoff_base = float(settings.get("watcher.retry_backoff_base", 0.6) or 0.6)
        self._retry_backoff_cap = float(settings.get("watcher.retry_backoff_cap", 15.0) or 15.0)
        self._retry_jitter = float(settings.get("watcher.retry_jitter", 0.35) or 0.35)
        self._locale_ru_rotation = bool(settings.get("watcher.locale_ru_rotation", True))
        self._locale_ru_weight = float(settings.get("watcher.locale_ru_weight", 0.55) or 0.55)
        self._retry_stats: Dict[str, int] = {
            "success": 0,
            "failed": 0,
            "retries": 0,
            "locale_ru": 0,
            "locale_intl": 0,
        }

        self._accept_languages = self._accept_languages_intl + self._accept_languages_ru

        # ============================================================
        # Stealth Mode 11.0 — Red Team Edition
        # ============================================================
        self.stealth = StealthMode()
        self.stealth.activate()
        logger.info("[RealTimeWatcher] Stealth Mode 11.0 ACTIVATED — %d browser profiles",
                    self.stealth.header_engine.profile_count)

        # TLS cipher profiles — JA3‑like rotation (Chrome / Firefox / Safari / Legacy)
        # NOTE: legacy profiles kept for fallback; StealthMode.tls_rotator is primary
        self._tls_cipher_profiles: List[Optional[str]] = [
            None,
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:HIGH:!aNULL:!MD5",
            "DEFAULT@SECLEVEL=1",
        ]

        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Дедуплікація з TTL (hash -> ts)
        self._seen_hashes: Dict[int, float] = {}
        self._last_cleanup = time.time()
        self._dedup_ttl = dedup_ttl

        # Threat Intel connector
        self.tic = tic or ThreatIntelConnector()

        # Throttling counters
        self._max_artifacts_per_cycle = max(20, max_artifacts_per_cycle)

        # Статус
        self._status: str = "idle"
        self._last_gui_status: Optional[str] = None

    # ============================================================
    # WAF Evasion Techniques
    # ============================================================
    def _get_random_delay(self) -> float:
        """Random delay between requests — delegates to StealthMode DynamicDelayJitter."""
        if self.stealth.is_active:
            return self.stealth.get_delay()
        base = random.uniform(0.4, 1.8)
        jitter = random.uniform(-0.2, 0.6)
        return max(0.2, base + jitter)

    def _get_random_user_agent(self, locale: Optional[str] = None) -> str:
        """Random user agent rotation (INTL / RU pools)."""
        pool = self._user_agents_ru if locale == "ru" else self._user_agents_intl
        if locale is None:
            pool = self._user_agents
        return random.choice(pool)

    def _get_random_referer(self, locale: Optional[str] = None) -> str:
        """Random referer — INTL search engines or RU/CIS portals."""
        if locale == "ru":
            return random.choice(self._referers_ru)
        if locale == "intl":
            return random.choice(self._referers_intl)
        referers = self._referers_ru + self._referers_intl
        return random.choice(referers)

    def _get_accept_language(self, locale: Optional[str] = None) -> str:
        if locale == "ru":
            return random.choice(self._accept_languages_ru)
        if locale == "intl":
            return random.choice(self._accept_languages_intl)
        return random.choice(self._accept_languages)

    def _get_random_timezone(self) -> str:
        return random.choice(self._timezone_headers)

    def _get_sec_ch_ua(self) -> Dict[str, str]:
        return random.choice(self._sec_ch_ua_profiles)

    def _locale_for_attempt(self, attempt: int) -> str:
        """
        RU rotation across retry attempts:
        even attempts → RU/CIS profile, odd → INTL (when locale_ru_rotation enabled).
        """
        if not self._locale_ru_rotation:
            return "ru" if random.random() < self._locale_ru_weight else "intl"
        if attempt % 2 == 0:
            return "ru"
        return "intl"

    def _get_random_headers(self, locale: Optional[str] = None) -> Dict[str, str]:
        """Generate random headers — StealthMode 11.0 Header Rotation Engine."""
        loc = locale or ("ru" if random.random() < self._locale_ru_weight else "intl")

        # Use StealthMode header engine when active (22 browser profiles + anti-bot)
        if self.stealth.is_active:
            headers = self.stealth.get_stealth_headers(loc)
            headers["Referer"] = self._get_random_referer(loc)
            return headers

        # Fallback to legacy header generation
        headers = self._headers.copy()
        headers["User-Agent"] = self._get_random_user_agent(loc)
        headers["Referer"] = self._get_random_referer(loc)
        headers["Accept-Language"] = self._get_accept_language(loc)

        tz = self._get_random_timezone()
        headers["X-Timezone"] = tz
        ch = self._get_sec_ch_ua()
        headers.update(ch)

        if random.random() < 0.4:
            headers["X-Requested-With"] = "XMLHttpRequest"
        if random.random() < 0.3:
            headers["X-Forwarded-For"] = f"192.0.2.{random.randint(1, 254)}"

        return headers

    def _run_combat_cycle_safe(self):
        """Безпечний запуск CombatCrawler у окремому потоці."""
        try:
            crawler = CombatCrawler(
                target_url=self.url,
                result_queue=self.result_queue,  # 🔥 СПІЛЬНА ЧЕРГА
                progress_callback=self._push_status_to_gui
            )

            logger.info("[RealTimeWatcher] CombatCrawler started")
            report = crawler.run_full_combat_cycle()

            logger.info("[RealTimeWatcher] CombatCrawler finished")
            self._push_status_to_gui("combat_complete")

        except Exception as e:
            logger.error(f"[RealTimeWatcher] CombatCrawler error: {e}", exc_info=True)

    # ============================================================
    # Adaptive Retry Engine — UA / timeout / TLS / headers / backoff
    # ============================================================

    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff with jitter between retry attempts."""
        delay = min(
            self._retry_backoff_cap,
            self._retry_backoff_base * (2 ** max(0, attempt - 1)),
        )
        jitter = random.uniform(0, self._retry_jitter * delay)
        return delay + jitter

    def _adaptive_timeout(self, attempt: int, base: Optional[float] = None) -> float:
        """Increase timeout on later attempts (slow / challenged responses)."""
        base_val = base if base is not None else self._retry_base_timeout
        return min(45.0, base_val + attempt * 2.5)

    def _adaptive_verify_ssl(self, attempt: int) -> bool:
        """Rotate TLS verification strategy across attempts."""
        default = bool(settings.get("http.verify_ssl", False))
        if attempt == 0:
            return default
        if attempt >= self._retry_max_attempts - 1:
            return False
        return default

    def _make_tls_context(self, attempt: int) -> Optional[ssl.SSLContext]:
        """Build SSL context — StealthMode JA3 fingerprint rotation."""
        # StealthMode: use JA3 impersonation profiles
        if self.stealth.is_active:
            try:
                ctx, profile_name = self.stealth.get_stealth_context()
                logger.debug("[RealTimeWatcher] Stealth TLS profile: %s (attempt %d)", profile_name, attempt)
                return ctx
            except Exception as exc:
                logger.debug("[RealTimeWatcher] Stealth TLS fallback: %s", exc)

        # Legacy fallback
        profile = self._tls_cipher_profiles[attempt % len(self._tls_cipher_profiles)]
        if profile is None:
            return None
        try:
            ctx = ssl.create_default_context()
            ctx.set_ciphers(profile)
            if attempt % 2 == 1:
                ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
            return ctx
        except Exception as exc:
            logger.debug("[RealTimeWatcher] TLS profile %r skipped: %s", profile, exc)
            return None

    def _adaptive_headers(
        self,
        attempt: int,
        extra: Optional[Dict[str, str]] = None,
        locale: Optional[str] = None,
    ) -> Dict[str, str]:
        """Header profiles rotated per retry attempt (RU ↔ INTL locale rotation)."""
        loc = locale or self._locale_for_attempt(attempt)
        if loc == "ru":
            self._retry_stats["locale_ru"] += 1
        else:
            self._retry_stats["locale_intl"] += 1

        ua = self._get_random_user_agent(loc)
        referer = self._get_random_referer(loc)
        lang = self._get_accept_language(loc)

        if attempt == 0:
            headers = {
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": lang,
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Referer": referer,
                "DNT": "1",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "cross-site" if loc == "ru" else "none",
                "Sec-Fetch-User": "?1",
            }
            if loc == "ru":
                headers["Accept-Charset"] = "utf-8, windows-1251;q=0.7, *;q=0.7"
        elif attempt == 1:
            headers = {
                "User-Agent": ua,
                "Accept": "*/*",
                "Accept-Language": lang,
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Referer": referer,
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            }
        elif attempt == 2:
            headers = {
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": lang,
                "Accept-Encoding": "identity",
                "Connection": "close",
                "Referer": referer,
            }
        else:
            headers = self._get_random_headers(loc)
            cc = random.choice(["max-age=0", "no-cache", ""])
            if cc:
                headers["Cache-Control"] = cc
            if random.random() < 0.5:
                headers["Connection"] = "close"

        if extra:
            headers.update(extra)
        return headers

    def _build_adaptive_session(
        self,
        attempt: int,
        proxies: Optional[Dict[str, str]] = None,
    ) -> requests.Session:
        """Session with per-attempt TLS adapter and header baseline."""
        session = requests.Session()
        tls_ctx = self._make_tls_context(attempt)
        if tls_ctx is not None:
            adapter = _AdaptiveTLSAdapter(ssl_context=tls_ctx)
            session.mount("https://", adapter)
        if proxies:
            session.proxies.update(proxies)
        session.max_redirects = min(10, 3 + attempt)
        return session

    def _should_retry(
        self,
        attempt: int,
        max_attempts: int,
        status_code: Optional[int],
        exc: Optional[Exception],
    ) -> bool:
        if attempt >= max_attempts - 1:
            return False
        if exc is not None:
            return True
        if status_code is None:
            return True
        if status_code in _RETRYABLE_STATUS:
            # StealthMode: report block for adaptive throttling
            if self.stealth.is_active and status_code in (403, 429, 503):
                self.stealth.report_block()
            return True
        if 400 <= (status_code or 0) < 500 and status_code not in (404, 410):
            return attempt < 2
        return False

    def _adaptive_request(
        self,
        method: str,
        url: str,
        *,
        max_attempts: Optional[int] = None,
        base_timeout: Optional[float] = None,
        proxies: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        data: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        HTTP with adaptive retry:
        - rotating User-Agent / headers / Accept-Language
        - escalating timeout
        - TLS cipher profile rotation
        - exponential backoff + jitter
        """
        attempts_limit = max(1, max_attempts or self._retry_max_attempts)
        last_error: Optional[str] = None
        last_status: Optional[int] = None
        response: Optional[requests.Response] = None

        for attempt in range(attempts_limit):
            if attempt > 0:
                self._retry_stats["retries"] += 1
                delay = self._backoff_delay(attempt)
                logger.debug(
                    "[RealTimeWatcher] Adaptive retry #%d for %s (backoff %.2fs)",
                    attempt,
                    url[:80],
                    delay,
                )
                time.sleep(delay)

            locale = self._locale_for_attempt(attempt)
            headers = self._adaptive_headers(attempt, extra_headers, locale=locale)
            timeout = self._adaptive_timeout(attempt, base_timeout)
            verify = self._adaptive_verify_ssl(attempt)
            session = self._build_adaptive_session(attempt, proxies)

            try:
                response = session.request(
                    method.upper(),
                    url,
                    headers=headers,
                    timeout=timeout,
                    verify=verify,
                    allow_redirects=allow_redirects,
                    data=data if data is not None else None,
                )
                last_status = response.status_code
                # StealthMode: adaptive throttle based on response time
                if self.stealth.is_active:
                    elapsed = response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0
                    self.stealth.adaptive_throttle(elapsed)
                    if response.ok:
                        self.stealth.report_success()
                if response.ok or not self._should_retry(attempt, attempts_limit, last_status, None):
                    self._retry_stats["success"] += 1
                    return {
                        "success": response.ok,
                        "response": response,
                        "status_code": last_status,
                        "headers": dict(response.headers),
                        "text": response.text,
                        "content": response.content,
                        "attempts": attempt + 1,
                        "timeout_used": timeout,
                        "user_agent": headers.get("User-Agent"),
                        "locale": locale,
                        "accept_language": headers.get("Accept-Language"),
                        "referer": headers.get("Referer"),
                    }
                last_error = f"HTTP {last_status}"
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if not self._should_retry(attempt, attempts_limit, None, exc):
                    break
            finally:
                session.close()

        self._retry_stats["failed"] += 1
        return {
            "success": False,
            "error": last_error or "unknown",
            "status_code": last_status,
            "response": response,
            "text": getattr(response, "text", "") if response else "",
            "content": getattr(response, "content", b"") if response else b"",
            "attempts": attempts_limit,
        }

    def get_retry_stats(self) -> Dict[str, int]:
        """Telemetry for dashboards / Threat Intel."""
        return dict(self._retry_stats)

    def get_stealth_stats(self) -> Dict[str, Any]:
        """Stealth Mode 11.0 telemetry — TLS rotation, header engine, delay jitter, WAF evasion."""
        return self.stealth.stats

    # ============================================================
    # Control
    # ============================================================
    def start(self) -> None:
        if self._running:
            logger.info("[RealTimeWatcher] Already running (status=%s)", self._status)
            return

        if not self.threat_tab or not self.threat_tab.winfo_exists():
            logger.warning("[RealTimeWatcher] ThreatTab not ready, cannot start watcher")
            return

        self._running = True
        self._status = "running"
        self._push_status_to_gui()

        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name="RealTimeThreatWatcher11StealthRedTeam",
        )
        self._thread.start()

        logger.info("[RealTimeWatcher] Started monitoring %s (interval=%ds)", self.url, self.interval)

    def stop(self) -> None:
        if not self._running:
            logger.info("[RealTimeWatcher] Stop called but watcher is not running (status=%s)", self._status)
            return

        self._running = False
        self._status = "stopped"
        logger.info("[RealTimeWatcher] Stopped")
        self._push_status_to_gui()

    def is_running(self) -> bool:
        return self._running

    def get_status(self) -> str:
        return self._status

    # ============================================================
    # Main loop with WAF evasion
    # ============================================================
    def _loop(self) -> None:
        while self._running:
            try:
                if not self.threat_tab or not self.threat_tab.winfo_exists():
                    logger.warning("[RealTimeWatcher] ThreatTab closed, stopping watcher")
                    self._running = False
                    self._status = "stopped"
                    self._push_status_to_gui()
                    break

                logger.info(
                    "[RealTimeWatcher] Heartbeat — status=%s, next scan in %ds, url=%s",
                    self._status,
                    self.interval,
                    self.url,
                )

                # === SCANNING ===
                self._status = "scanning"
                self._push_status_to_gui()

                # Random delay before scanning
                time.sleep(self._get_random_delay())

                artifacts_count = self._scan_once()

                # === RUNNING ===
                self._status = "running"
                self._push_status_to_gui()

                # === Adaptive throttling ===
                if artifacts_count > self._max_artifacts_per_cycle * 0.8:
                    self.interval = min(self._base_interval * 4, self.interval + 10)
                    logger.info(
                        "[RealTimeWatcher] High artifact load (%d), increasing interval to %ds",
                        artifacts_count,
                        self.interval,
                    )
                else:
                    if self.interval > self._base_interval:
                        self.interval = max(self._base_interval, self.interval - 5)

                # WAF‑aware stealth scaling
                retry_stats = self.get_retry_stats()
                waf_pressure = retry_stats.get("failed", 0) + retry_stats.get("retries", 0)
                if waf_pressure > 50 and self.interval < self._base_interval * 4:
                    self.interval = min(self._base_interval * 4, self.interval + 5)
                    logger.info(
                        "[RealTimeWatcher] WAF pressure detected (failed+retries=%d), increasing interval to %ds",
                        waf_pressure,
                        self.interval,
                    )

                # === CombatCrawler Trigger (автоматичні атаки) ===
                try:
                    # Ініціалізація параметрів, якщо їх ще немає
                    if not hasattr(self, "combat_enabled"):
                        self.combat_enabled = True
                    if not hasattr(self, "combat_last_run"):
                        self.combat_last_run = 0
                    if not hasattr(self, "combat_min_interval"):
                        self.combat_min_interval = 120  # не частіше ніж раз на 2 хвилини
                    if not hasattr(self, "combat_thread"):
                        self.combat_thread = None

                    if self.combat_enabled:
                        now = time.time()

                        # Умова запуску:
                        # 1) є нові артефакти
                        # 2) пройшло достатньо часу з останнього запуску
                        # 3) немає активного combat-потоку
                        if artifacts_count > 0:
                            if (now - self.combat_last_run) > self.combat_min_interval:
                                if not self.combat_thread or not self.combat_thread.is_alive():
                                    logger.info(
                                        "[RealTimeWatcher] Triggering CombatCrawler due to new artifacts"
                                    )

                                    self.combat_thread = threading.Thread(
                                        target=self._run_combat_cycle_safe,
                                        daemon=True
                                    )
                                    self.combat_thread.start()
                                    self.combat_last_run = now

                except Exception as combat_err:
                    logger.error(f"[RealTimeWatcher] CombatCrawler trigger error: {combat_err}")

            except Exception as e:
                self._status = "error"
                logger.exception("[RealTimeWatcher] Loop error: %s", e)
                self._push_status_to_gui()

            # === IDLE (waiting for next cycle) ===
            self._status = "idle"
            self._push_status_to_gui()

            time.sleep(self.interval)



    # ============================================================
    # Thread‑safe push status → ThreatAnalysisTab
    # ============================================================
    def _push_status_to_gui(self, status: Optional[str] = None, progress_pct: Optional[int] = None) -> None:
        """Push watcher state to the Threat tab.

        Supports both internal calls (`_push_status_to_gui()`) and external
        callbacks that pass a status string/message (`_push_status_to_gui("combat_complete")`)
        or a CombatCrawler progress callback form (`_push_status_to_gui("scan", 65)`).
        """
        try:
            if status is None:
                target_status = self._status
            else:
                target_status = str(status)

            if not self.threat_tab or not self.threat_tab.winfo_exists():
                return

            if not hasattr(self.threat_tab, "update_watcher_status"):
                return

            # не спамимо однаковий статус
            if self._last_gui_status == target_status and progress_pct is None:
                return
            self._last_gui_status = target_status

            bridge = getattr(self.threat_tab, "_bridge", None)
            if bridge is not None:
                bridge.post_ui(self.threat_tab.update_watcher_status, target_status)
            else:
                self.threat_tab.after(
                    0,
                    lambda s=target_status: self.threat_tab.update_watcher_status(s),
                )
        except Exception:
            pass

    # ============================================================
    # HTTP fetch with WAF evasion
    # ============================================================
    def _fetch_page(self, headers: Optional[Dict[str, str]] = None, proxies: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Fetch page via adaptive retry (UA / timeout / TLS / headers / backoff)."""
        try:
            if '?' in self.url:
                url = f"{self.url}&{self._generate_random_params()}"
            else:
                url = f"{self.url}?{self._generate_random_params()}"

            result = self._adaptive_request(
                "GET",
                url,
                proxies=proxies,
                extra_headers=headers,
                base_timeout=self._retry_base_timeout,
            )

            if not result.get("success"):
                return {
                    "success": False,
                    "error": result.get("error", "fetch failed"),
                    "status_code": result.get("status_code"),
                    "attempts": result.get("attempts"),
                }

            resp_text = result.get("text") or ""
            soup = BeautifulSoup(resp_text, "html.parser")
            js_files = [urljoin(self.url, tag.get("src")) for tag in soup.find_all("script", src=True)]

            return {
                "success": True,
                "html": resp_text,
                "soup": soup,
                "js_files": js_files,
                "headers": result.get("headers") or {},
                "attempts": result.get("attempts"),
                "timeout_used": result.get("timeout_used"),
                "locale": result.get("locale"),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _record_network_noise(self, phase: str, details: Any) -> None:
        """Track transient network resets/timeouts without crashing the watcher loop."""
        try:
            item = {
                "phase": phase,
                "detail": str(details),
                "ts": time.time(),
            }
            self._network_noise.append(item)
            if len(self._network_noise) > self._network_noise_limit:
                self._network_noise = self._network_noise[-self._network_noise_limit:]
        except Exception:
            pass

    def _is_target_allowed(self) -> bool:
        """Approved-target gate for login brute force or equivalent auth probing."""
        try:
            host = urlparse(self.url).hostname or ""
            allowed = {str(x).lower() for x in (getattr(settings, "ALLOWED_TARGETS", []) or [])}
            if not getattr(settings, "ALLOW_REAL_RUN", False):
                return False
            if not allowed:
                return True
            return host.lower() in allowed or self.url.lower() in {x.lower() for x in (getattr(settings, "ALLOWED_TARGETS", []) or [])}
        except Exception:
            return False

    def _find_login_targets(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Best-effort login form discovery for controlled brute-force validation."""
        targets: List[Dict[str, str]] = []
        try:
            for form in soup.find_all("form"):
                method = str((form.get("method") or "GET")).upper()
                action = form.get("action") or self.url
                action_url = action if action.startswith("http") else urljoin(self.url, action)
                fields = [
                    (el.get("name") or "").strip()
                    for el in form.find_all(["input", "textarea", "select"])
                    if (el.get("name") or "").strip()
                ]
                username_candidates = ["username", "user", "email", "login", "uname", "account"]
                password_candidates = ["password", "passwd", "pass", "pwd"]
                has_user = any(name.lower() in username_candidates or "user" in name.lower() for name in fields)
                has_pass = any(name.lower() in password_candidates or "pass" in name.lower() for name in fields)
                if has_user and has_pass:
                    targets.append({
                        "method": method,
                        "action": action_url,
                        "fields": fields,
                    })
        except Exception:
            pass
        return targets

    def _bruteforce_login_targets(self, html: str) -> List[Dict[str, Any]]:
        """Run a small, rate-limited brute-force probe only when a login form is present."""
        if not self._bruteforce_enabled:
            return []
        if not self._is_target_allowed():
            return []
        try:
            soup = BeautifulSoup(html, "html.parser")
            targets = self._find_login_targets(soup)
            if not targets:
                return []

            hits: List[Dict[str, Any]] = []
            user_names = [
                "admin", "administrator", "root", "user", "support", "demo",
                "manager", "test", "qa", "guest"
            ]
            if self._bruteforce_aggressive:
                user_names.extend(["ops", "billing", "portal", "operator", "service", "login"])
            for target in targets[:3]:
                action = target["action"]
                fields = target["fields"]
                for username in user_names:
                    password_pool = self._bruteforce_candidates[:16]
                    if self._bruteforce_aggressive:
                        password_pool = self._bruteforce_candidates[:32]
                    for password in password_pool:
                        payload = {}
                        for name in fields:
                            lname = name.lower()
                            if any(token in lname for token in ("user", "email", "login", "account")):
                                payload[name] = username
                            elif any(token in lname for token in ("pass", "pwd")):
                                payload[name] = password
                            else:
                                payload[name] = ""
                        try:
                            result = self._adaptive_request(
                                target["method"],
                                action,
                                max_attempts=2,
                                base_timeout=6.0,
                                extra_headers={
                                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                    "X-Requested-With": "XMLHttpRequest",
                                },
                                allow_redirects=True,
                                data=payload,
                            )
                            if not result.get("success"):
                                continue
                            body_text = (result.get("text") or "").lower()
                            if any(marker in body_text for marker in ["dashboard", "welcome", "logout", "profile", "account", "success", "home"]):
                                hits.append({
                                    "url": action,
                                    "username": username,
                                    "password": password,
                                    "status_code": result.get("status_code"),
                                })
                                return hits
                        except Exception:
                            continue
            return hits
        except Exception:
            return []

    def _generate_random_params(self) -> str:
        """Generate random query parameters to avoid caching"""
        params = []
        for _ in range(random.randint(1, 3)):
            key = ''.join(random.choices(string.ascii_lowercase, k=5))
            value = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            params.append(f"{key}={value}")
        return "&".join(params)

    # ============================================================
    # Dedup cleanup (TTL)
    # ============================================================
    def _cleanup_dedup(self) -> None:
        now = time.time()
        ttl = self._dedup_ttl

        old_keys = [h for h, ts in self._seen_hashes.items() if now - ts > ttl]
        if old_keys:
            for h in old_keys:
                del self._seen_hashes[h]
            logger.info("[RealTimeWatcher] Dedup cleanup: removed %d expired entries", len(old_keys))

        self._last_cleanup = now

    # ============================================================
    # Add artifact (with throttling + TTL‑dedup)
    # ============================================================
    def _emit(self, module: str, target: str, result: Dict[str, Any], artifacts: List[Dict[str, Any]]):
        """
        Додає артефакт у список:
        - стабільний хеш (через JSON)
        - TTL‑дедуплікація
        - захист від вибуху артефактів
        """

        if len(artifacts) >= self._max_artifacts_per_cycle:
            return

        try:
            blob = {
                "module": module,
                "target": target,
                "result": result,
            }

            blob_json = json.dumps(blob, sort_keys=True, ensure_ascii=False)
            h = hash(blob_json)

            now = time.time()
            last_ts = self._seen_hashes.get(h)
            if last_ts and (now - last_ts) < self._dedup_ttl:
                return

            self._seen_hashes[h] = now
            artifacts.append(blob)

        except Exception as e:
            logger.exception("[RealTimeWatcher] Emit error: %s", e)

    # ============================================================
    # Main scan — ULTRA‑MAX
    # ============================================================
    def _scan_once(self) -> int:
        logger.info("[RealTimeWatcher] Scan cycle started for %s", self.url)
        self._cleanup_dedup()
        artifacts: List[Dict[str, Any]] = []

        try:
            # ============================================================
            # WAF/Bot Circumvention — adaptive retry fetch
            # ============================================================
            time.sleep(random.uniform(0.5, 2.0))

            proxies = None
            if hasattr(self, 'proxy_list') and self.proxy_list:
                proxy = random.choice(self.proxy_list)
                proxies = {'http': proxy, 'https': proxy}

            page = self._fetch_page(proxies=proxies)
            if not page.get("success"):
                self._record_network_noise("fetch", page.get("error"))
                logger.warning(
                    "[RealTimeWatcher] Fetch error: %s (attempts=%s, stats=%s)",
                    page.get("error"),
                    page.get("attempts"),
                    self.get_retry_stats(),
                )
                return 0

            if page.get("attempts", 1) > 1:
                logger.info(
                    "[RealTimeWatcher] Page fetched after %d adaptive attempt(s), "
                    "timeout=%s, locale=%s, stats=%s",
                    page.get("attempts"),
                    page.get("timeout_used"),
                    page.get("locale"),
                    self.get_retry_stats(),
                )

            html = page["html"]
            soup = page["soup"]
            js_urls = page["js_files"]
            headers = page["headers"]

            # ============================================================
            # Brute-force / login probing — controlled and low-noise
            # ============================================================
            try:
                brute_hits = self._bruteforce_login_targets(html)
                for hit in brute_hits:
                    self._emit("LoginBruteforce", hit.get("url", self.url), {
                        "category": "login_guessing",
                        "risk": "critical",
                        "url": hit.get("url"),
                        "username": hit.get("username"),
                        "password": hit.get("password"),
                        "status_code": hit.get("status_code"),
                    }, artifacts)
            except Exception:
                logger.debug("[RealTimeWatcher] Login brute-force probe skipped", exc_info=True)

        except Exception as exc:
            self._record_network_noise("page_process", exc)
            logger.exception("[RealTimeWatcher] Page processing error: %s", exc)
            return 0

        # ============================================================
        # Network events — розширений
        # ============================================================
        suspicious_domains = {
            "pastebin.com", "ghostbin.com", "hastebin.com",
            "api.telegram.org", "discordapp.com", "dropbox.com",
            "mega.nz", "ipinfo.io", "ifconfig.me",
            "binance.com", "coinbase.com", "crypto.com",
            "webhook.site", "requestbin.net", "ngrok.io",
            "telegram.me", "t.me",
        }

        for js in js_urls[:20]:
            low = js.lower()
            if any(dom in low for dom in suspicious_domains):
                self._emit("NetworkWatcher", js, {
                    "category": "suspicious_network",
                    "risk": "high",
                    "url": js,
                }, artifacts)

        # ============================================================
        # JSInspector — паралельний
        # ============================================================
        def fetch_js(url: str) -> Optional[str]:
            try:
                js_result = self._adaptive_request(
                    "GET",
                    url,
                    max_attempts=3,
                    base_timeout=4.0,
                    extra_headers={"Accept": "*/*", "Sec-Fetch-Dest": "script", "Sec-Fetch-Mode": "no-cors"},
                )
                if not js_result.get("success"):
                    return None
                content = js_result.get("content") or b""
                if not content:
                    return None
                with tempfile.NamedTemporaryFile(delete=False, suffix=".js") as tmp:
                    tmp.write(content)
                    return tmp.name
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(fetch_js, u): u for u in js_urls[:10]}

            for future in concurrent.futures.as_completed(futures):
                js_url = futures[future]
                tmp_path = future.result()
                if not tmp_path:
                    continue

                try:
                    from xss_security_gui.js_inspector import analyze_js_file
                    js_result = analyze_js_file(tmp_path)
                    os.remove(tmp_path)

                    if js_result:
                        self._emit("JSInspector", js_url, {
                            "category": "js_sensitive",
                            "risk": "medium",
                            "url": js_url,
                            "payload": js_result,
                        }, artifacts)
                except Exception:
                    continue

        # ============================================================
        # Secrets / PII — розширений
        # ============================================================
        secret_patterns = {
            # ============================
            # Google API Keys
            # ============================
            "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",

            # ============================
            # AWS Keys
            # ============================
            "aws_access_key": r"AKIA[0-9A-Z]{16}",
            "aws_secret_key": r"(?i)aws(.{0,20})?(secret|access)[^A-Za-z0-9]?([A-Za-z0-9/+=]{40})",

            # ============================
            # Slack Tokens
            # ============================
            "slack_token": r"xox[baprs]-[0-9A-Za-z\-]{10,48}",

            # ============================
            # Stripe Keys
            # ============================
            "stripe_live_key": r"sk_live_[0-9A-Za-z]{20,40}",
            "stripe_test_key": r"sk_test_[0-9A-Za-z]{20,40}",
            "stripe_publishable": r"pk_(live|test)_[0-9A-Za-z]{20,40}",

            # ============================
            # Twilio
            # ============================
            "twilio_sid": r"AC[0-9a-fA-F]{32}",
            "twilio_auth": r"[0-9a-fA-F]{32}",

            # ============================
            # GitHub Tokens
            # ============================
            "github_token": r"ghp_[0-9A-Za-z]{36}",
            "github_pat": r"gho_[0-9A-Za-z]{36}",

            # ============================
            # GitLab Tokens
            # ============================
            "gitlab_token": r"glpat-[0-9A-Za-z\-]{20,60}",

            # ============================
            # JWT Tokens
            # ============================
            "jwt_token": r"eyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+",

            # ============================
            # Azure Keys
            # ============================
            "azure_key": r"[A-Za-z0-9]{52}",
            "azure_conn_string": r"DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{88}",

            # ============================
            # Google OAuth / Refresh Tokens
            # ============================
            "google_oauth_refresh": r"1/[A-Za-z0-9_\-]{50,200}",
            "google_client_secret": r"(?i)client_secret[^A-Za-z0-9]?([A-Za-z0-9_\-]{20,100})",

            # ============================
            # Facebook / Meta Tokens
            # ============================
            "facebook_access_token": r"EAACEdEose0cBA[0-9A-Za-z]+",

            # ============================
            # Telegram Bot Tokens
            # ============================
            "telegram_bot_token": r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}",

            # ============================
            # Discord Bot Tokens
            # ============================
            "discord_bot_token": r"[A-Za-z0-9]{24}\.[A-Za-z0-9]{6}\.[A-Za-z0-9_\-]{27}",

            # ============================
            # Dropbox API Keys
            # ============================
            "dropbox_api_key": r"[A-Za-z0-9]{15}_[A-Za-z0-9]{32}",

            # ============================
            # PayPal
            # ============================
            "paypal_access_token": r"A21A[A-Za-z0-9\-]{50,100}",

            # ============================
            # SSH Private Keys
            # ============================
            "ssh_private_key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",

            # ============================
            # PEM Certificates
            # ============================
            "pem_certificate": r"-----BEGIN CERTIFICATE-----",

            # ============================
            # Private Keys (generic)
            # ============================
            "private_key": r"-----BEGIN PRIVATE KEY-----",

            # ============================
            # Cloudflare API Keys
            # ============================
            "cloudflare_api_key": r"[A-Za-z0-9]{37}",

            # ============================
            # Heroku API Keys
            # ============================
            "heroku_api_key": r"[0-9a-fA-F]{32}",

            # ============================
            # Firebase Keys
            # ============================
            "firebase_api_key": r"AIza[0-9A-Za-z\-_]{35}",

            # ============================
            # DigitalOcean Tokens
            # ============================
            "digitalocean_token": r"do_[A-Za-z0-9]{30}",

            # ============================
            # OpenAI API Keys
            # ============================
            "openai_api_key": r"sk-[A-Za-z0-9]{20,100}",

            # ============================
            # Mailgun Keys
            # ============================
            "mailgun_api_key": r"key-[0-9a-zA-Z]{32}",

            # ============================
            # SendGrid Keys
            # ============================
            "sendgrid_api_key": r"SG\.[A-Za-z0-9_\-]{20,200}",

            # ============================
            # Stripe Webhook Secrets
            # ============================
            "stripe_webhook_secret": r"whsec_[A-Za-z0-9]{20,100}",

            # ============================
            # Generic Bearer Tokens
            # ============================
            "bearer_token": r"Bearer\s+[A-Za-z0-9\.\-_]{10,500}",

            # ============================
            # Generic API Keys
            # ============================
            "generic_api_key": r"(?i)(api[_-]?key|secret)[^A-Za-z0-9]?([A-Za-z0-9]{16,64})",
        }

        for name, pattern in secret_patterns.items():
            for match in re.findall(pattern, html):
                self._emit("SecretScanner", self.url, {
                    "category": "secret_leak",
                    "risk": "high",
                    "type": name,
                    "value": match,
                }, artifacts)

        pii_patterns = {
            # ============================
            # EMAIL — максимально реалістичний
            # ============================
            "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(?:[A-Za-z]{2,63})\b",

            # ============================
            # PHONE — міжнародні, мобільні, VoIP, стаціонарні
            # ============================
            "phone": r"\b(?:\+?\d{1,3}[\s\-]?)?(?:\(?\d{2,4}\)?[\s\-]?)?\d{3,4}[\s\-]?\d{2,4}[\s\-]?\d{2,4}\b",

            # ============================
            # IPv4
            # ============================
            "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",

            # ============================
            # IPv6 — повна підтримка
            # ============================
            "ipv6": r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b",

            # ============================
            # IBAN — всі країни світу
            # ============================
            "iban": r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b",

            # ============================
            # CREDIT CARD — Visa, MasterCard, AmEx, Discover, UnionPay, JCB, Maestro
            # ============================
            "credit_card": (
                r"\b(?:"
                r"4[0-9]{12}(?:[0-9]{3})?"  # Visa
                r"|5[1-5][0-9]{14}"  # MasterCard
                r"|3[47][0-9]{13}"  # American Express
                r"|6(?:011|5[0-9]{2})[0-9]{12}"  # Discover
                r"|35[0-9]{14}"  # JCB
                r"|62[0-9]{14,17}"  # UnionPay
                r"|5[06789][0-9]{14}"  # Maestro
                r")\b"
            ),

            # ============================
            # CVV / CVC — 3 або 4 цифри
            # ============================
            "cvv": r"\b\d{3,4}\b",

            # ============================
            # CARD EXPIRY — MM/YY або MM/YYYY
            # ============================
            "card_expiry": r"\b(?:0[1-9]|1[0-2])\/(?:\d{2}|\d{4})\b",

            # ============================
            # FULL NAME — латиниця + кирилиця
            # ============================
            "full_name": (
                r"\b(?:"
                r"[A-Z][a-z]{2,30}\s[A-Z][a-z]{2,30}"  # John Smith
                r"|[A-Z][a-z]{2,30}\s[A-Z][a-z]{2,30}\s[A-Z][a-z]{2,30}"  # John Adam Smith
                r"|[А-Я][а-я]{2,30}\s[А-Я][а-я]{2,30}"  # Іван Петренко
                r"|[А-Я][а-я]{2,30}\s[А-Я][а-я]{2,30}\s[А-Я][а-я]{2,30}"  # Іван Іванович Петренко
                r")\b"
            ),

            # ============================
            # ADDRESS — спрощений формат
            # ============================
            "address": r"\b\d{1,5}\s+[A-Za-zА-Яа-я0-9\s\.,'-]{5,80}\b",

            # ============================
            # PASSPORT — міжнародні формати
            # ============================
            "passport": r"\b[A-Z]{1,3}[0-9]{6,9}\b",

            # ============================
            # NATIONAL ID — різні країни
            # ============================
            "national_id": r"\b[0-9]{6,12}\b",

            # ============================
            # MAC ADDRESS
            # ============================
            "mac": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",

            # ============================
            # UUID v1–v5
            # ============================
            "uuid": r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",

            # ============================
            # JWT токени
            # ============================
            "jwt": r"\beyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\b",

            # ============================
            # USERNAME — логіни
            # ============================
            "username": r"\b[a-zA-Z0-9._-]{3,32}\b",
        }

        for name, pattern in pii_patterns.items():
            for match in re.findall(pattern, html):
                self._emit("PIIScanner", self.url, {
                    "category": "pii_leak",
                    "risk": "medium",
                    "type": name,
                    "value": match,
                }, artifacts)

        # ============================================================
        # SSRF — ULTRA‑MAX
        # ============================================================
        ssrf_hosts = {
            # ============================
            # Loopback / Localhost
            # ============================
            "127.0.0.1",
            "localhost",
            "0.0.0.0",
            "::1",

            # ============================
            # Link-local IPv4
            # ============================
            "169.254.169.254",  # AWS metadata
            "169.254.169.253",  # Azure IMDS
            "169.254.42.42",  # GCP legacy
            "169.254.170.2",  # ECS metadata
            "169.254.123.123",  # Alibaba Cloud
            "169.254.",  # any link-local

            # ============================
            # Link-local IPv6
            # ============================
            "fe80::",  # IPv6 link-local

            # ============================
            # Cloud metadata endpoints
            # ============================
            "metadata.google.internal",
            "metadata.azure.internal",
            "metadata.oraclecloud.com",
            "metadata.digitalocean.com",
            "metadata.aliyun.com",
            "metadata.tencentcloudapi.com",
            "metadata.cloudsigma.com",
            "metadata.scaleway.com",
            "metadata.equinix.com",
            "metadata.hetzner.cloud",

            # ============================
            # Kubernetes internal
            # ============================
            "kubernetes.default",
            "kubernetes.default.svc",
            "kubernetes.default.svc.cluster.local",

            # ============================
            # Docker internal
            # ============================
            "docker.for.mac.localhost",
            "docker.for.win.localhost",

            # ============================
            # Private IPv4 ranges
            # ============================
            "10.",
            "192.168.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",

            # ============================
            # Internal admin panels
            # ============================
            "admin.",
            "internal.",
            "intranet.",
            "corp.",
            "dev.",
            "stage.",
            "local.",
            "lan.",
            "home.",
            "router.",
            "gateway.",
            "switch.",
            "firewall.",
            "nas.",
            "storage.",
            "vpn.",
            "mesh.",
            "service.",
        }

        urls = re.findall(
            r"https?://[A-Za-z0-9\.\-:%_\/\?\#=&]+",
            html,
            flags=re.IGNORECASE
        )

        for u in urls:
            low = u.lower()

            # Пряме попадання по хостам
            if any(h in low for h in ssrf_hosts):
                self._emit("SSRFFinder", self.url, {
                    "category": "ssrf_candidate",
                    "risk": "critical",
                    "url": u,
                }, artifacts)
                continue

            # IPv4 SSRF (приватні діапазони)
            if re.search(r"https?://(?:10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)", low):
                self._emit("SSRFFinder", self.url, {
                    "category": "ssrf_candidate",
                    "risk": "high",
                    "url": u,
                }, artifacts)
                continue

            # IPv6 SSRF (link-local)
            if "fe80:" in low or "::1" in low:
                self._emit("SSRFFinder", self.url, {
                    "category": "ssrf_candidate",
                    "risk": "high",
                    "url": u,
                }, artifacts)
                continue

            # Kubernetes internal
            if ".svc.cluster.local" in low:
                self._emit("SSRFFinder", self.url, {
                    "category": "ssrf_candidate",
                    "risk": "high",
                    "url": u,
                }, artifacts)
                continue

            # Internal admin panels
            if re.search(r"https?://(?:admin|internal|intranet|corp|dev|stage)\.", low):
                self._emit("SSRFFinder", self.url, {
                    "category": "ssrf_candidate",
                    "risk": "medium",
                    "url": u,
                }, artifacts)
                continue

        # ============================================================
        # Headers — розширений
        # ============================================================
        header_checks = {
            # ============================
            # CORE SECURITY HEADERS
            # ============================
            "Content-Security-Policy": "csp_header",
            "Content-Security-Policy-Report-Only": "csp_report_only",
            "X-Frame-Options": "clickjacking_protection",
            "X-XSS-Protection": "xss_protection",
            "X-Content-Type-Options": "mime_sniffing_protection",
            "Strict-Transport-Security": "hsts",
            "Referrer-Policy": "referrer_policy",
            "Permissions-Policy": "permissions_policy",
            "Cross-Origin-Resource-Policy": "corp",
            "Cross-Origin-Embedder-Policy": "coep",
            "Cross-Origin-Opener-Policy": "coop",

            # ============================
            # CORS HEADERS
            # ============================
            "Access-Control-Allow-Origin": "cors_allow_origin",
            "Access-Control-Allow-Credentials": "cors_allow_credentials",
            "Access-Control-Allow-Headers": "cors_allow_headers",
            "Access-Control-Allow-Methods": "cors_allow_methods",
            "Access-Control-Expose-Headers": "cors_expose_headers",
            "Access-Control-Max-Age": "cors_max_age",

            # ============================
            # FETCH METADATA HEADERS
            # ============================
            "Sec-Fetch-Site": "fetch_site",
            "Sec-Fetch-Mode": "fetch_mode",
            "Sec-Fetch-User": "fetch_user",
            "Sec-Fetch-Dest": "fetch_dest",

            # ============================
            # CSRF PROTECTION HEADERS
            # ============================
            "X-CSRF-Token": "csrf_token",
            "X-Request-ID": "request_id",
            "X-Requested-With": "requested_with",

            # ============================
            # PRIVACY / TRACKING HEADERS
            # ============================
            "P3P": "p3p_policy",
            "Tk": "tracking_status",

            # ============================
            # SERVER / TECHNOLOGY LEAKS
            # ============================
            "Server": "server_header",
            "X-Powered-By": "powered_by",
            "X-AspNet-Version": "aspnet_version",
            "X-AspNetMvc-Version": "aspnetmvc_version",

            # ============================
            # CACHE HEADERS
            # ============================
            "Cache-Control": "cache_control",
            "Pragma": "pragma",
            "Expires": "expires",

            # ============================
            # AUTH HEADERS
            # ============================
            "WWW-Authenticate": "www_authenticate",
            "Authorization": "authorization_header",

            # ============================
            # TLS / CERT HEADERS
            # ============================
            "Public-Key-Pins": "hpkp",
            "Public-Key-Pins-Report-Only": "hpkp_report_only",

            # ============================
            # REPORTING / LOGGING HEADERS
            # ============================
            "Report-To": "report_to",
            "NEL": "network_error_logging",

            # ============================
            # COOKIE SECURITY
            # ============================
            "Set-Cookie": "set_cookie",
        }

        for hname, category in header_checks.items():
            if hname in headers:
                value = headers[hname]

                risk = "info"

                # High-risk cases
                if hname == "X-Frame-Options" and value.lower() not in ("deny", "sameorigin"):
                    risk = "medium"

                if hname == "X-Content-Type-Options" and value.lower() != "nosniff":
                    risk = "medium"

                if hname == "Strict-Transport-Security" and "max-age" not in value.lower():
                    risk = "medium"

                if hname == "Content-Security-Policy" and "default-src" not in value.lower():
                    risk = "medium"

                if hname == "Access-Control-Allow-Origin" and value == "*":
                    risk = "high"

                if hname == "Set-Cookie":
                    if "secure" not in value.lower() or "httponly" not in value.lower():
                        risk = "high"
                    if "samesite" not in value.lower():
                        risk = "medium"

                self._emit("HeaderScanner", self.url, {
                    "category": category,
                    "risk": risk,
                    "value": value,
                }, artifacts)

        # ============================================================
        # Snapshot — розширений
        # ============================================================
        self._emit("RealTimeWatcher", self.url, {
            "category": "realtime_snapshot",
            "risk": "info",

            # ============================
            # Core page info
            # ============================
            "url": self.url,
            "html_len": len(html),
            "js_files": js_urls[:50],
            "headers": headers,
            "ssrf_urls": urls[:50],

            # ============================
            # Metrics
            # ============================
            "metrics": {
                "js_count": len(js_urls),
                "header_count": len(headers),
                "ssrf_count": len(urls),
                "entropy_html": round(sum(ord(c) for c in html[:5000]) / 5000, 2),
                "entropy_js": round(sum(len(j) for j in js_urls) / max(1, len(js_urls)), 2),
            },

            # ============================
            # Detected modules summary
            # ============================
            "detected": {
                "network": [
                    u for u in urls if any(h in u.lower() for h in ssrf_hosts)
                ],
                "secrets": [
                    match for name, pattern in secret_patterns.items()
                    for match in re.findall(pattern, html)
                ],
                "pii": [
                    match for name, pattern in pii_patterns.items()
                    for match in re.findall(pattern, html)
                ],
                "headers": {
                    hname: headers[hname]
                    for hname in header_checks.keys()
                    if hname in headers
                },
                "js_sensitive": [
                    js for js in js_urls[:10]
                ],
            },

            # ============================
            # Risk score (ULTRA‑MAX)
            # ============================
            "risk_score": {
                "ssrf": len([u for u in urls if any(h in u.lower() for h in ssrf_hosts)]) * 10,
                "secrets": len([
                    match for name, pattern in secret_patterns.items()
                    for match in re.findall(pattern, html)
                ]) * 8,
                "pii": len([
                    match for name, pattern in pii_patterns.items()
                    for match in re.findall(pattern, html)
                ]) * 5,
                "headers": len([
                    hname for hname in header_checks.keys()
                    if hname in headers
                ]) * 2,
                "js": len(js_urls) * 1,
            },

            # ============================
            # Performance
            # ============================
            "performance": {
                "scan_interval": self.interval,
                "max_artifacts": self._max_artifacts_per_cycle,
                "dedup_cache_size": len(self._seen_hashes),
            },
        }, artifacts)

        try:
            # ============================================================
            # Flush to Threat Intel
            # ============================================================
            for a in artifacts:
                # Ensure each artifact result has a timestamp before emitting to ThreatConnector
                try:
                    res = a.get("result") or {}
                    if "timestamp" not in res:
                        res["timestamp"] = time.time()
                        a["result"] = res
                except Exception:
                    pass

                try:
                    self.tic.emit(a["module"], a["target"], a["result"])
                except Exception:
                    # best-effort: try underlying tc if available
                    try:
                        if hasattr(self.tic, "tc") and hasattr(self.tic.tc, "emit"):
                            self.tic.tc.emit(a["module"], a["target"], a["result"])
                    except Exception:
                        self.logger = globals().get('logger')
                        if self.logger:
                            self.logger.debug("Failed to emit artifact to tic")

            logger.info("[RealTimeWatcher] Sent %d artifacts", len(artifacts))
            logger.info("[RealTimeWatcher] Cycle complete — %d artifacts", len(artifacts))

            # ============================================================
            # Threat Intel Integration (GUI only — DB already handled by emit)
            # ============================================================
            for art in artifacts:
                try:
                    # ensure result timestamp exists for GUI display
                    res = art.get("result") or {}
                    if "timestamp" not in res:
                        res["timestamp"] = time.time()
                        art["result"] = res
                except Exception:
                    pass

                try:
                    if hasattr(self.threat_tab, "add_threat"):
                        self.threat_tab.add_threat(art)
                except Exception as e:
                    logger.exception("[RealTimeWatcher] add_threat error: %s", e)

            logger.info("[RealTimeWatcher] Sent %d artifacts to Threat Analysis Tab (GUI)", len(artifacts))

            return len(artifacts)
        except Exception as exc:
            self._record_network_noise("scan_once", exc)
            logger.exception("[RealTimeWatcher] Scan cycle processing error: %s", exc)
            return 0







