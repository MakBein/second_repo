# xss_security_gui/core/stealth_engine.py
# ============================================================
# Stealth Engine 11.0 — Red Team Edition
# Full TLS Fingerprint Rotation + Header Engine + Dynamic Delay
# + IP Reputation Randomizer + Full Stealth Mode
# ============================================================

import random
import ssl
import time
import hashlib
import logging
from typing import Dict, Any, Optional, List, Tuple

logger = logging.getLogger(__name__)


# ============================================================
# 1. Stealth TLS Fingerprint Rotation
# ============================================================

class JA3Profile:
    """JA3 TLS fingerprint profile for browser impersonation."""

    def __init__(self, name: str, ciphers: str, extensions: List[int],
                 curves: List[int], point_formats: List[int],
                 tls_version: int = 0x0303):
        self.name = name
        self.ciphers = ciphers
        self.extensions = extensions
        self.curves = curves
        self.point_formats = point_formats
        self.tls_version = tls_version

    def build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers(self.ciphers)
        except ssl.SSLError:
            ctx.set_ciphers("DEFAULT")
        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
        return ctx

    @property
    def ja3_hash(self) -> str:
        raw = f"{self.tls_version},{self.ciphers},{self.extensions},{self.curves},{self.point_formats}"
        return hashlib.md5(raw.encode()).hexdigest()


# Pre-built JA3 profiles
CHROME_JA3 = JA3Profile(
    name="Chrome 124",
    ciphers=(
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
    ),
    extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
    curves=[29, 23, 24],
    point_formats=[0],
)

FIREFOX_JA3 = JA3Profile(
    name="Firefox 125",
    ciphers=(
        "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE+AESGCM:DHE+AESGCM:HIGH:!aNULL:!MD5"
    ),
    extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 51, 43, 13, 45, 28, 21],
    curves=[29, 23, 24, 25],
    point_formats=[0],
)

SAFARI_JA3 = JA3Profile(
    name="Safari 17.4",
    ciphers=(
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
        "DEFAULT@SECLEVEL=1"
    ),
    extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21],
    curves=[29, 23, 24],
    point_formats=[0],
)

RANDOMIZED_JA3 = JA3Profile(
    name="Randomized",
    ciphers="DEFAULT",
    extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 13],
    curves=[29, 23, 24],
    point_formats=[0],
)

ALL_JA3_PROFILES = [CHROME_JA3, FIREFOX_JA3, SAFARI_JA3, RANDOMIZED_JA3]


class TLSFingerprintRotator:
    """Rotates TLS fingerprints to bypass WAF JA3 detection."""

    def __init__(self):
        self._profiles = list(ALL_JA3_PROFILES)
        self._current_idx = 0
        self._waf_blocked_profiles: set = set()

    def get_next_context(self) -> Tuple[ssl.SSLContext, str]:
        available = [p for p in self._profiles if p.name not in self._waf_blocked_profiles]
        if not available:
            self._waf_blocked_profiles.clear()
            available = self._profiles
        profile = random.choice(available)
        self._current_idx = self._profiles.index(profile)
        return profile.build_ssl_context(), profile.name

    def get_impersonation_context(self, target_waf: str = "cloudflare") -> Tuple[ssl.SSLContext, str]:
        """Get best JA3 profile for bypassing specific WAF."""
        waf_best = {
            "cloudflare": CHROME_JA3,
            "akamai": FIREFOX_JA3,
            "perimeterx": CHROME_JA3,
            "imperva": SAFARI_JA3,
        }
        profile = waf_best.get(target_waf.lower(), random.choice(self._profiles))
        return profile.build_ssl_context(), profile.name

    def mark_blocked(self, profile_name: str):
        self._waf_blocked_profiles.add(profile_name)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "total_profiles": len(self._profiles),
            "blocked_profiles": list(self._waf_blocked_profiles),
            "current_index": self._current_idx,
        }


# ============================================================
# 2. Header Rotation Engine — 20+ Browser Profiles
# ============================================================

BROWSER_PROFILES: List[Dict[str, str]] = [
    # Chrome Windows
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
     "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
     "Sec-CH-UA-Platform": '"Windows"', "Sec-CH-UA-Mobile": "?0"},
    # Chrome macOS
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
     "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
     "Sec-CH-UA-Platform": '"macOS"', "Sec-CH-UA-Mobile": "?0"},
    # Chrome Linux
    {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
     "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
     "Sec-CH-UA-Platform": '"Linux"', "Sec-CH-UA-Mobile": "?0"},
    # Chrome Android
    {"User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
     "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
     "Sec-CH-UA-Platform": '"Android"', "Sec-CH-UA-Mobile": "?1"},
    # Edge Windows
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
     "Sec-CH-UA": '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
     "Sec-CH-UA-Platform": '"Windows"', "Sec-CH-UA-Mobile": "?0"},
    # Edge macOS
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
     "Sec-CH-UA": '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
     "Sec-CH-UA-Platform": '"macOS"', "Sec-CH-UA-Mobile": "?0"},
    # Firefox Windows
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
     "Sec-CH-UA": "", "Sec-CH-UA-Platform": "", "Sec-CH-UA-Mobile": ""},
    # Firefox macOS
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
     "Sec-CH-UA": "", "Sec-CH-UA-Platform": "", "Sec-CH-UA-Mobile": ""},
    # Firefox Linux
    {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
     "Sec-CH-UA": "", "Sec-CH-UA-Platform": "", "Sec-CH-UA-Mobile": ""},
    # Safari macOS
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
     "Sec-CH-UA": "", "Sec-CH-UA-Platform": "", "Sec-CH-UA-Mobile": ""},
    # Safari iOS
    {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
     "Sec-CH-UA": "", "Sec-CH-UA-Platform": "", "Sec-CH-UA-Mobile": ""},
    # Safari iPad
    {"User-Agent": "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
     "Sec-CH-UA": "", "Sec-CH-UA-Platform": "", "Sec-CH-UA-Mobile": ""},
    # Opera Windows
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
     "Sec-CH-UA": '"Chromium";v="124", "Opera";v="110", "Not-A.Brand";v="99"',
     "Sec-CH-UA-Platform": '"Windows"', "Sec-CH-UA-Mobile": "?0"},
    # Brave Linux
    {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
     "Sec-CH-UA": '"Chromium";v="124", "Brave";v="124", "Not-A.Brand";v="99"',
     "Sec-CH-UA-Platform": '"Linux"', "Sec-CH-UA-Mobile": "?0"},
    # Vivaldi Windows
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Vivaldi/6.7",
     "Sec-CH-UA": '"Chromium";v="124", "Vivaldi";v="6.7", "Not-A.Brand";v="99"',
     "Sec-CH-UA-Platform": '"Windows"', "Sec-CH-UA-Mobile": "?0"},
    # YaBrowser Windows
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 YaBrowser/24.4.0.0 Safari/537.36",
     "Sec-CH-UA": '"Chromium";v="124", "YaBrowser";v="24.4", "Not-A.Brand";v="99"',
     "Sec-CH-UA-Platform": '"Windows"', "Sec-CH-UA-Mobile": "?0"},
    # Samsung Internet
    {"User-Agent": "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36",
     "Sec-CH-UA": '"Chromium";v="121", "Samsung Internet";v="25.0", "Not-A.Brand";v="99"',
     "Sec-CH-UA-Platform": '"Android"', "Sec-CH-UA-Mobile": "?1"},
    # UC Browser Android
    {"User-Agent": "Mozilla/5.0 (Linux; U; Android 13; en-US; RMX3085 Build/TP1A.220905.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/100.0.4896.127 UCBrowser/16.4.8.1017 Mobile Safari/537.36",
     "Sec-CH-UA": "", "Sec-CH-UA-Platform": "", "Sec-CH-UA-Mobile": ""},
    # Chrome Windows 11
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
     "Sec-CH-UA": '"Chromium";v="125", "Google Chrome";v="125", "Not-A.Brand";v="99"',
     "Sec-CH-UA-Platform": '"Windows"', "Sec-CH-UA-Mobile": "?0"},
    # Firefox Android
    {"User-Agent": "Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0",
     "Sec-CH-UA": "", "Sec-CH-UA-Platform": "", "Sec-CH-UA-Mobile": ""},
    # Tor Browser
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
     "Sec-CH-UA": "", "Sec-CH-UA-Platform": "", "Sec-CH-UA-Mobile": ""},
    # Chrome ChromeOS
    {"User-Agent": "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
     "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
     "Sec-CH-UA-Platform": '"Chrome OS"', "Sec-CH-UA-Mobile": "?0"},
]

# Anti-bot headers injected randomly
ANTI_BOT_HEADERS = [
    {"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1"},
    {"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "same-origin"},
    {"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-User": "?1"},
    {"Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin"},
]

ANTI_FINGERPRINT_HEADERS = [
    {"DNT": "1", "Upgrade-Insecure-Requests": "1"},
    {"DNT": "0", "Upgrade-Insecure-Requests": "1"},
    {"Upgrade-Insecure-Requests": "1"},
    {"DNT": "1"},
]


class HeaderRotationEngine:
    """Rotates 20+ real browser header profiles with anti-bot/anti-fingerprint."""

    def __init__(self):
        self._profiles = list(BROWSER_PROFILES)
        self._used_indices: List[int] = []

    def get_headers(self, locale: str = "intl") -> Dict[str, str]:
        idx = random.randint(0, len(self._profiles) - 1)
        self._used_indices.append(idx)
        profile = self._profiles[idx].copy()

        # Remove empty Sec-CH-UA for Firefox/Safari
        profile = {k: v for k, v in profile.items() if v}

        # Base headers
        headers = {
            "Accept": random.choice([
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            ]),
            "Accept-Encoding": random.choice(["gzip, deflate, br", "gzip, deflate", "gzip, deflate, br, zstd"]),
            "Connection": "keep-alive",
        }
        headers.update(profile)

        # Anti-bot
        headers.update(random.choice(ANTI_BOT_HEADERS))

        # Anti-fingerprint
        headers.update(random.choice(ANTI_FINGERPRINT_HEADERS))

        return headers

    @property
    def profile_count(self) -> int:
        return len(self._profiles)


# ============================================================
# 3. Dynamic Delay Jitter — Human-like Behavior
# ============================================================

class DynamicDelayJitter:
    """Generates human-like random delays with adaptive throttling."""

    def __init__(self):
        self._consecutive_blocks = 0
        self._base_delay = 0.5
        self._max_delay = 30.0
        self._history: List[float] = []

    def get_delay(self) -> float:
        """Random pause with human-like jitter."""
        base = self._base_delay * (1 + self._consecutive_blocks * 0.5)
        # Human-like: normal distribution centered around base
        delay = max(0.1, random.gauss(base, base * 0.3))
        # Micro-pauses simulating reading/thinking
        if random.random() < 0.15:
            delay += random.uniform(1.0, 4.0)
        delay = min(delay, self._max_delay)
        self._history.append(delay)
        return delay

    def report_block(self):
        """Called when WAF block detected — increases delays."""
        self._consecutive_blocks += 1
        logger.debug("[DynamicDelay] Block detected, level=%d", self._consecutive_blocks)

    def report_success(self):
        """Called on successful request — slowly decreases delays."""
        self._consecutive_blocks = max(0, self._consecutive_blocks - 1)

    def adaptive_throttle(self, response_time: float):
        """Adjust base delay based on server response time."""
        if response_time > 5.0:
            self._base_delay = min(self._max_delay, self._base_delay * 1.5)
        elif response_time < 0.5 and self._consecutive_blocks == 0:
            self._base_delay = max(0.3, self._base_delay * 0.9)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "consecutive_blocks": self._consecutive_blocks,
            "base_delay": round(self._base_delay, 2),
            "avg_delay": round(sum(self._history[-20:]) / max(1, len(self._history[-20:])), 2),
            "total_delays": len(self._history),
        }


# ============================================================
# 4. IP Reputation Randomizer
# ============================================================

ACCEPT_LANGUAGE_POOL = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "pt-BR,pt;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8",
    "ko-KR,ko;q=0.9,en;q=0.8",
    "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "uk-UA,uk;q=0.9,ru;q=0.8,en;q=0.7",
    "pl-PL,pl;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.8",
    "nl-NL,nl;q=0.9,en;q=0.8",
    "tr-TR,tr;q=0.9,en;q=0.8",
    "ar-SA,ar;q=0.9,en;q=0.8",
    "hi-IN,hi;q=0.9,en;q=0.8",
    "sv-SE,sv;q=0.9,en;q=0.8",
]

TIMEZONE_POOL = [
    "America/New_York", "America/Chicago", "America/Los_Angeles", "America/Denver",
    "Europe/London", "Europe/Berlin", "Europe/Paris", "Europe/Moscow",
    "Europe/Kiev", "Europe/Warsaw", "Europe/Istanbul",
    "Asia/Tokyo", "Asia/Shanghai", "Asia/Seoul", "Asia/Kolkata",
    "Asia/Almaty", "Australia/Sydney", "America/Sao_Paulo",
]

SEC_CH_UA_POOL = [
    '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    '"Chromium";v="125", "Google Chrome";v="125", "Not-A.Brand";v="99"',
    '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
    '"Chromium";v="124", "Brave";v="124", "Not-A.Brand";v="99"',
    '"Chromium";v="124", "Opera";v="110", "Not-A.Brand";v="99"',
    '"Chromium";v="124", "Vivaldi";v="6.7", "Not-A.Brand";v="99"',
    '"Chromium";v="124", "YaBrowser";v="24.4", "Not-A.Brand";v="99"',
    '"Not_A Brand";v="8", "Chromium";v="124", "Google Chrome";v="124"',
]


class IPReputationRandomizer:
    """Randomizes Accept-Language, Timezone, Sec-CH-UA to mask IP reputation."""

    def __init__(self):
        self._lang_pool = list(ACCEPT_LANGUAGE_POOL)
        self._tz_pool = list(TIMEZONE_POOL)
        self._sec_ch_pool = list(SEC_CH_UA_POOL)

    def get_reputation_headers(self) -> Dict[str, str]:
        headers = {
            "Accept-Language": random.choice(self._lang_pool),
            "X-Timezone": random.choice(self._tz_pool),
        }
        sec_ch = random.choice(self._sec_ch_pool)
        if sec_ch:
            headers["Sec-CH-UA"] = sec_ch
        # Random X-Forwarded-For to diversify IP reputation
        headers["X-Forwarded-For"] = self._random_ip()
        return headers

    @staticmethod
    def _random_ip() -> str:
        """Generate random public-looking IP."""
        blocks = [
            (1, 126), (128, 191), (192, 223),
        ]
        block = random.choice(blocks)
        return f"{random.randint(*block)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


# ============================================================
# 5. Full Stealth Mode 11.0
# ============================================================

class StealthMode:
    """
    Full Stealth Mode 11.0 — combines all stealth components.
    Bypasses Cloudflare, Akamai, PerimeterX, Imperva.
    """

    def __init__(self):
        self.tls_rotator = TLSFingerprintRotator()
        self.header_engine = HeaderRotationEngine()
        self.delay_jitter = DynamicDelayJitter()
        self.ip_randomizer = IPReputationRandomizer()
        self._active = True
        self._detected_waf: Optional[str] = None
        self._evasion_stats = {
            "requests_sent": 0,
            "blocks_evaded": 0,
            "waf_detections": 0,
            "profiles_rotated": 0,
        }

    def activate(self):
        self._active = True
        logger.info("[StealthMode 11.0] ACTIVATED — Full fingerprint masking enabled")

    def deactivate(self):
        self._active = False

    @property
    def is_active(self) -> bool:
        return self._active

    def set_detected_waf(self, waf_name: str):
        """Set detected WAF for targeted evasion."""
        self._detected_waf = waf_name.lower() if waf_name else None
        self._evasion_stats["waf_detections"] += 1
        logger.info("[StealthMode] WAF detected: %s — switching to targeted evasion", waf_name)

    def get_stealth_context(self) -> Tuple[ssl.SSLContext, str]:
        """Get TLS context optimized for current WAF."""
        if self._detected_waf:
            return self.tls_rotator.get_impersonation_context(self._detected_waf)
        return self.tls_rotator.get_next_context()

    def get_stealth_headers(self, locale: str = "intl") -> Dict[str, str]:
        """Get full stealth headers combining all engines."""
        if not self._active:
            return {}

        headers = self.header_engine.get_headers(locale)
        rep_headers = self.ip_randomizer.get_reputation_headers()

        # Merge — header_engine profile takes priority for UA
        for k, v in rep_headers.items():
            if k not in headers or not headers[k]:
                headers[k] = v

        # WAF-specific evasion headers
        if self._detected_waf == "cloudflare":
            headers.setdefault("CF-Connecting-IP", IPReputationRandomizer._random_ip())
            headers.setdefault("CF-IPCountry", random.choice(["US", "GB", "DE", "FR", "NL"]))
        elif self._detected_waf == "akamai":
            headers.setdefault("True-Client-IP", IPReputationRandomizer._random_ip())
            headers.setdefault("Akamai-Origin-Hop", "1")
        elif self._detected_waf == "perimeterx":
            headers.setdefault("X-PX-BYPASS", "")
            headers.pop("X-PX-BYPASS", None)
        elif self._detected_waf == "imperva":
            headers.setdefault("X-Forwarded-Host", "cdn-cache.example.com")

        self._evasion_stats["requests_sent"] += 1
        self._evasion_stats["profiles_rotated"] += 1
        return headers

    def get_delay(self) -> float:
        """Get human-like delay."""
        return self.delay_jitter.get_delay() if self._active else 0.0

    def report_block(self):
        """Report WAF block — adapts all components."""
        self.delay_jitter.report_block()
        self._evasion_stats["blocks_evaded"] += 1

    def report_success(self):
        self.delay_jitter.report_success()

    def adaptive_throttle(self, response_time: float):
        self.delay_jitter.adaptive_throttle(response_time)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "stealth_active": self._active,
            "detected_waf": self._detected_waf,
            "tls": self.tls_rotator.stats,
            "delay": self.delay_jitter.stats,
            "evasion": self._evasion_stats,
            "browser_profiles_count": self.header_engine.profile_count,
        }
