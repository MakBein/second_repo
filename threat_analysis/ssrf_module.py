# xss_security_gui/threat_analysis/ssrf_module.py
"""
SSRFTester (ULTRA Hybrid 8.3 — Payload & Internal Intelligence)
---------------------------------------------------------------
• Advanced internal-host detection (IPv4/IPv6 loopback, RFC1918, link-local)
• Cloud metadata detection (AWS/GCP/Azure)
• Kubernetes/Consul/internal-domain detection
• SSRF-chain detection via hostname parsing
• RCE-aware indicators (Docker/Redis/Jenkins/AWS keys)
• Payload Intelligence (scheme/host/port/family/risk/notes)
• CRITICAL/HIGH/MEDIUM/INFO scoring
• Fully compatible with Threat Intel + SSRF Heatmap + Internal Hosts
"""

import re
import ipaddress
import requests
import socket
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from xss_security_gui.settings import settings
from xss_security_gui.threat_analysis.tester_base import TesterBase


class SSRFTester(TesterBase):
    """Модуль тестирования SSRF-уязвимостей."""

    def __init__(
        self,
        base_url: str,
        param: str,
        base_value: str,
        payloads: List[str],
        output_callback: Optional[callable] = None,
        timeout: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        body_indicators: Optional[List[str]] = None,
        header_indicators: Optional[List[str]] = None,
        internal_ports: Optional[List[int]] = None,
        fuzz_schemes: Optional[List[str]] = None,
    ):
        super().__init__("SSRF", base_url, param, base_value, {"default": payloads}, output_callback)

        self.timeout = timeout or settings.REQUEST_TIMEOUT
        self.headers = headers or {"User-Agent": settings.DEFAULT_USER_AGENT}

        self.body_indicators = body_indicators or [
            "169.254.", "metadata", "ec2", "internal", "localhost", "127.0.0.1",
            "google.internal", "azure", "gcp", "aws", "openstack",
            "file://", "ftp://", "unix://",
        ]

        self.header_indicators = header_indicators or [
            "via", "x-forwarded-for", "x-aws-", "metadata", "x-real-ip"
        ]

        # Regex for LAN
        self.lan_pattern = re.compile(
            r"(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+)"
        )

        # ports to scan on any internal host (default common services)
        self.internal_ports = internal_ports or [22, 80, 443, 3306, 5432, 6379, 8080]

        # which SSRF‑fuzzing schemes to generate
        self.fuzz_schemes = fuzz_schemes or ['gopher', 'dict', 'redis']

    # ---------------------------------------------------------
    # HTTP-запрос
    # ---------------------------------------------------------
    def send_request(self, full_value: str):
        try:
            response = requests.get(
                self.base_url,
                params={self.param: full_value},
                timeout=self.timeout,
                headers=self.headers,
                allow_redirects=True,
            )
            return response
        except Exception as e:
            return {"status": "blocked", "reason": str(e)}

    # ---------------------------------------------------------
    # Core test routine (TesterBase.run → _run_test)
    # ---------------------------------------------------------
    def _run_test(self, value: str) -> Dict[str, Any]:
        """
        Базовий тестовий цикл:
        • виконує HTTP‑запит з payload
        • аналізує відповідь
        • повертає уніфікований артефакт для Threat Intel
        """
        response = self.send_request(value)

        # Якщо запит заблоковано на рівні requests/мережі
        if not hasattr(response, "status_code"):
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "http_status": "blocked",
                "response_length": 0,
                "headers": {},
                "final_url": self.base_url,
                "redirects": [],
                "body_hit": False,
                "header_hit": False,
                "redirected_to_internal": False,
                "cloud_metadata": None,
                "lan_access": False,
                "ssrf_chain": False,
                "aws_keys_leak": False,
                "docker_api_detected": False,
                "redis_service_detected": False,
                "jenkins_console_detected": False,
                "payload_meta": None,
                "severity": "INFO",
                "threat_score": 10,
            }

        # 1. Визначаємо хост
        final_host = self._extract_hostname_safe(response.url, response.url)

        # 2. Порт-скан (якщо ти реалізуєш його самостійно)
        port_scan_res = []
        if final_host and self._is_internal_host(final_host):
            port_scan_res = self._scan_internal_ports(final_host)

        # 3. Аналіз відповіді
        result = self._analyze_response(
            text=response.text,
            headers_lower={k.lower(): v for k, v in response.headers.items()},
            response=response,
        )

        # 4. Додаємо порт-скан у результат
        result["internal_port_scan"] = port_scan_res
        result["category"] = "ssrf_candidate"
        result["risk"] = result.get("severity", "INFO")
        result["action"] = "ssrf_attack"
        result["final_host"] = final_host
        result["timestamp"] = datetime.now(timezone.utc).isoformat()

        return result

    # ---------------------------------------------------------
    # Internal host classifier helpers
    # ---------------------------------------------------------
    def _scan_internal_ports(self, host: str) -> List[int]:
        """
        Attempts a TCP connection to each port in ``self.internal_ports`` on *host*.
        Returns the list of ports that responded (i.e. are open).
        """
        open_ports = []
        for port in self.internal_ports:
            try:
                # tiny timeout – we only need a quick “open/closed” probe
                sock = socket.create_connection((host, port), timeout=1)
                sock.close()
                open_ports.append(port)
            except Exception:
                continue
        return open_ports

    def _extract_hostname_safe(self, loc: str, base_url: str) -> Optional[str]:
        """
        Коректно витягує hostname з Location, навіть якщо:
        - Location = "/path"
        - Location = "host/path"
        - Location = "//127.0.0.1/admin"
        - Location = "[::1]/admin"
        - Location = "fe80::1%eth0"
        """
        if not loc:
            return None

        loc = loc.strip()

        # 1) Scheme-relative URL: //127.0.0.1/admin
        if loc.startswith("//"):
            parsed = urlparse("http:" + loc)
            return parsed.hostname

        # 2) Absolute URL
        if "://" in loc:
            parsed = urlparse(loc)
            return parsed.hostname

        # 3) Host/path (no scheme)
        if "/" in loc and "." in loc.split("/")[0]:
            parsed = urlparse("http://" + loc)
            return parsed.hostname

        # 4) Pure IPv6 with brackets or zone-id
        host = loc
        host = host.lstrip("[").rstrip("]")
        if "%" in host:
            host = host.split("%")[0]

        # 5) If it's a valid IP — return it
        try:
            ipaddress.ip_address(host)
            return host
        except Exception:
            pass

        # 6) Relative path → fallback to base URL host
        parsed_base = urlparse(base_url)
        return parsed_base.hostname

    def _is_internal_host(self, host: str) -> bool:
        """Перевіряє, чи hostname/IP є внутрішнім."""
        if not host:
            return False

        host_l = host.lower()

        # IPv6 loopback
        if host_l in ("::1", "0:0:0:0:0:0:0:1"):
            return True

        # localhost
        if host_l in ("localhost", "localhost.localdomain"):
            return True

        # Kubernetes / Consul / internal domains
        if host_l.endswith(".svc") or host_l.endswith(".svc.cluster.local"):
            return True
        if host_l.endswith(".cluster.local"):
            return True
        if host_l.endswith(".consul"):
            return True
        if any(x in host_l for x in ("internal", "intranet", "corp")):
            return True

        # IPv4/IPv6 parsing
        try:
            clean = host_l.lstrip("[").rstrip("]")
            if "%" in clean:
                clean = clean.split("%")[0]

            ip = ipaddress.ip_address(clean)
            if ip.is_loopback or ip.is_private or ip.is_link_local:
                return True
        except Exception:
            pass

        # LAN regex fallback
        if self.lan_pattern.search(host_l):
            return True

        return False

    # ---------------------------------------------------------
    # Payload Intelligence (Detectify-style)
    # ---------------------------------------------------------
    def _extract_payload_meta(self, response) -> Optional[Dict[str, Any]]:
        try:
            req_url = response.request.url
            parsed_req = urlparse(req_url)
            qs = parse_qs(parsed_req.query)
            raw = qs.get(self.param, [None])[0]
        except Exception:
            raw = None

        if not raw:
            return None

        raw_str = str(raw)
        p = urlparse(raw_str)

        scheme = (p.scheme or "").lower()
        host = p.hostname
        port = p.port
        path = p.path or ""

        family = "Generic"
        risk = "INFO"
        notes = ""

        # FILE://
        if scheme == "file":
            family = "Local File Access"
            risk = "HIGH"
            notes = "Potential LFI via file://"
            if "/etc/passwd" in raw_str:
                risk = "CRITICAL"
                notes = "Attempt to read /etc/passwd"

        # GOPHER://
        elif scheme == "gopher":
            family = "Gopher SSRF"
            risk = "HIGH"
            notes = "Legacy protocol used for SSRF chaining, banner grabbing, Redis/SMTP abuse"
            if "_SET" in raw_str or "%0d%0aSET" in raw_str:
                risk = "CRITICAL"
                notes = "Potential Redis write via gopher"

        # DICT://
        elif scheme == "dict":
            family = "Dictionary Service"
            risk = "MEDIUM"
            notes = "DICT payload detected (classification only, no execution)"

        # REDIS://
        elif scheme == "redis":
            family = "Redis Internal"
            risk = "HIGH"
            notes = "Potential Redis exposure via redis://"
            if "config" in raw_str or "set" in raw_str:
                risk = "CRITICAL"
                notes = "Potential Redis write operation"

        # UNIX://
        elif scheme == "unix":
            family = "Unix Socket Access"
            risk = "HIGH"
            notes = "Potential access to local Unix sockets"

        # HTTP/HTTPS
        elif scheme in ("http", "https"):
            if host in ("127.0.0.1", "localhost"):
                family = "Loopback HTTP"
                risk = "HIGH"
                notes = "HTTP request to loopback"
            elif host and self.lan_pattern.search(host):
                family = "LAN HTTP"
                risk = "HIGH"
                notes = "HTTP request to RFC1918 address"
            elif host and host.startswith("169.254."):
                family = "Metadata HTTP"
                risk = "CRITICAL"
                notes = "Potential cloud metadata access"
            else:
                family = "HTTP/HTTPS"
                risk = "INFO"
                notes = "Standard HTTP/HTTPS payload"

        else:
            family = "Unknown"
            risk = "INFO"
            notes = "Unclassified or custom scheme"

        return {
            "raw": raw_str,
            "scheme": scheme or None,
            "target_host": host,
            "target_port": port,
            "path": path,
            "family": family,
            "risk": risk,
            "notes": notes,
        }

    def _generate_fuzz_payloads(self) -> List[str]:
        """
        Builds a list of payloads for the selected schemes.
        Example outputs:
            gopher://127.0.0.1/_GET_/ HTTP/1.1\r\nHost:127.0.0.1\r\n\r\n
            dict://127.0.0.1:8888/ANY
            redis://127.0.0.1:6379/CONFIG%20GET%20*
        """
        fuzz = []
        for scheme in self.fuzz_schemes:
            if scheme == 'gopher':
                fuzz.append('gopher://127.0.0.1/_GET_/ HTTP/1.1\r\nHost:127.0.0.1\r\n\r\n')
            elif scheme == 'dict':
                fuzz.append('dict://127.0.0.1:8888/ANY')
            elif scheme == 'redis':
                fuzz.append('redis://127.0.0.1:6379/CONFIG%20GET%20*')
        return fuzz

    # ---------------------------------------------------------
    # Анализ ответа
    # ---------------------------------------------------------
    def _analyze_response(
        self,
        text: str,
        headers_lower: Dict[str, str],
        response,
    ) -> Dict[str, Any]:

        body_lower = text.lower()
        url = response.url
        url_l = url.lower()

        # === Indicators ===
        body_hit = any(ind in body_lower for ind in self.body_indicators)
        header_hit = any(ind in headers_lower for ind in self.header_indicators)
        suspicious_status = response.status_code in (500, 502, 503, 504)

        # === Cloud metadata ===
        cloud_metadata = None
        if "169.254.169.254/latest/meta-data" in url_l:
            cloud_metadata = "AWS"
        elif "metadata.google.internal" in url_l:
            cloud_metadata = "GCP"
        elif "metadata/instance" in url_l and "api-version" in url_l:
            cloud_metadata = "Azure"

        # === LAN access ===
        lan_access = bool(self.lan_pattern.search(url_l))

        # === SSRF-chain via hostname parsing ===
        ssrf_chain = False
        redirected_to_internal = False

        if response.history:
            for h in response.history:
                loc = h.headers.get("Location", "")
                host = self._extract_hostname_safe(loc, response.url)

                if host and self._is_internal_host(host):
                    ssrf_chain = True
                    redirected_to_internal = True

        final_host = self._extract_hostname_safe(response.url, response.url)
        if final_host and self._is_internal_host(final_host):
            redirected_to_internal = True

        # === RCE-aware detectors (signature-based only) ===
        aws_keys_leak = any(
            kw in body_lower
            for kw in (
                "accesskeyid", "secretaccesskey", "sessiontoken",
                "aws_access_key_id", "aws_secret_access_key", "aws_session_token",
            )
        )

        docker_api_detected = (
            "docker" in headers_lower.get("server", "")
            or "docker-distribution-api-version" in headers_lower
            or ("/v1." in url_l and "docker" in body_lower)
        )

        redis_service_detected = (
            "redis" in body_lower
            or "redis_version" in body_lower
            or "redis" in headers_lower.get("server", "")
        )

        jenkins_console_detected = (
            "x-jenkins" in headers_lower
            or "<title>jenkins" in body_lower
            or ("jenkins" in body_lower and "/script" in body_lower)
        )

        # === Payload Intelligence ===
        payload_meta = self._extract_payload_meta(response)

        # === Risk scoring ===
        severity = self._assess_severity(
            body_hit=body_hit,
            header_hit=header_hit,
            suspicious_status=suspicious_status,
            redirected_to_internal=redirected_to_internal,
            cloud_metadata=cloud_metadata,
            lan_access=lan_access,
            ssrf_chain=ssrf_chain,
            aws_keys_leak=aws_keys_leak,
            docker_api_detected=docker_api_detected,
            redis_service_detected=redis_service_detected,
            jenkins_console_detected=jenkins_console_detected,
            payload_meta=payload_meta,
        )

        threat_score = self._compute_threat_score(
            severity=severity,
            payload_meta=payload_meta,
            cloud_metadata=cloud_metadata,
            aws_keys_leak=aws_keys_leak,
            docker_api_detected=docker_api_detected,
            redis_service_detected=redis_service_detected,
            jenkins_console_detected=jenkins_console_detected,
            redirected_to_internal=redirected_to_internal,
            lan_access=lan_access,
            ssrf_chain=ssrf_chain,
        )


        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "http_status": response.status_code,
            "response_length": len(response.text),
            "headers": dict(response.headers),
            "final_url": response.url,
            "redirects": [h.url for h in response.history],
            "body_hit": body_hit,
            "header_hit": header_hit,
            "redirected_to_internal": redirected_to_internal,
            "cloud_metadata": cloud_metadata,
            "lan_access": lan_access,
            "ssrf_chain": ssrf_chain,
            "aws_keys_leak": aws_keys_leak,
            "docker_api_detected": docker_api_detected,
            "redis_service_detected": redis_service_detected,
            "jenkins_console_detected": jenkins_console_detected,
            "payload_meta": payload_meta,
            "severity": severity,
            "threat_score": threat_score,
        }

    # ---------------------------------------------------------
    # Risk scoring
    # ---------------------------------------------------------
    @staticmethod
    def _compute_threat_score(
        severity: str,
        payload_meta: Optional[Dict[str, Any]],
        cloud_metadata: Optional[str],
        aws_keys_leak: bool,
        docker_api_detected: bool,
        redis_service_detected: bool,
        jenkins_console_detected: bool,
        redirected_to_internal: bool,
        lan_access: bool,
        ssrf_chain: bool,
    ) -> int:
        """
        ThreatScore 0–100 (Burp-style):
        • базується на severity
        • підсилюється ознаками SSRF/RCE/metadata
        """

        base = {
            "INFO": 10,
            "MEDIUM": 40,
            "HIGH": 70,
            "CRITICAL": 90,
        }.get(severity.upper(), 10)

        score = base

        # Payload bump
        payload_risk = (payload_meta or {}).get("risk", "INFO").upper()
        if payload_risk == "MEDIUM":
            score += 5
        elif payload_risk == "HIGH":
            score += 15
        elif payload_risk == "CRITICAL":
            score += 25

        # Internal / chain
        if redirected_to_internal:
            score += 10
        if lan_access:
            score += 5
        if ssrf_chain:
            score += 10

        # Metadata / RCE indicators (сигнатурно, без експлуатації)
        if cloud_metadata:
            score += 20
        if aws_keys_leak:
            score += 25
        if docker_api_detected:
            score += 15
        if redis_service_detected:
            score += 10
        if jenkins_console_detected:
            score += 15

        return max(0, min(100, score))


    @staticmethod
    def _assess_severity(
        body_hit: bool,
        header_hit: bool,
        suspicious_status: bool,
        redirected_to_internal: bool,
        cloud_metadata: Optional[str],
        lan_access: bool,
        ssrf_chain: bool,
        aws_keys_leak: bool,
        docker_api_detected: bool,
        redis_service_detected: bool,
        jenkins_console_detected: bool,
        payload_meta: Optional[Dict[str, Any]],
    ) -> str:

        payload_risk = (payload_meta or {}).get("risk", "INFO").upper()

        # CRITICAL — явні ознаки RCE/priv‑esc
        if cloud_metadata or aws_keys_leak or docker_api_detected or jenkins_console_detected:
            return "CRITICAL"
        if payload_risk == "CRITICAL":
            return "CRITICAL"

        # HIGH — внутрішні хости, SSRF-chain, Redis, високоризикові payload-и
        if redirected_to_internal or lan_access or ssrf_chain or redis_service_detected:
            return "HIGH"
        if payload_risk == "HIGH":
            return "HIGH"

        # MEDIUM — індикатори в тілі/заголовках/статусах або payload MEDIUM
        if body_hit or header_hit or suspicious_status or payload_risk == "MEDIUM":
            return "MEDIUM"

        return "INFO"



