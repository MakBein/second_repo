# xss_security_gui/network_checker.py
"""
NetworkChecker ULTRA 7.0
Встроенные сетевые проверки для XSS Security Suite:
- ICMP ping
- HTTP headers fingerprinting + WAF-fingerprinting
- TLS/SSL + HTTP/2 ALPN detector
- Port availability
- DNS analysis (A/AAAA/CNAME/MX/TXT)
Интеграция с settings.py и ThreatConnector
"""

import os
import re
import socket
import ssl
import subprocess
import threading
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from pythonping import ping

from xss_security_gui.settings import settings, LOG_DIR
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR

try:
    import whois
except ImportError:
    whois = None

try:
    import dns.resolver
except ImportError:
    dns = None


NETWORK_LOG_PATH = LOG_DIR / "network_checks.log"

# Типичные HTTP-пути утечки pg_hba.conf (только read-only проверка)
PG_HBA_PROBE_PATHS: List[str] = [
    "/pg_hba.conf",
    "/data/pg_hba.conf",
    "/postgresql/data/pg_hba.conf",
    "/var/lib/postgresql/data/pg_hba.conf",
    "/PostgreSQL/data/pg_hba.conf",
    "/backup/pg_hba.conf",
    "/backups/pg_hba.conf",
    "/config/pg_hba.conf",
    "/pg_hba.conf.bak",
    "/pg_hba.conf.old",
    "/pg_hba.conf~",
    "/.pg_hba.conf.swp",
]

PG_HBA_AUTH_METHODS = (
    "scram-sha-256",
    "md5",
    "password",
    "trust",
    "reject",
    "peer",
    "ident",
    "cert",
    "gss",
    "sspi",
    "ldap",
    "radius",
)

KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "WEB",
    81: "WEB",
    443: "WEB",
    465: "SMTPS",
    587: "SMTP",
    8080: "WEB",
    8443: "WEB",
    9443: "WEB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    3389: "RDP",
    5601: "Kibana",
    9200: "Elasticsearch",
    2375: "Docker",
    2376: "Docker TLS",
}

WEB_PORTS = {
    80: "http",
    81: "http",
    443: "https",
    8080: "http",
    8443: "https",
    9443: "https",
}

SERVICE_VALIDATORS = {
    22: "_validate_ssh",
    25: "_validate_smtp",
    465: "_validate_smtp",
    587: "_validate_smtp",
    6379: "_validate_redis",
    2375: "_validate_docker",
    2376: "_validate_docker_tls",
    9200: "_validate_elasticsearch",
    3389: "_validate_rdp",
    3306: "_validate_mysql",
    27017: "_validate_mongodb",
    5432: "_validate_postgresql",

}


def _hostname_from_target(target: str) -> str:
    target = target.strip()
    if "://" in target:
        host = urlparse(target).hostname
        return host or target.split("/")[0]
    return target.split("/")[0].split(":")[0]


def _normalize_scan_base(domain: str) -> List[str]:
    """Возвращает базовые URL для HTTP-проб (http + https)."""
    domain = domain.strip().rstrip("/")
    if domain.startswith(("http://", "https://")):
        return [domain]
    return [f"https://{domain}", f"http://{domain}"]


def is_pg_hba_content(text: str) -> bool:
    """Эвристика: похоже ли содержимое на pg_hba.conf."""
    if not text or len(text) < 20:
        return False
    low = text.lower()
    if "pg_hba" in low and any(k in low for k in ("host", "local", "hostssl")):
        return True
    return bool(re.search(r"^\s*(local|host|hostssl|hostnossl)\s+\S+", text, re.M | re.I))


def audit_pg_hba_content(text: str) -> Dict[str, Any]:
    """Read-only аудит методов аутентификации в pg_hba.conf."""
    methods: Dict[str, int] = {}
    rules: List[str] = []
    warnings: List[str] = []

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts and parts[0].lower() in {"local", "host", "hostssl", "hostnossl"}:
            rules.append(line[:240])
            if len(parts) >= 2:
                method = parts[-1].lower()
                if method in PG_HBA_AUTH_METHODS or method.isalpha():
                    methods[method] = methods.get(method, 0) + 1

    if methods.get("trust"):
        warnings.append("⚠️ Найден метод trust — подключение без пароля")
    if methods.get("md5") and not methods.get("scram-sha-256"):
        warnings.append("ℹ️ Используется устаревший md5 вместо scram-sha-256")
    if not methods:
        warnings.append("ℹ️ Строки HBA не распознаны — возможно частичная утечка")

    return {
        "rule_count": len(rules),
        "auth_methods": methods,
        "warnings": warnings,
        "sample_rules": rules[:8],
    }


# Примитивный WAF-фингерпринт по заголовкам/баннерам
WAF_SIGNATURES = {
    "cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
    "akamai": ["akamai", "akamai-ghost"],
    "imperva": ["incapsula", "x-iinfo", "x-cdn"],
    "f5_bigip": ["bigip", "x-waf", "x-wa-info"],
    "mod_security": ["mod_security", "modsecurity"],
    "sucuri": ["sucuri", "x-sucuri-id"],
}


def check_url_alive(url: str):
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name"),
                    "type": inp.get("type", "text")
                })
            forms.append({
                "action": form.get("action", ""),
                "method": form.get("method", "GET"),
                "inputs": inputs
            })
        return forms
    except Exception:
        return []


def check_ssl_valid(url: str):
    try:
        r = requests.get(url, timeout=5, verify=True)
        cert = r.raw.connection.sock.getpeercert()
        return True, cert.get("subject", "OK")
    except Exception as e:
        return False, str(e)


def resolve_redirects(url: str):
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        return r.url
    except Exception:
        return url


def measure_latency(url: str):
    try:
        start = time.time()
        requests.get(url, timeout=5)
        return (time.time() - start) * 1000
    except Exception:
        return -1



class NetworkChecker:
    def __init__(
        self,
        domain: str,
        gui_output=None,
        log_fn: Optional[Callable[[str], None]] = None,
    ):
        self.domain = domain.strip()

        self.target_ip = None

        try:

            self.target_ip = socket.gethostbyname(
                self.domain
            )

        except Exception:
            pass

        self.open_ports = []

        self.scan_context = {
            "open_ports": [],
            "confirmed_services": [],
            "possible_services": [],
            "service_evidence": {},

            "http": {},
            "tls": {},
            "icmp": {},
            "waf": {},

            "assessment_findings": [],

            "started_at": None,
            "finished_at": None,
            "scan_duration": None,
            "completed": False,
        }

        # ----------------------------------------------------
        # Runtime findings
        # ----------------------------------------------------

        self.target_hostname = None

        self.icmp_available = False

        self.tls_version = None

        self.alpn_protocol = None

        self.waf_detected = False

        self.waf_vendors = []

        self.csp_header = None

        self.hsts_enabled = False

        self.http_server = None

        self.content_type = None

        self.geoip_data = {}

        # ----------------------------------------------------
        # UI / logging
        # ----------------------------------------------------

        self.gui_output = gui_output

        self.log_fn = log_fn

        # ----------------------------------------------------
        # Settings
        # ----------------------------------------------------

        self.user_agent = settings.get(
            "crawl.user_agent",
            "Mozilla/5.0"
        )

        self.request_timeout = float(
            settings.get(
                "http.default_timeout",
                8
            )
        )

        self.connect_timeout = float(
            settings.get(
                "http.connect_timeout",
                5
            )
        )

        self.read_timeout = float(
            settings.get(
                "http.read_timeout",
                8
            )
        )

    # ---------------------------------------------------------
    # Thread-safe log
    # ---------------------------------------------------------
    def _log(self, text: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {text}"

        try:
            with open(NETWORK_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

        if self.log_fn:
            try:
                self.log_fn(line)
                return
            except Exception:
                pass

        if self.gui_output:
            try:
                self.gui_output.insert("end", line + "\n")
                self.gui_output.see("end")
            except Exception:
                print(line)
        else:
            print(line)

    # ---------------------------------------------------------
    # Run all checks async
    # ---------------------------------------------------------
    def run_all_checks(self):
        threading.Thread(
            target=self._worker,
            daemon=True
        ).start()

    def _safe_run(
            self,
            name: str,
            func
    ):

        try:

            func()

        except Exception as e:

            self._log(
                f"❌ {name}: {type(e).__name__}: {e}"
            )

    def _worker(self):

        scan_started = time.time()

        self.scan_context["started_at"] = (
            datetime.now().isoformat()
        )

        self.scan_context["completed"] = False

        self._log(
            f"🌐 Запуск сетевых проверок для "
            f"{self.domain}"
        )

        if self.target_ip:
            self._log(
                f"🎯 Target IP: "
                f"{self.target_ip}"
            )

        # -------------------------------------------------
        # Core Network Checks
        # -------------------------------------------------

        self._safe_run(
            "ICMP",
            self.check_icmp
        )

        self._safe_run(
            "HTTP",
            self.check_http
        )

        self._safe_run(
            "WAF",
            self.check_waf
        )

        self._safe_run(
            "TLS",
            self.check_tls_and_alpn
        )

        # -------------------------------------------------
        # TCP Scan
        # -------------------------------------------------

        self._safe_run(
            "PortScan",
            self.check_ports
        )

        # -------------------------------------------------
        # Service Discovery
        # -------------------------------------------------

        self._safe_run(
            "ServiceDiscovery",
            self.service_discovery
        )

        # -------------------------------------------------
        # Infrastructure
        # -------------------------------------------------

        self._safe_run(
            "DNS",
            self.check_dns
        )

        self._safe_run(
            "WHOIS",
            self.check_whois
        )

        self._safe_run(
            "GeoIP",
            self.check_asn_geoip
        )

        # -------------------------------------------------
        # PostgreSQL
        # -------------------------------------------------

        self._safe_run(
            "PostgreSQLAudit",
            self.check_pg_hba_exposure
        )

        # -------------------------------------------------
        # AI Assessment
        # -------------------------------------------------

        self._safe_run(
            "Assessment",
            self.network_assessment
        )

        duration = round(
            time.time() - scan_started,
            2
        )

        self.scan_context[
            "scan_duration"
        ] = duration

        self.scan_context["finished_at"] = (
            datetime.now().isoformat()
        )

        self.scan_context[
            "completed"
        ] = True

        self._log(
            f"⏱ Scan duration: "
            f"{duration:.2f}s"
        )

        self._log(
            "✔️ Сетевые проверки завершены."
        )


    # ---------------------------------------------------------
    # ICMP
    # ---------------------------------------------------------
    def check_icmp(self):

        icmp_available: bool = False

        avg_rtt: Optional[float] = None
        packet_loss: Optional[float] = None

        sent: Optional[int] = None
        lost: Optional[int] = None

        evidence: Dict[str, Any] = {
            "reachable": False,
            "avg_rtt_ms": None,
            "packet_loss": None,
            "packets_sent": None,
            "packets_lost": None,
            "method": "pythonping",
        }

        try:

            response = ping(
                self.domain,
                count=3,
                timeout=2,
            )

            try:

                avg_rtt = round(
                    float(response.rtt_avg_ms),
                    2,
                )

            except Exception:

                avg_rtt = None

            try:

                sent = getattr(
                    response,
                    "packets_sent",
                    None,
                )

                lost = getattr(
                    response,
                    "packets_lost",
                    None,
                )

                if (
                        sent is not None
                        and lost is not None
                        and sent > 0
                ):

                    packet_loss = round(
                        (lost / sent) * 100,
                        1,
                    )

                else:

                    packet_loss = None

            except Exception:

                packet_loss = None

            # --------------------------------------
            # Fallback for pythonping versions
            # --------------------------------------

            if packet_loss is None:

                try:

                    icmp_available = bool(
                        response.success()
                    )

                except Exception:

                    icmp_available = False

                packet_loss = (
                    0.0
                    if icmp_available
                    else 100.0
                )

            else:

                icmp_available = (
                        packet_loss < 100
                )

        except Exception:

            evidence["method"] = "system_ping"

            cmd = (
                ["ping", "-n", "3", self.domain]
                if os.name == "nt"
                else ["ping", "-c", "3", self.domain]
            )

            try:

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=8,
                )

                output = (
                        result.stdout or ""
                )

                # =====================================
                # Windows
                # =====================================

                if os.name == "nt":

                    sent_match = re.search(
                        r"Sent\s*=\s*(\d+)",
                        output,
                        re.I,
                    )

                    lost_match = re.search(
                        r"Lost\s*=\s*(\d+)",
                        output,
                        re.I,
                    )

                    if (
                            sent_match
                            and lost_match
                    ):

                        sent = int(
                            sent_match.group(1)
                        )

                        lost = int(
                            lost_match.group(1)
                        )

                        if sent > 0:
                            packet_loss = round(
                                (
                                        lost / sent
                                ) * 100,
                                1,
                            )

                    rtt_match = re.search(
                        r"Average\s*=\s*(\d+)ms",
                        output,
                        re.I,
                    )

                    if rtt_match:
                        avg_rtt = float(
                            rtt_match.group(1)
                        )

                # =====================================
                # Linux/macOS
                # =====================================

                else:

                    loss_match = re.search(
                        r"(\d+(?:\.\d+)?)%\s*packet loss",
                        output,
                        re.I,
                    )

                    if loss_match:
                        packet_loss = float(
                            loss_match.group(1)
                        )

                    rtt_match = re.search(
                        r"min/avg/max(?:/mdev)?"
                        r"\s*=\s*"
                        r"[\d\.]+/"
                        r"([\d\.]+)/",
                        output,
                        re.I,
                    )

                    if rtt_match:
                        avg_rtt = float(
                            rtt_match.group(1)
                        )

                if packet_loss is None:
                    packet_loss = 100.0

                icmp_available = (
                        packet_loss < 100
                )

            except Exception as e:

                status = (
                    f"❌ Ошибка ICMP: {e}"
                )

                self._log(status)

                THREAT_CONNECTOR.emit(
                    module="NetworkChecker",
                    target=self.domain,
                    result={
                        "check": "icmp",
                        "status": status,
                    },
                )

                return

        # ===========================================
        # Status generation
        # ===========================================

        if packet_loss >= 100:

            status = (
                "⚠️ ICMP заблокирован "
                "или нет ответа"
            )

        elif packet_loss > 0:

            status = (
                f"⚠️ ICMP частично доступен"
                f" | Loss={packet_loss}%"
                f" | AvgRTT={avg_rtt}ms"
            )

        else:

            if avg_rtt is not None:

                status = (
                    f"✅ ICMP доступен"
                    f" | AvgRTT={avg_rtt}ms"
                )

            else:

                status = (
                    "✅ ICMP доступен"
                )

        self.icmp_available = (
            icmp_available
        )

        self.scan_context["icmp"] = {
            "reachable": icmp_available,
            "avg_rtt_ms": avg_rtt,
            "packet_loss": packet_loss,
            "packets_sent": sent,
            "packets_lost": lost,
        }

        evidence["reachable"] = (
            icmp_available
        )

        evidence["avg_rtt_ms"] = (
            avg_rtt
        )

        evidence["packet_loss"] = (
            packet_loss
        )

        evidence["packets_sent"] = (
            sent
        )

        evidence["packets_lost"] = (
            lost
        )

        self._log(status)

        THREAT_CONNECTOR.emit(
            module="NetworkChecker",
            target=self.domain,
            result={
                "check": "icmp",
                "status": status,
                "reachable": icmp_available,
                "avg_rtt_ms": avg_rtt,
                "packet_loss": packet_loss,
                "packets_sent": sent,
                "packets_lost": lost,
                "evidence": evidence,
            },
        )

    # ---------------------------------------------------------
    # HTTP HEAD fingerprint
    # ---------------------------------------------------------
    def check_http(self):

        self.scan_context.setdefault(
            "http",
            {}
        )

        headers = {
            "User-Agent": self.user_agent
        }

        for scheme in ("http", "https"):

            try:

                try:

                    r = requests.head(
                        f"{scheme}://{self.domain}",
                        timeout=8,
                        headers=headers,
                        allow_redirects=True,
                    )

                    if r.status_code in (
                            403,
                            405,
                            501,
                    ):
                        raise Exception()

                except Exception:

                    r = requests.get(
                        f"{scheme}://{self.domain}",
                        timeout=8,
                        headers=headers,
                        allow_redirects=True,
                        stream=True,
                    )

                server = r.headers.get(
                    "Server",
                    "Unknown",
                )

                csp = r.headers.get(
                    "Content-Security-Policy"
                )

                hsts = r.headers.get(
                    "Strict-Transport-Security"
                )

                xfo = r.headers.get(
                    "X-Frame-Options"
                )

                xcto = r.headers.get(
                    "X-Content-Type-Options"
                )

                referrer = r.headers.get(
                    "Referrer-Policy"
                )

                permissions = r.headers.get(
                    "Permissions-Policy"
                )

                content_type = r.headers.get(
                    "Content-Type",
                    "Unknown",
                )

                cookies = r.headers.get_all(
                    "Set-Cookie",
                    []
                ) if hasattr(
                    r.headers,
                    "get_all"
                ) else [
                    r.headers.get(
                        "Set-Cookie",
                        ""
                    )
                ]

                self.scan_context[
                    "http"
                ][scheme] = {

                    "status_code": r.status_code,

                    "server": server,

                    "csp": csp,

                    "hsts": hsts,

                    "xfo": xfo,

                    "xcto": xcto,

                    "referrer_policy": referrer,

                    "permissions_policy": permissions,

                    "content_type": content_type,
                }

                if scheme == "https":
                    self.csp_header = csp

                details = (
                    f"{scheme.upper()}/"
                    f"{r.status_code} "
                    f"{r.reason}"
                    f" | Server={server}"
                    f" | CSP={'YES' if csp else 'NO'}"
                    f" | HSTS={'YES' if hsts else 'NO'}"
                    f" | XFO={'YES' if xfo else 'NO'}"
                    f" | XCTO={'YES' if xcto else 'NO'}"
                    f" | Content-Type={content_type}"
                )

                self._log(details)

                for cookie in cookies:

                    if not cookie:
                        continue

                    attrs = []

                    low = cookie.lower()

                    if "secure" in low:
                        attrs.append("Secure")

                    if "httponly" in low:
                        attrs.append("HttpOnly")

                    same_site = re.search(
                        r"samesite=([^;]+)",
                        cookie,
                        re.I,
                    )

                    if same_site:
                        attrs.append(
                            f"SameSite="
                            f"{same_site.group(1)}"
                        )

                    parts = cookie.split(
                        ";",
                        1,
                    )

                    self._log(
                        f"🍪 {scheme.upper()} | "
                        f"{parts[0]}"
                        f" | "
                        f"{', '.join(attrs)}"
                    )

                THREAT_CONNECTOR.emit(
                    module="NetworkChecker",
                    target=self.domain,
                    result={
                        "check": f"{scheme}_http",
                        "status": details,
                        "server": server,
                        "content_type": content_type,
                        "csp": bool(csp),
                        "hsts": bool(hsts),
                    },
                )

            except Exception as e:

                self._log(
                    f"❌ "
                    f"{scheme.upper()} "
                    f"error: {e}"
                )

    # ---------------------------------------------------------
    # WAF fingerprinting (по HTTP-ответу)
    # ---------------------------------------------------------
    def check_waf(self):

        waf_detected = []

        self.scan_context.setdefault(
            "waf",
            {}
        )

        headers = {
            "User-Agent": self.user_agent
        }

        for scheme in (
                "http",
                "https",
        ):

            try:

                r = requests.get(
                    f"{scheme}://{self.domain}",
                    timeout=10,
                    headers=headers,
                    allow_redirects=True,
                )

                fingerprint = " ".join(

                    [
                        r.headers.get(
                            "Server",
                            ""
                        ),

                        r.headers.get(
                            "Set-Cookie",
                            ""
                        ),

                        r.headers.get(
                            "X-Powered-By",
                            ""
                        ),

                        r.headers.get(
                            "CF-Ray",
                            ""
                        ),

                        r.headers.get(
                            "X-Sucuri-ID",
                            ""
                        ),

                        r.headers.get(
                            "X-Iinfo",
                            ""
                        ),

                        r.headers.get(
                            "Server-Timing",
                            ""
                        ),
                    ]
                ).lower()

                local_hits = []

                for (
                        waf_name,
                        signatures
                ) in WAF_SIGNATURES.items():

                    if any(
                            sig.lower()
                            in fingerprint
                            for sig in signatures
                    ):
                        local_hits.append(
                            waf_name
                        )

                        waf_detected.append(
                            waf_name
                        )

                self.scan_context[
                    "waf"
                ][scheme] = {
                    "status_code":
                        r.status_code,
                    "detections":
                        local_hits,
                }

                if local_hits:

                    self._log(
                        f"🛡 {scheme.upper()}"
                        f": "
                        f"{', '.join(local_hits)}"
                    )

                else:

                    self._log(
                        f"ℹ️ {scheme.upper()}: "
                        f"Явных признаков "
                        f"WAF не обнаружено"
                    )

            except Exception as e:

                self._log(
                    f"❌ {scheme.upper()} "
                    f"WAF error: {e}"
                )

        waf_detected = sorted(
            set(waf_detected)
        )

        self.waf_detected = bool(
            waf_detected
        )

        self.scan_context[
            "waf_detected"
        ] = waf_detected

        THREAT_CONNECTOR.emit(
            module="NetworkChecker",
            target=self.domain,
            result={
                "check":
                    "waf_detection",
                "detected":
                    waf_detected,
                "count":
                    len(waf_detected),
            },
        )

    # ---------------------------------------------------------
    # TLS/SSL + HTTP/2 ALPN
    # ---------------------------------------------------------
    def check_tls_and_alpn(self):

        tls_version = None
        alpn = None

        self.scan_context.setdefault(
            "tls",
            {}
        )

        try:

            ctx = ssl.create_default_context()

            try:

                ctx.set_alpn_protocols(
                    [
                        "h2",
                        "http/1.1",
                    ]
                )

            except Exception:
                pass

            with socket.create_connection(
                    (
                            self.domain,
                            443,
                    ),
                    timeout=8,
            ) as sock:

                with ctx.wrap_socket(
                        sock,
                        server_hostname=self.domain,
                ) as ssock:

                    # ==========================================
                    # TLS Version
                    # ==========================================

                    tls_version = (
                            ssock.version()
                            or "unknown"
                    )

                    self.tls_version = (
                        tls_version
                    )

                    # ==========================================
                    # ALPN
                    # ==========================================

                    try:

                        alpn = (
                                ssock.selected_alpn_protocol()
                                or "unknown"
                        )

                    except Exception:

                        alpn = "unknown"

                    # ==========================================
                    # Cipher
                    # ==========================================

                    try:

                        cipher = (
                            ssock.cipher()
                        )

                        cipher_name = (
                            cipher[0]
                            if cipher
                            else "Unknown"
                        )

                    except Exception:

                        cipher_name = (
                            "Unknown"
                        )

                    # ==========================================
                    # Certificate
                    # ==========================================

                    cert = (
                            ssock.getpeercert()
                            or {}
                    )

                    # ------------------------------------------
                    # Subject
                    # ------------------------------------------

                    subject_parts = []

                    for item in cert.get(
                            "subject",
                            [],
                    ):

                        for pair in item:

                            if (
                                    isinstance(
                                        pair,
                                        tuple,
                                    )
                                    and len(pair) == 2
                            ):
                                key, value = pair

                                subject_parts.append(
                                    f"{key}={value}"
                                )

                    subject = (
                        ", ".join(
                            subject_parts
                        )
                        if subject_parts
                        else "Unknown"
                    )

                    # ------------------------------------------
                    # Issuer
                    # ------------------------------------------

                    issuer_parts = []

                    for item in cert.get(
                            "issuer",
                            [],
                    ):

                        for pair in item:

                            if (
                                    isinstance(
                                        pair,
                                        tuple,
                                    )
                                    and len(pair) == 2
                            ):
                                key, value = pair

                                issuer_parts.append(
                                    f"{key}={value}"
                                )

                    issuer = (
                        ", ".join(
                            issuer_parts
                        )
                        if issuer_parts
                        else "Unknown"
                    )

                    # ------------------------------------------
                    # Expiry
                    # ------------------------------------------

                    not_after = cert.get(
                        "notAfter"
                    )

                    exp_str = "Unknown"
                    days_left = None

                    try:

                        expiry = datetime.strptime(
                            not_after,
                            "%b %d %H:%M:%S %Y %Z",
                        )

                        exp_str = (
                            expiry.strftime(
                                "%Y-%m-%d"
                            )
                        )

                        days_left = (
                                expiry
                                - datetime.utcnow()
                        ).days

                    except Exception:
                        pass

                    # ------------------------------------------
                    # SAN
                    # ------------------------------------------

                    san_list = []

                    try:

                        san_entries = cert.get(
                            "subjectAltName",
                            []
                        )

                        for san_type, san_value in san_entries:

                            if (
                                    san_type.lower()
                                    == "dns"
                            ):
                                san_list.append(
                                    san_value
                                )

                    except Exception:
                        pass

                    # ==========================================
                    # Risk indicators
                    # ==========================================

                    warnings = []

                    if tls_version in {
                        "TLSv1",
                        "TLSv1.1",
                    }:
                        warnings.append(
                            "Legacy TLS version"
                        )

                    if (
                            days_left is not None
                            and days_left < 30
                    ):
                        warnings.append(
                            "Certificate expires soon"
                        )

                    # ==========================================
                    # Save for AI assessment
                    # ==========================================

                    self.scan_context[
                        "tls"
                    ] = {

                        "version":
                            tls_version,

                        "alpn":
                            alpn,

                        "cipher":
                            cipher_name,

                        "subject":
                            subject,

                        "issuer":
                            issuer,

                        "expiry":
                            exp_str,

                        "days_left":
                            days_left,

                        "warnings":
                            warnings,

                        "san":
                            san_list[:15],
                    }

                    details = (
                        f"🧪 TLS={tls_version}, "
                        f"ALPN={alpn}, "
                        f"Cipher={cipher_name}, "
                        f"CN={subject}, "
                        f"Expiry={exp_str}"
                    )

                    if days_left is not None:
                        details += (
                            f", DaysLeft={days_left}"
                        )

                    if warnings:
                        details += (
                                " | Warnings="
                                + ",".join(
                            warnings
                        )
                        )

        except Exception as e:

            details = (
                f"❌ Ошибка TLS/ALPN: {e}"
            )

        self._log(details)

        THREAT_CONNECTOR.emit(
            module="NetworkChecker",
            target=self.domain,
            result={
                "check": "tls_alpn",
                "status": details,
                "tls_version": tls_version,
                "alpn": alpn,
                "tls_data": self.scan_context.get(
                    "tls",
                    {},
                ),
            },
        )

    # ---------------------------------------------------------
    # Port scan
    # ---------------------------------------------------------
    def check_ports(self):

        self.open_ports = []

        ports = [
            80,
            443,
            8080,
            8443,
            9443,
            22,
            21,
            25,
            465,
            587,
            53,
            1433,
            1521,
            3306,
            5432,
            6379,
            27017,
            3389,
            5900,
            9200,
            5601,
            2375,
            2376,
        ]

        self._log("")
        self._log("🔍 Starting TCP Port Scan")

        web_count = 0
        service_count = 0

        for port in ports:

            try:

                start = time.time()

                sock = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                )

                sock.settimeout(2)

                target = (
                        self.target_ip
                        or self.domain
                )

                result = sock.connect_ex(
                    (
                        target,
                        port,
                    )
                )

                rtt = (
                              time.time() - start
                      ) * 1000

                sock.close()

                if result == 0:

                    self.open_ports.append(
                        port
                    )

                    service = KNOWN_SERVICES.get(
                        port,
                        "Unknown"
                    )

                    category = (
                        "web"
                        if port in WEB_PORTS
                        else "service"
                    )

                    if category == "web":
                        web_count += 1
                    else:
                        service_count += 1

                    status = (
                        f"🟡 TCP Reachable"
                        f" | Port={port}"
                        f" | Category={category}"
                        f" | Service={service}"
                        f" | RTT={rtt:.1f}ms"
                    )

                else:

                    continue

            except Exception:
                continue

            self._log(status)

            THREAT_CONNECTOR.emit(
                module="NetworkChecker",
                target=self.domain,
                result={
                    "check": "port_scan",
                    "port": port,
                    "reachable": True,
                    "service": KNOWN_SERVICES.get(
                        port,
                        "Unknown"
                    ),
                },
            )

        self.scan_context["open_ports"] = list(
            self.open_ports
        )

        self._log("")
        self._log("=" * 60)
        self._log("📊 Port Scan Summary")
        self._log("=" * 60)

        self._log(
            f"TCP Reachable : "
            f"{len(self.open_ports)}"
        )

        self._log(
            f"Web Ports     : "
            f"{web_count}"
        )

        self._log(
            f"Service Ports : "
            f"{service_count}"
        )

        if self.open_ports:
            self._log(
                "Open Ports    : "
                + ", ".join(
                    map(
                        str,
                        self.open_ports
                    )
                )
            )

    # ---------------------------------------------------------
    # DNS analysis (A/AAAA/CNAME/MX/TXT)
    # ---------------------------------------------------------
    def check_dns(self):
        if dns is None:
            status = "⚠️ DNS-анализ недоступен: модуль dnspython не установлен"
            self._log(status)
            THREAT_CONNECTOR.emit(
                module="NetworkChecker",
                target=self.domain,
                result={"check": "dns", "status": status},
            )
            return

        records_summary = []

        def _resolve(record_type: str):
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                values = [str(rdata) for rdata in answers]
                return values
            except Exception:
                return []

        record_types = ["A", "AAAA", "CNAME", "MX", "TXT"]
        dns_result = {}

        for rtype in record_types:
            values = _resolve(rtype)
            dns_result[rtype] = values
            if values:
                records_summary.append(f"{rtype}={'; '.join(values)}")

        if records_summary:
            status = "🧬 DNS: " + " | ".join(records_summary)
        else:
            status = "⚠️ DNS-записи не найдены или недоступны"

        self._log(status)
        THREAT_CONNECTOR.emit(
            module="NetworkChecker",
            target=self.domain,
            result={"check": "dns", "status": status, "records": dns_result},
        )

    # ---------------------------------------------------------
    # WHOIS analysis
    # ---------------------------------------------------------

    def check_whois(self):
        # 1) Модуль може бути не встановлений
        if whois is None:
            status = "⚠️ WHOIS недоступен: пакет python-whois не установлен"
            self._log(status)
            THREAT_CONNECTOR.emit(
                module="NetworkChecker",
                target=self.domain,
                result={"check": "whois", "status": status},
            )
            return

        try:
            # 2) Захист від зависань: WHOIS іноді може дуже довго відповідати
            # Якщо у тебе є внешний timeout-обертка — краще викликати через неї
            data = whois.whois(self.domain)

            # 3) WHOIS іноді повертає dict, іноді об’єкт
            def _get(field):
                try:
                    if isinstance(data, dict):
                        return data.get(field)
                    return getattr(data, field, None)
                except Exception:
                    return None

            def _normalize_date(value):
                # Може бути datetime, список, str, None
                try:
                    if isinstance(value, (list, tuple)) and value:
                        value = value[0]
                    return str(value) if value else "Unknown"
                except Exception:
                    return "Unknown"

            registrar = _get("registrar") or "Unknown"
            country = _get("country") or "Unknown"
            created = _normalize_date(_get("creation_date"))
            expires = _normalize_date(_get("expiration_date"))

            status = (
                f"📄 WHOIS: Registrar={registrar}, Country={country}, "
                f"Created={created}, Expires={expires}"
            )

        except Exception as e:
            status = f"❌ Ошибка WHOIS: {e}"

        self._log(status)
        THREAT_CONNECTOR.emit(
            module="NetworkChecker",
            target=self.domain,
            result={"check": "whois", "status": status},
        )

    # ---------------------------------------------------------
    # ASN / GeoIP
    # ---------------------------------------------------------
    def check_asn_geoip(self):
        try:
            ip = socket.gethostbyname(self.domain)
            r = requests.get(f"https://ipwho.is/{ip}", timeout=5).json()

            if not r.get("success", False):
                status = f"⚠️ GeoIP: сервис ipwho.is не смог обработать IP {ip}"
            else:
                country = r.get("country", "Unknown")
                city = r.get("city", "Unknown")

                # Coordinates + accuracy
                latitude = r.get("latitude")
                longitude = r.get("longitude")
                accuracy = r.get("location", {}).get("accuracy")

                # ASN / ISP
                conn = r.get("connection", {})
                asn = conn.get("asn", "Unknown")
                isp = conn.get("isp") or conn.get("org") or "Unknown"

                # Security flags (best way to detect datacenter / vpn / tor)
                sec = r.get("security", {})
                is_hosting = sec.get("hosting")
                is_vpn = sec.get("vpn")
                is_tor = sec.get("tor")
                is_proxy = sec.get("proxy")

                # Network type logic
                if is_hosting:
                    net_type = "hosting"
                elif is_vpn:
                    net_type = "vpn"
                elif is_tor:
                    net_type = "tor"
                elif is_proxy:
                    net_type = "proxy"
                else:
                    # fallback heuristic
                    org_lower = (isp or "").lower()
                    if any(x in org_lower for x in ("cloud", "datacenter", "colo", "llc", "gmbh")):
                        net_type = "hosting"
                    elif any(x in org_lower for x in ("mobile", "cellular", "wireless")):
                        net_type = "mobile"
                    else:
                        net_type = "residential"

                # Формируем красивый лог
                status = (
                    f"🌍 GeoIP: IP={ip}, ASN={asn}, Country={country}, City={city}, "
                    f"Provider={isp}, NetworkType={net_type}, "
                    f"Lat={latitude}, Lon={longitude}, Accuracy={accuracy}km, "
                    f"Datacenter={is_hosting}"
                )

        except Exception as e:
            status = f"❌ Ошибка GeoIP/ASN: {e}"

        self._log(status)
        THREAT_CONNECTOR.emit(
            module="NetworkChecker",
            target=self.domain,
            result={"check": "asn_geoip", "status": status},
        )

    # ---------------------------------------------------------
    # PostgreSQL pg_hba.conf — сетевой поиск (read-only)
    # ---------------------------------------------------------
    def check_pg_hba_exposure(self) -> Dict[str, Any]:
        """
        Ищет признаки pg_hba.conf:
        - открытый порт PostgreSQL 5432
        - HTTP-утечки конфигурации по типичным путям
        - аудит методов аутентификации (без изменения файлов)
        """
        self._log(f"🔍 Поиск pg_hba.conf / PostgreSQL для {self.domain}")

        report: Dict[str, Any] = {
            "domain": self.domain,
            "postgres_port_open": False,
            "findings": [],
            "auth_audit": [],
        }

        # 1) Порт 5432
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            host = _hostname_from_target(self.domain)
            if sock.connect_ex((host, 5432)) == 0:
                report["postgres_port_open"] = True
                self._log("✅ Порт 5432 (PostgreSQL) открыт")
            else:
                self._log("ℹ️ Порт 5432 закрыт или фильтруется")
            sock.close()
        except Exception as e:
            self._log(f"⚠️ Проверка порта 5432: {e}")

        # 2) HTTP-пробы типичных путей
        headers = {"User-Agent": self.user_agent}
        paths = list(PG_HBA_PROBE_PATHS)
        extra = settings.get("postgres.pg_hba_probe_paths", [])
        if isinstance(extra, list):
            paths.extend(str(p) for p in extra if p)

        for base in _normalize_scan_base(self.domain):
            for path in paths:
                url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
                try:
                    r = requests.get(
                        url,
                        headers=headers,
                        timeout=self.request_timeout,
                        allow_redirects=False,
                        verify=False,
                    )
                except Exception:
                    continue

                body = (r.text or "")[:50000]
                if r.status_code not in (200, 403, 401) and not is_pg_hba_content(body):
                    continue

                if is_pg_hba_content(body) or (
                    r.status_code == 200 and path.lower().endswith("pg_hba.conf") and len(body) > 40
                ):
                    audit = audit_pg_hba_content(body)
                    finding = {
                        "url": url,
                        "status": r.status_code,
                        "size": len(body),
                        "audit": audit,
                    }
                    report["findings"].append(finding)
                    report["auth_audit"].append(audit)

                    self._log(f"🎯 Возможный pg_hba.conf: {url} (HTTP {r.status_code}, {len(body)} bytes)")
                    if audit.get("auth_methods"):
                        self._log(f"   Методы: {audit['auth_methods']}")
                    for warn in audit.get("warnings", []):
                        self._log(f"   {warn}")

                    THREAT_CONNECTOR.emit(
                        module="NetworkChecker",
                        target=self.domain,
                        result={
                            "check": "pg_hba_exposure",
                            "category": "postgres_config_leak",
                            "severity": "critical" if audit.get("auth_methods", {}).get("trust") else "high",
                            "url": url,
                            "status_code": r.status_code,
                            "auth_methods": audit.get("auth_methods", {}),
                            "warnings": audit.get("warnings", []),
                        },
                    )

        if not report["findings"]:
            self._log("ℹ️ pg_hba.conf по HTTP не обнаружен (это нормально для корректно настроенных серверов)")
        else:
            self._log(f"📋 Итого находок pg_hba: {len(report['findings'])}")

        self._log("✔️ Поиск pg_hba.conf завершён")
        return report

    def service_discovery(self):

        self._log("")
        self._log("🔎 Service Discovery...")

        self.scan_context.setdefault(
            "service_evidence",
            {}
        )

        confirmed_services = self.scan_context.setdefault(
            "confirmed_services",
            []
        )

        possible_services = self.scan_context.setdefault(
            "possible_services",
            []
        )

        for port in self.open_ports:

            service = KNOWN_SERVICES.get(
                port,
                "Unknown"
            )

            validator_name = SERVICE_VALIDATORS.get(
                port
            )

            validator_confirmed = False
            validator_evidence = ""

            if validator_name:

                validator = getattr(
                    self,
                    validator_name,
                    None,
                )

                if callable(validator):

                    try:

                        (
                            validator_confirmed,
                            validator_evidence,
                        ) = validator(port)

                    except Exception:
                        pass

            if (
                    service != "Unknown"
                    and service not in possible_services
            ):
                possible_services.append(
                    service
                )

            # =====================================================
            # NON-WEB SERVICES
            # =====================================================

            if port not in WEB_PORTS:

                banner = ""

                try:

                    sock = socket.socket(
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                    )

                    sock.settimeout(3)

                    if sock.connect_ex(
                            (
                                    self.domain,
                                    port,
                            )
                    ) == 0:

                        try:

                            banner = (
                                sock.recv(1024)
                                .decode(
                                    "utf-8",
                                    errors="ignore",
                                )
                                .strip()
                            )

                        except Exception:
                            pass

                    sock.close()

                except Exception:
                    pass

                status = (
                    f"🔹 {port}"
                    f" | PossibleService={service}"
                )

                if validator_confirmed:
                    status += " | CONFIRMED"

                if validator_evidence:
                    status += (
                        f" | Evidence="
                        f"{validator_evidence[:120]}"
                    )

                if banner:
                    status += (
                        f" | Banner="
                        f"{banner[:120]}"
                    )

                if validator_confirmed:

                    if (
                            service
                            not in confirmed_services
                    ):
                        confirmed_services.append(
                            service
                        )

                    self.scan_context[
                        "service_evidence"
                    ][service] = {
                        "port": port,
                        "evidence": validator_evidence,
                        "confidence": 100,
                    }

                elif (
                        service in {
                    "SMTP",
                    "SMTPS",
                }
                        and "smtp" in banner.lower()
                ):

                    if (
                            "SMTP"
                            not in confirmed_services
                    ):
                        confirmed_services.append(
                            "SMTP"
                        )

                self._log(status)

                THREAT_CONNECTOR.emit(
                    module="NetworkChecker",
                    target=self.domain,
                    result={
                        "check": "service_discovery",
                        "port": port,
                        "service": service,
                        "banner": banner,
                        "confirmed": validator_confirmed,
                        "evidence": validator_evidence,
                        "validator_used": validator_name,
                    },
                )

                continue

            # =====================================================
            # WEB SERVICES
            # =====================================================

            scheme = WEB_PORTS[port]

            if port == 80:

                url = f"http://{self.domain}"

            elif port == 443:

                url = f"https://{self.domain}"

            else:

                url = (
                    f"{scheme}://"
                    f"{self.domain}:{port}"
                )

            try:

                r = requests.get(
                    url,
                    timeout=5,
                    allow_redirects=True,
                    headers={
                        "User-Agent": self.user_agent
                    },
                    stream=True,
                )

                server = r.headers.get(
                    "Server",
                    "Unknown",
                )

                powered_by = r.headers.get(
                    "X-Powered-By",
                    "",
                )

                content_type = r.headers.get(
                    "Content-Type",
                    "",
                )

                location = r.headers.get(
                    "Location",
                    "",
                )

                title = ""

                try:

                    body = r.text[:15000]

                    soup = BeautifulSoup(
                        body,
                        "html.parser",
                    )

                    if soup.title:
                        title = (
                            soup.title.get_text(
                                strip=True
                            )
                        )

                except Exception:
                    pass

                if (
                        "WEB"
                        not in confirmed_services
                ):
                    confirmed_services.append(
                        "WEB"
                    )

                self.scan_context[
                    "service_evidence"
                ].setdefault(
                    "WEB",
                    {
                        "hosts": [],
                        "ports": [],
                        "servers": [],
                        "titles": [],
                        "status_codes": [],
                        "content_types": [],
                        "powered_by": [],
                        "confidence": 100,
                    },
                )

                web_evidence = (
                    self.scan_context[
                        "service_evidence"
                    ]["WEB"]
                )

                if (
                        self.domain
                        not in web_evidence["hosts"]
                ):
                    web_evidence["hosts"].append(
                        self.domain
                    )

                if (
                        port
                        not in web_evidence["ports"]
                ):
                    web_evidence["ports"].append(
                        port
                    )

                if (
                        server
                        and server
                        not in web_evidence["servers"]
                ):
                    web_evidence["servers"].append(
                        server
                    )

                if (
                        title
                        and title
                        not in web_evidence["titles"]
                ):
                    web_evidence["titles"].append(
                        title
                    )

                if (
                        r.status_code
                        not in web_evidence["status_codes"]
                ):
                    web_evidence[
                        "status_codes"
                    ].append(
                        r.status_code
                    )

                if (
                        content_type
                        and content_type
                        not in web_evidence[
                    "content_types"
                ]
                ):
                    web_evidence[
                        "content_types"
                    ].append(
                        content_type
                    )

                status = (
                    f"🔹 {port}"
                    f" | Service=WEB"
                    f" | HTTP={r.status_code}"
                    f" | Server={server}"
                )

                if title:
                    status += (
                        f" | Title={title}"
                    )

                self._log(status)

            except Exception as e:

                self._log(
                    f"⚠️ {port}"
                    f" | {service}"
                    f" | {e}"
                )

        confirmed_services = sorted(
            set(confirmed_services)
        )

        possible_services = sorted(
            set(possible_services)
        )

        self.scan_context[
            "confirmed_services"
        ] = confirmed_services

        self.scan_context[
            "possible_services"
        ] = possible_services

        self._log("")
        self._log("=" * 60)
        self._log("📊 Service Discovery Summary")
        self._log("=" * 60)

        self._log(
            f"Possible Services : "
            f"{len(possible_services)}"
        )

        self._log(
            f"Confirmed Services : "
            f"{len(confirmed_services)}"
        )

        if confirmed_services:
            self._log(
                "✅ Confirmed: "
                + ", ".join(
                    confirmed_services
                )
            )

        if possible_services:
            self._log(
                "⚠️ Possible: "
                + ", ".join(
                    possible_services
                )
            )

    def network_assessment(self):

        confirmed_services = set(
            self.scan_context.get(
                "confirmed_services",
                [],
            )
        )

        possible_services = set(
            self.scan_context.get(
                "possible_services",
                [],
            )
        )

        evidence = self.scan_context.get(
            "service_evidence",
            {},
        )

        risk_score = 0
        findings = []

        # =====================================================
        # Exposure
        # =====================================================

        open_ports = len(self.open_ports)

        if open_ports >= 20:

            risk_score += 4

            findings.append(
                f"{open_ports} TCP endpoints responded"
            )

            findings.append(
                "Exposure classification: large"
            )

        elif open_ports >= 10:

            risk_score += 2

            findings.append(
                f"{open_ports} TCP endpoints responded"
            )

        # =====================================================
        # Service surface
        # =====================================================

        if len(possible_services) >= 10:
            risk_score += 2

            findings.append(
                f"Large service surface ({len(possible_services)})"
            )

        if "WEB" in confirmed_services:
            findings.append(
                "Web service confirmed"
            )

        # =====================================================
        # High-risk services
        # =====================================================

        HIGH_RISK = {
            "Redis": 4,
            "MongoDB": 4,
            "Docker": 5,
            "Docker TLS": 4,
            "PostgreSQL": 3,
            "MySQL": 3,
            "MSSQL": 3,
            "RDP": 4,
            "VNC": 4,
            "Elasticsearch": 4,
            "Kibana": 3,
        }

        for service, score in HIGH_RISK.items():

            if service in confirmed_services:
                risk_score += score

                findings.append(
                    f"Confirmed {service} exposure"
                )

        # =====================================================
        # Infrastructure fingerprint
        # =====================================================

        web_info = evidence.get(
            "WEB",
            {}
        )

        servers = web_info.get(
            "servers",
            []
        )

        if servers:
            findings.append(
                "Infrastructure: web platform "
                "or load-balanced infrastructure"
            )

        # =====================================================
        # WAF
        # =====================================================

        try:

            waf_detected = getattr(
                self,
                "waf_detected",
                False,
            )

            if waf_detected:

                findings.append(
                    "WAF detected"
                )

            else:

                risk_score += 1

                findings.append(
                    "WAF not detected"
                )

        except Exception:
            pass

        # =====================================================
        # TLS
        # =====================================================

        try:

            tls_version = getattr(
                self,
                "tls_version",
                None,
            )

            if tls_version:

                findings.append(
                    f"{tls_version} enabled"
                )

                if "TLSv1.3" in tls_version:
                    risk_score -= 1

        except Exception:
            pass

        # =====================================================
        # CSP
        # =====================================================

        try:

            csp = getattr(
                self,
                "csp_header",
                None,
            )

            if not csp:
                risk_score += 2

                findings.append(
                    "CSP missing"
                )

        except Exception:
            pass

        # =====================================================
        # ICMP
        # =====================================================

        try:

            icmp_available = getattr(
                self,
                "icmp_available",
                None,
            )

            if icmp_available is False:
                findings.append(
                    "ICMP filtered or blocked"
                )

        except Exception:
            pass

        # =====================================================
        # Risk normalization
        # =====================================================

        risk_score = max(
            0,
            min(
                100,
                risk_score,
            ),
        )

        if risk_score >= 20:

            risk_level = "CRITICAL"

        elif risk_score >= 15:

            risk_level = "HIGH"

        elif risk_score >= 8:

            risk_level = "MEDIUM"

        else:

            risk_level = "LOW"

        confirmed_count = len(
            confirmed_services
        )

        possible_count = len(
            possible_services
        )

        confidence = 0.0

        if possible_count:
            confidence = round(
                (
                        confirmed_count
                        / possible_count
                ) * 100,
                1,
            )

        self.scan_context[
            "risk_score"
        ] = risk_score

        self.scan_context[
            "risk_level"
        ] = risk_level

        self.scan_context[
            "assessment_findings"
        ] = findings

        self._log("")
        self._log("=" * 60)
        self._log("🧠 AI Network Assessment")
        self._log("=" * 60)

        self._log(
            f"Risk Level : {risk_level}"
        )

        self._log(
            f"Risk Score : {risk_score}"
        )

        self._log(
            f"Summary    : "
            f"Risk={risk_level}, "
            f"Score={risk_score}, "
            f"Confirmed={confirmed_count}, "
            f"Possible={possible_count}, "
            f"Confidence={confidence}%, "
            f"TCP={open_ports}"
        )

        self._log("")
        self._log("Findings:")

        for finding in findings:
            self._log(
                f" • {finding}"
            )

        if confirmed_services:
            self._log(
                "✅ Confirmed Services: "
                + ", ".join(
                    sorted(
                        confirmed_services
                    )
                )
            )

        if possible_services:
            self._log(
                "⚠️ Possible Services: "
                + ", ".join(
                    sorted(
                        possible_services
                    )
                )
            )

        THREAT_CONNECTOR.emit(
            module="NetworkChecker",
            target=self.domain,
            result={
                "check": "network_assessment",
                "risk_level": risk_level,
                "risk_score": risk_score,
                "confirmed_services": list(
                    confirmed_services
                ),
                "possible_services": list(
                    possible_services
                ),
                "confidence": confidence,
                "findings": findings,
            },
        )

    def _validate_ssh(self, port: int):

        try:

            sock = socket.create_connection(
                (self.domain, port),
                timeout=5,
            )

            banner = sock.recv(256).decode(
                "utf-8",
                errors="ignore",
            )

            sock.close()

            if banner.startswith("SSH-"):
                return True, banner.strip()

        except Exception:
            pass

        return False, ""

    def _validate_smtp(self, port: int):

        try:

            sock = socket.create_connection(
                (self.domain, port),
                timeout=5,
            )

            banner = sock.recv(512).decode(
                "utf-8",
                errors="ignore",
            )

            sock.close()

            low = banner.lower()

            if (
                    "smtp" in low
                    or banner.startswith("220")
            ):
                return True, banner.strip()

        except Exception:
            pass

        return False, ""

    def _validate_redis(self, port: int):

        try:

            sock = socket.create_connection(
                (self.domain, port),
                timeout=5,
            )

            sock.sendall(b"PING\r\n")

            response = sock.recv(128)

            sock.close()

            if b"+PONG" in response:
                return True, response.decode(
                    errors="ignore"
                )

        except Exception:
            pass

        return False, ""

    def _validate_docker(self, port: int):

        try:

            url = (
                f"http://{self.domain}:{port}/version"
            )

            r = requests.get(
                url,
                timeout=5,
            )

            text = r.text.lower()

            if (
                    r.status_code == 200
                    and "docker" in text
            ):
                return True, "Docker API"

        except Exception:
            pass

        return False, ""

    def _validate_docker_tls(self, port: int):

        try:

            url = (
                f"https://{self.domain}:{port}/version"
            )

            r = requests.get(
                url,
                timeout=5,
                verify=False,
            )

            text = r.text.lower()

            if (
                    r.status_code == 200
                    and "docker" in text
            ):
                return True, "Docker TLS API"

        except Exception:
            pass

        return False, ""

    def _validate_elasticsearch(
            self,
            port: int
    ):

        try:

            url = (
                f"http://{self.domain}:{port}/"
            )

            r = requests.get(
                url,
                timeout=5,
            )

            text = r.text.lower()

            if (
                    "cluster_name" in text
                    or "elasticsearch" in text
                    or "lucene" in text
            ):
                return True, "Elasticsearch"

        except Exception:
            pass

        return False, ""

    def _validate_postgresql(
            self,
            port: int
    ):

        try:

            sock = socket.create_connection(
                (
                    self.domain,
                    port,
                ),
                timeout=5,
            )

            startup = (
                b"\x00\x00\x00\x08"
                b"\x04\xd2\x16\x2f"
            )

            sock.sendall(startup)

            response = sock.recv(512)

            sock.close()

            if response:
                return (
                    True,
                    "PostgreSQL protocol response"
                )

        except Exception:
            pass

        return (
            False,
            ""
        )

    def _validate_mysql(
            self,
            port: int
    ):

        try:

            sock = socket.create_connection(
                (
                    self.domain,
                    port,
                ),
                timeout=5,
            )

            banner = sock.recv(
                512
            ).decode(
                "latin1",
                errors="ignore",
            )

            sock.close()

            if (
                    "mariadb" in banner.lower()
                    or "mysql" in banner.lower()
            ):
                return (
                    True,
                    banner[:150]
                )

        except Exception:
            pass

        return (
            False,
            ""
        )

    def _validate_mongodb(
            self,
            port: int
    ):

        try:

            sock = socket.create_connection(
                (
                    self.target_ip
                    or self.domain,
                    port,
                ),
                timeout=5,
            )

            sock.settimeout(5)

            # MongoDB OP_QUERY isMaster

            payload = bytes.fromhex(
                "3a000000"
                "00000000"
                "00000000"
                "d4070000"
                "00000000"
                "61646d696e2e24636d6400"
                "00000000"
                "ffffffff"
                "13000000"
                "1069734d61737465720001000000"
                "00"
            )

            sock.sendall(
                payload
            )

            data = sock.recv(
                4096
            )

            sock.close()

            if not data:
                return (
                    False,
                    ""
                )

            low = data.lower()

            signatures = (
                b"ismaster",
                b"maxwireversion",
                b"maxbsonobjectsize",
                b"logicalsessiontimeoutminutes",
                b"mongodb",
            )

            if any(
                    sig in low
                    for sig in signatures
            ):
                return (
                    True,
                    "MongoDB protocol response"
                )

        except Exception:
            pass

        return (
            False,
            ""
        )

    def _validate_rdp(
            self,
            port: int
    ):

        try:

            sock = socket.create_connection(
                (
                    self.domain,
                    port,
                ),
                timeout=5,
            )

            sock.sendall(
                bytes.fromhex(
                    "030000130ee0000000000001000800000000"
                )
            )

            response = sock.recv(
                64
            )

            sock.close()

            if response:
                return (
                    True,
                    "RDP handshake"
                )

        except Exception:
            pass

        return (
            False,
            ""
        )




