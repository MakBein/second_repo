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
        r = requests.head(url, timeout=5, allow_redirects=True)
        return True, r.status_code
    except Exception:
        return False, None


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
        self.gui_output = gui_output
        self.log_fn = log_fn
        self.user_agent = settings.get("crawl.user_agent", "Mozilla/5.0")
        self.request_timeout = float(settings.get("http.default_timeout", 8))

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
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        self._log(f"🌐 Запуск сетевых проверок для {self.domain}")
        self.check_icmp()
        self.check_http()
        self.check_waf()
        self.check_tls_and_alpn()
        self.check_ports()
        self.check_dns()
        self.check_whois()
        self.check_asn_geoip()
        self._log("✔️ Сетевые проверки завершены.")


    # ---------------------------------------------------------
    # ICMP
    # ---------------------------------------------------------
    def check_icmp(self):
        try:
            response = ping(self.domain, count=2, timeout=2)
            if response.success():
                status = f"✅ ICMP доступен: {response.rtt_avg_ms} ms"
            else:
                status = "⚠️ ICMP заблокирован или нет ответа"
        except Exception:
            cmd = ["ping", "-c", "2", self.domain] if os.name != "nt" else ["ping", "-n", "2", self.domain]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
                status = result.stdout.strip() or "❌ Ошибка ICMP"
            except Exception as e:
                status = f"❌ Ошибка ICMP: {e}"

        self._log(status)
        THREAT_CONNECTOR.emit(
            module="NetworkChecker",
            target=self.domain,
            result={"check": "icmp", "status": status},
        )

    # ---------------------------------------------------------
    # HTTP HEAD fingerprint
    # ---------------------------------------------------------
    def check_http(self):
        try:
            headers = {"User-Agent": self.user_agent}
            r = requests.head(
                f"http://{self.domain}",
                timeout=5,
                headers=headers,
                allow_redirects=True,
            )

            status = f"HTTP/{r.status_code} {r.reason}"
            server = r.headers.get("Server", "Unknown")
            csp = r.headers.get("Content-Security-Policy", "None")
            cookies = r.headers.get("Set-Cookie", "None")

            details = f"{status} | Server={server} | CSP={csp} | Cookies={cookies}"

        except Exception as e:
            details = f"❌ Ошибка HTTP: {e}"

        self._log(details)
        THREAT_CONNECTOR.emit(
            module="NetworkChecker",
            target=self.domain,
            result={"check": "http", "status": details},
        )

    # ---------------------------------------------------------
    # WAF fingerprinting (по HTTP-ответу)
    # ---------------------------------------------------------
    def check_waf(self):
        try:
            headers = {"User-Agent": self.user_agent}
            r = requests.get(
                f"http://{self.domain}",
                timeout=7,
                headers=headers,
                allow_redirects=True,
            )

            banner = " ".join(
                [
                    r.headers.get("Server", ""),
                    r.headers.get("X-Powered-By", ""),
                    r.headers.get("Set-Cookie", ""),
                ]
            ).lower()

            detected = []
            for waf_name, sigs in WAF_SIGNATURES.items():
                if any(sig in banner for sig in sigs):
                    detected.append(waf_name)

            if detected:
                status = f"🛡 Обнаружены признаки WAF: {', '.join(sorted(set(detected)))}"
            else:
                status = "ℹ️ Явных признаков WAF не обнаружено"

        except Exception as e:
            status = f"❌ Ошибка WAF-анализа: {e}"

        self._log(status)
        THREAT_CONNECTOR.emit(
            module="NetworkChecker",
            target=self.domain,
            result={"check": "waf", "status": status},
        )

    # ---------------------------------------------------------
    # TLS/SSL + HTTP/2 ALPN
    # ---------------------------------------------------------
    def check_tls_and_alpn(self):
        try:
            ctx = ssl.create_default_context()

            # Попытка согласовать ALPN (h2 / http1.1)
            try:
                ctx.set_alpn_protocols(["h2", "http/1.1"])
            except Exception:
                pass  # ALPN может быть недоступен

            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:

                    # --- TLS версия ---
                    tls_version = ssock.version() or "unknown"

                    # --- ALPN ---
                    try:
                        alpn = ssock.selected_alpn_protocol() or "unknown"
                    except Exception:
                        alpn = "unknown"

                    # --- Сертификат ---
                    cert = ssock.getpeercert() or {}

                    # Expiry
                    not_after = cert.get("notAfter")
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        exp_str = expiry.strftime("%Y-%m-%d")
                    except Exception:
                        exp_str = "Unknown"

                    # Subject (надёжный парсер)
                    subject_parts = []
                    for item in cert.get("subject", []):
                        # item = [(("key","value"),)]
                        for pair in item:
                            if isinstance(pair, tuple) and len(pair) == 2:
                                key, value = pair
                                subject_parts.append(f"{key}={value}")

                    subject = ", ".join(subject_parts) if subject_parts else "Unknown"

                    # --- Финальный вывод ---
                    details = (
                        f"🧪 TLS={tls_version}, ALPN={alpn}, "
                        f"CN={subject}, Expiry={exp_str}"
                    )

        except Exception as e:
            details = f"❌ Ошибка TLS/ALPN: {e}"

        # Логирование и отправка в Threat Intel
        self._log(details)
        THREAT_CONNECTOR.emit(
            module="NetworkChecker",
            target=self.domain,
            result={"check": "tls_alpn", "status": details},
        )

    # ---------------------------------------------------------
    # Port scan
    # ---------------------------------------------------------
    def check_ports(self):
        ports = [443, 80, 8443, 8080, 9443]

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.domain, port))
                sock.close()

                if result == 0:
                    status = f"✅ Порт {port} открыт"
                else:
                    status = f"❌ Порт {port} закрыт/недоступен"

            except Exception as e:
                status = f"❌ Ошибка проверки порта {port}: {e}"

            self._log(status)
            THREAT_CONNECTOR.emit(
                module="NetworkChecker",
                target=self.domain,
                result={"check": f"port{port}", "status": status},
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
