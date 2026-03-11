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
import socket
import ssl
import subprocess
import threading
from datetime import datetime

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


# Примитивный WAF-фингерпринт по заголовкам/баннерам
WAF_SIGNATURES = {
    "cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
    "akamai": ["akamai", "akamai-ghost"],
    "imperva": ["incapsula", "x-iinfo", "x-cdn"],
    "f5_bigip": ["bigip", "x-waf", "x-wa-info"],
    "mod_security": ["mod_security", "modsecurity"],
    "sucuri": ["sucuri", "x-sucuri-id"],
}


class NetworkChecker:
    def __init__(self, domain: str, gui_output=None):
        self.domain = domain.strip()
        self.gui_output = gui_output
        self.user_agent = settings.get("crawl.user_agent", "Mozilla/5.0")

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
            # ALPN: пытаемся договориться о h2 / http/1.1
            try:
                ctx.set_alpn_protocols(["h2", "http/1.1"])
            except Exception:
                # Не все OpenSSL/SSL сборки поддерживают ALPN
                pass

            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    alpn = None
                    try:
                        alpn = ssock.selected_alpn_protocol()
                    except Exception:
                        alpn = None

                    not_after = cert.get("notAfter")
                    expiry = (
                        datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        if not_after
                        else None
                    )
                    exp_str = expiry.strftime("%Y-%m-%d") if expiry else "Unknown"

                    subject = ", ".join("=".join(x) for x in cert.get("subject", []))

                    alpn_str = alpn or "unknown"
                    details = (
                        f"🧪 TLS={tls_version}, ALPN={alpn_str}, "
                        f"CN={subject}, Expiry={exp_str}"
                    )

        except Exception as e:
            details = f"❌ Ошибка TLS/ALPN: {e}"

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
        if whois is None:
            status = "⚠️ WHOIS недоступен: python-whois не установлен"
            self._log(status)
            return

        try:
            data = whois.whois(self.domain)

            registrar = data.registrar or "Unknown"
            country = data.country or "Unknown"
            created = str(data.creation_date) if data.creation_date else "Unknown"
            expires = str(data.expiration_date) if data.expiration_date else "Unknown"

            status = f"📄 WHOIS: Registrar={registrar}, Country={country}, Created={created}, Expires={expires}"

        except Exception as e:
            status = f"❌ Ошибка WHOIS: {e}"

        self._log(status)
        THREAT_CONNECTOR.emit(module="NetworkChecker", target=self.domain,
                              result={"check": "whois", "status": status})

    # ---------------------------------------------------------
    # ASN / GeoIP
    # ---------------------------------------------------------
    def check_asn_geoip(self):
        try:
            ip = socket.gethostbyname(self.domain)
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5).json()

            asn = r.get("org", "Unknown")
            city = r.get("city", "Unknown")
            country = r.get("country", "Unknown")
            provider = r.get("org", "Unknown")

            status = f"🌍 GeoIP: IP={ip}, ASN={asn}, Country={country}, City={city}, Provider={provider}"

        except Exception as e:
            status = f"❌ Ошибка GeoIP/ASN: {e}"

        self._log(status)
        THREAT_CONNECTOR.emit(module="NetworkChecker", target=self.domain,
                              result={"check": "asn_geoip", "status": status})





