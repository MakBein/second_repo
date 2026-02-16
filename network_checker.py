# xss_security_gui/network_checker.py
"""
NetworkChecker ULTRA 6.2
Встроенные сетевые проверки для XSS Security Suite:
- ICMP ping
- HTTP headers
- TLS/SSL
- Port availability
Интеграция с settings.py и ThreatConnector
"""

import os, socket, ssl, subprocess, threading, requests
from datetime import datetime
from pythonping import ping
from xss_security_gui.settings import settings, LOG_DIR
from xss_security_gui.threat_analysis.threat_connector import THREAT_CONNECTOR

NETWORK_LOG_PATH = LOG_DIR / "network_checks.log"

class NetworkChecker:
    def __init__(self, domain: str, gui_output=None):
        self.domain = domain
        self.gui_output = gui_output

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

    def run_all_checks(self):
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        self._log(f"🌐 Запуск сетевых проверок для {self.domain}")
        self.check_icmp()
        self.check_http()
        self.check_tls()
        self.check_ports()
        self._log("✔️ Сетевые проверки завершены.")

    def check_icmp(self):
        try:
            response = ping(self.domain, count=2, timeout=2)
            if response.success():
                status = f"✅ ICMP доступен: {response.rtt_avg_ms} ms"
            else:
                status = "⚠️ ICMP заблокирован или нет ответа"
        except Exception:
            cmd = ["ping", "-c", "2", self.domain] if os.name != "nt" else ["ping", "-n", "2", self.domain]
            result = subprocess.run(cmd, capture_output=True, text=True)
            status = result.stdout.strip() or "❌ Ошибка ICMP"
        self._log(status)
        THREAT_CONNECTOR.emit(module="NetworkChecker", target=self.domain,
                              result={"check": "icmp", "status": status})

    def check_http(self):
        try:
            headers = {"User-Agent": settings.get("crawl.user_agent", "Mozilla/5.0")}
            r = requests.head(f"http://{self.domain}", timeout=5, headers=headers, allow_redirects=True)
            status = f"HTTP/{r.status_code} {r.reason}"
            server = r.headers.get("Server", "Unknown")
            csp = r.headers.get("Content-Security-Policy", "None")
            cookies = r.headers.get("Set-Cookie", "None")
            details = f"{status} | Server={server} | CSP={csp} | Cookies={cookies}"
        except Exception as e:
            details = f"❌ Ошибка HTTP: {e}"
        self._log(details)
        THREAT_CONNECTOR.emit(module="NetworkChecker", target=self.domain,
                              result={"check": "http", "status": details})

    def check_tls(self):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    not_after = cert.get("notAfter")
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") if not_after else None
                    exp_str = expiry.strftime("%Y-%m-%d") if expiry else "Unknown"
                    subject = ", ".join("=".join(x) for x in cert.get("subject", []))
                    details = f"🧪 TLS={tls_version}, CN={subject}, Expiry={exp_str}"
        except Exception as e:
            details = f"❌ Ошибка TLS: {e}"
        self._log(details)
        THREAT_CONNECTOR.emit(module="NetworkChecker", target=self.domain,
                              result={"check": "tls", "status": details})

    def check_ports(self):
        ports = [443, 80, 8443, 8080, 9443]
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.domain, port))
                sock.close()
                if result == 0:
                    status = f"✅ Порт {port} открыт"
                else:
                    status = f"❌ Порт {port} закрыт/недоступен"
            except Exception as e:
                status = f"❌ Ошибка проверки порта {port}: {e}"
            self._log(status)
            THREAT_CONNECTOR.emit(module="NetworkChecker", target=self.domain,
                                  result={"check": f"port{port}", "status": status})