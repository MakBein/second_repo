# xss_security_gui/api_parser.py
import re
import os
import json
import datetime

from xss_security_gui.threat_analysis.threat_connector import ThreatConnector


# ============================================================
#   VALIDATION & CLASSIFICATION HELPERS
# ============================================================

def is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        n = int(p)
        if n < 0 or n > 255:
            return False
    return True


def classify_ipv4(ip: str) -> str:
    a, b, c, d = map(int, ip.split("."))

    if a == 10:
        return "private"
    if a == 172 and 16 <= b <= 31:
        return "private"
    if a == 192 and b == 168:
        return "private"
    if a == 127:
        return "loopback"
    if a == 169 and b == 254:
        return "link-local"

    return "public"


def classify_ipv6(ip: str) -> str:
    ip = ip.lower()

    if ip.startswith("fe80"):
        return "link-local"
    if ip.startswith("fc") or ip.startswith("fd"):
        return "private"
    if ip == "::1":
        return "loopback"

    return "public"


def detect_ip_type(ip: str) -> str:
    return "ipv6" if ":" in ip else "ipv4"


# ============================================================
#   IP ENRICHMENT (GeoIP, ASN, ISP)
# ============================================================

def enrich_ip(ip: str) -> dict:
    """
    Обогащение IP: геолокация, ASN, ISP, тип сети.
    Здесь — заглушка с примерной структурой.
    Ты можешь подключить любой GeoIP/ASN-провайдер (MaxMind, IP2Location, ipinfo, etc.)
    и просто заменить тело этой функции.
    """
    # TODO: заменить на реальный вызов GeoIP/ASN сервиса
    # Пример структуры:
    return {
        "country": None,
        "city": None,
        "asn": None,
        "isp": None,
        "network_type": None,  # hosting, residential, mobile, tor, vpn, unknown
    }


# ============================================================
#   TOKEN CLASSIFICATION
# ============================================================

def classify_token(token: str) -> str:
    """
    Классификация токенов:
    - jwt
    - aws_access_key
    - google_api_key
    - generic_api_key
    """
    if re.match(r"^eyJ[a-zA-Z0-9._-]+$", token):
        return "jwt"
    if re.match(r"^AKIA[0-9A-Z]{16}$", token):
        return "aws_access_key"
    if re.match(r"^AIza[0-9A-Za-z\-_]{35}$", token):
        return "google_api_key"
    if re.match(r"^(?:auth[_-]?token|session[_-]?id|api[_-]?key)[=:]?[a-zA-Z0-9_\-]+", token, re.IGNORECASE):
        return "generic_api_key"
    return "unknown"


# ============================================================
#   REGEX PATTERNS (улучшенные)
# ============================================================

API_REGEX = r"(\/(?:api|graphql|rest|internal|v\d+)\/[^\s\"']+)"
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+(?:@|\[at\])[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
CARD_REGEX = r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b"
URL_REGEX = r"https?:\/\/[^\s\"'<>]+"
TOKEN_REGEX = (
    r"(?:auth[_-]?token|session[_-]?id|api[_-]?key)[=:]?[a-zA-Z0-9_\-]+"
    r"|eyJ[a-zA-Z0-9._-]+"          # JWT
    r"|AKIA[0-9A-Z]{16}"            # AWS Access Key
    r"|AIza[0-9A-Za-z\-_]{35}"      # Google API Key
)
PHONE_REGEX = r"""
    (?:
        \+?[1-9]\d{0,2}[-.\s]?
        \(?\d{2,3}\)?[-.\s]?
        \d{2,3}[-.\s]?\d{2}[-.\s]?\d{2}
    )
    |
    (?:
        (?:\+7|8)[-\s]?
        (?:9\d{2}|3\d{2}|4\d{2}|8\d{2})[-\s]?
        \d{3}[-\s]?\d{2}[-\s]?\d{2}
    )
"""
PARAM_REGEX = r"\b([a-zA-Z0-9_]+=[a-zA-Z0-9_\-]+)\b|\"([a-zA-Z0-9_]+)\":\"([^\"]+)\""
IP_REGEX = r"\b(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[A-Fa-f0-9:]+:+)+[A-Fa-f0-9]+)\b"


# ============================================================
#   MAIN PARSER
# ============================================================

def extract_api_data(
    log_path,
    threat_tab=None,
    save_json=True,
    send_to_threat=True,
    add_to_connector=True
):
    """
    API Parser 4.0:
    - улучшенные паттерны
    - классификация токенов
    - обогащение IP (гео, ASN, ISP)
    - интеграция ThreatConnector 2.0
    - вкладка API Intelligence в Dashboard
    """

    results = {
        "api_endpoints": [],
        "tokens": [],          # raw tokens
        "token_objects": [],   # structured tokens with type
        "user_ids": [],
        "emails": [],
        "cards": [],
        "phones": [],
        "logins": [],
        "passwords": [],
        "ips": [],             # structured dicts
        "urls": [],
        "parameters": []
    }

    if not os.path.exists(log_path):
        print(f"[⚠️] Файл {log_path} не найден.")
        return results

    try:
        with open(log_path, encoding="utf-8") as f:
            lines = f.readlines()

        for line in lines:

            # API endpoints
            results["api_endpoints"].extend(re.findall(API_REGEX, line, re.IGNORECASE))

            # Tokens (raw)
            raw_tokens = re.findall(TOKEN_REGEX, line, re.IGNORECASE)
            results["tokens"].extend(raw_tokens)

            # Token objects (classified)
            for t in raw_tokens:
                t_type = classify_token(t)
                results["token_objects"].append({
                    "token": t,
                    "type": t_type
                })

            # User IDs
            results["user_ids"].extend(re.findall(
                r"(?:user[_-]?id|uid|account[_-]?id|customer[_-]?id|profile[_-]?id|member[_-]?id)"
                r"[=:]?[a-zA-Z0-9_-]+",
                line, re.IGNORECASE
            ))

            # Emails
            results["emails"].extend(re.findall(EMAIL_REGEX, line))

            # Cards
            results["cards"].extend(re.findall(CARD_REGEX, line))

            # Phones
            results["phones"].extend(re.findall(PHONE_REGEX, line, re.VERBOSE))

            # Logins
            results["logins"].extend(re.findall(
                r"(?:login|username)[=:]?[a-zA-Z0-9_.-]+",
                line, re.IGNORECASE
            ))

            # Passwords
            results["passwords"].extend(re.findall(
                r"(?:password|passwd)[=:]?[a-zA-Z0-9!@#$%^&*_.-]+",
                line, re.IGNORECASE
            ))

            # IP addresses
            for ip in re.findall(IP_REGEX, line):
                ip_type = detect_ip_type(ip)

                if ip_type == "ipv4":
                    if not is_valid_ipv4(ip):
                        continue
                    scope = classify_ipv4(ip)
                else:
                    scope = classify_ipv6(ip)

                geo = enrich_ip(ip)

                results["ips"].append({
                    "ip": ip,
                    "type": ip_type,
                    "scope": scope,
                    "country": geo.get("country"),
                    "city": geo.get("city"),
                    "asn": geo.get("asn"),
                    "isp": geo.get("isp"),
                    "network_type": geo.get("network_type"),
                })

            # URLs
            results["urls"].extend(re.findall(URL_REGEX, line))

            # Parameters
            for p in re.findall(PARAM_REGEX, line):
                if p[0]:
                    results["parameters"].append(p[0])
                elif p[1] and p[2]:
                    results["parameters"].append(f"{p[1]}={p[2]}")

        # Deduplicate simple lists
        for key in ["api_endpoints", "tokens", "user_ids", "emails",
                    "cards", "phones", "logins", "passwords", "urls", "parameters"]:
            results[key] = list(set(results[key]))

        print(
            f"[ℹ️] API Parser: найдено {len(results['api_endpoints'])} endpoints, "
            f"{len(results['tokens'])} токенов, {len(results['user_ids'])} ID, "
            f"{len(results['emails'])} email, {len(results['cards'])} карт, "
            f"{len(results['phones'])} телефонов, {len(results['logins'])} логинов, "
            f"{len(results['passwords'])} паролей, {len(results['ips'])} IP, "
            f"{len(results['urls'])} URL, {len(results['parameters'])} параметров."
        )

        # === ThreatConnector 2.0 integration ===
        if add_to_connector:
            connector = ThreatConnector()

            # IP artifacts (enriched)
            for ip_entry in results["ips"]:
                severity = "info"
                if ip_entry["scope"] == "public":
                    severity = "info"
                if ip_entry["network_type"] in ("hosting", "tor", "vpn"):
                    severity = "medium"

                connector.add_artifact(
                    module_name="IP_INTEL",
                    target=log_path,
                    results=[{
                        "severity": severity,
                        "source": "APIParser",
                        "ip": ip_entry["ip"],
                        "type": ip_entry["type"],
                        "scope": ip_entry["scope"],
                        "country": ip_entry["country"],
                        "city": ip_entry["city"],
                        "asn": ip_entry["asn"],
                        "isp": ip_entry["isp"],
                        "network_type": ip_entry["network_type"],
                        "timestamp": datetime.datetime.utcnow().isoformat()
                    }]
                )

            # Token artifacts
            for t_obj in results["token_objects"]:
                t = t_obj["token"]
                t_type = t_obj["type"]

                severity = "medium"
                if t_type in ("aws_access_key", "google_api_key", "jwt"):
                    severity = "high"

                connector.add_artifact(
                    module_name="TOKEN_INTEL",
                    target=log_path,
                    results=[{
                        "severity": severity,
                        "source": "APIParser",
                        "token": t,
                        "token_type": t_type,
                        "timestamp": datetime.datetime.utcnow().isoformat()
                    }]
                )

            # Email artifacts
            for email in results["emails"]:
                connector.add_artifact(
                    module_name="EMAIL_INTEL",
                    target=log_path,
                    results=[{
                        "severity": "low",
                        "source": "APIParser",
                        "email": email,
                        "timestamp": datetime.datetime.utcnow().isoformat()
                    }]
                )

        # === GUI: API Intelligence tab integration ===
        if send_to_threat and threat_tab and hasattr(threat_tab, "send_to_threat_intel"):
            threat_tab.send_to_threat_intel("api_intelligence", {
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source_tab": "API Intelligence",
                "payload": results
            })

        # === Save JSON ===
        if save_json:
            os.makedirs("logs", exist_ok=True)
            out_path = "logs/api_parser_results.json"
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"[💾] Результаты сохранены в {out_path}")

    except Exception as e:
        print(f"[❌] Ошибка парсинга логов: {e}")

    return results


# Пример использования
if __name__ == "__main__":
    data = extract_api_data("logs/form_fuzz_hits.log")
    print(json.dumps(data, ensure_ascii=False, indent=2))
