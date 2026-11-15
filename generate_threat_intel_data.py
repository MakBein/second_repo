# xss_security_gui/generate_threat_intel_data.py
"""
Генератор тестовых данных для Threat Intel
Создает analyzer1.json с реалистичными утечками:
- Пароли
- Кредитные карты
- Emails
- Телефоны
- Города
- Адреса
- Состояние счета
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime, timedelta
import random

# Добавляем путь для импорта
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, base_dir)

from xss_security_gui.data_generator import (
    generate_credit_card,
    generate_email,
    generate_password,
    generate_phone_number,
    generate_address,
    generate_name,
    generate_user_profile,
    CITIES,
)


def generate_threat_intel_artifacts():
    """Генерирует массив артефактов для Threat Intel"""
    
    artifacts = []
    timestamp = datetime.now().isoformat()
    
    # ============================================================
    # 1. EMAIL LEAK ARTIFACTS (главные - должны отображаться как 📧 Email Leak)
    # ============================================================
    
    for i in range(3):
        emails_list = [generate_email() for _ in range(random.randint(2, 5))]
        smtp_users = [f"admin_{j}" for j in range(len(emails_list))]
        smtp_pass = [generate_password(length=12) for _ in range(len(emails_list))]
        
        artifact = {
            "_hash": f"email_leak_{i}_{random.randint(10000, 99999)}",
            "timestamp": (datetime.now() - timedelta(hours=i)).isoformat(),
            "module": "LFI_Scanner",
            "target": f"https://gazprombank.ru/?file=../../../.env{i}",
            "result": {
                "severity": "high",
                "category": "email_leak",
                "source": "lfi_tab",
                "type": "LFI",
                "risk": "high",
                "email_leak": {
                    "emails": emails_list,
                    "phones": [generate_phone_number() for _ in range(len(emails_list))],
                    "credit_cards": [generate_credit_card() for _ in range(min(2, len(emails_list)))],
                    "cvv": [f"{random.randint(100, 999)}" for _ in range(min(2, len(emails_list)))],
                    "card_expiry": [f"{random.randint(1,12):02d}/{random.randint(26,30)}" for _ in range(min(2, len(emails_list)))],
                    "account_numbers": [f"40817810{random.randint(10000000, 99999999)}" for _ in range(len(emails_list))],
                    "passwords": smtp_pass,
                    "logins": smtp_users,
                    "full_names": [generate_name() for _ in range(len(emails_list))],
                    "addresses": [generate_address() for _ in range(len(emails_list))],
                    "smtp_users": smtp_users,
                    "smtp_passwords": smtp_pass,
                },
                "url": f"https://gazprombank.ru/?file=../../../.env{i}",
                "payload": f"php://filter/convert.base64-encode/resource=../../../../.env{i}",
                "status": "200",
                "tags": ["email_leak", "smtp_credentials", "high_priority"],
            }
        }
        artifacts.append(artifact)
    
    # ============================================================
    # 2. CREDIT CARD LEAKS
    # ============================================================
    
    for i in range(2):
        cards = [generate_credit_card(card_type="visa") for _ in range(3)]
        
        artifact = {
            "_hash": f"credit_card_leak_{i}_{random.randint(10000, 99999)}",
            "timestamp": (datetime.now() - timedelta(hours=5+i)).isoformat(),
            "module": "SQLi_Scanner",
            "target": "https://gazprombank.ru/account",
            "result": {
                "severity": "critical",
                "category": "credit_card_leak",
                "source": "sqli_tab",
                "type": "SQLi",
                "risk": "critical",
                "credit_cards": cards,
                "user_data": {
                    "names": [generate_name() for _ in range(3)],
                    "addresses": [generate_address() for _ in range(3)],
                    "phone_numbers": [generate_phone_number() for _ in range(3)],
                },
                "tags": ["credit_card", "pci_dss", "critical_priority"],
            }
        }
        artifacts.append(artifact)
    
    # ============================================================
    # 3. PASSWORD DUMPS
    # ============================================================
    
    passwords_dump = {
        "_hash": f"password_dump_{random.randint(10000, 99999)}",
        "timestamp": (datetime.now() - timedelta(days=1)).isoformat(),
        "module": "Database_Leak",
        "target": "https://gazprombank.ru",
        "result": {
            "severity": "critical",
            "category": "password_dump",
            "source": "analyzer",
            "type": "Authentication",
            "risk": "critical",
            "passwords": [generate_password() for _ in range(5)],
            "user_passwords": [
                {
                    "username": f"user_{i}",
                    "password": generate_password(),
                    "hash_type": "bcrypt"
                }
                for i in range(5)
            ],
            "tags": ["password_dump", "credentials", "critical_priority"],
        }
    }
    artifacts.append(passwords_dump)
    
    # ============================================================
    # 4. COMBINED USER DATA LEAK
    # ============================================================
    
    for i in range(2):
        profiles = [generate_user_profile() for _ in range(3)]
        
        artifact = {
            "_hash": f"user_data_leak_{i}_{random.randint(10000, 99999)}",
            "timestamp": (datetime.now() - timedelta(hours=10+i)).isoformat(),
            "module": "Breach_Analysis",
            "target": "https://gazprombank.ru/users",
            "result": {
                "severity": "critical",
                "category": "user_data_leak",
                "source": "analyzer",
                "type": "Data Breach",
                "risk": "critical",
                "leaked_users": [
                    {
                        "email": p["email"],
                        "password": p["password"],
                        "phone": p["phone"],
                        "address": p["address"],
                        "credit_card": p["credit_card"],
                        "birth_date": p["birth_date"],
                        "account_status": random.choice(["active", "premium", "blocked", "suspended"]),
                        "city": generate_address().split(",")[0],
                    }
                    for p in profiles
                ],
                "count": len(profiles),
                "tags": ["user_data", "full_profile", "critical_priority"],
            }
        }
        artifacts.append(artifact)
    
    # ============================================================
    # 5. ACCOUNT STATE EXPOSURES
    # ============================================================
    
    account_states = {
        "_hash": f"account_state_{random.randint(10000, 99999)}",
        "timestamp": (datetime.now() - timedelta(hours=3)).isoformat(),
        "module": "Account_Analyzer",
        "target": "https://gazprombank.ru/api/account",
        "result": {
            "severity": "high",
            "category": "account_state_leak",
            "source": "analyzer",
            "type": "Information Disclosure",
            "risk": "high",
            "accounts": [
                {
                    "account_id": f"ACC_{random.randint(100000, 999999)}",
                    "balance": f"{random.randint(1000, 500000)} RUB",
                    "status": random.choice(["active", "pending", "locked", "suspended"]),
                    "email": generate_email(),
                    "phone": generate_phone_number(),
                    "city": random.choice(CITIES),
                    "verification_status": random.choice(["verified", "pending", "failed"]),
                    "account_age_days": random.randint(1, 3650),
                }
                for _ in range(5)
            ],
            "tags": ["account_state", "financial_data", "high_priority"],
        }
    }
    artifacts.append(account_states)
    
    # ============================================================
    # 6. PHONE NUMBER AGGREGATIONS
    # ============================================================
    
    phone_artifact = {
        "_hash": f"phone_numbers_{random.randint(10000, 99999)}",
        "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
        "module": "Contact_Leak",
        "target": "https://gazprombank.ru/contacts",
        "result": {
            "severity": "high",
            "category": "phone_leak",
            "source": "analyzer",
            "type": "Contact Information",
            "risk": "high",
            "phone_numbers": [generate_phone_number() for _ in range(10)],
            "phone_with_names": [
                {
                    "phone": generate_phone_number(),
                    "name": generate_name(),
                    "city": random.choice(CITIES),
                }
                for _ in range(10)
            ],
            "tags": ["phone_numbers", "contact_data", "high_priority"],
        }
    }
    artifacts.append(phone_artifact)
    
    # ============================================================
    # 7. ADDRESS / LOCATION LEAKS
    # ============================================================
    
    address_artifact = {
        "_hash": f"addresses_{random.randint(10000, 99999)}",
        "timestamp": (datetime.now() - timedelta(hours=1)).isoformat(),
        "module": "GeoLocation_Leak",
        "target": "https://gazprombank.ru/locations",
        "result": {
            "severity": "high",
            "category": "location_leak",
            "source": "analyzer",
            "type": "Location Information",
            "risk": "high",
            "addresses": [generate_address() for _ in range(10)],
            "cities": list(set([random.choice(CITIES) for _ in range(5)])),
            "user_locations": [
                {
                    "user_id": f"U_{random.randint(100000, 999999)}",
                    "email": generate_email(),
                    "city": random.choice(CITIES),
                    "address": generate_address(),
                    "latitude": round(random.uniform(55.0, 56.0), 4),
                    "longitude": round(random.uniform(37.0, 38.0), 4),
                }
                for _ in range(10)
            ],
            "tags": ["locations", "addresses", "gps_data", "high_priority"],
        }
    }
    artifacts.append(address_artifact)
    
    return artifacts


def main():
    """Генерирует и сохраняет данные в analyzer1.json"""
    
    log_dir = Path(__file__).parent / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = log_dir / "analyzer1.json"
    
    print(f"[📊] Генерация тестовых данных Threat Intel...")
    
    artifacts = generate_threat_intel_artifacts()
    
    print(f"[✅] Создано {len(artifacts)} артефактов")
    
    # Структура, как в оригинальном analyzer.json
    data = {
        "total": sum([len(a.get("result", {}).get("emails", [])) or 
                      len(a.get("result", {}).get("credit_cards", [])) or
                      len(a.get("result", {}).get("leaked_users", [])) or
                      len(a.get("result", {}).get("phone_numbers", [])) or 1
                      for a in artifacts]),
        "by_module": {a["module"]: 1 for a in artifacts},
        "by_severity": {},
        "by_category": {},
        "by_source": {},
        "artifacts": artifacts,
    }
    
    # Подсчитываем severity
    for artifact in artifacts:
        severity = artifact.get("result", {}).get("severity", "unknown")
        data["by_severity"][severity] = data["by_severity"].get(severity, 0) + 1
    
    # Подсчитываем category
    for artifact in artifacts:
        category = artifact.get("result", {}).get("category", "unknown")
        data["by_category"][category] = data["by_category"].get(category, 0) + 1
    
    # Подсчитываем source
    for artifact in artifacts:
        source = artifact.get("result", {}).get("source", "engine")
        data["by_source"][source] = data["by_source"].get(source, 0) + 1
    
    # Сохраняем в JSON
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"[💾] Данные сохранены: {output_file}")
        print(f"[📦] Артефактов: {len(artifacts)}")
        print(f"[🏷️] Категории: {list(data['by_category'].keys())}")
        print(f"[⚠️] Severity: {data['by_severity']}")
        
    except Exception as e:
        print(f"[❌] Ошибка при сохранении: {e}")
        return False
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)


