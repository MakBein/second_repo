# xss_security_gui/test_email_leak_display.py
"""
Тестирование отображения Email Leak в Threat Intel GUI

Проверяет:
1. Загрузку analyzer1.json
2. Парсинг email_leak артефактов
3. Отображение в Threat Tab
4. Потокобезопасное взаимодействие
"""

import sys
import os
from pathlib import Path

# Setup path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, base_dir)

from xss_security_gui.threat_data_loader import ThreatDataLoader
import json


def test_data_loader():
    """Тест загрузчика данных"""
    print("\n" + "="*60)
    print("[🧪] TEST 1: Data Loader")
    print("="*60)
    
    loader = ThreatDataLoader()
    
    assert loader.load(), "Не удалось загрузить analyzer1.json"
    
    print(f"[✅] Загружено {len(loader.artifacts)} артефактов")
    
    # Проверяем email leaks
    email_leaks = loader.get_email_leaks()
    print(f"[📧] Email Leaks: {len(email_leaks)}")
    
    for i, leak in enumerate(email_leaks, 1):
        result = leak.get("result", {})
        email_leak = result.get("email_leak", {})
        print(f"\n  📧 Email Leak #{i}")
        print(f"     Module: {leak.get('module')}")
        print(f"     Risk: {result.get('risk')}")
        print(f"     Emails: {len(email_leak.get('emails', []))}")
        print(f"     SMTP Users: {len(email_leak.get('smtp_users', []))}")
        print(f"     SMTP Passwords: {len(email_leak.get('smtp_passwords', []))}")
        
        # Показываем примеры
        emails = email_leak.get('emails', [])
        if emails:
            print(f"     Examples: {', '.join(emails[:2])}")
    
    # Проверяем credit card leaks
    card_leaks = loader.get_credit_card_leaks()
    print(f"\n[💳] Credit Card Leaks: {len(card_leaks)}")
    for i, leak in enumerate(card_leaks, 1):
        result = leak.get("result", {})
        cards = result.get('credit_cards', [])
        print(f"  💳 Card Leak #{i}: {len(cards)} cards")
    
    # Проверяем password dumps
    pwd_dumps = loader.get_password_dumps()
    print(f"\n[🔐] Password Dumps: {len(pwd_dumps)}")
    
    # Проверяем account states
    account_states = loader.get_account_states()
    print(f"\n[💰] Account States: {len(account_states)}")
    for i, acct in enumerate(account_states, 1):
        result = acct.get("result", {})
        accounts = result.get('accounts', [])
        print(f"  💰 Account State #{i}: {len(accounts)} accounts")
        if accounts:
            sample = accounts[0]
            print(f"     Example: {sample.get('email')} ({sample.get('status')})")
    
    # Summary
    summary = loader.get_summary()
    print(f"\n[📊] SUMMARY:")
    print(f"  Total events: {summary['total']}")
    print(f"  By severity: {summary['by_severity']}")
    print(f"  By category: {summary['by_category']}")


def test_artifact_conversion():
    """Тест преобразования артефактов для GUI"""
    print("\n" + "="*60)
    print("[🧪] TEST 2: Artifact Conversion for GUI")
    print("="*60)
    
    loader = ThreatDataLoader()
    
    assert loader.load(), "Не удалось загрузить analyzer1.json"
    
    email_leaks = loader.get_email_leaks()
    
    assert email_leaks, "Email leaks не найдены"
    
    artifact = email_leaks[0]
    gui_artifact = loader.convert_artifact_for_gui(artifact)
    
    print(f"\n[✅] Email Leak артефакт преобразован:")
    print(f"  Type: {gui_artifact.get('type')}")
    print(f"  Category: {gui_artifact.get('category')}")
    print(f"  Risk: {gui_artifact.get('risk')}")
    print(f"  Module: {gui_artifact.get('module')}")
    
    assert "email_leak" in gui_artifact, "email_leak not in artifact"
    
    email_leak = gui_artifact["email_leak"]
    print(f"\n  📧 Email Leak Data:")
    print(f"     Emails: {len(email_leak.get('emails', []))}")
    print(f"     SMTP Users: {len(email_leak.get('smtp_users', []))}")
    print(f"     SMTP Passwords: {len(email_leak.get('smtp_passwords', []))}")
    
    # Проверяем структуру data
    emails = email_leak.get('emails', [])
    users = email_leak.get('smtp_users', [])
    passwords = email_leak.get('smtp_passwords', [])
    
    assert emails and users and passwords, "Структура неполная"
    
    print(f"\n  ✅ Структура корректна для отображения в Threat Tab")


def test_json_structure():
    """Тест структуры JSON данных"""
    print("\n" + "="*60)
    print("[🧪] TEST 3: JSON Structure Validation")
    print("="*60)
    
    loader = ThreatDataLoader()
    
    assert loader.load(), "Не удалось загрузить analyzer1.json"
    
    print(f"\n[✅] JSON Структура:")
    print(f"  Root keys: {list(loader.data.keys())}")
    
    print(f"\n  by_module: {list(loader.data.get('by_module', {}).keys())}")
    print(f"  by_severity: {loader.data.get('by_severity', {})}")
    print(f"  by_category: {list(loader.data.get('by_category', {}).keys())}")
    print(f"  by_source: {loader.data.get('by_source', {})}")
    
    # Проверяем каждый артефакт
    errors = []
    for i, artifact in enumerate(loader.artifacts):
        required_keys = ["_hash", "timestamp", "module", "result"]
        for key in required_keys:
            if key not in artifact:
                errors.append(f"Artifact #{i}: missing {key}")
        
        result = artifact.get("result", {})
        if not isinstance(result, dict):
            errors.append(f"Artifact #{i}: result is not dict")
    
    assert not errors, f"Ошибки в структуре: {errors}"
    
    print(f"\n[✅] Все {len(loader.artifacts)} артефактов имеют правильную структуру")


def test_email_leak_rendering():
    """Тест отображение email leak в формате Threat Tab"""
    print("\n" + "="*60)
    print("[🧪] TEST 4: Email Leak Rendering Simulation")
    print("="*60)
    
    loader = ThreatDataLoader()
    
    assert loader.load(), "Не удалось загрузить analyzer1.json"
    
    email_leaks = loader.get_email_leaks()
    
    assert email_leaks, "Email leaks не найдены"
    
    artifact = email_leaks[0]
    gui_artifact = loader.convert_artifact_for_gui(artifact)
    
    print(f"\n[📧] Симуляция отображения Email Leak:\n")
    
    # Симулируем структуру дерева Threat Tab
    print("  📧 Email Leak (high)")
    print("    ├── Emails")
    
    emails = gui_artifact.get("email_leak", {}).get("emails", [])
    for i, email in enumerate(emails[:3], 1):
        if i < len(emails):
            print(f"    │   ├── {email}")
        else:
            print(f"    │   └── {email}")
    
    if len(emails) > 3:
        print(f"    │   └── ... + {len(emails) - 3} more")
    
    print("    ├── SMTP Users")
    users = gui_artifact.get("email_leak", {}).get("smtp_users", [])
    for i, user in enumerate(users[:3], 1):
        if i < len(users):
            print(f"    │   ├── {user}")
        else:
            print(f"    │   └── {user}")
    
    if len(users) > 3:
        print(f"    │   └── ... + {len(users) - 3} more")
    
    print("    ├── SMTP Passwords")
    passwords = gui_artifact.get("email_leak", {}).get("smtp_passwords", [])
    for i, pwd in enumerate(passwords[:3], 1):
        masked = "*" * len(pwd)
        if i < len(passwords):
            print(f"    │   ├── {masked}")
        else:
            print(f"    │   └── {masked}")
    
    if len(passwords) > 3:
        print(f"    │   └── ... + {len(passwords) - 3} more")
    
    print("    └── Meta")
    print(f"        ├── URL")
    print(f"        ├── Payload")
    print(f"        ├── Status")
    print(f"        └── Length")
    
    print(f"\n[✅] Симуляция успешна")


def main():
    """Запуск всех тестов"""
    print("\n" + "🔴"*30)
    print("THREAT INTEL EMAIL LEAK DISPLAY TEST SUITE")
    print("🔴"*30)
    
    tests = [
        ("Data Loader", test_data_loader),
        ("Artifact Conversion", test_artifact_conversion),
        ("JSON Structure", test_json_structure),
        ("Email Leak Rendering", test_email_leak_rendering),
    ]
    
    results = {}
    
    for name, test_func in tests:
        try:
            test_func()
            results[name] = "✅ PASS"
        except AssertionError as e:
            results[name] = f"❌ FAIL: {e}"
            import traceback
            traceback.print_exc()
        except Exception as e:
            results[name] = f"❌ ERROR: {e}"
            import traceback
            traceback.print_exc()
    
    # Summary
    print("\n" + "="*60)
    print("[📊] TEST SUMMARY")
    print("="*60)
    
    for name, result in results.items():
        print(f"  {name:<30} {result}")
    
    passed = sum(1 for r in results.values() if "✅ PASS" in r)
    total = len(results)
    
    print(f"\n  Total: {passed}/{total} passed")
    
    assert passed == total, f"Некоторые тесты не пройдены: {passed}/{total}"
    
    print("\n[🎉] Все тесты пройдены! GUI готов к отображению email leak.")


if __name__ == "__main__":
    try:
        main()
        sys.exit(0)
    except AssertionError:
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

