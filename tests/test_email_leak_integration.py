# xss_security_gui/tests/test_email_leak_integration.py
"""
Интеграционные тесты для Email Leak в Threat Tab

Проверяет:
1. Загрузку analyzer1.json
2. Преобразование артефактов для GUI
3. Добавление угроз в Threat Tab
4. Отображение в GUI структуре
"""

import sys
import os
from pathlib import Path

# Setup path
base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, base_dir)

from xss_security_gui.threat_data_loader import ThreatDataLoader


def test_complete_email_leak_workflow():
    """Полный workflow загрузки Email Leak в GUI"""
    
    print("\n" + "="*70)
    print("[🧪] COMPLETE EMAIL LEAK INTEGRATION TEST")
    print("="*70)
    
    # Шаг 1: Инициализация загрузчика
    print("\n[STEP 1] Инициализация ThreatDataLoader...")
    loader = ThreatDataLoader()
    print("[✅] Загрузчик инициализирован")
    
    # Шаг 2: Загрузка данных
    print("\n[STEP 2] Загрузка analyzer1.json...")
    assert loader.load(), "Не удалось загрузить analyzer1.json"
    print(f"[✅] Загружено {len(loader.artifacts)} артефактов")
    
    # Шаг 3: Фильтрация Email Leaks
    print("\n[STEP 3] Фильтрация Email Leak артефактов...")
    email_leaks = loader.get_email_leaks()
    assert email_leaks, "Email leaks не найдены"
    print(f"[✅] Найдено {len(email_leaks)} Email Leak артефактов")
    
    # Шаг 4: Преобразование для GUI
    print("\n[STEP 4] Преобразование артефактов для GUI...")
    gui_artifacts = []
    for i, artifact in enumerate(email_leaks, 1):
        gui_artifact = loader.convert_artifact_for_gui(artifact)
        assert "email_leak" in gui_artifact, f"Artifact #{i}: email_leak not found"
        assert "category" in gui_artifact, f"Artifact #{i}: category not found"
        assert "risk" in gui_artifact, f"Artifact #{i}: risk not found"
        
        gui_artifacts.append(gui_artifact)
        
        print(f"  📧 Email Leak #{i}")
        print(f"     Category: {gui_artifact.get('category')}")
        print(f"     Risk: {gui_artifact.get('risk')}")
        print(f"     Module: {gui_artifact.get('module')}")
    
    print(f"[✅] Преобразовано {len(gui_artifacts)} артефактов")
    
    # Шаг 5: Проверка структуры для GUI
    print("\n[STEP 5] Проверка структуры артефактов для GUI...")
    for i, artifact in enumerate(gui_artifacts, 1):
        email_leak = artifact.get("email_leak", {})
        assert isinstance(email_leak, dict), f"Artifact #{i}: email_leak is not dict"
        
        emails = email_leak.get("emails", [])
        smtp_users = email_leak.get("smtp_users", [])
        smtp_passwords = email_leak.get("smtp_passwords", [])
        
        assert isinstance(emails, list), f"Artifact #{i}: emails is not list"
        assert isinstance(smtp_users, list), f"Artifact #{i}: smtp_users is not list"
        assert isinstance(smtp_passwords, list), f"Artifact #{i}: smtp_passwords is not list"
        
        assert len(emails) > 0, f"Artifact #{i}: no emails"
        assert len(smtp_users) > 0, f"Artifact #{i}: no smtp_users"
        assert len(smtp_passwords) > 0, f"Artifact #{i}: no smtp_passwords"
        
        print(f"  📧 Email Leak #{i}")
        print(f"     ✓ Emails: {len(emails)}")
        print(f"     ✓ SMTP Users: {len(smtp_users)}")
        print(f"     ✓ SMTP Passwords: {len(smtp_passwords)}")
    
    print("[✅] Все артефакты имеют корректную структуру")
    
    # Шаг 6: Проверка совместимости с add_threat()
    print("\n[STEP 6] Проверка совместимости с threat_tab.add_threat()...")
    for i, artifact in enumerate(gui_artifacts, 1):
        # add_threat() ожидает следующие ключи:
        required_keys = ["type", "category", "risk", "module", "email_leak"]
        
        for key in required_keys:
            assert key in artifact, f"Artifact #{i}: missing required key '{key}'"
        
        print(f"  ✓ Artifact #{i} ready for add_threat()")
    
    print("[✅] Все артефакты готовы к добавлению в Threat Tab")
    
    # Шаг 7: Имитация добавления в GUI
    print("\n[STEP 7] Имитация добавления в threat_tab...")
    simulated_threat_tab = {"threats": []}
    
    for artifact in gui_artifacts:
        simulated_threat_tab["threats"].append(artifact)
    
    print(f"[✅] Добавлено {len(simulated_threat_tab['threats'])} угроз в Threat Tab")
    
    # Summary
    print("\n" + "="*70)
    print("[📊] SUMMARY")
    print("="*70)
    print(f"✅ Total Email Leak artifacts: {len(gui_artifacts)}")
    print(f"✅ All artifacts converted to GUI format")
    print(f"✅ All artifacts ready for threat_tab.add_threat()")
    
    total_emails = sum(len(a.get("email_leak", {}).get("emails", [])) for a in gui_artifacts)
    total_users = sum(len(a.get("email_leak", {}).get("smtp_users", [])) for a in gui_artifacts)
    total_passwords = sum(len(a.get("email_leak", {}).get("smtp_passwords", [])) for a in gui_artifacts)
    
    print(f"\n📧 Total Emails: {total_emails}")
    print(f"👤 Total SMTP Users: {total_users}")
    print(f"🔐 Total SMTP Passwords: {total_passwords}")
    
    print("\n[🎉] Email Leak Integration Complete!")
    
    return gui_artifacts


if __name__ == "__main__":
    try:
        artifacts = test_complete_email_leak_workflow()
        sys.exit(0)
    except AssertionError as e:
        print(f"\n[❌] Assertion Failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"\n[❌] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

