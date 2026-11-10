# xss_security_gui/email_leak_loader_demo.py
"""
Демонстрация загрузки Email Leak данных в Threat Tab

Использует threat_data_loader.py для интеграции с GUI
"""

import sys
from pathlib import Path

# Setup path
base_dir = Path(__file__).parent.parent
sys.path.insert(0, str(base_dir))

from xss_security_gui.threat_data_loader import ThreatDataLoader


def demo_email_leak_loading():
    """Демонстрирует процесс загрузки Email Leak данных"""
    
    print("\n" + "="*60)
    print("[📧] EMAIL LEAK LOADER DEMO")
    print("="*60)
    
    loader = ThreatDataLoader()
    
    # Загрузка данных
    print("\n[1️⃣] Загрузка analyzer1.json...")
    if not loader.load():
        print("[❌] Не удалось загрузить данные")
        return
    
    # Получение Email Leaks
    print("\n[2️⃣] Получение Email Leak артефактов...")
    email_leaks = loader.get_email_leaks()
    print(f"[✅] Найдено {len(email_leaks)} Email Leak артефактов")
    
    # Преобразование для GUI
    print("\n[3️⃣] Преобразование артефактов для GUI...")
    gui_artifacts = []
    for i, artifact in enumerate(email_leaks, 1):
        gui_artifact = loader.convert_artifact_for_gui(artifact)
        gui_artifacts.append(gui_artifact)
        
        print(f"\n  📧 Email Leak #{i}")
        print(f"     Module: {gui_artifact.get('module')}")
        print(f"     Risk: {gui_artifact.get('risk')}")
        print(f"     URL: {gui_artifact.get('url', 'N/A')}")
        
        email_leak = gui_artifact.get("email_leak", {})
        print(f"     📊 Data:")
        print(f"        Emails: {len(email_leak.get('emails', []))}")
        print(f"        SMTP Users: {len(email_leak.get('smtp_users', []))}")
        print(f"        SMTP Passwords: {len(email_leak.get('smtp_passwords', []))}")
    
    # Структура для отправки в GUI
    print("\n[4️⃣] Структура для GUI:")
    print("\n  Каждая угроза отправляется в threat_tab.add_threat()")
    print("  Метод автоматически добавляет ее в Threat Intel Tab")
    
    print("\n[✅] Демонстрация завершена")
    print(f"\n[📦] Готово к интеграции с GUI:")
    print(f"    - {len(gui_artifacts)} Email Leak артефактов")
    print(f"    - Все данные преобразованы в GUI формат")
    
    return gui_artifacts


if __name__ == "__main__":
    try:
        artifacts = demo_email_leak_loading()
        if artifacts:
            print("\n[🎉] Email Leak загрузчик готов к использованию!")
            sys.exit(0)
        else:
            sys.exit(1)
    except Exception as e:
        print(f"\n[❌] Ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

