#!/usr/bin/env python3
# xss_security_gui/quick_demo.py
"""
Быстрая демонстрация Email Leak Display

1. Генерирует данные
2. Запускает GUI
3. Автоматически загружает Email Leak во вкладку
"""

import sys
import os
import subprocess
from pathlib import Path

def main():
    base_dir = Path(__file__).parent.parent
    os.chdir(base_dir)
    
    print("\n" + "="*60)
    print("[🚀] XSS Security Suite - Email Leak Display Demo")
    print("="*60)
    
    # Step 1: Генерируем данные
    print("\n[Step 1/2] Генерируем тестовые данные...")
    print("-" * 60)
    
    result = subprocess.run(
        [sys.executable, "-m", "xss_security_gui.generate_threat_intel_data"],
        cwd=base_dir
    )
    
    if result.returncode != 0:
        print("[❌] Ошибка при генерации данных")
        return False
    
    # Step 2: Запускаем GUI
    print("\n[Step 2/2] Запускаем GUI...")
    print("-" * 60)
    print("""
[📋] Инструкции:
    
    1. Когда откроется окно, нажмите на вкладку "📦 Threat Intel"
    2. Дождитесь загрузки данных (может занять 1-2 сек)
    3. Увидите в дереве несколько "📧 Email Leak (high)" записей
    4. Двойной клик по Email Leak откроет окно с деталями
    5. Попробуйте:
       - "Copy email only" - копирует только email адреса
       - "Copy smtp_user:smtp_pass" - копирует пары логин:пароль
       - "Mask/Show passwords" - переключает видимость паролей
       - "Domain Aggregator" - группирует email по доменам
       - "Export leak" - сохраняет утечку в JSON
    
    Закройте окно, чтобы выйти.
""")
    
    result = subprocess.run(
        [sys.executable, "-m", "xss_security_gui.main", "tk"],
        cwd=base_dir
    )
    
    print("\n[✅] Демонстрация завершена")
    return True


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n[⚠️] Демонстрация прерывана пользователем")
        sys.exit(0)
    except Exception as e:
        print(f"\n[❌] Ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

