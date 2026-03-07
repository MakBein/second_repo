# xss_security_gui/debug_project.py
"""
Debug Project ULTRA 6.2
Отладочный скрипт для XSS Security GUI:
- Проверка импортов модулей
- Проверка наличия файлов и __init__.py
- Универсальный вывод с логированием
"""

import os
import sys
import importlib
import traceback

print("🔧 Запуск отладочного скрипта XSS Security GUI\n")

# 📁 Корень проекта
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, PROJECT_ROOT)

# 📦 Модули для импорта
MODULES_TO_CHECK = [
    # Core GUI
    "main", "settings", "settings_gui", "settings_editor", "overview_tab", "live_log_tab",
    "form_fuzzer_tab", "batch_report_tab", "deep_analysis_tab", "deep_scanner_tab",
    "exploit_tab", "idor_tab", "lfi_tab", "site_map_tab", "attack_report_tab",
    "full_analysis_tab", "threat_tab", "autoanalyzer_tab",

    # Engine & logic
    "crawler", "mutator", "param_fuzzer", "attack_launcher", "trap_engine",
    "honeypot_server", "honeypot_monitor", "export_tools", "token_generator",
    "api_parser", "dom_parser", "analyzer",

    # Auto Recon
    "auto_recon.scanner", "auto_recon.payloads", "auto_recon.planner",
    "auto_recon.analyzer", "auto_recon.recon_pipeline",
    "auto_recon.gui_elements", "auto_recon.test_recon",

    # Threat Analysis
    "threat_analysis.engine", "threat_analysis.csp_module",
    "threat_analysis.dom_events_module", "threat_analysis.cookie_tracer",

    # Utils
    "utils.jwt_decoder", "utils.core_utils",

    # Payloads
    "payload_generator", "payloads",

    # GUI tabs
    "token_view_tab"
]

# 📁 Файлы для проверки
REQUIRED_FILES = [
    "settings.json", "gui_state.json", "requirements.txt", "README.md",
    "resources/xss_payload_db.json", "payloads/xss.txt", "payloads/payload_db.json",
    "logs/crawler_results.json", "logs/deep_crawl.json", "logs/api_attack.log",
    "logs/dom_attack.log", "logs/token_hits.log", "logs/attack_plan.json",
    "logs/idor_test_results.json", "logs/api_attack_history.json",
    "logs/attack_logs.md", "logs/idor_report.md", "logs/honeypot.log"
]

# 📁 Проверка наличия __init__.py в пакетах
REQUIRED_INITS = [
    "auto_recon/__init__.py",
    "threat_analysis/__init__.py",
    "utils/__init__.py"
]


def check_module(name: str):
    """Проверка импорта модуля"""
    try:
        importlib.import_module(name)
        print(f"[✅] Импортирован: {name}")
    except Exception:
        print(f"[❌] Ошибка импорта: {name}")
        traceback.print_exc()


def check_file(path: str):
    """Проверка наличия файла"""
    if os.path.exists(path):
        print(f"[📂] Найден: {path}")
    else:
        print(f"[⚠️] Отсутствует: {path}")


def main():
    print("📦 Проверка модулей:")
    for mod in MODULES_TO_CHECK:
        check_module(mod)

    print("\n📁 Проверка файлов:")
    for file in REQUIRED_FILES + REQUIRED_INITS:
        check_file(file)

    print("\n✅ Все проверки завершены. Если нет ошибок выше — проект готов к запуску.")


if __name__ == "__main__":
    main()