# xss_security_gui/env_check.py

import sys
import importlib.util
import subprocess

def run_env_check():
    results = []
    results.append(f"[ENV] Python: {sys.version}")
    results.append(f"[ENV] Executable: {sys.executable}")

    # Проверка ключевых пакетов
    for pkg in ["requests", "fpdf", "graphviz", "bs4"]:
        spec = importlib.util.find_spec(pkg)
        results.append(f"[ENV] {pkg}: {'OK' if spec else 'MISSING'}")

    # Проверка Graphviz (dot.exe)
    try:
        out = subprocess.check_output(["dot", "-V"], text=True)
        results.append(f"[ENV] Graphviz: {out.strip()}")
    except Exception as e:
        results.append(f"[ENV] Graphviz: ERROR ({e})")

    return "\n".join(results)