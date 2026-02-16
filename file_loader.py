# xss_security_gui/file_loader.py
import os
import json

BASE_DIR = os.path.dirname(__file__)
LOGS_DIR = os.path.join(BASE_DIR, "logs")

def ensure_logs_dir():
    """Создаёт папку logs внутри пакета, если её нет"""
    os.makedirs(LOGS_DIR, exist_ok=True)

def load_file(filename, default=""):
    """Загружает текстовый файл из logs/, если нет — возвращает default"""
    ensure_logs_dir()
    path = os.path.join(LOGS_DIR, filename)
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"[⚠️] Ошибка загрузки {filename}: {e}")
        return default

def load_json(filename, default=None):
    """Загружает JSON из logs/, если нет — возвращает default"""
    ensure_logs_dir()
    path = os.path.join(LOGS_DIR, filename)
    if not os.path.exists(path):
        return default if default is not None else {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[⚠️] Ошибка загрузки {filename}: {e}")
        return default if default is not None else {}

def save_json(filename, data):
    """Сохраняет JSON в logs/"""
    ensure_logs_dir()
    path = os.path.join(LOGS_DIR, filename)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[⚠️] Ошибка сохранения {filename}: {e}")