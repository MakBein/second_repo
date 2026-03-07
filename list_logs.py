# xss_security_gui/list_logs.py
import os
from datetime import datetime

BASE_DIR = os.path.dirname(__file__)
LOGS_DIR = os.path.join(BASE_DIR, "logs")

def main():
    if not os.path.exists(LOGS_DIR):
        print(f"⚠️ Папка logs не найдена: {LOGS_DIR}")
        return

    print(f"📂 Содержимое папки logs ({LOGS_DIR}):")
    files = []
    for root, dirs, fs in os.walk(LOGS_DIR):
        for name in fs:
            path = os.path.join(root, name)
            size = os.path.getsize(path)
            mtime = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
            files.append((path, size, mtime))

    # сортировка по дате изменения (сначала самые свежие)
    files.sort(key=lambda x: x[2], reverse=True)

    for path, size, mtime in files:
        print(f"{path} — {size} байт — изменён {mtime}")

if __name__ == "__main__":
    main()