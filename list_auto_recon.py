# xss_security_gui/list_auto_recon.py

from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent
AUTO_RECON_DIR = BASE_DIR / "auto_recon"


def format_time(ts: float) -> str:
    """Форматирует timestamp в читаемую дату."""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def human_size(size: int) -> str:
    """Преобразует размер файла в удобный формат."""
    for unit in ["байт", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def list_auto_recon_files(extension: str | None = None) -> list[dict]:
    """
    Возвращает список файлов в auto_recon/ с размерами и датами.
    Можно фильтровать по расширению (например, '.txt').
    """
    if not AUTO_RECON_DIR.exists():
        print(f"❌ Папка auto_recon не найдена: {AUTO_RECON_DIR}")
        return []

    files_info = []
    for path in sorted(AUTO_RECON_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if not path.is_file():
            continue
        if extension and not path.suffix == extension:
            continue

        stat = path.stat()
        files_info.append({
            "path": str(path),
            "size": human_size(stat.st_size),
            "mtime": format_time(stat.st_mtime),
        })

    # Печать в консоль
    print(f"📂 Содержимое папки auto_recon ({AUTO_RECON_DIR}):")
    for f in files_info:
        print(f"{f['path']} — {f['size']} — изменён {f['mtime']}")

    return files_info


if __name__ == "__main__":
    list_auto_recon_files()