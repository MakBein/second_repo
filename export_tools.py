# xss_security_gui/export_tools.py
"""
Export Tools ULTRA 7.5

- Атомарная запись JSON и текстовых файлов
- Безопасный экспорт CSV
- Автоматическое создание директорий
- Защита от ошибок GUI
- Универсальные функции экспорта
"""

from __future__ import annotations

import os
import re
import json
import csv
from pathlib import Path
from typing import Any, Dict, List

from tkinter import filedialog, messagebox


# ============================================================
# Internal helpers
# ============================================================

def _ensure_dir(path: Path) -> None:
    """Гарантирует существование директории."""
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)


def atomic_json_write(path: str | Path, data: Any) -> bool:
    """
    Атомарная запись JSON:
    - запись во временный файл
    - безопасная замена
    """
    try:
        path = Path(path)
        _ensure_dir(path)

        tmp = path.with_suffix(path.suffix + ".tmp")

        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        os.replace(tmp, path)
        return True

    except Exception as e:
        print(f"[⚠️] Ошибка атомарной записи JSON {path}: {e}")
        return False


def save_text_atomic(content: str, default_name: str = "response.txt") -> None:
    """
    Сохраняет текстовый файл через атомарную запись.
    Использует диалог сохранения.
    """
    try:
        path = filedialog.asksaveasfilename(
            title="Сохранить файл",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[
                ("Text", "*.txt"),
                ("HTML", "*.html"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return

        path = Path(path)
        _ensure_dir(path)

        tmp = path.with_suffix(path.suffix + ".tmp")

        with tmp.open("w", encoding="utf-8") as f:
            f.write(content)

        os.replace(tmp, path)

        messagebox.showinfo("Сохранено", f"Файл сохранён:\n{path}")

    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}")


# ============================================================
# Honeypot CSV Export
# ============================================================

HONEYPOT_PATTERN = re.compile(
    r"\[(.*?)\]\s+ATTACK from (\d+\.\d+\.\d+\.\d+):\s+\"(.+?)\""
)


def export_honeypot_csv(
    log_path: str | Path = "/var/log/honeypot.log",
    output: str | Path = "honeypot_report.csv",
) -> bool:
    """
    Экспортирует honeypot-логи в CSV.
    Формат строки:
        [TIME] ATTACK from IP: "PAYLOAD"
    """
    log_path = Path(log_path)
    output = Path(output)

    if not log_path.exists():
        print(f"[⚠️] Лог-файл не найден: {log_path}")
        return False

    rows: List[Dict[str, str]] = []

    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = HONEYPOT_PATTERN.search(line)
                if m:
                    rows.append(
                        {
                            "Time": m.group(1),
                            "IP": m.group(2),
                            "Payload": m.group(3),
                        }
                    )

        _ensure_dir(output)

        with output.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["Time", "IP", "Payload"])
            writer.writeheader()
            writer.writerows(rows)

        print(f"✅ Экспортировано {len(rows)} событий в {output}")
        return True

    except Exception as e:
        print(f"[⚠️] Ошибка экспорта CSV: {e}")
        return False
