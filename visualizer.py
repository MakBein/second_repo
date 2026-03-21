# xss_security_gui/visualizer.py
import os
import shutil
import subprocess
import threading


def render_dot_to_svg(dot_path: str, output_path: str, callback=None, timeout: int = 5):
    """
    ULTRA 7.0:
    - Перевірка наявності Graphviz (dot)
    - Безпечний рендер .dot → .svg у окремому потоці
    - Таймаут + гарантоване завершення процесу
    - callback(success: bool, message: str) викликається завжди
    - Повна ізоляція помилок, GUI ніколи не падає
    """

    def safe_callback(success: bool, message: str):
        if callback:
            try:
                callback(success, message)
            except Exception:
                pass

    def worker():
        # 1) Перевірка існування .dot файлу
        if not os.path.exists(dot_path):
            safe_callback(False, f"❌ DOT файл не знайдено: {dot_path}")
            return

        # 2) Перевірка наявності Graphviz
        if shutil.which("dot") is None:
            safe_callback(False, "❌ Graphviz (dot) не знайдено у PATH")
            return

        # 3) Перевірка директорії для output
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
        except Exception as e:
            safe_callback(False, f"❌ Неможливо створити директорію: {e}")
            return

        # 4) Запуск Graphviz
        try:
            proc = subprocess.Popen(
                ["dot", "-Tsvg", dot_path, "-o", output_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                safe_callback(False, f"⏳ Graphviz завис (таймаут {timeout} сек)")
                return

            if proc.returncode == 0:
                safe_callback(True, f"✅ SVG створено: {output_path}")
            else:
                msg = stderr.strip() or stdout.strip() or "Невідома помилка Graphviz"
                safe_callback(False, f"❌ Graphviz помилка: {msg}")

        except Exception as e:
            safe_callback(False, f"❌ Неочікувана помилка: {e}")

    # Запуск у окремому потоці
    threading.Thread(target=worker, daemon=True, name="DotRendererThread").start()