# xss_security_gui/visualizer.py
import os
import subprocess
import threading


def render_dot_to_svg(dot_path: str, output_path: str, callback=None, timeout=5):
    """
    ULTRA 5.0:
    - Рендер .dot → .svg в отдельном потоке
    - Таймаут защиты от зависания Graphviz
    - callback(success: bool, message: str) вызывается в конце
    """

    def worker():
        if not os.path.exists(dot_path):
            if callback:
                callback(False, f"❌ DOT файл не найден: {dot_path}")
            return

        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            result = subprocess.run(
                ["dot", "-Tsvg", dot_path, "-o", output_path],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode == 0:
                if callback:
                    callback(True, f"✅ SVG создан: {output_path}")
            else:
                if callback:
                    callback(False, f"❌ Ошибка Graphviz: {result.stderr or result.stdout}")

        except subprocess.TimeoutExpired:
            if callback:
                callback(False, f"⏳ Graphviz завис (таймаут {timeout} сек)")

        except Exception as e:
            if callback:
                callback(False, f"❌ Неожиданная ошибка: {e}")

    # Запускаем рендер в отдельном потоке
    threading.Thread(target=worker, daemon=True).start()