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

    def _call_callback_safe(success: bool, message: str):
        if not callback:
            return
        try:
            owner = getattr(callback, "__self__", None)
            after = getattr(owner, "after", None)
            if callable(after):
                try:
                    owner.after(0, lambda s=success, m=message: callback(s, m))
                    return
                except Exception:
                    pass
            # fallback: direct call
            callback(success, message)
        except Exception:
            try:
                callback(success, message)
            except Exception:
                pass

    def _worker_run() -> tuple[bool, str]:
        # Synchronous worker implementation that returns (success, message)
        # 1) Check .dot file
        if not os.path.exists(dot_path):
            return False, f"❌ DOT файл не знайдено: {dot_path}"

        # 2) Check Graphviz availability
        if shutil.which("dot") is None:
            return False, "❌ Graphviz (dot) не знайдено у PATH"

        # 3) Ensure output directory exists
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
        except Exception as e:
            return False, f"❌ Неможливо створити директорію: {e}"

        # 4) Run Graphviz
        try:
            proc = subprocess.Popen(
                ["dot", "-Tsvg", dot_path, "-o", output_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                return False, f"⏳ Graphviz завис (таймаут {timeout} сек)"

            if proc.returncode == 0:
                return True, f"✅ SVG створено: {output_path}"
            else:
                msg = stderr.strip() or stdout.strip() or "Невідома помилка Graphviz"
                return False, f"❌ Graphviz помилка: {msg}"

        except Exception as e:
            return False, f"❌ Неочікувана помилка: {e}"

    # If caller provided a callback, run asynchronously and invoke callback safely
    if callable(callback):
        def _bg():
            success, message = _worker_run()
            _call_callback_safe(success, message)

        threading.Thread(target=_bg, daemon=True, name="DotRendererThread").start()
        return None

    # Otherwise run synchronously and return result tuple
    return _worker_run()
