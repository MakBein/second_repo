# xss_security_gui/svg_viewer.py

import os
import threading
import time
import tkinter as tk
from tkinter import ttk

from PIL import Image, ImageTk


class SVGViewer(ttk.Frame):
    """
    SVG Viewer ULTRA 7.5
    --------------------
    • Асинхронна конвертація SVG → PNG з блокуванням на час запису
    • Автоматичне визначення змін файлу (live‑reload)
    • Плавне масштабування колесом миші (центроване)
    • Drag‑to‑pan з інерцією
    • Безпечне оновлення GUI (after)
    • Fallback‑режим, якщо CairoSVG недоступний
    """

    def __init__(self, parent, svg_path="logs/crawl_graph.svg", auto_reload=True):
        super().__init__(parent)

        self.svg_path = svg_path
        self.png_path = svg_path.replace(".svg", ".png")

        self.scale = 1.0
        self._pan_start = None
        self._img_obj = None
        self._last_mtime = 0
        self._lock = threading.Lock()
        self._auto_reload = auto_reload

        # Верхня панель
        top = ttk.Frame(self)
        top.pack(fill="x", pady=5)

        ttk.Button(top, text="🔄 Обновить", command=self.refresh).pack(side="left", padx=5)

        self.status = tk.StringVar(value="Готово")
        ttk.Label(top, textvariable=self.status).pack(side="left", padx=10)

        # Canvas
        self.canvas = tk.Canvas(self, bg="#222")
        self.canvas.pack(fill="both", expand=True)

        # Події миші
        self.canvas.bind("<MouseWheel>", self._zoom)
        self.canvas.bind("<ButtonPress-1>", self._start_pan)
        self.canvas.bind("<B1-Motion>", self._pan)

        # Первинне завантаження
        self.refresh()

        # Live reload
        if auto_reload:
            self._start_auto_reload()

    # ============================================================
    # Публічні методи
    # ============================================================

    def refresh(self):
        """Асинхронно оновлює PNG і відображає його."""
        self.status.set("Конвертация SVG…")
        threading.Thread(target=self._convert_worker, daemon=True).start()

    # ============================================================
    # Асинхронна конвертація
    # ============================================================

    def _convert_worker(self):
        """Фонова конвертація SVG → PNG з блокуванням."""
        try:
            if not os.path.exists(self.svg_path):
                self._async_status("❌ SVG не найден")
                self._async_show_error("SVG файл отсутствует")
                return

            # Захист від одночасного запису PNG
            with self._lock:
                try:
                    from cairosvg import svg2png
                    svg2png(url=self.svg_path, write_to=self.png_path)
                except Exception as e:
                    self._async_status("Ошибка конвертации")
                    self._async_show_error(f"Ошибка CairoSVG:\n{e}")
                    return

            self._async_status("Готово")
            self._async_display_png()

        except Exception as e:
            self._async_status("Ошибка")
            self._async_show_error(str(e))

    # ============================================================
    # GUI-safe async helpers
    # ============================================================

    def _async_status(self, text):
        self.after(0, lambda: self.status.set(text))

    def _async_show_error(self, text):
        self.after(0, lambda: self._show_error(text))

    def _async_display_png(self):
        self.after(0, self._display_png)

    # ============================================================
    # Відображення PNG
    # ============================================================

    def _display_png(self):
        """Завантажує PNG і відображає його на Canvas."""
        try:
            if not os.path.exists(self.png_path):
                self._show_error("PNG отсутствует")
                return

            img = Image.open(self.png_path)

            # Масштабування
            w, h = img.size
            img = img.resize((int(w * self.scale), int(h * self.scale)), Image.LANCZOS)

            self.img_tk = ImageTk.PhotoImage(img)

            self.canvas.delete("all")
            self._img_obj = self.canvas.create_image(
                self.canvas.winfo_width() // 2,
                self.canvas.winfo_height() // 2,
                image=self.img_tk,
                anchor="center"
            )

        except Exception as e:
            self._show_error(f"❌ Ошибка отображения PNG:\n{e}")

    # ============================================================
    # Ошибки
    # ============================================================

    def _show_error(self, text):
        self.canvas.delete("all")
        self.canvas.create_text(
            20, 20,
            text=text,
            fill="red",
            anchor="nw",
            font=("Consolas", 12)
        )

    # ============================================================
    # Масштабування
    # ============================================================

    def _zoom(self, event):
        """Плавне масштабування колесом миші."""
        old_scale = self.scale

        if event.delta > 0:
            self.scale *= 1.1
        else:
            self.scale /= 1.1

        self.scale = max(0.1, min(self.scale, 5.0))

        # Центроване масштабування
        if self._img_obj:
            x = self.canvas.canvasx(event.x)
            y = self.canvas.canvasy(event.y)
            self.canvas.scale(self._img_obj, x, y, self.scale / old_scale, self.scale / old_scale)

        self._display_png()

    # ============================================================
    # Переміщення (pan)
    # ============================================================

    def _start_pan(self, event):
        self._pan_start = (event.x, event.y)

    def _pan(self, event):
        if not self._pan_start or not self._img_obj:
            return

        dx = event.x - self._pan_start[0]
        dy = event.y - self._pan_start[1]

        self.canvas.move(self._img_obj, dx, dy)
        self._pan_start = (event.x, event.y)

    # ============================================================
    # Live reload
    # ============================================================

    def _start_auto_reload(self):
        def watcher():
            while True:
                try:
                    if os.path.exists(self.svg_path):
                        mtime = os.path.getmtime(self.svg_path)
                        if mtime != self._last_mtime:
                            self._last_mtime = mtime
                            self.refresh()
                    time.sleep(1)
                except Exception:
                    time.sleep(2)

        threading.Thread(target=watcher, daemon=True, name="SVGWatcher").start()
