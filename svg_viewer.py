# xss_security_gui/svg_viewer.py
import os
import threading
import tkinter as tk
from tkinter import ttk

from PIL import Image, ImageTk


class SVGViewer(ttk.Frame):
    """
    SVG Viewer ULTRA 5.0
    - Асинхронная конвертация SVG → PNG
    - Масштабирование колесом мыши
    - Перемещение изображения (drag-to-pan)
    - Автообновление
    - Кнопка «Обновить»
    """

    def __init__(self, parent, svg_path="logs/crawl_graph.svg"):
        super().__init__(parent)

        self.svg_path = svg_path
        self.png_path = svg_path.replace(".svg", ".png")

        # Масштаб
        self.scale = 1.0

        # ============================================================
        # Верхняя панель
        # ============================================================
        top = ttk.Frame(self)
        top.pack(fill="x", pady=5)

        ttk.Button(top, text="🔄 Обновить", command=self.refresh).pack(side="left", padx=5)

        self.status = tk.StringVar(value="Готово")
        ttk.Label(top, textvariable=self.status).pack(side="left", padx=10)

        # ============================================================
        # Canvas для изображения
        # ============================================================
        self.canvas = tk.Canvas(self, bg="#222")
        self.canvas.pack(fill="both", expand=True)

        # События мыши
        self.canvas.bind("<MouseWheel>", self._zoom)
        self.canvas.bind("<ButtonPress-1>", self._start_pan)
        self.canvas.bind("<B1-Motion>", self._pan)

        self._pan_start = None
        self._img_obj = None

        # Первичная загрузка
        self.refresh()

    # ============================================================
    # Публичные методы
    # ============================================================

    def refresh(self):
        """Асинхронно обновляет PNG и отображает его."""
        self.status.set("Конвертация SVG…")
        threading.Thread(target=self._convert_worker, daemon=True).start()

    # ============================================================
    # Асинхронная конвертация
    # ============================================================

    def _convert_worker(self):
        """Фоновая конвертация SVG → PNG."""
        try:
            if not os.path.exists(self.svg_path):
                self._async_status("❌ SVG не найден")
                self._async_show_error("SVG файл отсутствует")
                return

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
    # Отображение PNG
    # ============================================================

    def _display_png(self):
        """Загружает PNG и отображает его на Canvas."""
        try:
            img = Image.open(self.png_path)

            # Масштабирование
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
    # Масштабирование
    # ============================================================

    def _zoom(self, event):
        """Масштабирование колесом мыши."""
        if event.delta > 0:
            self.scale *= 1.1
        else:
            self.scale /= 1.1

        self.scale = max(0.1, min(self.scale, 5.0))
        self._display_png()

    # ============================================================
    # Перемещение изображения
    # ============================================================

    def _start_pan(self, event):
        self._pan_start = (event.x, event.y)

    def _pan(self, event):
        if not self._pan_start:
            return

        dx = event.x - self._pan_start[0]
        dy = event.y - self._pan_start[1]

        self.canvas.move(self._img_obj, dx, dy)
        self._pan_start = (event.x, event.y)
