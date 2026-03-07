# xss_security_gui/auto_recon/gui_elements.py
"""
GUI Elements — панель управления AutoRecon.
"""

from tkinter import Frame, Button, Label
from typing import Callable


def build_auto_recon_panel(
    parent,
    on_scan: Callable[[], None],
    on_generate: Callable[[], None],
    on_attack: Callable[[], None],
) -> Frame:
    """
    Создаёт панель AutoRecon с тремя кнопками:
    • Сканирование целей
    • Генерация payload'ов
    • Запуск атаки

    :param parent: родительский Tkinter‑виджет
    :param on_scan: callback для кнопки "Сканировать цели"
    :param on_generate: callback для кнопки "Сгенерировать Payload'ы"
    :param on_attack: callback для кнопки "Запустить атаку"
    :return: готовый Frame
    """
    panel = Frame(parent)

    Label(panel, text="🔍 AutoRecon Suite", font=("Arial", 12, "bold")).pack(pady=(0, 8))

    Button(panel, text="Сканировать цели", command=on_scan, width=28).pack(pady=2)
    Button(panel, text="Сгенерировать Payload'ы", command=on_generate, width=28).pack(pady=2)
    Button(panel, text="Запустить атаку", command=on_attack, width=28).pack(pady=2)

    return panel


__all__ = ["build_auto_recon_panel"]