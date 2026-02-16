# xss_security_gui/auto_recon/gui_elements.py
from tkinter import Frame, Button, Label

def build_auto_recon_panel(parent, on_scan, on_generate, on_attack):
    panel = Frame(parent)
    Label(panel, text="🔍 AutoRecon Suite").pack()

    Button(panel, text="Сканировать цели", command=on_scan).pack()
    Button(panel, text="Сгенерировать Payload'ы", command=on_generate).pack()
    Button(panel, text="Запустить атаку", command=on_attack).pack()

    return panel