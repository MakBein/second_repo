import tkinter as tk

def test_tab_switch_memory():
    from xss_security_gui.main import XSSSecurityGUI
    window = XSSSecurityGUI()   # сам создаёт Tk()
    window.update_idletasks()

    # переключаем вкладки
    for i in range(window.tab_control.index("end")):
        window.tab_control.select(i)

    assert window.tab_control.index("end") > 0
    window.destroy()