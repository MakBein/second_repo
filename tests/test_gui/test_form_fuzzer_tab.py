import tkinter as tk

def test_tab_switch_memory():
    from xss_security_gui.main import XSSSecurityGUI
    import tkinter as _tk
    try:
        window = XSSSecurityGUI()   # сам создаёт Tk()
    except _tk.TclError:
        import pytest
        pytest.skip("Tcl/Tk not available in test environment")
    window.update_idletasks()

    # переключаем вкладки
    for i in range(window.tab_control.index("end")):
        window.tab_control.select(i)

    assert window.tab_control.index("end") > 0
    window.destroy()