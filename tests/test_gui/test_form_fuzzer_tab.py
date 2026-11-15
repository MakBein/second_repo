import tkinter as tk
from tkinter import ttk


def _find_button(parent: tk.Misc, label: str) -> ttk.Button:
    for child in parent.winfo_children():
        if isinstance(child, ttk.Button) and child.cget("text") == label:
            return child
        try:
            return _find_button(child, label)
        except LookupError:
            continue
    raise LookupError(f"Sidebar button not found: {label}")


def test_sidebar_navigation_reuses_tab_instances():
    from xss_security_gui.main import XSSSecurityGUI

    window = XSSSecurityGUI()
    bridge = window._ui_queue_bridge

    class ImmediateBridge:
        def post_ui(self, callback, *args, **kwargs):
            callback(*args, **kwargs)

        def stop(self):
            pass

    try:
        # Keep the test deterministic and prevent opening background services
        # through the initial, queued Threat Intel navigation.
        bridge.stop()
        window._ui_queue_bridge = ImmediateBridge()

        created = {}
        labels = ("🛡️ Proxy", "📄 Attack Report")

        for label in labels:
            def create_tab(parent, tab_label=label):
                tab = ttk.Frame(parent)
                ttk.Label(tab, text=tab_label).pack()
                created[tab_label] = created.get(tab_label, 0) + 1
                return tab

            window.tabs[label] = create_tab

        first_button = _find_button(window.sidebar, labels[0])
        second_button = _find_button(window.sidebar, labels[1])

        first_button.invoke()
        window.update_idletasks()
        first_tab = window._tab_instances[labels[0]]
        assert first_tab.winfo_manager() == "pack"

        second_button.invoke()
        window.update_idletasks()
        second_tab = window._tab_instances[labels[1]]
        assert second_tab.winfo_manager() == "pack"
        assert first_tab.winfo_manager() == ""

        first_button.invoke()
        window.update_idletasks()
        assert window._tab_instances[labels[0]] is first_tab
        assert first_tab.winfo_manager() == "pack"
        assert second_tab.winfo_manager() == ""
        assert created == {labels[0]: 1, labels[1]: 1}
    finally:
        window.on_close()
