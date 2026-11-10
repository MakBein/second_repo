import tkinter as tk

from xss_security_gui.site_map_tab import SiteMapTab


def test_site_map_refresh_runs_on_tk_schedule_and_is_cancelled(tmp_path):
    root = tk.Tk()
    root.withdraw()
    tab = None

    try:
        tab = SiteMapTab(root)
        tab.json_path = str(tmp_path / "missing-crawler-results.json")

        assert tab._refresh_after_id is not None

        tab.auto_refresh_loop()
        assert tab._refresh_after_id is not None

        tab.destroy()
        tab = None
    finally:
        if tab is not None:
            tab.destroy()
        root.destroy()
