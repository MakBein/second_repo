import queue
import tkinter as tk

import pytest

from xss_security_gui.threat_analysis import internal_hosts_tab as hosts_module


@pytest.fixture(scope="module")
def tk_root():
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


def _wait_for_callback(callback_queue):
    callback, args, kwargs = callback_queue.get(timeout=3)
    callback(*args, **kwargs)


def test_internal_hosts_loads_filters_and_shows_sources(tk_root, monkeypatch):
    artifacts = [
        {
            "target": "https://example.test/",
            "module": "Crawler",
            "result": {"finding": "private address 10.1.2.3"},
        },
        {
            "target": "https://other.test/",
            "module": "Analyzer",
            "result": {"finding": "private address 192.168.1.8"},
        },
    ]

    class FakeConnector:
        def load_all(self):
            return artifacts

    class QueuedBridge:
        def __init__(self):
            self.callbacks = queue.Queue()

        def post_ui(self, callback, *args, **kwargs):
            self.callbacks.put((callback, args, kwargs))

        def stop(self):
            pass

    bridge = QueuedBridge()
    monkeypatch.setattr(hosts_module, "THREAT_CONNECTOR", FakeConnector())
    monkeypatch.setattr(hosts_module, "UIQueueBridge", lambda *_args, **_kwargs: bridge)
    tab = hosts_module.InternalHostsTab(tk_root)
    tab.pack(fill="both", expand=True)

    try:
        _wait_for_callback(bridge.callbacks)
        tk_root.update_idletasks()
        assert len(tab.tree.get_children()) == 2
        assert "IP-адресов: 2" in tab.summary_var.get()

        tab.search_var.set("10.1.2.3")
        tk_root.update_idletasks()
        assert len(tab.tree.get_children()) == 1
        assert tab.tree.item(tab.tree.get_children()[0], "values")[0] == "10.1.2.3"

        tab.tree.selection_set(tab.tree.get_children()[0])
        tab._show_host_details()
        assert "Crawler" in tab.details_box.get("1.0", "end")
    finally:
        tab.destroy()


def test_internal_host_audit_requires_authorized_matching_http_target(
    tk_root, monkeypatch
):
    class QueuedBridge:
        def __init__(self, *_args, **_kwargs):
            pass

        def post_ui(self, *_args, **_kwargs):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(hosts_module, "UIQueueBridge", QueuedBridge)
    monkeypatch.setattr(hosts_module, "is_target_authorized", lambda _url: False)
    warnings = []
    monkeypatch.setattr(hosts_module.messagebox, "showwarning", lambda *args, **kwargs: warnings.append(args))
    tab = hosts_module.InternalHostsTab(tk_root)
    tab.pack(fill="both", expand=True)

    try:
        tab.tree.insert(
            "", "end", values=("10.1.2.3", "https://10.1.2.3/", "Crawler")
        )
        item = tab.tree.get_children()[0]
        tab.tree.selection_set(item)

        tab.audit_selected()

        assert warnings
        assert not any(isinstance(child, tk.Toplevel) for child in tab.winfo_children())
    finally:
        tab.destroy()
