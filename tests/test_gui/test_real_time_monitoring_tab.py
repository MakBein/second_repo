import queue
import time
import tkinter as tk

import pytest

from xss_security_gui.gui import real_time_monitoring_tab as monitoring_module


@pytest.fixture(scope="module")
def tk_root():
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


def _pump_until(root, predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        root.update()
        if predicate():
            return True
        time.sleep(0.01)
    root.update()
    return predicate()


def test_monitoring_loads_filters_and_displays_events(tk_root, monkeypatch):
    artifacts = [
        {
            "timestamp": "2026-11-07T10:00:00Z",
            "module": "Crawler",
            "target": "https://example.test/",
            "result": {"severity": "high", "category": "exposure", "source": "test"},
        },
        {
            "timestamp": "2026-11-07T09:00:00Z",
            "module": "Analyzer",
            "target": "https://other.test/",
            "result": {"severity": "low", "category": "headers"},
        },
    ]

    class FakeConnector:
        def load_all(self):
            return artifacts

    class FakeWatcher:
        url = "https://example.test/"
        interval = 5

        def get_status(self):
            return "running"

        def get_retry_stats(self):
            return {"retries": 1}

    class QueuedBridge:
        def __init__(self):
            self.callbacks = queue.Queue()

        def post_ui(self, callback, *args, **kwargs):
            self.callbacks.put((callback, args, kwargs))

    monkeypatch.setattr(monitoring_module, "THREAT_CONNECTOR", FakeConnector())
    bridge = QueuedBridge()
    tab = monitoring_module.RealTimeMonitoringTab(
        tk_root, bridge, watcher=FakeWatcher()
    )
    tab.pack(fill="both", expand=True)
    try:
        callback, args, kwargs = bridge.callbacks.get(timeout=3)
        callback(*args, **kwargs)
        tk_root.update_idletasks()
        assert len(tab.tree.get_children()) == 2
        assert "running" in tab.status_var.get()
        assert "Подій: 2" in tab.summary_var.get()

        tab.severity_filter.set("high")
        tab._apply_filters()
        assert len(tab.tree.get_children()) == 1
        assert tab.tree.item(tab.tree.get_children()[0], "values")[1] == "Crawler"

        tab.tree.selection_set(tab.tree.get_children()[0])
        tab._show_event_details()
        assert "exposure" in tab.details_box.get("1.0", "end")
    finally:
        tab.destroy()
