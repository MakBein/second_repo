import json
import threading
import time
import tkinter as tk

import pytest

from xss_security_gui import deep_analysis_tab


@pytest.fixture(scope="module")
def tk_root():
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


def _create_tab(root, json_path):
    tab = deep_analysis_tab.DeepAnalysisTab(root, json_path=str(json_path))
    tab.pack(fill="both", expand=True)
    root.update_idletasks()
    return tab


def _pump_until(root, predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        root.update()
        if predicate():
            return True
        time.sleep(0.01)
    root.update()
    return predicate()


def test_deep_analysis_load_filter_and_details(tmp_path, tk_root):
    results_file = tmp_path / "crawl.json"
    results_file.write_text(
        json.dumps(
            {
                "details": [
                    {
                        "url": "https://example.test/",
                        "cms": ["WordPress", "PHP"],
                        "frameworks": ["React"],
                        "api_endpoints": ["/api"],
                        "tokens": [],
                        "graphql": [],
                        "content_score": 2,
                    },
                    {
                        "url": "https://example.test/about",
                        "cms": "Drupal",
                        "api_endpoints": [],
                        "tokens": ["redacted"],
                        "graphql": [],
                        "content_score": 1,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    root = tk_root
    tab = None

    try:
        tab = _create_tab(root, results_file)

        assert len(tab.tree.get_children()) == 2
        assert tab.summary_var.get() == "Сайтів: 2  |  CMS: 3  |  API endpoints: 1"
        assert tab.cms_filter["values"] == ("Все", "Drupal", "PHP", "WordPress")

        tab.cms_filter.set("WordPress")
        tab.apply_filter()
        assert len(tab.tree.get_children()) == 1
        assert tab.tree.item(tab.tree.get_children()[0], "values")[0] == (
            "https://example.test/"
        )

        tab.tree.selection_set(tab.tree.get_children()[0])
        tab.show_details()
        assert "https://example.test/" in tab.detail_box.get("1.0", "end")
    finally:
        if tab is not None:
            tab.destroy()


def test_deep_crawl_uses_mocked_worker_and_saves_results(
    tmp_path, monkeypatch, tk_root
):
    root = tk_root
    tab = None
    results_file = tmp_path / "crawl.json"
    completed = threading.Event()
    fake_results = {
        "details": [
            {
                "url": "https://authorized.test/",
                "cms": "ExampleCMS",
                "api_endpoints": [],
                "tokens": [],
                "graphql": [],
                "content_score": 0,
            }
        ]
    }

    monkeypatch.setattr(deep_analysis_tab, "is_target_authorized", lambda _url: True)
    monkeypatch.setattr(
        deep_analysis_tab, "deep_crawl_site", lambda _url: fake_results
    )

    try:
        tab = _create_tab(root, results_file)
        tab.ask_target_url = lambda: "authorized.test"

        original_populate = tab.populate_table

        def finish_populate(data):
            original_populate(data)
            completed.set()

        tab.populate_table = finish_populate
        tab.run_deep_crawl()

        assert _pump_until(root, completed.is_set)
        assert json.loads(results_file.read_text(encoding="utf-8")) == fake_results
        assert len(tab.tree.get_children()) == 1
        assert not tab._deep_crawl_running
        assert str(tab.crawl_button.cget("state")) == "normal"
    finally:
        if tab is not None:
            tab.destroy()


def test_network_check_dispatch_uses_ui_bridge_without_real_requests(
    tmp_path, monkeypatch, tk_root
):
    root = tk_root
    tab = None
    logged = threading.Event()
    called = []

    class FakeNetworkChecker:
        def __init__(self, domain, log_fn):
            called.append(("init", domain))
            self.log_fn = log_fn

        def check_icmp(self):
            pass

        def check_http(self):
            pass

        def check_tls_and_alpn(self):
            called.append(("tls", threading.current_thread() is threading.main_thread()))
            self.log_fn("TLS check completed (mock)")
            logged.set()

        def check_ports(self):
            pass

        def run_all_checks(self):
            raise AssertionError("Full network check must not run in this test")

    monkeypatch.setattr(deep_analysis_tab, "NetworkChecker", FakeNetworkChecker)
    monkeypatch.setattr(deep_analysis_tab, "is_target_authorized", lambda _url: True)

    try:
        tab = _create_tab(root, tmp_path / "missing.json")
        tab.full_data = [
            {
                "url": "https://authorized.test/",
                "cms": "ExampleCMS",
                "api_endpoints": [],
                "tokens": [],
                "graphql": [],
            }
        ]
        tab.populate_table(tab.full_data)
        tab.tree.selection_set(tab.tree.get_children()[0])

        tab.run_tls()

        assert _pump_until(root, logged.is_set)
        assert _pump_until(root, lambda: not tab._network_check_running)
        assert called == [
            ("init", "https://authorized.test/"),
            ("tls", False),
        ]
        assert "TLS check completed (mock)" in tab.network_output.get("1.0", "end")
    finally:
        if tab is not None:
            tab.destroy()
