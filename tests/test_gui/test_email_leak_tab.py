import tkinter as tk

import pytest

from xss_security_gui.integrations.email_leak_tab import EmailLeakWorkerTab
import xss_security_gui.integrations.email_leak_tab as tab_module


@pytest.fixture(scope="module")
def tk_root():
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class FakeWorker:
    last_result = None

    def __init__(self, started=True):
        self.started = started
        self.start_args = None

    def is_running(self):
        return False

    def start(self, target, **kwargs):
        self.start_args = (target, kwargs)
        return self.started

    def stop(self):
        pass


def test_email_audit_tab_requires_allowlisted_target(tk_root, monkeypatch):
    worker = FakeWorker()
    monkeypatch.setattr(tab_module, "is_target_authorized", lambda _target: False)
    tab = EmailLeakWorkerTab(
        tk_root,
        worker_provider=lambda: worker,
        target_provider=lambda: "https://example.test/",
    )
    tab.pack(fill="both", expand=True)

    try:
        tab.start_audit()

        assert worker.start_args is None
        assert "запуск заблокирован" in tab.status_var.get().lower()
        assert "Опубликованные email" == tab.workspace.tab(0, "text")
    finally:
        tab.destroy()


def test_email_audit_tab_starts_active_and_shows_unmasked_results(tk_root, monkeypatch):
    worker = FakeWorker()
    monkeypatch.setattr(tab_module, "is_target_authorized", lambda _target: True)
    tab = EmailLeakWorkerTab(
        tk_root,
        worker_provider=lambda: worker,
        target_provider=lambda: "https://example.test/",
    )
    tab.pack(fill="both", expand=True)

    try:
        tab.start_audit()
        assert worker.start_args == (
            "https://example.test/",
            {"active_testing": True},
        )

        tab.set_result(
            {
                "status": "completed",
                "target": "https://example.test/",
                "page_count": 1,
                "emails": ["alice@example.test"],
                "email_sources": {"alice@example.test": ["https://example.test/"]},
                "forms": [
                    {
                        "action": "https://example.test/contact",
                        "url": "https://example.test/contact",
                        "method": "POST",
                        "fields": [
                            {"name": "email", "type": "email"},
                            {"name": "password", "type": "password"},
                        ],
                        "input_count": 2,
                        "contains_email": True,
                        "contains_password": True,
                    }
                ],
                "form_submissions": [
                    {
                        "url": "https://example.test/contact",
                        "method": "POST",
                        "status": 200,
                    }
                ],
                "requests": 2,
            }
        )

        email_row = tab.email_tree.item(tab.email_tree.get_children()[0], "values")
        assert email_row[0] == "alice@example.test"
        form_row = tab.form_tree.item(tab.form_tree.get_children()[0], "values")
        assert form_row[1] == "POST"
        assert "email:email" in form_row[2]
        assert "password:password" in form_row[2]
        output = tab.output.get("1.0", "end")
        assert "alice@example.test" in output
        assert '"method": "POST"' in output
    finally:
        tab.destroy()
