import pytest

from xss_security_gui.auto_recon import scope as scope_module
from xss_security_gui.integrations import email_leak_worker as worker_module


class _FakeResponse:
    status_code = 200
    is_redirect = False
    url = "https://authorized.test/"
    headers = {"Content-Type": "text/html; charset=utf-8"}
    encoding = "utf-8"

    def iter_content(self, chunk_size):
        yield (
            b'<p>Contact: alice@example.test</p>'
            b'<form action="/contact" method="POST">'
            b'<input name="email" type="email">'
            b'<input name="password" type="password">'
            b'<textarea name="message"></textarea>'
            b'<select name="topic"><option value="help">Help</option></select>'
            b'<input name="resume" type="file">'
            b'</form>'
        )

    def close(self):
        pass


class _FakeSession:
    def __init__(self):
        self.headers = {}
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return _FakeResponse()

    def close(self):
        pass


def _force_requests_engine(monkeypatch, session):
    monkeypatch.setattr(worker_module, "playwright_is_available", lambda: False)
    monkeypatch.setattr(worker_module.requests, "Session", lambda: session)
    monkeypatch.setattr(worker_module, "is_target_authorized", lambda _url: True)
    monkeypatch.setattr(scope_module, "is_target_authorized", lambda _url: True)
    monkeypatch.setattr(worker_module, "rate_limit", lambda: None)


def test_email_audit_inventories_forms_without_submitting(monkeypatch):
    session = _FakeSession()
    _force_requests_engine(monkeypatch, session)

    result = worker_module.run_email_leak_audit(
        "https://authorized.test/",
        active_testing=False,
    )

    assert result["status"] == "completed"
    assert result["emails"] == ["alice@example.test"]
    assert result["form_count"] == 1
    assert result["forms"][0]["method"] == "POST"
    assert result["forms"][0]["action"] == "https://authorized.test/contact"
    assert [field["type"] for field in result["forms"][0]["fields"]] == [
        "email",
        "password",
        "textarea",
        "select",
        "file",
    ]
    assert result["form_submissions"] == []
    assert result["active_form_submissions"] is False
    assert [call[0] for call in session.calls] == ["GET"]


def test_email_audit_submits_post_for_allowlisted_target(monkeypatch):
    session = _FakeSession()
    _force_requests_engine(monkeypatch, session)

    result = worker_module.run_email_leak_audit(
        "https://authorized.test/",
        active_testing=True,
        form_values={"email": "audit@example.test"},
    )

    assert result["status"] == "completed"
    assert result["active_testing"] is True
    assert result["active_form_submissions"] is True
    assert result["form_submissions"][0]["method"] == "POST"
    assert result["form_submissions"][0]["url"] == "https://authorized.test/contact"
    assert [call[0] for call in session.calls] == ["GET", "POST"]
    posted = session.calls[1]
    assert posted[2]["data"]["email"] == "audit@example.test"
    assert posted[2]["data"]["password"] == "audit-check"
    assert "resume" not in posted[2]["data"]


def test_email_worker_starts_active_form_values(monkeypatch):
    captured = {}

    def fake_audit(target_url, **kwargs):
        captured["target"] = target_url
        captured["kwargs"] = kwargs
        return {"status": "completed", "emails": [], "artifact": None}

    monkeypatch.setattr(worker_module, "run_email_leak_audit", fake_audit)
    worker = worker_module.EmailLeakWorker()
    started = worker.start(
        "https://authorized.test/",
        active_testing=True,
        form_values={"email": "audit@example.test"},
    )
    assert started is True
    worker.stop()
    if worker._thread is not None:
        worker._thread.join(timeout=2)
    assert captured["kwargs"]["active_testing"] is True
    assert captured["kwargs"]["form_values"] == {"email": "audit@example.test"}
