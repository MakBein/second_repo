import pytest
from types import SimpleNamespace

from xss_security_gui.auto_recon import scope, xss_flooder
from xss_security_gui.auto_recon import analyzer as analyzer_module
from xss_security_gui.auto_recon.reporting import ReportGenerator
from xss_security_gui.monitor_tab import SuperCrawlerMonitorTab
from xss_security_gui.settings import Settings, settings
from xss_security_gui.threat_analysis.sqli_module import SQLiTester


class FakeResponse:
    def __init__(self, url, status_code=302, headers=None):
        self.url = url
        self.status_code = status_code
        self.headers = headers or {}
        self.is_redirect = 300 <= status_code < 400
        self.ok = 200 <= status_code < 400
        self.closed = False

    def close(self):
        self.closed = True


class FakeRequester:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.response


def test_target_scope_is_closed_by_default(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_REAL_RUN", False, raising=False)
    monkeypatch.setattr(settings, "ALLOWED_TARGETS", ["example.test"], raising=False)

    assert not scope.is_target_authorized("https://example.test")


def test_target_scope_can_be_explicitly_configured_from_environment(monkeypatch):
    monkeypatch.setenv("XSS_AUTORECON_ALLOW_REAL_RUN", "true")
    monkeypatch.setenv("XSS_AUTORECON_ALLOWED_TARGETS", "localhost,127.0.0.1")

    configured = Settings()

    assert configured.get("autorecon.allow_real_run") is True
    assert configured.get("autorecon.allowed_targets") == ["localhost", "127.0.0.1"]


def test_scoped_request_does_not_follow_external_redirect(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_REAL_RUN", True, raising=False)
    monkeypatch.setattr(settings, "ALLOWED_TARGETS", ["example.test"], raising=False)
    response = FakeResponse(
        "https://example.test/start",
        headers={"Location": "https://outside.test/next"},
    )
    requester = FakeRequester(response)

    result = scope.scoped_request(
        requester,
        "GET",
        "https://example.test/start",
        root_url="https://example.test",
    )

    assert result is response
    assert response.closed
    assert len(requester.calls) == 1


def test_flooder_rejects_unallowlisted_targets_without_requests(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_REAL_RUN", True, raising=False)
    monkeypatch.setattr(settings, "ALLOWED_TARGETS", ["allowed.test"], raising=False)

    with pytest.raises(PermissionError, match="not authorized"):
        xss_flooder.start_flood(target_urls=["https://outside.test/"])


def test_sqli_tester_fails_closed_when_allowlist_is_empty(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_REAL_RUN", True, raising=False)
    monkeypatch.setattr(settings, "ALLOWED_TARGETS", [], raising=False)
    tester = SQLiTester("https://outside.test/", "q", "test", {"default": ["test"]})

    result = tester.send_request("test")

    assert result == {"status": "blocked", "reason": "domain-not-allowed"}


def test_flooder_log_clear_removes_existing_content(monkeypatch, tmp_path):
    log_path = tmp_path / "flood.log"
    log_path.write_text("previous scan output", encoding="utf-8")
    monkeypatch.setattr(xss_flooder, "LOG_PATH", log_path)

    xss_flooder.clear_flood_log()

    assert log_path.read_text(encoding="utf-8") == ""


def test_monitor_audit_uses_current_url_provider():
    monitor_state = SimpleNamespace(
        root_url="",
        target_provider=lambda: " https://authorized.example.test/path ",
    )

    target = SuperCrawlerMonitorTab._resolve_audit_target(monitor_state)

    assert target == "https://authorized.example.test/path"


def test_passive_analysis_skips_active_probes_and_streams_progress(monkeypatch, tmp_path):
    class FakeCSP:
        def __init__(self, threat_tab):
            pass

        def run(self, response):
            return {}

    class FakeDOM:
        def __init__(self, threat_tab):
            pass

        def analyze_html(self, text, url):
            return []

    class FakeCSRF:
        def __init__(self, text):
            pass

        def extract_tokens(self):
            return []

        def analyze_headers(self, headers):
            return {}

    class FakeConnector:
        def add_artifact(self, *args):
            pass

        def summary(self):
            return {}

    def forbidden_probe(*args, **kwargs):
        raise AssertionError("active probe ran during passive analysis")

    monkeypatch.setattr(analyzer_module, "CSPAnalyzer", FakeCSP)
    monkeypatch.setattr(analyzer_module, "DOMXSSDetector", FakeDOM)
    monkeypatch.setattr(analyzer_module, "CSRFAnalyzer", FakeCSRF)
    monkeypatch.setattr(analyzer_module, "SQLiTester", forbidden_probe)
    monkeypatch.setattr(analyzer_module, "SSRFTester", forbidden_probe)
    analyzer = analyzer_module.AutoReconAnalyzerV2(FakeConnector())
    analyzer.log_path = str(tmp_path / "analysis.ndjson")
    events = []

    result = analyzer.analyze(
        [{"url": "https://example.test/", "text": "", "headers": {}}],
        progress_callback=events.append,
    )

    assert result["sqli"][0]["results"][0]["status"] == "skipped"
    assert result["ssrf"][0]["results"][0]["status"] == "skipped"
    assert any(event["status"] == "page_started" for event in events)
    assert any(
        event["status"] == "module_complete"
        and event["details"].get("module") == "DOM-XSS"
        for event in events
    )
    assert events[-1]["status"] == "page_complete"


def test_html_report_escapes_untrusted_scan_data(tmp_path):
    reporter = ReportGenerator()
    reporter.out_dir = tmp_path
    report = {
        "metadata": {
            "targets": ["https://example.test"],
            "generated_at": "2026-10-29T00:00:00+00:00",
            "risk_level": "low",
            "risk_score": 1,
        },
        "scan_report": {"count": 1, "items": []},
        "vulnerability_report": {
            "count": 1,
            "items": [{"severity": "high", "evidence": "<script>alert(1)</script>"}],
        },
        "threat_summary": {"example": "<img src=x onerror=alert(1)>"},
        "attack_results": [],
    }

    output = reporter.generate_html_report(report, "test-report")
    contents = (tmp_path / "autorecon_report_test-report.html").read_text(encoding="utf-8")

    assert output.endswith("autorecon_report_test-report.html")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in contents
    assert "&lt;img src=x onerror=alert(1)&gt;" in contents
    assert "<script>alert(1)</script>" not in contents
