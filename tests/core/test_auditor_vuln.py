#!/usr/bin/env python3
"""
RedAudit - Tests for auditor vulnerability helpers.
"""

import contextlib
from unittest.mock import MagicMock, patch

from redaudit.core import auditor_vuln
from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.core.auditor_vuln import AuditorVuln
from redaudit.core.models import Host


def _make_app():
    app = InteractiveNetworkAuditor()
    # v4.0 Mock UI
    app._ui_manager = MagicMock()
    app._ui_manager.colors = {
        "ENDC": "",
        "OKBLUE": "",
        "CYAN": "",
        "BOLD": "",
        "HEADER": "",
        "FAIL": "",
        "OKGREEN": "",
        "WARNING": "",
    }
    app._ui_manager.t.side_effect = lambda key, *args: key

    app.print_status = lambda *_args, **_kwargs: None
    app._set_ui_detail = lambda *_args, **_kwargs: None
    app.logger = None
    return app


def test_parse_url_target():
    app = _make_app()
    assert app._parse_url_target(None) == ("", 0, "")
    assert app._parse_url_target("example.com:8443") == ("example.com", 8443, "")
    assert app._parse_url_target("https://example.com") == ("example.com", 443, "https")
    assert app._parse_url_target("http://example.com:8080/path") == (
        "example.com",
        8080,
        "http",
    )


def test_parse_url_target_handles_empty_and_invalid(monkeypatch):
    app = _make_app()
    assert app._parse_url_target("   ") == ("", 0, "")
    assert app._parse_url_target("example.com:bad") == ("example.com", 0, "")
    assert app._parse_url_target("http://example.com") == ("example.com", 80, "http")

    def _broken_parse(*_args, **_kwargs):
        raise ValueError("boom")

    monkeypatch.setattr("urllib.parse.urlparse", _broken_parse)
    assert app._parse_url_target("http://bad.example") == ("", 0, "")


def test_normalize_host_info_with_host_model():
    host = Host(ip="10.0.0.9", ports=[{"port": 80, "service": "http"}], web_ports_count=1)
    normalized = AuditorVuln._normalize_host_info(host)
    assert normalized["ip"] == "10.0.0.9"
    assert normalized["web_ports_count"] == 1


def test_merge_nuclei_findings_creates_hosts():
    app = _make_app()
    app.results["vulnerabilities"] = [{"host": "10.0.0.1", "vulnerabilities": []}]

    findings = [
        {"matched_at": "http://10.0.0.1:80", "severity": "high", "template_id": "t1"},
        {"host": "10.0.0.2:443", "name": "n2"},
    ]
    merged = app._merge_nuclei_findings(findings)
    assert merged == 2

    vuln_hosts = {entry["host"] for entry in app.results["vulnerabilities"]}
    assert vuln_hosts == {"10.0.0.1", "10.0.0.2"}


def test_merge_nuclei_findings_skips_invalid_entries():
    app = _make_app()
    app.results["vulnerabilities"] = ["invalid", {"host": "10.0.0.1", "vulnerabilities": []}]

    findings = [
        "bad",
        {"matched_at": "", "host": "10.0.0.2:443", "template_id": "t2"},
        {"matched_at": "", "host": "", "template_id": "t3"},
    ]
    merged = app._merge_nuclei_findings(findings)
    assert merged == 1


def test_merge_nuclei_findings_empty_list():
    app = _make_app()
    assert app._merge_nuclei_findings([]) == 0


def test_estimate_vuln_budget_s_full_mode():
    app = _make_app()
    app.config["scan_mode"] = "completo"
    app.extra_tools = {
        "whatweb": "/bin/whatweb",
        "nikto": "/bin/nikto",
        "testssl.sh": "/bin/testssl",
    }

    host_info = {
        "ports": [
            {"port": 80, "service": "http"},
            {"port": 443, "service": "ssl"},
        ]
    }

    assert app._estimate_vuln_budget_s(host_info) == 490.0
    assert app._estimate_vuln_budget_s({"ports": []}) == 0.0


def test_estimate_vuln_budget_invalid_port():
    app = _make_app()
    app.config["scan_mode"] = "normal"
    app.extra_tools = {}
    host_info = {"ports": [{"port": "bad", "service": "http"}]}
    assert app._estimate_vuln_budget_s(host_info) == 15.0


def test_scan_vulnerabilities_web_basic_https():
    app = _make_app()
    app.config["scan_mode"] = "normal"
    app.extra_tools = {}

    host_info = {
        "ip": "10.0.0.3",
        "ports": [{"port": 443, "service": "https", "is_web_service": True}],
    }

    with patch("redaudit.core.auditor_vuln.http_enrichment", return_value={"http_status": 200}):
        with patch("redaudit.core.auditor_vuln.tls_enrichment", return_value={"tls": "ok"}):
            result = app.scan_vulnerabilities_web(host_info)

    assert result["host"] == "10.0.0.3"
    assert len(result["vulnerabilities"]) == 1
    finding = result["vulnerabilities"][0]
    assert finding["url"] == "https://10.0.0.3:443/"
    assert finding["http_status"] == 200
    assert finding["tls"] == "ok"


def test_scan_vulnerabilities_web_propagates_http_server():
    app = _make_app()
    app.config["scan_mode"] = "normal"
    app.extra_tools = {}

    host_info = {
        "ip": "10.0.0.9",
        "ports": [{"port": 80, "service": "http", "is_web_service": True}],
    }

    headers = "HTTP/1.1 200 OK\nServer: TestSrv\n"
    with patch(
        "redaudit.core.auditor_vuln.http_enrichment",
        return_value={"curl_headers": headers},
    ):
        result = app.scan_vulnerabilities_web(host_info)

    assert result["host"] == "10.0.0.9"
    agentless = host_info.get("agentless_fingerprint") or {}
    assert agentless.get("http_server") == "TestSrv"
    assert agentless.get("http_source") == "enrichment"


def test_scan_vulnerabilities_web_no_web_ports():
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "normal"
    host_info = {"ip": "10.0.0.5", "ports": [{"port": 22, "service": "ssh"}]}
    assert auditor.scan_vulnerabilities_web(host_info) is None


class _DummyLogger:
    def debug(self, *_args, **_kwargs):
        pass

    def info(self, *_args, **_kwargs):
        pass

    def error(self, *_args, **_kwargs):
        pass


class _DummyAuditor(AuditorVuln):
    def __init__(self):
        self.results = {"vulnerabilities": []}
        self.extra_tools = {}
        self.config = {"scan_mode": "completo", "threads": 2, "dry_run": False}
        self.logger = _DummyLogger()
        self.current_phase = ""
        self._ui_detail = ""
        self.interrupted = False
        self.proxy_manager = None
        self.statuses = []
        self.ui = self
        self.colors = {}

    def _set_ui_detail(self, detail):
        self._ui_detail = detail

    def _get_ui_detail(self):
        return self._ui_detail

    def _progress_ui(self):
        return contextlib.nullcontext()

    def _progress_columns(self, **_kwargs):
        return ()

    def _progress_console(self):
        return None

    def get_progress_console(self):
        return None

    def _format_eta(self, _value):
        return "00:00"

    def print_status(self, *args, **kwargs):
        self.statuses.append((args, kwargs))

    def t(self, key, *_args):
        return key


class _DummyResult:
    def __init__(self, stdout="", stderr="", timed_out=False):
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out


class _DummyRunner:
    def __init__(self, **_kwargs):
        pass

    def run(self, cmd, **_kwargs):
        tool = cmd[0]
        if "whatweb" in tool:
            return _DummyResult(stdout="whatweb: nginx 1.18")
        if "nikto" in tool:
            return _DummyResult(stdout="+ Finding 1\n+ Finding 2\n")
        return _DummyResult()


def test_scan_vulnerabilities_web_full_flow(monkeypatch):
    auditor = _DummyAuditor()
    auditor.extra_tools = {
        "whatweb": "/usr/bin/whatweb",
        "nikto": "/usr/bin/nikto",
        "testssl.sh": "/usr/bin/testssl.sh",
    }

    monkeypatch.setattr(auditor_vuln, "http_enrichment", lambda *_args, **_kwargs: {"http": "ok"})
    monkeypatch.setattr(auditor_vuln, "tls_enrichment", lambda *_args, **_kwargs: {"tls": "1.2"})
    monkeypatch.setattr(
        auditor_vuln, "ssl_deep_analysis", lambda *_args, **_kwargs: {"vulnerabilities": ["x"]}
    )
    monkeypatch.setattr(auditor_vuln, "CommandRunner", _DummyRunner)

    def _filter(findings, *_args, **_kwargs):
        return findings[:1]

    monkeypatch.setattr("redaudit.core.verify_vuln.filter_nikto_false_positives", _filter)

    host_info = {
        "ip": "10.0.0.1",
        "ports": [{"port": 443, "service": "https", "is_web_service": True}],
    }

    result = auditor.scan_vulnerabilities_web(host_info)
    assert result is not None
    assert result["host"] == "10.0.0.1"
    assert result["vulnerabilities"]
    finding = result["vulnerabilities"][0]
    assert "whatweb" in finding
    assert "nikto_findings" in finding
    assert finding.get("nikto_filtered_count") == 1
    assert "testssl_analysis" in finding


def test_scan_vulnerabilities_web_whatweb_exception(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "normal"
    auditor.extra_tools = {"whatweb": "/usr/bin/whatweb"}
    auditor.logger = MagicMock()

    class _BoomRunner:
        def __init__(self, **_kwargs):
            raise RuntimeError("boom")

    monkeypatch.setattr(auditor_vuln, "http_enrichment", lambda *_args, **_kwargs: {"http": "ok"})
    monkeypatch.setattr(auditor_vuln, "CommandRunner", _BoomRunner)

    host_info = {
        "ip": "10.0.0.6",
        "ports": [{"port": 80, "service": "http", "is_web_service": True}],
    }
    result = auditor.scan_vulnerabilities_web(host_info)
    assert result["host"] == "10.0.0.6"
    assert auditor.logger.debug.called


def test_scan_vulnerabilities_web_nikto_exception(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "completo"
    auditor.extra_tools = {"nikto": "/usr/bin/nikto"}
    auditor.logger = MagicMock()

    class _BoomRunner:
        def __init__(self, **_kwargs):
            raise RuntimeError("boom")

    monkeypatch.setattr(auditor_vuln, "http_enrichment", lambda *_args, **_kwargs: {"http": "ok"})
    monkeypatch.setattr(auditor_vuln, "CommandRunner", _BoomRunner)

    host_info = {
        "ip": "10.0.0.7",
        "ports": [{"port": 80, "service": "http", "is_web_service": True}],
    }
    result = auditor.scan_vulnerabilities_web(host_info)
    assert result["host"] == "10.0.0.7"
    assert auditor.logger.debug.called


def test_scan_vulnerabilities_concurrent_fallback(monkeypatch):
    auditor = _DummyAuditor()

    def _fake_scan(host, **_kwargs):
        return {"host": host["ip"], "vulnerabilities": [{"name": "x"}]}

    monkeypatch.setattr(auditor, "scan_vulnerabilities_web", _fake_scan)

    real_import = __import__

    def _blocked_import(name, *args, **kwargs):
        if name == "rich.progress":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _blocked_import)

    host_results = [{"ip": "10.0.0.2", "web_ports_count": 1, "ports": [{"port": 80}]}]
    auditor.scan_vulnerabilities_concurrent(host_results)
    assert auditor.results["vulnerabilities"]


def test_scan_vulnerabilities_concurrent_rich_progress(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["threads"] = 1
    auditor.logger = MagicMock()
    details = ["first", "updated"]

    def _next_detail():
        return details.pop(0) if details else "updated"

    auditor._get_ui_detail = _next_detail

    def _scan(host, **_kwargs):
        if host["ip"] == "10.0.0.2":
            raise RuntimeError("boom")
        return {"host": host["ip"], "vulnerabilities": [{"name": "x"}]}

    class _DummyProgress:
        def __init__(self, *args, **kwargs):
            self.updates = []
            self.added = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def add_task(self, *args, **kwargs):
            self.added.append((args, kwargs))
            return "task"

        def update(self, task, **kwargs):
            self.updates.append((task, kwargs))

    monkeypatch.setattr("rich.progress.Progress", _DummyProgress)
    monkeypatch.setattr(auditor, "scan_vulnerabilities_web", _scan)

    host_results = [
        {"ip": "10.0.0.1", "web_ports_count": 1, "ports": [{"port": 80, "service": "http"}]},
        {"ip": "10.0.0.2", "web_ports_count": 1, "ports": [{"port": 80, "service": "http"}]},
    ]
    auditor.scan_vulnerabilities_concurrent(host_results)
    assert auditor.results["vulnerabilities"]
    assert auditor.logger.error.called


def test_scan_vulnerabilities_concurrent_rich_interrupted(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["threads"] = 1
    auditor.interrupted = True

    class _DummyProgress:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def add_task(self, *_args, **_kwargs):
            return "task"

        def update(self, *_args, **_kwargs):
            return None

    monkeypatch.setattr("rich.progress.Progress", _DummyProgress)

    host_results = [{"ip": "10.0.0.3", "web_ports_count": 1, "ports": [{"port": 80}]}]
    auditor.scan_vulnerabilities_concurrent(host_results)


def test_scan_vulnerabilities_concurrent_no_web_hosts():
    auditor = _DummyAuditor()
    auditor.scan_vulnerabilities_concurrent([{"ip": "10.0.0.4", "web_ports_count": 0}])


def test_scan_vulnerabilities_concurrent_skips_upnp_http_only(monkeypatch):
    auditor = _DummyAuditor()
    called = []

    def _fake_scan(host, **_kwargs):
        called.append(host["ip"])
        return {"host": host["ip"], "vulnerabilities": []}

    monkeypatch.setattr(auditor, "scan_vulnerabilities_web", _fake_scan)

    host_results = [
        {
            "ip": "10.0.0.8",
            "web_ports_count": 0,
            "agentless_fingerprint": {"http_title": "UPnP Device", "http_source": "upnp"},
        }
    ]
    auditor.scan_vulnerabilities_concurrent(host_results)
    assert not called


def test_scan_vulnerabilities_concurrent_fallback_interrupt(monkeypatch):
    auditor = _DummyAuditor()
    auditor.interrupted = True

    def _fake_scan(host, **_kwargs):
        return {"host": host["ip"], "vulnerabilities": [{"name": "x"}]}

    monkeypatch.setattr(auditor, "scan_vulnerabilities_web", _fake_scan)

    real_import = __import__

    def _blocked_import(name, *args, **kwargs):
        if name == "rich.progress":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _blocked_import)

    host_results = [{"ip": "10.0.0.5", "web_ports_count": 1, "ports": [{"port": 80}]}]
    auditor.scan_vulnerabilities_concurrent(host_results)


def test_scan_vulnerabilities_concurrent_fallback_worker_error(monkeypatch):
    auditor = _DummyAuditor()
    auditor.logger = MagicMock()

    def _boom(_host, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(auditor, "scan_vulnerabilities_web", _boom)

    real_import = __import__

    def _blocked_import(name, *args, **kwargs):
        if name == "rich.progress":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _blocked_import)

    host_results = [{"ip": "10.0.0.6", "web_ports_count": 1, "ports": [{"port": 80}]}]
    auditor.scan_vulnerabilities_concurrent(host_results)
    assert auditor.statuses
    assert auditor.logger.error.called


# -----------------------------------------------------------------------------
# v4.1 sqlmap integration tests
# -----------------------------------------------------------------------------


def test_scan_vulnerabilities_web_includes_sqlmap_in_parallel(monkeypatch):
    """v4.1: Verify that sqlmap is included in vuln tools parallel execution."""
    auditor = _DummyAuditor()
    auditor.extra_tools = {
        "whatweb": "/usr/bin/whatweb",
        "nikto": "/usr/bin/nikto",
        "sqlmap": "/usr/bin/sqlmap",
    }
    auditor.config["scan_mode"] = "completo"

    # Track which tools were called
    tools_called = []

    class _TrackingRunner:
        def __init__(self, **_kwargs):
            pass

        def run(self, cmd, **_kwargs):
            tool = cmd[0]
            tools_called.append(tool)
            return _DummyResult(stdout="test output")

    monkeypatch.setattr(auditor_vuln, "http_enrichment", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(auditor_vuln, "tls_enrichment", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(auditor_vuln, "CommandRunner", _TrackingRunner)
    monkeypatch.setattr(
        "redaudit.core.verify_vuln.filter_nikto_false_positives", lambda x, *_a, **_k: x
    )

    host_info = {
        "ip": "10.0.0.10",
        "ports": [{"port": 80, "service": "http", "is_web_service": True}],
    }

    auditor.scan_vulnerabilities_web(host_info)

    # sqlmap should have been called
    sqlmap_calls = [t for t in tools_called if "sqlmap" in t]
    assert len(sqlmap_calls) > 0, "sqlmap should be called during vuln scan"


def test_sqlmap_shutil_which_fallback(monkeypatch):
    """v4.1: Verify sqlmap uses shutil.which fallback when not in extra_tools."""
    auditor = _DummyAuditor()
    auditor.extra_tools = {}  # Empty - no sqlmap preregistered
    auditor.config["scan_mode"] = "completo"

    sqlmap_called = []

    class _TrackingRunner:
        def __init__(self, **_kwargs):
            pass

        def run(self, cmd, **_kwargs):
            if "sqlmap" in str(cmd[0]):
                sqlmap_called.append(cmd)
            return _DummyResult(stdout="[12:00:00] [INFO] testing parameters")

    # Mock shutil.which to return sqlmap path
    monkeypatch.setattr(
        "shutil.which", lambda tool: f"/usr/bin/{tool}" if tool == "sqlmap" else None
    )
    monkeypatch.setattr(auditor_vuln, "http_enrichment", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(auditor_vuln, "CommandRunner", _TrackingRunner)
    monkeypatch.setattr(
        "redaudit.core.verify_vuln.filter_nikto_false_positives", lambda x, *_a, **_k: x
    )

    host_info = {
        "ip": "10.0.0.11",
        "ports": [{"port": 80, "service": "http", "is_web_service": True}],
    }

    auditor.scan_vulnerabilities_web(host_info)

    # sqlmap should have been called via shutil.which fallback
    assert len(sqlmap_called) > 0, "sqlmap should be called via shutil.which fallback"


def test_sqlmap_detects_injection_indicators(monkeypatch):
    """v4.1: Verify sqlmap findings are captured when SQLi indicators present."""
    auditor = _DummyAuditor()
    auditor.extra_tools = {"sqlmap": "/usr/bin/sqlmap"}
    auditor.config["scan_mode"] = "completo"

    # Simulate sqlmap finding injection
    sqlmap_output = """
[12:00:00] [INFO] testing parameter 'id'
[12:00:01] [INFO] GET parameter 'id' is vulnerable
[12:00:02] [INFO] Parameter: id (GET)
    Type: boolean-based blind
[12:00:03] [INFO] sql injection detected
"""

    class _SqlmapRunner:
        def __init__(self, **_kwargs):
            pass

        def run(self, cmd, **_kwargs):
            if "sqlmap" in str(cmd[0]):
                return _DummyResult(stdout=sqlmap_output)
            return _DummyResult()

    monkeypatch.setattr(auditor_vuln, "http_enrichment", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(auditor_vuln, "CommandRunner", _SqlmapRunner)
    monkeypatch.setattr(
        "redaudit.core.verify_vuln.filter_nikto_false_positives", lambda x, *_a, **_k: x
    )

    host_info = {
        "ip": "10.0.0.12",
        "ports": [{"port": 80, "service": "http", "is_web_service": True}],
    }

    result = auditor.scan_vulnerabilities_web(host_info)
    assert result is not None
    findings = result["vulnerabilities"][0]
    assert "sqlmap_findings" in findings
    assert len(findings["sqlmap_findings"]) > 0


def test_sqlmap_not_called_when_unavailable(monkeypatch):
    """v4.1: Verify sqlmap is not called when neither in extra_tools nor shutil.which."""
    auditor = _DummyAuditor()
    auditor.extra_tools = {}  # Empty
    auditor.config["scan_mode"] = "completo"

    tools_called = []

    class _TrackingRunner:
        def __init__(self, **_kwargs):
            pass

        def run(self, cmd, **_kwargs):
            tools_called.append(str(cmd[0]))
            return _DummyResult()

    # shutil.which returns None for sqlmap
    monkeypatch.setattr("shutil.which", lambda tool: None)
    monkeypatch.setattr(auditor_vuln, "http_enrichment", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(auditor_vuln, "CommandRunner", _TrackingRunner)
    monkeypatch.setattr(
        "redaudit.core.verify_vuln.filter_nikto_false_positives", lambda x, *_a, **_k: x
    )

    host_info = {
        "ip": "10.0.0.13",
        "ports": [{"port": 80, "service": "http", "is_web_service": True}],
    }

    auditor.scan_vulnerabilities_web(host_info)

    # sqlmap should NOT have been called
    sqlmap_calls = [t for t in tools_called if "sqlmap" in t]
    assert len(sqlmap_calls) == 0, "sqlmap should not be called when unavailable"


def test_run_vuln_tools_parallel_future_exception(monkeypatch):
    """Test exception handling within the parallel execution loop."""
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "completo"
    # Ensure tools are present so futures are submitted
    auditor.extra_tools = {"whatweb": "whatweb", "nikto": "nikto"}
    auditor.logger = MagicMock()

    # We need to mock ThreadPoolExecutor context manager
    mock_executor = MagicMock()

    # We need a future that raises when result() is called
    mock_future = MagicMock()
    mock_future.result.side_effect = RuntimeError("Worker crashed")

    context_manager = MagicMock()
    context_manager.__enter__.return_value = mock_executor
    context_manager.__exit__.return_value = None

    # Mock submit to return our crashing future
    mock_executor.submit.return_value = mock_future

    # Mock as_completed to yield our crashing future
    def fake_as_completed(futures):
        yield mock_future

    monkeypatch.setattr(
        "redaudit.core.auditor_vuln.ThreadPoolExecutor", lambda **k: context_manager
    )
    monkeypatch.setattr("redaudit.core.auditor_vuln.as_completed", fake_as_completed)

    # Bypass helpers
    monkeypatch.setattr(auditor, "_should_run_nikto", lambda *a: (True, ""))

    finding = {}
    auditor._run_vuln_tools_parallel(
        ip="10.0.0.1", port=443, url="https://10.0.0.1", scheme="https", finding=finding
    )

    # Logger should have caught the exception
    assert auditor.logger.debug.called
    found = False
    for call in auditor.logger.debug.call_args_list:
        if "Parallel vuln tool error" in str(call):
            found = True
            break
    assert found, "Expected 'Parallel vuln tool error' not found in logger calls"


def test_run_vuln_tools_parallel_whatweb_timeout(monkeypatch):
    """Test specific timeout handling in whatweb parallel runner."""
    auditor = _DummyAuditor()
    auditor.extra_tools = {"whatweb": "whatweb"}

    # Mock command runner to timeout
    runner_mock = MagicMock()
    result_mock = MagicMock()
    result_mock.timed_out = True
    runner_mock.run.return_value = result_mock

    monkeypatch.setattr("redaudit.core.auditor_vuln.CommandRunner", lambda **k: runner_mock)

    # We need to execute the inner run_whatweb function.
    # Since it's inside _run_vuln_tools_parallel, we run the whole thing.
    # We can use the real ThreadPoolExecutor or mock it to run synchronously for simplicity.
    # Let's use real execution but with single worker or mock.
    # Mocking is safer to avoid creating threads in unit tests if possible,
    # but the previous test mocked everything.
    # Let's trust the logic and just inspect result.

    # Actually, if whatweb times out, it returns {}.
    res = auditor._run_vuln_tools_parallel("10.0.0.1", 443, "https://10.0.0.1", "https", {})
    assert "whatweb" not in res


def test_extract_server_header_and_app_scan_policy(monkeypatch):
    auditor = _DummyAuditor()
    headers = "HTTP/1.1 200 OK\nServer: TestSrv\n"
    assert auditor_vuln.AuditorVuln._extract_server_header(headers) == "TestSrv"

    auditor.config["scan_mode"] = "normal"
    allowed, reason = auditor._should_run_app_scans({}, {})
    assert allowed is False
    assert reason == "mode_not_full"

    auditor.config["scan_mode"] = "completo"
    monkeypatch.setattr(auditor_vuln, "is_infra_identity", lambda **_k: (True, "infra"))
    allowed, reason = auditor._should_run_app_scans({}, {})
    assert allowed is False
    assert reason == "infra"

    monkeypatch.setattr(auditor_vuln, "is_infra_identity", lambda **_k: (False, ""))
    allowed, reason = auditor._should_run_app_scans({}, {})
    assert allowed is True
    assert reason == ""


def test_should_run_nikto_profiles(monkeypatch):
    auditor = _DummyAuditor()
    host_info = {"agentless_fingerprint": {}, "device_type_hints": []}

    auditor.config["nuclei_profile"] = "fast"
    allowed, reason = auditor._should_run_nikto(host_info, {})
    assert allowed is False
    assert reason == "profile_fast"

    auditor.config["nuclei_profile"] = "balanced"
    monkeypatch.setattr(auditor_vuln, "is_infra_identity", lambda **_k: (True, "router"))
    allowed, reason = auditor._should_run_nikto(host_info, {})
    assert allowed is False
    assert reason == "infra_router"

    auditor.config["nuclei_profile"] = "full"
    monkeypatch.setattr(auditor_vuln, "is_infra_identity", lambda **_k: (False, ""))
    allowed, reason = auditor._should_run_nikto(host_info, {})
    assert allowed is True


def test_scan_vulnerabilities_web_status_callback_and_agentless(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "normal"
    auditor._run_vuln_tools_sequential = MagicMock()

    host_info = {
        "ip": "10.0.0.20",
        "ports": [{"port": 80, "service": "http", "is_web_service": True}],
        "agentless_fingerprint": {"http_source": "upnp", "http_title": "UPNP Device"},
    }
    host_obj = Host(ip="10.0.0.20")

    statuses = []

    def _status(msg):
        statuses.append(msg)

    monkeypatch.setattr(
        auditor_vuln,
        "http_enrichment",
        lambda *_a, **_k: {"curl_headers": "Server: TestSrv"},
    )
    monkeypatch.setattr(auditor_vuln, "tls_enrichment", lambda *_a, **_k: {})

    result = auditor.scan_vulnerabilities_web(host_info, status_callback=_status, host_obj=host_obj)
    assert result is not None
    assert statuses
    assert host_info["agentless_fingerprint"]["http_server"] == "TestSrv"
    assert host_info["agentless_fingerprint"]["http_source"] == "enrichment"
    assert host_info["agentless_fingerprint"]["upnp_device_name"] == "UPNP Device"
    assert host_obj.agentless_fingerprint["http_server"] == "TestSrv"


def test_run_vuln_tools_parallel_collects_results(monkeypatch, tmp_path):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "completo"
    auditor.config["zap_enabled"] = True
    auditor.extra_tools = {
        "testssl.sh": "testssl",
        "whatweb": "whatweb",
        "nikto": "nikto",
        "sqlmap": "sqlmap",
        "zap.sh": "zap.sh",
    }
    auditor.logger = MagicMock()

    def _runner_factory(**_kwargs):
        class _Runner:
            def run(self, cmd, **_kw):
                tool = cmd[0]
                if "whatweb" in tool:
                    return _DummyResult(stdout="whatweb output")
                if "nikto" in tool:
                    return _DummyResult(stdout="+ finding 1\n+ finding 2")
                if "sqlmap" in tool:
                    return _DummyResult(stdout="is vulnerable")
                if "zap.sh" in tool:
                    return _DummyResult(stdout="ok")
                return _DummyResult()

        return _Runner()

    monkeypatch.setattr(auditor_vuln, "CommandRunner", _runner_factory)
    monkeypatch.setattr(
        auditor_vuln, "ssl_deep_analysis", lambda *_a, **_k: {"vulnerabilities": [1]}
    )
    monkeypatch.setattr(
        "redaudit.core.verify_vuln.filter_nikto_false_positives",
        lambda findings, *_a, **_k: findings[:1],
    )
    monkeypatch.setattr("os.path.exists", lambda _p: True)
    monkeypatch.setattr(
        "tempfile.gettempdir",
        lambda: str(tmp_path),
    )

    finding = {"headers": "", "server": "apache"}
    res = auditor._run_vuln_tools_parallel(
        "10.0.0.1",
        443,
        "https://10.0.0.1",
        "https",
        finding,
        host_info={"device_type_hints": []},
    )
    assert "testssl_analysis" in res
    assert "whatweb" in res
    assert "nikto_findings" in res
    assert "nikto_filtered_count" in res
    assert "sqlmap_findings" in res
    assert "zap_report" in res


def test_run_vuln_tools_parallel_skips_nikto(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "completo"
    auditor.extra_tools = {"nikto": "nikto"}
    auditor.logger = MagicMock()

    monkeypatch.setattr(auditor, "_should_run_nikto", lambda *_a, **_k: (False, "infra"))
    res = auditor._run_vuln_tools_parallel(
        "10.0.0.1",
        80,
        "http://10.0.0.1",
        "http",
        {"headers": "", "server": "apache"},
        host_info={"device_type_hints": []},
    )
    assert res["nikto_skipped"] == "infra"


def test_run_vuln_tools_parallel_cdn_skip(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "completo"
    auditor.extra_tools = {"nikto": "nikto"}
    auditor.logger = MagicMock()

    res = auditor._run_vuln_tools_parallel(
        "10.0.0.1",
        80,
        "http://10.0.0.1",
        "http",
        {"headers": "cf-ray: x", "server": "cloudflare"},
        host_info={},
    )
    assert res["nikto_skipped"] == "cdn_proxy_detected"
    assert "nikto_server" in res


def test_run_vuln_tools_parallel_app_scan_policy(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "completo"
    auditor.config["zap_enabled"] = True
    auditor.extra_tools = {"sqlmap": "sqlmap"}
    monkeypatch.setattr(
        "shutil.which",
        lambda tool: "/usr/bin/zap.sh" if tool == "zap.sh" else None,
    )

    res = auditor._run_vuln_tools_parallel(
        "10.0.0.1",
        80,
        "http://10.0.0.1",
        "http",
        {},
        app_scan_allowed=False,
        app_scan_reason="policy",
    )
    assert res["sqlmap_skipped"] == "policy"
    assert res["zap_skipped"] == "policy"


def test_run_vuln_tools_parallel_zap_missing(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "completo"
    auditor.config["zap_enabled"] = True
    monkeypatch.setattr("shutil.which", lambda tool: None)
    res = auditor._run_vuln_tools_parallel("10.0.0.1", 80, "http://10.0.0.1", "http", {})
    assert "zap_report" not in res


def test_run_vuln_tools_parallel_testssl_empty(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "completo"
    auditor.extra_tools = {"testssl.sh": "testssl"}
    monkeypatch.setattr(auditor_vuln, "ssl_deep_analysis", lambda *_a, **_k: {})
    res = auditor._run_vuln_tools_parallel("10.0.0.1", 443, "https://10.0.0.1", "https", {})
    assert "testssl_analysis" not in res


def test_run_vuln_tools_parallel_whatweb_exception(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "completo"
    auditor.extra_tools = {"whatweb": "whatweb"}
    auditor.logger = MagicMock()

    class _Runner:
        def __init__(self, **_k):
            raise RuntimeError("boom")

    monkeypatch.setattr(auditor_vuln, "CommandRunner", _Runner)
    res = auditor._run_vuln_tools_parallel("10.0.0.1", 80, "http://10.0.0.1", "http", {})
    assert res == {}
    assert auditor.logger.debug.called


def test_run_vuln_tools_parallel_nikto_timeout(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "completo"
    auditor.extra_tools = {"nikto": "nikto"}

    class _Runner:
        def __init__(self, **_k):
            pass

        def run(self, *_a, **_k):
            return _DummyResult(stdout="", stderr="", timed_out=True)

    monkeypatch.setattr(auditor_vuln, "CommandRunner", _Runner)
    res = auditor._run_vuln_tools_parallel(
        "10.0.0.1",
        80,
        "http://10.0.0.1",
        "http",
        {"headers": "", "server": "apache"},
    )
    assert res["nikto_timeout"] is True


def test_run_vuln_tools_parallel_sqlmap_exception(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "completo"
    auditor.extra_tools = {"sqlmap": "sqlmap"}
    auditor.logger = MagicMock()

    class _Runner:
        def __init__(self, **_k):
            pass

        def run(self, *_a, **_k):
            raise RuntimeError("boom")

    monkeypatch.setattr(auditor_vuln, "CommandRunner", _Runner)
    res = auditor._run_vuln_tools_parallel("10.0.0.1", 80, "http://10.0.0.1", "http", {})
    assert res == {}
    assert auditor.logger.debug.called


def test_run_vuln_tools_parallel_zap_exception(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "completo"
    auditor.config["zap_enabled"] = True
    auditor.logger = MagicMock()
    monkeypatch.setattr(
        "shutil.which", lambda tool: "/usr/bin/zap.sh" if tool == "zap.sh" else None
    )

    class _Runner:
        def __init__(self, **_k):
            pass

        def run(self, *_a, **_k):
            raise RuntimeError("boom")

    monkeypatch.setattr(auditor_vuln, "CommandRunner", _Runner)
    res = auditor._run_vuln_tools_parallel("10.0.0.1", 80, "http://10.0.0.1", "http", {})
    assert res == {}
    assert auditor.logger.debug.called


def test_run_vuln_tools_sequential_nikto_timeout(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "completo"
    auditor.extra_tools = {"nikto": "nikto"}

    class _Runner:
        def __init__(self, **_k):
            pass

        def run(self, *_a, **_k):
            return _DummyResult(stdout="", stderr="", timed_out=True)

    monkeypatch.setattr(auditor_vuln, "CommandRunner", _Runner)
    finding = {}
    auditor._run_vuln_tools_sequential(
        ip="10.0.0.1",
        port=80,
        url="http://10.0.0.1",
        scheme="http",
        finding=finding,
    )
    assert finding["nikto_timeout"] is True


def test_run_vuln_tools_sequential_nikto_exception(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "completo"
    auditor.extra_tools = {"nikto": "nikto"}
    auditor.logger = MagicMock()

    class _Runner:
        def __init__(self, **_k):
            pass

        def run(self, *_a, **_k):
            raise RuntimeError("boom")

    monkeypatch.setattr(auditor_vuln, "CommandRunner", _Runner)
    finding = {}
    auditor._run_vuln_tools_sequential(
        ip="10.0.0.1",
        port=80,
        url="http://10.0.0.1",
        scheme="http",
        finding=finding,
    )
    assert auditor.logger.debug.called


def test_run_vuln_tools_sequential_full(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["scan_mode"] = "completo"
    auditor.extra_tools = {"testssl.sh": "testssl", "whatweb": "whatweb", "nikto": "nikto"}

    def _runner_factory(**_kwargs):
        class _Runner:
            def run(self, cmd, **_kw):
                tool = cmd[0]
                if "whatweb" in tool:
                    return _DummyResult(stdout="whatweb output")
                if "nikto" in tool:
                    return _DummyResult(stdout="+ finding 1\n+ finding 2")
                return _DummyResult()

        return _Runner()

    monkeypatch.setattr(auditor_vuln, "CommandRunner", _runner_factory)
    monkeypatch.setattr(
        auditor_vuln, "ssl_deep_analysis", lambda *_a, **_k: {"vulnerabilities": [1]}
    )
    monkeypatch.setattr(
        "redaudit.core.verify_vuln.filter_nikto_false_positives",
        lambda findings, *_a, **_k: findings[:1],
    )

    finding = {}
    auditor._run_vuln_tools_sequential(
        ip="10.0.0.1",
        port=443,
        url="https://10.0.0.1",
        scheme="https",
        finding=finding,
    )
    assert "testssl_analysis" in finding
    assert "whatweb" in finding
    assert "nikto_findings" in finding
    assert "nikto_filtered_count" in finding


def test_scan_vulnerabilities_concurrent_rich_progress(monkeypatch):
    auditor = _DummyAuditor()
    auditor.config["threads"] = 2
    auditor.results["vulnerabilities"] = []

    host = Host(ip="10.0.0.50", web_ports_count=1)
    host_dict = {"ip": "10.0.0.51", "web_ports_count": 1}

    class _Progress:
        def __init__(self):
            self.console = MagicMock()
            self.tasks = {}

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def add_task(self, *_a, **_k):
            task_id = len(self.tasks) + 1
            self.tasks[task_id] = {}
            return task_id

        def update(self, *_a, **_k):
            return None

    progress = _Progress()

    def _scan(host_info, status_callback=None, host_obj=None):
        if status_callback:
            status_callback("running")
        return {"host": host_info["ip"], "vulnerabilities": [{"name": "test"}]}

    auditor.get_progress_console = MagicMock(return_value=object())
    auditor.get_standard_progress = MagicMock(return_value=progress)
    auditor.scan_vulnerabilities_web = _scan

    auditor.scan_vulnerabilities_concurrent([host, host_dict])
    assert auditor.results["vulnerabilities"]
