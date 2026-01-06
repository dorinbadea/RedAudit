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

    def _fake_scan(host):
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

    def _scan(host):
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
    assert auditor.logger.info.called
    assert auditor.logger.error.called
    assert auditor.logger.debug.called


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


def test_scan_vulnerabilities_concurrent_fallback_interrupt(monkeypatch):
    auditor = _DummyAuditor()
    auditor.interrupted = True

    def _fake_scan(host):
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

    def _boom(_host):
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
    assert auditor.logger.debug.called


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
