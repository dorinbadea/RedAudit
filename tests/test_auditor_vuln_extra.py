#!/usr/bin/env python3
"""
Extra coverage for AuditorVuln paths.
"""

import contextlib

from redaudit.core import auditor_vuln
from redaudit.core.auditor_vuln import AuditorVuln


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
        self.interrupted = False
        self.statuses = []
        # v4.0 Shim
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
