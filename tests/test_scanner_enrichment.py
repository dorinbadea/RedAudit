#!/usr/bin/env python3
"""
RedAudit - Tests for scanner enrichment and capture helpers.
"""

from types import SimpleNamespace

import subprocess

from redaudit.core import scanner


def _result(stdout="", stderr="", returncode=0, timed_out=False):
    return SimpleNamespace(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        timed_out=timed_out,
    )


class _DummyProc:
    def __init__(self, *, timeout=False):
        self.terminated = False
        self.killed = False
        self.timeout = timeout

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        if self.timeout:
            raise subprocess.TimeoutExpired(cmd="tcpdump", timeout=timeout)
        return None

    def kill(self):
        self.killed = True


def test_enrich_host_with_dns_and_whois(monkeypatch):
    def _fake_make_runner(**_kwargs):
        def _run(args, **_run_kwargs):
            if "dig" in args[0]:
                return _result(stdout="example.com.\n")
            return _result(stdout="OrgName: Example Org\nAddress: 1 Main St\n")

        return SimpleNamespace(run=_run)

    monkeypatch.setattr(scanner, "_make_runner", _fake_make_runner)

    host_record = {"ip": "8.8.8.8"}
    tools = {"dig": "dig", "whois": "whois"}

    scanner.enrich_host_with_dns(host_record, tools)
    scanner.enrich_host_with_whois(host_record, tools)

    assert host_record["dns"]["reverse"] == ["example.com."]
    assert "OrgName" in host_record["dns"]["whois_summary"]


def test_http_tls_and_exploit_enrichment(monkeypatch):
    def _fake_make_runner(**_kwargs):
        def _run(args, **_run_kwargs):
            if "curl" in args[0]:
                return _result(stdout="HTTP/1.1 200 OK\nServer: Test\n")
            if "wget" in args[0]:
                return _result(stderr="HTTP/1.1 200 OK\nServer: Test\n")
            if "openssl" in args[0]:
                return _result(stdout="Protocol  : TLSv1.2\n")
            if "searchsploit" in args[0]:
                output = "OpenSSH 7.9 - Sample Exploit | path\n"
                return _result(stdout=output, returncode=0)
            return _result()

        return SimpleNamespace(run=_run)

    monkeypatch.setattr(scanner, "_make_runner", _fake_make_runner)

    http_data = scanner.http_enrichment("http://example.com", {"curl": "curl", "wget": "wget"})
    assert "curl_headers" in http_data
    assert "wget_headers" in http_data

    tls_data = scanner.tls_enrichment("1.2.3.4", 443, {"openssl": "openssl"})
    assert "tls_info" in tls_data

    exploits = scanner.exploit_lookup("OpenSSH", "7.9", {"searchsploit": "searchsploit"})
    assert exploits == ["OpenSSH 7.9 - Sample Exploit"]


def test_http_identity_probe_extracts_title_and_server(monkeypatch):
    def _fake_make_runner(**_kwargs):
        def _run(args, **_run_kwargs):
            if "-I" in args:
                return _result(stdout="HTTP/1.1 200 OK\nServer: ZyxelHTTP\n")
            return _result(stdout="<html><title>Zyxel GS1200-5</title></html>")

        return SimpleNamespace(run=_run)

    monkeypatch.setattr(scanner, "_make_runner", _fake_make_runner)

    result = scanner.http_identity_probe("10.0.0.1", {"curl": "curl"}, ports=[80])
    assert result["http_title"] == "Zyxel GS1200-5"
    assert result["http_server"] == "ZyxelHTTP"


def test_ssl_deep_analysis_parses_findings(monkeypatch):
    output = """
TLS 1.0 offered
VULNERABLE: Heartbleed
weak cipher suites detected
"""

    def _fake_make_runner(**_kwargs):
        return SimpleNamespace(run=lambda *_args, **_kw: _result(stdout=output))

    monkeypatch.setattr(scanner, "_make_runner", _fake_make_runner)

    findings = scanner.ssl_deep_analysis("1.2.3.4", 443, {"testssl.sh": "testssl.sh"})
    assert findings
    assert findings["summary"].startswith("CRITICAL")
    assert findings["vulnerabilities"]
    assert findings["weak_ciphers"]
    assert findings["protocols"]


def test_ssl_deep_analysis_timeout(monkeypatch):
    def _fake_make_runner(**_kwargs):
        return SimpleNamespace(run=lambda *_args, **_kw: _result(timed_out=True))

    monkeypatch.setattr(scanner, "_make_runner", _fake_make_runner)

    findings = scanner.ssl_deep_analysis("1.2.3.4", 443, {"testssl.sh": "testssl.sh"})
    assert findings["error"].startswith("Analysis timeout")


def test_start_and_stop_background_capture(tmp_path, monkeypatch):
    dummy_proc = _DummyProc()

    def _fake_popen(*_args, **_kwargs):
        return dummy_proc

    def _fake_make_runner(**_kwargs):
        return SimpleNamespace(run=lambda *_args, **_kw: _result(stdout="Summary"))

    monkeypatch.setattr(scanner.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(scanner, "_make_runner", _fake_make_runner)

    capture = scanner.start_background_capture(
        "10.0.0.1",
        str(tmp_path),
        networks=[{"network": "10.0.0.0/24", "interface": "eth0"}],
        extra_tools={"tcpdump": "tcpdump"},
    )
    assert capture

    pcap_path = capture["pcap_file_abs"]
    with open(pcap_path, "wb") as handle:
        handle.write(b"")

    result = scanner.stop_background_capture(capture, {"tshark": "tshark"})
    assert result["pcap_file"] == capture["pcap_file"]
    assert result["tshark_summary"] == "Summary"
    assert dummy_proc.terminated is True


def test_stop_background_capture_timeout(monkeypatch):
    proc = _DummyProc(timeout=True)
    capture_info = {"process": proc, "pcap_file": "capture.pcap", "pcap_file_abs": ""}

    result = scanner.stop_background_capture(capture_info, {})
    assert result["tcpdump_error"] == "Process killed after timeout"
    assert proc.killed is True


def test_banner_grab_and_finalize_status(monkeypatch):
    output = """
80/tcp open http
|_banner: Apache Test
| ssl-cert: Subject: CN=example
"""

    def _fake_make_runner(**_kwargs):
        return SimpleNamespace(run=lambda *_args, **_kw: _result(stdout=output))

    monkeypatch.setattr(scanner, "_make_runner", _fake_make_runner)

    results = scanner.banner_grab_fallback("10.0.0.1", [80, 65536])
    assert results[80]["service"] == "http"
    assert results[80]["banner"] == "Apache Test"
    assert "ssl_cert" in results[80]

    status = scanner.finalize_host_status(
        {
            "status": scanner.STATUS_DOWN,
            "deep_scan": {"commands": [{"stdout": "Host is up"}]},
        }
    )
    assert status == scanner.STATUS_FILTERED

    status = scanner.finalize_host_status(
        {
            "status": scanner.STATUS_DOWN,
            "deep_scan": {"commands": [{"stdout": "22/tcp open"}]},
        }
    )
    assert status == scanner.STATUS_UP

    status = scanner.finalize_host_status({"status": scanner.STATUS_UP})
    assert status == scanner.STATUS_UP
