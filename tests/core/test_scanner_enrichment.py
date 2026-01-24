#!/usr/bin/env python3
"""
RedAudit - Tests for scanner enrichment and capture helpers.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import subprocess
import tempfile

from redaudit.core import scanner
from redaudit.core.scanner import traffic as scanner_traffic
from redaudit.core.scanner import enrichment as scanner_enrichment
from redaudit.core.scanner.traffic import (
    capture_traffic_snippet,
    start_background_capture,
    stop_background_capture,
)
from redaudit.core.scanner.enrichment import (
    _fetch_http_body,
    _fetch_http_headers,
    banner_grab_fallback,
    enrich_host_with_dns,
    enrich_host_with_whois,
    exploit_lookup,
    http_enrichment,
    http_identity_probe,
    ssl_deep_analysis,
    tls_enrichment,
)
from redaudit.utils.constants import STATUS_UP, STATUS_DOWN, STATUS_FILTERED


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

    monkeypatch.setattr(scanner_enrichment, "_make_runner", _fake_make_runner)

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

    monkeypatch.setattr(scanner_enrichment, "_make_runner", _fake_make_runner)

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

    monkeypatch.setattr(scanner_enrichment, "_make_runner", _fake_make_runner)

    result = scanner.http_identity_probe("10.0.0.1", {"curl": "curl"}, ports=[80])
    assert result.get("http_title") == "Zyxel GS1200-5"
    assert result.get("http_server") == "ZyxelHTTP"


def test_http_identity_probe_falls_back_to_heading(monkeypatch):
    def _fake_make_runner(**_kwargs):
        def _run(args, **_run_kwargs):
            if "-I" in args:
                return _result(stdout="HTTP/1.1 200 OK\n")
            return _result(stdout="<html><h1>ZYXEL GS1200-5</h1></html>")

        return SimpleNamespace(run=_run)

    monkeypatch.setattr(scanner_enrichment, "_make_runner", _fake_make_runner)

    result = scanner.http_identity_probe("10.0.0.1", {"curl": "curl"}, ports=[80])
    assert result.get("http_title") == "ZYXEL GS1200-5"


def test_http_identity_probe_falls_back_to_meta(monkeypatch):
    def _fake_make_runner(**_kwargs):
        def _run(args, **_run_kwargs):
            if "-I" in args:
                return _result(stdout="HTTP/1.1 200 OK\n")
            return _result(
                stdout=('<html><meta property="og:title" content="Gateway Model X"></html>')
            )

        return SimpleNamespace(run=_run)

    monkeypatch.setattr(scanner_enrichment, "_make_runner", _fake_make_runner)

    result = scanner.http_identity_probe("10.0.0.1", {"curl": "curl"}, ports=[80])
    assert result.get("http_title") == "Gateway Model X"


def test_http_identity_probe_tries_login_paths(monkeypatch):
    seen = []

    def _fake_fetch_headers(url, *_args, **_kwargs):
        seen.append(("head", url))
        return ""

    def _fake_fetch_body(url, *_args, **_kwargs):
        seen.append(("body", url))
        if url.endswith("/login.html"):
            return "<h1>Vodafone</h1>"
        return ""

    monkeypatch.setattr(scanner_enrichment, "_fetch_http_headers", _fake_fetch_headers)
    monkeypatch.setattr(scanner_enrichment, "_fetch_http_body", _fake_fetch_body)

    result = scanner.http_identity_probe("10.0.0.2", {"curl": "curl"}, ports=[80])
    assert result.get("http_title") == "Vodafone"
    assert any(url.endswith("/login.html") for _, url in seen)


def test_ssl_deep_analysis_parses_findings(monkeypatch):
    output = """
TLS 1.0 offered
VULNERABLE: Heartbleed
weak cipher suites detected
"""

    def _fake_make_runner(**_kwargs):
        return SimpleNamespace(run=lambda *_args, **_kw: _result(stdout=output))

    monkeypatch.setattr(scanner_enrichment, "_make_runner", _fake_make_runner)

    findings = scanner.ssl_deep_analysis("1.2.3.4", 443, {"testssl.sh": "testssl.sh"})
    assert findings
    assert findings["summary"].startswith("CRITICAL")
    assert findings["vulnerabilities"]
    assert findings["weak_ciphers"]
    assert findings["protocols"]


def test_ssl_deep_analysis_ignores_not_tested_vulns(monkeypatch):
    output = """
BREACH (CVE-2013-3587) not having provided client certificate and private key file, the client x509-based authentication prevents this from being tested
TLS 1.2 offered
"""

    def _fake_make_runner(**_kwargs):
        return SimpleNamespace(run=lambda *_args, **_kw: _result(stdout=output))

    monkeypatch.setattr(scanner_enrichment, "_make_runner", _fake_make_runner)

    findings = scanner.ssl_deep_analysis("1.2.3.4", 443, {"testssl.sh": "testssl.sh"})
    assert findings
    assert findings["vulnerabilities"] == []
    assert findings["protocols"]
    assert findings["summary"] == "No major issues detected"


def test_ssl_deep_analysis_timeout(monkeypatch):
    def _fake_make_runner(**_kwargs):
        return SimpleNamespace(run=lambda *_args, **_kw: _result(timed_out=True))

    monkeypatch.setattr(scanner_enrichment, "_make_runner", _fake_make_runner)

    findings = scanner.ssl_deep_analysis("1.2.3.4", 443, {"testssl.sh": "testssl.sh"})
    assert findings["error"].startswith("Analysis timeout")


def test_start_and_stop_background_capture(tmp_path, monkeypatch):
    dummy_proc = _DummyProc()

    def _fake_popen(*_args, **_kwargs):
        return dummy_proc

    def _fake_make_runner(**_kwargs):
        return SimpleNamespace(run=lambda *_args, **_kw: _result(stdout="Summary"))

    monkeypatch.setattr(
        scanner_traffic,
        "subprocess",
        SimpleNamespace(
            Popen=_fake_popen,
            DEVNULL=subprocess.DEVNULL,
        ),
    )
    monkeypatch.setattr(scanner_traffic, "_make_runner", _fake_make_runner)

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
    assert result.get("tshark_summary") == "Summary"
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

    monkeypatch.setattr(scanner_enrichment, "_make_runner", _fake_make_runner)

    results = scanner.banner_grab_fallback("10.0.0.1", [80, 65536])
    assert results[80]["service"] == "http"
    assert results[80].get("banner") == "Apache Test"
    assert "ssl_cert" in results[80]

    status = scanner.finalize_host_status(
        {
            "status": STATUS_DOWN,
            "deep_scan": {"commands": [{"stdout": "Host is up"}]},
        }
    )
    assert status == STATUS_FILTERED

    # Simple case: already UP stays UP
    status = scanner.finalize_host_status({"status": STATUS_UP})
    assert status == STATUS_UP


def test_enrich_host_with_dns_exception():
    """Test enrich_host_with_dns with exception (lines 42-43)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("dig failed")
    ):
        host = {"ip": "8.8.8.8"}
        enrich_host_with_dns(host, {"dig": "dig"})
        assert "reverse" not in host["dns"]


def test_enrich_host_with_whois_exception():
    """Test enrich_host_with_whois with exception (lines 68-69)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("whois failed")
    ):
        host = {"ip": "8.8.8.8"}
        enrich_host_with_whois(host, {"whois": "whois"})
        assert "whois_summary" not in host["dns"]


def test_fetch_http_headers_https_k():
    """Test _fetch_http_headers with https -k (line 87)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner_cls:
        _fetch_http_headers("https://target", {"curl": "curl"})
        args = mock_runner_cls.return_value.run.call_args[0][0]
        assert "-k" in args


def test_fetch_http_headers_curl_exception():
    """Test _fetch_http_headers curl exception (lines 99-100)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("curl error")
    ):
        assert _fetch_http_headers("http://t", {"curl": "curl"}) == ""


def test_fetch_http_headers_wget_https():
    """Test _fetch_http_headers wget https (line 110)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner_cls:
        _fetch_http_headers("https://target", {"wget": "wget"})
        args = mock_runner_cls.return_value.run.call_args[0][0]
        assert "--no-check-certificate" in args


def test_fetch_http_headers_wget_exception():
    """Test _fetch_http_headers wget exception (lines 122-124)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("wget error")
    ):
        assert _fetch_http_headers("http://t", {"wget": "wget"}) == ""


def test_fetch_http_body_https_k():
    """Test _fetch_http_body with https -k (line 143)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner_cls:
        _fetch_http_body("https://target", {"curl": "curl"})
        args = mock_runner_cls.return_value.run.call_args[0][0]
        assert "-k" in args


def test_fetch_http_body_curl_exception():
    """Test _fetch_http_body curl exception (lines 155-156)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("curl error")
    ):
        assert _fetch_http_body("http://t", {"curl": "curl"}) == ""


def test_fetch_http_body_wget_https():
    """Test _fetch_http_body wget https (line 166)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner_cls:
        _fetch_http_body("https://target", {"wget": "wget"})
        args = mock_runner_cls.return_value.run.call_args[0][0]
        assert "--no-check-certificate" in args


def test_fetch_http_body_wget_exception():
    """Test _fetch_http_body wget exception (lines 178-180)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("wget error")
    ):
        assert _fetch_http_body("http://t", {"wget": "wget"}) == ""


def test_http_enrichment_exceptions():
    """Test http_enrichment curl/wget exceptions (lines 204-205, 220-221)."""
    with patch("redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("error")):
        res = http_enrichment("http://t", {"curl": "curl", "wget": "wget"})
        assert res == {}


def test_http_identity_probe_invalid_ip():
    """Test http_identity_probe with invalid IP (line 301)."""
    assert http_identity_probe("invalid", {"curl": "curl"}) == {}


def test_http_identity_probe_fallback():
    """Test http_identity_probe fallback return (line 330)."""
    with patch("redaudit.core.scanner.enrichment._fetch_http_headers", return_value=""):
        with patch("redaudit.core.scanner.enrichment._fetch_http_body", return_value=""):
            assert http_identity_probe("1.2.3.4", {"curl": "curl"}) == {}


def test_tls_enrichment_exception():
    """Test tls_enrichment exception (lines 368-369)."""
    with patch("redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("ssl error")):
        assert tls_enrichment("1.2.3.4", 443, {"openssl": "openssl"}) == {}


def test_exploit_lookup_empty_params():
    """Test exploit_lookup with empty params (line 392)."""
    assert exploit_lookup(" ", " ", {"searchsploit": "s"}) == []


def test_exploit_lookup_empty_output():
    """Test exploit_lookup with empty output (line 412)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner:
        mock_runner.return_value.run.return_value = MagicMock(stdout="", returncode=0)
        assert exploit_lookup("ssh", "2.0", {"searchsploit": "s"}) == []


def test_exploit_lookup_timeout():
    """Test exploit_lookup timeout (lines 431-433)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner:
        mock_runner.return_value.run.side_effect = subprocess.TimeoutExpired(["s"], 10)
        assert exploit_lookup("ssh", "2.0", {"searchsploit": "s"}, logger=MagicMock()) == []


def test_exploit_lookup_exception():
    """Test exploit_lookup general exception (line 436)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("fatal error")
    ):
        assert exploit_lookup("ssh", "2.0", {"searchsploit": "s"}, logger=MagicMock()) == []


def test_ssl_deep_analysis_invalid_target():
    """Test ssl_deep_analysis invalid target/port (lines 451, 454)."""
    assert ssl_deep_analysis("invalid", 443, {"testssl.sh": "t"}) is None
    assert ssl_deep_analysis("1.2.3.4", -1, {"testssl.sh": "t"}) is None


def test_ssl_deep_analysis_timeout():
    """Test ssl_deep_analysis timeout (line 472)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner:
        mock_res = MagicMock()
        mock_res.timed_out = True
        mock_runner.return_value.run.return_value = mock_res
        assert (
            ssl_deep_analysis("1.2.3.4", 443, {"testssl.sh": "t"}, logger=MagicMock()) is not None
        )


def test_ssl_deep_analysis_empty_output():
    """Test ssl_deep_analysis empty output (line 477)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner:
        mock_runner.return_value.run.return_value = MagicMock(stdout="", stderr="", timed_out=False)
        assert ssl_deep_analysis("1.2.3.4", 443, {"testssl.sh": "t"}) is None


def test_ssl_deep_analysis_weak_ciphers_summary():
    """Test ssl_deep_analysis weak ciphers summary (line 519)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner:
        mock_runner.return_value.run.return_value = MagicMock(
            stdout="Weak cipher detected", timed_out=False
        )
        res = ssl_deep_analysis("1.2.3.4", 443, {"testssl.sh": "t"})
        assert "WARNING: 1 weak" in res["summary"]


def test_ssl_deep_analysis_fail_and_exception():
    """Test ssl_deep_analysis fail scenarios (lines 531-536)."""
    # Fail to find anything useful
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner:
        mock_runner.return_value.run.return_value = MagicMock(stdout="All OK", timed_out=False)
        assert ssl_deep_analysis("1.2.3.4", 443, {"testssl.sh": "t"}) is None
    # Exception
    with patch("redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("fail")):
        assert ssl_deep_analysis("1.2.3.4", 443, {"testssl.sh": "t"}, logger=MagicMock()) is None


def test_banner_grab_no_ports():
    """Test banner_grab_fallback no ports (line 555)."""
    assert banner_grab_fallback("1.2.3.4", []) == {}


def test_banner_grab_timeout():
    """Test banner_grab_fallback timeout (line 579)."""
    with patch("redaudit.core.scanner.enrichment._make_runner") as mock_runner:
        mock_res = MagicMock()
        mock_res.timed_out = True
        mock_runner.return_value.run.return_value = mock_res
        assert banner_grab_fallback("1.2.3.4", [80], logger=MagicMock()) == {}


def test_banner_grab_exception():
    """Test banner_grab_fallback exception (line 604)."""
    with patch(
        "redaudit.core.scanner.enrichment._make_runner", side_effect=Exception("nmap error")
    ):
        assert banner_grab_fallback("1.2.3.4", [80], logger=MagicMock()) == {}


def test_capture_traffic_snippet_dry_run():
    """Test capture_traffic_snippet in dry run mode (line 40)."""
    logger = MagicMock()
    result = capture_traffic_snippet(
        "192.168.1.1", "/tmp", [], {"tcpdump": "/usr/bin/tcpdump"}, logger=logger, dry_run=True
    )
    assert result is None
    assert logger.info.called


def test_capture_traffic_snippet_invalid_ip():
    """Test capture_traffic_snippet with invalid IP (line 45)."""
    result = capture_traffic_snippet("invalid-ip", "/tmp", [], {"tcpdump": "/usr/bin/tcpdump"})
    assert result is None


def test_capture_traffic_snippet_invalid_duration():
    """Test capture_traffic_snippet with invalid duration (lines 52-54)."""
    logger = MagicMock()
    with tempfile.TemporaryDirectory() as tmpdir:
        result = capture_traffic_snippet(
            "192.168.1.1",
            tmpdir,
            [{"network": "192.168.1.0/24", "interface": "eth0"}],
            {"tcpdump": "/usr/bin/tcpdump"},
            duration=-5,  # Invalid
            logger=logger,
        )
        assert logger.warning.called


def test_capture_traffic_snippet_network_exception():
    """Test capture_traffic_snippet with network exception (lines 68-69)."""
    networks = [{"network": "invalid", "interface": "eth0"}]
    result = capture_traffic_snippet(
        "192.168.1.1", "/tmp", networks, {"tcpdump": "/usr/bin/tcpdump"}
    )
    # Should handle exception gracefully


def test_capture_traffic_snippet_no_interface():
    """Test capture_traffic_snippet with no interface found (line 73)."""
    logger = MagicMock()
    result = capture_traffic_snippet(
        "192.168.1.1", "/tmp", [], {"tcpdump": "/usr/bin/tcpdump"}, logger=logger  # No networks
    )
    assert result is None
    assert logger.info.called


def test_capture_traffic_snippet_invalid_interface_name():
    """Test capture_traffic_snippet with invalid interface name (line 77)."""
    networks = [{"network": "192.168.1.0/24", "interface": "eth0; rm -rf /"}]
    result = capture_traffic_snippet(
        "192.168.1.1", "/tmp", networks, {"tcpdump": "/usr/bin/tcpdump"}
    )
    assert result is None


def test_capture_traffic_snippet_subprocess_error():
    """Test capture_traffic_snippet with subprocess error (line 115)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("redaudit.core.scanner.traffic._make_runner") as mock_runner_factory:
            mock_runner = MagicMock()
            mock_runner_factory.return_value = mock_runner
            mock_runner.run.side_effect = Exception("Subprocess failed")

            logger = MagicMock()
            result = capture_traffic_snippet(
                "192.168.1.1",
                tmpdir,
                [{"network": "192.168.1.0/24", "interface": "eth0"}],
                {"tcpdump": "/usr/bin/tcpdump"},
                logger=logger,
            )
            # Should handle exception


def test_start_background_capture_dry_run():
    """Test start_background_capture in dry run (line 156)."""
    logger = MagicMock()
    result = start_background_capture(
        "192.168.1.1", "/tmp", [], {"tcpdump": "/usr/bin/tcpdump"}, logger=logger, dry_run=True
    )
    assert result is None


def test_start_background_capture_no_interface():
    """Test start_background_capture with no interface (line 180)."""
    logger = MagicMock()
    result = start_background_capture(
        "192.168.1.1", "/tmp", [], {"tcpdump": "/usr/bin/tcpdump"}, logger=logger
    )
    assert result is None
    assert logger.info.called


def test_start_background_capture_invalid_interface():
    """Test start_background_capture with invalid interface (line 184)."""
    networks = [{"network": "192.168.1.0/24", "interface": "eth0; rm -rf /"}]
    result = start_background_capture(
        "192.168.1.1", "/tmp", networks, {"tcpdump": "/usr/bin/tcpdump"}
    )
    assert result is None


def test_start_background_capture_subprocess_error():
    """Test start_background_capture with subprocess error (line 219)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("subprocess.Popen", side_effect=Exception("Failed")):
            logger = MagicMock()
            result = start_background_capture(
                "192.168.1.1",
                tmpdir,
                [{"network": "192.168.1.0/24", "interface": "eth0"}],
                {"tcpdump": "/usr/bin/tcpdump"},
                logger=logger,
            )
            assert result is None
            assert logger.debug.called


def test_stop_background_capture_path_normalization():
    """Test stop_background_capture with path normalization (line 244)."""
    proc = MagicMock()
    capture_info = {
        "process": proc,
        "pcap_file": "/absolute/path/to/file.pcap",  # Absolute path
        "pcap_file_abs": "/absolute/path/to/file.pcap",
        "iface": "eth0",
    }

    result = stop_background_capture(capture_info, {})
    assert result is not None
    assert "/" not in result["pcap_file"]  # Should be normalized to basename


def test_stop_background_capture_tshark_error():
    """Test stop_background_capture with tshark error (lines 284-285)."""
    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmpfile:
        proc = MagicMock()
        capture_info = {
            "process": proc,
            "pcap_file": "test.pcap",
            "pcap_file_abs": tmpfile.name,
            "iface": "eth0",
        }

        with patch("redaudit.core.scanner.traffic._make_runner") as mock_runner_factory:
            mock_runner = MagicMock()
            mock_runner_factory.return_value = mock_runner
            mock_runner.run.side_effect = Exception("tshark failed")

            logger = MagicMock()
            result = stop_background_capture(
                capture_info, {"tshark": "/usr/bin/tshark"}, logger=logger
            )
            assert "tshark_error" in result
