#!/usr/bin/env python3
"""
Coverage for scanner enrichment and capture helpers.
"""

from __future__ import annotations

import os
from types import SimpleNamespace

from redaudit.core import scanner


def test_capture_traffic_snippet_with_tshark(monkeypatch, tmp_path):
    class _Runner:
        def run(self, *_args, **_kwargs):
            return SimpleNamespace(timed_out=False, stdout="summary", stderr="")

    monkeypatch.setattr(scanner, "_make_runner", lambda **_k: _Runner())

    info = scanner.capture_traffic_snippet(
        host_ip="192.168.1.10",
        output_dir=str(tmp_path),
        networks=[{"interface": "eth0", "network": "192.168.1.0/24"}],
        extra_tools={"tcpdump": "tcpdump", "tshark": "tshark"},
        duration=1,
        dry_run=False,
    )

    assert info is not None
    assert info["iface"] == "eth0"
    assert "pcap_file" in info
    assert "tshark_summary" in info


def test_enrich_host_with_dns_and_whois(monkeypatch):
    class _Runner:
        def run(self, cmd, **_kwargs):
            if cmd[0] == "dig":
                return SimpleNamespace(stdout="dns.google.\n", stderr="")
            if cmd[0] == "whois":
                return SimpleNamespace(stdout="OrgName: Example\n", stderr="")
            return SimpleNamespace(stdout="", stderr="")

    monkeypatch.setattr(scanner, "_make_runner", lambda **_k: _Runner())

    host = {"ip": "8.8.8.8"}
    tools = {"dig": "dig", "whois": "whois"}

    scanner.enrich_host_with_dns(host, tools)
    scanner.enrich_host_with_whois(host, tools)

    assert "reverse" in host["dns"]
    assert "whois_summary" in host["dns"]


def test_http_tls_enrichment(monkeypatch):
    class _Runner:
        def run(self, cmd, **_kwargs):
            if cmd[0] == "curl":
                return SimpleNamespace(stdout="HTTP/1.1 200 OK", stderr="")
            if cmd[0] == "wget":
                return SimpleNamespace(stdout="", stderr="HTTP/1.1 200 OK")
            if cmd[0] == "openssl":
                return SimpleNamespace(stdout="Protocol : TLSv1.2", stderr="")
            return SimpleNamespace(stdout="", stderr="")

    monkeypatch.setattr(scanner, "_make_runner", lambda **_k: _Runner())

    http = scanner.http_enrichment(
        "https://example.com",
        extra_tools={"curl": "curl", "wget": "wget"},
        dry_run=False,
    )
    tls = scanner.tls_enrichment(
        "1.2.3.4",
        443,
        extra_tools={"openssl": "openssl"},
        dry_run=False,
    )

    assert "curl_headers" in http
    assert "wget_headers" in http
    assert "tls_info" in tls


def test_exploit_lookup_parses_output(monkeypatch):
    class _Runner:
        def run(self, *_args, **_kwargs):
            output = "\n".join(
                [
                    "Exploit Title | Path",
                    "-------------- | ----",
                    "Apache 2.4.49 - RCE | exploits/1",
                ]
            )
            return SimpleNamespace(returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(scanner, "_make_runner", lambda **_k: _Runner())

    exploits = scanner.exploit_lookup("Apache", "2.4.49", {"searchsploit": "searchsploit"})

    assert exploits == ["Apache 2.4.49 - RCE"]


def test_ssl_deep_analysis_detects_findings(monkeypatch):
    class _Runner:
        def run(self, *_args, **_kwargs):
            output = "\n".join(
                [
                    "VULNERABLE - heartbleed",
                    "Weak cipher: RC4",
                    "TLS 1.2 supported",
                ]
            )
            return SimpleNamespace(timed_out=False, stdout=output, stderr="")

    monkeypatch.setattr(scanner, "_make_runner", lambda **_k: _Runner())

    result = scanner.ssl_deep_analysis(
        "192.168.1.10",
        443,
        extra_tools={"testssl.sh": "testssl.sh"},
    )

    assert result is not None
    assert result["summary"].startswith("CRITICAL")


def test_start_and_stop_background_capture(monkeypatch, tmp_path):
    class _Proc:
        def terminate(self):
            return None

        def wait(self, *_args, **_kwargs):
            return 0

        def kill(self):
            return None

    class _Runner:
        def run(self, *_args, **_kwargs):
            return SimpleNamespace(timed_out=False, stdout="summary", stderr="")

    monkeypatch.setattr(scanner.subprocess, "Popen", lambda *_a, **_k: _Proc())
    monkeypatch.setattr(scanner, "_make_runner", lambda **_k: _Runner())

    capture = scanner.start_background_capture(
        host_ip="192.168.1.10",
        output_dir=str(tmp_path),
        networks=[{"interface": "eth0", "network": "192.168.1.0/24"}],
        extra_tools={"tcpdump": "tcpdump"},
        dry_run=False,
    )

    assert capture is not None
    pcap_path = capture["pcap_file_abs"]
    os.makedirs(os.path.dirname(pcap_path), exist_ok=True)
    with open(pcap_path, "w", encoding="utf-8"):
        pass

    result = scanner.stop_background_capture(
        capture,
        extra_tools={"tshark": "tshark"},
        dry_run=False,
    )

    assert "tshark_summary" in result


def test_banner_grab_fallback_parses_output(monkeypatch):
    class _Runner:
        def run(self, *_args, **_kwargs):
            output = "\n".join(
                [
                    "80/tcp open http",
                    "banner: Apache",
                    "ssl-cert: Subject: CN=example",
                ]
            )
            return SimpleNamespace(timed_out=False, stdout=output, stderr="")

    monkeypatch.setattr(scanner, "_make_runner", lambda **_k: _Runner())

    result = scanner.banner_grab_fallback("192.168.1.10", [80])

    assert result[80]["banner"] == "Apache"
    assert "ssl-cert" in result[80]["ssl_cert"].lower()


def test_finalize_host_status_from_deep_scan():
    status = scanner.finalize_host_status(
        {
            "status": "down",
            "deep_scan": {"commands": [{"stdout": "Host is up"}]},
        }
    )

    assert status == scanner.STATUS_FILTERED
