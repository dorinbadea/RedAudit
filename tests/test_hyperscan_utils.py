#!/usr/bin/env python3
"""
RedAudit - Tests for HyperScan helpers.
"""

from unittest.mock import patch

from redaudit.core import hyperscan


def test_build_discovery_packets():
    ssdp = hyperscan._build_ssdp_msearch()
    mdns = hyperscan._build_mdns_query()
    wiz = hyperscan._build_wiz_discovery()

    assert b"M-SEARCH" in ssdp
    assert mdns[:2] == b"\x00\x00"
    assert b"registration" in wiz.lower()


def test_detect_potential_backdoors():
    tcp_results = {"10.0.0.1": [31337, 50000, 22]}
    service_info = {"10.0.0.1": {22: "weird"}}

    with patch("redaudit.core.scanner.is_suspicious_service", return_value=True):
        with patch("redaudit.core.scanner.is_port_anomaly", return_value=False):
            findings = hyperscan.detect_potential_backdoors(tcp_results, service_info=service_info)

    reasons = {f["port"]: f["reason"] for f in findings}
    assert 31337 in reasons
    assert 50000 in reasons
    assert 22 in reasons


def test_hyperscan_deep_scan_empty_and_forward(monkeypatch):
    assert hyperscan.hyperscan_deep_scan([]) == {}

    called = {}

    def _fake_sync(targets, ports, **_kwargs):
        called["targets"] = targets
        called["ports"] = ports
        return {"10.0.0.1": [80]}

    monkeypatch.setattr(hyperscan, "hyperscan_tcp_sweep_sync", _fake_sync)
    result = hyperscan.hyperscan_deep_scan(["10.0.0.1"], batch_size=10, timeout=0.1)
    assert result == {"10.0.0.1": [80]}
    assert called["targets"] == ["10.0.0.1"]
    assert called["ports"][0] == 1
