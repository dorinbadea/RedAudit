#!/usr/bin/env python3
"""
RedAudit - Tests for hyperscan sweeps and discovery.
"""

import socket
import shutil
from types import SimpleNamespace

from redaudit.core import hyperscan


def test_hyperscan_udp_sweep_collects_results(monkeypatch):
    captured = {}

    async def _fake_udp_probe(_sem, ip, port, _timeout, payload=b""):
        captured[port] = payload
        return (ip, port, b"ok")

    monkeypatch.setattr(hyperscan, "_udp_probe", _fake_udp_probe)

    results = hyperscan.hyperscan_udp_sweep_sync(
        ["10.0.0.1"],
        ports=[53, 123, 999],
        batch_size=2,
        timeout=0.01,
    )
    by_port = {entry["port"]: entry for entry in results["10.0.0.1"]}
    assert by_port[53]["protocol"] == "dns"
    assert by_port[123]["protocol"] == "ntp"
    assert by_port[999]["protocol"] == "unknown"
    assert by_port[53]["response_preview"] == "6f6b"
    assert captured[53].startswith(b"\x00\x00")
    assert captured[123].startswith(b"\x1b")
    assert captured[999] == b"\x00"


def test_hyperscan_udp_sweep_empty_inputs():
    assert hyperscan.hyperscan_udp_sweep_sync([], ports=[53]) == {}
    assert hyperscan.hyperscan_udp_sweep_sync(["10.0.0.1"], ports=[]) == {}


def test_hyperscan_udp_broadcast_invalid_network():
    assert hyperscan.hyperscan_udp_broadcast("bad") == []


def test_hyperscan_udp_broadcast_dedupes(monkeypatch):
    responses = [
        (b"resp1", ("192.168.1.10", 1900)),
        (b"resp2", ("192.168.1.10", 38899)),
    ]

    class _DummySocket:
        def __init__(self):
            self.timeout = None

        def setsockopt(self, *_args, **_kwargs):
            return None

        def settimeout(self, value):
            self.timeout = value

        def sendto(self, _data, _addr):
            return None

        def recvfrom(self, _size):
            if responses:
                return responses.pop(0)
            raise socket.timeout()

        def close(self):
            return None

    monkeypatch.setattr(hyperscan.socket, "socket", lambda *_args, **_kwargs: _DummySocket())

    devices = hyperscan.hyperscan_udp_broadcast("192.168.1.0/30", timeout=0.01)
    assert len(devices) == 1
    assert devices[0]["ip"] == "192.168.1.10"
    assert devices[0]["protocol"] == "ssdp"


def test_hyperscan_arp_aggressive_with_arp_scan(monkeypatch):
    def _fake_make_runner(**_kwargs):
        def _run(cmd, **_run_kwargs):
            if cmd[:3] == ["ip", "route", "show"]:
                return SimpleNamespace(stdout="dev eth0", timed_out=False)
            return SimpleNamespace(
                stdout="192.168.1.2 aa:bb:cc:dd:ee:ff Vendor\ninvalid\n",
                timed_out=False,
            )

        return SimpleNamespace(run=_run)

    monkeypatch.setattr(hyperscan, "_make_runner", _fake_make_runner)
    monkeypatch.setattr(shutil, "which", lambda name: "arp-scan" if name == "arp-scan" else None)

    results = hyperscan.hyperscan_arp_aggressive("192.168.1.0/30", retries=1, timeout=1.0)
    assert results[0]["ip"] == "192.168.1.2"
    assert results[0]["method"] == "arp-scan"


def test_hyperscan_arp_aggressive_with_arping(monkeypatch):
    def _fake_make_runner(**_kwargs):
        def _run(_cmd, **_run_kwargs):
            return SimpleNamespace(stdout="Reply from 192.168.1.1", timed_out=False)

        return SimpleNamespace(run=_run)

    monkeypatch.setattr(hyperscan, "_make_runner", _fake_make_runner)
    monkeypatch.setattr(shutil, "which", lambda name: "arping" if name == "arping" else None)

    results = hyperscan.hyperscan_arp_aggressive("192.168.1.0/30", retries=1, timeout=1.0)
    ips = {entry["ip"] for entry in results}
    assert ips == {"192.168.1.1", "192.168.1.2"}
    assert all(entry["method"] == "arping" for entry in results)


def test_hyperscan_full_discovery_invalid_network():
    calls = []

    def _progress(c, t, desc):
        calls.append((c, t, desc))

    result = hyperscan.hyperscan_full_discovery(["bad"], progress_callback=_progress)
    assert result["total_hosts_found"] == 0
    assert calls[-1][0] == 100


def test_hyperscan_full_discovery_priority_targets(monkeypatch):
    monkeypatch.setattr(
        hyperscan,
        "hyperscan_arp_aggressive",
        lambda *_args, **_kwargs: [{"ip": "10.0.0.1", "method": "arp-scan"}],
    )
    monkeypatch.setattr(
        hyperscan,
        "hyperscan_udp_broadcast",
        lambda *_args, **_kwargs: [{"ip": "10.0.0.2", "protocol": "ssdp"}],
    )

    captured = {}

    def _fake_tcp_sweep(targets, *_args, **_kwargs):
        captured["targets"] = set(targets)
        return {"10.0.0.1": [22]}

    monkeypatch.setattr(hyperscan, "hyperscan_tcp_sweep_sync", _fake_tcp_sweep)

    result = hyperscan.hyperscan_full_discovery(["10.0.0.0/30"], tcp_batch_size=10)
    assert captured["targets"] == {"10.0.0.1", "10.0.0.2"}
    assert result["tcp_hosts"]["10.0.0.1"] == [22]
    assert result["total_hosts_found"] == 2
