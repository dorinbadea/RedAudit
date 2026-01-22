#!/usr/bin/env python3
"""
RedAudit - Consolidated tests for hyperscan helpers, sweeps, and progress.
"""

import asyncio
import builtins
import logging
import shutil
import socket
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from redaudit.core import hyperscan
from redaudit.core.hyperscan import (
    detect_potential_backdoors,
    hyperscan_arp_aggressive,
    hyperscan_full_discovery,
    hyperscan_tcp_sweep,
    hyperscan_tcp_sweep_sync,
    hyperscan_udp_broadcast,
    hyperscan_udp_sweep,
    hyperscan_udp_sweep_sync,
    hyperscan_with_nmap_enrichment,
    hyperscan_with_progress,
    _tcp_connect,
    _udp_probe,
)


def test_build_discovery_packets():
    ssdp = hyperscan._build_ssdp_msearch()
    mdns = hyperscan._build_mdns_query()
    wiz = hyperscan._build_wiz_discovery()

    assert b"M-SEARCH" in ssdp
    assert mdns[:2] == b"\x00\x00"
    assert b"registration" in wiz.lower()


def test_compute_safe_max_batch_no_limit(monkeypatch):
    monkeypatch.setattr(hyperscan, "_get_fd_soft_limit", lambda: None)
    assert hyperscan._compute_safe_max_batch(20000, min_batch=100) == 20000


def test_compute_safe_max_batch_caps_by_limit(monkeypatch):
    monkeypatch.setattr(hyperscan, "_get_fd_soft_limit", lambda: 1000)
    assert hyperscan._compute_safe_max_batch(20000, min_batch=100) == 800


def test_compute_safe_max_batch_respects_min(monkeypatch):
    monkeypatch.setattr(hyperscan, "_get_fd_soft_limit", lambda: 80)
    assert hyperscan._compute_safe_max_batch(20000, min_batch=100) == 100


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
    assert captured[53].startswith(b"\x12\x34")  # DNS query TX ID
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


def test_hyperscan_udp_broadcast_edge():
    """Test hyperscan_udp_broadcast with invalid CIDR and socket failures (lines 419, 432, 446-462)."""
    # 419: Invalid network
    assert hyperscan_udp_broadcast("invalid") == []

    # 432, 466: Socket exceptions
    with patch("socket.socket", side_effect=Exception("Socket Fail")):
        res = hyperscan_udp_broadcast("192.168.1.0/24")
        assert res == []


def test_hyperscan_arp_aggressive_failures():
    """Test hyperscan_arp_aggressive with missing tools and timeouts (lines 597, 627, 632, 659)."""
    # 559: arp-scan missing, 632: arping missing
    with patch("shutil.which", return_value=None):
        assert hyperscan_arp_aggressive("1.1.1.0/24") == []

    # 597: arp-scan timeout
    with patch("shutil.which", side_effect=lambda x: "/bin/arp-scan" if x == "arp-scan" else None):
        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(timed_out=True, stdout="")
        with patch("redaudit.core.hyperscan._make_runner", return_value=mock_runner):
            res = hyperscan_arp_aggressive("1.1.1.0/24")
            assert res == []

    # 627: arp-scan exception
    with patch("shutil.which", side_effect=lambda x: "/bin/arp-scan" if x == "arp-scan" else None):
        mock_runner = MagicMock()
        mock_runner.run.side_effect = Exception("Runner Crash")
        with patch("redaudit.core.hyperscan._make_runner", return_value=mock_runner):
            res = hyperscan_arp_aggressive("1.1.1.0/24")
            assert res == []


def test_hyperscan_full_discovery_invalid_net():
    """Test hyperscan_full_discovery with invalid networks (lines 761, 764)."""
    res = hyperscan_full_discovery(["invalid"])
    assert res["total_hosts_found"] == 0


def test_hyperscan_full_discovery_sampling():
    """Test hyperscan_full_discovery network sampling logic (lines 843-852)."""
    # Create a large network (/24)
    ips = [f"1.1.1.{i}" for i in range(1, 255)]
    with patch("redaudit.core.hyperscan.hyperscan_arp_aggressive", return_value=[]):
        with patch("redaudit.core.hyperscan.hyperscan_udp_broadcast", return_value=[]):
            with patch(
                "redaudit.core.hyperscan.hyperscan_tcp_sweep_sync", return_value={}
            ) as mock_tcp:
                hyperscan_full_discovery(["1.1.1.0/24"], include_arp=True, include_udp=True)
                # Check targets length (should be around 150)
                targets = mock_tcp.call_args[0][0]
                assert len(targets) <= 150


def test_detect_potential_backdoors_sev():
    """Test detect_potential_backdoors severity and anomalies (lines 965, 975, 980)."""
    # 965: High port medium severity
    res = detect_potential_backdoors({"1.1.1.1": [50000]})
    assert res[0]["severity"] == "medium"

    # 975: Suspicious service
    with patch("redaudit.core.scanner.is_suspicious_service", return_value=True):
        with patch("redaudit.core.scanner.is_port_anomaly", return_value=False):
            res = detect_potential_backdoors({"1.1.1.1": [80]}, {"1.1.1.1": {80: "backdoor"}})
            assert res[0]["severity"] == "high"
            assert "Suspicious service" in res[0]["reason"]


def test_hyperscan_with_progress_fallback():
    """Test hyperscan_with_progress rich missing fallback (lines 1109, 1111)."""
    # Mock the rich.progress import to raise ImportError
    import sys

    # Temporarily remove rich from sys.modules cache to force re-import attempt
    orig_rich = sys.modules.get("rich.progress")
    sys.modules["rich.progress"] = None  # This will cause ImportError during import

    try:
        # Now when hyperscan_with_progress tries `from rich.progress import ...` it will fail
        with patch("redaudit.core.hyperscan.hyperscan_full_discovery", return_value={"ok": True}):
            res = hyperscan_with_progress(["1.1.1.0/24"])
            assert res["ok"] is True
    finally:
        # Restore original
        if orig_rich is not None:
            sys.modules["rich.progress"] = orig_rich
        elif "rich.progress" in sys.modules:
            del sys.modules["rich.progress"]


def test_hyperscan_with_nmap_enrichment_missing():
    """Test hyperscan_with_nmap_enrichment nmap missing (lines 1142-1143, 1146-1147)."""
    # 1142: Missing nmap
    with patch("shutil.which", return_value=None):
        res = hyperscan_with_nmap_enrichment({"tcp_hosts": {"1.1.1.1": [80]}})
        assert "service_info" not in res

    # 1146: Empty tcp_hosts
    with patch("shutil.which", return_value="/bin/nmap"):
        res = hyperscan_with_nmap_enrichment({"tcp_hosts": {}})
        assert "service_info" not in res


def test_hyperscan_with_nmap_enrichment_parse():
    """Test hyperscan_with_nmap_enrichment output parsing (lines 1165-1176)."""
    with patch("shutil.which", return_value="/bin/nmap"):
        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(
            stdout="80/tcp open http\n443/tcp open https", stderr=""
        )
        with patch("redaudit.core.hyperscan._make_runner", return_value=mock_runner):
            res = hyperscan_with_nmap_enrichment({"tcp_hosts": {"1.1.1.1": [80, 443]}})
            assert res["service_info"]["1.1.1.1"][80] == "http"
            assert res["service_info"]["1.1.1.1"][443] == "https"


def test_hyperscan_udp_broadcast_recv_loop():
    """Test hyperscan_udp_broadcast recv loop edge cases (lines 446-462)."""
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = mock_sock_cls.return_value
        # First call returns data, second call raises timeout
        mock_sock.recvfrom.side_effect = [((b"resp", ("1.1.1.1", 123))), socket.timeout()]
        res = hyperscan_udp_broadcast("1.1.1.0/24", timeout=0.1)
        assert len(res) >= 1
        assert res[0]["ip"] == "1.1.1.1"


def test_hyperscan_arp_aggressive_parsing_edge():
    """Test hyperscan_arp_aggressive output parsing (lines 607, 608, 624-625)."""
    with patch("shutil.which", return_value="/bin/arp-scan"):
        mock_runner = MagicMock()
        # Invalid line, then valid line with missing vendor
        mock_runner.run.return_value = MagicMock(
            stdout="invalid\n1.1.1.1 aa:bb:cc:dd:ee:ff", timed_out=False
        )
        with patch("redaudit.core.hyperscan._make_runner", return_value=mock_runner):
            res = hyperscan_arp_aggressive("1.1.1.0/24")
            assert res[0]["ip"] == "1.1.1.1"
            assert res[0]["vendor"] == ""


def test_hyperscan_with_progress_complete():
    """Test hyperscan_with_progress full flow with rich (lines 1095-1096)."""
    with patch("rich.progress.Progress") as mock_progress:
        from redaudit.core.hyperscan import hyperscan_with_progress

        with patch("redaudit.core.hyperscan.hyperscan_full_discovery", return_value={"ok": True}):
            hyperscan_with_progress(["1.1.1.0/24"])
            assert mock_progress.called


class _DummyProgress:
    instances = []

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.updates = []
        _DummyProgress.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def add_task(self, *args, **kwargs):
        self.task_args = args
        self.task_kwargs = kwargs
        return 1

    def update(self, task_id, **kwargs):
        self.updates.append(kwargs)


class _DummyColumn:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class _DummyConsole:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


def test_hyperscan_with_progress_rich(monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "rich.progress",
        SimpleNamespace(
            Progress=_DummyProgress,
            SpinnerColumn=_DummyColumn,
            BarColumn=_DummyColumn,
            TextColumn=_DummyColumn,
            TimeElapsedColumn=_DummyColumn,
        ),
    )
    monkeypatch.setitem(sys.modules, "rich.console", SimpleNamespace(Console=_DummyConsole))

    def _fake_full_discovery(networks, logger=None, dry_run=None, progress_callback=None):
        if progress_callback:
            progress_callback(5, 10, "half")
        return {"ok": True}

    monkeypatch.setattr(hyperscan, "hyperscan_full_discovery", _fake_full_discovery)

    result = hyperscan.hyperscan_with_progress(["10.0.0.0/24"])
    assert result == {"ok": True}

    progress = _DummyProgress.instances[-1]
    assert any(update.get("completed") == 100 for update in progress.updates)


def test_hyperscan_with_progress_fallback(monkeypatch):
    real_import = builtins.__import__

    def _blocked_import(name, *args, **kwargs):
        if name.startswith("rich"):
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)

    called = {}

    def _fake_full_discovery(networks, logger=None, dry_run=None, progress_callback=None):
        called["networks"] = networks
        return {"fallback": True}

    monkeypatch.setattr(hyperscan, "hyperscan_full_discovery", _fake_full_discovery)

    result = hyperscan.hyperscan_with_progress(["10.0.0.0/24"])
    assert result == {"fallback": True}
    assert called["networks"] == ["10.0.0.0/24"]


def test_hyperscan_with_nmap_enrichment(monkeypatch):
    discovery = {"tcp_hosts": {"10.0.0.1": [22, 80]}}

    def _fake_runner(*_args, **_kwargs):
        output = "22/tcp open ssh\n80/tcp open http\n"
        return SimpleNamespace(run=lambda *_a, **_kw: SimpleNamespace(stdout=output))

    monkeypatch.setattr(hyperscan, "_make_runner", lambda *a, **k: _fake_runner())
    monkeypatch.setattr(shutil, "which", lambda _name: "nmap")
    monkeypatch.setattr(
        hyperscan,
        "detect_potential_backdoors",
        lambda *_args, **_kwargs: [{"ip": "10.0.0.1", "port": 22, "reason": "test"}],
    )

    enriched = hyperscan.hyperscan_with_nmap_enrichment(discovery, extra_tools={})
    assert enriched["service_info"]["10.0.0.1"][22] == "ssh"
    assert enriched["potential_backdoors"][0]["port"] == 22


def test_hyperscan_with_nmap_enrichment_no_nmap(monkeypatch):
    discovery = {"tcp_hosts": {"10.0.0.1": [22]}}
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert hyperscan.hyperscan_with_nmap_enrichment(discovery, extra_tools={}) == discovery


@pytest.mark.asyncio
async def test_hyperscan_tcp_sweep_success():
    """Test async TCP sweep success path."""
    targets = ["192.168.1.1"]
    ports = [80]

    # Mock asyncio.open_connection
    # It returns (reader, writer)
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
        mock_conn.return_value = (mock_reader, mock_writer)

        results = await hyperscan.hyperscan_tcp_sweep(targets, ports, batch_size=10, timeout=0.1)

        assert 80 in results["192.168.1.1"]
        mock_writer.close.assert_called()
        mock_writer.wait_closed.assert_awaited()


@pytest.mark.asyncio
async def test_hyperscan_tcp_sweep_refused():
    """Test async TCP sweep connection refused."""
    targets = ["192.168.1.1"]
    ports = [80]

    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
        mock_conn.side_effect = ConnectionRefusedError()

        results = await hyperscan.hyperscan_tcp_sweep(targets, ports, batch_size=10, timeout=0.1)

        assert 80 not in results["192.168.1.1"]


@pytest.mark.asyncio
async def test_hyperscan_tcp_sweep_timeout():
    """Test async TCP sweep timeout."""
    targets = ["192.168.1.1"]
    ports = [80]

    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
        mock_conn.side_effect = asyncio.TimeoutError()

        results = await hyperscan.hyperscan_tcp_sweep(targets, ports, batch_size=10, timeout=0.1)

        assert 80 not in results["192.168.1.1"]


@pytest.mark.asyncio
async def test_hyperscan_udp_sweep_success():
    """Test async UDP sweep success path."""
    targets = ["192.168.1.1"]
    ports = [161]

    # Mock loop.sock_sendto and sock_recv
    mock_loop = MagicMock()
    mock_sock = MagicMock()

    # mock_loop.sock_sendto is awaitable
    mock_loop.sock_sendto = AsyncMock()
    # mock_loop.sock_recv is awaitable, returns data
    mock_loop.sock_recv = AsyncMock(return_value=b"response")

    with patch("asyncio.get_event_loop", return_value=mock_loop):
        with patch("socket.socket", return_value=mock_sock):

            results = await hyperscan.hyperscan_udp_sweep(
                targets, ports, batch_size=10, timeout=0.1
            )

            port_info = results["192.168.1.1"][0]
            assert port_info["port"] == 161
            assert port_info["response_size"] == 8


@pytest.mark.asyncio
async def test_hyperscan_udp_sweep_timeout():
    """Test async UDP sweep timeout."""
    targets = ["192.168.1.1"]
    ports = [161]

    mock_loop = MagicMock()
    mock_sock = MagicMock()

    mock_loop.sock_sendto = AsyncMock()
    mock_loop.sock_recv = AsyncMock(side_effect=asyncio.TimeoutError)

    with patch("asyncio.get_event_loop", return_value=mock_loop):
        with patch("socket.socket", return_value=mock_sock):

            results = await hyperscan.hyperscan_udp_sweep(
                targets, ports, batch_size=10, timeout=0.1
            )

            assert len(results["192.168.1.1"]) == 0


def test_hyperscan_full_port_sweep_rustscan(monkeypatch):
    """Test full port sweep using RustScan."""

    # Mock is_rustscan_available -> True
    monkeypatch.setattr("redaudit.core.rustscan.is_rustscan_available", lambda: True)

    # Mock run_rustscan_discovery_only -> ([80, 443], None)
    def fake_rustscan(*args, **kwargs):
        return [80, 443], None

    monkeypatch.setattr("redaudit.core.rustscan.run_rustscan_discovery_only", fake_rustscan)

    ports = hyperscan.hyperscan_full_port_sweep("192.168.1.1")
    assert ports == [80, 443]


def test_hyperscan_full_port_sweep_fallback(monkeypatch):
    """Test full port sweep fallback to asyncio."""

    # Mock is_rustscan_available -> False
    # Check if module exists first to avoid import error in mock if not installed?
    # Hyperscan imports safely.
    # We can mock the function even if module not loaded if we use sys.modules or patch.
    # But hyperscan.py does: try: from redaudit.core.rustscan ... except ImportError
    # So we need to ensure it fails or mock the function if available.

    # Let's just patch is_rustscan_available to False if it can be imported,
    # or ensure ImportError if not.
    # Simpler: Mock is_rustscan_available to False

    # We need to handle the import inside hyperscan.py
    # If we patch redaudit.core.rustscan.is_rustscan_available, we assume it's importable.
    # If not importable, fallback happens anyway.

    # Let's force fallback by patching is_rustscan_available = False
    # If runtime has it.

    with patch("redaudit.core.rustscan.is_rustscan_available", return_value=False):
        # We also need to mock hyperscan_tcp_sweep (the sync call inside loop.run_until_complete)
        # Note: hyperscan_full_port_sweep calls hyperscan_tcp_sweep (async) via a new event loop.

        async def fake_sweep(*args, **kwargs):
            return {"192.168.1.1": [22, 80]}

        with patch("redaudit.core.hyperscan.hyperscan_tcp_sweep", side_effect=fake_sweep):
            ports = hyperscan.hyperscan_full_port_sweep("192.168.1.1")
            assert ports == [22, 80]
