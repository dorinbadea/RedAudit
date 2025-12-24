import asyncio
import socket
import time
import pytest
import shutil
import sys
from unittest.mock import MagicMock, patch, AsyncMock
from types import SimpleNamespace
from redaudit.core import hyperscan


@pytest.fixture
def mock_semaphore():
    return asyncio.Semaphore(1)


# -------------------------------------------------------------------------
# TCP Sweep Tests
# -------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tcp_connect_success(mock_semaphore):
    mock_writer = AsyncMock()
    with patch("asyncio.open_connection", return_value=(AsyncMock(), mock_writer)) as mock_open:
        res = await hyperscan._tcp_connect(mock_semaphore, "127.0.0.1", 80, 0.1)
        assert res == ("127.0.0.1", 80)
        # writer.close() is called, but it might be a mock
        mock_writer.close.assert_called()


@pytest.mark.asyncio
async def test_tcp_connect_failure(mock_semaphore):
    # Timeout
    with patch("asyncio.open_connection", side_effect=asyncio.TimeoutError):
        res = await hyperscan._tcp_connect(mock_semaphore, "127.0.0.1", 80, 0.1)
        assert res is None

    # Connection refused
    with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
        res = await hyperscan._tcp_connect(mock_semaphore, "127.0.0.1", 80, 0.1)
        assert res is None


@pytest.mark.asyncio
async def test_hyperscan_tcp_sweep_logic():
    # Mock _tcp_connect to return specific results
    async def fake_connect(sem, ip, port, timeout):
        if port == 80:
            return (ip, port)
        return None

    with patch("redaudit.core.hyperscan._tcp_connect", side_effect=fake_connect):
        progress_calls = []

        def pb(c, t, d):
            progress_calls.append(c)

        results = await hyperscan.hyperscan_tcp_sweep(
            ["1.1.1.1", "2.2.2.2"],
            [80, 443],
            batch_size=10,
            logger=MagicMock(),
            progress_callback=pb,
        )
        assert results["1.1.1.1"] == [80]
        assert results["2.2.2.2"] == [80]
        assert len(progress_calls) > 0


def test_hyperscan_tcp_sweep_sync_wrapper():
    with patch("redaudit.core.hyperscan.hyperscan_tcp_sweep", new_callable=AsyncMock) as mock_async:
        mock_async.return_value = {}
        hyperscan.hyperscan_tcp_sweep_sync(["1.1.1.1"], [80])
        mock_async.assert_called()


@pytest.mark.asyncio
async def test_hyperscan_tcp_sweep_empty_async():
    assert await hyperscan.hyperscan_tcp_sweep([], [80]) == {}


# -------------------------------------------------------------------------
# UDP Probe Tests
# -------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_udp_probe_success(mock_semaphore):
    mock_sock = MagicMock()
    with (
        patch("socket.socket", return_value=mock_sock),
        patch("asyncio.get_event_loop") as mock_loop,
    ):

        loop = AsyncMock()
        mock_loop.return_value = loop
        loop.sock_recv.return_value = b"resp"

        res = await hyperscan._udp_probe(mock_semaphore, "1.1.1.1", 53, 0.1)
        assert res == ("1.1.1.1", 53, b"resp")
        mock_sock.close.assert_called()


@pytest.mark.asyncio
async def test_udp_probe_timeout(mock_semaphore):
    mock_sock = MagicMock()
    with (
        patch("socket.socket", return_value=mock_sock),
        patch("asyncio.get_event_loop") as mock_loop,
    ):

        loop = AsyncMock()
        mock_loop.return_value = loop
        loop.sock_recv.side_effect = asyncio.TimeoutError

        res = await hyperscan._udp_probe(mock_semaphore, "1.1.1.1", 53, 0.1)
        assert res is None


@pytest.mark.asyncio
async def test_udp_probe_exception(mock_semaphore):
    with patch("socket.socket", side_effect=Exception("ouch")):
        res = await hyperscan._udp_probe(mock_semaphore, "1.1.1.1", 53, 0.1)
        assert res is None


@pytest.mark.asyncio
async def test_hyperscan_udp_sweep_defaults_and_payloads():
    # Test default ports and specific payloads (SNMP=161, NetBIOS=137)
    async def fake_probe(sem, ip, port, timeout, payload):
        return (ip, port, b"")

    with patch("redaudit.core.hyperscan._udp_probe", side_effect=fake_probe) as mock_probe:
        # Default ports case
        await hyperscan.hyperscan_udp_sweep(["1.1.1.1"], ports=None, logger=MagicMock())
        assert mock_probe.called

        mock_probe.reset_mock()
        # Specific payloads
        await hyperscan.hyperscan_udp_sweep(["1.1.1.1"], ports=[161, 137, 53, 123])
        assert mock_probe.call_count == 4


# -------------------------------------------------------------------------
# UDP Broadcast Tests
# -------------------------------------------------------------------------


def test_hyperscan_udp_broadcast_unicast_logic(monkeypatch):
    class UnicastMockSocket:
        def __init__(self, *args, **kwargs):
            self.last_addr = None

        def settimeout(self, t):
            pass

        def setsockopt(self, *args, **kwargs):
            pass

        def sendto(self, data, addr):
            self.last_addr = addr

        def recvfrom(self, size):
            if self.last_addr and self.last_addr[0] == "192.168.1.10":
                return b"iot_resp", ("192.168.1.10", 38899)
            raise socket.timeout()

        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", UnicastMockSocket)
    results = hyperscan.hyperscan_udp_broadcast("192.168.1.0/24", timeout=0.01, logger=MagicMock())
    iot = [r for r in results if r["ip"] == "192.168.1.10"]
    assert len(iot) >= 1


def test_hyperscan_udp_broadcast_socket_error(monkeypatch):
    def block_socket(*args, **kwargs):
        raise Exception("socket failed")

    monkeypatch.setattr(socket, "socket", block_socket)
    assert hyperscan.hyperscan_udp_broadcast("192.168.1.0/24", logger=MagicMock()) == []


# -------------------------------------------------------------------------
# ARP sweep and Orchestration
# -------------------------------------------------------------------------


def test_hyperscan_arp_aggressive_fallbacks(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda n: "arping" if n == "arping" else None)
    mock_runner = MagicMock()
    mock_runner.run.return_value = SimpleNamespace(stdout="reply from 192.168.1.5", timed_out=False)
    monkeypatch.setattr(hyperscan, "_make_runner", lambda **kwargs: mock_runner)
    res = hyperscan.hyperscan_arp_aggressive("192.168.1.0/24", logger=MagicMock())
    assert len(res) > 0


def test_hyperscan_arp_aggressive_errors(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda n: "arp-scan")
    mock_runner = MagicMock()
    mock_runner.run.side_effect = [Exception("route fail"), Exception("arp-scan fail")]
    monkeypatch.setattr(hyperscan, "_make_runner", lambda **kwargs: mock_runner)
    # Should not crash
    hyperscan.hyperscan_arp_aggressive("10.0.0.0/24", logger=MagicMock())


def test_hyperscan_full_discovery_sampling(monkeypatch):
    monkeypatch.setattr(hyperscan, "hyperscan_arp_aggressive", lambda *a, **k: [])
    monkeypatch.setattr(hyperscan, "hyperscan_udp_broadcast", lambda *a, **k: [])
    captured = []
    monkeypatch.setattr(
        hyperscan,
        "hyperscan_tcp_sweep_sync",
        lambda targets, *a, **k: captured.extend(targets) or {},
    )

    # Large network sampling
    hyperscan.hyperscan_full_discovery(["10.0.0.0/23"])
    assert len(captured) == 150

    # Small network sampling
    captured.clear()
    hyperscan.hyperscan_full_discovery(["10.0.0.0/30"])
    assert len(captured) == 2


def test_hyperscan_full_discovery_no_weights():
    res = hyperscan.hyperscan_full_discovery(
        ["10.0.0.0/24"], include_arp=False, include_udp=False, include_tcp=False
    )
    assert res["total_hosts_found"] == 0


def test_report_exception_handling():
    def bad_callback(c, t, d):
        raise Exception("boom")

    with (
        patch("redaudit.core.hyperscan.hyperscan_arp_aggressive", return_value=[]),
        patch("redaudit.core.hyperscan.hyperscan_udp_broadcast", return_value=[]),
        patch("redaudit.core.hyperscan.hyperscan_tcp_sweep_sync", return_value={}),
    ):
        # Should not crash
        hyperscan.hyperscan_full_discovery(["10.0.0.0/24"], progress_callback=bad_callback)


# -------------------------------------------------------------------------
# Backdoor Detection
# -------------------------------------------------------------------------


def test_detect_potential_backdoors():
    tcp = {"1.1.1.1": [31337, 80, 60000]}
    findings = hyperscan.detect_potential_backdoors(tcp, logger=MagicMock())
    assert len(findings) == 2


def test_detect_backdoors_with_scanner_integration():
    tcp = {"1.1.1.1": [80]}
    svc_info = {"1.1.1.1": {80: "suspicious-shell"}}
    with (
        patch("redaudit.core.scanner.is_suspicious_service", return_value=True),
        patch("redaudit.core.scanner.is_port_anomaly", return_value=False),
    ):
        findings = hyperscan.detect_potential_backdoors(tcp, service_info=svc_info)
        assert len(findings) == 1
    with (
        patch("redaudit.core.scanner.is_suspicious_service", return_value=False),
        patch("redaudit.core.scanner.is_port_anomaly", return_value=True),
    ):
        findings = hyperscan.detect_potential_backdoors(tcp, service_info=svc_info)
        assert len(findings) == 1


def test_detect_backdoors_scanner_missing():
    with patch.dict("sys.modules", {"redaudit.core.scanner": None}):
        # Need to reload or just rely on the fact that it will fail import inside
        with patch("builtins.__import__", side_effect=ImportError):
            findings = hyperscan.detect_potential_backdoors({"1.1.1.1": [31337]})
            assert len(findings) == 1


# -------------------------------------------------------------------------
# Deep Scan and Progress Bar
# -------------------------------------------------------------------------


def test_hyperscan_deep_scan():
    with patch("redaudit.core.hyperscan.hyperscan_tcp_sweep_sync", return_value={}) as mock_tcp:
        hyperscan.hyperscan_deep_scan(["1.1.1.1"], logger=MagicMock())
        assert hyperscan.hyperscan_deep_scan([]) == {}
        args, kwargs = mock_tcp.call_args
        assert len(args[1]) == 65535


def test_hyperscan_with_progress_logic():
    # Case 1: Rich missing
    with patch("builtins.__import__", side_effect=ImportError):
        with patch("redaudit.core.hyperscan.hyperscan_full_discovery") as mock_full:
            hyperscan.hyperscan_with_progress(["1.1.1.1"])
            mock_full.assert_called()

    # Case 2: Rich present
    from rich.progress import Progress

    with (
        patch("redaudit.core.hyperscan.hyperscan_full_discovery", return_value={}) as mock_disc,
        patch("rich.progress.Progress") as mock_prog,
    ):

        prog_inst = MagicMock()
        mock_prog.return_value.__enter__.return_value = prog_inst
        hyperscan.hyperscan_with_progress(["1.1.1.1"])

        # Test the callback
        args, kwargs = mock_disc.call_args
        cb = kwargs.get("progress_callback")
        if not cb and len(args) > 3:
            cb = args[3]

        if cb:
            cb(50, 100, "test")
            prog_inst.update.assert_called()


# -------------------------------------------------------------------------
# Nmap Enrichment
# -------------------------------------------------------------------------


def test_hyperscan_with_nmap_enrichment():
    res = {"tcp_hosts": {"1.1.1.1": [22]}}
    with patch("shutil.which", return_value=None):
        assert hyperscan.hyperscan_with_nmap_enrichment(res) == res

    with patch("shutil.which", return_value="/usr/bin/nmap"):
        mock_runner = MagicMock()
        mock_runner.run.return_value = SimpleNamespace(stdout="22/tcp open ssh", timed_out=False)
        with patch("redaudit.core.hyperscan._make_runner", return_value=mock_runner):
            enriched = hyperscan.hyperscan_with_nmap_enrichment(res)
            assert enriched["service_info"]["1.1.1.1"][22] == "ssh"

    # Edge cases
    assert hyperscan.hyperscan_with_nmap_enrichment({"tcp_hosts": {}}) == {"tcp_hosts": {}}
    assert hyperscan.hyperscan_with_nmap_enrichment({"tcp_hosts": {"1.1.1.1": []}}) == {
        "tcp_hosts": {"1.1.1.1": []}
    }

    with (
        patch("shutil.which", return_value="/usr/bin/nmap"),
        patch("redaudit.core.hyperscan._make_runner") as mock_rf,
    ):
        runner = MagicMock()
        runner.run.side_effect = Exception("fail")
        mock_rf.return_value = runner
        hyperscan.hyperscan_with_nmap_enrichment(
            {"tcp_hosts": {"1.1.1.1": [80]}}, logger=MagicMock()
        )
