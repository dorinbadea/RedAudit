"""Edge-case tests for hyperscan async sweeps and probe utilities."""

import asyncio
import socket
from unittest.mock import patch, MagicMock, AsyncMock
import pytest
from redaudit.core.hyperscan import (
    hyperscan_tcp_sweep,
    hyperscan_udp_sweep,
    hyperscan_udp_broadcast,
    hyperscan_arp_aggressive,
    _tcp_connect,
    _udp_probe,
)


@pytest.mark.asyncio
async def test_tcp_connect_wait_closed_fallback():
    """Test _tcp_connect with wait_closed failure (lines 129-131)."""
    sem = asyncio.Semaphore(1)
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock(side_effect=OSError("Already closed"))

    async def _fake_wait_for(coro, timeout=None):
        return await coro

    with patch("asyncio.open_connection", AsyncMock(return_value=(MagicMock(), mock_writer))):
        with patch("asyncio.wait_for", _fake_wait_for):
            res = await _tcp_connect(sem, "1.1.1.1", 80, 0.1)
            # Should still return result because open_connection succeeded
            assert res == ("1.1.1.1", 80)


@pytest.mark.asyncio
async def test_hyperscan_tcp_sweep_chunking():
    """Test hyperscan_tcp_sweep chunking and progress (lines 183-198)."""
    targets = ["1.1.1.1", "1.1.1.2"]
    ports = [80, 443]
    mock_cb = MagicMock()
    with patch("redaudit.core.hyperscan._tcp_connect", side_effect=lambda s, i, p, t: (i, p)):
        res = await hyperscan_tcp_sweep(targets, ports, progress_callback=mock_cb)
        assert len(res["1.1.1.1"]) == 2
        assert mock_cb.called


@pytest.mark.asyncio
async def test_udp_probe_socket_errors():
    """Test _udp_probe socket creation and send errors (lines 257-263)."""
    sem = asyncio.Semaphore(1)
    # 258-260: Sock recv error
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = mock_sock_cls.return_value
        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.sock_sendto = AsyncMock()
            mock_loop.return_value.sock_recv = AsyncMock(side_effect=OSError("Recv failed"))
            res = await _udp_probe(sem, "1.1.1.1", 53, 0.1)
            assert res is None
            assert mock_sock.close.called


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
