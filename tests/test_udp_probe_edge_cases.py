"""
Additional tests for udp_probe.py to reach 95%+ coverage.
Targets remaining uncovered lines: 128-129, 154-155, 164-165, 194.
"""

import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import pytest

from redaudit.core.udp_probe import (
    udp_probe_port,
    udp_probe_host,
    run_udp_probe,
)


# -------------------------------------------------------------------------
# udp_probe_port Error Handling Tests
# -------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_udp_probe_port_send_oserror():
    """Test udp_probe_port handles OSError on send (line 128-129)."""
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        # Mock connect to succeed
        mock_sock.connect = MagicMock()

        # Mock loop.sock_sendall to raise OSError
        with patch("asyncio.get_running_loop") as mock_loop:
            mock_event_loop = AsyncMock()
            mock_loop.return_value = mock_event_loop
            mock_event_loop.sock_sendall = AsyncMock(side_effect=OSError("Send failed"))

            result = await udp_probe_port("192.168.1.1", 53)

            assert result["port"] == 53
            assert result["state"] == "no_response"
            assert result["response_bytes"] == 0


@pytest.mark.asyncio
async def test_udp_probe_port_recv_oserror():
    """Test udp_probe_port handles OSError on recv (line 154-155)."""
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        # Mock connect and send to succeed
        mock_sock.connect = MagicMock()

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_event_loop = AsyncMock()
            mock_loop.return_value = mock_event_loop
            mock_event_loop.sock_sendall = AsyncMock()

            # Mock sock_recv to raise OSError (not ConnectionRefusedError)
            mock_event_loop.sock_recv = AsyncMock(side_effect=OSError("Recv failed"))

            result = await udp_probe_port("192.168.1.1", 53)

            assert result["port"] == 53
            assert result["state"] == "no_response"
            assert result["response_bytes"] == 0


@pytest.mark.asyncio
async def test_udp_probe_port_socket_close_exception():
    """Test udp_probe_port handles exception on socket.close (line 164-165)."""
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        # Make close() raise an exception
        mock_sock.close = MagicMock(side_effect=RuntimeError("Close failed"))
        mock_sock.connect = MagicMock()

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_event_loop = AsyncMock()
            mock_loop.return_value = mock_event_loop
            mock_event_loop.sock_sendall = AsyncMock()
            mock_event_loop.sock_recv = AsyncMock(side_effect=asyncio.TimeoutError())

            # Should not raise, exception is caught
            result = await udp_probe_port("192.168.1.1", 53)

            assert result["port"] == 53
            assert result["state"] == "no_response"


@pytest.mark.asyncio
async def test_udp_probe_host_gather_exception():
    """Test udp_probe_host handles exception in gather (line 194)."""
    with patch("redaudit.core.udp_probe.udp_probe_port") as mock_probe:
        # Make one probe raise an exception
        mock_probe.side_effect = [
            {"port": 53, "state": "responded", "response_bytes": 10, "response_sample_hex": "abc"},
            RuntimeError("Probe failed"),  # This triggers line 194
            {"port": 123, "state": "no_response", "response_bytes": 0, "response_sample_hex": ""},
        ]

        result = await udp_probe_host("192.168.1.1", [53, 80, 123])

        assert len(result) == 3
        # Port 80 should have fallback response due to exception
        port_80_result = next(r for r in result if r["port"] == 80)
        assert port_80_result["state"] == "no_response"
        assert port_80_result["response_bytes"] == 0
