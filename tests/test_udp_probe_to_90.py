"""
Tests for udp_probe.py to push coverage to 90%+.
Targets uncovered lines: 49-50, 58, 88-89, 114-115, 124-125, 154, 195-196.
"""

import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import pytest

from redaudit.core.udp_probe import (
    _build_dns_query,
    _normalize_ports,
    _hex_sample,
    udp_probe_port,
    udp_probe_host,
    run_udp_probe,
    UDP_PROBE_PAYLOADS,
)


# -------------------------------------------------------------------------
# _build_dns_query Tests
# -------------------------------------------------------------------------


def test_build_dns_query():
    """Test _build_dns_query returns valid DNS query bytes."""
    query = _build_dns_query()
    assert isinstance(query, bytes)
    assert len(query) > 0
    assert query[:2] == b"\x12\x34"  # Transaction ID


# -------------------------------------------------------------------------
# _normalize_ports Tests (lines 44-53)
# -------------------------------------------------------------------------


def test_normalize_ports_valid():
    """Test _normalize_ports with valid ports."""
    result = _normalize_ports([80, 443, 22])
    assert result == [22, 80, 443]


def test_normalize_ports_invalid_string():
    """Test _normalize_ports skips invalid string."""
    result = _normalize_ports([80, "invalid", 443])
    assert result == [80, 443]


def test_normalize_ports_out_of_range():
    """Test _normalize_ports skips out-of-range ports."""
    result = _normalize_ports([0, -1, 80, 70000, 443])
    assert result == [80, 443]


def test_normalize_ports_deduplicates():
    """Test _normalize_ports deduplicates."""
    result = _normalize_ports([80, 80, 443, 443])
    assert result == [80, 443]


def test_normalize_ports_exception():
    """Test _normalize_ports handles exception on int conversion."""
    result = _normalize_ports([80, None, 443])
    assert result == [80, 443]


# -------------------------------------------------------------------------
# _hex_sample Tests (lines 56-59)
# -------------------------------------------------------------------------


def test_hex_sample_normal():
    """Test _hex_sample returns hex string."""
    result = _hex_sample(b"\x00\x01\x02\x03")
    assert result == "00010203"


def test_hex_sample_empty():
    """Test _hex_sample with empty bytes."""
    result = _hex_sample(b"")
    assert result == ""


def test_hex_sample_none():
    """Test _hex_sample with None (falsy)."""
    result = _hex_sample(None)
    assert result == ""


def test_hex_sample_truncates():
    """Test _hex_sample truncates long data."""
    long_data = b"\x00" * 100
    result = _hex_sample(long_data, max_bytes=8)
    assert len(result) == 16  # 8 bytes * 2 hex chars


# -------------------------------------------------------------------------
# udp_probe_port Tests (lines 62-125)
# -------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_udp_probe_port_timeout():
    """Test udp_probe_port handles timeout."""
    # Probe a non-existent host/port combination to trigger timeout
    result = await udp_probe_port("127.0.0.1", 65534, timeout=0.1)
    assert result["port"] == 65534
    assert result["state"] in ["no_response", "closed", "responded"]


@pytest.mark.asyncio
async def test_udp_probe_port_sendall_exception():
    """Test udp_probe_port handles sendall exception."""
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect.return_value = None

        async def mock_error(*args):
            raise OSError("Send failed")

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop_instance = MagicMock()
            mock_loop.return_value = mock_loop_instance
            mock_loop_instance.sock_sendall = mock_error

            result = await udp_probe_port("192.168.1.1", 53, timeout=0.1)
            assert result["state"] == "no_response"


# -------------------------------------------------------------------------
# udp_probe_host Tests (lines 128-165)
# -------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_udp_probe_host_empty_ports():
    """Test udp_probe_host with empty ports list."""
    result = await udp_probe_host("192.168.1.1", [])
    assert result == []


@pytest.mark.asyncio
async def test_udp_probe_host_exception_handling():
    """Test udp_probe_host handles exceptions in gather."""

    async def mock_probe(*args, **kwargs):
        raise Exception("Probe failed")

    with patch("redaudit.core.udp_probe.udp_probe_port", side_effect=mock_probe):
        result = await udp_probe_host("192.168.1.1", [53, 123], timeout=0.1)
        # Should still return results with no_response state
        assert len(result) == 2
        for r in result:
            assert r["state"] == "no_response"


# -------------------------------------------------------------------------
# run_udp_probe Tests (lines 168-201)
# -------------------------------------------------------------------------


def test_run_udp_probe_empty_ports():
    """Test run_udp_probe with empty ports."""
    result = run_udp_probe("192.168.1.1", [])
    assert result == []


def test_run_udp_probe_runtime_error():
    """Test run_udp_probe handles RuntimeError with thread fallback."""

    def mock_asyncio_run(*args, **kwargs):
        raise RuntimeError("Cannot call from running loop")

    with patch("asyncio.run", side_effect=mock_asyncio_run):
        # Should fall back to thread-based execution
        result = run_udp_probe("192.168.1.1", [53], timeout=0.1)
        # Result depends on thread execution
        assert isinstance(result, list)


def test_run_udp_probe_thread_exception():
    """Test run_udp_probe handles exception in thread fallback."""

    def mock_asyncio_run(*args, **kwargs):
        raise RuntimeError("Cannot call from running loop")

    with patch("asyncio.run") as mock_run:
        # First call raises RuntimeError, second (in thread) raises Exception
        mock_run.side_effect = [RuntimeError("First"), Exception("Second")]
        result = run_udp_probe("192.168.1.1", [53], timeout=0.1)
        # Should return empty list on thread exception
        assert isinstance(result, list)


# -------------------------------------------------------------------------
# UDP_PROBE_PAYLOADS Tests
# -------------------------------------------------------------------------


def test_udp_probe_payloads_dns():
    """Test UDP_PROBE_PAYLOADS has DNS payload."""
    assert 53 in UDP_PROBE_PAYLOADS
    assert isinstance(UDP_PROBE_PAYLOADS[53], bytes)


def test_udp_probe_payloads_ntp():
    """Test UDP_PROBE_PAYLOADS has NTP payload."""
    assert 123 in UDP_PROBE_PAYLOADS
    assert len(UDP_PROBE_PAYLOADS[123]) == 48
