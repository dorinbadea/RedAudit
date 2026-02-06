#!/usr/bin/env python3
"""
RedAudit - UDP Probe Tests
Unit tests for redaudit/core/udp_probe.py.

Note: Some CI/restricted environments may block opening sockets even on localhost,
so these tests mock socket and asyncio loop I/O.
"""

import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pytest

from redaudit.core.udp_probe import run_udp_probe, udp_probe_host, udp_probe_port


class TestUdpProbePort(unittest.IsolatedAsyncioTestCase):
    async def test_responded(self):
        fake_sock = Mock()
        fake_loop = Mock()
        fake_loop.sock_sendall = AsyncMock(return_value=None)
        fake_loop.sock_recv = AsyncMock(return_value=b"pong")

        with patch("redaudit.core.udp_probe.socket.socket", return_value=fake_sock):
            with patch("redaudit.core.udp_probe.asyncio.get_running_loop", return_value=fake_loop):
                res = await udp_probe_port("127.0.0.1", 9999, timeout=0.1, payload=b"x")

        self.assertEqual(res.get("port"), 9999)
        self.assertEqual(res.get("state"), "responded")
        self.assertGreaterEqual(int(res.get("response_bytes") or 0), 1)

    async def test_closed(self):
        fake_sock = Mock()
        fake_loop = Mock()
        fake_loop.sock_sendall = AsyncMock(return_value=None)
        fake_loop.sock_recv = AsyncMock(side_effect=ConnectionRefusedError())

        with patch("redaudit.core.udp_probe.socket.socket", return_value=fake_sock):
            with patch("redaudit.core.udp_probe.asyncio.get_running_loop", return_value=fake_loop):
                res = await udp_probe_port("127.0.0.1", 9999, timeout=0.1, payload=b"x")

        self.assertEqual(res.get("state"), "closed")

    async def test_no_response(self):
        import asyncio

        fake_sock = Mock()
        fake_loop = Mock()
        fake_loop.sock_sendall = AsyncMock(return_value=None)
        fake_loop.sock_recv = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch("redaudit.core.udp_probe.socket.socket", return_value=fake_sock):
            with patch("redaudit.core.udp_probe.asyncio.get_running_loop", return_value=fake_loop):
                res = await udp_probe_port("127.0.0.1", 9999, timeout=0.1, payload=b"x")

        self.assertEqual(res.get("state"), "no_response")


class TestUdpProbeHost(unittest.IsolatedAsyncioTestCase):
    async def test_empty_ports_returns_empty(self):
        res = await udp_probe_host("127.0.0.1", [])
        self.assertEqual(res, [])

    async def test_multiple_ports_sorted(self):
        async def fake_probe(ip, port, timeout=0.8, payload=None):
            return {
                "port": port,
                "state": "responded",
                "response_bytes": 1,
                "response_sample_hex": "00",
            }

        with patch("redaudit.core.udp_probe.udp_probe_port", new=AsyncMock(side_effect=fake_probe)):
            res = await udp_probe_host("127.0.0.1", [53, 1, 9999], timeout=0.1, concurrency=2)

        self.assertEqual([r.get("port") for r in res], [1, 53, 9999])


class TestUdpProbeRunner(unittest.TestCase):
    def test_run_udp_probe_fallback_threaded(self):
        import redaudit.core.udp_probe as udp_module

        calls = {"count": 0}
        expected = [
            {"port": 53, "state": "responded", "response_bytes": 1, "response_sample_hex": "00"}
        ]

        def _fake_run(_coroutine):
            try:
                _coroutine.close()
            except Exception:
                pass
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("loop already running")
            return expected

        with patch.object(udp_module.asyncio, "run", side_effect=_fake_run):
            res = run_udp_probe("127.0.0.1", [53], timeout=0.1, concurrency=1)

        self.assertEqual(res, expected)


def test_normalize_ports_and_hex_sample():
    import redaudit.core.udp_probe as udp_module

    ports = udp_module._normalize_ports([53, "bad", None, 70000, 53])
    assert ports == [53]
    assert udp_module._hex_sample(b"") == ""


def test_run_udp_probe_thread_exception():
    import redaudit.core.udp_probe as udp_module

    calls = {"count": 0}

    def _fake_run(_coroutine):
        try:
            _coroutine.close()
        except Exception:
            pass
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("loop already running")
        raise Exception("boom")

    with patch.object(udp_module.asyncio, "run", side_effect=_fake_run):
        res = run_udp_probe("127.0.0.1", [53], timeout=0.1, concurrency=1)

    assert res == []


if __name__ == "__main__":
    unittest.main()


@pytest.mark.asyncio
async def test_udp_probe_port_send_oserror():
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        mock_sock.connect = MagicMock()

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
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        mock_sock.connect = MagicMock()

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_event_loop = AsyncMock()
            mock_loop.return_value = mock_event_loop
            mock_event_loop.sock_sendall = AsyncMock()
            mock_event_loop.sock_recv = AsyncMock(side_effect=OSError("Recv failed"))

            result = await udp_probe_port("192.168.1.1", 53)

            assert result["port"] == 53
            assert result["state"] == "no_response"
            assert result["response_bytes"] == 0


@pytest.mark.asyncio
async def test_udp_probe_port_socket_close_exception():
    with patch("socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        mock_sock.close = MagicMock(side_effect=RuntimeError("Close failed"))
        mock_sock.connect = MagicMock()

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_event_loop = AsyncMock()
            mock_loop.return_value = mock_event_loop
            mock_event_loop.sock_sendall = AsyncMock()
            mock_event_loop.sock_recv = AsyncMock(side_effect=asyncio.TimeoutError())

            result = await udp_probe_port("192.168.1.1", 53)

            assert result["port"] == 53
            assert result["state"] == "no_response"


@pytest.mark.asyncio
async def test_udp_probe_host_gather_exception():
    with patch("redaudit.core.udp_probe.udp_probe_port") as mock_probe:
        mock_probe.side_effect = [
            {"port": 53, "state": "responded", "response_bytes": 10, "response_sample_hex": "abc"},
            RuntimeError("Probe failed"),
            {"port": 123, "state": "no_response", "response_bytes": 0, "response_sample_hex": ""},
        ]

        result = await udp_probe_host("192.168.1.1", [53, 80, 123])

        assert len(result) == 3
        port_80_result = next(r for r in result if r["port"] == 80)
        assert port_80_result["state"] == "no_response"
        assert port_80_result["response_bytes"] == 0
