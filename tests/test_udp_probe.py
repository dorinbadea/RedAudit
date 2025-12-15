#!/usr/bin/env python3
"""
RedAudit - UDP Probe Tests
Unit tests for redaudit/core/udp_probe.py.

Note: Some CI/restricted environments may block opening sockets even on localhost,
so these tests mock socket and asyncio loop I/O.
"""

import os
import sys
import unittest
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.udp_probe import udp_probe_host, udp_probe_port


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
    async def test_multiple_ports_sorted(self):
        async def fake_probe(ip, port, timeout=0.8, payload=None):
            return {"port": port, "state": "responded", "response_bytes": 1, "response_sample_hex": "00"}

        with patch("redaudit.core.udp_probe.udp_probe_port", new=AsyncMock(side_effect=fake_probe)):
            res = await udp_probe_host("127.0.0.1", [53, 1, 9999], timeout=0.1, concurrency=2)

        self.assertEqual([r.get("port") for r in res], [1, 53, 9999])


if __name__ == "__main__":
    unittest.main()
