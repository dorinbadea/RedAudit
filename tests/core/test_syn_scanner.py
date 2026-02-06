#!/usr/bin/env python3
"""
Tests for SYN scanner module.

v4.3: Tests for is_syn_scan_available and syn_probe functions.
v4.4.5: Comprehensive coverage push (21% → 90%+).
"""

import asyncio
import importlib
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

import redaudit.core.syn_scanner as syn_mod
from redaudit.core.syn_scanner import (
    is_syn_scan_available,
    syn_probe_single,
    syn_sweep_batch,
    syn_sweep_sync,
)


class TestSynScanAvailability(unittest.TestCase):
    """Tests for is_syn_scan_available function."""

    def test_import_sets_scapy_flags(self):
        """Should set scapy flags when scapy is available at import time."""
        original_module = sys.modules["redaudit.core.syn_scanner"]
        fake_scapy = types.ModuleType("scapy")
        fake_scapy_all = types.ModuleType("scapy.all")
        fake_conf = types.SimpleNamespace(verb=1)
        fake_scapy_all.conf = fake_conf
        fake_scapy_all.IP = MagicMock()
        fake_scapy_all.TCP = MagicMock()
        fake_scapy_all.sr1 = MagicMock()
        sys.modules["scapy"] = fake_scapy
        sys.modules["scapy.all"] = fake_scapy_all
        try:
            reloaded = importlib.reload(original_module)
            self.assertTrue(reloaded.SCAPY_AVAILABLE)
            self.assertEqual(fake_conf.verb, 0)
        finally:
            sys.modules.pop("scapy.all", None)
            sys.modules.pop("scapy", None)
            importlib.reload(original_module)

    def test_not_available_without_root(self):
        """Should return unavailable when not running as root."""
        with patch("os.geteuid", return_value=1000):
            available, reason = is_syn_scan_available()
            self.assertFalse(available)
            self.assertEqual(reason, "requires_root")

    def test_not_available_without_scapy(self):
        """Should return unavailable when scapy is not installed."""
        with patch("os.geteuid", return_value=0):
            original = syn_mod.SCAPY_AVAILABLE
            syn_mod.SCAPY_AVAILABLE = False
            try:
                available, reason = is_syn_scan_available()
                self.assertFalse(available)
                self.assertEqual(reason, "scapy_not_installed")
            finally:
                syn_mod.SCAPY_AVAILABLE = original

    def test_available_with_root_and_scapy(self):
        """Should return available when running as root and scapy is installed."""
        with patch("os.geteuid", return_value=0):
            original = syn_mod.SCAPY_AVAILABLE
            syn_mod.SCAPY_AVAILABLE = True
            try:
                available, reason = is_syn_scan_available()
                self.assertTrue(available)
                self.assertEqual(reason, "available")
            finally:
                syn_mod.SCAPY_AVAILABLE = original


class TestSynProbe(unittest.TestCase):
    """Tests for syn_probe_single function."""

    def test_probe_returns_false_without_scapy(self):
        """Should return False when scapy is not available."""
        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = False
        try:
            result = syn_probe_single("127.0.0.1", 80)
            self.assertFalse(result)
        finally:
            syn_mod.SCAPY_AVAILABLE = original

    def _setup_scapy_mocks(self):
        """Inject mock scapy symbols into the module."""
        # Create mock scapy functions
        mock_IP = MagicMock()
        mock_TCP = MagicMock()
        mock_sr1 = MagicMock()

        # Inject into module
        syn_mod.IP = mock_IP
        syn_mod.TCP = mock_TCP
        syn_mod.sr1 = mock_sr1

        return mock_IP, mock_TCP, mock_sr1

    def _cleanup_scapy_mocks(self):
        """Remove injected mocks if they exist."""
        for attr in ["IP", "TCP", "sr1"]:
            if hasattr(syn_mod, attr):
                delattr(syn_mod, attr)

    def test_probe_returns_true_on_syn_ack(self):
        """Should return True when SYN-ACK is received (port open)."""
        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = True
        mock_IP, mock_TCP, mock_sr1 = self._setup_scapy_mocks()
        try:
            # Setup response with SYN-ACK
            mock_tcp_layer = MagicMock()
            mock_tcp_layer.flags = 0x12  # SYN-ACK
            mock_tcp_layer.dport = 12345

            mock_response = MagicMock()
            mock_response.getlayer.return_value = mock_tcp_layer

            mock_sr1.return_value = mock_response

            result = syn_probe_single("192.168.1.1", 80, timeout=0.1)
            self.assertTrue(result)
        finally:
            syn_mod.SCAPY_AVAILABLE = original
            self._cleanup_scapy_mocks()

    def test_probe_returns_false_on_timeout(self):
        """Should return False when no response (timeout)."""
        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = True
        mock_IP, mock_TCP, mock_sr1 = self._setup_scapy_mocks()
        try:
            mock_sr1.return_value = None
            result = syn_probe_single("192.168.1.1", 80)
            self.assertFalse(result)
        finally:
            syn_mod.SCAPY_AVAILABLE = original
            self._cleanup_scapy_mocks()

    def test_probe_returns_false_on_rst(self):
        """Should return False when RST is received (port closed)."""
        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = True
        mock_IP, mock_TCP, mock_sr1 = self._setup_scapy_mocks()
        try:
            mock_tcp_layer = MagicMock()
            mock_tcp_layer.flags = 0x14  # RST-ACK (port closed)

            mock_response = MagicMock()
            mock_response.getlayer.return_value = mock_tcp_layer

            mock_sr1.return_value = mock_response
            result = syn_probe_single("192.168.1.1", 80)
            self.assertFalse(result)
        finally:
            syn_mod.SCAPY_AVAILABLE = original
            self._cleanup_scapy_mocks()

    def test_probe_returns_false_on_exception(self):
        """Should return False when an exception occurs."""
        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = True
        mock_IP, mock_TCP, mock_sr1 = self._setup_scapy_mocks()
        try:
            # Make IP() raise an exception
            mock_IP.side_effect = Exception("Network error")
            result = syn_probe_single("192.168.1.1", 80)
            self.assertFalse(result)
        finally:
            syn_mod.SCAPY_AVAILABLE = original
            self._cleanup_scapy_mocks()

    def test_probe_returns_false_when_tcp_layer_none(self):
        """Should return False when TCP layer is not present."""
        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = True
        mock_IP, mock_TCP, mock_sr1 = self._setup_scapy_mocks()
        try:
            mock_response = MagicMock()
            mock_response.getlayer.return_value = None

            mock_sr1.return_value = mock_response
            result = syn_probe_single("192.168.1.1", 80)
            self.assertFalse(result)
        finally:
            syn_mod.SCAPY_AVAILABLE = original
            self._cleanup_scapy_mocks()


class TestSynSweepBatch(unittest.TestCase):
    """Tests for syn_sweep_batch async function."""

    def test_returns_empty_without_scapy(self):
        """Should return empty dict when scapy is not available."""
        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = False
        try:
            logger = MagicMock()
            result = asyncio.run(syn_sweep_batch(["192.168.1.1"], [80, 443], logger=logger))
            self.assertEqual(result, {})
            logger.warning.assert_called_once()
        finally:
            syn_mod.SCAPY_AVAILABLE = original

    def test_sweep_finds_open_ports(self):
        """Should return open ports when probes succeed."""
        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = True
        try:
            # Mock syn_probe_single to return True for port 80, False for others
            def mock_probe(ip, port, timeout=0.3):
                return port == 80

            with patch.object(syn_mod, "syn_probe_single", side_effect=mock_probe):
                logger = MagicMock()
                result = asyncio.run(
                    syn_sweep_batch(
                        ["192.168.1.1"],
                        [22, 80, 443],
                        batch_size=10,
                        timeout=0.1,
                        logger=logger,
                    )
                )
                self.assertIn("192.168.1.1", result)
                self.assertIn(80, result["192.168.1.1"])
                self.assertNotIn(22, result["192.168.1.1"])
        finally:
            syn_mod.SCAPY_AVAILABLE = original

    def test_sweep_multiple_targets(self):
        """Should scan multiple targets correctly."""
        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = True
        try:
            # Port 22 open on first host, port 80 on second
            def mock_probe(ip, port, timeout=0.3):
                if ip == "192.168.1.1" and port == 22:
                    return True
                if ip == "192.168.1.2" and port == 80:
                    return True
                return False

            with patch.object(syn_mod, "syn_probe_single", side_effect=mock_probe):
                result = asyncio.run(
                    syn_sweep_batch(
                        ["192.168.1.1", "192.168.1.2"],
                        [22, 80],
                        batch_size=10,
                        timeout=0.1,
                    )
                )
                self.assertIn("192.168.1.1", result)
                self.assertIn(22, result["192.168.1.1"])
                self.assertIn("192.168.1.2", result)
                self.assertIn(80, result["192.168.1.2"])
        finally:
            syn_mod.SCAPY_AVAILABLE = original

    def test_sweep_timeout_per_host(self):
        """Should respect max_time_per_host timeout."""
        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = True
        try:
            # Simulate slow probes that exceed timeout
            async def slow_sleep(*args, **kwargs):
                await asyncio.sleep(0.5)
                return False

            with patch("asyncio.to_thread", side_effect=slow_sleep):
                logger = MagicMock()
                result = asyncio.run(
                    syn_sweep_batch(
                        ["192.168.1.1"],
                        [80, 443, 8080],
                        batch_size=1,
                        timeout=0.1,
                        logger=logger,
                        max_time_per_host=0.1,  # Very short timeout
                    )
                )
                # Should have timed out and logged warning
                self.assertEqual(result, {})
        finally:
            syn_mod.SCAPY_AVAILABLE = original

    def test_sweep_timeout_before_batch_skips_probes(self):
        """Should skip probes when remaining time is exhausted."""
        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = True
        try:
            logger = MagicMock()
            with (
                patch.object(syn_mod, "syn_probe_single") as probe,
                patch("redaudit.core.syn_scanner.time.time", return_value=0),
            ):
                result = asyncio.run(
                    syn_sweep_batch(
                        ["192.168.1.1"],
                        [80],
                        batch_size=10,
                        timeout=0.1,
                        logger=logger,
                        max_time_per_host=0,
                    )
                )
            self.assertEqual(result, {})
            probe.assert_not_called()
            self.assertTrue(logger.warning.called)
            self.assertIn("timeout reached", logger.warning.call_args_list[0][0][0])
        finally:
            syn_mod.SCAPY_AVAILABLE = original

    def test_sweep_filters_empty_results(self):
        """Should not include hosts with no open ports."""
        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = True
        try:
            # All ports closed
            with patch.object(syn_mod, "syn_probe_single", return_value=False):
                result = asyncio.run(syn_sweep_batch(["192.168.1.1"], [80, 443], timeout=0.1))
                self.assertEqual(result, {})
        finally:
            syn_mod.SCAPY_AVAILABLE = original

    def test_sweep_logs_completion(self):
        """Should log completion message with stats."""
        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = True
        try:
            with patch.object(syn_mod, "syn_probe_single", return_value=True):
                logger = MagicMock()
                asyncio.run(
                    syn_sweep_batch(
                        ["192.168.1.1"],
                        [80],
                        logger=logger,
                        timeout=0.1,
                    )
                )
                # Should have logged info messages
                self.assertTrue(logger.info.called)
        finally:
            syn_mod.SCAPY_AVAILABLE = original


class TestSynSweepSync(unittest.TestCase):
    """Tests for syn_sweep_sync synchronous wrapper."""

    def test_sync_wrapper_calls_async(self):
        """Should call the async version and return results."""
        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = True
        try:
            with patch.object(syn_mod, "syn_probe_single", return_value=True):
                result = syn_sweep_sync(
                    ["192.168.1.1"],
                    [80],
                    batch_size=10,
                    timeout=0.1,
                )
                self.assertIn("192.168.1.1", result)
                self.assertIn(80, result["192.168.1.1"])
        finally:
            syn_mod.SCAPY_AVAILABLE = original

    def test_sync_wrapper_empty_without_scapy(self):
        """Should return empty when scapy unavailable."""
        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = False
        try:
            result = syn_sweep_sync(["192.168.1.1"], [80])
            self.assertEqual(result, {})
        finally:
            syn_mod.SCAPY_AVAILABLE = original


if __name__ == "__main__":
    unittest.main()
