#!/usr/bin/env python3
"""
Tests for SYN scanner module.

v4.3: Tests for is_syn_scan_available and syn_probe functions.
"""

import unittest
from unittest.mock import patch

from redaudit.core.syn_scanner import is_syn_scan_available


class TestSynScanAvailability(unittest.TestCase):
    """Tests for is_syn_scan_available function."""

    def test_not_available_without_root(self):
        """Should return unavailable when not running as root."""
        with patch("os.geteuid", return_value=1000):
            available, reason = is_syn_scan_available()
            self.assertFalse(available)
            self.assertEqual(reason, "requires_root")

    def test_not_available_without_scapy(self):
        """Should return unavailable when scapy is not installed."""
        with patch("os.geteuid", return_value=0):
            import redaudit.core.syn_scanner as syn_mod

            # Temporarily override SCAPY_AVAILABLE
            original = syn_mod.SCAPY_AVAILABLE
            syn_mod.SCAPY_AVAILABLE = False
            try:
                available, reason = is_syn_scan_available()
                if available:
                    # If scapy is actually available, skip this test
                    self.skipTest("scapy is installed")
                else:
                    self.assertEqual(reason, "scapy_not_installed")
            finally:
                syn_mod.SCAPY_AVAILABLE = original


class TestSynProbe(unittest.TestCase):
    """Tests for syn_probe_single function."""

    def test_probe_returns_false_without_scapy(self):
        """Should return False when scapy is not available."""
        import redaudit.core.syn_scanner as syn_mod

        original = syn_mod.SCAPY_AVAILABLE
        syn_mod.SCAPY_AVAILABLE = False
        try:
            result = syn_mod.syn_probe_single("127.0.0.1", 80)
            self.assertFalse(result)
        finally:
            syn_mod.SCAPY_AVAILABLE = original


if __name__ == "__main__":
    unittest.main()
