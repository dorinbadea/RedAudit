#!/usr/bin/env python3
"""
RedAudit - Integration Tests
Basic integration tests for core functionality.
"""

import sys
import os
import unittest
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit import InteractiveNetworkAuditor
from redaudit.utils.constants import VERSION, MAX_INPUT_LENGTH, MAX_CIDR_LENGTH


class TestIntegration(unittest.TestCase):
    """Integration tests for RedAudit."""

    def setUp(self):
        """Set up test fixtures."""
        self.app = InteractiveNetworkAuditor()

    def test_version(self):
        """Test that version is set."""
        self.assertEqual(VERSION, "3.5.1")

    def test_constants(self):
        """Test security constants."""
        self.assertGreater(MAX_INPUT_LENGTH, 0)
        self.assertGreater(MAX_CIDR_LENGTH, 0)
        self.assertEqual(MAX_INPUT_LENGTH, 1024)
        self.assertEqual(MAX_CIDR_LENGTH, 50)

    def test_initialization(self):
        """Test application initialization."""
        self.assertIsNotNone(self.app.results)
        self.assertIsNotNone(self.app.config)
        self.assertFalse(self.app.encryption_enabled)
        self.assertEqual(self.app.config["threads"], 6)

    def test_sanitize_ip_with_length(self):
        """Test IP sanitization with length validation."""
        # Valid IP
        result = self.app.sanitize_ip("192.168.1.1")
        self.assertEqual(result, "192.168.1.1")

        # Too long
        long_ip = "192.168.1." + "1" * 1000
        result = self.app.sanitize_ip(long_ip)
        self.assertIsNone(result)

        # Invalid type
        result = self.app.sanitize_ip(12345)
        self.assertIsNone(result)

        # None
        result = self.app.sanitize_ip(None)
        self.assertIsNone(result)

    def test_sanitize_hostname_with_length(self):
        """Test hostname sanitization with length validation."""
        # Valid hostname
        result = self.app.sanitize_hostname("example.com")
        self.assertEqual(result, "example.com")

        # Too long
        long_hostname = "a" * 2000
        result = self.app.sanitize_hostname(long_hostname)
        self.assertIsNone(result)

        # Invalid type
        result = self.app.sanitize_hostname(["list"])
        self.assertIsNone(result)

    def test_cidr_validation(self):
        """Test CIDR validation with length check."""
        # This would be called in ask_manual_network, but we test the logic
        valid_cidr = "192.168.1.0/24"
        try:
            import ipaddress

            ipaddress.ip_network(valid_cidr, strict=False)
            self.assertTrue(len(valid_cidr) <= MAX_CIDR_LENGTH)
        except ValueError:
            self.fail("Valid CIDR should not raise ValueError")

        # Too long
        long_cidr = "192.168.1." + "0/24" + "x" * 100
        self.assertGreater(len(long_cidr), MAX_CIDR_LENGTH)

    @patch("redaudit.core.auditor.shutil.which")
    def test_check_dependencies(self, mock_which):
        """Test dependency checking."""
        mock_which.return_value = "/usr/bin/nmap"

        with patch("redaudit.core.auditor.importlib.import_module") as mock_import:
            mock_import.return_value = MagicMock()
            result = self.app.check_dependencies()
            # Should return True if nmap is found
            # (actual result depends on cryptography availability)
            self.assertIsInstance(result, bool)

    def test_translations(self):
        """Test translation system."""
        # English
        self.app.lang = "en"
        result = self.app.t("nmap_avail")
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

        # Spanish
        self.app.lang = "es"
        result = self.app.t("nmap_avail")
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

        # Invalid key
        result = self.app.t("nonexistent_key")
        self.assertEqual(result, "nonexistent_key")

    def test_config_defaults(self):
        """Test default configuration values."""
        self.assertEqual(self.app.config["scan_mode"], "normal")
        self.assertEqual(self.app.config["threads"], 6)
        self.assertEqual(self.app.config["scan_vulnerabilities"], True)
        self.assertEqual(self.app.config["save_txt_report"], True)
        self.assertIsNone(self.app.config["encryption_salt"])

    def test_results_structure(self):
        """Test results structure initialization."""
        self.assertIn("timestamp", self.app.results)
        self.assertIn("version", self.app.results)
        self.assertIn("network_info", self.app.results)
        self.assertIn("hosts", self.app.results)
        self.assertIn("vulnerabilities", self.app.results)
        self.assertIn("summary", self.app.results)
        self.assertEqual(self.app.results["version"], VERSION)


if __name__ == "__main__":
    unittest.main()
