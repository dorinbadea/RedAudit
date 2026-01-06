#!/usr/bin/env python3
"""
Tests for Auditor IP Exclusion logic in InteractiveNetworkAuditor.
"""
import unittest
from unittest.mock import MagicMock
from redaudit.core.auditor import InteractiveNetworkAuditor


class TestAuditorIpExclusion(unittest.TestCase):
    def test_filter_auditor_ips_removes_own_ip(self):
        """Test that IPs found in network_info are removed from target list."""
        auditor = InteractiveNetworkAuditor()
        auditor.ui = MagicMock()
        # Mock logger to avoid errors if logic uses it (handled by hasattr check but good to have)
        auditor.logger = MagicMock()

        # Setup: Auditor has IP '192.168.1.50'
        auditor.results["network_info"] = [
            {"ip": "192.168.1.50", "interface": "eth0"},
            {"ip": "10.0.0.1", "interface": "tun0"},
        ]

        # Scenario: Discovery found 3 hosts, including the auditor itself
        discovered_hosts = ["192.168.1.10", "192.168.1.50", "192.168.1.254"]

        filtered = auditor._filter_auditor_ips(discovered_hosts)

        # Assertions
        self.assertNotIn("192.168.1.50", filtered)
        self.assertIn("192.168.1.10", filtered)
        self.assertIn("192.168.1.254", filtered)
        self.assertEqual(len(filtered), 2)

        # Verify UI notification
        auditor.ui.print_status.assert_called()
        # Verify translation was requested with correct key
        auditor.ui.t.assert_called_with("auditor_ip_excluded", 1)

    def test_filter_auditor_ips_no_match(self):
        """Test that list remains unchanged if auditor IP is not in targets."""
        auditor = InteractiveNetworkAuditor()
        auditor.ui = MagicMock()
        auditor.results["network_info"] = [{"ip": "1.2.3.4"}]

        hosts = ["192.168.1.10", "192.168.1.11"]
        filtered = auditor._filter_auditor_ips(hosts)

        self.assertEqual(filtered, hosts)
        auditor.ui.print_status.assert_not_called()

    def test_filter_auditor_ips_empty_network_info(self):
        """Test behavior when network_info is missing."""
        auditor = InteractiveNetworkAuditor()
        auditor.results["network_info"] = []

        hosts = ["192.168.1.10"]
        filtered = auditor._filter_auditor_ips(hosts)

        self.assertEqual(filtered, hosts)
