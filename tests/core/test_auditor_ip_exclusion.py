#!/usr/bin/env python3
"""
Tests for Auditor IP Exclusion logic in InteractiveNetworkAuditor.
"""
import unittest
from unittest.mock import MagicMock, patch
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

    def test_filter_auditor_ips_fallback_detect_all_networks(self):
        """Fallback detection should exclude auditor IPs when primary sources are empty."""
        auditor = InteractiveNetworkAuditor()
        auditor.ui = MagicMock()
        auditor.logger = MagicMock()
        auditor.results["network_info"] = []
        auditor.results["topology"] = {}

        hosts = ["192.168.1.10", "192.168.1.50"]
        fallback_nets = [{"ip": "192.168.1.50", "interface": "eth0"}]
        with patch("redaudit.core.auditor.detect_all_networks", return_value=fallback_nets):
            filtered = auditor._filter_auditor_ips(hosts)

        self.assertNotIn("192.168.1.50", filtered)
        self.assertIn("192.168.1.10", filtered)

    def test_filter_auditor_ips_uses_topology_src(self):
        """Topology src/interface IPs should be excluded when present."""
        auditor = InteractiveNetworkAuditor()
        auditor.ui = MagicMock()
        auditor.logger = MagicMock()
        auditor.results["network_info"] = [{"ip": "10.0.0.5"}]
        auditor.results["topology"] = {
            "routes": [{"src": "172.20.0.1"}],
            "interfaces": [{"ip": "172.20.0.2"}],
        }

        hosts = ["172.20.0.1", "172.20.0.2", "172.20.0.3", "10.0.0.5"]
        filtered = auditor._filter_auditor_ips(hosts)

        self.assertNotIn("172.20.0.1", filtered)
        self.assertNotIn("172.20.0.2", filtered)
        self.assertNotIn("10.0.0.5", filtered)
        self.assertIn("172.20.0.3", filtered)

    def test_filter_auditor_ips_empty_auditor_ips_sets_exclusions(self):
        """Test that empty auditor_ips sets exclusions count to 0 (lines 485-487)."""
        auditor = InteractiveNetworkAuditor()
        auditor.ui = MagicMock()
        auditor.logger = MagicMock()
        auditor.results["network_info"] = []
        auditor.results["topology"] = {}

        # Patch detect_all_networks to return empty list
        with patch("redaudit.core.auditor.detect_all_networks", return_value=[]):
            # Also patch socket to not return anything useful
            with patch("socket.socket") as mock_socket:
                mock_sock = MagicMock()
                mock_sock.getsockname.return_value = ("127.0.0.1", 80)  # localhost ignored
                mock_socket.return_value = mock_sock
                filtered = auditor._filter_auditor_ips(["192.168.1.10"])

        self.assertEqual(filtered, ["192.168.1.10"])
        self.assertEqual(auditor.results["auditor_exclusions"]["count"], 0)
        self.assertEqual(auditor.results["auditor_exclusions"]["items"], [])

    def test_collect_auditor_ip_reasons_socket_exception_handled(self):
        """Test that socket exceptions in fallback are handled (lines 467-474)."""
        auditor = InteractiveNetworkAuditor()
        auditor.logger = MagicMock()
        auditor.results["network_info"] = []
        auditor.results["topology"] = {}

        # Patch detect_all_networks to return empty
        with patch("redaudit.core.auditor.detect_all_networks", return_value=[]):
            # Also patch hostname resolution to return nothing useful
            with patch("socket.gethostbyname_ex", side_effect=OSError("no hostname")):
                # Patch socket to raise exception on connect
                with patch("socket.socket") as mock_socket:
                    mock_sock = MagicMock()
                    mock_sock.connect.side_effect = OSError("network unreachable")
                    mock_socket.return_value = mock_sock
                    reasons = auditor._collect_auditor_ip_reasons()

        # Should return empty dict without raising
        self.assertEqual(reasons, {})
        # Socket close should still be called despite exception
        mock_sock.close.assert_called()

    def test_collect_auditor_ip_reasons_socket_close_exception_handled(self):
        """Test that socket.close() exceptions are handled (lines 471-474)."""
        auditor = InteractiveNetworkAuditor()
        auditor.logger = MagicMock()
        auditor.results["network_info"] = []
        auditor.results["topology"] = {}

        with patch("redaudit.core.auditor.detect_all_networks", return_value=[]):
            # Also patch hostname resolution to return nothing useful
            with patch("socket.gethostbyname_ex", side_effect=OSError("no hostname")):
                with patch("socket.socket") as mock_socket:
                    mock_sock = MagicMock()
                    mock_sock.getsockname.return_value = ("10.0.0.5", 80)
                    mock_sock.close.side_effect = OSError("close failed")
                    mock_socket.return_value = mock_sock
                    reasons = auditor._collect_auditor_ip_reasons()

        # Should still have collected the IP despite close exception
        self.assertIn("10.0.0.5", reasons)
