"""Tests to increase coverage for auditor_scan.py"""

import unittest
from unittest.mock import Mock, patch


class TestAuditorScanCoverageV2(unittest.TestCase):
    """Additional tests for auditor_scan.py coverage."""

    def _make_auditor(self):
        """Create a mock auditor with necessary attributes."""
        auditor = Mock()
        auditor.config = {
            "scan_mode": "normal",
            "threads": 4,
            "dry_run": False,
            "target_networks": ["192.168.1.0/24"],
            "net_discovery_interface": None,
        }
        auditor.results = {"network_info": []}
        auditor.extra_tools = {"dig": None, "nmcli": None}
        auditor.logger = None
        auditor.rate_limit_delay = 0.0
        auditor.interrupted = False
        auditor.t = lambda k, *a: k
        auditor.print_status = Mock()
        return auditor

    # -- _select_net_discovery_interface tests --

    def test_select_interface_invalid_network_token(self):
        """Test with invalid network token in targets."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        auditor.config["target_networks"] = ["not_a_valid_cidr"]
        auditor.results["network_info"] = [{"interface": "eth0", "network": "192.168.1.0/24"}]

        result = AuditorScanMixin._select_net_discovery_interface(auditor)
        self.assertEqual(result, "eth0")

    def test_select_interface_missing_keys(self):
        """Test when interface or network is missing."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        auditor.config["target_networks"] = ["192.168.1.0/24"]
        auditor.results["network_info"] = [
            {"interface": "eth0"},
            {"network": "10.0.0.0/8"},
            {"interface": "eth1", "network": "192.168.1.0/24"},
        ]

        result = AuditorScanMixin._select_net_discovery_interface(auditor)
        self.assertEqual(result, "eth1")

    def test_select_interface_version_mismatch(self):
        """Test with IPv4/IPv6 version mismatch."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        auditor.config["target_networks"] = ["192.168.1.0/24"]
        auditor.results["network_info"] = [
            {"interface": "eth0", "network": "fe80::/10"},
            {"interface": "eth1", "network": "192.168.1.0/24"},
        ]

        result = AuditorScanMixin._select_net_discovery_interface(auditor)
        self.assertEqual(result, "eth1")

    def test_select_interface_invalid_network_string(self):
        """Test with invalid network string in available networks."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        auditor.config["target_networks"] = ["192.168.1.0/24"]
        auditor.results["network_info"] = [
            {"interface": "eth0", "network": "not_valid_cidr"},
            {"interface": "eth1", "network": "192.168.1.0/24"},
        ]

        result = AuditorScanMixin._select_net_discovery_interface(auditor)
        self.assertEqual(result, "eth1")

    def test_select_interface_explicit_config(self):
        """Test explicit interface configuration is respected."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        auditor.config["net_discovery_interface"] = "wlan0"

        result = AuditorScanMixin._select_net_discovery_interface(auditor)
        self.assertEqual(result, "wlan0")

    # -- _run_low_impact_enrichment tests --

    def test_enrichment_invalid_ip(self):
        """Test with invalid IP returns empty signals."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()

        with patch("redaudit.core.auditor_scan.sanitize_ip", return_value=None):
            result = AuditorScanMixin._run_low_impact_enrichment(auditor, "invalid")
            self.assertEqual(result, {})

    def test_enrichment_dry_run(self):
        """Test in dry_run mode returns empty signals."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        auditor.config["dry_run"] = True

        with patch("redaudit.core.auditor_scan.sanitize_ip", return_value="192.168.1.1"):
            with patch("redaudit.core.auditor_scan.is_dry_run", return_value=True):
                result = AuditorScanMixin._run_low_impact_enrichment(auditor, "192.168.1.1")
                self.assertEqual(result, {})

    def test_enrichment_with_dig(self):
        """Test using dig for DNS lookup."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        auditor.extra_tools["dig"] = "/usr/bin/dig"

        mock_result = Mock()
        mock_result.stdout = "myhost.local.\n"
        mock_result.returncode = 0

        with patch("redaudit.core.auditor_scan.sanitize_ip", return_value="192.168.1.1"):
            with patch("redaudit.core.auditor_scan.is_dry_run", return_value=False):
                with patch("redaudit.core.auditor_scan.CommandRunner") as MockRunner:
                    mock_instance = Mock()
                    mock_instance.run.return_value = mock_result
                    MockRunner.return_value = mock_instance

                    result = AuditorScanMixin._run_low_impact_enrichment(auditor, "192.168.1.1")
                    self.assertIn("dns_reverse", result)
                    self.assertEqual(result["dns_reverse"], "myhost.local")

    def test_enrichment_socket_fallback(self):
        """Test using socket when dig unavailable."""
        from redaudit.core.auditor_scan import AuditorScanMixin

        auditor = self._make_auditor()
        auditor.extra_tools["dig"] = None

        with patch("redaudit.core.auditor_scan.sanitize_ip", return_value="192.168.1.1"):
            with patch("redaudit.core.auditor_scan.is_dry_run", return_value=False):
                with patch(
                    "socket.gethostbyaddr",
                    return_value=("router.local", [], ["192.168.1.1"]),
                ):
                    result = AuditorScanMixin._run_low_impact_enrichment(auditor, "192.168.1.1")
                    self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()
