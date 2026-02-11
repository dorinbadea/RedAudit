import unittest
from unittest.mock import MagicMock, patch
from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.core.network_scanner import NetworkScanner


# Minimal patch for Auditor to instantiate without running things
@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.AuditorRuntime")
class TestAuditorFilterIPs(unittest.TestCase):
    def setUp(self):
        self.auditor = InteractiveNetworkAuditor()
        # Mock config as dict for easy setup
        self.auditor.config = {
            "target_networks": [],
            "scan_mode": "normal",
            "_actual_output_dir": "/tmp/out",
        }
        self.auditor.ui = MagicMock()
        self.auditor.logger = MagicMock()

    def test_collect_auditor_ip_reasons_basic(self, *args):
        """Test basic IP collection from system interfaces."""
        # Mock detect_all_networks
        with patch("redaudit.core.auditor.detect_all_networks") as mock_detect:
            mock_detect.return_value = [
                {"ip": "192.168.1.5", "interface": "en0", "netmask": "255.255.255.0"}
            ]

            reasons = self.auditor._collect_auditor_ip_reasons()

            self.assertIn("192.168.1.5", reasons)
            # Value is a SET of strings
            self.assertIn("fallback.network_info:en0", reasons["192.168.1.5"])

    def test_collect_auditor_ip_reasons_with_topology(self, *args):
        """Test IP collection including topology routes."""
        self.auditor.config["topology_enabled"] = True

        with patch("redaudit.core.auditor.detect_all_networks") as mock_detect:
            mock_detect.return_value = []

            self.auditor.results["topology"] = {"routes": [{"src": "10.0.0.1", "dst": "10.0.0.2"}]}

            reasons = self.auditor._collect_auditor_ip_reasons()

            self.assertIn("10.0.0.1", reasons)
            self.assertIn("topology.route_src", reasons["10.0.0.1"])

    def test_filter_auditor_ips_removal(self, *args):
        """Test filtering removes auditor IPs (inputs are IP strings)."""
        hosts = ["192.168.1.5", "192.168.1.10"]

        # Mock _collect_auditor_ip_reasons to return dict with IP keys
        self.auditor._collect_auditor_ip_reasons = MagicMock(
            return_value={"192.168.1.5": {"Local Interface"}}
        )

        filtered = self.auditor._filter_auditor_ips(hosts)

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0], "192.168.1.10")

        # Verify UI call
        self.auditor.ui.print_status.assert_called()
        # It logs "Excluding auditor IP..."

    def test_filter_auditor_ips_no_removal(self, *args):
        """Test filtering keeps all if no auditor IPs match."""
        hosts = ["192.168.1.10", "192.168.1.11"]

        self.auditor._collect_auditor_ip_reasons = MagicMock(
            return_value={"192.168.1.5": {"Local Interface"}}
        )

        filtered = self.auditor._filter_auditor_ips(hosts)

        self.assertEqual(len(filtered), 2)
