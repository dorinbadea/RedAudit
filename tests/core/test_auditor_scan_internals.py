import unittest
from unittest.mock import MagicMock, patch, call
from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.core.models import Host, Service


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestAuditorScanInternals(unittest.TestCase):
    def setUp(self):
        import redaudit.core.auditor

        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.logger = MagicMock()
        self.auditor.config = {
            "target_networks": [],
            "scan_mode": "normal",
        }
        self.auditor.results = {"net_discovery": {}, "network_info": []}

    def test_collect_discovery_hosts(self, *args):
        """Test _collect_discovery_hosts logic."""
        # Configure mock return
        self.mock_runtime_cls.return_value._collect_discovery_hosts.return_value = [
            "192.168.1.10",
            "192.168.1.11",
            "192.168.1.12",
        ]

        # Test delegation
        hosts = self.auditor._collect_discovery_hosts(["192.168.1.0/24"])

        self.assertIn("192.168.1.10", hosts)
        self.mock_runtime_cls.return_value._collect_discovery_hosts.assert_called_with(
            ["192.168.1.0/24"]
        )

    def test_scan_network_discovery(
        self, mock_scan_wizard, mock_iot, mock_scanner, mock_activity, mock_sleep
    ):
        """Test scan_network_discovery delegation."""
        # Configure mock return
        self.mock_runtime_cls.return_value.scan_network_discovery.return_value = ["192.168.1.50"]

        hosts = self.auditor.scan_network_discovery("192.168.1.0/24")

        self.assertEqual(hosts, ["192.168.1.50"])
        self.mock_runtime_cls.return_value.scan_network_discovery.assert_called_with(
            "192.168.1.0/24"
        )

    def test_scan_hosts_concurrent(self, mock_scan_wizard, *args):
        """Test scan_hosts_concurrent delegation."""
        targets = [MagicMock(spec=Host)]
        self.mock_runtime_cls.return_value.scan_hosts_concurrent.return_value = []

        res = self.auditor.scan_hosts_concurrent(targets)

        self.assertEqual(res, [])
        self.mock_runtime_cls.return_value.scan_hosts_concurrent.assert_called_with(targets)

    def test_run_deep_scans_concurrent(self, mock_scan_wizard, *args):
        """Test deep scan delegation."""
        targets = [MagicMock(spec=Host)]
        self.auditor.run_deep_scans_concurrent(targets)
        self.mock_runtime_cls.return_value.run_deep_scans_concurrent.assert_called_with(targets)

    def test_run_agentless_verification(self, mock_scan_wizard, *args):
        """Test agentless verification delegation."""
        targets = []
        self.auditor.run_agentless_verification(targets)
        self.mock_runtime_cls.return_value.run_agentless_verification.assert_called_with(targets)

    def test_scan_vulnerabilities_concurrent(self, mock_scan_wizard, *args):
        """Test vuln scan delegation."""
        targets = []
        self.auditor.scan_vulnerabilities_concurrent(targets)
        self.mock_runtime_cls.return_value.scan_vulnerabilities_concurrent.assert_called_with(
            targets
        )
