import unittest
from unittest.mock import MagicMock, patch
from redaudit.core.auditor_scan import AuditorScan


class MockAuditor(AuditorScan):
    """Mock class that mimics AuditorRuntime mixed with Wizard."""

    def __init__(self):
        self.ui = MagicMock()
        # Mock ui.colors dict
        self.ui.colors = {"HEADER": "", "ENDC": "", "OKGREEN": ""}
        self.ui.t.side_effect = lambda k, *a: k  # Simple identity translation

        self.scanner = MagicMock()
        self.logger = MagicMock()
        self.config = {}
        self.results = {}

        # Mock Wizard methods
        self.ask_yes_no = MagicMock()
        self.ask_choice = MagicMock()
        self.ask_manual_network = MagicMock()


class TestAuditorScanHiddenNets(unittest.TestCase):

    @patch("redaudit.core.net_discovery.detect_routed_networks")
    def test_ask_network_range_with_hidden_accepted(self, mock_detect):
        """Test accepting hidden networks adds them to scope."""
        auditor = MockAuditor()

        # 1. Setup Local Networks
        local_nets = [{"interface": "eth0", "network": "192.168.1.0/24", "hosts_estimated": 254}]
        auditor.scanner.detect_local_networks.return_value = local_nets

        # 2. Setup Routed Networks (one local, one hidden)
        mock_detect.return_value = {"networks": ["192.168.1.0/24", "10.0.100.0/24"], "gateways": []}

        # 3. User Interactions
        # ask_yes_no -> True (Add hidden nets)
        auditor.ask_yes_no.return_value = True

        # ask_choice -> 0 (Select eth0)
        # Options will be: [eth0, Manual, All]
        # index 0 is valid.
        auditor.ask_choice.return_value = 0

        # Execute
        result = auditor.ask_network_range()

        # Verify result contains BOTH local selection AND hidden net
        self.assertIn("192.168.1.0/24", result)
        self.assertIn("10.0.100.0/24", result)
        self.assertEqual(len(result), 2)

        # Verify prompt was shown
        auditor.ui.print_status.assert_called()
        args, _ = auditor.ui.print_status.call_args
        self.assertIn("net_discovery_routed_found", args[0])

    @patch("redaudit.core.net_discovery.detect_routed_networks")
    def test_ask_network_range_with_hidden_rejected(self, mock_detect):
        """Test rejecting hidden networks excludes them."""
        auditor = MockAuditor()

        # Should be same setup but user says No
        auditor.scanner.detect_local_networks.return_value = [
            {"interface": "eth0", "network": "192.168.1.0/24", "hosts_estimated": 254}
        ]
        mock_detect.return_value = {"networks": ["192.168.1.0/24", "10.0.100.0/24"], "gateways": []}

        auditor.ask_yes_no.return_value = False  # Reject
        auditor.ask_choice.return_value = 0

        result = auditor.ask_network_range()

        self.assertEqual(result, ["192.168.1.0/24"])

    @patch("redaudit.core.net_discovery.detect_routed_networks")
    def test_ask_network_range_no_hidden(self, mock_detect):
        """Test no hidden networks found (overlap only)."""
        auditor = MockAuditor()

        auditor.scanner.detect_local_networks.return_value = [
            {"interface": "eth0", "network": "192.168.1.0/24", "hosts_estimated": 254}
        ]
        # Only local net routed
        mock_detect.return_value = {"networks": ["192.168.1.0/24"], "gateways": []}

        auditor.ask_choice.return_value = 0

        result = auditor.ask_network_range()

        # Prompt should NOT be called
        # We need to distinguish this print_status from others.
        # But specifically the one with "net_discovery_routed_found".

        # Check printed messages
        # auditor.ui.print_status mocks simply record calls.
        # We check if any call arg matches.
        for call in auditor.ui.print_status.call_args_list:
            args, _ = call
            if "net_discovery_routed_found" in str(args[0]):
                self.fail("Prompt for hidden networks should not appear when no hidden nets exist")

        self.assertEqual(result, ["192.168.1.0/24"])
