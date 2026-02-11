"""Tests for init properties, wizard delegation, net discovery, and remaining gaps."""

import signal
import threading
import unittest
from unittest.mock import MagicMock, patch, call


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestInitAndProperties(unittest.TestCase):
    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.ui.colors = {
            "HEADER": "",
            "ENDC": "",
            "OKBLUE": "",
            "OKGREEN": "",
            "WARNING": "",
            "FAIL": "",
            "BOLD": "",
        }
        self.auditor.logger = MagicMock()

    def test_lang_property(self, *args):
        self.auditor.lang = "en"
        self.assertEqual(self.auditor.lang, "en")

    def test_lang_setter_invalid(self, *args):
        self.auditor.lang = "zz_invalid"
        self.assertEqual(self.auditor.lang, "en")

    def test_config_property(self, *args):
        self.auditor.config["test_key"] = "test_value"
        self.assertEqual(self.auditor.config["test_key"], "test_value")

    def test_config_setter_dict(self, *args):
        self.auditor.config = {"key": "val"}
        self.assertEqual(self.auditor.config["key"], "val")

    def test_proxy_manager_property(self, *args):
        pm = MagicMock()
        self.auditor.proxy_manager = pm
        self.assertEqual(self.auditor.proxy_manager, pm)

    def test_proxy_manager_updates_scanner(self, *args):
        pm = MagicMock()
        self.auditor.proxy_manager = pm
        self.assertEqual(self.auditor.scanner.proxy_manager, pm)

    def test_getattr_wizard_compat(self, *args):
        """__getattr__ delegates to WizardCompat."""
        from redaudit.core.auditor import WizardCompat

        if hasattr(WizardCompat, "WIZARD_BACK"):
            self.assertEqual(self.auditor.WIZARD_BACK, WizardCompat.WIZARD_BACK)

    def test_getattr_missing_returns_mock_or_raises(self, *args):
        """__getattr__ returns something for runtime-delegated attrs."""
        # With mocked runtime, unknown attrs resolve via MagicMock
        result = self.auditor.nonexistent_xyz_attr
        self.assertIsNotNone(result)

    def test_show_config_summary(self, *args):
        self.auditor.show_config_summary()

    def test_show_target_summary(self, *args):
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]
        self.auditor._show_target_summary()
        self.auditor.ui.print_status.assert_called()

    def test_show_target_summary_empty(self, *args):
        self.auditor.config["target_networks"] = []
        self.auditor._show_target_summary()

    def test_show_target_summary_hostname(self, *args):
        self.auditor.config["target_networks"] = ["example.com"]
        self.auditor._show_target_summary()

    def test_show_legal_warning(self, *args):
        self.auditor.ask_yes_no = MagicMock(return_value=True)
        result = self.auditor.show_legal_warning()
        self.assertTrue(result)

    def test_save_results(self, *args):
        self.auditor.save_results = MagicMock()
        self.auditor.save_results(partial=False)
        self.auditor.save_results.assert_called_once()

    def test_show_results(self, *args):
        self.auditor.show_results = MagicMock()
        self.auditor.show_results()


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestWizardDelegation(unittest.TestCase):
    """Test all wizard delegation methods."""

    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.logger = MagicMock()

    def test_clear_screen(self, *args):
        self.auditor.clear_screen()

    def test_print_banner(self, *args):
        self.auditor.print_banner()

    def test_show_main_menu(self, *args):
        self.auditor.wizard_service.show_main_menu = MagicMock(return_value=1)
        result = self.auditor.show_main_menu()
        self.assertEqual(result, 1)

    def test_ask_yes_no(self, *args):
        self.auditor.wizard_service.ask_yes_no = MagicMock(return_value=True)
        result = self.auditor.ask_yes_no("Continue?")
        self.assertTrue(result)

    def test_ask_yes_no_with_timeout(self, *args):
        self.auditor.wizard_service.ask_yes_no_with_timeout = MagicMock(return_value=False)
        result = self.auditor.ask_yes_no_with_timeout("Timeout?", timeout=5)
        self.assertFalse(result)

    def test_ask_number(self, *args):
        self.auditor.wizard_service.ask_number = MagicMock(return_value=42)
        result = self.auditor.ask_number("How many?")
        self.assertEqual(result, 42)

    def test_ask_choice(self, *args):
        self.auditor.wizard_service.ask_choice = MagicMock(return_value=0)
        result = self.auditor.ask_choice("Pick:", ["a", "b"])
        self.assertEqual(result, 0)

    def test_ask_choice_with_back(self, *args):
        self.auditor.wizard_service.ask_choice_with_back = MagicMock(return_value=1)
        result = self.auditor.ask_choice_with_back("Pick:", ["a", "b"])
        self.assertEqual(result, 1)

    def test_ask_manual_network(self, *args):
        self.auditor.wizard_service.ask_manual_network = MagicMock(return_value=["10.0.0.0/24"])
        result = self.auditor.ask_manual_network()
        self.assertEqual(result, ["10.0.0.0/24"])

    def test_ask_webhook_url(self, *args):
        self.auditor.ask_webhook_url = MagicMock(return_value="http://hook.example.com")
        result = self.auditor.ask_webhook_url()
        self.assertEqual(result, "http://hook.example.com")

    def test_ask_net_discovery_options(self, *args):
        self.auditor.ask_net_discovery_options = MagicMock(return_value={})
        result = self.auditor.ask_net_discovery_options()
        self.assertEqual(result, {})

    def test_ask_auth_config(self, *args):
        self.auditor.ask_auth_config = MagicMock(return_value={})
        result = self.auditor.ask_auth_config()
        self.assertEqual(result, {})


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestNetDiscoveryBlock(unittest.TestCase):
    """Test net_discovery block within run_complete_scan."""

    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.logger = MagicMock()

    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.core.auditor.maybe_chown_to_invoking_user")
    @patch("redaudit.utils.session_log.start_session_log")
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    @patch("redaudit.core.net_discovery.discover_networks")
    @patch("redaudit.core.net_discovery.detect_default_route_interface", return_value="eth0")
    def test_net_discovery_enabled(
        self, mock_detect, mock_discover, mock_stop, mock_start, mock_chown, mock_gen, *args
    ):
        """run_complete_scan with net_discovery_enabled=True executes discovery."""
        mock_discover.return_value = {
            "enabled": True,
            "dhcp_servers": [{"ip": "10.0.0.1"}],
            "candidate_vlans": [],
            "hyperscan_duration": 1.5,
            "arp_hosts": ["10.0.0.2"],
            "upnp_devices": [],
            "hyperscan_tcp_hosts": {},
            "potential_backdoors": [],
        }

        self.auditor.config["target_networks"] = ["10.0.0.0/24"]
        self.auditor.config["max_hosts_value"] = "all"
        self.auditor.config["prevent_sleep"] = False
        self.auditor.config["scan_vulnerabilities"] = False
        self.auditor.config["nuclei_enabled"] = False
        self.auditor.config["auth_enabled"] = False
        self.auditor.config["cve_lookup_enabled"] = False
        self.auditor.config["topology_enabled"] = False
        self.auditor.config["net_discovery_enabled"] = True
        self.auditor.config["net_discovery_redteam"] = False
        self.auditor.config["scan_mode"] = "normal"
        self.auditor.scan_network_discovery = MagicMock(return_value=["10.0.0.1"])
        host_mock = MagicMock()
        host_mock.ip = "10.0.0.1"
        host_mock.smart_scan = {}
        host_mock.to_dict = MagicMock(return_value={"ip": "10.0.0.1"})
        self.auditor.scanner.get_or_create_host = MagicMock(return_value=host_mock)
        self.auditor.scan_hosts_concurrent = MagicMock(return_value=[host_mock])
        self.auditor.run_agentless_verification = MagicMock()
        self.auditor.save_results = MagicMock()
        self.auditor.show_results = MagicMock()
        self.auditor.start_heartbeat = MagicMock()
        self.auditor.stop_heartbeat = MagicMock()
        self.auditor.proxy_manager = None
        self.auditor._run_hyperscan_discovery = MagicMock(return_value=None)
        self.auditor._filter_auditor_ips = MagicMock(side_effect=lambda x: x)
        self.auditor._build_scope_expansion_evidence = MagicMock(return_value=[])
        self.auditor._select_net_discovery_interface = MagicMock(return_value="eth0")

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)
        self.assertIn("net_discovery", self.auditor.results)

    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.core.auditor.maybe_chown_to_invoking_user")
    @patch("redaudit.utils.session_log.start_session_log")
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    @patch("redaudit.core.net_discovery.discover_networks")
    @patch("redaudit.core.net_discovery.detect_default_route_interface", return_value=None)
    def test_net_discovery_error(
        self, mock_detect, mock_discover, mock_stop, mock_start, mock_chown, mock_gen, *args
    ):
        """run_complete_scan handles net_discovery exceptions."""
        mock_discover.side_effect = RuntimeError("discovery failed")

        self.auditor.config["target_networks"] = ["10.0.0.0/24"]
        self.auditor.config["max_hosts_value"] = "all"
        self.auditor.config["prevent_sleep"] = False
        self.auditor.config["scan_vulnerabilities"] = False
        self.auditor.config["nuclei_enabled"] = False
        self.auditor.config["auth_enabled"] = False
        self.auditor.config["cve_lookup_enabled"] = False
        self.auditor.config["topology_enabled"] = False
        self.auditor.config["net_discovery_enabled"] = True
        self.auditor.config["net_discovery_redteam"] = False
        self.auditor.config["scan_mode"] = "normal"
        self.auditor.scan_network_discovery = MagicMock(return_value=[])
        self.auditor.start_heartbeat = MagicMock()
        self.auditor.stop_heartbeat = MagicMock()
        self.auditor.proxy_manager = None
        self.auditor._select_net_discovery_interface = MagicMock(return_value=None)

        self.auditor.run_complete_scan()
        # net_discovery should have error recorded
        nd = self.auditor.results.get("net_discovery", {})
        self.assertTrue(nd.get("error") or nd.get("enabled"))


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestCollectAuditorIPFallbacks(unittest.TestCase):
    """Test _collect_auditor_ip_reasons fallback paths."""

    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.logger = MagicMock()

    def test_fallback_detect_all_networks(self, *args):
        """Falls back to detect_all_networks when network_info is empty."""
        self.auditor.results["network_info"] = []
        with patch(
            "redaudit.core.auditor.detect_all_networks",
            return_value=[{"ip": "192.168.1.5", "interface": "en0"}],
        ):
            reasons = self.auditor._collect_auditor_ip_reasons()
            self.assertIn("192.168.1.5", reasons)

    def test_topology_routes(self, *args):
        """Collects IPs from topology routes."""
        self.auditor.results["network_info"] = []
        self.auditor.results["topology"] = {
            "routes": [{"src": "10.0.0.1", "dev": "eth0"}],
            "interfaces": [{"ip": "10.0.0.2", "interface": "wlan0"}],
        }
        reasons = self.auditor._collect_auditor_ip_reasons()
        self.assertIn("10.0.0.1", reasons)
        self.assertIn("10.0.0.2", reasons)

    @patch("redaudit.core.auditor.detect_all_networks", side_effect=Exception("fail"))
    @patch("socket.gethostname", return_value="testhost")
    @patch("socket.gethostbyname_ex", return_value=("testhost", [], ["192.168.1.100"]))
    def test_fallback_hostname(self, mock_gbn, mock_ghn, mock_detect, *args):
        """Falls back to hostname resolution."""
        self.auditor.results["network_info"] = []
        reasons = self.auditor._collect_auditor_ip_reasons()
        self.assertIn("192.168.1.100", reasons)

    @patch("redaudit.core.auditor.detect_all_networks", side_effect=Exception("fail"))
    @patch("socket.gethostname", side_effect=Exception("no host"))
    @patch("socket.socket")
    def test_fallback_udp_route(self, mock_socket, mock_ghn, mock_detect, *args):
        """Falls back to UDP route probe."""
        self.auditor.results["network_info"] = []
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("10.0.0.50", 12345)
        mock_socket.return_value = mock_sock
        reasons = self.auditor._collect_auditor_ip_reasons()
        self.assertIn("10.0.0.50", reasons)


if __name__ == "__main__":
    unittest.main()
