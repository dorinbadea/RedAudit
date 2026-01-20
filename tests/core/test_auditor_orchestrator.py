#!/usr/bin/env python3
"""
RedAudit - Orchestrator Logic Tests
Tests for InteractiveNetworkAuditor high-level flows, error handling, and cleanup.
"""

import unittest
from unittest.mock import MagicMock, patch

from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.utils.constants import COLORS, MAX_THREADS


class TestAuditorOrchestrator(unittest.TestCase):
    def setUp(self):
        self.mock_ui_manager = MagicMock()
        self.mock_ui_manager.colors = COLORS
        self.mock_ui_manager.t.side_effect = lambda key, *args: key
        # Patch UIManager before instantiating Auditor
        with patch("redaudit.core.ui_manager.UIManager", return_value=self.mock_ui_manager):
            self.auditor = InteractiveNetworkAuditor()
        # Disable logging to stdout/file during tests
        self.auditor.logger = MagicMock()
        self.auditor.print_status = MagicMock()

    def test_interactive_setup_fails_dependency_check(self):
        """Test interactive setup returns False if dependencies are missing."""
        self.auditor.clear_screen = MagicMock()
        self.auditor.print_banner = MagicMock()

        with patch.object(self.auditor, "check_dependencies", return_value=False):
            result = self.auditor.interactive_setup()
            self.assertFalse(result)

    def test_interactive_setup_legal_warning_rejected(self):
        """Test interactive setup returns False if user rejects legal warning."""
        self.auditor.clear_screen = MagicMock()
        self.auditor.print_banner = MagicMock()

        with patch.object(self.auditor, "check_dependencies", return_value=True):
            with patch.object(self.auditor, "show_legal_warning", return_value=False):
                result = self.auditor.interactive_setup()
                self.assertFalse(result)

    def test_run_complete_scan_keyboard_interrupt_cleanup(self):
        """Test cleanup on KeyboardInterrupt during run_complete_scan."""
        self.auditor.start_heartbeat = MagicMock()
        self.auditor.stop_heartbeat = MagicMock()

        # Raise KeyboardInterrupt
        self.auditor.scan_network_discovery = MagicMock(side_effect=KeyboardInterrupt)
        # Prepare state to reach scan_network_discovery
        self.auditor.results["network_info"] = [{"network": "192.168.1.0/24"}]
        self.auditor.config["target_networks"] = ["192.168.1.0/24"]
        self.auditor.config["topology_enabled"] = False
        # Ensure we pass the initial checks
        self.auditor._collect_discovery_hosts = MagicMock(return_value=["192.168.1.10"])
        # Mock paths and session log to avoid side effects
        with (
            patch("redaudit.utils.session_log.start_session_log"),
            patch("os.makedirs"),
            patch("redaudit.utils.paths.maybe_chown_to_invoking_user"),
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.auditor.run_complete_scan()

            # Verify cleanup (finally block)
            self.auditor.stop_heartbeat.assert_called()

    def test_run_complete_scan_general_exception(self):
        """Test general exception handling during run_complete_scan."""
        self.auditor.start_heartbeat = MagicMock()
        self.auditor.stop_heartbeat = MagicMock()

        # Raise exception at os.makedirs (very early)
        with (
            patch("redaudit.utils.session_log.start_session_log"),
            patch("os.makedirs", side_effect=OSError("Disk Full")),
            patch("redaudit.utils.paths.maybe_chown_to_invoking_user"),
        ):

            with self.assertRaises(OSError):
                self.auditor.run_complete_scan()

            # Verify cleanup
            self.auditor.stop_heartbeat.assert_called()

    def test_cleanup_subprocesses(self):
        """Test kill_all_subprocesses logic."""
        mock_proc_1 = MagicMock()
        mock_proc_1.poll.return_value = None  # Running
        mock_proc_2 = MagicMock()
        mock_proc_2.poll.return_value = 0  # Finished
        self.auditor._active_subprocesses = [mock_proc_1, mock_proc_2]
        # Patch shutil.which to prevent actual pkill attempt
        with patch("shutil.which", return_value=None):
            self.auditor.kill_all_subprocesses()
        mock_proc_1.terminate.assert_called()
        mock_proc_1.wait.assert_called()
        mock_proc_2.terminate.assert_not_called()
        self.assertEqual(len(self.auditor._active_subprocesses), 0)

    def test_filter_auditor_ips(self):
        """Test _filter_auditor_ips removes self-IPs."""
        self.auditor.results["network_info"] = [
            {"ip": "10.0.0.5", "interface": "eth0"},
            {"ip": "192.168.1.100", "interface": "wlan0"},
        ]
        hosts = ["10.0.0.1", "10.0.0.5", "192.168.1.50", "192.168.1.100"]
        filtered = self.auditor._filter_auditor_ips(hosts)
        self.assertEqual(len(filtered), 2)
        self.assertIn("10.0.0.1", filtered)
        self.assertIn("192.168.1.50", filtered)
        self.assertNotIn("10.0.0.5", filtered)
        self.assertNotIn("192.168.1.100", filtered)

    def test_filter_auditor_ips_empty_network_info(self):
        self.auditor.results["network_info"] = []
        hosts = ["10.0.0.5"]
        filtered = self.auditor._filter_auditor_ips(hosts)
        self.assertEqual(filtered, hosts)

    @patch("redaudit.core.auditor.InteractiveNetworkAuditor.save_results")
    @patch("redaudit.core.auditor.InteractiveNetworkAuditor.show_results")
    @patch("redaudit.core.topology.discover_topology")
    @patch("redaudit.core.net_discovery.discover_networks")
    def test_run_complete_scan_success(
        self, mock_discover_networks, mock_discover_topology, mock_show, mock_save
    ):
        """Test the happy path of run_complete_scan with features enabled."""
        auditor = InteractiveNetworkAuditor()
        auditor.config = {
            "prevent_sleep": False,
            "topology_enabled": True,
            "net_discovery_enabled": True,
            "scan_mode": "completo",
            "target_networks": ["10.0.0.0/24"],
        }
        auditor._setup_logging = MagicMock()
        auditor.ui = MagicMock()
        auditor.start_heartbeat = MagicMock()
        auditor.stop_heartbeat = MagicMock()
        auditor.logger = MagicMock()
        # Mock proxy manager
        auditor.proxy_manager = MagicMock()
        auditor.proxy_manager.proxy_config = {"host": "1.2.3.4", "port": 1080}
        # Mock scanner
        auditor.scanner = MagicMock()
        auditor.scanner.detect_local_networks.return_value = [
            {"interface": "eth0", "ip": "10.0.0.1"}
        ]
        # Mock _select_net_discovery_interface explicitly to avoid ValueError if it fails
        auditor._select_net_discovery_interface = MagicMock(return_value="eth0")
        # Mock discoveries
        mock_discover_topology.return_value = {"nodes": [], "edges": []}
        mock_discover_networks.return_value = [{"ip": "10.0.0.2", "os": "Linux"}]
        # Mock scan_network_discovery to return non-empty hosts so run_complete_scan continues
        mock_host = MagicMock()
        mock_host.ip = "10.0.0.5"
        auditor.scan_network_discovery = MagicMock(return_value=[mock_host])

        # Mock subsequent phases (scan_phase_network, etc) to avoid actual scanning
        auditor.scan_phase_network = MagicMock()
        auditor.scan_phase_hosts = MagicMock()
        auditor.scan_phase_vulnerabilities = MagicMock()
        auditor.scan_phase_post_exploitation = MagicMock()
        auditor.generate_report = MagicMock()
        # Mock separate heavy scan methods that might be called directly
        auditor._run_hyperscan_discovery = MagicMock()
        auditor.scan_hosts_concurrent = MagicMock(return_value=[])
        auditor.run_deep_scans_concurrent = MagicMock()
        auditor.run_agentless_verification = MagicMock()
        auditor.scan_vulnerabilities_concurrent = MagicMock()
        auditor._process_snmp_topology = MagicMock()

        # Mock date/time to avoid folder creation issues?
        # We can just let it run, mock os.makedirs and session logging
        with (
            patch("redaudit.core.auditor.os.makedirs"),
            patch("redaudit.core.auditor.maybe_chown_to_invoking_user"),
            patch("redaudit.utils.session_log.start_session_log"),
            patch("rich.progress.Progress"),
        ):  # Mock rich progress
            res = auditor.run_complete_scan()
        assert res is True
        assert auditor.results["network_info"]
        mock_discover_topology.assert_called()
        mock_discover_networks.assert_called()
        auditor.ui.print_status.assert_any_call(
            auditor.ui.t("proxy_in_use", "1.2.3.4:1080"), "INFO"
        )
        mock_save.assert_called()
        mock_show.assert_called()

    def test_configure_scan_profile_express(self):
        """Test _configure_scan_interactive selecting Express profile."""
        # Setup mocks
        self.auditor.ui = MagicMock()
        self.auditor.ui.t.side_effect = lambda key, *args: key
        self.auditor.ask_choice = MagicMock()
        self.auditor.ask_yes_no = MagicMock()
        self.auditor._ask_auditor_and_output_dir = MagicMock()

        # Profile 0: Express
        self.auditor.ask_choice.return_value = 0

        # low_impact_enrichment
        self.auditor.ask_yes_no.return_value = True

        defaults = {"low_impact_enrichment": "yes"}
        self.auditor._configure_scan_interactive(defaults)

        # Verify config
        self.assertEqual(self.auditor.config["scan_mode"], "rapido")
        self.assertEqual(self.auditor.config["max_hosts_value"], "all")
        self.assertFalse(self.auditor.config["scan_vulnerabilities"])
        self.assertTrue(self.auditor.config["topology_enabled"])
        self.auditor._ask_auditor_and_output_dir.assert_called()

    def test_configure_scan_profile_standard_stealth(self):
        """Test _configure_scan_interactive selecting Standard profile with Stealth timing."""
        self.auditor.ui = MagicMock()
        self.auditor.ui.t.side_effect = lambda key, *args: key
        self.auditor.ask_choice = MagicMock()
        self.auditor.ask_yes_no = MagicMock()
        self.auditor._ask_auditor_and_output_dir = MagicMock()
        self.auditor.ask_auth_config = MagicMock(return_value={})

        # Sequence of choices:
        # 1. Profile: Standard (index 1)
        # 2. Timing: Stealth (index 0)
        self.auditor.ask_choice.side_effect = [1, 0]

        self.auditor.ask_yes_no.return_value = False

        defaults = {}
        self.auditor._configure_scan_interactive(defaults)

        self.assertEqual(self.auditor.config["scan_mode"], "normal")
        self.assertEqual(self.auditor.rate_limit_delay, 2.0)
        self.assertTrue(self.auditor.config["scan_vulnerabilities"])
        self.auditor.ask_auth_config.assert_called()

    def test_configure_scan_profile_exhaustive(self):
        """Test _configure_scan_interactive selecting Exhaustive profile with Nuclei enabled."""
        self.auditor.ui = MagicMock()
        self.auditor.ui.t.side_effect = lambda key, *args: key
        self.auditor.ask_choice = MagicMock()
        self.auditor.ask_yes_no = MagicMock()
        self.auditor._ask_auditor_and_output_dir = MagicMock()
        self.auditor.ask_auth_config = MagicMock(return_value={})

        # Sequence of choices:
        # 1. Profile: Exhaustive (index 2)
        # 2. Timing: Normal (index 1) - T4
        # 3. Nuclei Profile: Full (index 0) - Only asked if Nuclei is enabled
        self.auditor.ask_choice.side_effect = [2, 1, 0]

        # Sequence of yes/no:
        # 1. Nuclei enabled? True
        # 2. Nuclei full coverage? True (v4.17+)
        # 3. Trust Hyperscan? True
        self.auditor.ask_yes_no.side_effect = [True, True, True]

        defaults = {}
        # Patch is_nvd_api_key_configured to avoid NVD warning path
        # Since it is imported from redaudit.utils.config inside the method, we patch the original source
        # And setup_nvd_api_key is on AuditorRuntime (via AuditorNVD), not InteractiveNetworkAuditor directly
        # Also patch shutil.which to simulate zap.sh installation for zap_enabled check
        with (
            patch("redaudit.utils.config.is_nvd_api_key_configured", return_value=True),
            patch("redaudit.core.auditor_runtime.AuditorRuntime.setup_nvd_api_key"),
            patch("shutil.which", return_value="/usr/bin/zap.sh"),
        ):
            self.auditor._configure_scan_interactive(defaults)

        # Verify config
        self.assertEqual(self.auditor.config["scan_mode"], "completo")
        self.assertEqual(self.auditor.config["threads"], MAX_THREADS)
        self.assertTrue(self.auditor.config["deep_id_scan"])
        self.assertTrue(self.auditor.config["scan_vulnerabilities"])
        self.assertTrue(self.auditor.config["nuclei_enabled"])
        self.assertEqual(self.auditor.config["nuclei_profile"], "full")
        self.assertTrue(self.auditor.config["trust_hyperscan"])
        self.assertTrue(
            self.auditor.config["zap_enabled"]
        )  # If zap is found. We should patch shutil.which

        self.auditor.ask_auth_config.assert_called()


if __name__ == "__main__":
    unittest.main()
