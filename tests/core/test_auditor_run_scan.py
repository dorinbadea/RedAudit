"""Tests for run_complete_scan, authenticated scans, SNMP topology, and resume methods."""

import os
import json
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, call


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestRunCompleteScan(unittest.TestCase):
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
    def test_run_complete_scan_no_hosts(self, mock_stop, mock_start, mock_chown, mock_gen, *args):
        """run_complete_scan returns False when no hosts found."""
        self.auditor.config["target_networks"] = ["192.168.1.0/24"]
        self.auditor.config["max_hosts_value"] = "all"
        self.auditor.config["prevent_sleep"] = False
        self.auditor.scan_network_discovery = MagicMock(return_value=[])
        self.auditor.start_heartbeat = MagicMock()
        self.auditor.stop_heartbeat = MagicMock()
        self.auditor.proxy_manager = None

        result = self.auditor.run_complete_scan()
        self.assertFalse(result)

    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.core.auditor.maybe_chown_to_invoking_user")
    @patch("redaudit.utils.session_log.start_session_log")
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    def test_run_complete_scan_basic_flow(self, mock_stop, mock_start, mock_chown, mock_gen, *args):
        """run_complete_scan executes basic flow with hosts."""
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]
        self.auditor.config["max_hosts_value"] = "all"
        self.auditor.config["prevent_sleep"] = False
        self.auditor.config["scan_vulnerabilities"] = False
        self.auditor.config["nuclei_enabled"] = False
        self.auditor.config["auth_enabled"] = False
        self.auditor.config["cve_lookup_enabled"] = False
        self.auditor.config["topology_enabled"] = False
        self.auditor.config["net_discovery_enabled"] = False
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

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)
        self.auditor.save_results.assert_called_once()

    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.core.auditor.maybe_chown_to_invoking_user")
    @patch("redaudit.utils.session_log.start_session_log")
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    def test_run_complete_scan_with_proxy(self, mock_stop, mock_start, mock_chown, mock_gen, *args):
        """run_complete_scan logs proxy info when proxy_manager is set."""
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]
        self.auditor.config["max_hosts_value"] = "all"
        self.auditor.config["prevent_sleep"] = False
        self.auditor.scan_network_discovery = MagicMock(return_value=[])
        self.auditor.start_heartbeat = MagicMock()
        self.auditor.stop_heartbeat = MagicMock()
        pm = MagicMock()
        pm.proxy_config = {"host": "127.0.0.1", "port": 8080}
        self.auditor.proxy_manager = pm

        self.auditor.run_complete_scan()
        self.auditor.ui.print_status.assert_any_call("proxy_in_use", "INFO")

    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.core.auditor.maybe_chown_to_invoking_user")
    @patch("redaudit.utils.session_log.start_session_log")
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    def test_run_complete_scan_max_hosts(self, mock_stop, mock_start, mock_chown, mock_gen, *args):
        """run_complete_scan limits hosts to max_hosts_value."""
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]
        self.auditor.config["max_hosts_value"] = 1
        self.auditor.config["prevent_sleep"] = False
        self.auditor.config["scan_vulnerabilities"] = False
        self.auditor.config["nuclei_enabled"] = False
        self.auditor.config["auth_enabled"] = False
        self.auditor.config["cve_lookup_enabled"] = False
        self.auditor.config["topology_enabled"] = False
        self.auditor.config["net_discovery_enabled"] = False
        self.auditor.scan_network_discovery = MagicMock(return_value=["10.0.0.1", "10.0.0.2"])
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

        self.auditor.run_complete_scan()
        # get_or_create_host should be called once (max 1 host)
        self.auditor.scanner.get_or_create_host.assert_called_once()

    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.core.auditor.maybe_chown_to_invoking_user")
    @patch("redaudit.utils.session_log.start_session_log")
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    def test_run_complete_scan_interrupted(
        self, mock_stop, mock_start, mock_chown, mock_gen, *args
    ):
        """run_complete_scan respects interrupted flag."""
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]
        self.auditor.config["max_hosts_value"] = "all"
        self.auditor.config["prevent_sleep"] = False
        self.auditor.config["scan_vulnerabilities"] = False
        self.auditor.config["nuclei_enabled"] = False
        self.auditor.config["auth_enabled"] = False
        self.auditor.config["cve_lookup_enabled"] = False
        self.auditor.config["topology_enabled"] = False
        self.auditor.config["net_discovery_enabled"] = False
        self.auditor.interrupted = True  # Pre-set interrupted
        self.auditor.scan_network_discovery = MagicMock(return_value=[])
        self.auditor.start_heartbeat = MagicMock()
        self.auditor.stop_heartbeat = MagicMock()
        self.auditor.proxy_manager = None

        self.auditor.run_complete_scan()
        # scan_network_discovery should not be called (interrupted before loop)


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestAuthenticatedScans(unittest.TestCase):
    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.logger = MagicMock()

    @patch("redaudit.core.auth_lynis.LynisScanner")
    @patch("redaudit.core.auth_ssh.SSHScanner")
    def test_no_credentials(self, mock_ssh, mock_lynis, *args):
        """Skip when no credentials configured."""
        self.auditor.config["auth_credentials"] = []
        self.auditor.config["auth_ssh_user"] = None
        self.auditor._run_authenticated_scans([])
        mock_ssh.assert_not_called()

    @patch("redaudit.core.auth_lynis.LynisScanner")
    @patch("redaudit.core.auth_ssh.SSHScanner")
    def test_no_ssh_hosts(self, mock_ssh, mock_lynis, *args):
        """Skip when no hosts have SSH ports."""
        self.auditor.config["auth_credentials"] = []
        self.auditor.config["auth_ssh_user"] = "root"
        self.auditor.config["auth_ssh_pass"] = "pass"
        self.auditor.config["auth_ssh_key"] = None
        self.auditor.config["auth_ssh_key_pass"] = None
        host = {"ip": "10.0.0.1", "ports": [{"port": 80, "service": "http"}], "services": []}
        self.auditor._run_authenticated_scans([host])
        self.auditor.ui.print_status.assert_any_call("auth_scan_no_hosts", "INFO")

    @patch("redaudit.core.auth_lynis.LynisScanner")
    @patch("redaudit.core.auth_ssh.SSHScanner")
    def test_ssh_success(self, mock_ssh_cls, mock_lynis_cls, *args):
        """Test successful SSH auth scan."""
        self.auditor.config["auth_credentials"] = [{"user": "root", "pass": "toor"}]
        mock_scanner = MagicMock()
        mock_ssh_cls.return_value = mock_scanner
        host_info = MagicMock()
        host_info.os_name = "Ubuntu"
        host_info.os_version = "22.04"
        host_info.kernel = "5.15"
        host_info.hostname = "srv1"
        host_info.packages = []
        host_info.services = []
        host_info.users = []
        mock_scanner.gather_host_info.return_value = host_info
        mock_lynis_cls.return_value.run_audit.return_value = None

        host = {"ip": "10.0.0.1", "ports": [{"port": 22, "service": "ssh"}], "services": []}
        self.auditor._run_authenticated_scans([host])
        self.assertEqual(self.auditor.results["auth_scan"]["ssh_success"], 1)

    @patch("redaudit.core.auth_lynis.LynisScanner")
    @patch("redaudit.core.auth_ssh.SSHScanner")
    def test_ssh_all_creds_fail(self, mock_ssh_cls, mock_lynis_cls, *args):
        """Test all credentials failing."""
        from redaudit.core.auth_ssh import SSHConnectionError

        self.auditor.config["auth_credentials"] = [{"user": "root", "pass": "bad"}]
        mock_ssh_cls.return_value.connect.side_effect = SSHConnectionError("denied")

        host = {"ip": "10.0.0.1", "ports": [{"port": 22, "service": "ssh"}], "services": []}
        self.auditor._run_authenticated_scans([host])
        self.assertEqual(len(self.auditor.results["auth_scan"]["errors"]), 1)


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestProcessSnmpTopology(unittest.TestCase):
    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.logger = MagicMock()

    def test_no_routes(self, *args):
        """No action when hosts have no routes."""
        hosts = [{"ip": "10.0.0.1", "auth_scan": {}}]
        self.auditor._process_snmp_topology(hosts)

    def test_discovers_new_networks(self, *args):
        """Discovers new networks from SNMP routes."""
        hosts = [
            {
                "ip": "10.0.0.1",
                "auth_scan": {
                    "routes": [
                        {"dest": "172.16.0.0", "mask": "255.255.0.0"},
                        {"dest": "0.0.0.0", "mask": "0.0.0.0"},  # default, skip
                    ]
                },
            }
        ]
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]
        self.auditor.config["follow_routes"] = False
        self.auditor._process_snmp_topology(hosts)
        self.auditor.ui.print_status.assert_any_call("  - 172.16.0.0/16 (via 10.0.0.1)", "INFO")

    def test_already_in_scope(self, *args):
        """No new networks when all are already in scope."""
        hosts = [
            {
                "ip": "10.0.0.1",
                "auth_scan": {"routes": [{"dest": "10.0.0.0", "mask": "255.255.255.0"}]},
            }
        ]
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]
        self.auditor._process_snmp_topology(hosts)

    def test_follow_routes(self, *args):
        """Follows routes and scans new networks."""
        hosts = [
            {
                "ip": "10.0.0.1",
                "auth_scan": {"routes": [{"dest": "172.16.0.0", "mask": "255.255.0.0"}]},
            }
        ]
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]
        self.auditor.config["follow_routes"] = True
        self.auditor.scan_network_discovery = MagicMock(return_value=["172.16.0.5"])
        host_mock = MagicMock()
        host_mock.ip = "172.16.0.5"
        self.auditor.scanner.get_or_create_host = MagicMock(return_value=host_mock)
        self.auditor.scan_hosts_concurrent = MagicMock(return_value=[host_mock])
        self.auditor._process_snmp_topology(hosts)
        self.auditor.scan_hosts_concurrent.assert_called_once()


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestResumeNuclei(unittest.TestCase):
    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.logger = MagicMock()

    def test_resume_from_path_no_state(self, *args):
        """Returns False when no resume state found."""
        result = self.auditor.resume_nuclei_from_path("/nonexistent/path")
        self.assertFalse(result)

    def test_resume_from_path_dir(self, *args):
        """Handles directory path by appending nuclei_resume.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.auditor.resume_nuclei_from_path(tmpdir)
            self.assertFalse(result)

    def test_resume_from_path_keyboard_interrupt(self, *args):
        """Handles KeyboardInterrupt gracefully."""
        self.auditor._load_nuclei_resume_state = MagicMock(side_effect=KeyboardInterrupt)
        result = self.auditor.resume_nuclei_from_path("/some/path")
        self.assertFalse(result)

    def test_resume_interactive_no_candidates(self, *args):
        """Returns False when no resume candidates found."""
        self.auditor._find_nuclei_resume_candidates = MagicMock(return_value=[])
        result = self.auditor.resume_nuclei_interactive()
        self.assertFalse(result)

    def test_resume_interactive_back(self, *args):
        """Handles user choosing back."""
        self.auditor._find_nuclei_resume_candidates = MagicMock(
            return_value=[{"label": "test", "path": "/tmp/r.json", "output_dir": "/tmp"}]
        )
        # back_idx = len(options) - 1 = 2 (manage at 1, back at 2)
        self.auditor.ask_choice = MagicMock(return_value=2)
        result = self.auditor.resume_nuclei_interactive()
        self.assertFalse(result)

    def test_resume_interactive_keyboard_interrupt(self, *args):
        """Handles KeyboardInterrupt in interactive mode."""
        self.auditor._find_nuclei_resume_candidates = MagicMock(side_effect=KeyboardInterrupt)
        result = self.auditor.resume_nuclei_interactive()
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
