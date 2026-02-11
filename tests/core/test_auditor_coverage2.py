"""Tests for _run_authenticated_scans, _process_snmp_topology,
_resume_nuclei_from_state internals, net discovery progress block,
and remaining gaps in auditor.py."""

import math
import os
import time
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, PropertyMock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_auditor():
    with patch("redaudit.core.auditor.AuditorRuntime"):
        from redaudit.core.auditor import InteractiveNetworkAuditor

        auditor = InteractiveNetworkAuditor()
    auditor.ui = MagicMock()
    auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
    auditor.logger = MagicMock()
    auditor.proxy_manager = None
    return auditor


def _host_mock(ip="10.0.0.1", ssh_port=22, with_auth=False, routes=None):
    h = MagicMock()
    h.ip = ip
    h.ports = [{"port": ssh_port, "service": "ssh"}] if ssh_port else []
    h.services = []
    h.tags = set()
    h.agentless_fingerprint = {}
    h.smart_scan = {}
    h.to_dict = MagicMock(return_value={"ip": ip})
    if with_auth:
        h.auth_scan = {"routes": routes or []}
    else:
        h.auth_scan = None
    return h


# ===========================================================================
# _run_authenticated_scans
# ===========================================================================


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestRunAuthenticatedScans(unittest.TestCase):

    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.logger = MagicMock()

    @patch("redaudit.core.auth_ssh.SSHScanner")
    @patch("redaudit.core.auth_lynis.LynisScanner")
    @patch("redaudit.core.credentials.Credential")
    def test_auth_scan_with_legacy_creds(self, mock_cred_cls, mock_lynis_cls, mock_ssh_cls, *args):
        """Auth scan with legacy single credential succeeds."""
        self.auditor.config["auth_ssh_user"] = "admin"
        self.auditor.config["auth_ssh_pass"] = "pass123"
        self.auditor.config["auth_credentials"] = []

        mock_scanner = MagicMock()
        mock_ssh_cls.return_value = mock_scanner
        host_info = MagicMock()
        host_info.os_name = "Ubuntu"
        host_info.os_version = "22.04"
        host_info.kernel = "5.15"
        host_info.hostname = "srv1"
        host_info.packages = ["pkg1"]
        host_info.services = ["sshd"]
        host_info.users = ["root"]
        mock_scanner.gather_host_info.return_value = host_info

        lynis_result = MagicMock()
        lynis_result.hardening_index = 72
        lynis_result.warnings = ["w1"]
        lynis_result.suggestions = ["s1", "s2"]
        lynis_result.tests_performed = 100
        mock_lynis = MagicMock()
        mock_lynis.run_audit.return_value = lynis_result
        mock_lynis_cls.return_value = mock_lynis

        host = {"ip": "10.0.0.1", "ports": [{"port": 22, "service": "ssh"}], "services": []}
        self.auditor._run_authenticated_scans([host])

        self.assertIn("auth_scan", self.auditor.results)
        self.assertEqual(self.auditor.results["auth_scan"]["ssh_success"], 1)
        self.assertEqual(self.auditor.results["auth_scan"]["lynis_success"], 1)

    @patch("redaudit.core.auth_ssh.SSHScanner")
    @patch("redaudit.core.auth_lynis.LynisScanner")
    @patch("redaudit.core.credentials.Credential")
    def test_auth_scan_multi_creds(self, mock_cred_cls, mock_lynis_cls, mock_ssh_cls, *args):
        """Auth scan with universal credentials list."""
        self.auditor.config["auth_credentials"] = [
            {"user": "admin", "pass": "p1"},
            {"user": "root", "pass": "p2"},
        ]

        mock_scanner = MagicMock()
        mock_ssh_cls.return_value = mock_scanner
        host_info = MagicMock()
        host_info.os_name = "Debian"
        host_info.os_version = "12"
        host_info.kernel = "6.1"
        host_info.hostname = "srv2"
        host_info.packages = []
        host_info.services = []
        host_info.users = []
        mock_scanner.gather_host_info.return_value = host_info

        mock_lynis = MagicMock()
        mock_lynis.run_audit.return_value = None  # Lynis returns None
        mock_lynis_cls.return_value = mock_lynis

        host = {"ip": "10.0.0.1", "ports": [{"port": 22, "service": "ssh"}], "services": []}
        self.auditor._run_authenticated_scans([host])

        self.assertEqual(self.auditor.results["auth_scan"]["ssh_success"], 1)
        self.assertEqual(self.auditor.results["auth_scan"]["lynis_success"], 0)

    @patch("redaudit.core.auth_ssh.SSHScanner")
    @patch("redaudit.core.auth_lynis.LynisScanner")
    @patch("redaudit.core.credentials.Credential")
    def test_auth_scan_connection_fails(self, mock_cred_cls, mock_lynis_cls, mock_ssh_cls, *args):
        """All credentials fail SSH connection."""
        from redaudit.core.auth_ssh import SSHConnectionError

        self.auditor.config["auth_ssh_user"] = "admin"
        self.auditor.config["auth_ssh_pass"] = "wrong"
        self.auditor.config["auth_credentials"] = []

        mock_ssh_cls.return_value.connect.side_effect = SSHConnectionError("denied")

        host = {"ip": "10.0.0.1", "ports": [{"port": 22, "service": "ssh"}], "services": []}
        self.auditor._run_authenticated_scans([host])

        self.assertEqual(self.auditor.results["auth_scan"]["ssh_success"], 0)
        self.assertEqual(len(self.auditor.results["auth_scan"]["errors"]), 1)

    @patch("redaudit.core.auth_ssh.SSHScanner")
    @patch("redaudit.core.auth_lynis.LynisScanner")
    @patch("redaudit.core.credentials.Credential")
    def test_auth_scan_no_ssh_hosts(self, mock_cred_cls, mock_lynis_cls, mock_ssh_cls, *args):
        """No hosts with SSH -> early return."""
        self.auditor.config["auth_ssh_user"] = "admin"
        self.auditor.config["auth_ssh_pass"] = "pass"
        self.auditor.config["auth_credentials"] = []

        host = {"ip": "10.0.0.1", "ports": [{"port": 80, "service": "http"}], "services": []}
        self.auditor._run_authenticated_scans([host])

        # No auth_scan in results since it returned early
        self.assertNotIn("auth_scan", self.auditor.results)

    def test_auth_scan_no_creds(self, *args):
        """No credentials configured -> early return."""
        self.auditor.config["auth_credentials"] = []
        # No auth_ssh_user either
        host = {"ip": "10.0.0.1", "ports": [{"port": 22, "service": "ssh"}], "services": []}
        self.auditor._run_authenticated_scans([host])
        self.assertNotIn("auth_scan", self.auditor.results)

    @patch("redaudit.core.auth_ssh.SSHScanner")
    @patch("redaudit.core.auth_lynis.LynisScanner")
    @patch("redaudit.core.credentials.Credential")
    def test_auth_scan_host_object(self, mock_cred_cls, mock_lynis_cls, mock_ssh_cls, *args):
        """Auth scan with Host object (not dict)."""
        self.auditor.config["auth_ssh_user"] = "admin"
        self.auditor.config["auth_ssh_pass"] = "pass"
        self.auditor.config["auth_credentials"] = []

        mock_scanner = MagicMock()
        mock_ssh_cls.return_value = mock_scanner
        host_info = MagicMock()
        host_info.os_name = "CentOS"
        host_info.os_version = "8"
        host_info.kernel = "4.18"
        host_info.hostname = "srv3"
        host_info.packages = []
        host_info.services = []
        host_info.users = []
        mock_scanner.gather_host_info.return_value = host_info

        mock_lynis = MagicMock()
        mock_lynis.run_audit.side_effect = RuntimeError("lynis boom")
        mock_lynis_cls.return_value = mock_lynis

        host = _host_mock("10.0.0.5", ssh_port=22)
        self.auditor._run_authenticated_scans([host])

        self.assertEqual(self.auditor.results["auth_scan"]["ssh_success"], 1)

    @patch("redaudit.core.auth_ssh.SSHScanner")
    @patch("redaudit.core.auth_lynis.LynisScanner")
    @patch("redaudit.core.credentials.Credential")
    def test_auth_scan_gather_exception(self, mock_cred_cls, mock_lynis_cls, mock_ssh_cls, *args):
        """SSH connects but gather_host_info raises SSHConnectionError."""
        from redaudit.core.auth_ssh import SSHConnectionError

        self.auditor.config["auth_ssh_user"] = "admin"
        self.auditor.config["auth_ssh_pass"] = "pass"
        self.auditor.config["auth_credentials"] = []

        mock_scanner = MagicMock()
        mock_ssh_cls.return_value = mock_scanner
        mock_scanner.gather_host_info.side_effect = SSHConnectionError("timeout")

        host = {"ip": "10.0.0.1", "ports": [{"port": 22, "service": "ssh"}], "services": []}
        self.auditor._run_authenticated_scans([host])

        self.assertEqual(self.auditor.results["auth_scan"]["ssh_success"], 0)

    @patch("redaudit.core.auth_ssh.SSHScanner")
    @patch("redaudit.core.auth_lynis.LynisScanner")
    @patch("redaudit.core.credentials.Credential")
    def test_auth_scan_services_ssh_detection(
        self, mock_cred_cls, mock_lynis_cls, mock_ssh_cls, *args
    ):
        """SSH detected via services list when ports have no service metadata."""
        self.auditor.config["auth_ssh_user"] = "admin"
        self.auditor.config["auth_ssh_pass"] = "pass"
        self.auditor.config["auth_credentials"] = []

        mock_scanner = MagicMock()
        mock_ssh_cls.return_value = mock_scanner
        host_info = MagicMock()
        host_info.os_name = "Ubuntu"
        host_info.os_version = "20"
        host_info.kernel = "5.4"
        host_info.hostname = "srv4"
        host_info.packages = []
        host_info.services = []
        host_info.users = []
        mock_scanner.gather_host_info.return_value = host_info

        mock_lynis = MagicMock()
        mock_lynis.run_audit.return_value = None
        mock_lynis_cls.return_value = mock_lynis

        # Host with SSH in services list not ports
        host = {
            "ip": "10.0.0.1",
            "ports": [{"port": 2222}],  # no service metadata
            "services": [{"name": "ssh", "port": 2222}],
        }
        self.auditor._run_authenticated_scans([host])
        self.assertEqual(self.auditor.results["auth_scan"]["ssh_success"], 1)


# ===========================================================================
# _process_snmp_topology
# ===========================================================================


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestProcessSNMPTopology(unittest.TestCase):

    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.logger = MagicMock()
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]

    def test_no_routes(self, *args):
        """No routes -> no-op."""
        host = {"ip": "10.0.0.1", "auth_scan": None}
        self.auditor._process_snmp_topology([host])
        calls = [str(c) for c in self.auditor.ui.print_status.call_args_list]
        self.assertFalse(any("SNMP" in c for c in calls))

    def test_routes_no_new_networks(self, *args):
        """Routes discovered but all within existing scope."""
        host = {
            "ip": "10.0.0.1",
            "auth_scan": {"routes": [{"dest": "10.0.0.0", "mask": "255.255.255.0"}]},
        }
        self.auditor._process_snmp_topology([host])
        calls = [str(c) for c in self.auditor.ui.print_status.call_args_list]
        self.assertFalse(any("SNMP" in c for c in calls))

    def test_routes_new_network_no_follow(self, *args):
        """New network discovered but follow_routes disabled."""
        host = {
            "ip": "10.0.0.1",
            "auth_scan": {"routes": [{"dest": "192.168.1.0", "mask": "255.255.255.0"}]},
        }
        self.auditor.config["follow_routes"] = False
        self.auditor._process_snmp_topology([host])
        calls = [str(c) for c in self.auditor.ui.print_status.call_args_list]
        status_text = " ".join(calls)
        self.assertIn("SNMP", status_text)
        self.assertIn("follow-routes", status_text)

    def test_routes_new_network_follow(self, *args):
        """New networks discovered with follow_routes enabled."""
        host = {
            "ip": "10.0.0.1",
            "auth_scan": {"routes": [{"dest": "192.168.1.0", "mask": "255.255.255.0"}]},
        }
        self.auditor.config["follow_routes"] = True
        self.auditor.scan_network_discovery = MagicMock(return_value=["192.168.1.10"])
        new_host = MagicMock()
        new_host.ip = "192.168.1.10"
        self.auditor.scanner.get_or_create_host = MagicMock(return_value=new_host)
        self.auditor.scan_hosts_concurrent = MagicMock(return_value=[new_host])
        self.auditor._progress_ui = MagicMock(
            return_value=MagicMock(
                __enter__=MagicMock(return_value=None),
                __exit__=MagicMock(return_value=False),
            )
        )

        hosts_list = [host]
        self.auditor._process_snmp_topology(hosts_list, api_key="test-key")

        self.auditor.scan_network_discovery.assert_called_once_with("192.168.1.0/24")
        self.auditor.scan_hosts_concurrent.assert_called_once()

    def test_routes_skip_defaults_and_loopback(self, *args):
        """Default routes and loopback routes are skipped."""
        host = {
            "ip": "10.0.0.1",
            "auth_scan": {
                "routes": [
                    {"dest": "0.0.0.0", "mask": "0.0.0.0"},
                    {"dest": "127.0.0.0", "mask": "255.0.0.0"},
                ]
            },
        }
        self.auditor._process_snmp_topology([host])
        calls = [str(c) for c in self.auditor.ui.print_status.call_args_list]
        self.assertFalse(any("SNMP" in c for c in calls))

    def test_routes_skip_host_routes(self, *args):
        """/32 host routes are skipped."""
        host = {
            "ip": "10.0.0.1",
            "auth_scan": {"routes": [{"dest": "192.168.1.5", "mask": "255.255.255.255"}]},
        }
        self.auditor._process_snmp_topology([host])
        calls = [str(c) for c in self.auditor.ui.print_status.call_args_list]
        self.assertFalse(any("SNMP" in c for c in calls))

    def test_routes_follow_no_new_hosts(self, *args):
        """Follow routes but no new live hosts found."""
        host = {
            "ip": "10.0.0.1",
            "auth_scan": {"routes": [{"dest": "172.16.0.0", "mask": "255.255.0.0"}]},
        }
        self.auditor.config["follow_routes"] = True
        self.auditor.scan_network_discovery = MagicMock(return_value=[])
        self.auditor._progress_ui = MagicMock(
            return_value=MagicMock(
                __enter__=MagicMock(return_value=None),
                __exit__=MagicMock(return_value=False),
            )
        )

        self.auditor._process_snmp_topology([host])
        calls = [str(c) for c in self.auditor.ui.print_status.call_args_list]
        status_text = " ".join(calls)
        self.assertIn("No new live hosts", status_text)

    def test_host_object_routes(self, *args):
        """Handle Host object (not dict) with auth_scan routes."""
        host = _host_mock(
            "10.0.0.1",
            with_auth=True,
            routes=[
                {"dest": "192.168.50.0", "mask": "255.255.255.0"},
            ],
        )
        self.auditor.config["follow_routes"] = False
        self.auditor._process_snmp_topology([host])
        calls = [str(c) for c in self.auditor.ui.print_status.call_args_list]
        status_text = " ".join(calls)
        self.assertIn("SNMP", status_text)


# ===========================================================================
# _resume_nuclei_from_state - detailed internals
# ===========================================================================


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestResumeNucleiFromStateInternals(unittest.TestCase):

    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.logger = MagicMock()
        self.auditor.proxy_manager = None

    def _base_resume_state(self):
        return {
            "pending_targets": ["http://10.0.0.1", "http://10.0.0.2"],
            "output_dir": "/tmp/test_output",
            "output_file": "nuclei_output.json",
            "nuclei": {
                "severity": "low,medium,high,critical",
                "timeout_s": 300,
                "request_timeout_s": 10,
                "retries": 1,
                "batch_size": 10,
                "max_runtime_minutes": 0,
                "fatigue_limit": 3,
                "profile": "balanced",
            },
            "profile": "balanced",
            "profile_selected": "balanced",
            "profile_effective": "balanced",
            "auto_switched": False,
            "full_coverage": False,
        }

    @patch("redaudit.core.auditor.run_nuclei_scan")
    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.utils.session_log.start_session_log", return_value=True)
    @patch("redaudit.utils.session_log.stop_session_log", return_value="/tmp/log.txt")
    @patch("os.path.exists", return_value=False)
    def test_resume_success_no_pending(
        self, mock_exists, mock_stop, mock_start, mock_gen, mock_nuclei, *args
    ):
        """Resume completes with all targets, no pending left."""
        mock_nuclei.return_value = {
            "success": True,
            "findings": [{"template_id": "xss", "matched_at": "http://10.0.0.1"}],
            "partial": False,
            "pending_targets": [],
            "timeout_batches": [],
            "failed_batches": [],
        }
        self.auditor._merge_nuclei_findings = MagicMock(return_value=1)
        self.auditor._append_nuclei_output = MagicMock()
        self.auditor._clear_nuclei_resume_state = MagicMock()
        self.auditor._write_nuclei_resume_state = MagicMock()
        self.auditor._load_resume_context = MagicMock(return_value=True)
        self.auditor.save_results = MagicMock()
        self.auditor._resume_scan_start_time = MagicMock(return_value=datetime.now())
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]

        resume_state = self._base_resume_state()
        result = self.auditor._resume_nuclei_from_state(
            resume_state=resume_state,
            resume_path="/tmp/resume.json",
            output_dir="/tmp/test_output",
            use_existing_results=False,
            save_after=True,
        )
        self.assertTrue(result)
        self.auditor._clear_nuclei_resume_state.assert_called_once()
        self.auditor.save_results.assert_called_once()

    @patch("redaudit.core.auditor.run_nuclei_scan")
    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.utils.session_log.start_session_log", return_value=False)
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    @patch("os.path.exists", return_value=True)
    @patch("os.remove")
    def test_resume_with_pending_after(
        self, mock_remove, mock_exists, mock_stop, mock_start, mock_gen, mock_nuclei, *args
    ):
        """Resume completes but some targets still pending."""
        mock_nuclei.return_value = {
            "success": True,
            "findings": [],
            "partial": True,
            "pending_targets": ["http://10.0.0.2"],
            "timeout_batches": ["batch_1"],  # strings, not lists
            "failed_batches": [],
            "budget_exceeded": True,
        }
        self.auditor._merge_nuclei_findings = MagicMock(return_value=0)
        self.auditor._append_nuclei_output = MagicMock()
        self.auditor._write_nuclei_resume_state = MagicMock(return_value="/tmp/resume.json")
        self.auditor._load_resume_context = MagicMock(return_value=True)
        self.auditor.save_results = MagicMock()
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]

        resume_state = self._base_resume_state()
        result = self.auditor._resume_nuclei_from_state(
            resume_state=resume_state,
            resume_path="/tmp/resume.json",
            output_dir="/tmp/test_output",
            use_existing_results=True,
            save_after=False,
        )
        self.assertTrue(result)
        self.auditor._write_nuclei_resume_state.assert_called()
        nuclei_res = self.auditor.results.get("nuclei", {})
        self.assertTrue(nuclei_res.get("budget_exceeded"))

    @patch("redaudit.core.auditor.run_nuclei_scan")
    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.utils.session_log.start_session_log", return_value=False)
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    @patch("os.path.exists", return_value=False)
    def test_resume_budget_override_keep(
        self, mock_exists, mock_stop, mock_start, mock_gen, mock_nuclei, *args
    ):
        """Resume with budget override prompt - user keeps budget."""
        mock_nuclei.return_value = {
            "success": True,
            "findings": [],
            "partial": False,
            "pending_targets": [],
            "timeout_batches": [],
            "failed_batches": [],
        }
        self.auditor._merge_nuclei_findings = MagicMock(return_value=0)
        self.auditor._append_nuclei_output = MagicMock()
        self.auditor._clear_nuclei_resume_state = MagicMock()
        self.auditor._write_nuclei_resume_state = MagicMock()
        self.auditor._load_resume_context = MagicMock(return_value=True)
        self.auditor.save_results = MagicMock()
        self.auditor.ask_yes_no = MagicMock(return_value=True)  # keep budget
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]

        resume_state = self._base_resume_state()
        resume_state["nuclei"]["max_runtime_minutes"] = 60
        result = self.auditor._resume_nuclei_from_state(
            resume_state=resume_state,
            resume_path="/tmp/resume.json",
            output_dir="/tmp/test_output",
            use_existing_results=True,
            save_after=False,
            prompt_budget_override=True,
        )
        self.assertTrue(result)

    @patch("redaudit.core.auditor.run_nuclei_scan")
    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.utils.session_log.start_session_log", return_value=False)
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    @patch("os.path.exists", return_value=False)
    def test_resume_budget_change(
        self, mock_exists, mock_stop, mock_start, mock_gen, mock_nuclei, *args
    ):
        """Resume with budget changed by user."""
        mock_nuclei.return_value = {
            "success": True,
            "findings": [],
            "partial": False,
            "pending_targets": [],
            "timeout_batches": [],
            "failed_batches": [],
        }
        self.auditor._merge_nuclei_findings = MagicMock(return_value=0)
        self.auditor._append_nuclei_output = MagicMock()
        self.auditor._clear_nuclei_resume_state = MagicMock()
        self.auditor._write_nuclei_resume_state = MagicMock()
        self.auditor._load_resume_context = MagicMock(return_value=True)
        self.auditor.save_results = MagicMock()
        self.auditor.ask_yes_no = MagicMock(return_value=False)  # don't keep budget
        self.auditor.ask_number = MagicMock(return_value=45)
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]

        resume_state = self._base_resume_state()
        resume_state["nuclei"]["max_runtime_minutes"] = 30
        result = self.auditor._resume_nuclei_from_state(
            resume_state=resume_state,
            resume_path="/tmp/resume.json",
            output_dir="/tmp/test_output",
            use_existing_results=True,
            save_after=False,
            prompt_budget_override=True,
        )
        self.assertTrue(result)

    @patch("redaudit.core.auditor.run_nuclei_scan")
    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.utils.session_log.start_session_log", return_value=False)
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    @patch("os.path.exists", return_value=False)
    def test_resume_with_override_max_runtime(
        self, mock_exists, mock_stop, mock_start, mock_gen, mock_nuclei, *args
    ):
        """Resume with override_max_runtime_minutes parameter."""
        mock_nuclei.return_value = {
            "success": True,
            "findings": [],
            "partial": False,
            "pending_targets": [],
            "timeout_batches": [],
            "failed_batches": [],
        }
        self.auditor._merge_nuclei_findings = MagicMock(return_value=0)
        self.auditor._append_nuclei_output = MagicMock()
        self.auditor._clear_nuclei_resume_state = MagicMock()
        self.auditor._write_nuclei_resume_state = MagicMock()
        self.auditor._load_resume_context = MagicMock(return_value=True)
        self.auditor.save_results = MagicMock()
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]

        resume_state = self._base_resume_state()
        result = self.auditor._resume_nuclei_from_state(
            resume_state=resume_state,
            resume_path="/tmp/resume.json",
            output_dir="/tmp/test_output",
            use_existing_results=True,
            save_after=False,
            override_max_runtime_minutes=120,
        )
        self.assertTrue(result)

    @patch("redaudit.core.auditor.run_nuclei_scan")
    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.utils.session_log.start_session_log", return_value=False)
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    @patch("os.path.exists", return_value=False)
    def test_resume_load_context_fails(
        self, mock_exists, mock_stop, mock_start, mock_gen, mock_nuclei, *args
    ):
        """Resume fails when load_resume_context returns False."""
        self.auditor._load_resume_context = MagicMock(return_value=False)
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]

        resume_state = self._base_resume_state()
        result = self.auditor._resume_nuclei_from_state(
            resume_state=resume_state,
            resume_path="/tmp/resume.json",
            output_dir="/tmp/test_output",
            use_existing_results=False,
            save_after=False,
        )
        self.assertFalse(result)


# ===========================================================================
# resume_nuclei_from_path
# ===========================================================================


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestResumeNucleiFromPath(unittest.TestCase):

    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.logger = MagicMock()
        self.auditor.proxy_manager = None

    def test_resume_no_state(self, *args):
        """No resume state found -> returns False."""
        self.auditor._load_nuclei_resume_state = MagicMock(return_value=None)
        result = self.auditor.resume_nuclei_from_path("/tmp/resume.json")
        self.assertFalse(result)

    def test_resume_keyboard_interrupt(self, *args):
        """KeyboardInterrupt during resume -> returns False."""
        self.auditor._load_nuclei_resume_state = MagicMock(side_effect=KeyboardInterrupt())
        result = self.auditor.resume_nuclei_from_path("/tmp/resume.json")
        self.assertFalse(result)

    def test_resume_directory_path(self, *args):
        """Path is a directory -> appends nuclei_resume.json."""
        with patch("os.path.isdir", return_value=True):
            self.auditor._load_nuclei_resume_state = MagicMock(return_value=None)
            result = self.auditor.resume_nuclei_from_path("/tmp/output_dir")
            self.assertFalse(result)
            load_call = self.auditor._load_nuclei_resume_state.call_args
            self.assertIn("nuclei_resume.json", str(load_call))


# ===========================================================================
# Net discovery progress block and exception handling
# ===========================================================================


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestNetDiscoveryProgress(unittest.TestCase):

    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.logger = MagicMock()

    def _wire_base_config(self):
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

    def _wire_scan_mocks(self):
        host = MagicMock()
        host.ip = "10.0.0.1"
        host.tags = set()
        host.ports = []
        host.services = []
        host.smart_scan = {}
        host.agentless_fingerprint = {}
        host.to_dict = MagicMock(return_value={"ip": "10.0.0.1"})

        self.auditor.scan_network_discovery = MagicMock(return_value=["10.0.0.1"])
        self.auditor.scanner.get_or_create_host = MagicMock(return_value=host)
        self.auditor.scan_hosts_concurrent = MagicMock(return_value=[host])
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
        return host

    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.core.auditor.maybe_chown_to_invoking_user")
    @patch("redaudit.utils.session_log.start_session_log")
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    @patch("redaudit.core.auditor.is_nuclei_available", return_value=False)
    @patch("redaudit.core.net_discovery.discover_networks")
    @patch("redaudit.core.net_discovery.detect_default_route_interface", return_value="eth0")
    def test_net_discovery_with_arp_and_upnp(
        self,
        mock_detect,
        mock_discover,
        mock_nuclei_avail,
        mock_stop,
        mock_start,
        mock_chown,
        mock_gen,
        *args,
    ):
        """Net discovery exercises the full progress block with ARP/UPnP/TCP results."""
        mock_discover.return_value = {
            "enabled": True,
            "dhcp_servers": [],
            "candidate_vlans": [],
            "hyperscan_duration": 1.5,
            "arp_hosts": ["10.0.0.5", "10.0.0.6"],
            "upnp_devices": [{"ip": "10.0.0.7", "name": "device1"}],
            "hyperscan_tcp_hosts": {"10.0.0.8": [80, 443]},
            "potential_backdoors": [],
        }

        self._wire_base_config()
        self._wire_scan_mocks()

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)
        nd = self.auditor.results.get("net_discovery", {})
        self.assertTrue(nd.get("enabled", False))

    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.core.auditor.maybe_chown_to_invoking_user")
    @patch("redaudit.utils.session_log.start_session_log")
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    @patch("redaudit.core.auditor.is_nuclei_available", return_value=False)
    @patch("redaudit.core.net_discovery.discover_networks")
    @patch("redaudit.core.net_discovery.detect_default_route_interface", return_value=None)
    def test_net_discovery_exception_caught(
        self,
        mock_detect,
        mock_discover,
        mock_nuclei_avail,
        mock_stop,
        mock_start,
        mock_chown,
        mock_gen,
        *args,
    ):
        """Net discovery exception is caught gracefully and scan still completes."""
        mock_discover.side_effect = RuntimeError("discovery failed")

        self._wire_base_config()
        self._wire_scan_mocks()
        # scan_network_discovery must still return valid IPs for rest of scan
        self.auditor.scan_network_discovery = MagicMock(return_value=[])

        result = self.auditor.run_complete_scan()
        # Scan completes without crashing even if net discovery fails
        # It may return True/False depending on other scan results
        self.assertIsInstance(result, bool)


# ===========================================================================
# Risk score recalculation
# ===========================================================================


class TestRiskRecalcAndPCAP(unittest.TestCase):

    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        patcher1 = patch("redaudit.core.power.SleepInhibitor")
        patcher2 = patch("redaudit.core.auditor._ActivityIndicator")
        patcher3 = patch("redaudit.core.auditor.NetworkScanner")
        patcher4 = patch("redaudit.core.auditor.run_iot_scope_probes")
        patcher5 = patch("redaudit.core.auditor.ScanWizardFlow")
        self.patchers = [patcher1, patcher2, patcher3, patcher4, patcher5]
        for p in self.patchers:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self.patchers])

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.logger = MagicMock()

    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.core.auditor.maybe_chown_to_invoking_user")
    @patch("redaudit.utils.session_log.start_session_log")
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    @patch("redaudit.core.auditor.is_nuclei_available", return_value=False)
    @patch("redaudit.core.siem.calculate_risk_score", return_value=85)
    def test_risk_score_recalculation(
        self, mock_risk, mock_nuclei_avail, mock_stop, mock_start, mock_chown, mock_gen
    ):
        """Risk scores are recalculated after all scans."""
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]
        self.auditor.config["max_hosts_value"] = "all"
        self.auditor.config["prevent_sleep"] = False
        self.auditor.config["scan_vulnerabilities"] = True
        self.auditor.config["scan_mode"] = "normal"
        self.auditor.config["nuclei_enabled"] = False
        self.auditor.config["auth_enabled"] = False
        self.auditor.config["cve_lookup_enabled"] = False
        self.auditor.config["topology_enabled"] = False
        self.auditor.config["net_discovery_enabled"] = False

        host = {"ip": "10.0.0.1", "ports": [], "services": [], "tags": []}
        self.auditor.scan_network_discovery = MagicMock(return_value=["10.0.0.1"])
        self.auditor.scanner.get_or_create_host = MagicMock(return_value=host)
        self.auditor.scan_hosts_concurrent = MagicMock(return_value=[host])
        self.auditor.run_agentless_verification = MagicMock()
        self.auditor.scan_vulnerabilities_concurrent = MagicMock()
        self.auditor.save_results = MagicMock()
        self.auditor.show_results = MagicMock()
        self.auditor.start_heartbeat = MagicMock()
        self.auditor.stop_heartbeat = MagicMock()
        self.auditor.proxy_manager = None
        self.auditor._run_hyperscan_discovery = MagicMock(return_value=None)
        self.auditor._filter_auditor_ips = MagicMock(side_effect=lambda x: x)
        self.auditor._build_scope_expansion_evidence = MagicMock(return_value=[])

        # Add vulnerability findings to trigger risk recalc
        self.auditor.results["vulnerabilities"] = [
            {"host": "10.0.0.1", "vulnerabilities": [{"severity": "high"}]}
        ]

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)
        self.assertEqual(host.get("risk_score"), 85)


if __name__ == "__main__":
    unittest.main()
