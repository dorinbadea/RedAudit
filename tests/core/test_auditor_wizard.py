"""Tests for interactive_setup wizard, nuclei scan block in run_complete_scan,
_merge_nuclei_findings, _run_hyperscan_discovery, and _resume_nuclei_from_state."""

import os
import json
import math
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, PropertyMock


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestInteractiveSetup(unittest.TestCase):
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

    @patch("redaudit.utils.config.get_persistent_defaults", return_value={})
    def test_setup_deps_fail(self, mock_defaults, *args):
        """Setup returns False when dependencies check fails."""
        self.auditor.clear_screen = MagicMock()
        self.auditor.print_banner = MagicMock()
        self.auditor.check_dependencies = MagicMock(return_value=False)
        result = self.auditor.interactive_setup()
        self.assertFalse(result)

    @patch("redaudit.utils.config.get_persistent_defaults", return_value={})
    def test_setup_legal_fail(self, mock_defaults, *args):
        """Setup returns False when legal warning rejected."""
        self.auditor.clear_screen = MagicMock()
        self.auditor.print_banner = MagicMock()
        self.auditor.check_dependencies = MagicMock(return_value=True)
        self.auditor.show_legal_warning = MagicMock(return_value=False)
        result = self.auditor.interactive_setup()
        self.assertFalse(result)

    @patch("redaudit.utils.config.get_persistent_defaults", return_value={})
    def test_setup_no_defaults(self, mock_defaults, *args):
        """Setup with no persisted defaults asks for network range."""
        self.auditor.clear_screen = MagicMock()
        self.auditor.print_banner = MagicMock()
        self.auditor.check_dependencies = MagicMock(return_value=True)
        self.auditor.show_legal_warning = MagicMock(return_value=True)
        self.auditor.ask_network_range = MagicMock(return_value=["10.0.0.0/24"])
        self.auditor._configure_scan_interactive = MagicMock()
        self.auditor._show_target_summary = MagicMock()
        self.auditor.show_config_summary = MagicMock()
        self.auditor.ask_yes_no = MagicMock(side_effect=[False, True])  # save=no, start=yes

        result = self.auditor.interactive_setup()
        self.assertTrue(result)
        self.auditor.ask_network_range.assert_called_once()

    @patch("redaudit.utils.config.get_persistent_defaults")
    def test_setup_with_defaults_use(self, mock_defaults, *args):
        """Setup with persisted defaults, user chooses to use them."""
        mock_defaults.return_value = {"target_networks": ["10.0.0.0/24"], "scan_mode": "normal"}
        self.auditor.clear_screen = MagicMock()
        self.auditor.print_banner = MagicMock()
        self.auditor.check_dependencies = MagicMock(return_value=True)
        self.auditor.show_legal_warning = MagicMock(return_value=True)
        self.auditor.defaults_mode = "ask"
        self.auditor.ask_choice = MagicMock(return_value=0)  # "Use defaults"
        self.auditor._apply_run_defaults = MagicMock()
        self.auditor._show_target_summary = MagicMock()
        self.auditor.show_config_summary = MagicMock()

        result = self.auditor.interactive_setup()
        self.assertTrue(result)  # auto_start=True
        self.auditor._apply_run_defaults.assert_called_once()

    @patch("redaudit.utils.config.get_persistent_defaults")
    def test_setup_with_defaults_ignore(self, mock_defaults, *args):
        """Setup with persisted defaults, user chooses to ignore them."""
        mock_defaults.return_value = {"scan_mode": "completo"}
        self.auditor.clear_screen = MagicMock()
        self.auditor.print_banner = MagicMock()
        self.auditor.check_dependencies = MagicMock(return_value=True)
        self.auditor.show_legal_warning = MagicMock(return_value=True)
        self.auditor.defaults_mode = "ask"
        self.auditor.ask_choice = MagicMock(return_value=2)  # "Ignore"
        self.auditor.ask_network_range = MagicMock(return_value=["10.0.0.0/24"])
        self.auditor._configure_scan_interactive = MagicMock()
        self.auditor._show_target_summary = MagicMock()
        self.auditor.show_config_summary = MagicMock()
        self.auditor.ask_yes_no = MagicMock(side_effect=[False, True])

        result = self.auditor.interactive_setup()
        self.assertTrue(result)

    @patch("redaudit.utils.config.get_persistent_defaults")
    def test_setup_defaults_review(self, mock_defaults, *args):
        """Setup reviews defaults with summary."""
        mock_defaults.return_value = {"scan_mode": "normal"}
        self.auditor.clear_screen = MagicMock()
        self.auditor.print_banner = MagicMock()
        self.auditor.check_dependencies = MagicMock(return_value=True)
        self.auditor.show_legal_warning = MagicMock(return_value=True)
        self.auditor.defaults_mode = "ask"
        self.auditor.ask_choice = MagicMock(return_value=1)  # "Review"
        self.auditor.ask_yes_no = MagicMock(
            side_effect=[True, False, True]
        )  # show_summary=yes, save=no, start=yes
        self.auditor._show_defaults_summary = MagicMock()
        self.auditor.ask_network_range = MagicMock(return_value=["10.0.0.0/24"])
        self.auditor._configure_scan_interactive = MagicMock()
        self.auditor._show_target_summary = MagicMock()
        self.auditor.show_config_summary = MagicMock()

        result = self.auditor.interactive_setup()
        self.assertTrue(result)
        self.auditor._show_defaults_summary.assert_called_once()

    @patch("redaudit.utils.config.get_persistent_defaults")
    @patch("redaudit.utils.config.update_persistent_defaults", return_value=True)
    def test_setup_save_defaults(self, mock_update, mock_defaults, *args):
        """Setup saves defaults when user opts in."""
        mock_defaults.return_value = {}
        self.auditor.clear_screen = MagicMock()
        self.auditor.print_banner = MagicMock()
        self.auditor.check_dependencies = MagicMock(return_value=True)
        self.auditor.show_legal_warning = MagicMock(return_value=True)
        self.auditor.ask_network_range = MagicMock(return_value=["10.0.0.0/24"])
        self.auditor._configure_scan_interactive = MagicMock()
        self.auditor._show_target_summary = MagicMock()
        self.auditor.show_config_summary = MagicMock()
        self.auditor.ask_yes_no = MagicMock(side_effect=[True, True])  # save=yes, start=yes

        result = self.auditor.interactive_setup()
        self.assertTrue(result)
        mock_update.assert_called_once()

    @patch("redaudit.utils.config.get_persistent_defaults")
    def test_setup_defaults_mode_ignore(self, mock_defaults, *args):
        """Setup with defaults_mode='ignore' skips defaults."""
        mock_defaults.return_value = {"scan_mode": "completo"}
        self.auditor.clear_screen = MagicMock()
        self.auditor.print_banner = MagicMock()
        self.auditor.check_dependencies = MagicMock(return_value=True)
        self.auditor.show_legal_warning = MagicMock(return_value=True)
        self.auditor.defaults_mode = "ignore"
        self.auditor.ask_network_range = MagicMock(return_value=["10.0.0.0/24"])
        self.auditor._configure_scan_interactive = MagicMock()
        self.auditor._show_target_summary = MagicMock()
        self.auditor.show_config_summary = MagicMock()
        self.auditor.ask_yes_no = MagicMock(side_effect=[False, True])

        result = self.auditor.interactive_setup()
        self.assertTrue(result)


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestNucleiScanBlock(unittest.TestCase):
    """Test the nuclei scan block within run_complete_scan."""

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
    @patch("redaudit.core.auditor.is_nuclei_available", return_value=True)
    @patch("redaudit.core.auditor.select_nuclei_targets")
    @patch("redaudit.core.auditor.extract_leak_follow_candidates", return_value=[])
    @patch("redaudit.core.auditor.evaluate_leak_follow_candidates")
    @patch("redaudit.core.auditor.build_leak_follow_targets", return_value=[])
    @patch("redaudit.core.auditor.run_nuclei_scan")
    def test_nuclei_scan_within_complete_scan(
        self,
        mock_nuclei,
        mock_leak_targets,
        mock_eval_leak,
        mock_extract_leak,
        mock_select,
        mock_nuclei_avail,
        mock_stop,
        mock_start,
        mock_chown,
        mock_gen,
        *args,
    ):
        """Nuclei scan executes when conditions met."""
        mock_eval_leak.return_value = {"mode": "off", "detected": 0, "eligible": 0}
        mock_select.return_value = {
            "targets": ["http://10.0.0.1"],
            "targets_total": 1,
            "targets_exception": 0,
            "targets_optimized": 0,
            "targets_excluded": 0,
            "selected_by_host": {"10.0.0.1": ["http://10.0.0.1"]},
            "exception_targets": set(),
        }
        mock_nuclei.return_value = {
            "success": True,
            "findings": [],
            "partial": False,
            "pending_targets": [],
            "raw_output_file": None,
        }

        self.auditor.config["target_networks"] = ["10.0.0.0/24"]
        self.auditor.config["max_hosts_value"] = "all"
        self.auditor.config["prevent_sleep"] = False
        self.auditor.config["scan_vulnerabilities"] = True
        self.auditor.config["scan_mode"] = "completo"
        self.auditor.config["nuclei_enabled"] = True
        self.auditor.config["nuclei_profile"] = "balanced"
        self.auditor.config["nuclei_timeout"] = 300
        self.auditor.config["nuclei_max_runtime"] = 0
        self.auditor.config["nuclei_fatigue_limit"] = 3
        self.auditor.config["nuclei_full_coverage"] = False
        self.auditor.config["auth_enabled"] = False
        self.auditor.config["cve_lookup_enabled"] = False
        self.auditor.config["topology_enabled"] = False
        self.auditor.config["net_discovery_enabled"] = False
        self.auditor.config["iot_probes_mode"] = "off"

        host_mock = MagicMock()
        host_mock.ip = "10.0.0.1"
        host_mock.smart_scan = {}
        host_mock.to_dict = MagicMock(return_value={"ip": "10.0.0.1"})
        self.auditor.scan_network_discovery = MagicMock(return_value=["10.0.0.1"])
        self.auditor.scanner.get_or_create_host = MagicMock(return_value=host_mock)
        self.auditor.scan_hosts_concurrent = MagicMock(return_value=[host_mock])
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
        self.auditor._merge_nuclei_findings = MagicMock(return_value=0)

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)
        mock_nuclei.assert_called_once()
        self.assertIn("nuclei", self.auditor.results)


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestResumeNucleiFromState(unittest.TestCase):
    """Test the _resume_nuclei_from_state method."""

    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.logger = MagicMock()

    @patch("redaudit.core.auditor.run_nuclei_scan")
    @patch("redaudit.utils.session_log.start_session_log", return_value=True)
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    def test_resume_empty_targets(self, mock_stop, mock_start, mock_nuclei, *args):
        """Returns False when no pending targets."""
        state = {"pending_targets": [], "nuclei": {}}
        result = self.auditor._resume_nuclei_from_state(
            resume_state=state,
            resume_path="/tmp/r.json",
            output_dir="/tmp",
            use_existing_results=True,
            save_after=False,
        )
        self.assertFalse(result)

    @patch("redaudit.core.auditor.run_nuclei_scan")
    @patch("redaudit.utils.session_log.start_session_log", return_value=True)
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    def test_resume_success(self, mock_stop, mock_start, mock_nuclei, *args):
        """Successful resume scan."""
        mock_nuclei.return_value = {
            "success": True,
            "findings": [],
            "partial": False,
            "pending_targets": [],
            "raw_output_file": None,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            state = {
                "pending_targets": ["http://10.0.0.1"],
                "nuclei": {
                    "profile": "balanced",
                    "severity": "high",
                    "timeout_s": 300,
                    "request_timeout_s": 10,
                    "retries": 1,
                    "batch_size": 10,
                    "max_runtime_minutes": 0,
                    "fatigue_limit": 3,
                },
                "output_file": "nuclei_output.json",
                "profile_selected": "balanced",
                "profile_effective": "balanced",
            }
            self.auditor.config["prevent_sleep"] = False
            self.auditor.config["dry_run"] = False
            self.auditor.proxy_manager = None
            self.auditor._merge_nuclei_findings = MagicMock(return_value=0)
            self.auditor._append_nuclei_output = MagicMock()

            result = self.auditor._resume_nuclei_from_state(
                resume_state=state,
                resume_path=os.path.join(tmpdir, "r.json"),
                output_dir=tmpdir,
                use_existing_results=True,
                save_after=False,
            )
            self.assertTrue(result)

    @patch("redaudit.core.auditor.run_nuclei_scan")
    @patch("redaudit.utils.session_log.start_session_log", return_value=True)
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    def test_resume_with_override_max_runtime(self, mock_stop, mock_start, mock_nuclei, *args):
        """Resume with override_max_runtime_minutes."""
        mock_nuclei.return_value = {
            "success": True,
            "findings": [],
            "partial": False,
            "pending_targets": [],
            "raw_output_file": None,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            state = {
                "pending_targets": ["http://10.0.0.1"],
                "nuclei": {
                    "profile": "fast",
                    "timeout_s": 300,
                    "batch_size": 10,
                    "max_runtime_minutes": 30,
                },
                "output_file": "nuclei_output.json",
            }
            self.auditor.config["prevent_sleep"] = False
            self.auditor.config["dry_run"] = False
            self.auditor.proxy_manager = None
            self.auditor._merge_nuclei_findings = MagicMock(return_value=0)
            self.auditor._append_nuclei_output = MagicMock()

            result = self.auditor._resume_nuclei_from_state(
                resume_state=state,
                resume_path=os.path.join(tmpdir, "r.json"),
                output_dir=tmpdir,
                use_existing_results=True,
                save_after=False,
                override_max_runtime_minutes=60,
            )
            self.assertTrue(result)


class TestMergeAndHyperscan(unittest.TestCase):
    def setUp(self):
        with (
            patch("redaudit.core.auditor.NetworkScanner"),
            patch("redaudit.core.auditor.ScanWizardFlow"),
            patch("redaudit.core.auditor.run_iot_scope_probes"),
            patch("redaudit.core.auditor._ActivityIndicator"),
        ):
            from redaudit.core.auditor import InteractiveNetworkAuditor

            self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.logger = MagicMock()

    def test_merge_nuclei_findings_empty(self):
        """Merge with empty findings."""
        result = self.auditor._merge_nuclei_findings([])
        self.assertEqual(result, 0)

    def test_merge_nuclei_findings_with_data(self):
        """Merge nuclei findings into results."""
        findings = [
            {
                "template_id": "xss",
                "matched_at": "http://10.0.0.1",
                "host": "10.0.0.1",
                "severity": "high",
                "name": "XSS",
            },
        ]
        result = self.auditor._merge_nuclei_findings(findings)
        self.assertEqual(result, 1)
        self.assertIn("vulnerabilities", self.auditor.results)

    def test_format_eta(self):
        """Test _format_eta helper."""
        result = self.auditor._format_eta(3661)
        self.assertIn("1:01", result)

    def test_format_eta_zero(self):
        """Test _format_eta with zero seconds."""
        result = self.auditor._format_eta(0)
        self.assertIsInstance(result, str)


if __name__ == "__main__":
    unittest.main()
