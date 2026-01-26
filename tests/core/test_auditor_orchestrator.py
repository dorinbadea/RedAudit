#!/usr/bin/env python3
"""
RedAudit - Orchestrator Logic Tests
Tests for InteractiveNetworkAuditor high-level flows, error handling, and cleanup.
"""

import contextlib
import json
import os
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.core.auditor_runtime import AuditorRuntime
from redaudit.core.config_context import ConfigurationContext
from redaudit.core.models import Host
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
        self.auditor.ask_number = MagicMock(return_value=0)
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

    def test_configure_scan_profile_standard_aggressive(self):
        """Test Standard profile with Aggressive timing enables max threads."""
        self.auditor.ui = MagicMock()
        self.auditor.ui.t.side_effect = lambda key, *args: key
        self.auditor.ask_choice = MagicMock()
        self.auditor.ask_yes_no = MagicMock()
        self.auditor.ask_number = MagicMock(return_value=0)
        self.auditor._ask_auditor_and_output_dir = MagicMock()
        self.auditor.ask_auth_config = MagicMock(return_value={})

        # Profile 1 (Standard), Timing 2 (Aggressive)
        self.auditor.ask_choice.side_effect = [1, 2]
        self.auditor.ask_yes_no.side_effect = [False, True]

        self.auditor._configure_scan_interactive({})
        self.assertEqual(self.auditor.config["threads"], MAX_THREADS)

    def test_configure_scan_profile_exhaustive(self):
        """Test _configure_scan_interactive selecting Exhaustive profile with Nuclei enabled."""
        self.auditor.ui = MagicMock()
        self.auditor.ui.t.side_effect = lambda key, *args: key
        self.auditor.ask_choice = MagicMock()
        self.auditor.ask_yes_no = MagicMock()
        self.auditor._runtime.ask_number = MagicMock(return_value=0)
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

    def test_config_setter_and_target_summary(self):
        self.auditor.config = {"target_networks": ["192.168.1.0/30", "bad"]}
        self.assertIsInstance(self.auditor.cfg, ConfigurationContext)
        self.auditor._show_target_summary()
        calls = [c.args[0] for c in self.auditor.ui.print_status.call_args_list]
        self.assertTrue(any("targets_normalized" in call for call in calls))
        self.assertTrue(any("targets_total" in call for call in calls))

    def test_config_setter_accepts_context(self):
        ctx = ConfigurationContext({"target_networks": []})
        self.auditor.config = ctx
        self.assertIs(self.auditor.cfg, ctx)

    def test_show_config_summary_invokes_helper(self):
        with patch("redaudit.core.auditor.show_config_summary") as mock_summary:
            self.auditor.show_config_summary()
        self.assertTrue(mock_summary.called)

    def test_show_target_summary_empty_targets(self):
        self.auditor.config["target_networks"] = None
        self.auditor._show_target_summary()

    def test_show_target_summary_skips_blank(self):
        self.auditor.config["target_networks"] = ["", "10.0.0.0/30"]
        self.auditor._show_target_summary()
        self.assertTrue(self.auditor.ui.print_status.called)


def test_auditor_runtime_getattr_reads_auditor_dict():
    class _Dummy:
        def __init__(self):
            self.value = "ok"

    auditor = _Dummy()
    runtime = AuditorRuntime(auditor)
    assert runtime.__getattr__("value") == "ok"


def test_auditor_runtime_setattr_auditor():
    class _Dummy:
        pass

    auditor = _Dummy()
    runtime = AuditorRuntime(auditor)
    replacement = _Dummy()
    runtime._auditor = replacement
    assert runtime._auditor is replacement


class TestAuditorOrchestratorExtras(unittest.TestCase):
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

    def test_show_legal_warning_calls_prompt(self):
        self.auditor.ask_yes_no = MagicMock(return_value=True)
        result = self.auditor.show_legal_warning()
        self.assertTrue(result)
        self.assertTrue(self.auditor.ask_yes_no.called)

    def test_save_results_sets_lang_and_phase(self):
        self.auditor.config["lang"] = None
        self.auditor.lang = "es"
        with patch("redaudit.core.auditor.save_results") as mock_save:
            self.auditor.save_results()
        self.assertEqual(self.auditor.current_phase, "saving")
        self.assertEqual(self.auditor.config["lang"], "es")
        self.assertTrue(mock_save.called)

    def test_filter_auditor_ips_fallback_networks(self):
        self.auditor.results["network_info"] = []
        self.auditor.results["topology"] = {}
        with patch(
            "redaudit.core.auditor.detect_all_networks",
            return_value=[{"ip": "10.0.0.5", "interface": "eth0"}],
        ):
            filtered = self.auditor._filter_auditor_ips(["10.0.0.5", "10.0.0.6"])
        self.assertNotIn("10.0.0.5", filtered)
        self.assertIn("10.0.0.6", filtered)

    def test_filter_auditor_ips_fallback_hostname(self):
        self.auditor.results["network_info"] = [{"ip": None, "interface": "eth0"}]
        self.auditor.results["topology"] = {}
        with (
            patch("redaudit.core.auditor.detect_all_networks", side_effect=RuntimeError("fail")),
            patch("socket.gethostbyname_ex", return_value=("host", [], ["10.0.0.8"])),
        ):
            filtered = self.auditor._filter_auditor_ips(["10.0.0.8", "10.0.0.9"])
        self.assertNotIn("10.0.0.8", filtered)
        self.assertIn("10.0.0.9", filtered)

    def test_filter_auditor_ips_fallback_udp_route(self):
        self.auditor.results["network_info"] = []
        self.auditor.results["topology"] = {}
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("10.0.0.9", 0)
        with (
            patch("redaudit.core.auditor.detect_all_networks", side_effect=RuntimeError("fail")),
            patch("socket.gethostbyname_ex", side_effect=OSError("fail")),
            patch("socket.socket", return_value=mock_sock),
        ):
            filtered = self.auditor._filter_auditor_ips(["10.0.0.9", "10.0.0.10"])
        self.assertNotIn("10.0.0.9", filtered)
        self.assertIn("10.0.0.10", filtered)

    def test_kill_all_subprocesses_error_path(self):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.terminate.side_effect = RuntimeError("boom")
        self.auditor.logger = MagicMock()
        self.auditor._active_subprocesses = [mock_proc]
        with patch("shutil.which", return_value=None):
            self.auditor.kill_all_subprocesses()
        self.assertTrue(self.auditor.logger.debug.called)

    def test_signal_handler_exits_before_scan(self):
        self.auditor.scan_start_time = None
        self.auditor.stop_heartbeat = MagicMock()
        with self.assertRaises(SystemExit):
            self.auditor.signal_handler(None, None)

    def test_ask_auditor_and_output_dir(self):
        self.auditor.ui = MagicMock()
        self.auditor.ui.colors = COLORS
        self.auditor.ui.t.side_effect = lambda key, *args: key
        defaults = {"auditor_name": "Alice", "output_dir": "/tmp/reports"}
        with (
            patch("builtins.input", side_effect=["", ""]),
            patch("redaudit.core.auditor.get_default_reports_base_dir", return_value="/tmp"),
            patch("redaudit.core.auditor.expand_user_path", side_effect=lambda p: p),
        ):
            self.auditor._ask_auditor_and_output_dir(defaults)
        self.assertEqual(self.auditor.config["auditor_name"], "Alice")
        self.assertEqual(self.auditor.config["output_dir"], "/tmp/reports")

    def test_show_defaults_summary(self):
        self.auditor.ui = MagicMock()
        self.auditor.ui.t.side_effect = lambda key, *args: key
        defaults = {
            "target_networks": ["10.0.0.0/24", "192.168.1.0/24"],
            "scan_mode": "normal",
            "threads": 4,
            "output_dir": "/tmp/out",
            "rate_limit": 1,
            "udp_mode": "quick",
            "udp_top_ports": 100,
            "topology_enabled": True,
            "net_discovery_enabled": False,
            "scan_vulnerabilities": True,
            "nuclei_enabled": False,
            "cve_lookup_enabled": True,
            "generate_txt": True,
            "generate_html": False,
            "windows_verify_enabled": True,
        }
        self.auditor._show_defaults_summary(defaults)
        self.assertTrue(self.auditor.ui.print_status.called)

    def test_show_defaults_summary_empty_targets(self):
        self.auditor.ui = MagicMock()
        self.auditor.ui.t.side_effect = lambda key, *args: key
        self.auditor._show_defaults_summary({"target_networks": []})
        self.assertTrue(self.auditor.ui.print_status.called)

    def test_apply_run_defaults_windows_verify_targets(self):
        self.auditor._apply_run_defaults({"windows_verify_max_targets": 50})
        self.assertEqual(self.auditor.config["windows_verify_max_targets"], 50)

    def test_progress_callbacks(self):
        progress = MagicMock()
        progress.console = MagicMock()
        self.auditor._touch_activity = MagicMock()
        start_time = time.time() - 31
        self.auditor._nd_progress_callback(
            "label" * 10,
            1,
            2,
            progress,
            "task",
            start_time,
        )
        progress.update.assert_called()
        progress.console.print.assert_called()

        self.auditor._format_eta = lambda *_a: "00:00"
        self.auditor._nuclei_progress_callback(
            completed=1,
            total=4,
            eta="",
            progress=progress,
            task="task",
            start_time=time.time() - 1,
            timeout=30,
            total_targets=10,
            batch_size=2,
            detail="running",
        )
        progress.update.assert_called()

    def test_nd_progress_callback_without_console(self):
        class _Progress:
            def update(self, *_a, **_k):
                return None

        progress = _Progress()
        self.auditor._touch_activity = MagicMock()
        self.auditor.ui.print_status = MagicMock()
        self.auditor._nd_progress_callback(
            "label",
            2,
            2,
            progress,
            "task",
            time.time() - 31,
        )
        self.assertTrue(self.auditor.ui.print_status.called)

    def test_nuclei_progress_callback_resets_targets(self):
        progress = MagicMock()
        self.auditor._touch_activity = MagicMock()
        self.auditor._format_eta = lambda *_a: "00:00"
        self.auditor._nuclei_progress_state = {"total_targets": 10, "max_targets": 5}
        self.auditor._nuclei_progress_callback(
            completed=1,
            total=10,
            eta="",
            progress=progress,
            task="task",
            start_time=time.time() - 1,
            timeout=30,
            total_targets=0,
            batch_size=2,
            detail="running",
        )
        self.assertTrue(progress.update.called)

    def test_nd_progress_callback_handles_exception(self):
        class _Progress:
            def update(self, *_a, **_k):
                raise RuntimeError("boom")

        progress = _Progress()
        self.auditor._touch_activity = MagicMock()
        self.auditor._nd_progress_callback("label", 1, 1, progress, "task", time.time())

    def test_nuclei_progress_callback_handles_exception(self):
        progress = MagicMock()
        progress.update.side_effect = RuntimeError("boom")
        self.auditor._touch_activity = MagicMock()
        self.auditor._format_eta = lambda *_a: "00:00"
        self.auditor._nuclei_progress_callback(
            completed=1,
            total=1,
            eta="",
            progress=progress,
            task="task",
            start_time=time.time() - 1,
            timeout=30,
            total_targets=1,
            batch_size=1,
            detail="running",
        )

    def test_process_snmp_topology_follow_routes(self):
        self.auditor.ui = MagicMock()
        self.auditor.ui.t.side_effect = lambda key, *args: key
        self.auditor.config["target_networks"] = ["192.168.1.0/24"]
        self.auditor.config["follow_routes"] = True
        self.auditor.scan_network_discovery = MagicMock(return_value=["10.10.0.10"])
        self.auditor.scan_hosts_concurrent = MagicMock(return_value=[Host(ip="10.10.0.10")])
        self.auditor.scanner = MagicMock()
        self.auditor.scanner.get_or_create_host.side_effect = lambda ip: Host(ip=ip)
        with patch("redaudit.core.auditor.enrich_host_with_cves") as mock_enrich:
            hosts = [
                {
                    "ip": "10.0.0.1",
                    "auth_scan": {"routes": [{"dest": "10.10.0.0", "mask": "255.255.255.0"}]},
                }
            ]
            self.auditor._process_snmp_topology(hosts, api_key="key")
            self.assertTrue(mock_enrich.called)

    def test_process_snmp_topology_filters_and_returns(self):
        self.auditor.ui = MagicMock()
        self.auditor.ui.t.side_effect = lambda key, *args: key
        self.auditor.config["target_networks"] = ["10.10.0.0/24", "bad"]
        self.auditor.config["follow_routes"] = False

        host_obj = Host(ip="10.0.0.1")
        host_obj.auth_scan = {
            "routes": [
                {"dest": "0.0.0.0", "mask": "0.0.0.0"},
                {"dest": "10.10.0.0", "mask": "255.255.255.0"},
                {"dest": "10.0.0.0", "mask": "255.255.255.255"},
                {"dest": "bad", "mask": "255.255.255.0"},
                {"dest": "10.0.0.0"},
            ]
        }
        host_missing = {"ip": "10.0.0.2", "auth_scan": None}
        host_no_routes = {"ip": "10.0.0.3", "auth_scan": {}}

        self.auditor._process_snmp_topology([host_obj, host_missing, host_no_routes])

    def test_process_snmp_topology_follow_routes_interrupts(self):
        self.auditor.ui = MagicMock()
        self.auditor.ui.t.side_effect = lambda key, *args: key
        self.auditor.config["target_networks"] = ["192.168.1.0/24"]
        self.auditor.config["follow_routes"] = True
        self.auditor.interrupted = False

        host_obj = Host(ip="192.168.1.10")
        host_obj.auth_scan = {
            "routes": [
                {"dest": "10.10.0.0", "mask": "255.255.255.0"},
                {"dest": "10.20.0.0", "mask": "255.255.255.0"},
            ]
        }
        self.auditor.scanner = MagicMock()
        self.auditor.scanner.get_or_create_host.side_effect = lambda ip: Host(ip=ip)

        def _scan(cidr):
            if cidr == "10.10.0.0/24":
                self.auditor.interrupted = True
            return ["10.10.0.2"]

        self.auditor.scan_network_discovery = MagicMock(side_effect=_scan)
        self.auditor.scan_hosts_concurrent = MagicMock(return_value=[Host(ip="10.10.0.2")])
        with patch("redaudit.core.auditor.enrich_host_with_cves", side_effect=RuntimeError("boom")):
            self.auditor._process_snmp_topology([host_obj], api_key="key")

    def test_process_snmp_topology_no_follow_routes(self):
        self.auditor.ui = MagicMock()
        self.auditor.ui.t.side_effect = lambda key, *args: key
        self.auditor.config["target_networks"] = ["192.168.1.0/24"]
        self.auditor.config["follow_routes"] = False
        hosts = [
            {
                "ip": "10.0.0.1",
                "auth_scan": {"routes": [{"dest": "10.10.0.0", "mask": "255.255.255.0"}]},
            }
        ]
        self.auditor._process_snmp_topology(hosts)
        calls = [c.args[0] for c in self.auditor.ui.print_status.call_args_list]
        self.assertTrue(any("Use --follow-routes" in call for call in calls))

    def test_run_authenticated_scans(self):
        class _SSHError(Exception):
            pass

        class _FakeSSHScanner:
            def __init__(self, _cred, timeout=30, trust_unknown_keys=True):
                self._ip = None

            def connect(self, ip, port=22):
                self._ip = ip

            def gather_host_info(self):
                if self._ip == "10.0.0.3":
                    raise _SSHError("boom")
                return SimpleNamespace(
                    os_name="Linux",
                    os_version="1",
                    kernel="k",
                    hostname="host",
                    packages=[1],
                    services=[1],
                    users=[1],
                )

            def close(self):
                return None

        class _FakeLynisScanner:
            def __init__(self, _scanner):
                pass

            def run_audit(self, use_portable=True):
                return SimpleNamespace(
                    hardening_index=50,
                    warnings=[],
                    suggestions=[],
                    tests_performed=10,
                )

        self.auditor.ui = MagicMock()
        self.auditor.ui.t.side_effect = lambda key, *args: key
        self.auditor.logger = MagicMock()
        self.auditor.config["auth_credentials"] = [{"user": "root", "pass": "x"}]

        host_dict = {"ip": "10.0.0.1", "ports": [{"port": 22, "service": "ssh"}]}
        host_obj = Host(ip="10.0.0.2")
        host_obj.ports = [{"port": 2222, "service": "ssh"}]
        host_fail = {"ip": "10.0.0.3", "ports": [{"port": 22, "service": "ssh"}]}

        with (
            patch("redaudit.core.auth_ssh.SSHScanner", _FakeSSHScanner),
            patch("redaudit.core.auth_ssh.SSHConnectionError", _SSHError),
            patch("redaudit.core.auth_lynis.LynisScanner", _FakeLynisScanner),
        ):
            self.auditor._run_authenticated_scans([host_dict, host_obj, host_fail])

        self.assertIn("auth_ssh", host_dict)
        self.assertIn("ssh", host_obj.auth_scan)
        self.assertTrue(self.auditor.results["auth_scan"]["ssh_success"])


def test_run_complete_scan_with_nuclei_and_cve(tmp_path, monkeypatch):
    mock_ui = MagicMock()
    mock_ui.colors = COLORS
    mock_ui.t.side_effect = lambda key, *args: key
    mock_ui.print_status = MagicMock()

    with patch("redaudit.core.ui_manager.UIManager", return_value=mock_ui):
        auditor = InteractiveNetworkAuditor()

    auditor.logger = MagicMock()
    auditor.start_heartbeat = MagicMock()
    auditor.stop_heartbeat = MagicMock()
    auditor._progress_ui = contextlib.nullcontext
    auditor._progress_console = lambda: None
    auditor._progress_columns = lambda **_k: []
    auditor._safe_text_column = lambda *_a, **_k: ""
    auditor._format_eta = lambda *_a: "00:00"
    auditor._touch_activity = MagicMock()

    auditor.config.update(
        {
            "prevent_sleep": False,
            "topology_enabled": False,
            "net_discovery_enabled": True,
            "scan_mode": "completo",
            "target_networks": ["10.0.0.0/24"],
            "scan_vulnerabilities": True,
            "nuclei_enabled": True,
            "cve_lookup_enabled": True,
            "threads": 2,
            "max_hosts_value": 2,
            "nuclei_profile": "balanced",
            "output_dir": str(tmp_path),
        }
    )

    auditor.scanner = MagicMock()
    auditor.scanner.detect_local_networks.return_value = [
        {"interface": "eth0", "ip": "10.0.0.1", "ip_version": 4}
    ]

    def _make_host(ip):
        host = Host(ip=ip)
        host.services = []
        host.ports = []
        host.tags = set()
        return host

    auditor.scanner.get_or_create_host.side_effect = _make_host
    auditor._select_net_discovery_interface = MagicMock(return_value="eth0")
    auditor.scan_network_discovery = MagicMock(
        return_value=["10.0.0.1", "10.0.0.1", "\x1b[31m10.0.0.2\x1b[0m"]
    )
    auditor._filter_auditor_ips = lambda hosts: hosts
    auditor._run_hyperscan_discovery = MagicMock(return_value={"10.0.0.2": {}})

    host_obj = Host(ip="10.0.0.2", web_ports_count=1)
    host_obj.smart_scan = {"trigger_deep": True, "deep_scan_executed": False}
    host_dict = {"ip": "10.0.0.1", "web_ports_count": 1}
    auditor.scan_hosts_concurrent = MagicMock(return_value=[host_obj, host_dict])

    auditor.run_deep_scans_concurrent = MagicMock()
    auditor.run_agentless_verification = MagicMock()
    auditor.scan_vulnerabilities_concurrent = MagicMock()
    auditor.setup_nvd_api_key = MagicMock()

    net_discovery_result = {
        "dhcp_servers": [{"ip": "10.0.0.254"}],
        "candidate_vlans": [{"id": 100}],
        "hyperscan_duration": 1.0,
        "arp_hosts": [{"ip": "10.0.0.5"}],
        "upnp_devices": [{"ip": "10.0.0.6", "device": "IoT (camera)"}],
        "hyperscan_tcp_hosts": {"10.0.0.7": {}},
        "potential_backdoors": [{"ip": "10.0.0.8"}],
        "l2_warning_note": "warn",
        "hyperscan_udp_ports": {"10.0.0.2": [161]},
    }

    monkeypatch.setattr(
        "redaudit.core.net_discovery.discover_networks",
        lambda *_a, **_k: net_discovery_result,
    )
    monkeypatch.setattr("redaudit.core.auditor.is_nuclei_available", lambda: True)
    monkeypatch.setattr(
        "redaudit.core.auditor.get_http_targets_from_hosts",
        lambda *_a, **_k: [
            "http://10.0.0.1:80",
            "https://10.0.0.1:443",
            "http://10.0.0.1:8080",
            "http://10.0.0.2:80",
        ],
    )
    monkeypatch.setattr("redaudit.core.auditor.get_api_key_from_config", lambda: "key")
    monkeypatch.setattr("redaudit.core.auditor.enrich_host_with_cves", lambda h, **_k: h)
    monkeypatch.setattr("redaudit.core.siem.calculate_risk_score", lambda *_a, **_k: 7.0)
    monkeypatch.setattr(
        "redaudit.core.scanner.traffic.finalize_pcap_artifacts",
        lambda **_k: {"merged_file": str(tmp_path / "merged.pcap"), "individual_count": 1},
    )

    raw_file = tmp_path / "nuclei.json"
    raw_file.write_text("[]", encoding="utf-8")

    def _fake_nuclei_scan(*_a, **kwargs):
        cb = kwargs.get("progress_callback")
        if cb:
            cb(1, 2, "running", detail="running")
        return {
            "findings": [
                {"host": "10.0.0.1:80", "template_id": "t1", "matched_at": "http://10.0.0.1"}
            ],
            "success": True,
            "partial": True,
            "timeout_batches": [1],
            "failed_batches": [2],
            "raw_output_file": str(raw_file),
        }

    monkeypatch.setattr("redaudit.core.auditor.run_nuclei_scan", _fake_nuclei_scan)
    monkeypatch.setattr(
        "redaudit.core.verify_vuln.filter_nuclei_false_positives",
        lambda findings, *_a, **_k: (findings, [{"template_id": "t2", "matched_at": "x"}]),
    )

    class _Progress:
        def __init__(self, *_a, **_k):
            self.console = MagicMock()

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def add_task(self, *_a, **_k):
            return "task"

        def update(self, *_a, **_k):
            return None

    monkeypatch.setattr("rich.progress.Progress", _Progress)
    monkeypatch.setattr("redaudit.utils.session_log.start_session_log", lambda *_a, **_k: None)
    monkeypatch.setattr("redaudit.utils.session_log.stop_session_log", lambda *_a, **_k: "")
    monkeypatch.setattr("redaudit.utils.paths.maybe_chown_to_invoking_user", lambda *_a, **_k: None)
    monkeypatch.setattr("os.makedirs", lambda *_a, **_k: None)
    monkeypatch.setattr("redaudit.core.auditor.show_results_summary", lambda *_a, **_k: None)

    auditor.save_results = MagicMock()
    auditor.show_results = MagicMock()

    assert auditor.run_complete_scan() is True
    assert "nuclei" in auditor.results


def _make_resume_auditor():
    mock_ui_manager = MagicMock()
    mock_ui_manager.colors = COLORS
    mock_ui_manager.t.side_effect = lambda key, *args: key.format(*args) if args else key
    with patch("redaudit.core.ui_manager.UIManager", return_value=mock_ui_manager):
        auditor = InteractiveNetworkAuditor()
    auditor.logger = MagicMock()
    auditor.print_status = MagicMock()
    return auditor


def test_nuclei_resume_state_roundtrip():
    auditor = _make_resume_auditor()
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = os.path.join(tmpdir, "nuclei_output.json")
        state = auditor._build_nuclei_resume_state(
            output_dir=tmpdir,
            pending_targets=["http://127.0.0.1:80"],
            total_targets=1,
            profile="balanced",
            full_coverage=False,
            severity="low",
            timeout_s=300,
            request_timeout_s=10,
            retries=1,
            batch_size=10,
            max_runtime_minutes=5,
            output_file=output_file,
        )
        resume_path = auditor._write_nuclei_resume_state(tmpdir, state)
        assert resume_path and os.path.exists(resume_path)
        assert os.path.exists(os.path.join(tmpdir, "nuclei_pending.txt"))
        loaded = auditor._load_nuclei_resume_state(resume_path)
        assert loaded and loaded.get("pending_targets") == ["http://127.0.0.1:80"]
        auditor._clear_nuclei_resume_state(resume_path, tmpdir)
        assert not os.path.exists(resume_path)


def test_load_nuclei_resume_state_missing():
    auditor = _make_resume_auditor()
    with tempfile.TemporaryDirectory() as tmpdir:
        missing = os.path.join(tmpdir, "missing.json")
        assert auditor._load_nuclei_resume_state(missing) is None


def test_write_nuclei_resume_state_empty_pending():
    auditor = _make_resume_auditor()
    with tempfile.TemporaryDirectory() as tmpdir:
        state = auditor._build_nuclei_resume_state(
            output_dir=tmpdir,
            pending_targets=["http://127.0.0.1:80"],
            total_targets=1,
            profile="balanced",
            full_coverage=False,
            severity="low",
            timeout_s=300,
            request_timeout_s=10,
            retries=1,
            batch_size=10,
            max_runtime_minutes=0,
            output_file=os.path.join(tmpdir, "nuclei_output.json"),
        )
        state["pending_targets"] = []
        assert auditor._write_nuclei_resume_state(tmpdir, state) is None


def test_find_nuclei_resume_candidates():
    auditor = _make_resume_auditor()
    with tempfile.TemporaryDirectory() as tmpdir:
        scan_dir = os.path.join(tmpdir, "RedAudit_2026-01-01_00-00-00")
        os.makedirs(scan_dir, exist_ok=True)
        state = auditor._build_nuclei_resume_state(
            output_dir=scan_dir,
            pending_targets=["http://127.0.0.1:80"],
            total_targets=1,
            profile="balanced",
            full_coverage=False,
            severity="low",
            timeout_s=300,
            request_timeout_s=10,
            retries=1,
            batch_size=10,
            max_runtime_minutes=0,
            output_file=os.path.join(scan_dir, "nuclei_output.json"),
        )
        auditor._write_nuclei_resume_state(scan_dir, state)
        candidates = auditor._find_nuclei_resume_candidates(tmpdir)
        assert len(candidates) == 1
        assert candidates[0]["pending"] == 1


def test_find_latest_report_json_none():
    auditor = _make_resume_auditor()
    with tempfile.TemporaryDirectory() as tmpdir:
        assert auditor._find_latest_report_json(tmpdir) is None


def test_detect_report_artifact_false():
    auditor = _make_resume_auditor()
    with tempfile.TemporaryDirectory() as tmpdir:
        assert auditor._detect_report_artifact(tmpdir, (".txt",)) is False


def test_load_resume_context_detects_reports():
    auditor = _make_resume_auditor()
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = os.path.join(tmpdir, "redaudit_20260101_000000.json")
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump({"config_snapshot": {"scan_mode": "completo"}, "hosts": []}, handle)
        txt_path = os.path.join(tmpdir, "redaudit_20260101_000000.txt")
        with open(txt_path, "w", encoding="utf-8") as handle:
            handle.write("report")
        assert auditor._load_resume_context(tmpdir) is True
        assert auditor.config["save_txt_report"] is True


def test_load_resume_context_missing_report():
    auditor = _make_resume_auditor()
    with tempfile.TemporaryDirectory() as tmpdir:
        assert auditor._load_resume_context(tmpdir) is False


def test_append_nuclei_output_appends_lines():
    auditor = _make_resume_auditor()
    with tempfile.TemporaryDirectory() as tmpdir:
        source = os.path.join(tmpdir, "nuclei_output_resume.json")
        dest = os.path.join(tmpdir, "nuclei_output.json")
        with open(source, "w", encoding="utf-8") as handle:
            handle.write('{"a": 1}\n')
        with open(dest, "w", encoding="utf-8") as handle:
            handle.write('{"existing": true}\n')
        auditor._append_nuclei_output(source, dest)
        with open(dest, "r", encoding="utf-8") as handle:
            content = handle.read()
        assert '"existing"' in content
        assert '"a": 1' in content


def test_resume_nuclei_from_state_updates_results():
    auditor = _make_resume_auditor()
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = os.path.join(tmpdir, "nuclei_output.json")
        state = auditor._build_nuclei_resume_state(
            output_dir=tmpdir,
            pending_targets=["http://127.0.0.1:80"],
            total_targets=1,
            profile="balanced",
            full_coverage=False,
            severity="low",
            timeout_s=300,
            request_timeout_s=10,
            retries=1,
            batch_size=10,
            max_runtime_minutes=0,
            output_file=output_file,
        )
        resume_path = auditor._write_nuclei_resume_state(tmpdir, state)
        auditor.results = {"hosts": [], "vulnerabilities": [], "nuclei": {"findings": 0}}
        auditor.config = {"dry_run": False}
        auditor.proxy_manager = None

        def _fake_nuclei_scan(**_kwargs):
            return {
                "findings": [
                    {
                        "matched_at": "http://127.0.0.1:80/",
                        "template_id": "t1",
                        "name": "test",
                        "severity": "high",
                    }
                ],
                "success": True,
                "pending_targets": [],
                "raw_output_file": _kwargs.get("output_file"),
            }

        with (
            patch("redaudit.core.auditor.run_nuclei_scan", side_effect=_fake_nuclei_scan),
            patch(
                "redaudit.core.verify_vuln.filter_nuclei_false_positives",
                lambda findings, *_a, **_k: (findings, []),
            ),
            patch.object(auditor, "_append_nuclei_output", lambda *_a, **_k: None),
        ):
            ok = auditor._resume_nuclei_from_state(
                resume_state=state,
                resume_path=resume_path,
                output_dir=tmpdir,
                use_existing_results=True,
                save_after=False,
            )
        assert ok is True
        assert auditor.results["nuclei"]["findings"] == 1
        assert "resume_pending" not in auditor.results["nuclei"]
        assert not os.path.exists(resume_path)


def test_resume_nuclei_from_state_keeps_pending():
    auditor = _make_resume_auditor()
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = os.path.join(tmpdir, "nuclei_output.json")
        state = auditor._build_nuclei_resume_state(
            output_dir=tmpdir,
            pending_targets=["http://127.0.0.1:80"],
            total_targets=1,
            profile="balanced",
            full_coverage=False,
            severity="low",
            timeout_s=300,
            request_timeout_s=10,
            retries=1,
            batch_size=10,
            max_runtime_minutes=0,
            output_file=output_file,
        )
        resume_path = auditor._write_nuclei_resume_state(tmpdir, state)
        auditor.results = {"hosts": [], "vulnerabilities": [], "nuclei": {"findings": 0}}
        auditor.config = {"dry_run": False}
        auditor.proxy_manager = None

        def _fake_nuclei_scan(**_kwargs):
            return {
                "findings": [],
                "success": True,
                "pending_targets": ["http://127.0.0.2:80"],
                "raw_output_file": _kwargs.get("output_file"),
                "partial": True,
                "error": "timeout",
            }

        with (
            patch("redaudit.core.auditor.run_nuclei_scan", side_effect=_fake_nuclei_scan),
            patch(
                "redaudit.core.verify_vuln.filter_nuclei_false_positives",
                lambda findings, *_a, **_k: (findings, []),
            ),
            patch.object(auditor, "_append_nuclei_output", lambda *_a, **_k: None),
        ):
            ok = auditor._resume_nuclei_from_state(
                resume_state=state,
                resume_path=resume_path,
                output_dir=tmpdir,
                use_existing_results=True,
                save_after=False,
            )
        assert ok is True
        assert auditor.results["nuclei"].get("partial") is True
        assert auditor.results["nuclei"].get("resume_pending") == 1
        assert os.path.exists(resume_path)


def test_resume_nuclei_from_state_no_pending():
    auditor = _make_resume_auditor()
    state = auditor._build_nuclei_resume_state(
        output_dir="/tmp",
        pending_targets=["http://127.0.0.1:80"],
        total_targets=1,
        profile="balanced",
        full_coverage=False,
        severity="low",
        timeout_s=300,
        request_timeout_s=10,
        retries=1,
        batch_size=10,
        max_runtime_minutes=0,
        output_file="/tmp/nuclei_output.json",
    )
    state["pending_targets"] = []
    auditor.results = {"hosts": [], "vulnerabilities": [], "nuclei": {"findings": 0}}
    auditor.config = {"dry_run": False}
    ok = auditor._resume_nuclei_from_state(
        resume_state=state,
        resume_path="/tmp/nuclei_resume.json",
        output_dir="/tmp",
        use_existing_results=True,
        save_after=False,
    )
    assert ok is False


def test_resume_nuclei_from_state_save_after():
    auditor = _make_resume_auditor()
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = os.path.join(tmpdir, "nuclei_output.json")
        state = auditor._build_nuclei_resume_state(
            output_dir=tmpdir,
            pending_targets=["http://127.0.0.1:80"],
            total_targets=1,
            profile="balanced",
            full_coverage=False,
            severity="low",
            timeout_s=300,
            request_timeout_s=10,
            retries=1,
            batch_size=10,
            max_runtime_minutes=0,
            output_file=output_file,
        )
        resume_path = auditor._write_nuclei_resume_state(tmpdir, state)
        auditor.results = {"hosts": [], "vulnerabilities": [], "nuclei": {"findings": 0}}
        auditor.config = {"dry_run": False, "output_dir": tmpdir, "_actual_output_dir": tmpdir}
        auditor.proxy_manager = None

        def _fake_nuclei_scan(**_kwargs):
            return {
                "findings": [],
                "success": True,
                "pending_targets": [],
                "raw_output_file": _kwargs.get("output_file"),
            }

        with (
            patch("redaudit.core.auditor.run_nuclei_scan", side_effect=_fake_nuclei_scan),
            patch(
                "redaudit.core.verify_vuln.filter_nuclei_false_positives",
                lambda findings, *_a, **_k: (findings, []),
            ),
            patch.object(auditor, "_append_nuclei_output", lambda *_a, **_k: None),
            patch.object(auditor, "save_results") as mock_save,
            patch("redaudit.core.auditor.generate_summary", lambda *_a, **_k: None),
        ):
            ok = auditor._resume_nuclei_from_state(
                resume_state=state,
                resume_path=resume_path,
                output_dir=tmpdir,
                use_existing_results=True,
                save_after=True,
            )
        assert ok is True
        assert mock_save.called


def test_resume_nuclei_from_state_load_context_failure():
    auditor = _make_resume_auditor()
    state = auditor._build_nuclei_resume_state(
        output_dir="/tmp",
        pending_targets=["http://127.0.0.1:80"],
        total_targets=1,
        profile="balanced",
        full_coverage=False,
        severity="low",
        timeout_s=300,
        request_timeout_s=10,
        retries=1,
        batch_size=10,
        max_runtime_minutes=0,
        output_file="/tmp/nuclei_output.json",
    )
    with patch.object(auditor, "_load_resume_context", return_value=False):
        ok = auditor._resume_nuclei_from_state(
            resume_state=state,
            resume_path="/tmp/nuclei_resume.json",
            output_dir="/tmp",
            use_existing_results=False,
            save_after=False,
        )
    assert ok is False


def test_resume_nuclei_from_path_accepts_directory():
    auditor = _make_resume_auditor()
    with tempfile.TemporaryDirectory() as tmpdir:
        state = auditor._build_nuclei_resume_state(
            output_dir=tmpdir,
            pending_targets=["http://127.0.0.1:80"],
            total_targets=1,
            profile="balanced",
            full_coverage=False,
            severity="low",
            timeout_s=300,
            request_timeout_s=10,
            retries=1,
            batch_size=10,
            max_runtime_minutes=0,
            output_file=os.path.join(tmpdir, "nuclei_output.json"),
        )
        auditor._write_nuclei_resume_state(tmpdir, state)
        with patch.object(auditor, "_resume_nuclei_from_state", return_value=True) as mock_run:
            assert auditor.resume_nuclei_from_path(tmpdir) is True
            assert mock_run.called


def test_resume_nuclei_from_path_missing():
    auditor = _make_resume_auditor()
    with tempfile.TemporaryDirectory() as tmpdir:
        missing = os.path.join(tmpdir, "missing.json")
        assert auditor.resume_nuclei_from_path(missing) is False


def test_resume_nuclei_interactive_no_candidates():
    auditor = _make_resume_auditor()
    with patch.object(auditor, "_find_nuclei_resume_candidates", return_value=[]):
        assert auditor.resume_nuclei_interactive() is False


def test_resume_nuclei_interactive_runs_selected():
    auditor = _make_resume_auditor()
    candidate = {"path": "/tmp/scan/nuclei_resume.json", "label": "scan (1 targets)"}
    with (
        patch.object(auditor, "_find_nuclei_resume_candidates", return_value=[candidate]),
        patch.object(auditor, "ask_choice", return_value=0),
        patch.object(auditor, "resume_nuclei_from_path", return_value=True) as mock_resume,
    ):
        assert auditor.resume_nuclei_interactive() is True
        mock_resume.assert_called_with(candidate["path"])


def test_resume_nuclei_interactive_cancel():
    auditor = _make_resume_auditor()
    candidate = {"path": "/tmp/scan/nuclei_resume.json", "label": "scan (1 targets)"}
    with (
        patch.object(auditor, "_find_nuclei_resume_candidates", return_value=[candidate]),
        patch.object(auditor, "ask_choice", return_value=1),
    ):
        assert auditor.resume_nuclei_interactive() is False


if __name__ == "__main__":
    unittest.main()
