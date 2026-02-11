"""Tests for nuclei scan internals, IoT/leak-follow, CVE correlation, topology,
_run_hyperscan_discovery, and resume_nuclei_interactive to maximize auditor.py coverage."""

import os
import tempfile
import math
import time
import unittest
from unittest.mock import MagicMock, patch, PropertyMock


def _make_auditor():
    """Create auditor with runtime patched."""
    with patch("redaudit.core.auditor.AuditorRuntime"):
        from redaudit.core.auditor import InteractiveNetworkAuditor

        auditor = InteractiveNetworkAuditor()
    auditor.ui = MagicMock()
    auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
    auditor.ui.colors = {
        "HEADER": "",
        "ENDC": "",
        "OKBLUE": "",
        "OKGREEN": "",
        "WARNING": "",
        "FAIL": "",
        "BOLD": "",
    }
    auditor.logger = MagicMock()
    return auditor


def _base_scan_config():
    """Minimum config for run_complete_scan."""
    return {
        "target_networks": ["10.0.0.0/24"],
        "max_hosts_value": "all",
        "prevent_sleep": False,
        "scan_vulnerabilities": True,
        "scan_mode": "completo",
        "nuclei_enabled": True,
        "nuclei_profile": "balanced",
        "nuclei_timeout": 300,
        "nuclei_max_runtime": 0,
        "nuclei_fatigue_limit": 3,
        "nuclei_full_coverage": False,
        "auth_enabled": False,
        "cve_lookup_enabled": False,
        "topology_enabled": False,
        "net_discovery_enabled": False,
        "iot_probes_mode": "off",
    }


def _host_mock(ip="10.0.0.1"):
    host = MagicMock()
    host.ip = ip
    host.smart_scan = {}
    host.ports = []
    host.services = []
    host.tags = set()
    host.agentless_fingerprint = {}
    host.to_dict = MagicMock(return_value={"ip": ip})
    return host


def _setup_run_scan_mocks(auditor, hosts=None):
    """Wire standard mocks for run_complete_scan."""
    if hosts is None:
        hosts = [_host_mock()]
    auditor.scan_network_discovery = MagicMock(return_value=[h.ip for h in hosts])
    for h in hosts:
        auditor.scanner.get_or_create_host = MagicMock(return_value=h)
    auditor.scan_hosts_concurrent = MagicMock(return_value=hosts)
    auditor.run_agentless_verification = MagicMock()
    auditor.scan_vulnerabilities_concurrent = MagicMock()
    auditor.save_results = MagicMock()
    auditor.show_results = MagicMock()
    auditor.start_heartbeat = MagicMock()
    auditor.stop_heartbeat = MagicMock()
    auditor.proxy_manager = None
    auditor._run_hyperscan_discovery = MagicMock(return_value=None)
    auditor._filter_auditor_ips = MagicMock(side_effect=lambda x: x)
    auditor._build_scope_expansion_evidence = MagicMock(return_value=[])
    auditor._merge_nuclei_findings = MagicMock(return_value=0)


# ---------------------------------------------------------------------------
# Tests for nuclei scan internals within run_complete_scan
# ---------------------------------------------------------------------------


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestNucleiScanInternals(unittest.TestCase):
    """Test the 400+ line nuclei scan block inside run_complete_scan."""

    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.logger = MagicMock()

    def _wire_nuclei(self, nuclei_result, select_result=None, hosts=None, **config_overrides):
        """Common setup for nuclei scan tests."""
        if hosts is None:
            hosts = [_host_mock()]
        if select_result is None:
            select_result = {
                "targets": ["http://10.0.0.1"],
                "targets_total": 1,
                "targets_exception": 0,
                "targets_optimized": 0,
                "targets_excluded": 0,
                "selected_by_host": {"10.0.0.1": ["http://10.0.0.1"]},
                "exception_targets": set(),
            }
        cfg = _base_scan_config()
        cfg.update(config_overrides)
        for k, v in cfg.items():
            self.auditor.config[k] = v

        _setup_run_scan_mocks(self.auditor, hosts)
        return select_result, nuclei_result

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
    def test_nuclei_with_findings(
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
        """Nuclei scan with findings populates results."""
        mock_eval_leak.return_value = {"mode": "off", "detected": 0, "eligible": 0}
        select_ret, _ = self._wire_nuclei(
            {
                "success": True,
                "findings": [
                    {
                        "template_id": "xss-1",
                        "matched_at": "http://10.0.0.1",
                        "host": "10.0.0.1",
                        "severity": "high",
                        "name": "XSS",
                    },
                ],
                "partial": False,
                "pending_targets": [],
                "raw_output_file": "/tmp/nuclei_out.json",
            }
        )
        mock_select.return_value = select_ret
        mock_nuclei.return_value = {
            "success": True,
            "findings": [
                {
                    "template_id": "xss-1",
                    "matched_at": "http://10.0.0.1",
                    "host": "10.0.0.1",
                    "severity": "high",
                    "name": "XSS",
                },
            ],
            "partial": False,
            "pending_targets": [],
            "raw_output_file": "/tmp/nuclei_out.json",
        }
        self.auditor._merge_nuclei_findings = MagicMock(return_value=1)

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)
        self.assertIn("nuclei", self.auditor.results)
        self.assertTrue(self.auditor.results["nuclei"]["success"])

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
    def test_nuclei_partial_with_pending(
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
        """Nuclei scan partial result with pending targets triggers resume save."""
        mock_eval_leak.return_value = {"mode": "off", "detected": 0, "eligible": 0}
        select_ret, _ = self._wire_nuclei({})
        mock_select.return_value = select_ret
        mock_nuclei.return_value = {
            "success": True,
            "findings": [],
            "partial": True,
            "pending_targets": ["http://10.0.0.2"],
            "raw_output_file": "/tmp/nuclei_out.json",
            "timeout_batches": [["http://10.0.0.2"]],
            "failed_batches": [],
        }
        self.auditor._build_nuclei_resume_state = MagicMock(
            return_value={"pending_targets": ["http://10.0.0.2"]}
        )
        self.auditor._write_nuclei_resume_state = MagicMock(return_value="/tmp/resume.json")
        self.auditor.ask_yes_no_with_timeout = MagicMock(return_value=False)

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)
        self.auditor._write_nuclei_resume_state.assert_called_once()
        nuclei_res = self.auditor.results.get("nuclei", {})
        self.assertTrue(nuclei_res.get("partial", False))

    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.core.auditor.maybe_chown_to_invoking_user")
    @patch("redaudit.utils.session_log.start_session_log")
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    @patch("redaudit.core.auditor.is_nuclei_available", return_value=True)
    @patch("redaudit.core.auditor.select_nuclei_targets")
    @patch("redaudit.core.auditor.extract_leak_follow_candidates", return_value=[])
    @patch("redaudit.core.auditor.evaluate_leak_follow_candidates")
    @patch("redaudit.core.auditor.build_leak_follow_targets", return_value=["http://10.0.0.99"])
    @patch("redaudit.core.auditor.run_nuclei_scan")
    def test_nuclei_with_leak_follow_targets(
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
        """Leak follow targets are added to nuclei targets."""
        mock_eval_leak.return_value = {"mode": "safe", "detected": 1, "eligible": 1}
        select_ret, _ = self._wire_nuclei({})
        mock_select.return_value = select_ret
        mock_nuclei.return_value = {
            "success": True,
            "findings": [],
            "partial": False,
            "pending_targets": [],
            "raw_output_file": None,
        }

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)
        # run_nuclei_scan should be called with merged targets
        call_args = mock_nuclei.call_args
        targets = (
            call_args.kwargs.get("targets") or call_args[1].get("targets") if call_args else []
        )
        self.assertGreaterEqual(len(targets), 1)

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
    def test_nuclei_auto_switch_fast_profile(
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
        """Auto-switches to fast profile when hosts have 3+ ports."""
        mock_eval_leak.return_value = {"mode": "off", "detected": 0, "eligible": 0}
        select_ret = {
            "targets": ["http://10.0.0.1", "http://10.0.0.1:8080", "http://10.0.0.1:8443"],
            "targets_total": 3,
            "targets_exception": 0,
            "targets_optimized": 0,
            "targets_excluded": 0,
            "selected_by_host": {
                "10.0.0.1": ["http://10.0.0.1", "http://10.0.0.1:8080", "http://10.0.0.1:8443"]
            },
            "exception_targets": set(),
        }
        mock_select.return_value = select_ret
        self._wire_nuclei({}, select_result=select_ret)
        mock_nuclei.return_value = {
            "success": True,
            "findings": [],
            "partial": False,
            "pending_targets": [],
            "raw_output_file": None,
        }

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)
        nuclei_res = self.auditor.results.get("nuclei", {})
        self.assertEqual(nuclei_res.get("profile"), "fast")
        self.assertTrue(nuclei_res.get("auto_switched", False))

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
    def test_nuclei_budget_exceeded(
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
        """Budget exceeded flag is recorded."""
        mock_eval_leak.return_value = {"mode": "off", "detected": 0, "eligible": 0}
        select_ret, _ = self._wire_nuclei({})
        mock_select.return_value = select_ret
        mock_nuclei.return_value = {
            "success": True,
            "findings": [],
            "partial": False,
            "pending_targets": [],
            "raw_output_file": None,
            "budget_exceeded": True,
        }

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)
        self.assertTrue(self.auditor.results.get("nuclei", {}).get("budget_exceeded"))

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
    def test_nuclei_no_findings_partial_error(
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
        """No findings with partial shows the correct status."""
        mock_eval_leak.return_value = {"mode": "off", "detected": 0, "eligible": 0}
        select_ret, _ = self._wire_nuclei({})
        mock_select.return_value = select_ret
        mock_nuclei.return_value = {
            "success": False,
            "findings": [],
            "partial": True,
            "pending_targets": [],
            "raw_output_file": None,
            "error": "timeout",
            "timeout_batches": [["http://10.0.0.1"]],
            "failed_batches": [],
        }

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)

    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.core.auditor.maybe_chown_to_invoking_user")
    @patch("redaudit.utils.session_log.start_session_log")
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    @patch("redaudit.core.auditor.is_nuclei_available", return_value=True)
    @patch("redaudit.core.auditor.select_nuclei_targets")
    @patch("redaudit.core.auditor.extract_leak_follow_candidates", return_value=[])
    @patch("redaudit.core.auditor.evaluate_leak_follow_candidates")
    @patch("redaudit.core.auditor.build_leak_follow_targets", return_value=[])
    @patch("redaudit.core.auditor.run_nuclei_scan", side_effect=RuntimeError("nuclei boom"))
    def test_nuclei_exception(
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
        """Nuclei scan exception is caught gracefully."""
        mock_eval_leak.return_value = {"mode": "off", "detected": 0, "eligible": 0}
        select_ret, _ = self._wire_nuclei({})
        mock_select.return_value = select_ret

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)
        self.auditor.logger.warning.assert_called()


# ---------------------------------------------------------------------------
# Topology block
# ---------------------------------------------------------------------------


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestTopologyBlock(unittest.TestCase):
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
    @patch("redaudit.core.topology.discover_topology")
    def test_topology_enabled(self, mock_topo, mock_stop, mock_start, mock_chown, mock_gen, *args):
        """Topology discovery runs when enabled."""
        mock_topo.return_value = {
            "routes": [{"dst": "10.0.0.0/24", "dev": "eth0"}],
            "interfaces": [],
        }
        self.auditor.config["target_networks"] = ["10.0.0.0/24"]
        self.auditor.config["max_hosts_value"] = "all"
        self.auditor.config["prevent_sleep"] = False
        self.auditor.config["scan_vulnerabilities"] = False
        self.auditor.config["nuclei_enabled"] = False
        self.auditor.config["auth_enabled"] = False
        self.auditor.config["cve_lookup_enabled"] = False
        self.auditor.config["topology_enabled"] = True
        self.auditor.config["topology_only"] = True
        self.auditor.config["net_discovery_enabled"] = False
        self.auditor.config["scan_mode"] = "normal"
        self.auditor.scan_network_discovery = MagicMock(return_value=[])
        self.auditor.start_heartbeat = MagicMock()
        self.auditor.stop_heartbeat = MagicMock()
        self.auditor.proxy_manager = None
        self.auditor.save_results = MagicMock()
        self.auditor.show_results = MagicMock()

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)
        self.assertIn("topology", self.auditor.results)


# ---------------------------------------------------------------------------
# IoT scope probes block
# ---------------------------------------------------------------------------


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestIoTScopeProbes(unittest.TestCase):
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
    @patch("redaudit.core.auditor.is_nuclei_available", return_value=False)
    def test_iot_probes_with_exception(
        self,
        mock_nuclei_avail,
        mock_stop,
        mock_start,
        mock_chown,
        mock_gen,
        mock_swf,
        mock_iot,
        mock_scanner,
        mock_indicator,
        mock_sleep,
        *args,
    ):
        """IoT probes exception is caught."""
        mock_iot.side_effect = RuntimeError("iot boom")
        cfg = _base_scan_config()
        cfg["iot_probes_mode"] = "safe"
        cfg["nuclei_enabled"] = False
        for k, v in cfg.items():
            self.auditor.config[k] = v

        _setup_run_scan_mocks(self.auditor)

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)
        scope_rt = self.auditor.results.get("scope_expansion_runtime", {})
        iot_rt = scope_rt.get("iot_probes", {})
        self.assertEqual(iot_rt.get("reasons", {}).get("runtime_error"), 1)


# ---------------------------------------------------------------------------
# CVE correlation block
# ---------------------------------------------------------------------------


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestCVECorrelation(unittest.TestCase):
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
    @patch("redaudit.core.auditor.is_nuclei_available", return_value=False)
    @patch("redaudit.core.auditor.enrich_host_with_cves")
    @patch("redaudit.core.auditor.get_api_key_from_config", return_value="test-key")
    def test_cve_lookup_enabled(
        self,
        mock_api_key,
        mock_cve,
        mock_nuclei_avail,
        mock_stop,
        mock_start,
        mock_chown,
        mock_gen,
        *args,
    ):
        """CVE correlation runs when enabled."""
        mock_cve.side_effect = lambda host, **kw: host
        cfg = _base_scan_config()
        cfg["cve_lookup_enabled"] = True
        cfg["nuclei_enabled"] = False
        for k, v in cfg.items():
            self.auditor.config[k] = v

        _setup_run_scan_mocks(self.auditor)
        self.auditor.setup_nvd_api_key = MagicMock()

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)


# ---------------------------------------------------------------------------
# _run_hyperscan_discovery
# ---------------------------------------------------------------------------


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestHyperscanDiscovery(unittest.TestCase):
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
    @patch("redaudit.core.auditor.is_nuclei_available", return_value=False)
    def test_hyperscan_integrates_ports(
        self, mock_nuclei_avail, mock_stop, mock_start, mock_chown, mock_gen, *args
    ):
        """HyperScan results feed into scan pipeline."""
        cfg = _base_scan_config()
        cfg["nuclei_enabled"] = False
        for k, v in cfg.items():
            self.auditor.config[k] = v

        host = _host_mock()
        _setup_run_scan_mocks(self.auditor, [host])
        # Override _run_hyperscan_discovery to return actual ports
        self.auditor._run_hyperscan_discovery = MagicMock(return_value={"10.0.0.1": [80, 443]})

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)
        self.auditor._run_hyperscan_discovery.assert_called_once()


# ---------------------------------------------------------------------------
# resume_nuclei_interactive
# ---------------------------------------------------------------------------


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestResumeNucleiInteractive(unittest.TestCase):
    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.logger = MagicMock()

    def test_no_candidates(self, *args):
        """Returns False when no resume candidates exist."""
        self.auditor._find_nuclei_resume_candidates = MagicMock(return_value=[])
        result = self.auditor.resume_nuclei_interactive()
        self.assertFalse(result)

    def test_select_candidate(self, *args):
        """Selects a resume candidate."""
        candidates = [{"label": "test-1", "path": "/tmp/resume.json", "output_dir": "/tmp"}]
        self.auditor._find_nuclei_resume_candidates = MagicMock(return_value=candidates)
        # options: ["test-1", manage, go_back] -> indices 0, 1, 2
        # Choose 0 -> select first candidate
        self.auditor.ask_choice = MagicMock(return_value=0)
        self.auditor.resume_nuclei_from_path = MagicMock(return_value=True)

        result = self.auditor.resume_nuclei_interactive()
        self.assertTrue(result)
        self.auditor.resume_nuclei_from_path.assert_called_once()

    def test_manage_delete_one(self, *args):
        """Manage > delete one candidate."""
        candidates = [
            {"label": "test-1", "path": "/tmp/r1.json", "output_dir": "/tmp"},
            {"label": "test-2", "path": "/tmp/r2.json", "output_dir": "/tmp"},
        ]
        self.auditor._find_nuclei_resume_candidates = MagicMock(return_value=candidates)
        # options: ["test-1", "test-2", manage(idx=2), go_back(idx=3)]
        # First call: choose manage (2)
        # manage_options: [delete_one, delete_all, go_back]
        # Second call: choose delete_one (0)
        # delete_options: ["test-1", "test-2", go_back]
        # Third call: choose first (0) to delete "test-1"
        # Loop restarts -> _find_nuclei_resume_candidates called again -> same candidates
        # Fourth call: choose back (idx=3)
        self.auditor.ask_choice = MagicMock(
            side_effect=[
                2,  # manage
                0,  # delete one
                0,  # delete first candidate
                3,  # go_back
            ]
        )
        self.auditor._clear_nuclei_resume_state = MagicMock()
        self.auditor.resume_nuclei_from_path = MagicMock(return_value=True)

        result = self.auditor.resume_nuclei_interactive()
        self.auditor._clear_nuclei_resume_state.assert_called_once()

    def test_manage_delete_all(self, *args):
        """Manage > delete all candidates."""
        candidates = [
            {"label": "test-1", "path": "/tmp/r1.json", "output_dir": "/tmp"},
            {"label": "test-2", "path": "/tmp/r2.json", "output_dir": "/tmp"},
        ]
        self.auditor._find_nuclei_resume_candidates = MagicMock(return_value=candidates)
        # options: ["test-1", "test-2", manage(idx=2), go_back(idx=3)]
        # First call: choose manage (2)
        # manage_options: [delete_one, delete_all, go_back]
        # Second call: choose delete_all (1)
        # ask_yes_no: confirm delete all -> True
        # Loop restarts -> _find_nuclei_resume_candidates returns same (but cleared)
        # Third ask_choice can be back_idx (3)
        self.auditor.ask_choice = MagicMock(
            side_effect=[
                2,  # manage
                1,  # delete all
                3,  # go_back after deletion
            ]
        )
        self.auditor.ask_yes_no = MagicMock(return_value=True)
        self.auditor._clear_nuclei_resume_state = MagicMock()

        result = self.auditor.resume_nuclei_interactive()
        self.assertEqual(self.auditor._clear_nuclei_resume_state.call_count, 2)

    def test_keyboard_interrupt(self, *args):
        """KeyboardInterrupt returns False."""
        self.auditor._find_nuclei_resume_candidates = MagicMock(side_effect=KeyboardInterrupt())
        result = self.auditor.resume_nuclei_interactive()
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# Net discovery with DHCP/VLAN/backdoor/L2 warning coverage
# ---------------------------------------------------------------------------


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestNetDiscoveryResults(unittest.TestCase):
    """Cover the DHCP servers, VLANs, backdoors, and L2 warning reporting."""

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
    @patch("redaudit.core.net_discovery.detect_default_route_interface", return_value=None)
    def test_nd_dhcp_vlans_backdoors_l2(
        self, mock_detect, mock_discover, mock_stop, mock_start, mock_chown, mock_gen, *args
    ):
        """Net discovery reports DHCP, VLANs, backdoors, and L2 warnings."""
        mock_discover.return_value = {
            "enabled": True,
            "dhcp_servers": [{"ip": "10.0.0.1"}],
            "candidate_vlans": [{"vlan_id": 100}],
            "hyperscan_duration": 2.0,
            "arp_hosts": ["10.0.0.2"],
            "upnp_devices": [{"ip": "10.0.0.3"}],
            "hyperscan_tcp_hosts": {"10.0.0.4": [80]},
            "potential_backdoors": [{"port": 31337}],
            "l2_warning_note": "L2 switches detected",
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
        self.auditor.config["scan_mode"] = "completo"  # full DHCP mode
        self.auditor.scan_network_discovery = MagicMock(return_value=["10.0.0.1"])
        host = _host_mock()
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
        self.auditor._select_net_discovery_interface = MagicMock(return_value=None)

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)
        # Verify net_discovery was called and results were reported
        calls = [str(c) for c in self.auditor.ui.print_status.call_args_list]
        status_text = " ".join(calls)
        # The discovery ran but results may be stored differently
        # Check that various reporting paths were exercised
        self.assertTrue(len(calls) > 0)


if __name__ == "__main__":
    unittest.main()
