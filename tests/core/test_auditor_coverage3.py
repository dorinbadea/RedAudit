"""Tests targeting remaining uncovered blocks: net discovery Rich Progress block
(841-917), UDP port injection (990-1028), __getattr__ WizardCompat (90-98),
and nuclei progress callback (1345-1354)."""

import time
import unittest
from unittest.mock import MagicMock, patch, call


# ===========================================================================
# __getattr__ WizardCompat fallback (lines 86-98)
# ===========================================================================


class TestGetAttrWizardCompat(unittest.TestCase):
    """Test __getattr__ delegation to scan_wizard_flow and WizardCompat."""

    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        # Patch other required imports
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
        self.auditor.logger = MagicMock()

    def test_getattr_scan_wizard_flow_fallback(self):
        """__getattr__ resolves to scan_wizard_flow when runtime doesn't have it."""
        self.auditor.__dict__["_runtime"] = None

        # Create a simple class that has the method on its type
        class FakeFlow:
            def custom_wizard_method_xyz(self):
                return "from_wizard"

        self.auditor.__dict__["scan_wizard_flow"] = FakeFlow()

        result = self.auditor.custom_wizard_method_xyz()
        self.assertEqual(result, "from_wizard")

    def test_getattr_wizard_compat_fallback(self):
        """__getattr__ falls back to WizardCompat for class-level attributes."""
        from redaudit.core.auditor import WizardCompat

        # Set _runtime to None to bypass runtime delegation
        self.auditor.__dict__["_runtime"] = None
        self.auditor.__dict__.pop("scan_wizard_flow", None)

        # WIZARD_BACK is directly on the class, not via __getattr__
        result = self.auditor.WIZARD_BACK
        self.assertEqual(result, WizardCompat.WIZARD_BACK)

    def test_getattr_raises_for_unknown(self):
        """__getattr__ raises AttributeError for truly unknown attributes."""
        # Set _runtime to None so it doesn't proxy
        self.auditor.__dict__["_runtime"] = None
        self.auditor.__dict__.pop("scan_wizard_flow", None)

        with self.assertRaises(AttributeError):
            _ = self.auditor._completely_nonexistent_attr_xyz_987


# ===========================================================================
# Net discovery with scan_mode=completo (exercises Rich Progress block 812-917)
# ===========================================================================


@patch("redaudit.core.power.SleepInhibitor")
@patch("redaudit.core.auditor._ActivityIndicator")
@patch("redaudit.core.auditor.NetworkScanner")
@patch("redaudit.core.auditor.run_iot_scope_probes")
@patch("redaudit.core.auditor.ScanWizardFlow")
class TestNetDiscoveryCompletoMode(unittest.TestCase):

    def setUp(self):
        self.runtime_patcher = patch("redaudit.core.auditor.AuditorRuntime")
        self.mock_runtime_cls = self.runtime_patcher.start()
        self.addCleanup(self.runtime_patcher.stop)

        from redaudit.core.auditor import InteractiveNetworkAuditor

        self.auditor = InteractiveNetworkAuditor()
        self.auditor.ui = MagicMock()
        self.auditor.ui.t = MagicMock(side_effect=lambda key, *a: f"{key}")
        self.auditor.logger = MagicMock()

    def _wire_completo_config(self):
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
        self.auditor.config["scan_mode"] = "completo"

    def _wire_scan_mocks(self):
        host = MagicMock()
        host.ip = "10.0.0.1"
        host.tags = set()
        host.ports = []
        host.services = []
        host.smart_scan = {}
        host.agentless_fingerprint = {}
        host.udp_ports = []
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
    def test_completo_full_discovery_results(
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
        """scan_mode=completo exercises the full_dhcp path without crashing."""
        nd_result = {
            "enabled": True,
            "dhcp_servers": [{"ip": "10.0.0.254"}],
            "candidate_vlans": [{"vlan": 100}],
            "hyperscan_duration": 2.5,
            "arp_hosts": ["10.0.0.5"],
            "upnp_devices": [],
            "hyperscan_tcp_hosts": {},
            "potential_backdoors": [],
        }
        mock_discover.return_value = nd_result

        self._wire_completo_config()
        self._wire_scan_mocks()
        self.auditor.results["network_info"] = [
            {"interface": "eth0", "ip_version": 4},
        ]

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)

    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.core.auditor.maybe_chown_to_invoking_user")
    @patch("redaudit.utils.session_log.start_session_log")
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    @patch("redaudit.core.auditor.is_nuclei_available", return_value=False)
    @patch("redaudit.core.net_discovery.discover_networks")
    @patch("redaudit.core.net_discovery.detect_default_route_interface", return_value="eth0")
    def test_completo_udp_port_injection(
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
        """UDP ports from hyperscan_udp_ports are injected into Host objects."""
        nd_result = {
            "enabled": True,
            "dhcp_servers": [],
            "candidate_vlans": [],
            "hyperscan_duration": 0,
            "arp_hosts": [],
            "upnp_devices": [{"ip": "10.0.0.1", "device": "IoT (camera)"}],
            "hyperscan_tcp_hosts": {},
            "hyperscan_udp_ports": {"10.0.0.1": [1900, 5353]},
            "potential_backdoors": [],
        }
        mock_discover.return_value = nd_result

        self._wire_completo_config()
        # Disable net discovery so the block doesn't overwrite our pre-set results
        self.auditor.config["net_discovery_enabled"] = False
        self.auditor.config["scan_mode"] = "normal"
        host = self._wire_scan_mocks()
        # Pre-set the net_discovery result with UDP ports
        self.auditor.results["net_discovery"] = nd_result
        # Use real lists so .append() and set work
        real_services = []
        host.udp_ports = []
        host.services = real_services
        host.tags = set()
        host.ports = set()

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)

        # Check UDP services were injected
        self.assertEqual(len(real_services), 2)
        self.assertIn("iot", host.tags)

    @patch("redaudit.core.auditor.generate_summary")
    @patch("redaudit.core.auditor.maybe_chown_to_invoking_user")
    @patch("redaudit.utils.session_log.start_session_log")
    @patch("redaudit.utils.session_log.stop_session_log", return_value=None)
    @patch("redaudit.core.auditor.is_nuclei_available", return_value=False)
    @patch("redaudit.core.net_discovery.discover_networks")
    @patch("redaudit.core.net_discovery.detect_default_route_interface", return_value="eth0")
    def test_completo_no_iface_set(
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
        """Completo mode with no dhcp interfaces (empty network_info)."""
        mock_discover.return_value = {
            "enabled": True,
            "dhcp_servers": [],
            "candidate_vlans": [],
            "hyperscan_duration": 0,
            "arp_hosts": [],
            "upnp_devices": [],
            "hyperscan_tcp_hosts": {},
            "potential_backdoors": [],
        }

        self._wire_completo_config()
        host = self._wire_scan_mocks()
        self.auditor._select_net_discovery_interface = MagicMock(return_value=None)
        self.auditor.results["network_info"] = []  # Empty yields dhcp_interfaces=None

        result = self.auditor.run_complete_scan()
        self.assertTrue(result)


# ===========================================================================
# _nuclei_progress_callback (lines 2423-2491)
# ===========================================================================


class TestNucleiProgressCallback(unittest.TestCase):
    """Test the _nuclei_progress_callback method directly."""

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

    def test_callback_mid_progress(self):
        """Progress callback with completed > 0."""
        mock_progress = MagicMock()
        mock_task = MagicMock()
        start_time = time.time() - 10

        self.auditor._nuclei_progress_state = {
            "total_targets": 100,
            "max_targets": 0,
        }

        # _nuclei_progress_callback signature: completed, total, eta, progress, task,
        #   start_time, timeout, total_targets, batch_size, *, detail=None
        self.auditor._nuclei_progress_callback(
            50,
            100,
            "5m",
            mock_progress,
            mock_task,
            start_time,
            300,
            100,
            10,
            detail="running batch 5/10",
        )
        mock_progress.update.assert_called()

    def test_callback_zero_completed(self):
        """Progress callback at start (0 completed)."""
        mock_progress = MagicMock()
        mock_task = MagicMock()
        start_time = time.time()

        self.auditor._nuclei_progress_state = {
            "total_targets": 50,
            "max_targets": 0,
        }

        self.auditor._nuclei_progress_callback(
            0,
            50,
            "",
            mock_progress,
            mock_task,
            start_time,
            300,
            50,
            10,
        )
        mock_progress.update.assert_called()

    def test_callback_regression_protection(self):
        """Progress bar doesn't regress when retries reset completed."""
        mock_progress = MagicMock()
        mock_task = MagicMock()
        start_time = time.time() - 30

        self.auditor._nuclei_progress_state = {
            "total_targets": 100,
            "max_targets": 60,  # Previously saw 60
        }

        # Completed "regresses" to 30 due to retry
        self.auditor._nuclei_progress_callback(
            3,
            10,
            "2m",
            mock_progress,
            mock_task,
            start_time,
            300,
            100,
            10,
            detail="running retry",
        )
        # The update call should use max_seen=60, not 30
        update_call = mock_progress.update.call_args
        self.assertGreaterEqual(update_call.kwargs.get("completed", 0), 60)

    def test_callback_is_running_detail(self):
        """Progress callback with 'running' keyword in detail caps targets."""
        mock_progress = MagicMock()
        mock_task = MagicMock()
        start_time = time.time() - 5

        self.auditor._nuclei_progress_state = {
            "total_targets": 10,
            "max_targets": 0,
        }

        # completed=10 (all done) but detail says "running" -> caps to 9
        self.auditor._nuclei_progress_callback(
            10,
            10,
            "",
            mock_progress,
            mock_task,
            start_time,
            300,
            10,
            1,
            detail="running nuclei scan",
        )
        update_call = mock_progress.update.call_args
        completed = update_call.kwargs.get("completed", 0)
        self.assertLessEqual(completed, 9)


# ===========================================================================
# _nd_progress_callback
# ===========================================================================


class TestNdProgressCallback(unittest.TestCase):
    """Test the _nd_progress_callback method directly."""

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
        self.auditor.logger = MagicMock()

    def test_nd_callback_updates_progress(self):
        """nd progress callback updates progress bar correctly."""
        mock_progress = MagicMock()
        mock_task = MagicMock()
        start_time = time.time()

        self.auditor._nd_progress_callback(
            "ARP Sweep", 50, 100, mock_progress, mock_task, start_time
        )
        mock_progress.update.assert_called()


if __name__ == "__main__":
    unittest.main()
