#!/usr/bin/env python3
"""
RedAudit - Tests for deep scan heuristics
Ensures adaptive deep scan doesn't waste time on quiet hosts.
"""

import os
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from redaudit.core.auditor import InteractiveNetworkAuditor


class _FakeHost(dict):
    def hostnames(self):
        return []

    def all_protocols(self):
        return ["tcp"]

    def state(self):
        return "up"


class _FakePortScanner:
    def __init__(self, ip: str, host: _FakeHost):
        self._ip = ip
        self._host = host

    def scan(self, *_args, **_kwargs):
        return None

    def all_hosts(self):
        return [self._ip]

    def __getitem__(self, ip):
        if ip != self._ip:
            raise KeyError(ip)
        return self._host


class TestAuditorDeepScanHeuristics(unittest.TestCase):
    def test_deep_scan_extracts_os_detection(self):
        app = InteractiveNetworkAuditor()
        app.print_status = lambda *_args, **_kwargs: None
        app.config["udp_mode"] = "quick"
        app.config["udp_top_ports"] = 100

        ip = "192.168.1.50"
        rec1 = {"stdout": "OS details: Linux 5.4 - 5.11\n", "stderr": "", "returncode": 0}

        with patch("redaudit.core.auditor_scan.start_background_capture", return_value=None):
            with patch("redaudit.core.auditor_scan.stop_background_capture", return_value=None):
                with patch("redaudit.core.auditor_scan.run_nmap_command", return_value=rec1):
                    with patch("redaudit.core.auditor_scan.output_has_identity", return_value=True):
                        with patch(
                            "redaudit.core.auditor_scan.extract_vendor_mac",
                            return_value=(None, None),
                        ):
                            deep = app.deep_scan_host(ip)

        self.assertIsInstance(deep, dict)
        self.assertEqual(deep.get("os_detected"), "Linux 5.4 - 5.11")

    def test_full_mode_skips_deep_scan_for_quiet_host(self):
        """v3.8: Deep scan is skipped for quiet hosts with no interesting signals.

        Note: Routers (AVM, Cisco, etc.) now ALWAYS trigger deep scan.
        This test uses a generic vendor to verify quiet host behavior.
        """
        app = InteractiveNetworkAuditor()
        app.print_status = lambda *_args, **_kwargs: None
        app.config["scan_mode"] = "completo"
        app.config["deep_id_scan"] = True

        ip = "192.168.1.201"
        # Use a generic vendor (not AVM/Cisco/router) to test quiet host logic
        fake_host = _FakeHost(
            {
                "tcp": {},  # No open ports = quiet host
                "addresses": {"mac": "00:11:22:33:44:55"},
                "vendor": {"00:11:22:33:44:55": "Generic Corp"},
            }
        )
        nm = _FakePortScanner(ip=ip, host=fake_host)

        with patch.object(app.scanner, "run_nmap_scan", return_value=(nm, "")):
            app.deep_scan_host = Mock(return_value={"strategy": "mock", "commands": []})
            result = app.scan_host_ports(ip)

        # v3.8: Quiet hosts (0 ports, generic vendor, no signals) skip deep scan
        self.assertFalse(app.deep_scan_host.called)
        self.assertEqual(result.total_ports_found, 0)
        self.assertEqual(result.deep_scan.get("mac_address"), "00:11:22:33:44:55")
        self.assertEqual(result.deep_scan.get("vendor"), "Generic Corp")

    def test_normal_mode_still_triggers_deep_scan_for_small_port_hosts(self):
        app = InteractiveNetworkAuditor()
        app.print_status = lambda *_args, **_kwargs: None
        app.config["scan_mode"] = "normal"
        app.config["deep_id_scan"] = True

        ip = "192.168.1.10"
        fake_host = _FakeHost(
            {
                "tcp": {
                    80: {"name": "http", "product": "", "version": "", "extrainfo": "", "cpe": []},
                    443: {
                        "name": "https",
                        "product": "",
                        "version": "",
                        "extrainfo": "",
                        "cpe": [],
                    },
                },
            }
        )
        nm = _FakePortScanner(ip=ip, host=fake_host)

        with patch.object(app.scanner, "run_nmap_scan", return_value=(nm, "")):
            app.deep_scan_host = Mock(return_value={"strategy": "mock", "commands": []})
            result = app.scan_host_ports(ip)

        # v4.2: Deep scan is decoupled. It is no longer called immediately.
        # Instead, the host is marked for deferred deep scan.
        # self.assertTrue(app.deep_scan_host.called)
        if hasattr(result, "smart_scan"):
            self.assertTrue(result.smart_scan.get("deep_scan_suggested"))
        else:
            self.assertTrue(result.get("smart_scan", {}).get("deep_scan_suggested"))

    def test_no_deep_scan_disables_hyperscan_override(self):
        app = InteractiveNetworkAuditor()
        app.print_status = lambda *_args, **_kwargs: None
        app.config["scan_mode"] = "completo"
        app.config["deep_id_scan"] = False

        ip = "192.168.1.250"
        fake_host = _FakeHost(
            {
                "tcp": {},  # No open ports from nmap
                "addresses": {"mac": "00:11:22:33:44:55"},
                "vendor": {"00:11:22:33:44:55": "Generic Corp"},
            }
        )
        nm = _FakePortScanner(ip=ip, host=fake_host)
        app.results = {"net_discovery": {"hyperscan_tcp_hosts": {ip: [80, 443]}}}

        with patch.object(app, "_compute_identity_score", return_value=(0, [])):
            with patch.object(app.scanner, "run_nmap_scan", return_value=(nm, "")):
                result = app.scan_host_ports(ip)

        smart_scan = (
            result.smart_scan if hasattr(result, "smart_scan") else result.get("smart_scan")
        )
        self.assertFalse(smart_scan.get("trigger_deep"))
        self.assertNotIn("hyperscan_ports_detected", smart_scan.get("reasons", []))
        self.assertFalse(smart_scan.get("deep_scan_suggested", False))

    def test_udp_full_uses_configurable_top_ports(self):
        app = InteractiveNetworkAuditor()
        app.print_status = lambda *_args, **_kwargs: None
        app.config["udp_mode"] = "full"
        app.config["udp_top_ports"] = 222

        with patch("redaudit.core.auditor_scan.start_background_capture", return_value=None):
            with patch("redaudit.core.auditor_scan.stop_background_capture", return_value=None):
                with patch("redaudit.core.auditor_scan.output_has_identity", return_value=False):
                    with patch(
                        "redaudit.core.auditor_scan.extract_vendor_mac", return_value=(None, None)
                    ):
                        with patch("redaudit.core.auditor_scan.run_udp_probe", return_value=[]):
                            with patch(
                                "redaudit.core.auditor_scan.get_neighbor_mac", return_value=None
                            ):
                                with patch(
                                    "redaudit.core.auditor_scan.run_nmap_command"
                                ) as mock_run:
                                    mock_run.return_value = {
                                        "stdout": "",
                                        "stderr": "",
                                        "returncode": 0,
                                    }
                                    deep = app.deep_scan_host("192.168.1.50")

        self.assertIsInstance(deep, dict)
        self.assertEqual(deep.get("udp_top_ports"), 222)
        self.assertIn("udp_priority_probe", deep)

        cmds = [call.args[0] for call in mock_run.call_args_list]
        self.assertGreaterEqual(len(cmds), 2)
        full_udp_cmd = cmds[1]
        self.assertIn("--top-ports", full_udp_cmd)
        self.assertIn("222", full_udp_cmd)

    def test_deep_scan_strategy_label_strips_parenthetical(self):
        app = InteractiveNetworkAuditor()
        app.ui = Mock()

        def _t(key, *args):
            labels = {
                "deep_strategy_adaptive": "Adaptativo (3 fases v2.8)",
                "deep_identity_start": "Escaneo de identidad profundo para {} (estrategia: {})",
            }
            val = labels.get(key, key)
            return val.format(*args) if args else val

        app.ui.t.side_effect = _t
        app.ui.print_status = Mock()
        app.config["output_dir"] = "/tmp"
        app.results = {"network_info": []}

        with patch(
            "redaudit.core.auditor_scan.start_background_capture",
            side_effect=RuntimeError("boom"),
        ):
            with self.assertRaises(RuntimeError):
                app.deep_scan_host("192.168.1.10")

        message = app.ui.print_status.call_args[0][0]
        self.assertIn("Adaptativo", message)
        self.assertNotIn("3 fases", message)
        self.assertNotIn("v2.8", message)

    def test_trust_hyperscan_quiet_host_uses_sanity_check(self):
        """v4.6.2: Quiet hosts with trust_hyperscan should use sanity check (top-1000) not -p-."""
        app = InteractiveNetworkAuditor()
        app.print_status = lambda *_args, **_kwargs: None
        app.config["trust_hyperscan"] = True

        # Mock empty discovery ports (mute host)
        trusted_ports = []
        ip = "192.168.1.99"

        with patch("redaudit.core.auditor_scan.start_background_capture", return_value=None):
            with patch("redaudit.core.auditor_scan.stop_background_capture", return_value=None):
                with patch("redaudit.core.auditor_scan.output_has_identity", return_value=False):
                    with patch(
                        "redaudit.core.auditor_scan.extract_vendor_mac", return_value=(None, None)
                    ):
                        with patch("redaudit.core.auditor_scan.run_udp_probe", return_value=[]):
                            with patch(
                                "redaudit.core.auditor_scan.get_neighbor_mac", return_value=None
                            ):
                                with patch(
                                    "redaudit.core.auditor_scan.run_nmap_command"
                                ) as mock_run:
                                    mock_run.return_value = {
                                        "stdout": "",
                                        "stderr": "",
                                        "returncode": 0,
                                    }

                                    app.deep_scan_host(ip, trusted_ports=trusted_ports)

                                    # Verify called with --top-ports 1000
                                    args = mock_run.call_args[0][0]  # First arg is cmd list
                                    self.assertIn("--top-ports", args)
                                    self.assertIn("1000", args)
                                    self.assertNotIn("-p-", args)

    def test_trust_hyperscan_uses_discovered_ports(self):
        app = InteractiveNetworkAuditor()
        app.print_status = lambda *_args, **_kwargs: None
        app.config["trust_hyperscan"] = True

        ip = "192.168.1.55"
        rec1 = {"stdout": "22/tcp open ssh OpenSSH 8.0\n", "stderr": "", "returncode": 0}

        with (
            patch("redaudit.core.auditor_scan.start_background_capture", return_value=None),
            patch("redaudit.core.auditor_scan.stop_background_capture", return_value=None),
            patch("redaudit.core.auditor_scan.output_has_identity", return_value=False),
            patch("redaudit.core.auditor_scan.extract_vendor_mac", return_value=(None, None)),
            patch("redaudit.core.auditor_scan.extract_os_detection", return_value=None),
            patch(
                "redaudit.core.auditor_scan.extract_detailed_identity",
                return_value={
                    "vendor": "VendorX",
                    "model": "ModelY",
                    "device_type": "router",
                    "os_detected": "OSZ",
                },
            ),
            patch("redaudit.core.auditor_scan.run_udp_probe", return_value=[]),
            patch("redaudit.core.auditor_scan.get_neighbor_mac", return_value=None),
            patch("redaudit.core.auditor_scan.run_nmap_command", return_value=rec1) as mock_run,
        ):
            deep = app.deep_scan_host(ip, trusted_ports=[22, 80])

        args = mock_run.call_args[0][0]
        self.assertIn("-p22,80", args)
        self.assertEqual(deep.get("vendor"), "VendorX")
        self.assertEqual(deep.get("model"), "ModelY")
        self.assertEqual(deep.get("device_type"), "router")
        self.assertEqual(deep.get("os_detected"), "OSZ")


if __name__ == "__main__":
    unittest.main()
