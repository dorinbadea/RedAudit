#!/usr/bin/env python3
"""
RedAudit - Tests for deep scan heuristics
Ensures adaptive deep scan doesn't waste time on quiet hosts.
"""

import os
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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

        with patch("redaudit.core.auditor_scan.nmap") as mock_nmap:
            mock_nmap.PortScanner.return_value = nm
            app.deep_scan_host = Mock(return_value={"strategy": "mock", "commands": []})

            result = app.scan_host_ports(ip)

        # v3.8: Quiet hosts (0 ports, generic vendor, no signals) skip deep scan
        self.assertFalse(app.deep_scan_host.called)
        self.assertEqual(result.get("total_ports_found"), 0)
        self.assertEqual(result.get("deep_scan", {}).get("mac_address"), "00:11:22:33:44:55")
        self.assertEqual(result.get("deep_scan", {}).get("vendor"), "Generic Corp")

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

        with patch("redaudit.core.auditor_scan.nmap") as mock_nmap:
            mock_nmap.PortScanner.return_value = nm
            app.deep_scan_host = Mock(return_value={"strategy": "mock", "commands": []})

            _ = app.scan_host_ports(ip)

        self.assertTrue(app.deep_scan_host.called)

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


if __name__ == "__main__":
    unittest.main()
