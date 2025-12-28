#!/usr/bin/env python3
"""
Unit tests for redaudit.core.auditor_scan.AuditorScanMixin coverage.
"""

import unittest
from unittest.mock import MagicMock, patch, ANY, call
import datetime
import ipaddress
import logging
import sys

# Import module to patch against
import redaudit.core.auditor_scan as auditor_scan_module
from redaudit.core.auditor_scan import AuditorScanMixin
from redaudit.utils.constants import (
    STATUS_UP,
    STATUS_DOWN,
    STATUS_NO_RESPONSE,
    UDP_SCAN_MODE_FULL,
    UDP_SCAN_MODE_QUICK,
)


class MockAuditor(AuditorScanMixin):
    def __init__(self, config=None):
        self.config = config or {"scan_mode": "default", "output_dir": "/tmp"}
        self.logger = MagicMock(spec=logging.Logger)
        self.results = {}
        self.extra_tools = {"nmap": "/usr/bin/nmap"}
        self.rate_limit_delay = 0.0
        self.interrupted = False
        self.lang = "en"
        self.COLORS = {"HEADER": "", "OKGREEN": "", "WARNING": "", "FAIL": "", "ENDC": ""}
        self.cryptography_available = True

    def print_status(self, msg, status_type, **kwargs):
        pass

    def t(self, key, *args):
        return f"{key}_{'_'.join(map(str, args))}"

    def ask_choice(self, question, options):
        return 0

    def ask_manual_network(self):
        return "192.168.1.0/24"

    def _set_ui_detail(self, detail):
        pass

    def _get_ui_detail(self):
        return ""

    def _progress_ui(self):
        return MagicMock()  # Context manager

    def _progress_console(self):
        return MagicMock()

    def _progress_columns(self, **kwargs):
        return []

    def _safe_text_column(self, *args, **kwargs):
        return MagicMock()

    def _format_eta(self, seconds):
        return "00:00"

    def _touch_activity(self):
        pass

    def _coerce_text(self, value: object) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value) if value is not None else ""


class TestAuditorScanCoverage(unittest.TestCase):

    def setUp(self):
        self.auditor = MockAuditor()
        # manual mock of nmap global
        from redaudit.core import auditor_scan

        self.original_nmap = auditor_scan.nmap
        self.mock_nmap_module = MagicMock()
        self.mock_portscanner = MagicMock()
        self.mock_nmap_module.PortScanner.return_value = self.mock_portscanner
        auditor_scan.nmap = self.mock_nmap_module

    def tearDown(self):
        from redaudit.core import auditor_scan

        auditor_scan.nmap = self.original_nmap

    def test_check_dependencies(self):
        with (
            patch("redaudit.core.auditor_scan.shutil.which") as mock_which,
            patch("redaudit.core.auditor_scan.importlib.import_module") as mock_import,
            patch.object(auditor_scan_module, "is_crypto_available") as mock_crypto,
        ):

            # 1. All good
            mock_which.return_value = "/bin/nmap"
            mock_crypto.return_value = True
            mock_import.return_value = self.mock_nmap_module
            self.assertTrue(self.auditor.check_dependencies())

            # 2. Crypto Missing (Patch object directly on module)
            mock_crypto.return_value = False
            self.assertTrue(self.auditor.check_dependencies())

            # 3. Nmap missing
            mock_which.return_value = None
            self.assertFalse(self.auditor.check_dependencies())

            # 4. Python-nmap import fails
            mock_which.return_value = "/bin/nmap"
            mock_import.side_effect = ImportError
            self.auditor.check_dependencies()

    @patch("redaudit.core.auditor_scan.detect_all_networks")
    def test_detect_all_networks(self, mock_detect):
        mock_detect.return_value = [
            {"network": "1.2.3.0/24", "interface": "eth0", "hosts_estimated": 254}
        ]
        nets = self.auditor.detect_all_networks()
        self.assertEqual(len(nets), 1)
        self.assertEqual(self.auditor.results["network_info"], nets)

    def test_collect_discovery_hosts(self):
        self.auditor.results["net_discovery"] = {
            "alive_hosts": ["192.168.1.10"],
            "arp_hosts": [{"ip": "192.168.1.11"}],
            "hyperscan_tcp_hosts": {"192.168.1.12": {}},
            # Ensure none behavior
            "upnp_devices": None,
        }

        hosts = self.auditor._collect_discovery_hosts([])
        self.assertIn("192.168.1.10", hosts)
        self.assertIn("192.168.1.11", hosts)
        self.assertIn("192.168.1.12", hosts)

        # Test empty input
        self.auditor.results["net_discovery"] = {}
        hosts_empty = self.auditor._collect_discovery_hosts([])
        self.assertEqual(hosts_empty, [])

        # Test filtering with invalid IP in list (should be handled by sanitize_ip inside)
        self.auditor.results["net_discovery"] = {"alive_hosts": ["invalid_ip"]}
        hosts_inv = self.auditor._collect_discovery_hosts([])
        self.assertEqual(hosts_inv, [])

    @patch("redaudit.core.auditor_scan.detect_all_networks")
    def test_ask_network_range_auto(self, mock_detect):
        mock_detect.return_value = [
            {"network": "10.0.0.0/24", "interface": "eth0", "hosts_estimated": 254}
        ]
        self.auditor.ask_choice = MagicMock(return_value=0)

        selected = self.auditor.ask_network_range()
        self.assertEqual(selected, ["10.0.0.0/24"])

        self.auditor.ask_choice = MagicMock(return_value=1)
        self.auditor.ask_manual_network = MagicMock(return_value="1.2.3.4")
        self.assertEqual(self.auditor.ask_network_range(), ["1.2.3.4"])

        mock_detect.return_value = []
        self.auditor.ask_manual_network = MagicMock(return_value="manual_net")
        self.assertEqual(self.auditor.ask_network_range(), ["manual_net"])

    def test_select_net_discovery_interface(self):
        self.auditor.config["net_discovery_interface"] = "tun0"
        self.assertEqual(self.auditor._select_net_discovery_interface(), "tun0")

        self.auditor.config["net_discovery_interface"] = None
        self.auditor.config["target_networks"] = ["192.168.1.0/24"]
        self.auditor.results["network_info"] = [
            {"network": "10.0.0.0/24", "interface": "eth0"},
            {"network": "192.168.1.0/24", "interface": "eth1"},
        ]
        self.assertEqual(self.auditor._select_net_discovery_interface(), "eth1")

        self.auditor.config["target_networks"] = ["1.1.1.0/24"]
        self.assertEqual(self.auditor._select_net_discovery_interface(), "eth0")

    @patch("redaudit.core.auditor_scan.run_nmap_command")
    def test_run_nmap_xml_scan(self, mock_run):
        self.auditor.config["dry_run"] = False

        # 1. Success with XML parser
        mock_run.return_value = {"stdout": "<nmaprun>XML</nmaprun>", "returncode": 0}
        nm, err = self.auditor._run_nmap_xml_scan("1.2.3.4", "-sV")
        self.assertIsNotNone(nm)
        self.assertEqual(err, "")
        self.mock_portscanner.analyse_nmap_xml_scan.assert_called()

        # 2. XML Parser error
        self.mock_portscanner.analyse_nmap_xml_scan.side_effect = Exception("Parsing fail")
        nm, err = self.auditor._run_nmap_xml_scan("1.2.3.4", "-sV")
        self.assertIsNone(nm)
        self.assertIn("nmap_xml_parse_error", err)
        self.mock_portscanner.analyse_nmap_xml_scan.side_effect = None

        # 3. No XML parser available (e.g. older python-nmap)
        del self.mock_portscanner.analyse_nmap_xml_scan
        del self.mock_portscanner.analyze_nmap_xml_scan

        nm, err = self.auditor._run_nmap_xml_scan("1.2.3.4", "-sV")
        # Should call scan() fallback
        self.mock_portscanner.scan.assert_called()
        self.assertIsNotNone(nm)

        # 4. Error case: Timeout
        mock_run.return_value = {"error": "Timeout"}
        nm, err = self.auditor._run_nmap_xml_scan("1.2.3.4", "-sV")
        self.assertIsNone(nm)
        self.assertEqual(err, "Timeout")

    def test_deep_scan_host(self):
        with (
            patch("redaudit.core.auditor_scan.extract_vendor_mac") as mock_extract_mac,
            patch("redaudit.core.auditor_scan.extract_os_detection") as mock_extract_os,
            patch("redaudit.core.auditor_scan.start_background_capture") as mock_start_cap,
            patch("redaudit.core.auditor_scan.stop_background_capture") as mock_stop_cap,
            patch("redaudit.core.auditor_scan.run_nmap_command") as mock_nmap,
            patch("redaudit.core.auditor_scan.run_udp_probe") as mock_udp,
            patch("redaudit.core.auditor_scan.output_has_identity") as mock_has_ident,
            patch(
                "redaudit.core.auditor_scan.UDP_PRIORITY_PORTS", "80,invalid,443"
            ) as mock_udp_ports,
        ):

            self.auditor.config["output_dir"] = "/tmp"
            mock_start_cap.return_value = {"proc": "foo"}

            # Mocks return values
            mock_extract_mac.return_value = (None, None)
            mock_extract_os.return_value = None

            # 1. Identity found in Phase 1 -> Skip Phase 2
            mock_nmap.return_value = {"stdout": "Scan Output", "timeout": False}
            mock_has_ident.return_value = True
            mock_udp.return_value = []

            res = self.auditor.deep_scan_host("192.168.1.100")
            self.assertIn("phase2_skipped", res)

            # 2. Identity NOT found -> UDP Priority Probe + Full UDP
            # Also testing invalid UDP port injection
            mock_has_ident.return_value = False
            self.auditor.config["udp_mode"] = UDP_SCAN_MODE_FULL

            # Reset mocks
            mock_nmap.reset_mock()
            # Phase 1, Phase 2b
            mock_nmap.side_effect = [
                {"stdout": "Mix1", "stderr": ""},
                {"stdout": "Mix2", "stderr": ""},
            ]

            res = self.auditor.deep_scan_host("192.168.1.100")
            self.assertIn("udp_top_ports", res)

            # 3. Quick mode UDP
            mock_nmap.side_effect = None
            mock_nmap.return_value = {"stdout": "Mix1", "stderr": ""}
            self.auditor.config["udp_mode"] = UDP_SCAN_MODE_QUICK
            mock_has_ident.return_value = False

            res_quick = self.auditor.deep_scan_host("192.168.1.101")
            self.assertIn("phase2b_skipped", res_quick)

    def test_scan_network_discovery(self):
        self.mock_portscanner.all_hosts.return_value = ["1.1.1.1"]
        self.mock_portscanner["1.1.1.1"].state.return_value = "up"

        hosts = self.auditor.scan_network_discovery("1.1.1.0/24")
        self.assertEqual(hosts, ["1.1.1.1"])
        self.mock_portscanner.scan.assert_called()

        # Error case
        self.mock_portscanner.scan.side_effect = Exception("Fail")
        hosts = self.auditor.scan_network_discovery("1.1.1.0/24")
        self.assertEqual(hosts, [])

    def test_scan_host_ports(self):
        with (
            patch("redaudit.core.auditor_scan.AuditorScanMixin.deep_scan_host") as mock_deep,
            patch("redaudit.core.auditor_scan.enrich_host_with_whois") as mock_whois,
            patch("redaudit.core.auditor_scan.enrich_host_with_dns") as mock_dns,
            patch("redaudit.core.auditor_scan.banner_grab_fallback") as mock_banner,
            patch("redaudit.core.auditor_scan.finalize_host_status") as mock_finalize,
            patch("redaudit.core.auditor_scan.AuditorScanMixin._run_nmap_xml_scan") as mock_run_xml,
            patch("redaudit.core.auditor_scan.exploit_lookup") as mock_exploit,
        ):

            mock_nm = MagicMock()
            mock_run_xml.return_value = (mock_nm, "")

            mock_nm.all_hosts.return_value = ["1.1.1.1"]
            host_data = MagicMock()
            mock_nm.__getitem__.return_value = host_data

            # 1. Standard Success
            host_data.hostnames.return_value = [{"name": "host1"}]
            host_data.state.return_value = "up"
            host_data.all_protocols.return_value = ["tcp"]
            # To trigger banner grab, name must be unknown
            p_data = {
                80: {"name": "tcpwrapped", "product": "", "version": "", "extrainfo": "", "cpe": []}
            }
            host_data.__getitem__.return_value = p_data

            mock_finalize.return_value = STATUS_UP
            mock_exploit.return_value = ["exploit1"]
            mock_deep.return_value = {"os_detected": "Linux"}
            mock_banner.return_value = {80: {"banner": "SSH-2.0", "service": "ssh"}}

            self.auditor.extra_tools["searchsploit"] = "yes"

            res = self.auditor.scan_host_ports("1.1.1.1")

            # Relaxed assertion: content check
            self.assertIn("smart_scan", res)
            self.assertEqual(res["ip"], "1.1.1.1")
            self.assertEqual(res["ports"][0]["port"], 80)

            # 2. Nmap failure
            mock_run_xml.return_value = (None, "Scan Error")
            res_fail = self.auditor.scan_host_ports("1.1.1.1")
            self.assertEqual(res_fail["status"], STATUS_NO_RESPONSE)
            self.assertEqual(res_fail["error"], "Scan Error")

    def test_parse_host_timeout_s(self):
        self.assertEqual(self.auditor._parse_host_timeout_s("--host-timeout 1000ms"), 1.0)
        self.assertEqual(self.auditor._parse_host_timeout_s("--host-timeout 60s"), 60.0)
        self.assertIsNone(self.auditor._parse_host_timeout_s(""))

    def test_scan_hosts_concurrent_smoke(self):
        with (
            patch("redaudit.core.auditor_scan.ThreadPoolExecutor") as mock_executor,
            patch("redaudit.core.auditor_scan.wait") as mock_wait,
            patch("redaudit.core.auditor_scan.as_completed") as mock_as_completed,
        ):

            # Setup wait to return done futures immediatley
            def side_effect_wait(fs, timeout=None, return_when=None):
                return fs, set()  # all done, none pending

            mock_wait.side_effect = side_effect_wait

            # submit returns a future mock
            mock_pool = MagicMock()
            mock_executor.return_value.__enter__.return_value = mock_pool
            mock_fut = MagicMock()
            mock_pool.submit.return_value = mock_fut
            mock_fut.result.return_value = {"ip": "1.1.1.1", "ports": []}

            # 1. With Rich
            with patch.dict(sys.modules, {"rich.progress": MagicMock()}):
                hosts = ["1.1.1.1"]

                self.auditor.scan_hosts_concurrent(hosts)
                mock_pool.submit.assert_called()

            # 2. Without Rich (forced ImportError)
            with patch.dict(sys.modules, {"rich.progress": None}):
                mock_as_completed.return_value = [mock_fut]
                self.auditor.scan_hosts_concurrent(hosts)
                mock_as_completed.assert_called()

    @patch("redaudit.core.auditor_scan.summarize_agentless_fingerprint")
    @patch("redaudit.core.auditor_scan.probe_agentless_services")
    @patch("redaudit.core.auditor_scan.select_agentless_probe_targets")
    def test_run_agentless_verification(self, mock_select, mock_probe, mock_summarize):
        self.auditor.config["windows_verify_enabled"] = True
        host_res = [{"ip": "1.1.1.1"}]

        MockTarget = MagicMock()
        MockTarget.ip = "1.1.1.1"

        # 1. With Rich and Windows OS
        mock_select.return_value = [MockTarget]
        mock_probe.return_value = {"ip": "1.1.1.1", "os": "Windows"}
        # ensure mock_summarize returns what we expect
        mock_summarize.return_value = {"os": "Windows"}

        with patch.dict(sys.modules, {"rich.progress": MagicMock()}):
            self.auditor.run_agentless_verification(host_res)

        self.assertIn("agentless_probe", host_res[0])
        self.assertEqual(host_res[0]["agentless_probe"]["os"], "Windows")

        # 2. Update existing Agentless Fingerprint logic & invalid Int parsing
        host_res[0]["agentless_fingerprint"] = {"existing_key": "existing_val"}
        # Force identity_score to be junk to test try/except
        host_res[0]["smart_scan"] = {"identity_score": "JUNK"}

        # New value to merge
        mock_summarize.return_value = {"new_key": "new_val"}

        with patch.dict(sys.modules, {"rich.progress": MagicMock()}):
            self.auditor.run_agentless_verification(host_res)

        # Check both keys exist
        self.assertEqual(host_res[0]["agentless_fingerprint"]["existing_key"], "existing_val")
        self.assertEqual(host_res[0]["agentless_fingerprint"]["new_key"], "new_val")
        # identity_score should remain JUNK because int() failed
        self.assertEqual(host_res[0]["smart_scan"]["identity_score"], "JUNK")


if __name__ == "__main__":
    unittest.main()
