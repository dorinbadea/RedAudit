import unittest
from unittest.mock import MagicMock, patch, ANY

from redaudit.core.models import Host, Service
from redaudit.core.auditor_scan import AuditorScan, STATUS_DOWN


class TestScanHostPorts(unittest.TestCase):
    def setUp(self):
        self.auditor = MagicMock()
        self.auditor.config = {
            "scan_mode": "default",
            "dry_run": False,
            "stealth": False,
            "no_hyperscan_first": False,
            "low_impact_enrichment": False,
        }
        self.auditor.ui = MagicMock()
        self.auditor.logger = MagicMock()
        self.auditor.scanner = MagicMock()
        self.auditor.results = {}
        self.auditor._hyperscan_discovery_ports = {}
        self.auditor._set_ui_detail = MagicMock()
        self.auditor.ui.t.return_value = "Test Message"
        self.auditor._run_low_impact_enrichment = MagicMock(return_value={})
        self.auditor._lookup_topology_identity = MagicMock(return_value=(None, None))
        self.scan_host = AuditorScan.scan_host_ports.__get__(self.auditor, AuditorScan)

    def test_scan_host_ports_invalid_ip(self):
        """Invalid IP returns error dict."""
        res = self.scan_host("invalid-ip")
        self.assertEqual(res.get("error"), "Invalid IP")

    def test_scan_host_ports_dry_run(self):
        """Dry run populates Host but skips nmap."""
        self.auditor.config["dry_run"] = True
        mock_host = MagicMock(spec=Host)
        self.auditor.scanner.get_or_create_host.return_value = mock_host
        res = self.scan_host("192.168.1.1")
        self.assertEqual(res, mock_host)
        self.assertEqual(mock_host.status, STATUS_DOWN)
        self.auditor.scanner.run_nmap_scan.assert_not_called()

    def test_scan_host_ports_nmap_success(self):
        """Successful nmap scan populates Host.services."""
        ip = "192.168.1.1"

        # Build a mock nmap result that iterates correctly.
        # The source code does:
        #   for proto in data.all_protocols():
        #       for p in data[proto]:          <-- iterates dict-like
        #           svc = data[proto][p]       <-- subscript access
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = [ip]
        data = mock_nm[ip]
        data.hostnames.return_value = [{"name": "test-host"}]
        data.state.return_value = "up"
        data.all_protocols.return_value = ["tcp"]

        # data["tcp"] must be iterable AND support subscript
        svc_info = {
            "state": "open",
            "name": "http",
            "product": "Apache",
            "version": "2.4.41",
            "extrainfo": "Ubuntu",
            "cpe": "cpe:/a:apache:http_server:2.4.41",
        }
        tcp_mock = MagicMock()
        tcp_mock.__iter__ = MagicMock(return_value=iter([80]))
        tcp_mock.__getitem__ = MagicMock(return_value=svc_info)
        data.__getitem__ = MagicMock(return_value=tcp_mock)

        self.auditor.scanner.run_nmap_scan.return_value = (mock_nm, None)

        # Real Host object so add_service actually appends
        host_obj = Host(ip=ip)
        self.auditor.scanner.get_or_create_host.return_value = host_obj

        res = self.scan_host(ip)

        self.assertIs(res, host_obj)
        self.assertTrue(len(host_obj.services) > 0)
        svc = host_obj.services[0]
        self.assertEqual(svc.port, 80)
        self.assertEqual(svc.name, "http")
        self.assertEqual(svc.product, "Apache")

    def test_scan_host_ports_hyperscan_optimization(self):
        """HyperScan-first optimisation passes discovered ports to nmap."""
        self.auditor.config["scan_mode"] = "full"
        ip = "192.168.1.1"
        self.auditor._hyperscan_discovery_ports = {ip: [80, 443]}

        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = [ip]
        self.auditor.scanner.run_nmap_scan.return_value = (mock_nm, None)
        self.auditor.scanner.get_or_create_host.return_value = MagicMock(spec=Host)

        self.scan_host(ip)

        args, _ = self.auditor.scanner.run_nmap_scan.call_args
        scan_args = args[1]
        self.assertIn("-p 80,443", scan_args)


class TestDeepScanHost(unittest.TestCase):
    def setUp(self):
        self.auditor = MagicMock()
        self.auditor.config = {
            "output_dir": "/tmp/scans",
            "trust_hyperscan": True,
            "udp_mode": "top-ports",
        }
        self.auditor.ui = MagicMock()
        self.auditor.logger = MagicMock()
        self.auditor.results = {}
        self.auditor.extra_tools = {}
        self.auditor.proxy_manager = None
        self.auditor._set_ui_detail = MagicMock()
        self.auditor.ui.t.return_value = "Test Message"
        self.auditor._parse_host_timeout_s = MagicMock(return_value=120)
        self.auditor._reserve_deep_scan_slot = MagicMock(return_value=None)
        self.auditor._coerce_text = MagicMock(side_effect=lambda x: x or "")
        self.auditor._parse_nmap_open_ports = MagicMock(return_value=[])
        self.auditor._merge_ports = MagicMock(side_effect=lambda a, b: a + b)
        self.deep_scan = AuditorScan.deep_scan_host.__get__(self.auditor, AuditorScan)

    @patch("redaudit.core.auditor_scan.run_udp_probe", return_value=[])
    @patch("redaudit.core.auditor_scan.extract_detailed_identity", return_value=None)
    @patch("redaudit.core.auditor_scan.extract_os_detection", return_value="")
    @patch("redaudit.core.auditor_scan.extract_vendor_mac", return_value=("", ""))
    @patch("redaudit.core.auditor_scan.output_has_identity", return_value=False)
    @patch("redaudit.core.auditor_scan.run_nmap_command")
    @patch("redaudit.core.auditor_scan.stop_background_capture")
    @patch("redaudit.core.auditor_scan.start_background_capture")
    def test_deep_scan_execution_flow(
        self,
        mock_start_cap,
        mock_stop_cap,
        mock_nmap_cmd,
        mock_has_id,
        mock_vendor,
        mock_os,
        mock_detail_id,
        mock_udp,
    ):
        """Deep scan with trusted ports uses optimised nmap command."""
        ip = "192.168.1.1"
        mock_start_cap.return_value = ("proc", "file.pcap")
        mock_nmap_cmd.return_value = {"stdout": "", "stderr": "", "returncode": 0}

        res = self.deep_scan(ip, trusted_ports=[80, 443])

        mock_start_cap.assert_called_once()
        mock_stop_cap.assert_called_once()
        # First run_nmap_command call should contain the trusted ports
        first_call_cmd = mock_nmap_cmd.call_args_list[0][0][0]
        cmd_str = " ".join(first_call_cmd)
        self.assertIn("nmap", cmd_str)
        self.assertIn("-p80,443", cmd_str)
        self.assertIsNotNone(res)
        self.assertEqual(res["strategy"], "adaptive_v2.8")

    @patch("redaudit.core.auditor_scan.get_neighbor_mac", return_value=None)
    @patch("redaudit.core.auditor_scan.run_udp_probe", return_value=[])
    @patch("redaudit.core.auditor_scan.extract_detailed_identity", return_value=None)
    @patch("redaudit.core.auditor_scan.extract_os_detection", return_value="")
    @patch("redaudit.core.auditor_scan.extract_vendor_mac", return_value=("", ""))
    @patch("redaudit.core.auditor_scan.output_has_identity", return_value=False)
    @patch("redaudit.core.auditor_scan.run_nmap_command")
    @patch("redaudit.core.auditor_scan.stop_background_capture")
    @patch("redaudit.core.auditor_scan.start_background_capture")
    def test_deep_scan_full_udp_trigger(
        self,
        mock_start_cap,
        mock_stop_cap,
        mock_nmap_cmd,
        mock_has_id,
        mock_vendor,
        mock_os,
        mock_detail_id,
        mock_udp,
        mock_neigh,
    ):
        """Full UDP mode triggers Phase 2b nmap -sU scan."""
        self.auditor.config["udp_mode"] = "full"
        mock_start_cap.return_value = ("proc", "file.pcap")
        mock_nmap_cmd.return_value = {"stdout": "", "stderr": "", "returncode": 0}

        self.deep_scan("192.168.1.1", trusted_ports=[])

        # Phase 2b command should contain -sU and --top-ports
        found_udp = False
        for call_obj in mock_nmap_cmd.call_args_list:
            cmd_list = call_obj[0][0]
            cmd_str = " ".join(cmd_list)
            if "-sU" in cmd_str and "--top-ports" in cmd_str:
                found_udp = True
                break
        self.assertTrue(found_udp, "Full UDP scan should have been triggered")
