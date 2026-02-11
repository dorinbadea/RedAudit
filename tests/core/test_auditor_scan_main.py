import unittest
from unittest.mock import MagicMock, patch, call
from redaudit.core.auditor_scan import AuditorScan
import concurrent.futures


class TestScanHostsConcurrent(unittest.TestCase):
    def setUp(self):
        self.auditor = MagicMock()  # Removed spec=AuditorScan
        self.auditor.config = {"threads": 2, "scan_mode": "default", "dry_run": False}
        self.auditor.ui = MagicMock()
        self.auditor.logger = MagicMock()
        self.auditor.results = {}
        self.auditor.interrupted = False
        self.auditor.rate_limit_delay = 0.0

        # Helper methods
        self.auditor._progress_ui.return_value.__enter__.return_value = None
        self.auditor._set_ui_detail = MagicMock()
        self.auditor._parse_host_timeout_s = MagicMock(return_value=10)
        self.auditor._scan_mode_host_timeout_s = MagicMock(return_value=10)
        self.auditor.ui.get_progress_console.return_value = None

        # Bind the method to test
        self.scan_hosts_concurrent = AuditorScan.scan_hosts_concurrent.__get__(
            self.auditor, AuditorScan
        )

    @patch("redaudit.core.auditor_scan.ThreadPoolExecutor")
    def test_scan_hosts_concurrent_execution(self, mock_executor_cls):
        """Test concurrent scanning of multiple hosts."""
        mock_executor = mock_executor_cls.return_value.__enter__.return_value

        # Define host list
        hosts = ["192.168.1.1", "192.168.1.2"]

        # Mock futures
        f1, f2 = MagicMock(), MagicMock()
        f1.result.return_value = {"ip": "192.168.1.1", "ports": []}
        f2.result.return_value = {"ip": "192.168.1.2", "ports": []}

        # Configure submit to return futures
        mock_executor.submit.side_effect = [f1, f2]

        # Use as_completed to yield futures
        with patch("redaudit.core.auditor_scan.as_completed", return_value=[f1, f2]):
            results = self.scan_hosts_concurrent(hosts)

        self.assertEqual(len(results), 2)
        # self.auditor.scan_host_ports.assert_not_called() # Actually called by executor

        # Verify calls to submit
        self.assertEqual(mock_executor.submit.call_count, 2)

    def test_scan_hosts_concurrent_deduplication(self):
        """Test that duplicate hosts are removed."""
        hosts = ["192.168.1.1", "192.168.1.1", "192.168.1.2"]

        with patch("redaudit.core.auditor_scan.ThreadPoolExecutor") as mock_executor_cls:
            mock_executor = mock_executor_cls.return_value.__enter__.return_value
            with patch("redaudit.core.auditor_scan.as_completed", return_value=[]):
                self.scan_hosts_concurrent(hosts)

            # Should only submit 2 tasks
            self.assertEqual(mock_executor.submit.call_count, 2)


class TestScanNetworkDiscovery(unittest.TestCase):
    def setUp(self):
        self.auditor = MagicMock()  # Removed spec=AuditorScan
        self.auditor.config = {}
        self.auditor.ui = MagicMock()
        self.auditor.logger = MagicMock()
        self.auditor.scanner = MagicMock()

        # Helper methods
        self.auditor._set_ui_detail = MagicMock()
        self.auditor.ui.t.return_value = "Test Message"

        # Bind method
        self.scan_network_discovery = AuditorScan.scan_network_discovery.__get__(
            self.auditor, AuditorScan
        )

    def test_scan_network_discovery_success(self):
        """Test successful network discovery."""
        network = "192.168.1.0/24"

        # Mock scanner response
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1", "192.168.1.5"]

        # Configure host lookups
        host1 = MagicMock()
        host1.state.return_value = "up"
        # Mock __contains__ so 'in' operator works correctly
        host1.__contains__.side_effect = lambda k: k in ["addresses", "vendor", "hostnames"]
        host1.__getitem__.side_effect = lambda k: {
            "addresses": {"mac": "AA:BB:CC:DD:EE:FF"},
            "vendor": {"AA:BB:CC:DD:EE:FF": "TestVendor"},
            "hostnames": [{"name": "test-host"}],
        }.get(k, {})

        host5 = MagicMock()
        host5.state.return_value = "down"

        mock_nm.__getitem__.side_effect = lambda ip: host1 if ip == "192.168.1.1" else host5

        self.auditor.scanner.run_nmap_scan.return_value = (mock_nm, None)

        # Mock host object creation
        mock_host = MagicMock()
        self.auditor.scanner.get_or_create_host.return_value = mock_host

        hosts = self.scan_network_discovery(network)

        self.auditor.scanner.get_or_create_host.assert_called_with("192.168.1.1")
        self.assertEqual(hosts, ["192.168.1.1"])
        self.assertEqual(mock_host.mac_address, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(mock_host.vendor, "TestVendor")
        self.assertEqual(mock_host.hostname, "test-host")

    def test_scan_network_discovery_failure(self):
        """Test handling of scan failure."""
        self.auditor.scanner.run_nmap_scan.return_value = (None, "Scan Error")

        hosts = self.scan_network_discovery("192.168.1.0/24")

        self.assertEqual(hosts, [])
        self.auditor.logger.error.assert_called()


class TestHyperScanDiscovery(unittest.TestCase):
    def setUp(self):
        self.auditor = MagicMock(spec=AuditorScan)
        self.auditor.config = {"scan_mode": "full"}
        self.auditor.ui = MagicMock()
        self.auditor.ui.get_progress_console.return_value = None
        self.auditor.logger = MagicMock()
        self.auditor.results = {}
        self.auditor.interrupted = False
        self.auditor._hyperscan_discovery_ports = {}

        # Bind method
        self.run_hyperscan = AuditorScan._run_hyperscan_discovery.__get__(self.auditor, AuditorScan)

    # Fix: Patch where it is imported FROM, since it's imported inside the function
    @patch("redaudit.core.hyperscan.hyperscan_full_port_sweep")
    @patch("redaudit.core.auditor_scan.ThreadPoolExecutor")
    def test_hyperscan_discovery_execution(self, mock_executor_cls, mock_sweep):
        """Test parallel HyperScan execution."""
        mock_executor = mock_executor_cls.return_value.__enter__.return_value

        ips = ["10.0.0.1", "10.0.0.2"]

        def mock_submit(fn, *args, **kwargs):
            fn(*args, **kwargs)
            f = MagicMock()
            f.result.return_value = None
            return f

        mock_executor.submit.side_effect = mock_submit

        mock_sweep.return_value = [80, 443]

        with patch("redaudit.core.auditor_scan.as_completed", side_effect=lambda x: list(x)):
            results = self.run_hyperscan(ips)

        self.assertEqual(len(results), 2)
        self.assertEqual(results["10.0.0.1"], [80, 443])
        self.assertEqual(mock_sweep.call_count, 2)

    def test_hyperscan_skipped(self):
        """Test that HyperScan is skipped if not in full mode."""
        self.auditor.config["scan_mode"] = "quick"
        res = self.run_hyperscan(["10.0.0.1"])
        self.assertEqual(res, {})
