import unittest
from unittest.mock import patch, MagicMock
from conftest import MockAuditorBase
from redaudit.core.auditor_vuln import AuditorVuln


class MockAuditorVuln(MockAuditorBase, AuditorVuln):
    """Mock auditor with AuditorVuln for testing vuln methods."""

    def __init__(self, config=None):
        super().__init__()
        self.config = config or {"scan_mode": "normal", "threads": 10}
        self.extra_tools = {}
        self.results = {"vulnerabilities": []}
        self.logger = MagicMock()


class TestAuditorVulnCoverage(unittest.TestCase):
    def setUp(self):
        self.auditor = MockAuditorVuln()

    def test_merge_nuclei_findings_missing_host(self):
        """Lines 169-172: _merge_nuclei_findings continue when host is missing."""
        findings = [
            {"matched_at": "", "host": ""},  # Invalid finding
            {"template_id": "test", "matched_at": "http://1.2.3.4:80", "severity": "info"},
        ]
        merged = self.auditor._merge_nuclei_findings(findings)
        self.assertEqual(merged, 1)
        self.assertEqual(len(self.auditor.results["vulnerabilities"]), 1)

    def test_estimate_vuln_budget_exception(self):
        """Lines 223-224: budget calculation exception path (int conversion fail)."""
        host_info = {"ports": [{"port": "invalid_port", "service": "http", "is_web_service": True}]}
        # Should catch exception and set port to 0, continuing calculation
        budget = self.auditor._estimate_vuln_budget_s(host_info)
        self.assertGreater(budget, 0)

    @patch("redaudit.core.auditor_vuln.http_enrichment")
    def test_scan_vulnerabilities_web_update_agentless_http(self, mock_enrich):
        """Lines 263-281: _update_agentless_http logic including upnp override."""
        mock_enrich.return_value = {"curl_headers": "Server: TestServer\r\n"}
        host_info = {
            "ip": "1.2.3.4",
            "ports": [{"port": 80, "service": "http", "is_web_service": True}],
            "agentless_fingerprint": {"http_source": "upnp", "http_title": "OldTitle"},
        }

        # Test override of upnp source
        self.auditor.scan_vulnerabilities_web(host_info)
        fp = host_info["agentless_fingerprint"]
        self.assertEqual(fp["http_server"], "TestServer")
        self.assertEqual(fp["http_source"], "enrichment")
        self.assertEqual(fp["upnp_device_name"], "OldTitle")

    @patch("redaudit.core.auditor_vuln.as_completed")
    @patch("redaudit.core.auditor_vuln.ThreadPoolExecutor")
    def test_run_vuln_tools_parallel_exception(self, mock_executor, mock_as_completed):
        """Lines 646-648: Parallel tools exception path."""
        mock_exec_inst = mock_executor.return_value.__enter__.return_value
        mock_future = MagicMock()
        mock_future.result.side_effect = Exception("Parallel tool crash")
        mock_exec_inst.submit.return_value = mock_future

        # Mock as_completed to return the mock future immediately
        mock_as_completed.return_value = [mock_future]

        # Should log debug and continue
        res = self.auditor._run_vuln_tools_parallel("1.2.3.4", 80, "http://1.2.3.4", "http", {})
        self.assertEqual(res, {})

    @patch("redaudit.core.auditor_vuln.wait")
    @patch("redaudit.core.auditor_vuln.ThreadPoolExecutor")
    def test_concurrent_scan_exception_handling(self, mock_executor, mock_wait):
        """Lines 913-923: Exception handling in concurrent scan worker."""
        # 1. Enable rich
        self.auditor.ui.get_progress_console = MagicMock(return_value=True)
        self.auditor.ui.get_standard_progress = MagicMock()

        # 2. Setup mock executor and futures
        mock_exec_inst = mock_executor.return_value.__enter__.return_value
        mock_future = MagicMock()
        mock_exec_inst.submit.return_value = mock_future

        # 3. Setup wait to return our future as completed
        # wait returns (done, not_done)
        mock_wait.return_value = ({mock_future}, set())

        # 4. Make future.result() raise Exception
        mock_future.result.side_effect = Exception("Worker Crash")

        # 5. Run
        hosts = [{"ip": "1.2.3.4", "web_ports_count": 1}]
        self.auditor.scan_vulnerabilities_concurrent(hosts)

        # 6. Verify logging and progress update
        # self.auditor.logger.error.assert_called_with("Vuln worker error for %s: %s", ...)
        # Check if error logic was hit by checking logger calls
        found_error = False
        for call in self.auditor.logger.error.call_args_list:
            if "Vuln worker error" in str(call):
                found_error = True
                break
        for call in self.auditor.logger.error.call_args_list:
            if "Vuln worker error" in str(call):
                found_error = True
                break
        self.assertTrue(found_error, "Should have logged worker error")

    @patch("redaudit.core.auditor_vuln.wait")
    @patch("redaudit.core.auditor_vuln.ThreadPoolExecutor")
    def test_concurrent_scan_interruption(self, mock_executor, mock_wait):
        """Lines 849-851: Interruption handling in concurrent loop."""
        # 1. Setup futures
        mock_exec_inst = mock_executor.return_value.__enter__.return_value
        mock_future = MagicMock()
        mock_exec_inst.submit.return_value = mock_future

        # 2. Setup wait to return empty (timeouts/pending) so loop continues
        # wait returns (done, not_done)
        # First call: returns not done, but we set interrupted=True
        mock_wait.return_value = (set(), {mock_future})

        # 3. Use side_effect on wait to set interrupted flag?
        # No, wait is called inside the loop.
        # We can set interrupted=True effectively before loop or via side-effect.
        # If we set it before, loop condition `while pending` runs, then checks `if self.interrupted`.
        self.auditor.interrupted = True

        # 4. Run
        # We need pending set to be non-empty initially.
        hosts = [{"ip": "1.2.3.4", "web_ports_count": 1}]
        self.auditor.scan_vulnerabilities_concurrent(hosts)

        # 5. proper cancellation check
        mock_future.cancel.assert_called()


if __name__ == "__main__":
    unittest.main()
