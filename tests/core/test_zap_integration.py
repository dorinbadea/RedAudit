#!/usr/bin/env python3
"""
Unit tests for OWASP ZAP integration (v4.2).
"""
import unittest
from unittest.mock import MagicMock, patch
import os

from redaudit.core.config_context import ConfigurationContext
from redaudit.core.auditor_vuln import AuditorVuln


class MockAuditor(AuditorVuln):
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.extra_tools = {}
        self.results = {}
        self.current_phase = ""
        self.ui = MagicMock()
        self.proxy_manager = None

    def _set_ui_detail(self, detail):
        pass


class TestZapIntegration(unittest.TestCase):
    def setUp(self):
        self.config = ConfigurationContext()
        self.logger = MagicMock()
        self.vuln_auditor = MockAuditor(self.config, self.logger)

    def test_zap_disabled_by_default(self):
        """Verify ZAP is not run if disabled in config."""
        self.config["zap_enabled"] = False
        self.vuln_auditor.extra_tools = {"zap.sh": "/usr/bin/zap.sh"}

        # We need to access run_zap inside scan_vulnerabilities_web
        # Effectively we test by ensuring NO zap command is called

        with patch("redaudit.core.auditor_vuln.CommandRunner") as mock_runner_cls:
            self.config["scan_vulnerabilities"] = True
            self.config["scan_mode"] = "completo"

            host_info = {
                "ip": "127.0.0.1",
                "ports": [{"port": 80, "service": "http", "scripts": [], "is_web_service": True}],
            }

            self.vuln_auditor.scan_vulnerabilities_web(host_info)

            # Check calls
            for call in mock_runner_cls.return_value.run.call_args_list:
                args, _ = call
                cmd = args[0]
                if cmd[0].endswith("zap.sh"):
                    self.fail("zap.sh should not be called when disabled")

    @patch("redaudit.core.auditor_vuln.CommandRunner")
    @patch("shutil.which")
    @patch("os.path.exists")
    def test_run_zap_success(self, mock_exists, mock_which, mock_runner_cls):
        """Verify ZAP command construction and execution."""

        def which_side_effect(arg):
            if arg == "zap.sh":
                return "/usr/bin/zap.sh"
            if arg == "sqlmap":
                return "/usr/bin/sqlmap"
            return None

        mock_which.side_effect = which_side_effect
        mock_exists.return_value = True  # Report exists

        mock_runner = mock_runner_cls.return_value
        mock_res = MagicMock()
        mock_res.timed_out = False
        mock_res.returncode = 0
        mock_runner.run.return_value = mock_res

        # Enable ZAP
        self.config["zap_enabled"] = True
        self.config["scan_vulnerabilities"] = True
        self.config["scan_mode"] = "completo"
        self.vuln_auditor.extra_tools = {"zap.sh": "/usr/bin/zap.sh"}

        host_info = {
            "ip": "127.0.0.1",
            "ports": [{"port": 80, "service": "http", "scripts": [], "is_web_service": True}],
        }

        # We assume parallel execution will eventually call run_zap
        # Since we can't easily await threads in this test structure without refactoring,
        # we rely on the fact that scan_vulnerabilities_web waits for futures in `as_completed`.

        result = self.vuln_auditor.scan_vulnerabilities_web(host_info)

        # Verify ZAP call
        found_zap = False
        for call in mock_runner.run.call_args_list:
            args, _ = call
            cmd = args[0]
            if cmd[0] == "/usr/bin/zap.sh":
                found_zap = True
                self.assertIn("-cmd", cmd)
                self.assertIn("-quickurl", cmd)
                self.assertIn("http://127.0.0.1:80/", cmd)
                self.assertIn("-quickout", cmd)

        self.assertTrue(found_zap, "zap.sh should have been called")

        # Verify result contains zap report
        # Note: result structure is {"host": ..., "vulnerabilities": list}
        # In scan_vulnerabilities_web, findings are updated.
        # Check if any finding has "zap_report"

        has_zap_report = False
        if result and "vulnerabilities" in result:
            for vuln in result["vulnerabilities"]:
                if "zap_report" in vuln:
                    has_zap_report = True
                    break

        self.assertTrue(has_zap_report, "Result should contain zap_report")


if __name__ == "__main__":
    unittest.main()
