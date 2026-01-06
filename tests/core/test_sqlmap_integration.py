#!/usr/bin/env python3
"""
Unit tests for SQLMap integration (v4.2).
"""
import unittest
from unittest.mock import MagicMock, patch

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


class TestSQLMapIntegration(unittest.TestCase):
    def setUp(self):
        self.config = ConfigurationContext()
        self.logger = MagicMock()
        self.vuln_auditor = MockAuditor(self.config, self.logger)
        # Mock extra tools to have sqlmap
        self.vuln_auditor.extra_tools = {"sqlmap": "/usr/bin/sqlmap"}

    def test_config_defaults(self):
        """Verify default configuration values."""
        self.assertEqual(self.config.sqlmap_level, 1)
        self.assertEqual(self.config.sqlmap_risk, 1)

    @patch("redaudit.core.auditor_vuln.CommandRunner")
    @patch("shutil.which")
    def test_run_sqlmap_default_config(self, mock_which, mock_runner_cls):
        """Verify sqlmap command with default config (level 1, risk 1)."""
        mock_which.return_value = "/usr/bin/sqlmap"
        mock_runner = mock_runner_cls.return_value
        # Mock result
        mock_res = MagicMock()
        mock_res.timed_out = False
        mock_res.stdout = "no findings"
        mock_runner.run.return_value = mock_res

        # Set config
        self.config["scan_vulnerabilities"] = True
        self.config["scan_mode"] = "completo"

        # Call scan_vulnerabilities_web with a web target structure
        host_info = {
            "ip": "127.0.0.1",
            "ports": [{"port": 80, "service": "http", "scripts": [], "is_web_service": True}],
        }

        self.vuln_auditor.scan_vulnerabilities_web(host_info)

        # Check calls
        found_sqlmap = False
        for call in mock_runner.run.call_args_list:
            args, _ = call
            cmd = args[0]
            if cmd[0] == "/usr/bin/sqlmap":
                found_sqlmap = True
                self.assertIn("--level=1", cmd)
                self.assertIn("--risk=1", cmd)

        self.assertTrue(found_sqlmap, "sqlmap should have been called")

    @patch("redaudit.core.auditor_vuln.CommandRunner")
    @patch("shutil.which")
    def test_run_sqlmap_high_intensity(self, mock_which, mock_runner_cls):
        """Verify sqlmap command with high intensity config."""
        mock_which.return_value = "/usr/bin/sqlmap"
        mock_runner = mock_runner_cls.return_value
        mock_res = MagicMock()
        mock_res.timed_out = False
        mock_res.stdout = "findings"
        mock_runner.run.return_value = mock_res

        # Set high intensity config
        self.config["sqlmap_level"] = 5
        self.config["sqlmap_risk"] = 3
        self.config["scan_mode"] = "completo"

        host_info = {
            "ip": "127.0.0.1",
            "ports": [{"port": 80, "service": "http", "scripts": [], "is_web_service": True}],
        }
        self.vuln_auditor.scan_vulnerabilities_web(host_info)

        found_sqlmap = False
        for call in mock_runner.run.call_args_list:
            args, _ = call
            cmd = args[0]
            if cmd[0] == "/usr/bin/sqlmap":
                found_sqlmap = True
                self.assertIn("--level=5", cmd)
                self.assertIn("--risk=3", cmd)

        self.assertTrue(found_sqlmap, "sqlmap should have been called")


if __name__ == "__main__":
    unittest.main()
