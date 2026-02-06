#!/usr/bin/env python3
"""
Unit tests for Lynis Scanner (auth_lynis.py)
"""

import unittest
from unittest.mock import MagicMock, patch, ANY
import sys

from redaudit.core.auth_lynis import LynisScanner, LynisResult
from redaudit.core.auth_ssh import SSHScanner


class TestLynisScanner(unittest.TestCase):

    def setUp(self):
        self.ssh = MagicMock(spec=SSHScanner)
        self.scanner = LynisScanner(self.ssh)

    def test_run_audit_existing(self):
        """Test running Lynis when already installed."""
        # 1. check_lynis_available -> 0 (found)
        # 2. run_command audit -> output

        self.ssh.run_command.side_effect = [
            ("", "", 0),  # which lynis
            ("Hardening index: 80\nTests performed: 200\n! [AUTH-123] Warning", "", 0),  # run
        ]

        res = self.scanner.run_audit()

        self.assertIsNotNone(res)
        self.assertEqual(res.hardening_index, 80)
        self.assertEqual(res.tests_performed, 200)
        self.assertEqual(len(res.warnings), 1)

    def test_run_audit_portable_success(self):
        """Test portable install and run."""
        # 1. check -> 1 (not found)
        # 2. which git -> 0
        # 3. clone -> 0
        # 4. run /tmp/lynis -> output

        self.ssh.run_command.side_effect = [
            ("", "", 1),  # which lynis
            ("", "", 0),  # which git
            ("", "", 0),  # clone
            ("Hardening index: 65", "", 0),  # run
        ]

        res = self.scanner.run_audit(use_portable=True)
        self.assertEqual(res.hardening_index, 65)
        # Check install called
        # We can't easily assert on exact calls due to dynamic args in side_effect, relies on count/logic

    def test_run_audit_portable_fail_git(self):
        """Test portable install fail due to missing git."""
        # 1. check -> 1
        # 2. which git -> 1

        self.ssh.run_command.side_effect = [
            ("", "", 1),  # which lynis
            ("", "", 1),  # which git
        ]

        res = self.scanner.run_audit(use_portable=True)
        self.assertIsNone(res)

    def test_run_audit_missing_lynis_no_portable(self):
        """Return None when Lynis is missing and portable mode is off."""
        self.ssh.run_command.side_effect = [
            ("", "", 1),  # which lynis
        ]
        with patch("redaudit.core.auth_lynis.logger") as log:
            res = self.scanner.run_audit(use_portable=False)
        self.assertIsNone(res)
        log.info.assert_called_once_with("Lynis not found on target.")

    def test_run_audit_portable_clone_failure(self):
        """Return None when portable clone fails."""
        self.ssh.run_command.side_effect = [
            ("", "", 1),  # which lynis
            ("", "", 0),  # which git
            ("", "boom", 1),  # clone
        ]
        with patch("redaudit.core.auth_lynis.logger") as log:
            res = self.scanner.run_audit(use_portable=True)
        self.assertIsNone(res)
        log.warning.assert_called_once_with("Failed to clone Lynis: boom")

    def test_parse_lynis_output_suggestions(self):
        """Parse suggestion lines into suggestions list."""
        output = "* [SUG-1] Enable firewall\nTests performed: 10"
        res = self.scanner._parse_lynis_output(output)
        self.assertIn("* [SUG-1] Enable firewall", res.suggestions)


if __name__ == "__main__":
    unittest.main()
