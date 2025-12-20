#!/usr/bin/env python3
"""
RedAudit - Interactive wizard Red Team prompts tests

Ensures the wizard wires Net Discovery / Red Team options into the runtime config.
"""

import os
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.auditor import InteractiveNetworkAuditor


class TestWizardRedTeam(unittest.TestCase):
    def test_wizard_redteam_options_are_applied(self):
        app = InteractiveNetworkAuditor()
        app.print_status = lambda *_args, **_kwargs: None
        app.setup_encryption = lambda *args, **kwargs: None

        # v3.8.1: Now uses ask_choice_with_back for all wizard steps (8 steps)
        # Step 1: scan mode (1=normal), Step 2: max hosts (skipped, uses ask_number)
        # Step 3: vuln scan (0=Yes), Step 4: CVE lookup (1=No)
        # Step 5: threads (skipped), Step 6: rate limit (skipped)
        # Step 7: output (skipped), Step 8: reports (0=both)
        app.ask_choice_with_back = Mock(side_effect=[1, 0, 1, 0])  # normal, vuln=yes, cve=no, reports
        app.ask_choice = Mock(side_effect=[0, 1])  # udp quick, topo off, Red Team (B)
        app.ask_number = Mock(side_effect=["all", 6, 50])  # max_hosts, threads, max_targets
        app.ask_yes_no = Mock(
            side_effect=[
                False,  # rate limiting
                True,  # net discovery
                True,  # active L2
                True,  # kerbrute userenum
                False,  # v3.7: net discovery advanced options
                False,  # v3.8: agentless verification
                False,  # v3.7: webhook prompt
            ]
        )

        with (
            patch("builtins.input", side_effect=["", "", "/tmp/users.txt", "", ""]),
            patch("redaudit.core.auditor.os.geteuid", return_value=0),
        ):
            app._configure_scan_interactive(defaults_for_run={})

        self.assertTrue(app.config.get("net_discovery_enabled"))
        self.assertTrue(app.config.get("net_discovery_redteam"))
        self.assertTrue(app.config.get("net_discovery_active_l2"))
        self.assertIsNone(app.config.get("net_discovery_kerberos_realm"))
        self.assertEqual(app.config.get("net_discovery_kerberos_userlist"), "/tmp/users.txt")

    def test_wizard_redteam_is_disabled_without_root(self):
        app = InteractiveNetworkAuditor()
        app.print_status = lambda *_args, **_kwargs: None
        app.setup_encryption = lambda *args, **kwargs: None

        # v3.8.1: Now uses ask_choice_with_back for wizard steps
        app.ask_choice_with_back = Mock(side_effect=[1, 0, 1, 0])  # normal, vuln=yes, cve=no, reports
        app.ask_choice = Mock(side_effect=[0, 0])  # udp quick, topo off
        app.ask_number = Mock(side_effect=["all", 6])  # max_hosts, threads
        app.ask_yes_no = Mock(
            side_effect=[
                False,  # rate limiting
                True,  # net discovery
                False,  # v3.8: agentless verification
                False,  # v3.7: webhook prompt
            ]
        )

        with (
            patch("builtins.input", side_effect=["", "", ""]),
            patch("redaudit.core.auditor.os.geteuid", return_value=1000),
        ):
            app._configure_scan_interactive(defaults_for_run={})

        self.assertTrue(app.config.get("net_discovery_enabled"))
        self.assertFalse(app.config.get("net_discovery_redteam"))
        self.assertFalse(app.config.get("net_discovery_active_l2"))
        self.assertIsNone(app.config.get("net_discovery_kerberos_userlist"))


if __name__ == "__main__":
    unittest.main()

