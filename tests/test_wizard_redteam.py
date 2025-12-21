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

        # v3.8.1: ask_choice_with_back handles steps 1,3,4,6,7,8
        # 1=scan mode(normal), 3=vuln(yes), 4=CVE(no), 6=UDP(quick), 6=topo(off),
        # 7=net discovery(yes), 8=windows verify(no)
        app.ask_choice_with_back = Mock(side_effect=[1, 0, 1, 0, 0, 0, 1])
        app.ask_choice = Mock(side_effect=[1])  # Red Team (B)
        app.ask_number = Mock(side_effect=["all", 6])  # max_hosts, threads
        app.ask_yes_no = Mock(
            side_effect=[
                False,  # rate limiting
                True,  # active L2
                True,  # kerbrute userenum
                False,  # v3.7: net discovery advanced options
                False,  # v3.7: webhook prompt
            ]
        )

        with (
            patch("builtins.input", side_effect=["", "", "", "/tmp/users.txt"]),
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

        # v3.8.1: ask_choice_with_back handles steps 1,3,4,6,7,8
        app.ask_choice_with_back = Mock(side_effect=[1, 0, 1, 0, 0, 0, 1])
        app.ask_choice = Mock(side_effect=[1])  # Red Team (B), blocked without root
        app.ask_number = Mock(side_effect=["all", 6])  # max_hosts, threads
        app.ask_yes_no = Mock(
            side_effect=[
                False,  # rate limiting
                False,  # v3.7: webhook prompt
            ]
        )

        with (
            patch("builtins.input", side_effect=["", ""]),
            patch("redaudit.core.auditor.os.geteuid", return_value=1000),
        ):
            app._configure_scan_interactive(defaults_for_run={})

        self.assertTrue(app.config.get("net_discovery_enabled"))
        self.assertFalse(app.config.get("net_discovery_redteam"))
        self.assertFalse(app.config.get("net_discovery_active_l2"))
        self.assertIsNone(app.config.get("net_discovery_kerberos_userlist"))


if __name__ == "__main__":
    unittest.main()
