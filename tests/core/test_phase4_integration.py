#!/usr/bin/env python3
"""
Tests for Phase 4: Authenticated Scanning - Integration
"""

import unittest
from unittest.mock import MagicMock, patch
import sys
import os

from redaudit.cli import parse_arguments, configure_from_args
from redaudit.core.auditor import InteractiveNetworkAuditor
from redaudit.core.credentials import CredentialProvider


class TestPhase4Integration(unittest.TestCase):

    def setUp(self):
        # Mock sys.argv to avoid messing with actual args
        self.original_argv = sys.argv
        sys.argv = ["redaudit"]

        # Mock UI for Auditor
        self.mock_ui = MagicMock()
        self.mock_ui.t.side_effect = lambda x, *args, **kwargs: x  # Dummy translation
        self.mock_ui.colors = {"CYAN": "", "ENDC": "", "OKBLUE": "", "HEADER": ""}

    def tearDown(self):
        sys.argv = self.original_argv

    def test_cli_auth_arguments(self):
        """Test parsing of new authentication arguments."""
        test_args = [
            "redaudit",
            "--target",
            "192.168.1.1",
            "--auth-provider",
            "env",
            "--ssh-user",
            "testuser",
            "--ssh-key",
            "/tmp/testkey",
            "--ssh-key-pass",
            "secretpass",
            "--ssh-trust-keys",
        ]
        with patch.object(sys, "argv", test_args):
            args = parse_arguments()
            self.assertEqual(args.auth_provider, "env")
            self.assertEqual(args.ssh_user, "testuser")
            self.assertEqual(args.ssh_key, "/tmp/testkey")
            self.assertEqual(args.ssh_key_pass, "secretpass")
            self.assertTrue(args.ssh_trust_keys)

            # Check config transfer
            config = {}

            # We need a dummy App object
            class DummyApp:
                def __init__(self):
                    self.config = {}

                def check_dependencies(self):
                    return True

                def show_legal_warning(self):
                    return True

            app = DummyApp()
            configure_from_args(app, args)

            self.assertEqual(app.config["auth_provider"], "env")
            self.assertEqual(app.config["auth_ssh_user"], "testuser")
            self.assertEqual(app.config["auth_ssh_key"], "/tmp/testkey")
            self.assertEqual(app.config["auth_ssh_key_pass"], "secretpass")
            self.assertTrue(app.config["auth_ssh_trust_keys"])

    def test_wizard_auth_step_custom_enabled(self):
        """Test that Authentication step in Custom profile configures Auth correctly."""
        auditor = InteractiveNetworkAuditor()

    def test_wizard_auth_step_custom_enabled(self):
        """Test that Authentication step in Custom profile configures Auth correctly."""
        auditor = InteractiveNetworkAuditor()
        auditor.ui = self.mock_ui
        auditor.ask_number = MagicMock(return_value=100)
        auditor.ask_net_discovery_options = MagicMock(return_value={})
        auditor.setup_encryption = MagicMock()
        auditor.ask_webhook_url = MagicMock(return_value=None)

        # Robust ask_yes_no mock that responds to prompts
        def yes_no_logic(question, default="yes"):
            print(f"DEBUG: ask_yes_no called with: {question}")
            q = str(question).lower()
            if "ssh" in q:
                return True
            if "smb" in q:
                return False
            if "snmp" in q:
                return False
            # Default for mystery calls (e.g. legal warning or auth scan enable)
            # If prompt says "scan input" (Auth Scan Q), we want YES (True) if ask_yes_no is used there.
            # But wait, Auth Scan Q is handled by ask_choice_with_back in this version.
            # So just return True to be safe for unknown prompts, unless it looks negative.
            return True

        # Class-level patches to ensure they apply
        with (
            patch("redaudit.core.wizard.Wizard.ask_choice_with_back") as mock_ask_back,
            patch("redaudit.core.wizard.Wizard.ask_choice") as mock_ask_choice,
            patch(
                "redaudit.core.wizard.Wizard.ask_yes_no", side_effect=yes_no_logic
            ) as mock_yes_no,
            patch("builtins.input") as mock_input,
        ):

            # 1. Profile -> 3 (Custom/Completo)
            # 2. UDP -> 1 (Balanced)
            # 3. Auth Method (Key) -> 0
            # Pad with 0s just in case
            mock_ask_choice.side_effect = [3, 1, 0] + [0] * 5

            # ask_choice_with_back mock steps:
            mock_ask_back.side_effect = [
                2,  # Mode: Full
                0,  # HyperScan: Auto
                1,  # Vuln: No
                1,  # CVE: No
                1,  # UDP: Full
                1,  # Topo: Enabled
                1,  # NetDisc: No
                0,  # Auth: Yes (Enable)
                1,  # Auth Mode: Advanced
                1,  # Windows: No
            ] + [
                1
            ] * 5  # Padding

            # Inputs: SSH User, SSH Key, Name, OutputDir
            # We need to match the calls.
            # If yes_no enables SSH, it asks User, Key path (if method 0), Passphrase (getpass)
            # Method selection is ask_choice.
            # We mocked ask_choice to return 0 (Key).
            # So inputs:
            # 1. Auditor Name
            # 2. Output Dir
            # 3. SSH User
            # 4. SSH Key Path
            mock_input.side_effect = ["root", "/tmp/key", "Tester", "/tmp"]

            # Run with patched shutil and getpass
            with (
                patch("shutil.which", return_value=None),
                patch("getpass.getpass", return_value="secret"),
                patch("os.path.isdir", return_value=True),
                patch("os.access", return_value=True),
            ):
                auditor._configure_scan_interactive({})

            # Asserts
            self.assertEqual(auditor.config["scan_mode"], "completo")
            self.assertEqual(auditor.config["auth_ssh_user"], "root")
            key = auditor.config.get("auth_ssh_key")
            self.assertTrue(key.endswith("key"))
            self.assertIsNone(auditor.config.get("auth_ssh_pass"))

    def test_wizard_auth_disabled(self):
        """Test disabling Auth step."""
        from redaudit.core.wizard import Wizard

        w = Wizard()
        w.ui = self.mock_ui
        w.ask_yes_no = MagicMock(return_value=False)

        # Verify helper method exists and returns correct structure
        cfg = w.ask_auth_config()
        self.assertFalse(cfg["auth_enabled"])


if __name__ == "__main__":
    unittest.main()
