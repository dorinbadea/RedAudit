"""
Integration test for Wizard credential loading flow.
"""

import unittest
from unittest.mock import MagicMock, patch
from redaudit.core.wizard import Wizard
from redaudit.core.credentials import Credential


class TestWizardCredentialLoading(unittest.TestCase):
    def setUp(self):
        self.mock_ui = MagicMock()
        self.mock_ui.t.side_effect = lambda x, *args: x  # identity translation
        self.mock_ui.colors = {"OKGREEN": "", "ENDC": ""}
        self.wizard = Wizard()
        self.wizard.ui = self.mock_ui

    @patch("redaudit.core.credentials.KeyringCredentialProvider")
    def test_check_and_load_saved_credentials_success(self, mock_provider_cls):
        """Test the full flow: credentials exist -> offer -> user accepts -> load."""
        mock_provider = mock_provider_cls.return_value

        # 1. Setup mock credentials summary (v4.6.19: 3-tuple format)
        mock_provider.get_saved_credential_summary.return_value = [
            ("SSH", "auditor", 0),
            ("SMB", "admin", 0),
        ]

        # 2. Setup mock credentials retrieval
        def get_cred_side_effect(target, protocol):
            if protocol == "ssh":
                return Credential(username="auditor", password="sshpass")
            if protocol == "smb":
                return Credential(username="admin", password="smbpass", domain="CORP")
            return None

        mock_provider.get_credential.side_effect = get_cred_side_effect

        # 3. Simulate User interacting (Yes to load)
        self.wizard.ask_yes_no = MagicMock(return_value=True)

        # 4. Execute
        auth_config = {}
        result = self.wizard._check_and_load_saved_credentials(auth_config)

        # 5. Assertions
        self.assertTrue(result, "Should return True when credentials loaded")
        self.assertEqual(auth_config["auth_ssh_user"], "auditor")
        self.assertEqual(auth_config["auth_ssh_pass"], "sshpass")
        self.assertEqual(auth_config["auth_smb_user"], "admin")
        self.assertEqual(auth_config["auth_smb_pass"], "smbpass")
        self.assertEqual(auth_config["auth_smb_domain"], "CORP")

        # Verify UI interactions
        # Should have printed summary
        # Should have asked question
        self.wizard.ask_yes_no.assert_called_with("auth_load_saved_q", default="yes")

    @patch("redaudit.core.credentials.KeyringCredentialProvider")
    def test_check_and_load_saved_credentials_declined(self, mock_provider_cls):
        """Test flow: credentials exist -> offer -> user declines."""
        mock_provider = mock_provider_cls.return_value
        mock_provider.get_saved_credential_summary.return_value = [("SSH", "auditor", 0)]

        # User says NO
        self.wizard.ask_yes_no = MagicMock(return_value=False)

        auth_config = {}
        result = self.wizard._check_and_load_saved_credentials(auth_config)

        self.assertFalse(result)
        self.assertEqual(auth_config, {})  # Empty

    @patch("redaudit.core.credentials.KeyringCredentialProvider")
    def test_check_and_load_saved_credentials_none_found(self, mock_provider_cls):
        """Test flow: no credentials found -> silent return."""
        mock_provider = mock_provider_cls.return_value
        mock_provider.get_saved_credential_summary.return_value = []

        result = self.wizard._check_and_load_saved_credentials({})

        self.assertFalse(result)
        # Should NOT ask question
        self.wizard.ask_yes_no = MagicMock()
        self.wizard.ask_yes_no.assert_not_called()
