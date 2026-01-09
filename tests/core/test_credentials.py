"""
Unit tests for redaudit.core.credentials module.
"""

import os
import unittest
from unittest.mock import patch, MagicMock

from redaudit.core.credentials import (
    Credential,
    CredentialProvider,
    EnvironmentCredentialProvider,
    KeyringCredentialProvider,
    get_credential_provider,
)


class TestCredentialDataclass(unittest.TestCase):
    """Tests for the Credential dataclass."""

    def test_credential_basic_creation(self):
        """Test creating a credential with username only."""
        cred = Credential(username="admin")
        self.assertEqual(cred.username, "admin")
        self.assertIsNone(cred.password)
        self.assertIsNone(cred.private_key)
        self.assertIsNone(cred.domain)

    def test_credential_full_creation(self):
        """Test creating a credential with all fields."""
        cred = Credential(
            username="auditor",
            password="secret123",
            private_key="/home/user/.ssh/id_rsa",
            private_key_passphrase="keypass",
            domain="CORP",
        )
        self.assertEqual(cred.username, "auditor")
        self.assertEqual(cred.password, "secret123")
        self.assertEqual(cred.private_key, "/home/user/.ssh/id_rsa")
        self.assertEqual(cred.private_key_passphrase, "keypass")
        self.assertEqual(cred.domain, "CORP")

    def test_credential_repr_redacts_password(self):
        """Test that repr redacts sensitive password field."""
        cred = Credential(username="admin", password="supersecret")
        repr_str = repr(cred)
        self.assertIn("username='admin'", repr_str)
        self.assertIn("password=***", repr_str)
        self.assertNotIn("supersecret", repr_str)

    def test_credential_repr_shows_none_password(self):
        """Test that repr shows None for missing password."""
        cred = Credential(username="admin")
        repr_str = repr(cred)
        self.assertIn("password=None", repr_str)


class TestEnvironmentCredentialProvider(unittest.TestCase):
    """Tests for the EnvironmentCredentialProvider."""

    def setUp(self):
        self.provider = EnvironmentCredentialProvider()

    @patch.dict(os.environ, {"REDAUDIT_SSH_USER": "testuser"}, clear=False)
    def test_get_credential_username_only(self):
        """Test getting credential with only username set."""
        cred = self.provider.get_credential("192.168.1.1", "ssh")
        self.assertIsNotNone(cred)
        self.assertEqual(cred.username, "testuser")
        self.assertIsNone(cred.password)

    @patch.dict(
        os.environ,
        {
            "REDAUDIT_SSH_USER": "auditor",
            "REDAUDIT_SSH_PASS": "password123",
            "REDAUDIT_SSH_KEY": "/path/to/key",
        },
        clear=False,
    )
    def test_get_credential_full_ssh(self):
        """Test getting full SSH credential from environment."""
        cred = self.provider.get_credential("10.0.0.1", "ssh")
        self.assertIsNotNone(cred)
        self.assertEqual(cred.username, "auditor")
        self.assertEqual(cred.password, "password123")
        self.assertEqual(cred.private_key, "/path/to/key")

    @patch.dict(
        os.environ,
        {
            "REDAUDIT_SMB_USER": "admin",
            "REDAUDIT_SMB_PASS": "smbpass",
            "REDAUDIT_SMB_DOMAIN": "CORP",
        },
        clear=False,
    )
    def test_get_credential_smb_with_domain(self):
        """Test getting SMB credential with domain."""
        cred = self.provider.get_credential("192.168.1.100", "smb")
        self.assertIsNotNone(cred)
        self.assertEqual(cred.username, "admin")
        self.assertEqual(cred.domain, "CORP")

    def test_get_credential_missing_user(self):
        """Test that None is returned when no username is set."""
        with patch.dict(os.environ, {}, clear=True):
            # Ensure no REDAUDIT vars are set
            for key in list(os.environ.keys()):
                if key.startswith("REDAUDIT_"):
                    del os.environ[key]
            cred = self.provider.get_credential("192.168.1.1", "ssh")
            self.assertIsNone(cred)

    def test_store_credential_returns_false(self):
        """Test that store_credential always returns False (not supported)."""
        cred = Credential(username="test")
        result = self.provider.store_credential("192.168.1.1", "ssh", cred)
        self.assertFalse(result)


class TestKeyringCredentialProvider(unittest.TestCase):
    """Tests for the KeyringCredentialProvider."""

    def test_keyring_unavailable_falls_back_to_env(self):
        """Test fallback to environment when keyring is not installed."""
        with patch.dict("sys.modules", {"keyring": None}):
            # Force reimport to trigger ImportError
            with patch("builtins.__import__", side_effect=ImportError("No module")):
                provider = KeyringCredentialProvider()
                self.assertFalse(provider._keyring_available)

    @patch("redaudit.core.credentials.KeyringCredentialProvider.__init__")
    def test_keyring_get_credential_from_keyring(self, mock_init):
        """Test getting credential from keyring."""
        mock_init.return_value = None
        provider = KeyringCredentialProvider.__new__(KeyringCredentialProvider)
        provider._keyring_available = True
        provider._keyring = MagicMock()

        # Mock keyring responses
        provider._keyring.get_password.side_effect = lambda svc, key: {
            ("redaudit-ssh", "192.168.1.1:username"): "sshuser",
            ("redaudit-ssh", "192.168.1.1:password"): "sshpass",
        }.get((svc, key))

        cred = provider.get_credential("192.168.1.1", "ssh")
        self.assertIsNotNone(cred)
        self.assertEqual(cred.username, "sshuser")
        self.assertEqual(cred.password, "sshpass")

    @patch("redaudit.core.credentials.KeyringCredentialProvider.__init__")
    def test_keyring_get_credential_fallback_to_default(self, mock_init):
        """Test fallback to default credential when target-specific not found."""
        mock_init.return_value = None
        provider = KeyringCredentialProvider.__new__(KeyringCredentialProvider)
        provider._keyring_available = True
        provider._keyring = MagicMock()

        # Only default credentials exist
        provider._keyring.get_password.side_effect = lambda svc, key: {
            ("redaudit-ssh", "default:username"): "defaultuser",
            ("redaudit-ssh", "default:password"): "defaultpass",
        }.get((svc, key))

        cred = provider.get_credential("192.168.1.1", "ssh")
        self.assertIsNotNone(cred)
        self.assertEqual(cred.username, "defaultuser")

    @patch("redaudit.core.credentials.KeyringCredentialProvider.__init__")
    def test_keyring_store_credential(self, mock_init):
        """Test storing credential in keyring."""
        mock_init.return_value = None
        provider = KeyringCredentialProvider.__new__(KeyringCredentialProvider)
        provider._keyring_available = True
        provider._keyring = MagicMock()

        cred = Credential(username="newuser", password="newpass", domain="DOMAIN")
        result = provider.store_credential("192.168.1.1", "smb", cred)

        self.assertTrue(result)
        # Verify set_password was called
        self.assertTrue(provider._keyring.set_password.called)


class TestGetCredentialProvider(unittest.TestCase):
    """Tests for the get_credential_provider factory function."""

    def test_get_env_provider(self):
        """Test getting environment provider."""
        provider = get_credential_provider("env")
        self.assertIsInstance(provider, EnvironmentCredentialProvider)

    def test_get_environment_provider_alias(self):
        """Test getting environment provider with full name."""
        provider = get_credential_provider("environment")
        self.assertIsInstance(provider, EnvironmentCredentialProvider)

    def test_get_keyring_provider(self):
        """Test getting keyring provider."""
        provider = get_credential_provider("keyring")
        self.assertIsInstance(provider, KeyringCredentialProvider)

    def test_invalid_provider_raises_error(self):
        """Test that invalid provider type raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            get_credential_provider("invalid")
        self.assertIn("Unknown credential provider", str(ctx.exception))

    def test_case_insensitive_provider_type(self):
        """Test that provider type is case insensitive."""
        provider = get_credential_provider("ENV")
        self.assertIsInstance(provider, EnvironmentCredentialProvider)


if __name__ == "__main__":
    unittest.main()
