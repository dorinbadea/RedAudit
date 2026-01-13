#!/usr/bin/env python3
"""
Tests for wizard authentication flow navigation.
"""

from unittest.mock import MagicMock, patch
from redaudit.core.wizard import Wizard


class MockWizard(Wizard):
    def __init__(self):
        self.ui = MagicMock()
        self.ui.t.side_effect = lambda x: x
        self.ui.colors = {"OKBLUE": "", "ENDC": "", "CYAN": "", "BOLD": "", "GREEN": ""}

    def ask_choice_with_back(self, *args, **kwargs):
        pass  # mock this

    def ask_yes_no(self, *args, **kwargs):
        return True


class TestWizardAuthNavigation:

    def test_auth_config_go_back_disables_auth(self):
        """Test that going back from auth mode selection disables auth."""
        wizard = MockWizard()

        # User says YES to "enable auth", but then selects BACK (-1) at mode selection
        with patch.object(wizard, "_check_and_load_saved_credentials", return_value=False):
            with patch.object(wizard, "ask_yes_no", return_value=True):
                with patch.object(wizard, "ask_choice_with_back", return_value=-1):  # WIZARD_BACK

                    config = wizard.ask_auth_config()

                    # Should correspond to "cancellation" -> auth_enabled = False
                    assert config["auth_enabled"] is False
                    assert config["auth_credentials"] == []

    def test_auth_config_universal_mode(self):
        """Test selecting Universal mode proceeds to collection."""
        wizard = MockWizard()

        # Mock _collect_universal_credentials to return dummy list
        with patch.object(wizard, "_check_and_load_saved_credentials", return_value=False):
            with patch.object(wizard, "ask_yes_no", return_value=True):
                with patch.object(wizard, "ask_choice_with_back", return_value=0):  # Universal
                    with patch.object(
                        wizard,
                        "_collect_universal_credentials",
                        return_value=[{"user": "u", "pass": "p"}],
                    ):

                        config = wizard.ask_auth_config()

                        assert config["auth_enabled"] is True
                        assert config["auth_credentials"] == [{"user": "u", "pass": "p"}]

    def test_auth_config_advanced_mode(self):
        """Test selecting Advanced mode calls advanced collector."""
        wizard = MockWizard()

        with patch.object(wizard, "_check_and_load_saved_credentials", return_value=False):
            with patch.object(wizard, "ask_yes_no", return_value=True):
                with patch.object(wizard, "ask_choice_with_back", return_value=1):  # Advanced
                    with patch.object(
                        wizard, "_collect_advanced_credentials", return_value=False
                    ) as mock_advanced:

                        config = wizard.ask_auth_config()

                        assert config["auth_enabled"] is True
                        mock_advanced.assert_called_once()

    def test_auth_config_universal_cancel(self):
        """Test cancelling during Universal credential collection disables auth."""
        wizard = MockWizard()

        with patch.object(wizard, "_check_and_load_saved_credentials", return_value=False):
            with patch.object(wizard, "ask_yes_no", return_value=True):
                with patch.object(wizard, "ask_choice_with_back", return_value=0):
                    with patch.object(wizard, "_collect_universal_credentials", return_value=None):
                        config = wizard.ask_auth_config()
                        assert config["auth_enabled"] is False
                        assert config["auth_credentials"] == []

    def test_auth_config_advanced_cancel(self):
        """Test cancelling during Advanced credential collection disables auth."""
        wizard = MockWizard()

        with patch.object(wizard, "_check_and_load_saved_credentials", return_value=False):
            with patch.object(wizard, "ask_yes_no", return_value=True):
                with patch.object(wizard, "ask_choice_with_back", return_value=1):
                    with patch.object(wizard, "_collect_advanced_credentials", return_value=True):
                        config = wizard.ask_auth_config()
                        assert config["auth_enabled"] is False

    def test_auth_config_keyring_load_skips_manual_when_no_add(self):
        """Test keyring load enables auth and skips manual when user says no."""
        wizard = MockWizard()

        def load_saved(config):
            config["auth_ssh_user"] = "root"
            return True

        with patch.object(wizard, "_check_and_load_saved_credentials", side_effect=load_saved):
            with patch.object(wizard, "ask_yes_no", side_effect=[True, False]):
                with patch.object(wizard, "ask_choice_with_back") as mock_choice:
                    config = wizard.ask_auth_config()
                    assert config["auth_enabled"] is True
                    assert config["auth_ssh_user"] == "root"
                    mock_choice.assert_not_called()

    def test_auth_config_keyring_load_add_more_back_keeps_auth(self):
        """Test keyring load + back from mode keeps auth enabled."""
        wizard = MockWizard()

        def load_saved(config):
            config["auth_ssh_user"] = "root"
            return True

        with patch.object(wizard, "_check_and_load_saved_credentials", side_effect=load_saved):
            with patch.object(wizard, "ask_yes_no", side_effect=[True, True]):
                with patch.object(wizard, "ask_choice_with_back", return_value=-1):
                    config = wizard.ask_auth_config()
                    assert config["auth_enabled"] is True
                    assert config["auth_ssh_user"] == "root"

    def test_auth_config_keyring_load_add_more_cancel_keeps_auth(self):
        """Test keyring load + cancel manual creds keeps auth enabled."""
        wizard = MockWizard()

        def load_saved(config):
            config["auth_ssh_user"] = "root"
            return True

        with patch.object(wizard, "_check_and_load_saved_credentials", side_effect=load_saved):
            with patch.object(wizard, "ask_yes_no", side_effect=[True, True]):
                with patch.object(wizard, "ask_choice_with_back", return_value=0):
                    with patch.object(wizard, "_collect_universal_credentials", return_value=None):
                        config = wizard.ask_auth_config()
                        assert config["auth_enabled"] is True
                        assert config["auth_ssh_user"] == "root"
