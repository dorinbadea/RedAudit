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

        with patch.object(wizard, "ask_yes_no", return_value=True):
            with patch.object(wizard, "ask_choice_with_back", return_value=0):
                with patch.object(wizard, "_collect_universal_credentials", return_value=None):
                    config = wizard.ask_auth_config()
                    assert config["auth_enabled"] is False
                    assert config["auth_credentials"] == []

    def test_auth_config_advanced_cancel(self):
        """Test cancelling during Advanced credential collection disables auth."""
        wizard = MockWizard()

        with patch.object(wizard, "ask_yes_no", return_value=True):
            with patch.object(wizard, "ask_choice_with_back", return_value=1):
                with patch.object(wizard, "_collect_advanced_credentials", return_value=True):
                    config = wizard.ask_auth_config()
                    assert config["auth_enabled"] is False
