#!/usr/bin/env python3
"""
Coverage for interactive auditor configuration flow.
v3.9.0: Updated to work with new profile selector.
"""

from __future__ import annotations

import builtins
from unittest.mock import patch

from redaudit.core.auditor import InteractiveNetworkAuditor


class MockWizardAuditor(InteractiveNetworkAuditor):
    def __init__(self):
        super().__init__()
        self.lang = "en"
        self.config = {"target_networks": [], "scan_vulnerabilities": True}
        self.rate_limit_delay = 0.0
        self.cryptography_available = True

    def t(self, key):
        return key

    def print_status(self, *args, **kwargs):
        pass

    def ask_choice(self, q, opts, default=0):
        return default

    def ask_choice_with_back(self, q, opts, default=0, **kwargs):
        return default

    def _ask_auditor_and_output_dir(self, defaults):
        pass

    def ask_yes_no(self, q, default="yes", **kwargs):
        return default == "yes"

    def ask_text(self, q, default="", **kwargs):
        return default

    def ask_num(self, q, min_val, max_val, default=0, **kwargs):
        return default

    def ask_number(self, q, default="all", **kwargs):
        return default

    def ask_network_range(self):
        return ["1.1.1.0/24"]

    def setup_encryption(self, **kwargs):
        pass


def test_configure_scan_interactive_full_flow(monkeypatch, tmp_path):
    app = InteractiveNetworkAuditor()
    app.config["deep_id_scan"] = True

    # v3.9.0: First ask_choice is for profile selection (3 = Custom)
    # Then the wizard steps follow. v4.3: Added hyperscan_mode + vulnerability scan step
    choice_with_back = iter([1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    # First choice is profile (3=Custom), second is redteam mode
    choice = iter([3, 1])
    yes_no = iter([False, False, True, True])
    numbers = iter(["all", 4, 10])

    monkeypatch.setattr(app, "print_status", lambda *_a, **_k: None)
    monkeypatch.setattr(app, "setup_nvd_api_key", lambda *_a, **_k: None)
    monkeypatch.setattr(app, "setup_encryption", lambda *_a, **_k: None)
    monkeypatch.setattr(app, "ask_webhook_url", lambda *_a, **_k: "")
    monkeypatch.setattr(app, "ask_net_discovery_options", lambda *_a, **_k: {"dns_zone": "corp"})

    monkeypatch.setattr(app, "ask_choice_with_back", lambda *_a, **_k: next(choice_with_back))
    monkeypatch.setattr(app, "ask_choice", lambda *_a, **_k: next(choice))
    monkeypatch.setattr(app, "ask_yes_no", lambda *_a, **_k: next(yes_no))
    monkeypatch.setattr(app, "ask_number", lambda *_a, **_k: next(numbers))

    inputs = iter(
        [
            "Auditor Name",
            str(tmp_path / "reports"),
            "EXAMPLE.COM",
            str(tmp_path / "users.txt"),
        ]
    )
    monkeypatch.setattr(builtins, "input", lambda *_a, **_k: next(inputs))

    monkeypatch.setattr("redaudit.core.auditor.get_default_reports_base_dir", lambda: str(tmp_path))
    monkeypatch.setattr("redaudit.core.auditor.expand_user_path", lambda val: val)
    monkeypatch.setattr("redaudit.core.auditor.os.geteuid", lambda: 0)

    app._configure_scan_interactive({})

    assert app.config["scan_mode"] == "normal"
    assert app.config["net_discovery_enabled"] is True
    assert app.config["windows_verify_enabled"] is True


def test_configure_scan_interactive_standard_profile(monkeypatch, tmp_path):
    """Test Standard profile auto-configuration."""
    app = InteractiveNetworkAuditor()

    # Select Standard profile (index 1), then timing Normal (index 1)
    choice_iter = iter([1, 1])
    monkeypatch.setattr(app, "ask_choice", lambda *_a, **_k: next(choice_iter))
    monkeypatch.setattr(app, "ask_yes_no", lambda *_a, **_k: False)
    monkeypatch.setattr("redaudit.core.auditor.get_default_reports_base_dir", lambda: str(tmp_path))
    # v3.9.0: Mock input() for auditor_name and output_dir prompts
    input_iter = iter(["", ""])  # Accept defaults for both
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: next(input_iter))

    app._configure_scan_interactive({})

    assert app.config["scan_mode"] == "normal"
    assert app.config["scan_vulnerabilities"] is True
    assert app.config["topology_enabled"] is True
    assert app.config["net_discovery_enabled"] is True
    assert app.rate_limit_delay == 0.0  # Normal timing


def test_configure_scan_interactive_exhaustive_profile(monkeypatch, tmp_path):
    """Test Exhaustive profile auto-configuration with NVD reminder."""
    app = InteractiveNetworkAuditor()

    # Select Exhaustive profile (index 2), then timing Stealth (index 0)
    choice_iter = iter([2, 0])
    monkeypatch.setattr(app, "ask_choice", lambda *_a, **_k: next(choice_iter))
    monkeypatch.setattr(app, "print_status", lambda *_a, **_k: None)
    monkeypatch.setattr(app, "ask_yes_no", lambda *_a, **_k: False)
    monkeypatch.setattr("redaudit.core.auditor.get_default_reports_base_dir", lambda: str(tmp_path))
    # Mock NVD not configured
    monkeypatch.setattr("redaudit.utils.config.is_nvd_api_key_configured", lambda: False)
    # v3.9.0: Mock input() for auditor_name and output_dir prompts
    input_iter = iter(["", ""])  # Accept defaults for both
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: next(input_iter))

    app._configure_scan_interactive({})

    assert app.config["scan_mode"] == "completo"
    # v3.9.0: Stealth timing uses reduced threads for IDS evasion
    assert app.config["threads"] == 2  # Stealth mode
    assert app.config["nmap_timing"] == "T1"  # Paranoid
    assert app.config["scan_vulnerabilities"] is True
    assert app.config["topology_enabled"] is True
    assert app.config["net_discovery_enabled"] is True
    assert app.config["net_discovery_redteam"] is True
    assert app.config["windows_verify_enabled"] is True
    # NVD disabled because key not configured
    assert app.config["cve_lookup_enabled"] is False
    # Stealth timing
    assert app.rate_limit_delay == 2.0


def test_interactive_setup_with_defaults_use(monkeypatch, tmp_path):
    """Test interactive_setup with 'use defaults' option."""
    app = InteractiveNetworkAuditor()
    app.defaults_mode = "ask"

    # Mock persisted defaults
    persisted = {
        "lang": "en",
        "target_networks": ["192.168.1.0/24"],
        "threads": 8,
        "output_dir": str(tmp_path),
        "scan_mode": "normal",
    }

    monkeypatch.setattr("redaudit.utils.config.get_persistent_defaults", lambda: persisted)
    monkeypatch.setattr(app, "clear_screen", lambda: None)
    monkeypatch.setattr(app, "print_banner", lambda: None)
    monkeypatch.setattr(app, "check_dependencies", lambda: True)
    monkeypatch.setattr(app, "show_legal_warning", lambda: True)
    monkeypatch.setattr(app, "show_config_summary", lambda: None)

    # Choose "Use defaults and start" (choice 0)
    monkeypatch.setattr(app, "ask_choice", lambda *a, **kw: 0)
    monkeypatch.setattr(app, "print_status", lambda *a, **kw: None)

    result = app.interactive_setup()

    assert result is True
    assert app.config["target_networks"] == ["192.168.1.0/24"]


def test_interactive_setup_with_defaults_ignore(monkeypatch, tmp_path):
    """Test interactive_setup with 'ignore defaults' option."""
    app = InteractiveNetworkAuditor()
    app.defaults_mode = "ignore"

    persisted = {"lang": "en", "target_networks": ["10.0.0.0/8"]}

    monkeypatch.setattr("redaudit.utils.config.get_persistent_defaults", lambda: persisted)
    monkeypatch.setattr(app, "clear_screen", lambda: None)
    monkeypatch.setattr(app, "print_banner", lambda: None)
    monkeypatch.setattr(app, "check_dependencies", lambda: True)
    monkeypatch.setattr(app, "show_legal_warning", lambda: True)
    monkeypatch.setattr(app, "show_config_summary", lambda: None)
    monkeypatch.setattr(app, "ask_network_range", lambda: ["172.16.0.0/16"])
    monkeypatch.setattr(app, "_configure_scan_interactive", lambda d: None)
    monkeypatch.setattr(app, "ask_yes_no", lambda *a, **kw: True)  # Start scan
    monkeypatch.setattr(app, "print_status", lambda *a, **kw: None)

    result = app.interactive_setup()

    assert result is True


def test_interactive_setup_legal_rejected(monkeypatch):
    """Test interactive_setup returns False when legal warning rejected."""
    app = InteractiveNetworkAuditor()

    monkeypatch.setattr("redaudit.utils.config.get_persistent_defaults", lambda: {})
    monkeypatch.setattr(app, "clear_screen", lambda: None)
    monkeypatch.setattr(app, "print_banner", lambda: None)
    monkeypatch.setattr(app, "check_dependencies", lambda: True)
    monkeypatch.setattr(app, "show_legal_warning", lambda: False)

    result = app.interactive_setup()

    assert result is False


def test_interactive_setup_dependencies_fail(monkeypatch):
    """Test interactive_setup returns False when dependencies fail."""
    app = InteractiveNetworkAuditor()

    monkeypatch.setattr("redaudit.utils.config.get_persistent_defaults", lambda: {})
    monkeypatch.setattr(app, "clear_screen", lambda: None)
    monkeypatch.setattr(app, "print_banner", lambda: None)
    monkeypatch.setattr(app, "check_dependencies", lambda: False)

    result = app.interactive_setup()

    assert result is False


def test_interactive_setup_save_defaults(monkeypatch, tmp_path):
    """Test saving defaults during interactive_setup."""
    app = InteractiveNetworkAuditor()
    app.defaults_mode = "ask"

    persisted = {}
    monkeypatch.setattr("redaudit.utils.config.get_persistent_defaults", lambda: persisted)
    monkeypatch.setattr(app, "clear_screen", lambda: None)
    monkeypatch.setattr(app, "print_banner", lambda: None)
    monkeypatch.setattr(app, "check_dependencies", lambda: True)
    monkeypatch.setattr(app, "show_legal_warning", lambda: True)
    monkeypatch.setattr(app, "show_config_summary", lambda: None)
    monkeypatch.setattr(app, "ask_network_range", lambda: ["10.0.0.0/24"])
    monkeypatch.setattr(app, "_configure_scan_interactive", lambda d: None)
    monkeypatch.setattr(app, "print_status", lambda *a, **kw: None)

    # First yes_no is save_defaults, second is start_audit
    yes_no_iter = iter([True, True])
    monkeypatch.setattr(app, "ask_yes_no", lambda *a, **kw: next(yes_no_iter))

    save_called = []
    monkeypatch.setattr(
        "redaudit.utils.config.update_persistent_defaults",
        lambda **kw: save_called.append(True) or True,
    )

    result = app.interactive_setup()

    assert result is True
    assert len(save_called) == 1


def test_wizard_express_profile():
    """Test Express profile configuration (profile 0)."""
    auditor = MockWizardAuditor()
    # ask_choice for profile = 0 (Express)
    with patch.object(auditor, "ask_choice", return_value=0):
        with patch("builtins.input", return_value=""):
            auditor._configure_scan_interactive({})
            assert auditor.config["scan_mode"] == "rapido"
            assert auditor.config["scan_vulnerabilities"] is False


def test_wizard_standard_profile_normal_timing():
    """Test Standard profile with Normal timing (profile 1, timing 1)."""
    auditor = MockWizardAuditor()
    # first call returns 1 (Standard), second returns 1 (Normal)
    with patch.object(auditor, "ask_choice", side_effect=[1, 1]):
        with patch.object(auditor, "ask_yes_no", return_value=True):
            with patch.object(auditor, "ask_num", return_value=10):
                with patch("builtins.input", return_value=""):
                    auditor._configure_scan_interactive({})
                    assert auditor.config["scan_mode"] == "normal"


def test_wizard_back_navigation():
    """Test 'Go back' navigation in timing screen (timing 3)."""
    auditor = MockWizardAuditor()
    # first: Standard (1), second: Back (3), third: Express (0)
    with patch.object(auditor, "ask_choice", side_effect=[1, 3, 0]):
        with patch("builtins.input", return_value=""):
            auditor._configure_scan_interactive({})
            assert auditor.config["scan_mode"] == "rapido"


def test_wizard_custom_profile():
    """Test Custom profile (profile 3) with full manual configuration."""
    auditor = MockWizardAuditor()
    # profile 3 = Custom. Map choice 2 to 'completo'
    with patch.object(auditor, "ask_choice", side_effect=[2, 2]):
        with patch("builtins.input", return_value=""):
            auditor._configure_scan_interactive({})
            assert auditor.config["scan_mode"] == "completo"


def test_wizard_exhaustive_profile():
    """Test Exhaustive profile configuration (profile 2)."""
    auditor = MockWizardAuditor()
    # profile 2 = Exhaustive
    with patch.object(auditor, "ask_choice", side_effect=[2, 2]):
        with patch("builtins.input", return_value=""):
            auditor._configure_scan_interactive({})
            assert auditor.config["scan_mode"] == "completo"
            assert auditor.config["scan_vulnerabilities"] is True
