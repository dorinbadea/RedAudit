#!/usr/bin/env python3
"""
Coverage for interactive auditor configuration flow.
v3.9.0: Updated to work with new profile selector.
"""

from __future__ import annotations

import builtins
from unittest.mock import MagicMock, patch

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
        if q == "auth_mode_q":
            return -1
        if q == "auth_scan_q":
            return 1  # No
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
    # Sequence: ScanMode(1), Hyperscan(0), Vuln(0), SQLMap(0), ZAP(0), CVE(0),
    # UDP(0), Topo(0), NetDisc(0), AuthScan(1-No), WindowsVerify(0)
    # Changing last 0 to 1 to disable Auth Scan and avoid dealing with credential inputs in this test
    choice_with_back = iter([1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1] + [0] * 50)
    # First choice is profile (3=Custom), second is redteam mode
    choice = iter([3, 1] + [0] * 50)
    # yes_no sequence for Standard profile (choice 1):
    # 1. Low impact enrichment? (False)
    # 2. Configure SSH? (False)
    # 3. Configure SMB? (False)
    # 4. Configure SNMP? (False)
    # 5. Start scan? (True)
    yes_no = iter([False, False, False, False, True] + [False] * 50)
    numbers = iter(["all", 4, 10] + [5] * 10)

    monkeypatch.setattr(app, "print_status", lambda *_a, **_k: None)
    monkeypatch.setattr(app, "setup_nvd_api_key", lambda *_a, **_k: None)
    monkeypatch.setattr(app, "setup_encryption", lambda *_a, **_k: None)
    monkeypatch.setattr(app, "ask_webhook_url", lambda *_a, **_k: "")
    monkeypatch.setattr(app, "ask_net_discovery_options", lambda *_a, **_k: {"dns_zone": "corp"})

    def smart_ask_choice_with_back(q, *args, **kwargs):
        if q == "auth_mode_q":
            return -1  # Go back/cancel auth config to avoid hanging on getpass
        return next(choice_with_back)

    monkeypatch.setattr(app, "ask_choice_with_back", smart_ask_choice_with_back)
    monkeypatch.setattr(app, "ask_choice", lambda *_a, **_k: next(choice))
    monkeypatch.setattr(app, "ask_yes_no", lambda *_a, **_k: next(yes_no))
    monkeypatch.setattr(app, "ask_number", lambda *_a, **_k: next(numbers))

    inputs = iter(
        [
            "EXAMPLE.COM",
            str(tmp_path / "users.txt"),
            "Auditor Name",
            str(tmp_path / "reports"),
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
    # Low impact (No), trust hyperscan (No)
    back_iter = iter([1, 1, 1])
    monkeypatch.setattr(app, "ask_choice_with_back", lambda *_a, **_k: next(back_iter))
    # v3.9.0: Mock input() for auditor_name and output_dir prompts
    input_iter = iter(["", ""])  # Accept defaults for both
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: next(input_iter))
    monkeypatch.setattr(app, "ask_auth_config", lambda *_a, **_k: {"auth_enabled": False})

    app._configure_scan_interactive({})

    assert app.config["scan_mode"] == "normal"
    assert app.config["scan_vulnerabilities"] is True
    assert app.config["topology_enabled"] is True
    assert app.config["net_discovery_enabled"] is True
    assert app.rate_limit_delay == 0.0  # Normal timing


def test_configure_scan_interactive_back_from_profile_prompt(monkeypatch):
    """Ensure back/cancel reopens profile selection."""
    app = InteractiveNetworkAuditor()

    # Select Standard profile (index 1), timing Normal (index 1), then Express (index 0)
    choice_iter = iter([1, 1, 0])
    monkeypatch.setattr(app, "ask_choice", lambda *_a, **_k: next(choice_iter))

    # First low-impact prompt returns back, second returns Yes
    back_iter = iter([app.WIZARD_BACK, 0])
    monkeypatch.setattr(app, "ask_choice_with_back", lambda *_a, **_k: next(back_iter))

    monkeypatch.setattr(app, "_ask_auditor_and_output_dir", lambda *_a, **_k: None)

    app._configure_scan_interactive({})

    assert app.config["scan_mode"] == "rapido"


def test_configure_scan_interactive_exhaustive_profile(monkeypatch, tmp_path):
    """Test Exhaustive profile auto-configuration with NVD reminder."""
    app = InteractiveNetworkAuditor()
    app.ui.print_status = MagicMock()
    app.ui.t = lambda key, *args: key

    # Select Exhaustive profile (index 2), then timing Stealth (index 0)
    choice_iter = iter([2, 0])
    monkeypatch.setattr(app, "ask_choice", lambda *_a, **_k: next(choice_iter))
    # Nuclei enabled? No. Trust hyperscan? No.
    back_iter = iter([1, 1, 1])
    monkeypatch.setattr(app, "ask_choice_with_back", lambda *_a, **_k: next(back_iter))
    monkeypatch.setattr("redaudit.core.auditor.get_default_reports_base_dir", lambda: str(tmp_path))
    # Mock NVD not configured
    monkeypatch.setattr("redaudit.utils.config.is_nvd_api_key_configured", lambda: False)
    # v3.9.0: Mock input() for auditor_name and output_dir prompts
    input_iter = iter(["", ""])  # Accept defaults for both
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: next(input_iter))
    monkeypatch.setattr(app, "ask_auth_config", lambda *_a, **_k: {"auth_enabled": False})

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
    # Warning now emitted before scan start prompt in interactive setup.


def test_interactive_setup_warns_before_start_when_nuclei_enabled(monkeypatch):
    app = InteractiveNetworkAuditor()
    app.ui = MagicMock()
    app.ui.t = lambda key, *args: key

    call_order = []

    def _print_status(msg, *_args, **_kwargs):
        if msg == "long_scan_warning":
            call_order.append("warning")

    app.ui.print_status = MagicMock(side_effect=_print_status)

    monkeypatch.setattr("redaudit.utils.config.get_persistent_defaults", lambda: {})
    monkeypatch.setattr(app, "clear_screen", lambda: None)
    monkeypatch.setattr(app, "print_banner", lambda: None)
    monkeypatch.setattr(app, "check_dependencies", lambda: True)
    monkeypatch.setattr(app, "show_legal_warning", lambda: True)
    monkeypatch.setattr(app, "ask_network_range", lambda: ["192.168.1.0/24"])
    monkeypatch.setattr(app, "_show_target_summary", lambda: None)

    def _configure(_defaults):
        app.config["nuclei_enabled"] = True
        app.config["scan_mode"] = "completo"

    monkeypatch.setattr(app, "_configure_scan_interactive", _configure)

    def _show_summary():
        call_order.append("summary")

    monkeypatch.setattr(app, "show_config_summary", _show_summary)

    def _ask_yes_no(*_args, **_kwargs):
        call_order.append("start")
        return False

    monkeypatch.setattr(app, "ask_yes_no", _ask_yes_no)

    app.interactive_setup()

    assert "warning" in call_order
    assert call_order.index("warning") > call_order.index("summary")
    assert call_order.index("warning") < call_order.index("start")


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


def test_interactive_setup_with_defaults_prompt_ignore_choice(monkeypatch):
    """Test interactive_setup with defaults prompt choosing ignore."""
    app = InteractiveNetworkAuditor()
    app.defaults_mode = "ask"

    persisted = {"lang": "en", "target_networks": ["10.0.0.0/8"]}

    monkeypatch.setattr("redaudit.utils.config.get_persistent_defaults", lambda: persisted)
    monkeypatch.setattr(app, "clear_screen", lambda: None)
    monkeypatch.setattr(app, "print_banner", lambda: None)
    monkeypatch.setattr(app, "check_dependencies", lambda: True)
    monkeypatch.setattr(app, "show_legal_warning", lambda: True)
    monkeypatch.setattr(app, "show_config_summary", lambda: None)
    monkeypatch.setattr(app, "ask_network_range", lambda: ["172.16.0.0/16"])
    monkeypatch.setattr(app, "_configure_scan_interactive", lambda d: None)
    monkeypatch.setattr(app, "print_status", lambda *a, **kw: None)
    monkeypatch.setattr(app, "ask_choice", lambda *a, **kw: 2)
    monkeypatch.setattr(app, "ask_yes_no", lambda *a, **kw: True)

    result = app.interactive_setup()

    assert result is True
    assert app.config["target_networks"] == ["172.16.0.0/16"]


def test_interactive_setup_with_defaults_review_summary(monkeypatch):
    """Test interactive_setup showing defaults summary."""
    app = InteractiveNetworkAuditor()
    app.defaults_mode = "ask"

    persisted = {"lang": "en", "target_networks": ["10.0.0.0/8"]}

    monkeypatch.setattr("redaudit.utils.config.get_persistent_defaults", lambda: persisted)
    monkeypatch.setattr(app, "clear_screen", lambda: None)
    monkeypatch.setattr(app, "print_banner", lambda: None)
    monkeypatch.setattr(app, "check_dependencies", lambda: True)
    monkeypatch.setattr(app, "show_legal_warning", lambda: True)
    monkeypatch.setattr(app, "show_config_summary", lambda: None)
    monkeypatch.setattr(app, "ask_network_range", lambda: ["172.16.0.0/16"])
    monkeypatch.setattr(app, "_configure_scan_interactive", lambda d: None)
    monkeypatch.setattr(app, "print_status", lambda *a, **kw: None)
    monkeypatch.setattr(app, "ask_choice", lambda *a, **kw: 1)

    yes_no_iter = iter([True, False, True])
    monkeypatch.setattr(app, "ask_yes_no", lambda *a, **kw: next(yes_no_iter))

    summary_calls = []
    monkeypatch.setattr(app, "_show_defaults_summary", lambda *_a, **_k: summary_calls.append(True))

    result = app.interactive_setup()

    assert result is True
    assert summary_calls


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


def test_interactive_setup_save_defaults_exception(monkeypatch):
    """Test defaults persistence failure logs warning."""
    app = InteractiveNetworkAuditor()
    app.defaults_mode = "ask"
    app.logger = MagicMock()

    monkeypatch.setattr("redaudit.utils.config.get_persistent_defaults", lambda: {})
    monkeypatch.setattr(app, "clear_screen", lambda: None)
    monkeypatch.setattr(app, "print_banner", lambda: None)
    monkeypatch.setattr(app, "check_dependencies", lambda: True)
    monkeypatch.setattr(app, "show_legal_warning", lambda: True)
    monkeypatch.setattr(app, "show_config_summary", lambda: None)
    monkeypatch.setattr(app, "ask_network_range", lambda: ["10.0.0.0/24"])
    monkeypatch.setattr(app, "_configure_scan_interactive", lambda d: None)
    monkeypatch.setattr(app, "print_status", lambda *a, **kw: None)

    yes_no_iter = iter([True, True])
    monkeypatch.setattr(app, "ask_yes_no", lambda *a, **kw: next(yes_no_iter))
    monkeypatch.setattr(
        "redaudit.utils.config.update_persistent_defaults",
        lambda **_kw: (_ for _ in ()).throw(ValueError("boom")),
    )

    result = app.interactive_setup()

    assert result is True
    assert app.logger.debug.called


def test_interactive_setup_defaults_load_error(monkeypatch):
    app = InteractiveNetworkAuditor()
    app.logger = MagicMock()

    def _boom():
        raise RuntimeError("fail")

    monkeypatch.setattr("redaudit.utils.config.get_persistent_defaults", _boom)
    monkeypatch.setattr(app, "clear_screen", lambda: None)
    monkeypatch.setattr(app, "print_banner", lambda: None)
    monkeypatch.setattr(app, "check_dependencies", lambda: False)

    result = app.interactive_setup()

    assert result is False
    assert app.logger.debug.called


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
    # 1. Profile = 1 (Standard)
    # 2. Timing = 1 (Normal)
    # 3. Auth Method = 0 (Key)
    with patch.object(auditor, "ask_choice", side_effect=[1, 1, 0, 0, 0]):
        # 1. Low impact? True
        # 2. SSH? True
        # 3. SMB? False
        # 4. SNMP? False
        # 5. Save Keyring? False
        # 6. Start scan? True
        with patch.object(
            auditor, "ask_yes_no", side_effect=[True, True, False, False, False, True] + [True] * 10
        ):
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


def test_wizard_custom_profile_nuclei_fatigue(monkeypatch):
    """Ensure Nuclei fatigue limit is prompted and stored in Custom profile."""
    auditor = MockWizardAuditor()
    auditor.ui.t = lambda key, *args: key

    def _ask_choice(q, _opts, default=0):
        if q == "wizard_profile_q":
            return 3
        if q == "nuclei_profile_q":
            return 1
        return default

    def _ask_choice_with_back(q, _opts, default=0, **kwargs):
        if q == "scan_mode":
            return 2
        if q == "nuclei_coverage_mode_q":
            return 0
        if q == "auth_mode_q":
            return -1
        if q == "auth_scan_q":
            return 1
        return default

    def _ask_yes_no(q, default="yes", **kwargs):
        if q == "nuclei_q":
            return True
        return default == "yes"

    def _ask_number(q, default="all", **kwargs):
        if q == "nuclei_budget_q":
            return 12
        if q == "nuclei_fatigue_q":
            return 4
        return default

    monkeypatch.setattr(auditor, "ask_choice", _ask_choice)
    monkeypatch.setattr(auditor, "ask_choice_with_back", _ask_choice_with_back)
    monkeypatch.setattr(auditor, "ask_yes_no", _ask_yes_no)
    monkeypatch.setattr(auditor, "ask_number", _ask_number)
    monkeypatch.setattr("redaudit.core.auditor.is_nuclei_available", lambda: True)
    monkeypatch.setattr("redaudit.utils.config.is_nvd_api_key_configured", lambda: False)
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "")

    auditor._configure_scan_interactive({})

    assert auditor.config["scan_mode"] == "completo"
    assert auditor.config["nuclei_enabled"] is True
    assert auditor.config["nuclei_full_coverage"] is False
    assert auditor.config["nuclei_max_runtime"] == 12
    assert auditor.config["nuclei_fatigue_limit"] == 4


def test_wizard_exhaustive_profile():
    """Test Exhaustive profile configuration (profile 2)."""
    auditor = MockWizardAuditor()
    # 1. Profile = 2 (Exhaustive)
    # 2. Timing = 2 (Aggressive)
    # 3. Auth Method = 0 (Key)
    with patch.object(auditor, "ask_choice", side_effect=[2, 2, 0]):
        # 1. Low impact? True (auto-enabled usually, but wizard asks if not auto)
        # 2. SSH? True
        # 3. SMB? False
        # 4. SNMP? False
        # 5. Trust HyperScan? False (default in Exhaustive)
        with patch.object(auditor, "ask_yes_no", side_effect=[True, True, False, False, False]):
            with patch("builtins.input", return_value=""):
                auditor._configure_scan_interactive({})
                assert auditor.config["scan_mode"] == "completo"
                assert auditor.config["scan_vulnerabilities"] is True


def test_wizard_exhaustive_profile_nuclei_fatigue():
    """Ensure Nuclei fatigue limit is prompted and stored in Exhaustive profile."""
    auditor = MockWizardAuditor()
    with patch.object(auditor, "ask_choice", side_effect=[2, 2, 1]):
        with patch.object(auditor, "ask_choice_with_back", side_effect=[0, 1, 1, 1, 1]):
            with patch.object(auditor, "ask_auth_config", return_value={}):
                with patch.object(auditor, "ask_number", side_effect=[15, 4]):
                    with (
                        patch("redaudit.utils.config.is_nvd_api_key_configured", lambda: False),
                        patch("builtins.input", return_value=""),
                    ):
                        auditor._configure_scan_interactive({})
    assert auditor.config["nuclei_enabled"] is True
    assert auditor.config["nuclei_full_coverage"] is True
    assert auditor.config["nuclei_max_runtime"] == 15
    assert auditor.config["nuclei_fatigue_limit"] == 4


def test_scope_expansion_profile_defaults_express_forces_off():
    auditor = MockWizardAuditor()
    defaults = {
        "leak_follow_mode": "safe",
        "iot_probes_mode": "safe",
        "leak_follow_policy_pack": "safe-extended",
        "iot_probe_packs": ["ssdp,coap"],
        "iot_probe_budget_seconds": 30,
        "iot_probe_timeout_seconds": 5,
    }

    auditor._apply_scope_expansion_profile_defaults(defaults, "express")

    assert auditor.config["leak_follow_mode"] == "off"
    assert auditor.config["iot_probes_mode"] == "off"
    assert auditor.config["leak_follow_policy_pack"] == "safe-extended"
    assert auditor.config["iot_probe_packs"] == ["ssdp", "coap"]
    assert auditor.config["iot_probe_budget_seconds"] == 30
    assert auditor.config["iot_probe_timeout_seconds"] == 5


def test_scope_expansion_quick_standard_enables_iot_only(monkeypatch):
    auditor = MockWizardAuditor()
    auditor.config.update(
        {"scan_mode": "normal", "scan_vulnerabilities": True, "nuclei_enabled": False}
    )
    monkeypatch.setattr(auditor, "ask_choice_with_back", MagicMock(side_effect=[0, 1]))

    result = auditor._ask_scope_expansion_quick(profile="standard", step_num=2, total_steps=2)

    assert result is True
    assert auditor.config["iot_probes_mode"] == "safe"
    assert auditor.config["leak_follow_mode"] == "off"


def test_scope_expansion_quick_exhaustive_leak_dependency(monkeypatch):
    auditor = MockWizardAuditor()
    auditor.config.update(
        {"scan_mode": "completo", "scan_vulnerabilities": True, "nuclei_enabled": False}
    )
    monkeypatch.setattr(auditor, "ask_choice_with_back", MagicMock(side_effect=[0, 1]))

    result = auditor._ask_scope_expansion_quick(profile="exhaustive", step_num=2, total_steps=2)

    assert result is True
    assert auditor.config["iot_probes_mode"] == "safe"
    assert auditor.config["leak_follow_mode"] == "off"


def test_scope_expansion_quick_custom_advanced_normalizes_inputs(monkeypatch):
    auditor = MockWizardAuditor()
    auditor.config.update(
        {
            "scan_mode": "completo",
            "scan_vulnerabilities": True,
            "nuclei_enabled": True,
            "iot_probes_mode": "off",
            "leak_follow_mode": "off",
            "iot_probe_packs": ["ssdp"],
        }
    )

    monkeypatch.setattr(
        auditor,
        "ask_choice_with_back",
        MagicMock(side_effect=[0, 0, 0]),
    )
    monkeypatch.setattr(auditor, "ask_choice", MagicMock(return_value=2))
    monkeypatch.setattr(auditor, "ask_number", MagicMock(side_effect=[40, 7]))
    input_values = iter(
        [
            "rfc1918-only,local-hosts",
            "10.0.0.0/24, 10.0.0.10",
            "10.0.9.0/24,10.0.9.20",
            "ssdp,coap,wiz",
        ]
    )
    monkeypatch.setattr(builtins, "input", lambda *_a, **_k: next(input_values))

    result = auditor._ask_scope_expansion_quick(profile="custom", step_num=9, total_steps=10)

    assert result is True
    assert auditor.config["iot_probes_mode"] == "safe"
    assert auditor.config["leak_follow_mode"] == "safe"
    assert auditor.config["leak_follow_policy_pack"] == "safe-extended"
    assert auditor.config["leak_follow_allowlist_profiles"] == ["rfc1918-only", "local-hosts"]
    assert auditor.config["leak_follow_allowlist"] == ["10.0.0.0/24", "10.0.0.10"]
    assert auditor.config["leak_follow_denylist"] == ["10.0.9.0/24", "10.0.9.20"]
    assert auditor.config["iot_probe_packs"] == ["ssdp", "coap", "wiz"]
    assert auditor.config["iot_probe_budget_seconds"] == 40
    assert auditor.config["iot_probe_timeout_seconds"] == 7


def test_scope_expansion_quick_custom_supports_back(monkeypatch):
    auditor = MockWizardAuditor()
    auditor.config.update(
        {"scan_mode": "completo", "scan_vulnerabilities": True, "nuclei_enabled": True}
    )
    monkeypatch.setattr(
        auditor, "ask_choice_with_back", MagicMock(return_value=auditor.WIZARD_BACK)
    )

    result = auditor._ask_scope_expansion_quick(profile="custom", step_num=9, total_steps=10)

    assert result is None
