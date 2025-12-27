#!/usr/bin/env python3
"""
Coverage for interactive auditor configuration flow.
v3.9.0: Updated to work with new profile selector.
"""

from __future__ import annotations

import builtins

from redaudit.core.auditor import InteractiveNetworkAuditor


def test_configure_scan_interactive_full_flow(monkeypatch, tmp_path):
    app = InteractiveNetworkAuditor()
    app.config["deep_id_scan"] = True

    # v3.9.0: First ask_choice is for profile selection (3 = Custom)
    # Then the wizard steps follow
    choice_with_back = iter([1, 0, 0, 0, 0, 0, 0])
    # First choice is profile (3=Custom), second is redteam mode
    choice = iter([3, 1])
    yes_no = iter([False, True, True])
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
