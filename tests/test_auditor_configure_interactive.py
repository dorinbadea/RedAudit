#!/usr/bin/env python3
"""
Coverage for interactive auditor configuration flow.
"""

from __future__ import annotations

import builtins

from redaudit.core.auditor import InteractiveNetworkAuditor


def test_configure_scan_interactive_full_flow(monkeypatch, tmp_path):
    app = InteractiveNetworkAuditor()
    app.config["deep_id_scan"] = True

    choice_with_back = iter([1, 0, 0, 0, 0, 0, 0])
    choice = iter([1])
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
