#!/usr/bin/env python3
"""
RedAudit - Tests for dry-run helpers.
"""

from redaudit.utils.dry_run import is_dry_run


def test_is_dry_run_explicit_overrides_env(monkeypatch):
    monkeypatch.setenv("REDAUDIT_DRY_RUN", "1")
    assert is_dry_run(True) is True
    assert is_dry_run(False) is False


def test_is_dry_run_env_tokens(monkeypatch):
    truthy = ["1", "true", "yes", "y", "on", "TRUE", " Yes "]
    for token in truthy:
        monkeypatch.setenv("REDAUDIT_DRY_RUN", token)
        assert is_dry_run() is True

    falsy = ["0", "false", "no", "off", "", "   "]
    for token in falsy:
        monkeypatch.setenv("REDAUDIT_DRY_RUN", token)
        assert is_dry_run() is False
