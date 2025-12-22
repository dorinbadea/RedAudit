#!/usr/bin/env python3
"""
Coverage for interactive CLI menu flows.
"""

from __future__ import annotations

import builtins

import pytest

from redaudit import cli


class _DummyAuditor:
    choices = []

    def __init__(self):
        self.COLORS = {
            "CYAN": "",
            "ENDC": "",
            "WARNING": "",
            "FAIL": "",
            "OKGREEN": "",
        }
        self.logger = None

    def t(self, key, *_args):
        return key

    def clear_screen(self):
        return None

    def print_banner(self):
        return None

    def check_dependencies(self):
        return True

    def show_legal_warning(self):
        return True

    def ask_yes_no(self, *_args, **_kwargs):
        return False

    def show_main_menu(self):
        return self.choices.pop(0)

    def interactive_setup(self):
        return False

    def run_complete_scan(self):
        return True

    def print_status(self, *_args, **_kwargs):
        return None


def _patch_auditor(monkeypatch, choices):
    _DummyAuditor.choices = list(choices)
    monkeypatch.setattr("redaudit.core.auditor.InteractiveNetworkAuditor", _DummyAuditor)
    monkeypatch.setattr("redaudit.core.updater.interactive_update_check", lambda **_k: False)


def test_cli_main_interactive_exit(monkeypatch):
    _patch_auditor(monkeypatch, [0])
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.sys, "argv", ["redaudit", "--skip-update-check"])

    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0


def test_cli_main_interactive_start_scan_cancel(monkeypatch):
    _patch_auditor(monkeypatch, [1])
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.sys, "argv", ["redaudit", "--skip-update-check"])

    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0


def test_cli_main_interactive_check_updates_non_root(monkeypatch):
    _patch_auditor(monkeypatch, [2, 0])
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli.sys, "argv", ["redaudit", "--allow-non-root", "--skip-update-check"])

    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0


def test_cli_main_interactive_diff_reports(monkeypatch, tmp_path):
    _patch_auditor(monkeypatch, [3, 0])
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.sys, "argv", ["redaudit", "--skip-update-check"])

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        builtins,
        "input",
        lambda *_a, **_k: "old.json" if "old" in _a[0] else "new.json",
    )
    monkeypatch.setattr("redaudit.core.diff.generate_diff_report", lambda *_a, **_k: {"generated_at": "2025-01-01"})
    monkeypatch.setattr("redaudit.core.diff.format_diff_text", lambda *_a, **_k: "diff text")
    monkeypatch.setattr("redaudit.core.diff.format_diff_markdown", lambda *_a, **_k: "diff md")

    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
